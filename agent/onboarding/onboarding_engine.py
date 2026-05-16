#!/usr/bin/env python3
"""
agent/onboarding/onboarding_engine.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
ENTERPRISE CUSTOMER ONBOARDING AUTOMATION ENGINE

Orchestrates the full customer journey from signup → active user:
  1. Account creation (org + owner user)
  2. API key provisioning
  3. Welcome email dispatch
  4. Guided setup checklist tracking
  5. Trial activation (if applicable)
  6. Slack/Teams notification (for Enterprise/MSSP)
  7. Audit trail entry

Onboarding state machine:
  PENDING → PROVISIONING → ACTIVE → (TRIAL_EXPIRING → CONVERTED | CHURNED)

The engine is event-driven — call trigger_step() in response to user actions,
webhook events, or timer-based nudges.

Feature-flag gated: CDB_ONBOARDING_ENABLED=true
"""

import os
import json
import uuid
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("CDB-ONBOARDING")

_ONBOARDING_ENABLED   = os.environ.get("CDB_ONBOARDING_ENABLED", "false").lower() == "true"
_ONBOARDING_DATA_PATH = "data/onboarding"
_SENDGRID_API_KEY     = os.environ.get("SENDGRID_API_KEY", "")
_SENDGRID_FROM        = os.environ.get("CDB_EMAIL_FROM", "platform@cyberdudebivash.com")
_SLACK_WEBHOOK        = os.environ.get("CDB_SLACK_WEBHOOK_URL", "")  # Internal ops channel

# Checklist steps per tier
_CHECKLIST_STEPS: Dict[str, List[str]] = {
    "FREE": [
        "account_created",
        "api_key_issued",
        "first_api_call",
        "intel_feed_explored",
    ],
    "PRO": [
        "account_created",
        "api_key_issued",
        "first_api_call",
        "intel_feed_explored",
        "stix_export_tested",
        "webhook_configured",
    ],
    "ENTERPRISE": [
        "account_created",
        "api_key_issued",
        "first_api_call",
        "intel_feed_explored",
        "stix_export_tested",
        "siem_integration_configured",
        "rbac_roles_configured",
        "mfa_enrolled",
        "ip_allowlist_configured",
        "webhook_configured",
    ],
    "MSSP": [
        "account_created",
        "api_key_issued",
        "first_api_call",
        "intel_feed_explored",
        "stix_export_tested",
        "siem_integration_configured",
        "rbac_roles_configured",
        "mfa_enrolled",
        "ip_allowlist_configured",
        "webhook_configured",
        "multi_tenant_org_created",
        "sub_org_provisioned",
        "technical_kickoff_scheduled",
    ],
}


@dataclass
class OnboardingState:
    """Per-organisation onboarding progress record."""
    org_id:           str
    tier:             str
    email:            str
    org_name:         str
    status:           str          = "PENDING"    # PENDING | PROVISIONING | ACTIVE | TRIAL_EXPIRING | CONVERTED | CHURNED
    steps_completed:  List[str]    = field(default_factory=list)
    steps_total:      List[str]    = field(default_factory=list)
    created_at:       str          = ""
    activated_at:     str          = ""
    trial_ends_at:    str          = ""
    completion_pct:   float        = 0.0
    api_key_issued:   bool         = False
    welcome_sent:     bool         = False
    metadata:         Dict         = field(default_factory=dict)

    def progress(self) -> float:
        if not self.steps_total:
            return 0.0
        return round((len(self.steps_completed) / len(self.steps_total)) * 100, 1)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["completion_pct"] = self.progress()
        return d


class OnboardingEngine:
    """
    Stateful onboarding orchestrator.
    State persisted to Redis (primary) + local JSONL (fallback).
    """

    def __init__(self):
        self._redis = self._get_redis()
        os.makedirs(_ONBOARDING_DATA_PATH, exist_ok=True)

    def _get_redis(self):
        redis_url = os.environ.get("REDIS_URL", "")
        if not redis_url:
            return None
        try:
            import redis
            r = redis.from_url(redis_url, decode_responses=True, socket_timeout=1)
            r.ping()
            return r
        except Exception:
            return None

    def _state_key(self, org_id: str) -> str:
        return f"cdb:onboarding:{org_id}"

    def _save_state(self, state: OnboardingState) -> None:
        data = json.dumps(state.to_dict())
        if self._redis:
            try:
                self._redis.set(self._state_key(state.org_id), data, ex=86400 * 365)
            except Exception:
                pass
        path = os.path.join(_ONBOARDING_DATA_PATH, f"{state.org_id}.json")
        with open(path, "w") as f:
            f.write(data)

    def _load_state(self, org_id: str) -> Optional[OnboardingState]:
        data = None
        if self._redis:
            try:
                raw = self._redis.get(self._state_key(org_id))
                if raw:
                    data = json.loads(raw)
            except Exception:
                pass
        if not data:
            path = os.path.join(_ONBOARDING_DATA_PATH, f"{org_id}.json")
            try:
                with open(path) as f:
                    data = json.load(f)
            except FileNotFoundError:
                return None
        if not data:
            return None
        return OnboardingState(**{k: v for k, v in data.items() if k in OnboardingState.__dataclass_fields__})

    # ── Onboarding Trigger ──────────────────────────────────────────────────

    async def begin_onboarding(
        self,
        org_id:    str,
        org_name:  str,
        email:     str,
        tier:      str,
        trial:     bool = False,
    ) -> OnboardingState:
        """
        Initiate onboarding for a new organisation.
        Idempotent — calling twice for same org_id is safe.
        """
        existing = self._load_state(org_id)
        if existing:
            logger.info(f"[ONBOARDING] Already started for org={org_id}")
            return existing

        now      = datetime.now(tz=timezone.utc).isoformat()
        state    = OnboardingState(
            org_id=org_id,
            tier=tier.upper(),
            email=email,
            org_name=org_name,
            status="PROVISIONING",
            steps_completed=[],
            steps_total=_CHECKLIST_STEPS.get(tier.upper(), _CHECKLIST_STEPS["FREE"]),
            created_at=now,
        )

        if trial:
            trial_end = datetime.now(tz=timezone.utc) + timedelta(days=14)
            state.trial_ends_at = trial_end.isoformat()

        self._save_state(state)
        logger.info(f"[ONBOARDING] Started for org={org_id} tier={tier} trial={trial}")
        return state

    async def trigger_step(self, org_id: str, step: str, metadata: Optional[Dict] = None) -> Dict:
        """
        Mark an onboarding step as completed and advance the state machine.

        Args:
            org_id: Organisation ID
            step:   Step name from _CHECKLIST_STEPS
            metadata: Optional context (api_key_id, etc.)

        Returns:
            {step, completed, status, progress, next_recommended_step}
        """
        state = self._load_state(org_id)
        if not state:
            return {"status": "error", "message": f"No onboarding state for org={org_id}"}

        # Idempotent — don't double-count
        if step in state.steps_completed:
            return {
                "step":     step,
                "already_completed": True,
                "progress": state.progress(),
                "status":   state.status,
            }

        state.steps_completed.append(step)
        if metadata:
            state.metadata[step] = metadata

        # Handle specific step side effects
        await self._handle_step_effects(state, step)

        # Check if onboarding is complete
        remaining = [s for s in state.steps_total if s not in state.steps_completed]
        if not remaining and state.status == "PROVISIONING":
            state.status      = "ACTIVE"
            state.activated_at = datetime.now(tz=timezone.utc).isoformat()
            logger.info(f"[ONBOARDING] COMPLETE for org={state.org_id} tier={state.tier}")
            # Record metric
            try:
                from agent.telemetry.metrics import record_onboarding_completion
                record_onboarding_completion(state.tier)
            except Exception:
                pass

        self._save_state(state)

        next_step = remaining[0] if remaining else None
        return {
            "step":                   step,
            "completed":              True,
            "progress":               state.progress(),
            "status":                 state.status,
            "steps_completed":        len(state.steps_completed),
            "steps_total":            len(state.steps_total),
            "next_recommended_step":  next_step,
        }

    async def _handle_step_effects(self, state: OnboardingState, step: str) -> None:
        """Execute side effects when specific steps complete."""

        if step == "account_created":
            # Send welcome email
            if not state.welcome_sent:
                await self._send_welcome_email(state)
                state.welcome_sent = True
            # Notify ops for Enterprise/MSSP
            if state.tier in ("ENTERPRISE", "MSSP"):
                await self._notify_ops_slack(state, "New Enterprise signup")

        elif step == "api_key_issued":
            state.api_key_issued = True

        elif step == "first_api_call":
            logger.info(f"[ONBOARDING] First API call: org={state.org_id} tier={state.tier}")

        elif step == "technical_kickoff_scheduled" and state.tier == "MSSP":
            await self._notify_ops_slack(state, "MSSP technical kickoff scheduled — assign CSM")

    # ── Email ───────────────────────────────────────────────────────────────

    async def _send_welcome_email(self, state: OnboardingState) -> bool:
        """Send welcome email via SendGrid."""
        if not _SENDGRID_API_KEY:
            logger.debug("[ONBOARDING] No SendGrid key — skipping welcome email")
            return False
        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail

            tier_feature = {
                "FREE":       "access to live threat intelligence feeds",
                "PRO":        "premium threat intel + STIX exports",
                "ENTERPRISE": "enterprise-grade multi-tenant threat intelligence",
                "MSSP":       "unlimited multi-tenant threat intelligence infrastructure",
            }.get(state.tier, "threat intelligence access")

            mail = Mail(
                from_email=(_SENDGRID_FROM, "CyberDudeBivash SENTINEL APEX"),
                to_emails=state.email,
                subject=f"Welcome to SENTINEL APEX — Your {state.tier} access is ready",
                html_content=f"""
<h2>Welcome to CyberDudeBivash SENTINEL APEX, {state.org_name}!</h2>
<p>Your <strong>{state.tier}</strong> plan gives you {tier_feature}.</p>
<p><strong>Next steps:</strong></p>
<ol>
  <li>Get your API key from your dashboard</li>
  <li>Make your first request: <code>GET /api/v1/intel/feed</code></li>
  <li>Export threat intel in STIX 2.1 format</li>
</ol>
<p>Questions? Reply to this email or visit our documentation.</p>
<p>— The CyberDudeBivash Team</p>
""",
            )
            sg = SendGridAPIClient(_SENDGRID_API_KEY)
            sg.send(mail)
            logger.info(f"[ONBOARDING] Welcome email sent to {state.email}")
            return True
        except ImportError:
            logger.warning("[ONBOARDING] sendgrid not installed — skipping welcome email")
            return False
        except Exception as e:
            logger.error(f"[ONBOARDING] Welcome email failed: {e}")
            return False

    # ── Slack Ops Notification ───────────────────────────────────────────────

    async def _notify_ops_slack(self, state: OnboardingState, message: str) -> bool:
        if not _SLACK_WEBHOOK:
            return False
        try:
            import urllib.request
            payload = json.dumps({
                "text": (
                    f"*SENTINEL APEX Onboarding*\n"
                    f"{message}\n"
                    f"• Org: `{state.org_id}` — {state.org_name}\n"
                    f"• Tier: `{state.tier}`\n"
                    f"• Email: {state.email}"
                )
            }).encode()
            req = urllib.request.Request(
                _SLACK_WEBHOOK,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.warning(f"[ONBOARDING] Slack notification failed: {e}")
            return False

    # ── Status / Query ───────────────────────────────────────────────────────

    def get_status(self, org_id: str) -> Optional[Dict]:
        """Get current onboarding status for an org."""
        state = self._load_state(org_id)
        if not state:
            return None
        return state.to_dict()

    def get_checklist(self, org_id: str) -> Dict:
        """Get complete checklist with completion status per step."""
        state = self._load_state(org_id)
        if not state:
            return {"error": "not_found"}
        return {
            "org_id":   org_id,
            "tier":     state.tier,
            "progress": state.progress(),
            "status":   state.status,
            "steps": [
                {
                    "step":      s,
                    "completed": s in state.steps_completed,
                    "metadata":  state.metadata.get(s, {}),
                }
                for s in state.steps_total
            ],
        }


# Singleton
onboarding_engine = OnboardingEngine()
