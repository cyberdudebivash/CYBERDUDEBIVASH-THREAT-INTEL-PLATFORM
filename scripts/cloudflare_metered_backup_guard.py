#!/usr/bin/env python3
"""Pre-network account-wide Cloudflare cost admission for OPTIONAL metered backups.

All ten CYBERDUDEBIVASH ECOSYSTEM platforms use the same billing account.
This does not call Cloudflare. It denies backup enumeration/export unless an
owner-reviewed, fresh billing attestation explicitly budgets the operation.
Importing this module is side-effect-free. Never log the attestation JSON.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OPS = ROOT / "ops"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from cloudflare_shared_account_release_gate import (  # noqa: E402
    POLICY, ReleaseBlocked, certify, validate_policy,
)

class MeteredBackupDenied(ReleaseBlocked):
    """Refusal BEFORE any Cloudflare/R2 API call."""


def require_metered_backup_permit(*, environ=None) -> None:
    env = os.environ if environ is None else environ
    if env.get("CDB_CF_METERED_BACKUP_APPROVED") != "true":
        raise MeteredBackupDenied("Cloudflare metered backups are disabled by default")
    raw = env.get("CDB_CF_ACCOUNT_ATTESTATION_JSON", "")
    if not isinstance(raw, str) or not raw or len(raw) > 131072:
        raise MeteredBackupDenied("Missing/oversized private account-wide usage attestation")
    try:
        policy = validate_policy(json.loads(POLICY.read_text(encoding="utf-8")))
        document = json.loads(raw)
        certify(policy, document)
        # Backups entail billable requests. Reject a fabricated forecast with
        # zero incremental usage even if the total account has free headroom.
        metrics = document["metrics"]
        from decimal import Decimal
        for name in ("r2_class_a", "r2_class_b", "kv_reads", "kv_lists"):
            delta = Decimal(str(metrics[name]["proposed_increment_until_reset"]))
            if not delta.is_finite() or delta <= 0:
                raise MeteredBackupDenied(f"{name}: metered backup requires positive forecast")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise MeteredBackupDenied("Backup account-wide cost preflight denied") from exc
    print("CLOUDFLARE_BACKUP_COST_PREFLIGHT: CONDITIONAL_ALLOW; owner attestation checked.")
    print("Account headroom is not a platform-enforced spending cap.")
