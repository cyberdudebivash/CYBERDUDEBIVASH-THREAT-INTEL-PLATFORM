"""
CYBERDUDEBIVASH® SENTINEL APEX
ENTERPRISE MONETIZATION ANALYTICS ENGINE v1.0
Phase 7+8: Revenue tracking, conversion funnel analytics,
tier upgrade signals, churn prediction, MRR/ARR computation,
affiliate attribution, Gumroad/Stripe event processing.
Deterministic. Zero external API calls. Atomic writes only.
"""
import json
import logging
import os
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-MONETIZATION-ENGINE")

# ── CONSTANTS ─────────────────────────────────────────────────────────────────

TIER_PRICES_MONTHLY: Dict[str, float] = {
    "free":       0.0,
    "pro":        49.0,
    "enterprise": 299.0,
}

TIER_PRICES_ANNUAL: Dict[str, float] = {
    "free":       0.0,
    "pro":        490.0,      # 2 months free
    "enterprise": 2990.0,
}

# Revenue share: affiliate commission rates
AFFILIATE_COMMISSION: Dict[str, float] = {
    "standard":  0.20,   # 20%
    "premium":   0.30,   # 30% for top affiliates
    "partner":   0.40,   # 40% for strategic partners
}

# Funnel stages in order
FUNNEL_STAGES = [
    "visit",
    "signup_free",
    "api_key_created",
    "first_api_call",
    "preview_consumed",
    "paywall_hit",
    "pricing_view",
    "checkout_start",
    "checkout_complete",
    "subscription_active",
]

# Churn risk thresholds
CHURN_RISK_THRESHOLDS = {
    "days_inactive_warn":    7,
    "days_inactive_high":   14,
    "days_inactive_critical": 30,
    "api_call_drop_pct":    0.50,   # 50% drop week-over-week
}

# ── ENUMS ─────────────────────────────────────────────────────────────────────

class RevenueSource(str, Enum):
    SUBSCRIPTION = "subscription"
    GUMROAD      = "gumroad"
    STRIPE       = "stripe"
    AFFILIATE    = "affiliate"
    ENTERPRISE   = "enterprise_contract"
    REFUND       = "refund"

class ChurnRisk(str, Enum):
    LOW      = "LOW"
    MODERATE = "MODERATE"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

class ConversionEvent(str, Enum):
    VISIT           = "visit"
    SIGNUP          = "signup_free"
    UPGRADE_PRO     = "upgrade_pro"
    UPGRADE_ENT     = "upgrade_enterprise"
    DOWNGRADE       = "downgrade"
    CHURN           = "churn"
    REACTIVATION    = "reactivation"
    AFFILIATE_CLICK = "affiliate_click"
    GUMROAD_SALE    = "gumroad_sale"

# ── DATA CLASSES ──────────────────────────────────────────────────────────────

@dataclass
class RevenueEvent:
    event_id:     str
    tenant_id:    str
    source:       RevenueSource
    amount_usd:   float
    tier_from:    str
    tier_to:      str
    affiliate_id: Optional[str]
    timestamp:    str
    metadata:     Dict = field(default_factory=dict)

@dataclass
class FunnelSnapshot:
    stage_counts:   Dict[str, int]   # stage → count
    stage_rates:    Dict[str, float] # stage → conversion rate from prev
    overall_rate:   float            # visit → subscription
    drop_off_stage: str              # highest drop-off point
    snapshot_date:  str

@dataclass
class MRRBreakdown:
    total_mrr:       float
    new_mrr:         float
    expansion_mrr:   float
    contraction_mrr: float
    churn_mrr:       float
    net_new_mrr:     float
    arr:             float
    free_count:      int
    pro_count:       int
    enterprise_count: int
    calculated_at:   str

@dataclass
class ChurnSignal:
    tenant_id:     str
    tier:          str
    risk_level:    ChurnRisk
    days_inactive: int
    api_call_trend: float   # +/- % change
    signals:       List[str]
    recommended_action: str

@dataclass
class AffiliateReport:
    affiliate_id:      str
    tier:              str
    clicks:            int
    conversions:       int
    revenue_generated: float
    commission_owed:   float
    conversion_rate:   float
    top_referred_tier: str

@dataclass
class MonetizationReport:
    mrr:                MRRBreakdown
    funnel:             FunnelSnapshot
    churn_signals:      List[ChurnSignal]
    affiliate_reports:  List[AffiliateReport]
    total_revenue_30d:  float
    total_revenue_90d:  float
    avg_revenue_per_user: float
    ltv_estimate:       float
    paywall_hit_rate:   float
    upgrade_rate:       float
    top_revenue_source: str
    recommendations:    List[str]
    generated_at:       str

# ── REVENUE LEDGER ────────────────────────────────────────────────────────────

class RevenueLedger:
    """
    Append-only revenue ledger. Atomic writes. Idempotent by event_id.
    Processes Gumroad webhooks, Stripe events, and internal tier upgrades.
    """

    def __init__(self, ledger_path: str = "data/monetization/revenue_ledger.jsonl"):
        self._path   = ledger_path
        self._events: List[RevenueEvent] = []
        self._seen_ids: set = set()
        os.makedirs(os.path.dirname(ledger_path), exist_ok=True)
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    if d["event_id"] in self._seen_ids:
                        continue
                    self._seen_ids.add(d["event_id"])
                    self._events.append(RevenueEvent(
                        event_id=d["event_id"],
                        tenant_id=d["tenant_id"],
                        source=RevenueSource(d["source"]),
                        amount_usd=float(d["amount_usd"]),
                        tier_from=d.get("tier_from", ""),
                        tier_to=d.get("tier_to", ""),
                        affiliate_id=d.get("affiliate_id"),
                        timestamp=d["timestamp"],
                        metadata=d.get("metadata", {}),
                    ))
        except Exception as e:
            logger.warning(f"[LEDGER] Load error: {e}")

    def record(self, event: RevenueEvent) -> bool:
        """Record a revenue event. Returns False if duplicate."""
        if event.event_id in self._seen_ids:
            return False
        self._seen_ids.add(event.event_id)
        self._events.append(event)
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "event_id":    event.event_id,
                    "tenant_id":   event.tenant_id,
                    "source":      event.source.value,
                    "amount_usd":  event.amount_usd,
                    "tier_from":   event.tier_from,
                    "tier_to":     event.tier_to,
                    "affiliate_id": event.affiliate_id,
                    "timestamp":   event.timestamp,
                    "metadata":    event.metadata,
                }, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning(f"[LEDGER] Write error: {e}")
        return True

    def events_since(self, days: int) -> List[RevenueEvent]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        return [e for e in self._events if e.timestamp >= cutoff]

    def total_revenue(self, days: int) -> float:
        return sum(
            e.amount_usd for e in self.events_since(days)
            if e.source != RevenueSource.REFUND
        )

    def process_gumroad_webhook(self, payload: Dict) -> Optional[RevenueEvent]:
        """Parse and record a Gumroad webhook payload."""
        try:
            event_id = payload.get("sale_id") or hashlib.md5(
                json.dumps(payload, sort_keys=True).encode()
            , usedforsecurity=False).hexdigest()[:16]
            amount = float(payload.get("price", 0)) / 100.0  # cents → dollars
            tenant_id = payload.get("email", "unknown")
            affiliate = payload.get("referrer_id")
            ev = RevenueEvent(
                event_id=f"gumroad-{event_id}",
                tenant_id=tenant_id,
                source=RevenueSource.GUMROAD,
                amount_usd=amount,
                tier_from="free",
                tier_to=payload.get("product_name", "pro").lower(),
                affiliate_id=affiliate,
                timestamp=payload.get("created_at", datetime.now(timezone.utc).isoformat()),
                metadata={"product": payload.get("product_name", "")},
            )
            self.record(ev)
            return ev
        except Exception as e:
            logger.warning(f"[LEDGER] Gumroad parse error: {e}")
            return None

    def process_stripe_event(self, payload: Dict) -> Optional[RevenueEvent]:
        """Parse and record a Stripe webhook event."""
        try:
            event_type = payload.get("type", "")
            if event_type not in ("invoice.payment_succeeded", "checkout.session.completed"):
                return None
            obj = payload.get("data", {}).get("object", {})
            event_id = obj.get("id") or hashlib.md5(
                json.dumps(obj, sort_keys=True).encode()
            , usedforsecurity=False).hexdigest()[:16]
            amount = float(obj.get("amount_paid", 0)) / 100.0
            tenant_id = obj.get("customer_email") or obj.get("customer", "unknown")
            ev = RevenueEvent(
                event_id=f"stripe-{event_id}",
                tenant_id=tenant_id,
                source=RevenueSource.STRIPE,
                amount_usd=amount,
                tier_from="free",
                tier_to=obj.get("metadata", {}).get("tier", "pro"),
                affiliate_id=obj.get("metadata", {}).get("affiliate_id"),
                timestamp=datetime.fromtimestamp(
                    obj.get("created", 0), tz=timezone.utc
                ).isoformat() if obj.get("created") else datetime.now(timezone.utc).isoformat(),
                metadata={"stripe_event": event_type},
            )
            self.record(ev)
            return ev
        except Exception as e:
            logger.warning(f"[LEDGER] Stripe parse error: {e}")
            return None

# ── MRR CALCULATOR ────────────────────────────────────────────────────────────

class MRRCalculator:
    """
    Computes MRR/ARR from tenant tier distribution + revenue events.
    Standard SaaS MRR accounting: New + Expansion + Contraction + Churn.
    """

    def compute(
        self,
        tenant_tiers: Dict[str, str],  # tenant_id → tier
        events_30d: List[RevenueEvent],
    ) -> MRRBreakdown:
        # Count active subscribers
        free_count = pro_count = ent_count = 0
        for tier in tenant_tiers.values():
            if tier == "free":
                free_count += 1
            elif tier == "pro":
                pro_count += 1
            elif tier == "enterprise":
                ent_count += 1

        total_mrr = (
            pro_count * TIER_PRICES_MONTHLY["pro"] +
            ent_count * TIER_PRICES_MONTHLY["enterprise"]
        )
        arr = total_mrr * 12

        # Compute MRR movements from events
        new_mrr = expansion_mrr = contraction_mrr = churn_mrr = 0.0
        for ev in events_30d:
            price_from = TIER_PRICES_MONTHLY.get(ev.tier_from, 0.0)
            price_to   = TIER_PRICES_MONTHLY.get(ev.tier_to,   0.0)
            delta = price_to - price_from
            if ev.tier_from == "free" and price_to > 0:
                new_mrr += price_to
            elif delta > 0:
                expansion_mrr += delta
            elif delta < 0 and price_to > 0:
                contraction_mrr += abs(delta)
            elif price_to == 0 and price_from > 0:
                churn_mrr += price_from

        net_new_mrr = new_mrr + expansion_mrr - contraction_mrr - churn_mrr

        return MRRBreakdown(
            total_mrr=round(total_mrr, 2),
            new_mrr=round(new_mrr, 2),
            expansion_mrr=round(expansion_mrr, 2),
            contraction_mrr=round(contraction_mrr, 2),
            churn_mrr=round(churn_mrr, 2),
            net_new_mrr=round(net_new_mrr, 2),
            arr=round(arr, 2),
            free_count=free_count,
            pro_count=pro_count,
            enterprise_count=ent_count,
            calculated_at=datetime.now(timezone.utc).isoformat(),
        )

# ── FUNNEL ANALYZER ───────────────────────────────────────────────────────────

class FunnelAnalyzer:
    """
    Conversion funnel from visit → subscription.
    Computes stage-to-stage rates and identifies biggest drop-off.
    """

    def analyze(self, stage_data: Dict[str, int]) -> FunnelSnapshot:
        counts: Dict[str, int] = {}
        for stage in FUNNEL_STAGES:
            counts[stage] = stage_data.get(stage, 0)

        rates: Dict[str, float] = {}
        for i, stage in enumerate(FUNNEL_STAGES):
            if i == 0:
                rates[stage] = 100.0
                continue
            prev = FUNNEL_STAGES[i - 1]
            prev_count = counts.get(prev, 0)
            curr_count = counts.get(stage, 0)
            if prev_count > 0:
                rates[stage] = round(100.0 * curr_count / prev_count, 1)
            else:
                rates[stage] = 0.0

        # Overall: visit → subscription
        visits = counts.get("visit", 1)
        subs   = counts.get("subscription_active", 0)
        overall = round(100.0 * subs / visits, 3) if visits > 0 else 0.0

        # Biggest drop-off stage (lowest stage-to-stage rate, excluding first)
        drop_stage = min(
            (s for s in FUNNEL_STAGES[1:] if rates.get(s, 100) < 100),
            key=lambda s: rates.get(s, 100.0),
            default="paywall_hit",
        )

        return FunnelSnapshot(
            stage_counts=counts,
            stage_rates=rates,
            overall_rate=overall,
            drop_off_stage=drop_stage,
            snapshot_date=datetime.now(timezone.utc).isoformat()[:10],
        )

# ── CHURN PREDICTOR ───────────────────────────────────────────────────────────

class ChurnPredictor:
    """
    Churn risk scoring from tenant activity signals.
    Rule-based, deterministic, no ML dependency.
    """

    def score_tenant(
        self,
        tenant_id:     str,
        tier:          str,
        last_active:   str,
        api_calls_7d:  int,
        api_calls_14d: int,
    ) -> ChurnSignal:
        signals: List[str] = []
        now = datetime.now(timezone.utc)

        # Days inactive
        try:
            last_dt = datetime.fromisoformat(last_active.replace("Z", "+00:00"))
            days_inactive = (now - last_dt).days
        except Exception:
            days_inactive = 0

        if days_inactive >= CHURN_RISK_THRESHOLDS["days_inactive_critical"]:
            signals.append(f"Inactive {days_inactive}d (CRITICAL threshold)")
        elif days_inactive >= CHURN_RISK_THRESHOLDS["days_inactive_high"]:
            signals.append(f"Inactive {days_inactive}d (HIGH threshold)")
        elif days_inactive >= CHURN_RISK_THRESHOLDS["days_inactive_warn"]:
            signals.append(f"Inactive {days_inactive}d (WARNING threshold)")

        # API call trend (14d vs 7d annualized)
        baseline_7d = api_calls_14d - api_calls_7d
        trend_pct = 0.0
        if baseline_7d > 0:
            trend_pct = (api_calls_7d - baseline_7d) / baseline_7d
            if trend_pct < -CHURN_RISK_THRESHOLDS["api_call_drop_pct"]:
                signals.append(f"API call drop {trend_pct*100:.0f}% week-over-week")

        # Zero calls this week
        if api_calls_7d == 0 and tier != "free":
            signals.append("Zero API calls this week (paid tier inactive)")

        # Risk level
        risk = ChurnRisk.LOW
        if days_inactive >= 30 or (api_calls_7d == 0 and tier != "free"):
            risk = ChurnRisk.CRITICAL
        elif days_inactive >= 14 or trend_pct < -0.5:
            risk = ChurnRisk.HIGH
        elif days_inactive >= 7 or trend_pct < -0.25:
            risk = ChurnRisk.MODERATE

        # Action
        actions = {
            ChurnRisk.CRITICAL: "Immediate outreach — offer concierge onboarding or discount",
            ChurnRisk.HIGH:     "Send re-engagement email with new feature highlights",
            ChurnRisk.MODERATE: "Trigger in-app nudge showing new threat advisories",
            ChurnRisk.LOW:      "Monitor — no action required",
        }

        return ChurnSignal(
            tenant_id=tenant_id,
            tier=tier,
            risk_level=risk,
            days_inactive=days_inactive,
            api_call_trend=round(trend_pct * 100, 1),
            signals=signals,
            recommended_action=actions[risk],
        )

# ── AFFILIATE TRACKER ─────────────────────────────────────────────────────────

class AffiliateTracker:
    """
    Tracks affiliate clicks, conversions, and commission computation.
    Last-click attribution model.
    """

    def __init__(self):
        self._clicks:      Dict[str, int]   = defaultdict(int)
        self._conversions: Dict[str, List]  = defaultdict(list)
        self._tiers:       Dict[str, str]   = {}

    def record_click(self, affiliate_id: str, tier: str = "standard") -> None:
        self._clicks[affiliate_id] += 1
        self._tiers[affiliate_id] = tier

    def record_conversion(self, affiliate_id: str, amount_usd: float,
                           tier_to: str) -> None:
        self._conversions[affiliate_id].append({
            "amount": amount_usd, "tier_to": tier_to,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def compute_reports(self) -> List[AffiliateReport]:
        reports: List[AffiliateReport] = []
        for aff_id, clicks in self._clicks.items():
            convs  = self._conversions.get(aff_id, [])
            rev    = sum(c["amount"] for c in convs)
            tier   = self._tiers.get(aff_id, "standard")
            rate   = AFFILIATE_COMMISSION.get(tier, 0.20)
            comm   = rev * rate

            tier_counts: Dict[str, int] = defaultdict(int)
            for c in convs:
                tier_counts[c["tier_to"]] += 1
            top_tier = max(tier_counts, key=tier_counts.get) if tier_counts else "pro"

            conv_rate = round(100.0 * len(convs) / clicks, 1) if clicks > 0 else 0.0
            reports.append(AffiliateReport(
                affiliate_id=aff_id,
                tier=tier,
                clicks=clicks,
                conversions=len(convs),
                revenue_generated=round(rev, 2),
                commission_owed=round(comm, 2),
                conversion_rate=conv_rate,
                top_referred_tier=top_tier,
            ))
        return sorted(reports, key=lambda r: r.revenue_generated, reverse=True)

# ── MASTER ENGINE ─────────────────────────────────────────────────────────────

class EnterpriseMonetizationAnalyticsEngine:
    """
    Master monetization engine.
    Wires: revenue ledger + MRR calc + funnel + churn + affiliates.
    Outputs atomic JSON reports to data/monetization/.
    """

    def __init__(self):
        self._output_dir = "data/monetization"
        os.makedirs(self._output_dir, exist_ok=True)
        self.ledger    = RevenueLedger(
            os.path.join(self._output_dir, "revenue_ledger.jsonl"))
        self.mrr_calc  = MRRCalculator()
        self.funnel    = FunnelAnalyzer()
        self.churn     = ChurnPredictor()
        self.affiliate = AffiliateTracker()

    def ingest_gumroad(self, payload: Dict) -> Optional[RevenueEvent]:
        return self.ledger.process_gumroad_webhook(payload)

    def ingest_stripe(self, payload: Dict) -> Optional[RevenueEvent]:
        return self.ledger.process_stripe_event(payload)

    def record_direct(self, tenant_id: str, amount: float,
                      source: str, tier_to: str,
                      affiliate_id: Optional[str] = None) -> RevenueEvent:
        ev = RevenueEvent(
            event_id=f"direct-{hashlib.md5(f'{tenant_id}{amount}{source}'.encode(), usedforsecurity=False).hexdigest()[:12]}",
            tenant_id=tenant_id,
            source=RevenueSource(source),
            amount_usd=amount,
            tier_from="free",
            tier_to=tier_to,
            affiliate_id=affiliate_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self.ledger.record(ev)
        if affiliate_id:
            self.affiliate.record_conversion(affiliate_id, amount, tier_to)
        return ev

    def run_full_pipeline(
        self,
        tenant_tiers:  Dict[str, str],
        tenant_activity: Dict[str, Dict],  # tenant_id → {last_active, api_7d, api_14d}
        funnel_stage_data: Dict[str, int],
    ) -> MonetizationReport:
        """
        Full monetization analytics pipeline.
        All inputs are in-memory — no external calls.
        """
        now = datetime.now(timezone.utc).isoformat()

        # MRR
        events_30d = self.ledger.events_since(30)
        mrr = self.mrr_calc.compute(tenant_tiers, events_30d)

        # Funnel
        funnel_snap = self.funnel.analyze(funnel_stage_data)

        # Churn signals
        churn_signals: List[ChurnSignal] = []
        for tid, activity in tenant_activity.items():
            tier = tenant_tiers.get(tid, "free")
            if tier == "free":
                continue   # churn for free = irrelevant for revenue
            sig = self.churn.score_tenant(
                tenant_id=tid,
                tier=tier,
                last_active=activity.get("last_active", now),
                api_calls_7d=activity.get("api_7d", 0),
                api_calls_14d=activity.get("api_14d", 0),
            )
            churn_signals.append(sig)
        churn_signals.sort(key=lambda s: ["LOW","MODERATE","HIGH","CRITICAL"].index(s.risk_level.value), reverse=True)

        # Affiliate
        aff_reports = self.affiliate.compute_reports()

        # Revenue totals
        rev_30d = self.ledger.total_revenue(30)
        rev_90d = self.ledger.total_revenue(90)
        total_paid = max(1, mrr.pro_count + mrr.enterprise_count)
        arpu = round(mrr.total_mrr / total_paid, 2)
        # LTV = ARPU / est. monthly churn rate (assume 5% default)
        ltv = round(arpu / 0.05, 2)

        paywall_hit_rate = round(
            100.0 * funnel_snap.stage_counts.get("paywall_hit", 0) /
            max(1, funnel_snap.stage_counts.get("signup_free", 1)), 1
        )
        upgrade_rate = round(
            100.0 * funnel_snap.stage_counts.get("subscription_active", 0) /
            max(1, funnel_snap.stage_counts.get("paywall_hit", 1)), 1
        )

        # Top revenue source
        source_totals: Dict[str, float] = defaultdict(float)
        for ev in events_30d:
            if ev.source != RevenueSource.REFUND:
                source_totals[ev.source.value] += ev.amount_usd
        top_source = max(source_totals, key=source_totals.get) if source_totals else "subscription"

        # Recommendations
        recs: List[str] = []
        if funnel_snap.drop_off_stage == "paywall_hit":
            recs.append("High paywall drop-off — A/B test pricing page copy and CTA")
        if mrr.churn_mrr > mrr.new_mrr:
            recs.append("Churn MRR exceeds new MRR — urgent retention initiative needed")
        critical_churners = [s for s in churn_signals if s.risk_level == ChurnRisk.CRITICAL]
        if critical_churners:
            recs.append(f"{len(critical_churners)} critical churn risk tenant(s) — initiate outreach immediately")
        if upgrade_rate < 5.0:
            recs.append(f"Upgrade rate {upgrade_rate}% below 5% target — improve paywall UX")
        if mrr.expansion_mrr > 0:
            recs.append(f"Expansion MRR ${mrr.expansion_mrr:.0f} detected — nurture expansion accounts")
        if not recs:
            recs.append("Monetization metrics healthy — maintain current growth trajectory")

        report = MonetizationReport(
            mrr=mrr,
            funnel=funnel_snap,
            churn_signals=churn_signals,
            affiliate_reports=aff_reports,
            total_revenue_30d=round(rev_30d, 2),
            total_revenue_90d=round(rev_90d, 2),
            avg_revenue_per_user=arpu,
            ltv_estimate=ltv,
            paywall_hit_rate=paywall_hit_rate,
            upgrade_rate=upgrade_rate,
            top_revenue_source=top_source,
            recommendations=recs,
            generated_at=now,
        )

        self._persist(report)
        return report

    def _persist(self, report: MonetizationReport) -> None:
        payload = {
            "mrr": {
                "total_mrr":        report.mrr.total_mrr,
                "new_mrr":          report.mrr.new_mrr,
                "expansion_mrr":    report.mrr.expansion_mrr,
                "contraction_mrr":  report.mrr.contraction_mrr,
                "churn_mrr":        report.mrr.churn_mrr,
                "net_new_mrr":      report.mrr.net_new_mrr,
                "arr":              report.mrr.arr,
                "free_count":       report.mrr.free_count,
                "pro_count":        report.mrr.pro_count,
                "enterprise_count": report.mrr.enterprise_count,
            },
            "funnel": {
                "overall_rate":   report.funnel.overall_rate,
                "drop_off_stage": report.funnel.drop_off_stage,
                "stage_rates":    report.funnel.stage_rates,
            },
            "churn_signals": [
                {"tenant_id": s.tenant_id, "tier": s.tier,
                 "risk": s.risk_level.value, "days_inactive": s.days_inactive,
                 "action": s.recommended_action}
                for s in report.churn_signals
            ],
            "affiliate_reports": [
                {"id": a.affiliate_id, "conversions": a.conversions,
                 "revenue": a.revenue_generated, "commission": a.commission_owed}
                for a in report.affiliate_reports
            ],
            "total_revenue_30d":     report.total_revenue_30d,
            "total_revenue_90d":     report.total_revenue_90d,
            "avg_revenue_per_user":  report.avg_revenue_per_user,
            "ltv_estimate":          report.ltv_estimate,
            "paywall_hit_rate":      report.paywall_hit_rate,
            "upgrade_rate":          report.upgrade_rate,
            "top_revenue_source":    report.top_revenue_source,
            "recommendations":       report.recommendations,
            "generated_at":          report.generated_at,
        }
        path = os.path.join(self._output_dir, "monetization_report.json")
        tmp  = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        logger.info(f"[MONETIZATION] Report written → {path}")


# ── SMOKE TEST ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    engine = EnterpriseMonetizationAnalyticsEngine()

    # Simulate Gumroad sale
    engine.ingest_gumroad({
        "sale_id": "gm001", "email": "buyer@test.com",
        "price": 4900, "product_name": "pro",
        "referrer_id": "aff-alpha",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    # Simulate Stripe subscription
    engine.ingest_stripe({
        "type": "invoice.payment_succeeded",
        "data": {"object": {
            "id": "in_stripe001",
            "amount_paid": 29900,
            "customer_email": "enterprise@bigco.com",
            "created": int(datetime.now(timezone.utc).timestamp()),
            "metadata": {"tier": "enterprise", "affiliate_id": "aff-beta"},
        }}
    })

    # Affiliate clicks
    engine.affiliate.record_click("aff-alpha", "standard")
    engine.affiliate.record_click("aff-alpha", "standard")
    engine.affiliate.record_click("aff-beta",  "premium")

    # Tenant tiers
    tenant_tiers = {
        "t001": "free",  "t002": "free",  "t003": "free",
        "t004": "pro",   "t005": "pro",
        "t006": "enterprise",
    }

    # Activity (for churn scoring)
    now_iso = datetime.now(timezone.utc).isoformat()
    stale   = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
    tenant_activity = {
        "t004": {"last_active": now_iso, "api_7d": 150, "api_14d": 280},
        "t005": {"last_active": stale,   "api_7d": 0,   "api_14d": 45},
        "t006": {"last_active": now_iso, "api_7d": 1200,"api_14d": 2100},
    }

    # Funnel data
    funnel_data = {
        "visit":                1000,
        "signup_free":          200,
        "api_key_created":      180,
        "first_api_call":       160,
        "preview_consumed":     140,
        "paywall_hit":          80,
        "pricing_view":         55,
        "checkout_start":       20,
        "checkout_complete":    12,
        "subscription_active":  10,
    }

    report = engine.run_full_pipeline(tenant_tiers, tenant_activity, funnel_data)

    print("\n[MONETIZATION] Smoke Test")
    print(f"  MRR Total:        ${report.mrr.total_mrr:.2f}")
    print(f"  ARR:              ${report.mrr.arr:.2f}")
    print(f"  New MRR (30d):    ${report.mrr.new_mrr:.2f}")
    print(f"  Tenants:          {report.mrr.free_count}F / {report.mrr.pro_count}P / {report.mrr.enterprise_count}E")
    print(f"  Revenue 30d:      ${report.total_revenue_30d:.2f}")
    print(f"  ARPU:             ${report.avg_revenue_per_user:.2f}")
    print(f"  LTV Estimate:     ${report.ltv_estimate:.2f}")
    print(f"  Funnel Rate:      {report.funnel.overall_rate}% (visit→sub)")
    print(f"  Paywall Hit Rate: {report.paywall_hit_rate}%")
    print(f"  Upgrade Rate:     {report.upgrade_rate}%")
    print(f"  Drop-off Stage:   {report.funnel.drop_off_stage}")
    print(f"  Churn Signals:    {len(report.churn_signals)} paid tenants scored")
    for s in report.churn_signals:
        print(f"    [{s.risk_level.value:8s}] {s.tenant_id} — {s.days_inactive}d inactive")
    print(f"  Affiliates:       {len(report.affiliate_reports)}")
    for a in report.affiliate_reports:
        print(f"    {a.affiliate_id}: {a.conversions} conv, ${a.revenue_generated:.2f} rev, ${a.commission_owed:.2f} commission")
    print(f"  Recommendations:")
    for r in report.recommendations:
        print(f"    - {r}")
