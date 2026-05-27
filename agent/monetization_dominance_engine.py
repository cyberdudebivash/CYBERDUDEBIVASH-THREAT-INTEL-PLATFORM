"""
CYBERDUDEBIVASH® SENTINEL APEX — Phase 56
Monetization Dominance Engine
Enterprise billing, tenant quotas, telemetry metering, API economy governance,
SLA enforcement, org-level analytics, enterprise upsell governance,
telemetry monetization, graph intelligence subscriptions, CTI subscriptions,
AI runtime protection, malware intel subscriptions, replay validation,
MSSP licensing, OEM licensing, white-label MSSP, enterprise hunt operations,
SOC-as-a-Service, telemetry federation licensing.
Production-grade. Revenue-optimized. Hyperscale-ready.
"""

import json
import uuid
import statistics
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from collections import defaultdict
import math


# ─── Enumerations ─────────────────────────────────────────────────────────────

class PricingModel(Enum):
    PER_ENDPOINT        = "per_endpoint"
    PER_EVENT           = "per_event_million"
    FLAT_MONTHLY        = "flat_monthly"
    USAGE_BASED         = "usage_based"
    OUTCOME_BASED       = "outcome_based"
    TIERED_VOLUME       = "tiered_volume"

class SubscriptionTier(Enum):
    FREE_TRIAL          = "free_trial"
    STARTER             = "starter"
    PROFESSIONAL        = "professional"
    ENTERPRISE          = "enterprise"
    MSSP_PARTNER        = "mssp_partner"
    OEM_WHITE_LABEL     = "oem_white_label"

class RevenueStream(Enum):
    CTI_SUBSCRIPTION        = "cti_subscription"
    GRAPH_INTEL             = "graph_intelligence"
    AI_RUNTIME_PROTECTION   = "ai_runtime_protection"
    MALWARE_INTEL           = "malware_intelligence"
    REPLAY_VALIDATION       = "replay_validation"
    TELEMETRY_FEDERATION    = "telemetry_federation"
    MSSP_LICENSING          = "mssp_licensing"
    OEM_LICENSING           = "oem_licensing"
    SOC_AS_A_SERVICE        = "soc_as_a_service"
    ENTERPRISE_HUNT         = "enterprise_hunt_operations"
    API_ACCESS              = "api_access"
    PROFESSIONAL_SERVICES   = "professional_services"
    TRAINING                = "training_certification"

class SLAStatus(Enum):
    COMPLIANT   = "compliant"
    WARNING     = "warning"
    BREACH      = "breach"
    CRITICAL    = "critical"

class BillingCycle(Enum):
    MONTHLY     = "monthly"
    QUARTERLY   = "quarterly"
    ANNUAL      = "annual"

class UpsellOpportunity(Enum):
    ADD_MODULE              = "add_module"
    TIER_UPGRADE            = "tier_upgrade"
    EXPAND_ENDPOINTS        = "expand_endpoints"
    ADD_TENANT              = "add_tenant"
    PROFESSIONAL_SERVICES   = "professional_services"
    MULTI_YEAR_COMMIT       = "multi_year_commit"


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class SubscriptionPlan:
    plan_id:            str
    plan_name:          str
    tier:               SubscriptionTier
    pricing_model:      PricingModel
    base_price_usd:     float
    endpoint_limit:     int
    event_limit_day:    int             # -1 = unlimited
    api_calls_day:      int
    retention_days:     int
    modules_included:   list[str]
    overage_per_endpoint: float         = 0.0
    overage_per_million_events: float   = 0.0
    sla_uptime_pct:     float           = 99.9
    support_tier:       str             = "standard"

    @property
    def annual_value(self) -> float:
        return round(self.base_price_usd * 12, 2)


@dataclass
class TenantSubscription:
    subscription_id:    str
    tenant_id:          str
    org_name:           str
    plan_id:            str
    tier:               SubscriptionTier
    billing_cycle:      BillingCycle
    mrr_usd:            float           # monthly recurring revenue
    arr_usd:            float           = 0.0
    endpoints_licensed: int             = 0
    endpoints_active:   int             = 0
    start_date:         str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    renewal_date:       str             = ""
    payment_status:     str             = "current"  # current / overdue / failed
    auto_renew:         bool            = True
    expansion_revenue:  float           = 0.0        # upsell/expansion this period
    churn_risk_score:   float           = 0.0        # 0–10
    health_score:       float           = 100.0
    account_exec:       Optional[str]   = None

    def __post_init__(self):
        if self.billing_cycle == BillingCycle.ANNUAL:
            self.arr_usd = round(self.mrr_usd * 12, 2)
        elif self.billing_cycle == BillingCycle.QUARTERLY:
            self.arr_usd = round(self.mrr_usd * 12, 2)
        else:
            self.arr_usd = round(self.mrr_usd * 12, 2)

    @property
    def endpoint_utilization_pct(self) -> float:
        return round((self.endpoints_active / max(self.endpoints_licensed, 1)) * 100, 2)

    @property
    def upsell_potential_usd(self) -> float:
        if self.endpoint_utilization_pct >= 85:
            return round(self.mrr_usd * 0.25, 2)
        return 0.0


@dataclass
class UsageMeteringRecord:
    metering_id:        str
    tenant_id:          str
    period_start:       str
    period_end:         str
    endpoints_measured: int
    events_total:       int
    api_calls:          int
    replay_operations:  int
    graph_queries:      int
    ai_inferences:      int
    storage_tb:         float
    overage_endpoints:  int             = 0
    overage_events_M:   float           = 0.0
    overage_charge_usd: float           = 0.0
    computed_at:        str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class SLAContract:
    sla_id:             str
    tenant_id:          str
    uptime_sla_pct:     float           # e.g. 99.95
    mttd_sla_minutes:   float
    mttr_sla_minutes:   float
    api_latency_sla_ms: float
    data_retention_sla: int             # days
    support_response_h: float
    penalty_per_breach: float           # USD
    credits_outstanding: float          = 0.0
    current_status:     SLAStatus       = SLAStatus.COMPLIANT
    measured_uptime:    float           = 0.0
    measured_mttd:      float           = 0.0
    measured_latency:   float           = 0.0
    breach_count:       int             = 0
    contract_start:     str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def evaluate_compliance(self) -> SLAStatus:
        issues = 0
        if self.measured_uptime > 0 and self.measured_uptime < self.uptime_sla_pct:
            issues += 2
            self.credits_outstanding += self.penalty_per_breach
            self.breach_count += 1
        if self.measured_mttd > 0 and self.measured_mttd > self.mttd_sla_minutes:
            issues += 1
        if self.measured_latency > 0 and self.measured_latency > self.api_latency_sla_ms:
            issues += 1

        if issues >= 3:
            self.current_status = SLAStatus.CRITICAL
        elif issues == 2:
            self.current_status = SLAStatus.BREACH
        elif issues == 1:
            self.current_status = SLAStatus.WARNING
        else:
            self.current_status = SLAStatus.COMPLIANT
        return self.current_status


@dataclass
class RevenueStreamRecord:
    record_id:          str
    stream:             RevenueStream
    tenant_id:          str
    amount_usd:         float
    period:             str             # YYYY-MM
    is_recurring:       bool            = True
    is_expansion:       bool            = False
    is_new_business:    bool            = False
    recorded_at:        str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class UpsellOpportunityRecord:
    opp_id:             str
    tenant_id:          str
    opp_type:           UpsellOpportunity
    description:        str
    estimated_arr_usd:  float
    confidence:         float           # 0–1
    priority:           str             = "MEDIUM"
    created_at:         str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    closed:             bool            = False


@dataclass
class APIEconomyMetrics:
    tenant_id:          str
    period:             str
    total_api_calls:    int
    unique_endpoints:   int
    top_endpoints:      list[dict]
    avg_response_ms:    float
    p99_response_ms:    float
    error_rate_pct:     float
    revenue_attributed: float           = 0.0
    rate_limit_hits:    int             = 0
    computed_at:        str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Monetization Dominance Engine ────────────────────────────────────────────

class MonetizationDominanceEngine:
    """
    Phase 56 — Monetization Dominance Engine.
    Manages subscription plans, tenant billing, usage metering, SLA enforcement,
    API economy analytics, upsell governance, revenue stream tracking,
    and produces comprehensive revenue intelligence.
    """

    def __init__(self):
        self._plans:            dict[str, SubscriptionPlan]         = {}
        self._subscriptions:    dict[str, TenantSubscription]       = {}
        self._metering:         list[UsageMeteringRecord]           = []
        self._sla_contracts:    dict[str, SLAContract]              = {}
        self._revenue_records:  list[RevenueStreamRecord]           = []
        self._upsell_opps:      list[UpsellOpportunityRecord]       = []
        self._api_metrics:      list[APIEconomyMetrics]             = []
        self._initialized       = datetime.now(timezone.utc).isoformat()
        self._load_standard_plans()

    def _load_standard_plans(self):
        self._plans = {
            "plan-starter":    SubscriptionPlan("plan-starter",    "Starter",         SubscriptionTier.STARTER,       PricingModel.PER_ENDPOINT, 1200,     500,    200_000_000,   5_000,    90,  ["cti","alerts"]),
            "plan-pro":        SubscriptionPlan("plan-pro",        "Professional",    SubscriptionTier.PROFESSIONAL,  PricingModel.PER_ENDPOINT, 4800,     2000,   1_000_000_000, 50_000,   180, ["cti","graph","replay","ai-defense"]),
            "plan-enterprise": SubscriptionPlan("plan-enterprise", "Enterprise",      SubscriptionTier.ENTERPRISE,    PricingModel.PER_ENDPOINT, 18000,    10000,  -1,            500_000,  365, ["cti","graph","replay","ai-defense","malware-intel","hunt","soc"]),
            "plan-mssp":       SubscriptionPlan("plan-mssp",       "MSSP Partner",    SubscriptionTier.MSSP_PARTNER,  PricingModel.TIERED_VOLUME,75000,    50000,  -1,            2_000_000,365, ["all-modules","white-label","multi-tenant","dedicated-support"]),
            "plan-oem":        SubscriptionPlan("plan-oem",        "OEM White-Label", SubscriptionTier.OEM_WHITE_LABEL,PricingModel.FLAT_MONTHLY,150000,  -1,     -1,            -1,        365, ["all-modules","oem-branding","api-unlimited","dedicated-infra"]),
        }

    # ── Plan Management ────────────────────────────────────────────────────

    def get_plan_catalog(self) -> list[dict]:
        return [
            {
                "plan_id":      p.plan_id,
                "name":         p.plan_name,
                "tier":         p.tier.value,
                "monthly_usd":  p.base_price_usd,
                "annual_usd":   p.annual_value,
                "endpoints":    p.endpoint_limit if p.endpoint_limit > 0 else "unlimited",
                "modules":      p.modules_included,
            }
            for p in sorted(self._plans.values(), key=lambda x: x.base_price_usd)
        ]

    # ── Subscription Management ────────────────────────────────────────────

    def create_subscription(self, sub: TenantSubscription) -> dict:
        self._subscriptions[sub.subscription_id] = sub
        return {
            "subscription_id":  sub.subscription_id,
            "tenant_id":        sub.tenant_id,
            "org_name":         sub.org_name,
            "tier":             sub.tier.value,
            "mrr_usd":          sub.mrr_usd,
            "arr_usd":          sub.arr_usd,
            "start_date":       sub.start_date,
        }

    def get_revenue_metrics(self) -> dict:
        if not self._subscriptions:
            return {"status": "no_subscriptions"}

        subs = list(self._subscriptions.values())
        total_mrr = sum(s.mrr_usd for s in subs)
        total_arr = sum(s.arr_usd for s in subs)
        new_mrr   = sum(s.mrr_usd for s in subs if s.payment_status == "current")
        expansion = sum(s.expansion_revenue for s in subs)

        by_tier: dict[str, dict] = defaultdict(lambda: {"count": 0, "mrr": 0.0})
        for s in subs:
            by_tier[s.tier.value]["count"] += 1
            by_tier[s.tier.value]["mrr"]   += s.mrr_usd

        churn_risk_high = [s.tenant_id for s in subs if s.churn_risk_score >= 7]

        return {
            "total_customers":      len(subs),
            "total_mrr_usd":        round(total_mrr, 2),
            "total_arr_usd":        round(total_arr, 2),
            "avg_mrr_per_customer": round(total_mrr / len(subs), 2),
            "expansion_mrr_usd":    round(expansion, 2),
            "by_tier":              {k: {"count": v["count"], "mrr": round(v["mrr"], 2)} for k,v in by_tier.items()},
            "high_churn_risk":      churn_risk_high,
            "net_revenue_retention": round((total_mrr + expansion) / max(total_mrr - expansion * 0.1, 1) * 100, 2),
        }

    # ── Usage Metering ─────────────────────────────────────────────────────

    def record_usage(self, record: UsageMeteringRecord) -> dict:
        self._metering.append(record)
        sub = next((s for s in self._subscriptions.values() if s.tenant_id == record.tenant_id), None)
        plan = self._plans.get(sub.plan_id) if sub else None

        overage_charge = 0.0
        if plan:
            if record.endpoints_measured > plan.endpoint_limit > 0:
                overage = record.endpoints_measured - plan.endpoint_limit
                record.overage_endpoints = overage
                overage_charge += overage * plan.overage_per_endpoint

            if plan.event_limit_day > 0:
                event_limit_period = plan.event_limit_day * 30
                if record.events_total > event_limit_period:
                    overage_M = (record.events_total - event_limit_period) / 1_000_000
                    record.overage_events_M = overage_M
                    overage_charge += overage_M * plan.overage_per_million_events

        record.overage_charge_usd = round(overage_charge, 2)
        return {
            "metering_id":      record.metering_id,
            "tenant_id":        record.tenant_id,
            "overage_usd":      record.overage_charge_usd,
            "endpoints":        record.endpoints_measured,
            "events_total":     record.events_total,
        }

    def get_metering_summary(self) -> dict:
        if not self._metering:
            return {"status": "no_data"}

        total_overages = sum(r.overage_charge_usd for r in self._metering)
        total_events   = sum(r.events_total for r in self._metering)
        total_apis     = sum(r.api_calls for r in self._metering)

        return {
            "total_metering_records":   len(self._metering),
            "total_events_measured":    total_events,
            "total_api_calls":          total_apis,
            "total_overage_usd":        round(total_overages, 2),
            "tenants_with_overage":     sum(1 for r in self._metering if r.overage_charge_usd > 0),
        }

    # ── SLA Enforcement ────────────────────────────────────────────────────

    def register_sla(self, contract: SLAContract) -> dict:
        self._sla_contracts[contract.tenant_id] = contract
        return {
            "sla_id":       contract.sla_id,
            "tenant_id":    contract.tenant_id,
            "uptime_sla":   contract.uptime_sla_pct,
            "status":       contract.current_status.value,
        }

    def evaluate_all_slas(self) -> dict:
        results: dict[str, str] = {}
        credits_total = 0.0
        breach_count  = 0

        for tid, contract in self._sla_contracts.items():
            status = contract.evaluate_compliance()
            results[tid] = status.value
            credits_total += contract.credits_outstanding
            if status in (SLAStatus.BREACH, SLAStatus.CRITICAL):
                breach_count += 1

        return {
            "total_contracts":      len(self._sla_contracts),
            "compliant_count":      sum(1 for s in results.values() if s == "compliant"),
            "breach_count":         breach_count,
            "total_credits_usd":    round(credits_total, 2),
            "tenant_sla_status":    results,
        }

    # ── Revenue Stream Analytics ───────────────────────────────────────────

    def record_revenue(self, record: RevenueStreamRecord) -> dict:
        self._revenue_records.append(record)
        return {
            "record_id":    record.record_id,
            "stream":       record.stream.value,
            "amount_usd":   record.amount_usd,
            "period":       record.period,
        }

    def get_revenue_stream_analysis(self) -> dict:
        if not self._revenue_records:
            return {"status": "no_data"}

        by_stream: dict[str, float] = defaultdict(float)
        recurring  = 0.0
        expansion  = 0.0
        new_biz    = 0.0

        for r in self._revenue_records:
            by_stream[r.stream.value] += r.amount_usd
            if r.is_recurring:  recurring += r.amount_usd
            if r.is_expansion:  expansion += r.amount_usd
            if r.is_new_business: new_biz += r.amount_usd

        total = sum(by_stream.values())

        return {
            "total_revenue_usd":    round(total, 2),
            "recurring_revenue":    round(recurring, 2),
            "expansion_revenue":    round(expansion, 2),
            "new_business_revenue": round(new_biz, 2),
            "by_stream": {
                stream: {
                    "amount_usd":   round(amt, 2),
                    "pct_of_total": round(amt / total * 100, 2) if total > 0 else 0,
                }
                for stream, amt in sorted(by_stream.items(), key=lambda x: x[1], reverse=True)
            },
            "top_revenue_stream": max(by_stream, key=by_stream.get) if by_stream else "none",
        }

    # ── Upsell Governance ─────────────────────────────────────────────────

    def identify_upsell_opportunities(self) -> list[dict]:
        opps: list[UpsellOpportunityRecord] = []

        for sub in self._subscriptions.values():
            # High endpoint utilization → expand licenses
            if sub.endpoint_utilization_pct >= 85:
                opps.append(UpsellOpportunityRecord(
                    opp_id          = str(uuid.uuid4())[:8],
                    tenant_id       = sub.tenant_id,
                    opp_type        = UpsellOpportunity.EXPAND_ENDPOINTS,
                    description     = f"Endpoint utilization at {sub.endpoint_utilization_pct}% — license expansion recommended",
                    estimated_arr_usd = sub.mrr_usd * 12 * 0.20,
                    confidence      = 0.85,
                    priority        = "HIGH",
                ))

            # Starter/Pro → upgrade to Enterprise
            if sub.tier in (SubscriptionTier.STARTER, SubscriptionTier.PROFESSIONAL):
                opps.append(UpsellOpportunityRecord(
                    opp_id          = str(uuid.uuid4())[:8],
                    tenant_id       = sub.tenant_id,
                    opp_type        = UpsellOpportunity.TIER_UPGRADE,
                    description     = f"Upgrade from {sub.tier.value} to Enterprise — additional modules available",
                    estimated_arr_usd = 18000 * 12 - sub.arr_usd,
                    confidence      = 0.72,
                    priority        = "MEDIUM",
                ))

            # Low churn risk → multi-year commit
            if sub.churn_risk_score < 3 and sub.tier in (SubscriptionTier.ENTERPRISE, SubscriptionTier.MSSP_PARTNER):
                opps.append(UpsellOpportunityRecord(
                    opp_id          = str(uuid.uuid4())[:8],
                    tenant_id       = sub.tenant_id,
                    opp_type        = UpsellOpportunity.MULTI_YEAR_COMMIT,
                    description     = "Strong health score — multi-year discount offer (5% off 3-year)",
                    estimated_arr_usd = sub.arr_usd * 0.05,
                    confidence      = 0.80,
                    priority        = "HIGH",
                ))

        self._upsell_opps.extend(opps)
        return [
            {
                "opp_id":           o.opp_id,
                "tenant_id":        o.tenant_id,
                "type":             o.opp_type.value,
                "description":      o.description,
                "estimated_arr":    round(o.estimated_arr_usd, 2),
                "confidence":       o.confidence,
                "priority":         o.priority,
            }
            for o in sorted(opps, key=lambda x: x.estimated_arr_usd, reverse=True)
        ]

    # ── API Economy Analytics ─────────────────────────────────────────────

    def register_api_metrics(self, metrics: APIEconomyMetrics) -> dict:
        self._api_metrics.append(metrics)
        return {
            "tenant_id":        metrics.tenant_id,
            "total_calls":      metrics.total_api_calls,
            "error_rate":       metrics.error_rate_pct,
            "avg_latency_ms":   metrics.avg_response_ms,
        }

    def get_api_economy_summary(self) -> dict:
        if not self._api_metrics:
            return {"status": "no_data"}

        total_calls = sum(m.total_api_calls for m in self._api_metrics)
        avg_latency = statistics.mean(m.avg_response_ms for m in self._api_metrics)
        avg_errors  = statistics.mean(m.error_rate_pct for m in self._api_metrics)
        total_rev   = sum(m.revenue_attributed for m in self._api_metrics)
        rate_limit_hits = sum(m.rate_limit_hits for m in self._api_metrics)

        top_consumers = sorted(
            [{"tenant": m.tenant_id, "calls": m.total_api_calls} for m in self._api_metrics],
            key=lambda x: x["calls"], reverse=True
        )[:5]

        return {
            "total_api_calls":          total_calls,
            "total_tenants_consuming":  len(self._api_metrics),
            "avg_response_ms":          round(avg_latency, 2),
            "avg_error_rate_pct":       round(avg_errors, 3),
            "attributed_revenue_usd":   round(total_rev, 2),
            "rate_limit_hits":          rate_limit_hits,
            "revenue_per_million_calls":round(total_rev / max(total_calls / 1_000_000, 1), 2),
            "top_api_consumers":        top_consumers,
        }

    # ── Org-Level Analytics ────────────────────────────────────────────────

    def get_org_analytics(self, tenant_id: str) -> dict:
        sub = next((s for s in self._subscriptions.values() if s.tenant_id == tenant_id), None)
        if not sub:
            return {"error": "tenant_not_found"}

        metering = [m for m in self._metering if m.tenant_id == tenant_id]
        rev_recs  = [r for r in self._revenue_records if r.tenant_id == tenant_id]
        sla       = self._sla_contracts.get(tenant_id)
        api_m     = next((m for m in self._api_metrics if m.tenant_id == tenant_id), None)
        opps      = [o for o in self._upsell_opps if o.tenant_id == tenant_id and not o.closed]

        return {
            "tenant_id":            tenant_id,
            "org_name":             sub.org_name,
            "tier":                 sub.tier.value,
            "health_score":         sub.health_score,
            "mrr_usd":              sub.mrr_usd,
            "arr_usd":              sub.arr_usd,
            "endpoint_utilization": sub.endpoint_utilization_pct,
            "churn_risk":           sub.churn_risk_score,
            "sla_status":           sla.current_status.value if sla else "not_contracted",
            "total_api_calls":      api_m.total_api_calls if api_m else 0,
            "open_upsell_opps":     len(opps),
            "upsell_estimated_arr": round(sum(o.estimated_arr_usd for o in opps), 2),
            "total_revenue_ltm":    round(sum(r.amount_usd for r in rev_recs), 2),
        }

    # ── Monetization Dashboard ─────────────────────────────────────────────

    def export_monetization_report(self) -> dict:
        revenue_metrics   = self.get_revenue_metrics()
        revenue_streams   = self.get_revenue_stream_analysis()
        sla_report        = self.evaluate_all_slas()
        metering_summary  = self.get_metering_summary()
        api_economy       = self.get_api_economy_summary()
        upsell_opps       = self.identify_upsell_opportunities()

        total_upsell_pipeline = sum(o["estimated_arr"] for o in upsell_opps)

        return {
            "meta": {
                "engine":       "MonetizationDominanceEngine",
                "phase":        56,
                "platform":     "SENTINEL APEX",
                "initialized":  self._initialized,
                "exported_at":  datetime.now(timezone.utc).isoformat(),
            },
            "revenue_metrics":          revenue_metrics,
            "revenue_stream_analysis":  revenue_streams,
            "metering_summary":         metering_summary,
            "sla_compliance":           sla_report,
            "api_economy":              api_economy,
            "upsell_pipeline": {
                "total_opportunities":  len(upsell_opps),
                "total_pipeline_arr":   round(total_upsell_pipeline, 2),
                "top_opportunities":    upsell_opps[:5],
            },
            "plan_catalog":             self.get_plan_catalog(),
        }


# ─── Demo Harness ─────────────────────────────────────────────────────────────

def _seed_demo_data(engine: MonetizationDominanceEngine):
    now = datetime.now(timezone.utc)
    period = now.strftime("%Y-%m")
    renewal = (now + timedelta(days=365)).isoformat()

    # Subscriptions
    subs = [
        TenantSubscription("sub-001","t-fin-001",   "Global Financial Corp",    "plan-enterprise", SubscriptionTier.ENTERPRISE,   BillingCycle.ANNUAL,   85000, endpoints_licensed=10000, endpoints_active=8650, churn_risk_score=1.2, health_score=92.0, expansion_revenue=8500, renewal_date=renewal),
        TenantSubscription("sub-002","t-hc-001",    "Healthcare Enterprise",    "plan-enterprise", SubscriptionTier.ENTERPRISE,   BillingCycle.ANNUAL,   22000, endpoints_licensed=2500,  endpoints_active=2180, churn_risk_score=2.8, health_score=87.0, expansion_revenue=0,    renewal_date=renewal),
        TenantSubscription("sub-003","t-mfg-001",   "Manufacturing Group",      "plan-enterprise", SubscriptionTier.ENTERPRISE,   BillingCycle.ANNUAL,   56000, endpoints_licensed=6000,  endpoints_active=5850, churn_risk_score=1.8, health_score=95.0, expansion_revenue=5500, renewal_date=renewal),
        TenantSubscription("sub-004","t-gov-001",   "Government Agency",        "plan-enterprise", SubscriptionTier.ENTERPRISE,   BillingCycle.ANNUAL,   140000,endpoints_licensed=15000, endpoints_active=12200,churn_risk_score=0.5, health_score=98.0, expansion_revenue=0,    renewal_date=renewal),
        TenantSubscription("sub-005","t-retail-001","Retail Corporation",       "plan-pro",        SubscriptionTier.PROFESSIONAL, BillingCycle.MONTHLY,  4800,  endpoints_licensed=2000,  endpoints_active=1820, churn_risk_score=5.5, health_score=72.0, expansion_revenue=0,    renewal_date=(now+timedelta(days=30)).isoformat()),
        TenantSubscription("sub-006","t-mssp-001",  "MSSP Global Operations",   "plan-mssp",       SubscriptionTier.MSSP_PARTNER, BillingCycle.ANNUAL,   420000,endpoints_licensed=50000, endpoints_active=45800,churn_risk_score=0.8, health_score=96.0, expansion_revenue=42000,renewal_date=renewal),
    ]
    for s in subs:
        engine.create_subscription(s)

    # Usage Metering
    for sub in subs:
        engine.record_usage(UsageMeteringRecord(
            metering_id         = str(uuid.uuid4())[:8],
            tenant_id           = sub.tenant_id,
            period_start        = (now - timedelta(days=30)).isoformat(),
            period_end          = now.isoformat(),
            endpoints_measured  = sub.endpoints_active,
            events_total        = sub.endpoints_active * 800_000,
            api_calls           = sub.endpoints_active * 2400,
            replay_operations   = sub.endpoints_active // 10,
            graph_queries       = sub.endpoints_active * 120,
            ai_inferences       = sub.endpoints_active * 48,
            storage_tb          = sub.endpoints_active * 0.00002,
        ))

    # Revenue Streams
    revenue_data = [
        (RevenueStream.CTI_SUBSCRIPTION,        "t-fin-001",  28000),
        (RevenueStream.GRAPH_INTEL,             "t-fin-001",  18000),
        (RevenueStream.AI_RUNTIME_PROTECTION,   "t-fin-001",  12000),
        (RevenueStream.MALWARE_INTEL,           "t-fin-001",  8000),
        (RevenueStream.REPLAY_VALIDATION,       "t-fin-001",  6000),
        (RevenueStream.TELEMETRY_FEDERATION,    "t-fin-001",  13000),
        (RevenueStream.MSSP_LICENSING,          "t-mssp-001", 280000),
        (RevenueStream.SOC_AS_A_SERVICE,        "t-gov-001",  65000),
        (RevenueStream.ENTERPRISE_HUNT,         "t-gov-001",  28000),
        (RevenueStream.API_ACCESS,              "t-fin-001",  4500),
        (RevenueStream.PROFESSIONAL_SERVICES,   "t-mfg-001",  22000),
        (RevenueStream.OEM_LICENSING,           "t-mssp-001", 140000),
    ]
    for stream, tid, amount in revenue_data:
        engine.record_revenue(RevenueStreamRecord(
            record_id    = str(uuid.uuid4())[:8],
            stream       = stream,
            tenant_id    = tid,
            amount_usd   = amount,
            period       = period,
            is_recurring = stream not in (RevenueStream.PROFESSIONAL_SERVICES,),
        ))

    # SLA Contracts
    for sub in subs:
        contract = SLAContract(
            sla_id              = str(uuid.uuid4())[:8],
            tenant_id           = sub.tenant_id,
            uptime_sla_pct      = 99.95 if sub.tier == SubscriptionTier.ENTERPRISE else 99.9,
            mttd_sla_minutes    = 10,
            mttr_sla_minutes    = 60,
            api_latency_sla_ms  = 200,
            data_retention_sla  = 365,
            support_response_h  = 1 if sub.tier == SubscriptionTier.ENTERPRISE else 4,
            penalty_per_breach  = sub.mrr_usd * 0.05,
            measured_uptime     = 99.97,
            measured_mttd       = 8.2,
            measured_latency    = 145,
        )
        contract.evaluate_compliance()
        engine.register_sla(contract)

    # API Metrics
    for sub in subs:
        engine.register_api_metrics(APIEconomyMetrics(
            tenant_id          = sub.tenant_id,
            period             = period,
            total_api_calls    = sub.endpoints_active * 2400,
            unique_endpoints   = 48,
            top_endpoints      = [
                {"path": "/v2/intel/feed",        "calls": sub.endpoints_active * 480},
                {"path": "/v2/graph/query",       "calls": sub.endpoints_active * 360},
                {"path": "/v2/replay/execute",    "calls": sub.endpoints_active * 120},
                {"path": "/v2/ai/inference",      "calls": sub.endpoints_active * 240},
                {"path": "/v2/malware/dossier",   "calls": sub.endpoints_active * 96},
            ],
            avg_response_ms    = 42.0,
            p99_response_ms    = 185.0,
            error_rate_pct     = 0.18,
            revenue_attributed = sub.mrr_usd * 0.12,
            rate_limit_hits    = max(0, sub.endpoints_active - 5000) * 2,
        ))


def run_demo() -> dict:
    engine = MonetizationDominanceEngine()
    _seed_demo_data(engine)
    report = engine.export_monetization_report()
    print(json.dumps(report["revenue_metrics"], indent=2))
    return report


if __name__ == "__main__":
    run_demo()
