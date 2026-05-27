"""
CYBERDUDEBIVASH® SENTINEL APEX — Phase 55
Global Scale Engine
Global telemetry federation, MSSP tenant scaling, distributed queue governance,
telemetry economics optimization, cloud cost governance, replay storage governance,
object lifecycle management, retention governance, distributed graph scaling,
hyperscale telemetry sustainability.
Production-grade. Hyperscale-ready. Infrastructure-economics sustainable.
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

class CloudProvider(Enum):
    AWS         = "aws"
    GCP         = "gcp"
    AZURE       = "azure"
    HYBRID      = "hybrid"
    ON_PREM     = "on_premises"

class StorageTier(Enum):
    HOT         = "hot"         # < 7 days  — NVMe SSD
    WARM        = "warm"        # 7–90 days — SSD
    COLD        = "cold"        # 90–365 days — HDD / object
    ARCHIVE     = "archive"     # > 365 days — glacier / tape

class QueueBackend(Enum):
    KAFKA           = "kafka"
    REDPANDA        = "redpanda"
    PULSAR          = "pulsar"
    AWS_KINESIS     = "aws_kinesis"
    AZURE_EVENT_HUB = "azure_event_hub"
    GCP_PUBSUB      = "gcp_pubsub"

class ScalingPolicy(Enum):
    HORIZONTAL_SCALE    = "horizontal_scale_out"
    VERTICAL_SCALE      = "vertical_scale_up"
    AUTO_SCALE          = "auto_scale"
    PREDICTIVE_SCALE    = "predictive_scale"
    COST_OPTIMIZED      = "cost_optimized_scale"

class TelemetryTier(Enum):
    REAL_TIME       = "real_time"       # < 100ms latency
    NEAR_REAL_TIME  = "near_real_time"  # < 5s
    BATCH           = "batch"           # minutes–hours
    OFFLINE         = "offline"         # replay only


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class TenantInfraConfig:
    tenant_id:          str
    tenant_name:        str
    region:             str
    cloud_provider:     CloudProvider
    endpoint_count:     int
    events_per_day:     int             # telemetry events/day
    retention_days:     int
    queue_backend:      QueueBackend
    storage_tier_policy: dict[str, int] = field(default_factory=dict)   # tier -> days
    dedicated_cluster:  bool            = False
    sla_tier:           str             = "standard"        # standard / premium / enterprise
    monthly_cost_usd:   float           = 0.0
    allocated_vcpu:     int             = 0
    allocated_ram_gb:   int             = 0
    allocated_storage_tb: float         = 0.0
    created_at:         str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def events_per_second(self) -> float:
        return round(self.events_per_day / 86400, 2)

    @property
    def storage_estimate_tb(self) -> float:
        bytes_per_event = 512
        total_bytes = self.events_per_day * bytes_per_event * self.retention_days
        return round(total_bytes / (1024**4), 4)


@dataclass
class DistributedQueueConfig:
    cluster_id:         str
    backend:            QueueBackend
    region:             str
    broker_count:       int
    partition_count:    int
    replication_factor: int
    throughput_mbps:    float
    consumer_groups:    int
    retention_hours:    int
    compression:        str             = "lz4"
    encryption:         bool            = True
    multi_zone:         bool            = True
    max_lag_seconds:    float           = 0.0
    bytes_in_rate_mbps: float           = 0.0
    bytes_out_rate_mbps: float          = 0.0

    @property
    def utilization_pct(self) -> float:
        return round((self.bytes_in_rate_mbps / max(self.throughput_mbps, 1)) * 100, 2)


@dataclass
class StorageLifecyclePolicy:
    policy_id:          str
    tenant_id:          str
    hot_days:           int             = 7
    warm_days:          int             = 83
    cold_days:          int             = 275
    archive_days:       int             = 999
    auto_delete_days:   int             = 0        # 0 = never delete
    compression:        str             = "zstd"
    deduplication:      bool            = True
    cost_per_tb_hot:    float           = 230.0    # USD/month
    cost_per_tb_warm:   float           = 80.0
    cost_per_tb_cold:   float           = 25.0
    cost_per_tb_archive: float          = 4.0
    created_at:         str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def monthly_cost(self, hot_tb: float, warm_tb: float, cold_tb: float, archive_tb: float) -> float:
        return round(
            hot_tb     * self.cost_per_tb_hot +
            warm_tb    * self.cost_per_tb_warm +
            cold_tb    * self.cost_per_tb_cold +
            archive_tb * self.cost_per_tb_archive,
            2
        )


@dataclass
class CloudCostReport:
    report_id:          str
    period_start:       str
    period_end:         str
    tenant_id:          str
    compute_cost_usd:   float
    storage_cost_usd:   float
    network_cost_usd:   float
    queue_cost_usd:     float
    total_cost_usd:     float           = 0.0
    cost_per_event:     float           = 0.0
    cost_per_endpoint:  float           = 0.0
    events_processed:   int             = 0
    endpoints_covered:  int             = 0
    optimization_recommendations: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.total_cost_usd = round(
            self.compute_cost_usd + self.storage_cost_usd +
            self.network_cost_usd + self.queue_cost_usd, 2
        )
        if self.events_processed > 0:
            self.cost_per_event = round(self.total_cost_usd / self.events_processed * 1_000_000, 4)  # per million
        if self.endpoints_covered > 0:
            self.cost_per_endpoint = round(self.total_cost_usd / self.endpoints_covered, 2)


@dataclass
class GraphScalingConfig:
    cluster_id:         str
    node_count:         int
    edge_count:         int
    shard_count:        int
    replication_factor: int
    query_latency_p50:  float   # ms
    query_latency_p99:  float   # ms
    write_throughput:   int     # edges/second
    read_throughput:    int     # queries/second
    storage_gb:         float
    backend:            str     = "neo4j"    # neo4j / tigergraph / memgraph / neptune
    distributed:        bool    = True
    cache_hit_rate:     float   = 0.0

    @property
    def avg_degree(self) -> float:
        return round((2 * self.edge_count) / max(self.node_count, 1), 2)

    @property
    def scalability_score(self) -> float:
        latency_score = max(0, 100 - self.query_latency_p99 / 10)
        throughput_score = min(100, self.read_throughput / 10)
        cache_score = self.cache_hit_rate * 100
        return round((latency_score * 0.4 + throughput_score * 0.4 + cache_score * 0.2), 2)


@dataclass
class FederationGateway:
    gateway_id:         str
    region:             str
    tenant_ids:         list[str]
    ingest_rate_eps:    float       # events per second
    max_eps:            float
    active_connections: int
    protocol:           str         = "grpc"     # grpc / kafka / websocket
    tls_enabled:        bool        = True
    auth_method:        str         = "mtls"
    latency_ms:         float       = 0.0
    uptime_pct:         float       = 99.9

    @property
    def utilization_pct(self) -> float:
        return round((self.ingest_rate_eps / max(self.max_eps, 1)) * 100, 2)

    @property
    def headroom_eps(self) -> float:
        return max(0.0, self.max_eps - self.ingest_rate_eps)


@dataclass
class TelemetryEconomicsModel:
    model_id:           str
    total_tenants:      int
    total_endpoints:    int
    events_per_day:     int
    storage_tb:         float
    monthly_infra_cost: float
    monthly_revenue:    float
    gross_margin_pct:   float       = 0.0
    cost_per_endpoint_monthly: float = 0.0
    revenue_per_endpoint_monthly: float = 0.0
    break_even_tenants: int         = 0
    computed_at:        str         = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if self.monthly_revenue > 0:
            self.gross_margin_pct = round((self.monthly_revenue - self.monthly_infra_cost) / self.monthly_revenue * 100, 2)
        if self.total_endpoints > 0:
            self.cost_per_endpoint_monthly = round(self.monthly_infra_cost / self.total_endpoints, 4)
            self.revenue_per_endpoint_monthly = round(self.monthly_revenue / self.total_endpoints, 4)
        if self.total_tenants > 0:
            revenue_per_tenant = self.monthly_revenue / self.total_tenants
            cost_per_tenant    = self.monthly_infra_cost / self.total_tenants
            self.break_even_tenants = max(1, math.ceil(self.monthly_infra_cost / max(revenue_per_tenant, 1)))


# ─── Global Scale Engine ──────────────────────────────────────────────────────

class GlobalScaleEngine:
    """
    Phase 55 — Global Scale Engine.
    Manages global telemetry federation, MSSP tenant scaling,
    distributed queue governance, telemetry economics, cloud cost governance,
    replay/object lifecycle management, distributed graph scaling.
    """

    def __init__(self):
        self._tenants:          dict[str, TenantInfraConfig]        = {}
        self._queue_clusters:   dict[str, DistributedQueueConfig]   = {}
        self._lifecycle_policies: dict[str, StorageLifecyclePolicy] = {}
        self._cost_reports:     list[CloudCostReport]               = []
        self._graph_configs:    dict[str, GraphScalingConfig]       = {}
        self._federation_gateways: dict[str, FederationGateway]     = {}
        self._economics:        Optional[TelemetryEconomicsModel]   = None
        self._initialized       = datetime.now(timezone.utc).isoformat()

    # ── Tenant Management ─────────────────────────────────────────────────

    def provision_tenant(self, config: TenantInfraConfig) -> dict:
        self._tenants[config.tenant_id] = config
        return {
            "tenant_id":        config.tenant_id,
            "region":           config.region,
            "cloud":            config.cloud_provider.value,
            "events_per_day":   config.events_per_day,
            "storage_estimate": f"{config.storage_estimate_tb} TB",
            "provisioned_at":   config.created_at,
        }

    def get_global_tenant_summary(self) -> dict:
        if not self._tenants:
            return {"status": "no_tenants"}

        total_endpoints = sum(t.endpoint_count for t in self._tenants.values())
        total_events    = sum(t.events_per_day for t in self._tenants.values())
        total_storage   = sum(t.storage_estimate_tb for t in self._tenants.values())
        total_cost      = sum(t.monthly_cost_usd for t in self._tenants.values())

        by_region: dict[str, int] = defaultdict(int)
        by_cloud:  dict[str, int] = defaultdict(int)
        by_sla:    dict[str, int] = defaultdict(int)
        for t in self._tenants.values():
            by_region[t.region]               += 1
            by_cloud[t.cloud_provider.value]   += 1
            by_sla[t.sla_tier]                 += 1

        return {
            "total_tenants":            len(self._tenants),
            "total_endpoints":          total_endpoints,
            "total_events_per_day":     total_events,
            "total_events_per_second":  round(total_events / 86400, 2),
            "estimated_storage_tb":     round(total_storage, 4),
            "total_monthly_cost_usd":   round(total_cost, 2),
            "by_region":                dict(by_region),
            "by_cloud":                 dict(by_cloud),
            "by_sla_tier":              dict(by_sla),
        }

    # ── Queue Governance ───────────────────────────────────────────────────

    def register_queue_cluster(self, config: DistributedQueueConfig) -> dict:
        self._queue_clusters[config.cluster_id] = config
        return {
            "cluster_id":       config.cluster_id,
            "backend":          config.backend.value,
            "region":           config.region,
            "throughput_mbps":  config.throughput_mbps,
            "utilization_pct":  config.utilization_pct,
        }

    def get_queue_health(self) -> dict:
        if not self._queue_clusters:
            return {"status": "no_clusters"}

        total_throughput  = sum(c.throughput_mbps for c in self._queue_clusters.values())
        avg_utilization   = statistics.mean(c.utilization_pct for c in self._queue_clusters.values())
        overloaded        = [c.cluster_id for c in self._queue_clusters.values() if c.utilization_pct > 80]
        total_partitions  = sum(c.partition_count for c in self._queue_clusters.values())

        return {
            "total_clusters":           len(self._queue_clusters),
            "total_throughput_mbps":    round(total_throughput, 2),
            "avg_utilization_pct":      round(avg_utilization, 2),
            "overloaded_clusters":      overloaded,
            "total_partitions":         total_partitions,
            "healthy_clusters":         len(self._queue_clusters) - len(overloaded),
        }

    # ── Storage Lifecycle ─────────────────────────────────────────────────

    def set_lifecycle_policy(self, policy: StorageLifecyclePolicy) -> dict:
        self._lifecycle_policies[policy.tenant_id] = policy
        return {
            "policy_id":        policy.policy_id,
            "tenant_id":        policy.tenant_id,
            "hot_days":         policy.hot_days,
            "total_retention":  policy.hot_days + policy.warm_days + policy.cold_days,
        }

    def compute_storage_costs(self, tenant_id: str, events_per_day: int) -> dict:
        policy = self._lifecycle_policies.get(tenant_id)
        if not policy:
            return {"error": "policy_not_found"}

        bytes_per_event = 512
        events_to_tb = lambda days: (events_per_day * bytes_per_event * days) / (1024**4)

        hot_tb      = events_to_tb(policy.hot_days)
        warm_tb     = events_to_tb(policy.warm_days)
        cold_tb     = events_to_tb(policy.cold_days)
        archive_tb  = events_to_tb(policy.archive_days) if policy.auto_delete_days == 0 else 0

        monthly_cost = policy.monthly_cost(hot_tb, warm_tb, cold_tb, archive_tb)

        return {
            "tenant_id":        tenant_id,
            "hot_tb":           round(hot_tb, 6),
            "warm_tb":          round(warm_tb, 6),
            "cold_tb":          round(cold_tb, 6),
            "archive_tb":       round(archive_tb, 6),
            "total_tb":         round(hot_tb + warm_tb + cold_tb + archive_tb, 6),
            "monthly_cost_usd": monthly_cost,
        }

    # ── Cloud Cost Governance ─────────────────────────────────────────────

    def submit_cost_report(self, report: CloudCostReport) -> dict:
        self._cost_reports.append(report)
        return {
            "report_id":        report.report_id,
            "tenant_id":        report.tenant_id,
            "total_cost_usd":   report.total_cost_usd,
            "cost_per_million_events": report.cost_per_event,
            "recommendations":  len(report.optimization_recommendations),
        }

    def get_cost_analytics(self) -> dict:
        if not self._cost_reports:
            return {"status": "no_data"}

        total_cost    = sum(r.total_cost_usd for r in self._cost_reports)
        avg_cost      = statistics.mean(r.total_cost_usd for r in self._cost_reports)
        by_component  = {
            "compute":  sum(r.compute_cost_usd for r in self._cost_reports),
            "storage":  sum(r.storage_cost_usd for r in self._cost_reports),
            "network":  sum(r.network_cost_usd for r in self._cost_reports),
            "queue":    sum(r.queue_cost_usd   for r in self._cost_reports),
        }
        most_expensive = max(by_component, key=by_component.get)
        savings_opportunities = []
        if by_component["storage"] / total_cost > 0.4:
            savings_opportunities.append("Move cold data to archive tier (estimated 60% storage savings)")
        if by_component["compute"] / total_cost > 0.5:
            savings_opportunities.append("Enable spot/preemptible compute for non-critical workloads")
        if by_component["network"] / total_cost > 0.2:
            savings_opportunities.append("Enable data compression at ingestion (estimated 40% network savings)")

        return {
            "total_spend_usd":      round(total_cost, 2),
            "avg_monthly_usd":      round(avg_cost, 2),
            "by_component_usd":     {k: round(v, 2) for k, v in by_component.items()},
            "highest_cost_component": most_expensive,
            "savings_opportunities": savings_opportunities,
            "cost_per_million_events": round(statistics.mean(r.cost_per_event for r in self._cost_reports), 4),
        }

    # ── Graph Scaling ─────────────────────────────────────────────────────

    def register_graph_config(self, config: GraphScalingConfig) -> dict:
        self._graph_configs[config.cluster_id] = config
        return {
            "cluster_id":       config.cluster_id,
            "backend":          config.backend,
            "scalability_score":config.scalability_score,
            "avg_degree":       config.avg_degree,
            "p99_latency_ms":   config.query_latency_p99,
        }

    def get_graph_scaling_health(self) -> dict:
        if not self._graph_configs:
            return {"status": "no_clusters"}

        configs = list(self._graph_configs.values())
        total_nodes = sum(c.node_count for c in configs)
        total_edges = sum(c.edge_count for c in configs)
        avg_score   = statistics.mean(c.scalability_score for c in configs)
        avg_p99     = statistics.mean(c.query_latency_p99 for c in configs)

        return {
            "total_graph_clusters": len(configs),
            "total_nodes":          total_nodes,
            "total_edges":          total_edges,
            "avg_scalability_score":round(avg_score, 2),
            "avg_p99_latency_ms":   round(avg_p99, 2),
            "total_storage_gb":     round(sum(c.storage_gb for c in configs), 2),
            "distributed_clusters": sum(1 for c in configs if c.distributed),
        }

    # ── Federation Gateways ───────────────────────────────────────────────

    def register_gateway(self, gw: FederationGateway) -> dict:
        self._federation_gateways[gw.gateway_id] = gw
        return {
            "gateway_id":       gw.gateway_id,
            "region":           gw.region,
            "tenants":          len(gw.tenant_ids),
            "utilization_pct":  gw.utilization_pct,
            "headroom_eps":     gw.headroom_eps,
        }

    def get_federation_summary(self) -> dict:
        if not self._federation_gateways:
            return {"status": "no_gateways"}

        total_eps   = sum(g.ingest_rate_eps for g in self._federation_gateways.values())
        max_eps     = sum(g.max_eps for g in self._federation_gateways.values())
        avg_uptime  = statistics.mean(g.uptime_pct for g in self._federation_gateways.values())
        tenants     = set(t for g in self._federation_gateways.values() for t in g.tenant_ids)
        saturated   = [g.gateway_id for g in self._federation_gateways.values() if g.utilization_pct > 85]

        return {
            "total_gateways":       len(self._federation_gateways),
            "total_ingest_eps":     round(total_eps, 2),
            "max_capacity_eps":     round(max_eps, 2),
            "global_utilization":   round(total_eps / max(max_eps, 1) * 100, 2),
            "avg_uptime_pct":       round(avg_uptime, 4),
            "total_tenants_served": len(tenants),
            "saturated_gateways":   saturated,
            "regions":              list(set(g.region for g in self._federation_gateways.values())),
        }

    # ── Telemetry Economics Model ─────────────────────────────────────────

    def compute_economics_model(self) -> TelemetryEconomicsModel:
        if not self._tenants:
            model = TelemetryEconomicsModel(
                model_id="econ-empty", total_tenants=0, total_endpoints=0,
                events_per_day=0, storage_tb=0, monthly_infra_cost=0, monthly_revenue=0,
            )
            self._economics = model
            return model

        total_endpoints = sum(t.endpoint_count for t in self._tenants.values())
        total_events    = sum(t.events_per_day for t in self._tenants.values())
        total_storage   = sum(t.storage_estimate_tb for t in self._tenants.values())
        total_cost      = sum(t.monthly_cost_usd for t in self._tenants.values())

        # Revenue model: $8/endpoint/month (standard), $15 (premium), $25 (enterprise)
        sla_prices = {"standard": 8.0, "premium": 15.0, "enterprise": 25.0}
        total_revenue = sum(
            t.endpoint_count * sla_prices.get(t.sla_tier, 8.0)
            for t in self._tenants.values()
        )

        model = TelemetryEconomicsModel(
            model_id        = str(uuid.uuid4())[:8],
            total_tenants   = len(self._tenants),
            total_endpoints = total_endpoints,
            events_per_day  = total_events,
            storage_tb      = round(total_storage, 4),
            monthly_infra_cost = round(total_cost, 2),
            monthly_revenue    = round(total_revenue, 2),
        )
        self._economics = model
        return model

    # ── Scaling Recommendations ───────────────────────────────────────────

    def generate_scaling_recommendations(self) -> list[dict]:
        recs = []
        tenant_summary = self.get_global_tenant_summary()
        queue_health   = self.get_queue_health()
        fed_summary    = self.get_federation_summary()
        graph_health   = self.get_graph_scaling_health()

        if "avg_utilization_pct" in queue_health and queue_health["avg_utilization_pct"] > 75:
            recs.append({
                "priority": "HIGH",
                "component": "Queue Clusters",
                "recommendation": "Scale queue cluster brokers by 50% — avg utilization above 75%",
                "estimated_cost_usd": 2800,
            })
        if "overloaded_clusters" in queue_health and queue_health["overloaded_clusters"]:
            recs.append({
                "priority": "CRITICAL",
                "component": "Queue",
                "recommendation": f"Immediate scaling required: {queue_health['overloaded_clusters']}",
                "estimated_cost_usd": 4500,
            })
        if "global_utilization" in fed_summary and fed_summary["global_utilization"] > 70:
            recs.append({
                "priority": "MEDIUM",
                "component": "Federation Gateways",
                "recommendation": "Deploy 2 additional gateway instances in high-traffic regions",
                "estimated_cost_usd": 1200,
            })
        if "avg_p99_latency_ms" in graph_health and graph_health["avg_p99_latency_ms"] > 200:
            recs.append({
                "priority": "HIGH",
                "component": "Graph Clusters",
                "recommendation": "Enable query result caching — P99 latency above SLA threshold",
                "estimated_cost_usd": 800,
            })

        return recs

    def export_scale_report(self) -> dict:
        economics = self.compute_economics_model()
        return {
            "meta": {
                "engine":       "GlobalScaleEngine",
                "phase":        55,
                "platform":     "SENTINEL APEX",
                "initialized":  self._initialized,
                "exported_at":  datetime.now(timezone.utc).isoformat(),
            },
            "tenant_summary":       self.get_global_tenant_summary(),
            "queue_health":         self.get_queue_health(),
            "federation_summary":   self.get_federation_summary(),
            "graph_scaling":        self.get_graph_scaling_health(),
            "cost_analytics":       self.get_cost_analytics(),
            "economics": {
                "total_tenants":        economics.total_tenants,
                "total_endpoints":      economics.total_endpoints,
                "monthly_cost_usd":     economics.monthly_infra_cost,
                "monthly_revenue_usd":  economics.monthly_revenue,
                "gross_margin_pct":     economics.gross_margin_pct,
                "cost_per_endpoint":    economics.cost_per_endpoint_monthly,
                "break_even_tenants":   economics.break_even_tenants,
            },
            "scaling_recommendations": self.generate_scaling_recommendations(),
        }


# ─── Demo Harness ─────────────────────────────────────────────────────────────

def _seed_demo_data(engine: GlobalScaleEngine):
    now = datetime.now(timezone.utc)

    # Tenants
    tenants = [
        TenantInfraConfig("t-fin-001",  "Global Financial Corp",    "us-east-1",    CloudProvider.AWS,   8500,  2_200_000_000, 365, QueueBackend.KAFKA,   {}, True,  "enterprise", 85000, 512, 2048, 180.0),
        TenantInfraConfig("t-hc-001",   "Healthcare Enterprise",     "us-west-2",    CloudProvider.AWS,   2100,  520_000_000,   180, QueueBackend.KAFKA,   {}, False, "premium",    22000, 128, 512,  42.0),
        TenantInfraConfig("t-mfg-001",  "Manufacturing Group",       "eu-west-1",    CloudProvider.AZURE, 5800,  1_400_000_000, 180, QueueBackend.AZURE_EVENT_HUB, {}, True, "enterprise", 56000, 256, 1024, 95.0),
        TenantInfraConfig("t-gov-001",  "Government Agency",         "us-gov-east",  CloudProvider.AWS,   12000, 3_800_000_000, 730, QueueBackend.KAFKA,   {}, True,  "enterprise", 140000,1024, 4096, 480.0),
        TenantInfraConfig("t-retail-01","Retail Corporation",        "ap-southeast-1",CloudProvider.GCP,  1800,  420_000_000,   90,  QueueBackend.GCP_PUBSUB, {}, False, "standard",  12000, 64,  256,  18.0),
        TenantInfraConfig("t-mssp-001", "MSSP Global Operations",    "multi-region", CloudProvider.HYBRID,45000, 12_000_000_000,365, QueueBackend.REDPANDA,{}, True,  "enterprise", 420000,2048, 8192, 2200.0),
    ]
    for t in tenants:
        engine.provision_tenant(t)

    # Queue Clusters
    queues = [
        DistributedQueueConfig("qc-kafka-us-001",  QueueBackend.KAFKA,    "us-east-1",  12, 2400, 3, 28000, 48, 168, bytes_in_rate_mbps=18500, bytes_out_rate_mbps=20800),
        DistributedQueueConfig("qc-kafka-eu-001",  QueueBackend.KAFKA,    "eu-west-1",  9,  1800, 3, 18000, 36, 168, bytes_in_rate_mbps=12400, bytes_out_rate_mbps=14200),
        DistributedQueueConfig("qc-rp-global-001", QueueBackend.REDPANDA, "multi",      6,  1200, 3, 35000, 24, 72,  bytes_in_rate_mbps=28000, bytes_out_rate_mbps=32000),
        DistributedQueueConfig("qc-azure-eu-001",  QueueBackend.AZURE_EVENT_HUB,"eu-west-1",4,800,2,8000, 16,  48,  bytes_in_rate_mbps=5200,  bytes_out_rate_mbps=5800),
    ]
    for q in queues:
        engine.register_queue_cluster(q)

    # Lifecycle Policies
    for t in tenants:
        engine.set_lifecycle_policy(StorageLifecyclePolicy(
            policy_id      = str(uuid.uuid4())[:8],
            tenant_id      = t.tenant_id,
            hot_days       = 7 if t.sla_tier == "enterprise" else 3,
            warm_days      = 83 if t.sla_tier in ("enterprise","premium") else 27,
            cold_days      = 275,
            archive_days   = 999 if t.retention_days >= 365 else 0,
            auto_delete_days = 0 if t.retention_days >= 365 else t.retention_days,
        ))

    # Cost Reports
    for t in tenants[:3]:
        engine.submit_cost_report(CloudCostReport(
            report_id       = str(uuid.uuid4())[:8],
            period_start    = (now - timedelta(days=30)).isoformat(),
            period_end      = now.isoformat(),
            tenant_id       = t.tenant_id,
            compute_cost_usd   = t.monthly_cost_usd * 0.45,
            storage_cost_usd   = t.monthly_cost_usd * 0.32,
            network_cost_usd   = t.monthly_cost_usd * 0.13,
            queue_cost_usd     = t.monthly_cost_usd * 0.10,
            events_processed   = t.events_per_day * 30,
            endpoints_covered  = t.endpoint_count,
            optimization_recommendations = [
                "Enable S3 Intelligent-Tiering for cold data",
                "Implement Zstandard compression (est. 45% reduction)",
            ],
        ))

    # Graph Clusters
    engine.register_graph_config(GraphScalingConfig(
        "graph-neo4j-001", 12_400_000, 48_200_000, 64, 3, 12.0, 85.0,
        125000, 48000, 2840.0, "neo4j", True, 0.78,
    ))
    engine.register_graph_config(GraphScalingConfig(
        "graph-tg-001",    8_200_000, 32_100_000, 48, 3,  8.0, 62.0,
        185000, 72000, 1920.0, "tigergraph", True, 0.82,
    ))

    # Federation Gateways
    gateways = [
        FederationGateway("gw-us-east-001",   "us-east-1",     ["t-fin-001","t-gov-001","t-retail-01"], 285000,400000,1240,"grpc",True,"mtls", 4.2, 99.97),
        FederationGateway("gw-eu-west-001",   "eu-west-1",     ["t-mfg-001","t-hc-001"],               145000,200000, 680,"grpc",True,"mtls", 5.8, 99.95),
        FederationGateway("gw-global-001",    "multi-region",  ["t-mssp-001"],                          520000,750000,2800,"grpc",True,"mtls", 6.1, 99.99),
    ]
    for g in gateways:
        engine.register_gateway(g)


def run_demo() -> dict:
    engine = GlobalScaleEngine()
    _seed_demo_data(engine)
    report = engine.export_scale_report()
    print(json.dumps(report["economics"], indent=2))
    return report


if __name__ == "__main__":
    run_demo()
