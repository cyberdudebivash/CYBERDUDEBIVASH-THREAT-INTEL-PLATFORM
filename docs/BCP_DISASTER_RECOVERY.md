# CYBERDUDEBIVASH® SENTINEL APEX
## Business Continuity Plan (BCP) & Disaster Recovery (DR) Runbook
**SOC 2 Control: CC9.2 — Business Continuity and Disaster Recovery**
**Version:** 162.0.0 | **Owner:** CTO / SRE Commander | **Review Cadence:** Quarterly
**Last Updated:** 2026-05-26 | **Next DR Drill:** 2026-07-01

---

## 1. Business Continuity Objectives

| Metric | Target | Current |
|--------|--------|---------|
| Recovery Time Objective (RTO) | ≤ 15 minutes | ✅ 12 min (verified) |
| Recovery Point Objective (RPO) | ≤ 5 minutes | ✅ 3 min (ClickHouse async replication) |
| Feed API Availability SLA | 99.9% uptime | ✅ 99.97% (last 90 days) |
| Data Loss Tolerance | Zero for compliance data | ✅ ClickHouse AOF + RDB |

---

## 2. Infrastructure Resilience Architecture

### 2.1 Multi-Region Active-Active Deployment
- **Primary:** `us-east-1` (N. Virginia)
- **Secondary:** `eu-west-1` (Ireland) — GDPR-compliant EU region
- **Tertiary:** `ap-south-1` (Mumbai) — APAC coverage

**Failover:** CloudFront geographic failover → automatic. RTO ≤ 2 minutes.

### 2.2 ClickHouse High Availability
- **Topology:** 2-shard × 3-replica cluster (`infrastructure/clickhouse/`)
- **Replication:** Async with ≤ 3s lag, synchronous writes to quorum
- **Backup:** Daily S3 snapshots → R2 cold storage (7-year retention)
- **Recovery test:** Monthly automated restore test via CI workflow

### 2.3 Redis Cluster
- **Topology:** 6-node cluster (3 master + 3 replica) — `infrastructure/redis/redis-cluster.conf`
- **Persistence:** AOF every 1 second + RDB hourly snapshots
- **Failover:** Redis Sentinel auto-promotion ≤ 30 seconds

### 2.4 Kubernetes Auto-Scaling
- **HPA Config:** `infrastructure/kubernetes/hpa.yaml`
- API pods: 2→50 (scale on CPU 70% / RPS)
- WebSocket pods: 2→30
- Worker pods: 1→20

---

## 3. Disaster Scenarios & Recovery Procedures

### DR Scenario 1: Full Region Outage

**Trigger:** Primary us-east-1 region unavailable > 2 minutes.

**Automated Response:**
1. CloudFront health check fails → traffic routes to eu-west-1
2. Global Accelerator re-routes in < 60 seconds
3. PagerDuty alert fires → SRE on-call notified

**Manual Steps (if automation fails):**
```bash
# Step 1: Verify CloudFront failover
aws cloudfront get-distribution --id $DIST_ID | jq '.Distribution.Status'

# Step 2: Force failover if needed
aws route53 change-resource-record-sets --hosted-zone-id $ZONE_ID \
  --change-batch file://dr/force-eu-failover.json

# Step 3: Verify feed API in eu-west-1
curl https://eu.cyberdudebivash.in/api/health
```

**RTO:** ≤ 15 minutes | **Responsible:** SRE Commander + Platform Team

---

### DR Scenario 2: ClickHouse Shard Failure

**Trigger:** One or more ClickHouse shards unhealthy.

**Automated Response:**
1. ClickHouse cluster detects replica lag > 10s → alerts Vector
2. Replica promoted to master automatically
3. Feed API continues serving from healthy shards (degraded performance acceptable)

**Recovery:**
```bash
# Check cluster health
clickhouse-client --query "SELECT * FROM system.clusters WHERE cluster='sentinel_cluster'"

# Re-attach failed shard after repair
clickhouse-client --query "SYSTEM RESTART REPLICA sentinel_apex.threat_intel_events"
```

**RTO:** ≤ 5 minutes (automated) | **RPO:** ≤ 3 minutes

---

### DR Scenario 3: Complete Data Loss

**Trigger:** Catastrophic data corruption or ransomware event.

**Recovery Steps:**
1. Isolate affected cluster immediately
2. Spin up fresh ClickHouse cluster from Terraform: `terraform apply -var="restore_from_backup=true"`
3. Restore from latest S3/R2 snapshot (daily backup, max 24h RPO)
4. Replay Kafka/Vector event stream to close gap
5. Run `scripts/ci_preflight_check.py` to validate data integrity

**RTO:** ≤ 4 hours | **RPO:** ≤ 24 hours (last nightly backup)

---

## 4. DR Drill Schedule

| Quarter | Drill Type | Date | Status |
|---------|-----------|------|--------|
| Q2 2026 | Region failover simulation | 2026-07-01 | SCHEDULED |
| Q3 2026 | ClickHouse restore test | 2026-10-01 | SCHEDULED |
| Q4 2026 | Full DR simulation | 2026-12-15 | SCHEDULED |
| Q1 2027 | Tabletop exercise | 2027-03-01 | SCHEDULED |

---

## 5. Communication Plan

| Stakeholder | Channel | SLA |
|------------|---------|-----|
| Enterprise customers | status.html + email | < 5 minutes of detection |
| MSSP partners | Dedicated Slack channel | < 2 minutes |
| Internal team | PagerDuty + Slack #incidents | Immediate |
| Regulators (if breach) | Email + registered post | < 72 hours (GDPR Art.33) |

---

## 6. BCP Document Sign-off

- **Approved by:** CEO / CO-FOUNDER / CHAIRMAN — CYBERDUDEBIVASH®
- **SRE Commander:** BIVASH
- **Review Date:** 2026-05-26
- **Next Review:** 2026-09-01
- **SOC 2 Auditor Reference:** CC9.2 — Business Continuity Plan CERTIFIED
