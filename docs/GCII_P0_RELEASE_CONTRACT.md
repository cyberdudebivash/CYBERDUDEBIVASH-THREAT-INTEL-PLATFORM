# Global Critical Incident Intelligence — P0 release contract

Status: PROPOSED / NOT DEPLOYED. Scope: SENTINEL APEX Threat Intel and SOC.

## Safety invariants
- Never label an incident confirmed without an attributable primary-source statement or independently corroborated authoritative reporting.
- Preserve source URL, publisher, publication timestamp, retrieval timestamp, and exact claim-to-evidence mapping.
- Unknown is not zero. Suspected actor attribution is not confirmed attribution. Reported losses are not verified recovered losses.
- Never auto-publish or auto-enrich wallet addresses, domains, IPs or hashes as malicious without provenance and analyst validation.
- Fail closed on malformed input, stale feeds, source outage, schema mismatch or missing evidence.
- Do not overwrite existing CVE/CTI feeds, dashboards, billing, authentication, or production routes.

## Shared incident contract (v1)
Required fields: id, title, category, first_seen_utc, updated_utc, status, severity, confidence, sources, claims.
Status: investigating | confirmed | disputed | resolved.
Severity: informational | low | medium | high | critical.
Confidence: low | medium | high.
Each source: url, publisher, published_at_utc, retrieved_at_utc.
Each claim: text, source_urls, verification_state (reported | corroborated | confirmed | disputed).
Optional: affected_entities, observed_techniques, validated_indicators, estimated_impact, last_reviewed_utc.
Use stable incident identity and deterministic deduplication; updates must be idempotent.

## Pipeline
1. Collect bounded official disclosures, CERT advisories, reputable reporting, and blockchain investigation feeds through allowlisted HTTPS sources.
2. Validate schema, timestamps, size, content type, provenance and freshness; quarantine failures.
3. Cluster related reports by canonical event identity, not title substring alone.
4. Apply evidence gates and confidence scoring; escalate P0 only for credible critical impact.
5. Persist append-only source evidence and revision history; preserve incident lifecycle.
6. Publish a versioned read-only incident feed atomically with freshness metadata.
7. SOC consumes the same contract and exposes source links, status, last verified time, and evidence drawer.
8. Alert on new material changes, suppress duplicates and rate-limit noisy sources.

## Acceptance gates
- Positive: confirmed non-CVE breach appears in both Threat Intel and SOC with source traceability.
- Negative: rumor, stale source, missing URL, duplicate, malformed timestamp, fabricated IOC, and disputed attribution never surface as confirmed.
- Reliability: collector outage preserves last-known-good data with visible staleness; no false zero metrics.
- Security: no unsafe HTML injection, SSRF, unbounded fetches, leaked secrets, or unauthenticated write endpoints.
- Cost: bounded Cloudflare Worker/R2/KV/D1 requests and retention; explicit budget check before enabling schedules.
- Release: tests, preview validation, reviewed PR, manual deployment, live smoke checks and rollback proof required.

## Initial event
Binance October 2026: use as a verification test case only after independent authoritative source validation; never hardcode reported figures as live facts.
