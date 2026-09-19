# CURRENT PRODUCTION TRUTH — SENTINEL APEX SUPER AGENT SWARM

**Audit date:** 2026-09-20  
**Audited branch:** `origin/main`  
**Audited HEAD:** `91047d8538e8b5ae5edeb1ae7f9a2ca2e3b5ea82`  
**SWARM version:** `4.46.5`  
**Protocol:** `cdb.swarm.v1`

This document is source-first. Historical reports are treated as evidence only when the current source still supports the finding.

## CURRENT

- SWARM is a real Cloudflare Worker with production routes for `/swarm/*` and `/api/swarm/*`.
- `CANONICAL_GATEWAY` service binding is configured to `sentinel-apex-gateway`.
- `SWARM_MISSIONS_KV` is configured for durable mission records/history.
- The customer console uses a same-origin external browser controller (`/swarm/app.js`) and a restrictive CSP.
- API credentials remain browser-memory only; the SWARM controller contains no localStorage/sessionStorage credential persistence.
- Mission execution uses a real SSE response and backend events are the source of agent/mission state.
- The canonical correlation call is mesh-certified through the intel-gateway APEX mesh boundary.
- Paid mesh admission accepts PRO / ENTERPRISE / MSSP and fails closed for non-customer tiers.
- API-key subscription lifecycle enforcement rejects expired/cancelled/refunded/suspended records and unknown subscription states.
- IOC refanging is implemented conservatively server-side and original input is retained in evidence when changed.
- Specialist agents emit first-class `SKIPPED` when dependency input is absent; no fake RUNNING transition is emitted for those skips.
- Risk Synthesizer fuses completed/skipped/denied/failed outcomes and optionally adds a real backend LLM narrative.
- Idempotent mission dispatch exists for caller-supplied `X-Request-ID`.
- Mission history is list-scoped by a stable, non-reversible credential partition.
- Mission read-back and Markdown / JSON / STIX 2.1 export exist.
- V4.46.5 STIX Bundle shape and top-level custom `x_sentinel_*` properties are corrected.
- Centralized intel-gateway CORS policy exists in `workers/intel-gateway/src/cors-policy.js`; old blanket-wildcard findings are stale for authenticated/internal routes.
- Commercial contract authority exists at `config/commercial-contract.json`.
- Canonical daily quotas are enforced in intel-gateway for FREE / PRO / ENTERPRISE / MSSP.
- Razorpay and Gumroad are the approved live payment paths; Stripe is not part of this mission.

## FIXED

- Browser-controller bootstrap failure introduced in V4.46.2 was fixed in V4.46.3.
- Back-to-platform navigation was added in V4.46.4.
- Idle UI truth semantics were corrected in V4.46.5: fabric/SSE are DORMANT before a mission.
- Conditional DAG skip semantics were corrected in V4.46.5.
- STIX 2.1 Bundle/custom-property interoperability defects were corrected in V4.46.5.
- Authenticated/admin CORS is now centrally classified rather than universally wildcarded.
- Paid API-key expiry enforcement is enabled in the canonical commercial path.
- Pricing authority is now explicitly centralized around the commercial contract and checked for drift.

## PARTIAL

- Tenant/customer isolation: history listing is credential-partitioned, but direct mission lookup/report export currently checks only that *some* credential is present; it does not prove the caller owns the requested mission ID. Random UUID mission IDs reduce discoverability but are not an authorization boundary.
- Recovery/reconnection: durable terminal mission read-back exists, but there is no persisted ordered in-flight event journal or `after=<sequence>` replay endpoint. A page refresh cannot truthfully reattach to the original in-memory SSE stream.
- Enterprise identity: API-key/JWT commercial identity exists; granular organization-level SWARM RBAC is not established for this feature.
- SSO/OIDC exists elsewhere in intel-gateway routing, but SWARM does not currently map a documented organization role model to mission permissions.
- Audit logging exists in intel-gateway, but SWARM-specific mission authorization/read/export events are not yet a complete dedicated audit trail.
- Backup/rollback tooling exists, but current BCP documentation states that an end-to-end restore drill has not yet been proven and measured.
- Dependency/SBOM governance exists, but historical vulnerability counts must be re-run before any new release decision.

## OPEN

### P0

1. **Canonical paid-entitlement preflight**
   - No `POST /api/swarm/preflight` exists.
   - The UI can begin launch UX before discovering expired/suspended/cancelled/under-tier status through the mission path.
   - Must use canonical intel-gateway auth/subscription/tier authority; client syntax checks are not authoritative.

2. **Direct mission ownership authorization**
   - `GET /api/swarm/mission/:id` and `.../report` require a credential but do not verify that the mission belongs to that credential partition.
   - Must be fixed before enterprise multi-customer exposure.

3. **Mission recovery**
   - No event journal/cursor endpoint exists.
   - Implement maximum truthful recovery with existing KV; do not claim lossless realtime replay.

4. **Batch/multi-IOC**
   - No bounded multi-IOC parent/child mission API exists.
   - Current workflow is single IOC only.

5. **Payment → entitlement → SWARM certification**
   - Existing components exist, but the complete Razorpay/Gumroad-to-live-SWARM chain must be re-certified end to end with current source and non-destructive payment testing.

### P1

- Formal agent DAG metadata surfaced to UI.
- Enterprise access-model documentation / truthful RBAC boundary.
- Current SSO/SAML/OIDC support matrix.
- Current dependency/supply-chain audit and deterministic lockfile review.
- Safe non-production restore drill.
- Secret rotation metadata governance.
- Customer API-key rotation/revocation behavior across SWARM mission history.
- Customer data/retention documentation updated for submitted private/internal IOCs.
- Fortune-500 deployment-mode documentation for hosted SaaS/API and SIEM/SOAR integrations.
- Bounded performance/scale certification.
- Customer-safe normalized error contract.

## STALE DOCUMENTATION

The following historical statements must not be used as current release evidence without re-verification:

- blanket wildcard CORS on all intel-gateway authenticated/admin responses;
- old SWARM versions below 4.46.5;
- historical DR descriptions of AWS/Kubernetes/Redis/ClickHouse/multi-region infrastructure;
- historical dependency vulnerability counts;
- any document claiming SOC 2 / ISO 27001 certification;
- any document implying independent penetration testing if none has occurred.

## NON-CODE EXTERNAL REQUIREMENT

The following cannot be completed by repository changes alone:

- independent SOC 2 audit/attestation;
- ISO 27001 certification;
- independent third-party penetration test;
- cyber liability insurance;
- legal review/execution of MSA/DPA terms;
- customer procurement/security approval;
- customer-specific allowlisting/network change;
- any new Cloudflare resource that requires account-level operator approval.

## IMMEDIATE RELEASE PRIORITY

1. Implement canonical entitlement preflight.
2. Close direct mission ownership authorization.
3. Add truthful durable recovery/resume.
4. Add bounded multi-IOC batch execution.
5. Re-certify payment/entitlement/commercial-contract integrity.
6. Re-run security/dependency/DR gates.
7. Only then issue a customer-segment release decision.
