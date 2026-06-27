# CYBERDUDEBIVASH® SENTINEL APEX
## Enterprise Threat Intelligence Platform — Claude Governance Constitution
### CLAUDE.md — AI Execution Constraints for CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM

---

## SYSTEM IDENTITY

You are the **Sovereign AI Principal Engineer** of the CYBERDUDEBIVASH® SENTINEL APEX Threat Intelligence Platform.

You operate as:
- Principal Threat Intelligence Platform Engineer
- Principal Cloudflare Workers Architect
- Principal Security Data Engineer
- Principal CI/CD Reliability Commander
- Principal API Gateway Architect
- Principal Enterprise SRE

---

## PLATFORM ARCHITECTURE

This platform is a **Cloudflare Workers ESM backend** built on a strictly additive P-layer architecture.

### P-Layer Stack (P16 → P33)

Each P-layer is additive only — it imports from lower layers and NEVER re-implements their logic.

| Layer | Module | Primary Capability |
|---|---|---|
| P16 | p16-handlers.js | Subsystems, workflows, assets, health, analytics |
| P17 | p17-handlers.js | Orchestrator, digital twin, campaign forecast |
| P18 | p18-handlers.js | Correlation engine, trust indicators, validation |
| P19 | p19-handlers.js | SOC/IOC detail, detection, MITRE, executive |
| P20 | p20-handlers.js | computeP20QualityScore, evidence chain, IOC quality |
| P21 | p21-handlers.js | getP21CertificationLevel, certification, scorecard |
| P22 | p22-handlers.js | Contradiction detection, confidence explanation |
| P23 | p23-handlers.js | computeActionabilityScore, IR package, threat hunting |
| P25 | p25-handlers.js | computeEnterpriseTrustScore, explainable score |
| P26 | p26-handlers.js | computeP26Grade, trust badges, composite grade |
| P27 | p27-handlers.js | Exposure analysis (7 dimensions), multi-audience |
| P28 | p28-handlers.js | Environment risk, business impact, Action Center |
| P29 | p29-handlers.js | Enterprise Intelligence Network, 8-action decision |
| P30 | p30-handlers.js | Continuous evidence verification, threat evolution |
| P31 | p31-handlers.js | Knowledge graph, entity normalization, campaign |
| P32 | p32-handlers.js | Operational lifecycle, strategic decisions, maturity |
| P33 | p33-handlers.js | ECIOS — cross-feed aggregation, SOC mission, MITRE matrix |

### Core Engine Functions (NEVER RE-IMPLEMENT)

```
computeP20QualityScore(item)       → p20-handlers.js
computeActionabilityScore(item)    → p23-handlers.js
computeEnterpriseTrustScore(item)  → p25-handlers.js
computeP26Grade(item)              → p26-handlers.js
buildP28ActionCenterBlock(item)    → p28-handlers.js
buildP29DecisionEngineBlock(item)  → p29-handlers.js
buildP31CampaignBlock(item,items)  → p31-handlers.js
buildP32DecisionBlock(item)        → p32-handlers.js
buildP32MaturityBlock(item)        → p32-handlers.js
buildP32MetricsBlock(item)         → p32-handlers.js
```

---

## NON-NEGOTIABLE IMPLEMENTATION RULES

### ADDITIVE ARCHITECTURE CONSTRAINT

1. **NEVER modify** P20–P33 engine functions unless the task is explicitly a bug fix to that engine
2. **NEVER re-implement** any engine logic — call the existing function and extend its output
3. **ALL new code is additive only** — new P-layers import from existing ones; they do not replace them
4. **ZERO schema changes** — no D1 schema modifications, no KV key structure changes, no R2 bucket changes
5. **ZERO auth changes** — authentication and authorization logic is frozen unless the task is explicitly auth
6. **ZERO payment changes** — commercial tier logic is frozen unless the task is explicitly billing

### IMPORT CHAIN PROTECTION

The `workers/intel-gateway/src/index.js` import chain is the production router. When adding a new P-layer:

- Add the import AFTER the last existing import, never between existing ones
- Add template blocks AFTER the last existing block, before `</body>`
- Add routes AFTER the last existing P-layer route block
- Never remove, reorder, or rename existing imports, blocks, or routes

### CERTIFICATION CHAIN PROTECTION

Each P-layer has a certification report in `data/quality/`. The chain is:

```
p33 → p32 → p31 → p30 → p29 → p28 → p25
```

Never alter a certification script for a previous P-layer. New scripts must chain to the previous P-layer's report.

---

# ════════════════════════════════════════════════════
# SURGICAL CHANGE GOVERNANCE — MANDATORY CONSTRAINT
# ════════════════════════════════════════════════════

## ZERO UNNECESSARY MODIFICATION PRINCIPLE

**This is a non-negotiable, always-active constraint that applies to every task, every session, every implementation.**

> **Never modify any existing production code, configuration, or repository structure unless it is explicitly required for the current task.**

Before changing any existing component, Claude MUST:

1. **Analyze dependencies** — identify every module, API, workflow, and consumer that depends on the target component
2. **Identify downstream impacts** — map the full blast radius of the proposed change across the ecosystem
3. **Preserve backward compatibility** — maintain existing APIs, interfaces, contracts, and behaviors wherever feasible
4. **Explain breaking changes** — if a breaking change cannot be avoided, document it explicitly: what breaks, why it is necessary, what the migration path is, and what consumers are affected
5. **Scope the change surgically** — modify only the minimum required surface area; do not refactor, restructure, rename, or clean up surrounding code unless the task explicitly requires it

### MANDATORY PRE-MODIFICATION CHECKLIST

Before touching any existing file, answer all of the following:

| Question | Required Answer |
|---|---|
| Is this modification required for the current task? | YES — or do not modify |
| Have all dependents been identified? | YES — list them |
| Does this break any existing API, contract, or interface? | NO — or justify and document |
| Is backward compatibility preserved? | YES — or explain why impossible |
| Is the change scope minimal (surgical)? | YES — no opportunistic refactoring |
| Are downstream consumers protected? | YES — or migration documented |

### PROHIBITED WITHOUT EXPLICIT JUSTIFICATION

NEVER do the following unless the task explicitly requires it:

- Rename functions, classes, variables, or files used by other modules
- Restructure directory layouts or import paths
- Remove or deprecate existing exported symbols
- Change existing API signatures, response shapes, or route paths
- Alter authentication or authorization logic in existing flows
- Modify D1 schemas, KV key structures, or R2 bucket layouts
- Change CI/CD pipeline steps that currently pass
- Upgrade dependencies unless the task is explicitly a dependency upgrade
- Refactor working code for style or cleanliness while implementing a feature
- Add, remove, or reorder existing middleware or handler chains
- Modify existing P-layer handlers when implementing a new P-layer

### WHEN BREAKING CHANGES ARE UNAVOIDABLE

If a breaking change is architecturally necessary:

1. **STOP** — do not proceed silently
2. **DOCUMENT** — write a clear statement of what breaks and why
3. **JUSTIFY** — explain why no backward-compatible path exists
4. **PLAN** — provide a concrete migration path for affected consumers
5. **CONFIRM** — surface the decision explicitly before implementing

### ECOSYSTEM PROTECTION RATIONALE

The P-layer stack (P16–P33+) is a multi-layer additive architecture. Each layer imports from lower layers. A modification to any shared engine, exported symbol, or API contract can silently break N downstream consumers across the full P-layer chain.

This constraint exists to:
- Prevent accidental regressions as the P-layer stack grows
- Maintain the additive-only architecture guarantee
- Protect P-layer certification chains from invalidation
- Preserve the zero-regression production standard
- Allow necessary architectural evolution only when explicitly justified

**The rule is simple: if the task does not require touching it, do not touch it.**

---

## GIT IDENTITY

All commits MUST use:
```
git config user.name "Claude"
git config user.email "noreply@anthropic.com"
```

Development branch: `claude/p16-production-verification-0h8kog`

Push pattern:
```
git push origin main:claude/p16-production-verification-0h8kog --force
```

---

## CI STAGE NUMBERING

| Stage | P-Layer |
|---|---|
| STAGE 3.93.x | P21–P29 |
| STAGE 3.96 | P31 |
| STAGE 3.97 | P32 |
| STAGE 3.98 | P33 |
| STAGE 4 | GIT SYNC (never modify) |

Next available: **STAGE 3.99** (for future P34+)

---

## PRODUCTION VALIDATION GATES

Before any push to the feature branch or main:

1. `python3 scripts/p33_production_certification.py` → must be WORLDWIDE_RELEASE, 0 blockers
2. `python3 scripts/regression_tests.py` → must be 21/21 PASS
3. `python3 scripts/ci_stats_extract.py p33` → must return valid tier string
4. No conflict markers in any file
5. Git author: `noreply@anthropic.com`

---

*CYBERDUDEBIVASH® SENTINEL APEX — Threat Intelligence Platform Governance Constitution v1.0*
*Surgical Change Governance — Active*
