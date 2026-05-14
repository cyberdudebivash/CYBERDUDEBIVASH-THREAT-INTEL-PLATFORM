# APEX Intelligence Upgrade v148.1 — Commit & Push Script
# Run from: C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM

Set-Location "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"

Write-Host "=== APEX Intelligence Upgrade v148.1 — Commit & Push ===" -ForegroundColor Cyan

# Stage the three modified files
git add agent/apex_intelligence_upgrade.py
git add agent/mitre_mapper.py
git add scripts/generate_intel_reports.py

Write-Host "Staged files:" -ForegroundColor Yellow
git status --short

# Commit
$msg = @"
feat(apex): APEX Intelligence Upgrade Engine v148.1 — World-Class CTI Transformation

MISSION: Transform ALL Sentinel APEX intelligence reports from AI-enriched automated
reports into world-class enterprise CTI dossiers — SOC-grade, analyst-grade,
enterprise-trusted, globally sellable, MSSP-ready, executive-ready.

NEW: agent/apex_intelligence_upgrade.py — Master CTI Engine (10 Intelligence Modules)
  - Module 1: IntelligenceNarrativeEngine — unique threat-specific technical narratives
    * 19 vulnerability class detectors (DoS, RCE, SQLi, XSS, path traversal, etc.)
    * Eliminates all generic 'Multi-stage; refer to IOC section' boilerplate
    * Context-aware attack surface, impact, escalation analysis per threat class
  - Module 2: ATTaCKOperationalizationEngine — deep ATT&CK with evidence
    * Full APEX_TECHNIQUE_REGISTRY: 80+ techniques with names, tactics, descriptions
    * Evidence-based justification for every mapped technique
    * Premium table with ATT&CK hyperlinks, confidence scoring, kill-chain stage
  - Module 3: AdversaryIntelligenceEngine — real actor profiling
    * Actor type, sophistication, motivation, targeting, infrastructure pattern
    * Contextual actor assessment replacing generic 'CDB-CVE-GEN' placeholder
    * Sector-adjacent threat actor correlation
  - Module 4: CampaignCorrelationEngine — operational campaign intelligence
    * Deterministic operation name derivation (OPERATION IRON-TIDE style)
    * Threat-specific campaign phase analysis (CVE, ransomware, phishing paths)
    * Escalation probability model (14-day horizon)
  - Module 5: IOCIntelligenceEngine — source URL suppression
    * Suppresses cvefeed.io, nvd.nist.gov and 40+ source domains from IOC table
    * Eliminates CVE IDs as primary IOC entries
  - Module 6: DetectionEngineeringEngine — technique-aware Sigma rules
    * Vulnerability-class-specific detection logic (not generic IOC string match)
    * DoS, SQLi, path traversal, RCE-specific detection patterns
  - Module 7: AIBrainEngine — visible, operationally credible AI intelligence
    * Replaces locked 'Full narrative unlocked for Enterprise' wall
    * Real predictive risk (14-day), escalation forecast, sector risk ranking
    * Next-action predictions, tactic chain visualization
  - Module 9: VisualIntelligenceEngine — threat-specific kill chains
    * 8 kill chain templates (RCE, DoS, SQLi, phishing, ransomware, etc.)
    * Replaces generic 4-phase kill chain with operationally accurate sequences
  - enrich_advisory() — master enrichment entry point

FIX: agent/mitre_mapper.py — eliminate 'Technique T1XXX' fallback (line 359)
  - Bare TTP strings (T1059, T1204.002) now resolve to real names via APEX registry
  - 'T1059' → 'Command and Scripting Interpreter' (Execution)
  - 'T1204.002' → 'Malicious File' (Execution)
  - 'T1190' → 'Exploit Public-Facing Application' (Initial Access)
  - Safe fallback chain: registry → mapping_db → ID as last resort

PATCH: scripts/generate_intel_reports.py — integrate upgrade engine
  - S5 Technical Analysis: apex_technical_narrative() replaces all boilerplate
  - S6 ATT&CK Mapping: render_ttps_premium() with evidence & ATT&CK hyperlinks
  - S9 Kill Chain: generate_kill_chain_html() with threat-specific phases
  - S11 Actor Profile: generate_actor_intelligence() with full adversary profile
  - S12 Campaign Intel: generate_campaign_intelligence() with operation names
  - S15 AI Insight: generate_ai_insight_premium() — visible AI content for all tiers
  - S18 Detection Pack: generate_enhanced_sigma() with technique-aware rules
  - CSS: apex-narrative, apex-intel-grid, apex-conf-high/med premium styles
  - Graceful fallback: if upgrade engine unavailable, original behavior preserved

PRODUCTION MANDATES: 0 regression | 0 syntax error | 0 runtime failure
  - All 3 modified files: python -m py_compile PASSED
  - Full smoke test suite: PASSED (resolve_technique, enrich_advisory,
    filter_operational_iocs, generate_technical_narrative, generate_kill_chain_html,
    generate_campaign_intelligence, generate_ai_insight_premium)
  - Backward compatible: pure additive enrichment, never raises, graceful fallback

VERSION: v148.1.0 — APEX Intelligence Upgrade Release
"@

git commit -m $msg

Write-Host ""
Write-Host "Pushing to remote..." -ForegroundColor Yellow
git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=== SUCCESS: APEX Intelligence Upgrade v148.1 committed & pushed ===" -ForegroundColor Green
    Write-Host "Files deployed:" -ForegroundColor Green
    Write-Host "  + agent/apex_intelligence_upgrade.py (NEW — Master CTI Engine)" -ForegroundColor Green
    Write-Host "  ~ agent/mitre_mapper.py (FIXED — T1XXX fallback eliminated)" -ForegroundColor Green
    Write-Host "  ~ scripts/generate_intel_reports.py (PATCHED — 7 sections upgraded)" -ForegroundColor Green
} else {
    Write-Host "Push failed — check git remote and credentials" -ForegroundColor Red
    exit 1
}
