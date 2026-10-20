# SENTINEL APEX™ — Enterprise Intelligence Dossier Trust & Presentation Standard

**Release class:** Draft implementation / customer acceptance pending
**Scope:** Canonical HTML dossiers emitted by `scripts/generate_intel_reports.py`; its `agent/apex_intelligence_upgrade.py` analyst narrative; publication remains governed by the existing P20/P21/P23/P25/P26 gates.

## Enterprise reader sequence

1. **CISO / executive decision (first 45 seconds):** What is reported, how it affects my estate (if known), source provenance, near-term action, confirmed unknowns and what further evidence could change the assessment.
2. **SOC lead (first 30 minutes):** 0–10 minute ownership/exposure inventory, 10–20 minute corroborating SIEM/EDR/gateway searches using *source-supported* indicators and TTPs, 20–30 minute evidence preservation/escalation. These are **suggested verification actions**, not platform-executed hunts.
3. **Threat analyst:** Clearly separate reported source facts, deterministic model/heuristic calculations, analyst inferences and unresolved questions. No ungrounded attribution, global telemetry claim, fabricated C2/IOC, or made-up loss figure.
4. **Detection engineer:** Use only vetted observables and cited technique mappings. Generated Sigma/YARA/KQL/SPL rules are hypotheses until tested against real schemas and telemetry. Zero-IoC items may legitimately have no signature.
5. **Procurement / security reviewer:** Stable public source URL, report ID, UTC timestamps, TLP disclosure, machine-readable link status, traceable incident handling. No unsupported claim of SOC 2 attestation, enterprise SLA or verified customer exposure.

## Analytic contract

| Field | Customer-facing rule |
|---|---|
| Source | Provide source URL when present, do not call an independent platform assertion external confirmation |
| TLP | Use FIRST TLP 2.0: `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`; actual public eligibility is decided by existing TLP policy, not this display layer |
| Confidence | Missing recorded IOC score = **Not assessed**. Only bounded, source-present score for validated IOCs may show; label **IOC-specific signal**, never a general model probability |
| Intelligence impact | Customer exposure, affected assets and financial/regulatory consequences remain **UNKNOWN** until tenant data and relevant factual prerequisites are confirmed |
| Priority | CVSS/KEV are vulnerability-specific; threat-severity colour and urgency must not imply an authoritative CVSS rating when unrated |
| AI analysis | Metadata heuristics are **scenario indices**, not calibrated model probabilities, actual attack timelines, 12-month historical correlations or observed activity |
| IOC / detection | Never synthesize hostile infrastructure, claim observed actor activity from an inferred ATT&CK mapping, or count CVE IDs as IOCs |
| Uncertainty | Explicitly say which observation, telemetry source or analyst review is needed for greater confidence |

## Publication and contractual safeguards

- A well-styled report is **not** a customer-ready report. P20/P21/P23/P25/P26 certification and externally verifiable underlying source evidence remain mandatory.
- Do not promote a withheld item to `customer_ready`, alter P21 thresholds, write new R2 objects outside the canonical writer, or bypass TLP/retraction controls merely to improve catalogue counts.
- Keep canonical writer ownership unchanged. The secondary historical `scripts/report_generator.py` does not regain write privileges.
- Any paid IOC/attribution elements remain access-controlled; public output must not reveal information withheld by existing masks.
- HTML print-to-PDF must preserve TLP, source/unknown disclosures, readable typography and report ID, and never imply the document is a SOC 2 Type II report or an externally audited certification.

## Review / regression evidence

```bash
python -m pytest tests/test_enterprise_intel_claim_integrity.py -v
python -m pytest tests/test_p0_report_evidence_quality.py -v
python -m pytest tests/test_generate_intel_reports_manifest_formats.py -v
```

**Before release:** inspect real, authorized TLP:CLEAR source items of different types (CVE, phishing/indicator, ransomware claim, news); compare old/new outputs on the **same immutable SHA and evidence inputs**; verify output HTML is not truncated and does not leak gated details; run canonical SAST and report-generator regression gates; obtain publisher review; confirm publication-eligible report objects through the controlled R2/Pages path, and independently check customer retrieval. Draft source quality improvements do not authorize deployment.

**Reference frameworks:** FIRST TLP v2.0 (https://www.first.org/tlp/); OASIS STIX v2.1 (https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html); MITRE ATT&CK (https://attack.mitre.org/). These provide terminology and interoperability guidance, not proof of independent certification of SENTINEL APEX.
