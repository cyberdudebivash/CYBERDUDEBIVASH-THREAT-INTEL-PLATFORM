// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : OneClaw Discovery and Observability for the Agentic Era
// STIX ID  : bundle--4b1c5d5e-d9f6-47e2-879f-cb903eb5db5c
// Scenario : GENERIC
// Generated: 2026-02-27T18:57:13.948000 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_OneClaw_Discovery_and_Observability_for_the_Agenti_Generic {
    meta:
        description = "Generic behavioral detection for: OneClaw Discovery and Observability for the Agentic Era"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-27"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
