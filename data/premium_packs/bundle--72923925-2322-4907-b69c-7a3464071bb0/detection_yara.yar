// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : OneClaw Discovery and Observability for the Agentic Era
// STIX ID  : bundle--72923925-2322-4907-b69c-7a3464071bb0
// Scenario : GENERIC
// Generated: 2026-03-13T06:23:37.491912 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_OneClaw_Discovery_and_Observability_for_the_Agenti_Generic {
    meta:
        description = "Generic behavioral detection for: OneClaw Discovery and Observability for the Agentic Era"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-13"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
