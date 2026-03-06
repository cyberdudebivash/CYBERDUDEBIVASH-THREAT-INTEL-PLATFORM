// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : OneClaw Discovery and Observability for the Agentic Era
// STIX ID  : bundle--477972f3-7bd6-41af-8278-edb727acb87e
// Scenario : GENERIC
// Generated: 2026-03-06T08:32:40.449089 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_OneClaw_Discovery_and_Observability_for_the_Agenti_Generic {
    meta:
        description = "Generic behavioral detection for: OneClaw Discovery and Observability for the Agentic Era"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-06"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
