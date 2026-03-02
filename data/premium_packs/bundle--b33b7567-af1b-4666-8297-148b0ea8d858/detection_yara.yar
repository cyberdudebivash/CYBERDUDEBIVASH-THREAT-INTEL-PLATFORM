// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2025-15597 - Dataease SQLBot API Endpoint assistantpy access control
// STIX ID  : bundle--b33b7567-af1b-4666-8297-148b0ea8d858
// Scenario : VULNERABILITY
// Generated: 2026-03-02T08:37:38.818789 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2025_15597___Dataease_SQLBot_API_Endpoint_assi_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2025-15597 - Dataease SQLBot API Endpoint assistantpy access control"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-02"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
