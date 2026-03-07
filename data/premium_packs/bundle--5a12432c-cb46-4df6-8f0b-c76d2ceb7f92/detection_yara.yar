// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-30247 - WeKnora SSRF via Redirection
// STIX ID  : bundle--5a12432c-cb46-4df6-8f0b-c76d2ceb7f92
// Scenario : VULNERABILITY
// Generated: 2026-03-07T05:00:43.364466 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_30247___WeKnora_SSRF_via_Redirection_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-30247 - WeKnora SSRF via Redirection"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-07"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
