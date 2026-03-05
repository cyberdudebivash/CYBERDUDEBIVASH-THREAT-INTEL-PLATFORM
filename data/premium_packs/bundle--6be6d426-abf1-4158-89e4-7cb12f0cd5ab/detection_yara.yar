// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-2893
// STIX ID  : bundle--6be6d426-abf1-4158-89e4-7cb12f0cd5ab
// Scenario : VULNERABILITY
// Generated: 2026-03-05T08:35:27.470426 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_2893_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-2893"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-05"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
