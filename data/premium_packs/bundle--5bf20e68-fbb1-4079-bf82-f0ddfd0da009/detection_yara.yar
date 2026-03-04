// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-28778
// STIX ID  : bundle--5bf20e68-fbb1-4079-bf82-f0ddfd0da009
// Scenario : VULNERABILITY
// Generated: 2026-03-04T08:33:56.718184 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_28778_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-28778"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-04"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
