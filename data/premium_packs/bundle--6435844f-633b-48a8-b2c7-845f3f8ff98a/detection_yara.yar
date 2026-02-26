// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-27963 - Audiobookshelf has Stored XSS in Tooltipvue via Audiobook Metad
// STIX ID  : bundle--6435844f-633b-48a8-b2c7-845f3f8ff98a
// Scenario : XSS
// Generated: 2026-02-26T07:10:55.933877 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_27963___Audiobookshelf_has_Stored_XSS_in__WebExploit {
    meta:
        description = "Web exploit payload detection for: CVE-2026-27963 - Audiobookshelf has Stored XSS in Tooltipvue via Audiobook Metad"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-26"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
