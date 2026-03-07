// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-30830 - Defuddle XSS via unescaped string interpolation in _findContent
// STIX ID  : bundle--501f689a-e060-4468-ace4-0fe43c84acac
// Scenario : XSS
// Generated: 2026-03-07T08:24:49.490775 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_30830___Defuddle_XSS_via_unescaped_string_WebExploit {
    meta:
        description = "Web exploit payload detection for: CVE-2026-30830 - Defuddle XSS via unescaped string interpolation in _findContent"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-07"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
