// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3148 - SourceCodester Simple and Nice Shopping Cart Script signupphp sq
// STIX ID  : bundle--2f9c4b26-38b2-4497-8779-a1b6d14c0a94
// Scenario : RCE
// Generated: 2026-02-25T07:12:35.107579 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3148___SourceCodester_Simple_and_Nice_Sho_WebExploit {
    meta:
        description = "Web exploit payload detection for: CVE-2026-3148 - SourceCodester Simple and Nice Shopping Cart Script signupphp sq"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-25"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
