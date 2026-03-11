// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-21286 - Adobe Commerce  Incorrect Authorization CWE-863
// STIX ID  : bundle--98be20f4-17f0-41ed-a139-c17d53a69587
// Scenario : RCE
// Generated: 2026-03-11T05:13:10.053134 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_21286___Adobe_Commerce__Incorrect_Authori_WebExploit {
    meta:
        description = "Web exploit payload detection for: CVE-2026-21286 - Adobe Commerce  Incorrect Authorization CWE-863"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-11"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
