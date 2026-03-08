// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3760 - itsourcecode University Management System view_resultphp sql inj
// STIX ID  : bundle--d9d5525a-dfad-4168-85a8-78bcc81311fd
// Scenario : RCE
// Generated: 2026-03-08T20:20:26.463818 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3760___itsourcecode_University_Management_WebExploit {
    meta:
        description = "Web exploit payload detection for: CVE-2026-3760 - itsourcecode University Management System view_resultphp sql inj"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-08"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
