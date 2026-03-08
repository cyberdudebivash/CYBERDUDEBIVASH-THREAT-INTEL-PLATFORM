// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3730 - itsourcecode Free Hotel Reservation System indexphp sql injectio
// STIX ID  : bundle--b8c0627a-b8cd-428a-9fd2-3f3b608855c8
// Scenario : RCE
// Generated: 2026-03-08T12:34:33.472865 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3730___itsourcecode_Free_Hotel_Reservatio_WebExploit {
    meta:
        description = "Web exploit payload detection for: CVE-2026-3730 - itsourcecode Free Hotel Reservation System indexphp sql injectio"
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
