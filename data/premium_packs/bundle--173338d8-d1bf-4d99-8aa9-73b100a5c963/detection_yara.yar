// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3070 - SourceCodester Modern Image Gallery App uploadphp cross site scr
// STIX ID  : bundle--173338d8-d1bf-4d99-8aa9-73b100a5c963
// Scenario : RCE
// Generated: 2026-02-24T07:18:29.832244 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3070___SourceCodester_Modern_Image_Galler_WebExploit {
    meta:
        description = "Web exploit payload detection for: CVE-2026-3070 - SourceCodester Modern Image Gallery App uploadphp cross site scr"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-24"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
