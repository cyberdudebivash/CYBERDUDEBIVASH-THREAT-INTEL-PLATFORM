// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-28560 - wpForo Forum 2414 Stored XSS via Unsafe JSON Encoding in Inline
// STIX ID  : bundle--6cb16de4-2dde-4a43-b80e-dfc669d83fba
// Scenario : XSS
// Generated: 2026-03-01T00:56:24.128739 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_28560___wpForo_Forum_2414_Stored_XSS_via__WebExploit {
    meta:
        description = "Web exploit payload detection for: CVE-2026-28560 - wpForo Forum 2414 Stored XSS via Unsafe JSON Encoding in Inline"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-01"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
