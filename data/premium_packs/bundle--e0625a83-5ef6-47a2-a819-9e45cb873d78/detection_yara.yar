// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-30903 - Zoom Workplace for Windows Path Traversal Vulnerability
// STIX ID  : bundle--e0625a83-5ef6-47a2-a819-9e45cb873d78
// Scenario : VULNERABILITY
// Generated: 2026-03-11T16:47:21.418000 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_30903___Zoom_Workplace_for_Windows_Path_T_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-30903 - Zoom Workplace for Windows Path Traversal Vulnerability"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-11"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
