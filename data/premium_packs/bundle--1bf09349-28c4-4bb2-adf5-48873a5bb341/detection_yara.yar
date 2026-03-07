// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-30244 - Plane Unauthenticated Workspace Member Information Disclosure
// STIX ID  : bundle--1bf09349-28c4-4bb2-adf5-48873a5bb341
// Scenario : VULNERABILITY
// Generated: 2026-03-07T01:17:45.772776 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_30244___Plane_Unauthenticated_Workspace_M_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-30244 - Plane Unauthenticated Workspace Member Information Disclosure"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-07"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
