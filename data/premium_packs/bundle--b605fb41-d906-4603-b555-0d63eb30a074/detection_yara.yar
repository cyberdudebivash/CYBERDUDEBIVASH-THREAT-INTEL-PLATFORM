// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2025-11165 - DotCMS Velocity Sandbox Escape Vulnerability
// STIX ID  : bundle--b605fb41-d906-4603-b555-0d63eb30a074
// Scenario : VULNERABILITY
// Generated: 2026-02-24T12:02:28.536884 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2025_11165___DotCMS_Velocity_Sandbox_Escape_Vu_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2025-11165 - DotCMS Velocity Sandbox Escape Vulnerability"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-24"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
