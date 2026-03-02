// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2025-50199 - Chamilo Blind Server-Side Request Forgery Unauth Blind SSRF
// STIX ID  : bundle--afebcf75-8c88-464c-8e79-43215aed997d
// Scenario : VULNERABILITY
// Generated: 2026-03-02T16:37:56.214202 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2025_50199___Chamilo_Blind_Server_Side_Request_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2025-50199 - Chamilo Blind Server-Side Request Forgery Unauth Blind SSRF"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-02"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
