// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3711 - code-projects Simple Flight Ticket Booking System Adminupdatephp
// STIX ID  : bundle--13992fac-bb4a-43b7-b24f-8128864e0065
// Scenario : VULNERABILITY
// Generated: 2026-03-08T08:25:18.025284 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3711___code_projects_Simple_Flight_Ticket_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-3711 - code-projects Simple Flight Ticket Booking System Adminupdatephp"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-08"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
