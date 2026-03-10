// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Security is a team sport AWS at RSAC 2026 Conference
// STIX ID  : bundle--8bf78081-f9da-4385-a71b-86b34f53b76f
// Scenario : GENERIC
// Generated: 2026-03-10T20:30:25.279456 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Security_is_a_team_sport_AWS_at_RSAC_2026_Conferen_Generic {
    meta:
        description = "Generic behavioral detection for: Security is a team sport AWS at RSAC 2026 Conference"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-10"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
