// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Shadow Agents How SentinelOne Secures the AI Tools That Act Like Users
// STIX ID  : bundle--60c2c6a7-66d7-4f0c-bb0e-c232b3df3476
// Scenario : GENERIC
// Generated: 2026-03-12T12:45:09.415437 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Shadow_Agents_How_SentinelOne_Secures_the_AI_Tools_Generic {
    meta:
        description = "Generic behavioral detection for: Shadow Agents How SentinelOne Secures the AI Tools That Act Like Users"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-12"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
