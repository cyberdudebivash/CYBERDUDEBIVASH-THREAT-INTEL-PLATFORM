// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Shadow Agents How SentinelOne Secures the AI Tools That Act Like Users
// STIX ID  : bundle--f0243805-5853-4ab9-9dfd-c44f288348eb
// Scenario : GENERIC
// Generated: 2026-03-05T20:34:45.418395 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Shadow_Agents_How_SentinelOne_Secures_the_AI_Tools_Generic {
    meta:
        description = "Generic behavioral detection for: Shadow Agents How SentinelOne Secures the AI Tools That Act Like Users"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-05"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
