// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Canadian Tire 2025 data breach impacts 38 million users
// STIX ID  : bundle--fad06ae0-0e3f-48f6-997f-fc5fd510861c
// Scenario : DATA_BREACH
// Generated: 2026-02-28T18:43:52.151712 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Canadian_Tire_2025_data_breach_impacts_38_million__Generic {
    meta:
        description = "Generic behavioral detection for: Canadian Tire 2025 data breach impacts 38 million users"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-28"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
