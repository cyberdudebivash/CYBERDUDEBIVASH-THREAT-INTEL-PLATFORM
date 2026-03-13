// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : The Good the Bad and the Ugly in Cybersecurity  Week 11
// STIX ID  : bundle--1b81ea75-6ff4-4cf2-b66e-765fe87131f9
// Scenario : GENERIC
// Generated: 2026-03-13T13:02:51.321652 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_The_Good_the_Bad_and_the_Ugly_in_Cybersecurity__We_Generic {
    meta:
        description = "Generic behavioral detection for: The Good the Bad and the Ugly in Cybersecurity  Week 11"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-13"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
