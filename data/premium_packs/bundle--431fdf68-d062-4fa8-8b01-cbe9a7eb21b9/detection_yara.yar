// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Spam and phishing in 2025
// STIX ID  : bundle--431fdf68-d062-4fa8-8b01-cbe9a7eb21b9
// Scenario : PHISHING
// Generated: 2026-03-06T05:10:10.986643 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Spam_and_phishing_in_2025_Generic {
    meta:
        description = "Generic behavioral detection for: Spam and phishing in 2025"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-06"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
