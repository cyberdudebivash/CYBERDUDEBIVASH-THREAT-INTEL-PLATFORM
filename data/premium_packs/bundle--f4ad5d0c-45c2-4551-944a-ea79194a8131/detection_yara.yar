// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Microsoft seizes 338 websites to disrupt rapidly growing RaccoonO365 phishing se
// STIX ID  : bundle--f4ad5d0c-45c2-4551-944a-ea79194a8131
// Scenario : PHISHING
// Generated: 2026-03-13T22:35:08.960229 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Microsoft_seizes_338_websites_to_disrupt_rapidly_g_Generic {
    meta:
        description = "Generic behavioral detection for: Microsoft seizes 338 websites to disrupt rapidly growing RaccoonO365 phishing se"
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
