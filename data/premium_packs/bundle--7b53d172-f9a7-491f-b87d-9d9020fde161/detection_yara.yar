// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Security Affairs newsletter Round 565 by Pierluigi Paganini  INTERNATIONAL EDITI
// STIX ID  : bundle--7b53d172-f9a7-491f-b87d-9d9020fde161
// Scenario : GENERIC
// Generated: 2026-03-01T02:02:56.327430 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Security_Affairs_newsletter_Round_565_by_Pierluigi_Generic {
    meta:
        description = "Generic behavioral detection for: Security Affairs newsletter Round 565 by Pierluigi Paganini  INTERNATIONAL EDITI"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-01"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
