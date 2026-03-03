// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2025-47147 - Command Centre Mobile Client Cleartext Storage of Sensitive Inf
// STIX ID  : bundle--dc177045-d5a4-409f-a1d5-67254ea09afd
// Scenario : VULNERABILITY
// Generated: 2026-03-03T05:03:26.750013 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2025_47147___Command_Centre_Mobile_Client_Clea_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2025-47147 - Command Centre Mobile Client Cleartext Storage of Sensitive Inf"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-03"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
