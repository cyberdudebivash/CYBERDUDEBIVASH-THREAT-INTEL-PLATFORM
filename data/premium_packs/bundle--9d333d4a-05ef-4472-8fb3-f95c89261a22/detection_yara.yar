// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-29788 - TSPortal Anyone can forge self-deletion requests of any user
// STIX ID  : bundle--9d333d4a-05ef-4472-8fb3-f95c89261a22
// Scenario : VULNERABILITY
// Generated: 2026-03-06T21:11:57.959353 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_29788___TSPortal_Anyone_can_forge_self_de_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-29788 - TSPortal Anyone can forge self-deletion requests of any user"
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
