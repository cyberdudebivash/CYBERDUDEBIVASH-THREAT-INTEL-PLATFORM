// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-30910 - CryptSodiumXS versions through 0001000 for Perl has potential i
// STIX ID  : bundle--a81db741-19d4-41ce-b007-feb99256def3
// Scenario : VULNERABILITY
// Generated: 2026-03-08T05:09:42.850461 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_30910___CryptSodiumXS_versions_through_00_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-30910 - CryptSodiumXS versions through 0001000 for Perl has potential i"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-08"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
