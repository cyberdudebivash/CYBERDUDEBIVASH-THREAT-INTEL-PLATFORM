// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3814 - UTT HiPER 810G getOneApConfTempEntry strcpy buffer overflow
// STIX ID  : bundle--5376ef85-5fbb-4a0c-bd65-8db3c0941614
// Scenario : VULNERABILITY
// Generated: 2026-03-09T12:47:14.855725 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3814___UTT_HiPER_810G_getOneApConfTempEnt_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-3814 - UTT HiPER 810G getOneApConfTempEntry strcpy buffer overflow"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-09"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
