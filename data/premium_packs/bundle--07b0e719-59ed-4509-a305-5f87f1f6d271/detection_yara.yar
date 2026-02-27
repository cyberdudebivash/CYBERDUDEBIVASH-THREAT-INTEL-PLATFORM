// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3289 - Sanluan PublicCMS Template Cache Generation TemplateCacheCompone
// STIX ID  : bundle--07b0e719-59ed-4509-a305-5f87f1f6d271
// Scenario : MALWARE
// Generated: 2026-02-27T05:59:16.442525 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3289___Sanluan_PublicCMS_Template_Cache_G_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-3289 - Sanluan PublicCMS Template Cache Generation TemplateCacheCompone"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-27"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
