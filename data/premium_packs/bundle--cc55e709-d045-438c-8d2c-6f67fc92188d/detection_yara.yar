// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3052 - DataLinkDC dinky Flink Proxy Controller FlinkProxyControllerjava
// STIX ID  : bundle--cc55e709-d045-438c-8d2c-6f67fc92188d
// Scenario : VULNERABILITY
// Generated: 2026-02-24T03:09:32.160216 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3052___DataLinkDC_dinky_Flink_Proxy_Contr_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-3052 - DataLinkDC dinky Flink Proxy Controller FlinkProxyControllerjava"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-24"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
