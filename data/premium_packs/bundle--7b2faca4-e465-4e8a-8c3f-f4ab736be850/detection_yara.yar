// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-29178 - Lemmy Unauthenticated SSRF via file_type query parameter inject
// STIX ID  : bundle--7b2faca4-e465-4e8a-8c3f-f4ab736be850
// Scenario : VULNERABILITY
// Generated: 2026-03-06T20:26:46.590212 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_29178___Lemmy_Unauthenticated_SSRF_via_fi_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-29178 - Lemmy Unauthenticated SSRF via file_type query parameter inject"
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
