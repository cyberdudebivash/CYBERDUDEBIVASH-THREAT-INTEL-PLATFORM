// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3281 - libvips bandrankc vips_bandrank_build heap-based overflow
// STIX ID  : bundle--e771587d-7653-4662-bbd5-bb8c237f22cd
// Scenario : VULNERABILITY
// Generated: 2026-02-27T02:38:40.386570 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3281___libvips_bandrankc_vips_bandrank_bu_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-3281 - libvips bandrankc vips_bandrank_build heap-based overflow"
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
