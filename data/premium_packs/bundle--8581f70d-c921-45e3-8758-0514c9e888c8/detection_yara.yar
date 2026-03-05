// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Important Red Hat Security Advisory kpatch-patch-4_18_0-477_107_1 kpatch-patch-4
// STIX ID  : bundle--8581f70d-c921-45e3-8758-0514c9e888c8
// Scenario : VULNERABILITY
// Generated: 2026-03-05T12:44:18.300440 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Important_Red_Hat_Security_Advisory_kpatch_patch_4_Generic {
    meta:
        description = "Generic behavioral detection for: Important Red Hat Security Advisory kpatch-patch-4_18_0-477_107_1 kpatch-patch-4"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-05"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
