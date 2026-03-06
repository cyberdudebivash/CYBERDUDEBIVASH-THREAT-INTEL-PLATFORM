// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-28787 - OneUptime has WebAuthn 2FA bypass server accepts client-supplie
// STIX ID  : bundle--44b4188e-b3bc-4e0d-ba6f-fa11c891b7dd
// Scenario : VULNERABILITY
// Generated: 2026-03-06T06:47:37.023470 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_28787___OneUptime_has_WebAuthn_2FA_bypass_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-28787 - OneUptime has WebAuthn 2FA bypass server accepts client-supplie"
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
