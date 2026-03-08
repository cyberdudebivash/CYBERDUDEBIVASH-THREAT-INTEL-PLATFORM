// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : From BRICKSTORM to GRIMBOLT UNC6201 Exploiting a Dell RecoverPoint for Virtual M
// STIX ID  : bundle--35952ac3-acc8-445c-93ab-4f82ef5262e3
// Scenario : RCE
// Generated: 2026-03-08T16:22:39.076440 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_From_BRICKSTORM_to_GRIMBOLT_UNC6201_Exploiting_a_D_WebExploit {
    meta:
        description = "Web exploit payload detection for: From BRICKSTORM to GRIMBOLT UNC6201 Exploiting a Dell RecoverPoint for Virtual M"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-08"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
