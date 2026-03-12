// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Look What You Made Us Patch 2025 Zero-Days in Review
// STIX ID  : bundle--cecab081-36f8-438e-94c7-123897a0449f
// Scenario : RCE
// Generated: 2026-03-12T05:18:37.883638 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Look_What_You_Made_Us_Patch_2025_Zero_Days_in_Revi_WebExploit {
    meta:
        description = "Web exploit payload detection for: Look What You Made Us Patch 2025 Zero-Days in Review"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-12"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
