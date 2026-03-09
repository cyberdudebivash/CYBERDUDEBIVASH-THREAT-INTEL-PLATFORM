// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3817 - SourceCodester Patients Waiting Area Queue Management System pat
// STIX ID  : bundle--9bd0e7e9-8abd-4371-8a1d-7f6be5cc951f
// Scenario : RCE
// Generated: 2026-03-09T15:00:04.302375 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3817___SourceCodester_Patients_Waiting_Ar_WebExploit {
    meta:
        description = "Web exploit payload detection for: CVE-2026-3817 - SourceCodester Patients Waiting Area Queue Management System pat"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-09"
    strings:
        $xss1 = "<script>alert(" ascii wide nocase
        $xss2 = "javascript:eval(" ascii wide nocase
        $xss3 = "onerror=alert(" ascii wide nocase
        $rce1 = "/bin/bash" ascii
        $rce2 = "cmd.exe /c" ascii wide nocase
    condition:
        any of them
}
