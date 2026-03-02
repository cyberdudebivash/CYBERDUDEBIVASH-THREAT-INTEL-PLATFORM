// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3403 - PHPGurukul Student Record Management System edit-subjectphp cros
// STIX ID  : bundle--762f60cf-47ba-4478-b67b-e8cd8d9e05fb
// Scenario : VULNERABILITY
// Generated: 2026-03-02T05:15:06.233487 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3403___PHPGurukul_Student_Record_Manageme_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-3403 - PHPGurukul Student Record Management System edit-subjectphp cros"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-02"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
