// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : How to manage the lifecycle of Amazon Machine Images using AMI Lineage for AWS
// STIX ID  : bundle--e997b802-9b82-4284-8716-210affa56d1e
// Scenario : GENERIC
// Generated: 2026-03-12T20:31:37.136342 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_How_to_manage_the_lifecycle_of_Amazon_Machine_Imag_Generic {
    meta:
        description = "Generic behavioral detection for: How to manage the lifecycle of Amazon Machine Images using AMI Lineage for AWS"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-12"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
