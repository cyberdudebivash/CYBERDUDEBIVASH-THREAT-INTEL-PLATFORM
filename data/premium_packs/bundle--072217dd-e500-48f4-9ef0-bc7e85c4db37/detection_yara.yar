// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : How to manage the lifecycle of Amazon Machine Images using AMI Lineage for AWS
// STIX ID  : bundle--072217dd-e500-48f4-9ef0-bc7e85c4db37
// Scenario : GENERIC
// Generated: 2026-03-13T22:52:07.476815 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_How_to_manage_the_lifecycle_of_Amazon_Machine_Imag_Generic {
    meta:
        description = "Generic behavioral detection for: How to manage the lifecycle of Amazon Machine Images using AMI Lineage for AWS"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-13"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
