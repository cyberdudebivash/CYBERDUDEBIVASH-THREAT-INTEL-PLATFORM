// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Your MRI is Online The Hidden Risks of Exposed DICOM Servers in UK Healthcare
// STIX ID  : bundle--713f913a-af2d-4992-84cb-46b78f9fc4dd
// Scenario : GENERIC
// Generated: 2026-02-25T19:16:51.183106 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Your_MRI_is_Online_The_Hidden_Risks_of_Exposed_DIC_Generic {
    meta:
        description = "Generic behavioral detection for: Your MRI is Online The Hidden Risks of Exposed DICOM Servers in UK Healthcare"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-25"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
