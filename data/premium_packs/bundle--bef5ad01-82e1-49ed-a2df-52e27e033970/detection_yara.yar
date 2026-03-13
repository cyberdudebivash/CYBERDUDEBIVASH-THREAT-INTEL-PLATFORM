// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Hackers targeted Polands National Centre for Nuclear Research
// STIX ID  : bundle--bef5ad01-82e1-49ed-a2df-52e27e033970
// Scenario : GENERIC
// Generated: 2026-03-13T21:25:04.688660 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Hackers_targeted_Polands_National_Centre_for_Nucle_Generic {
    meta:
        description = "Generic behavioral detection for: Hackers targeted Polands National Centre for Nuclear Research"
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
