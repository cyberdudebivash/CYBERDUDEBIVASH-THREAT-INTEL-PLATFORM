// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Divide and conquer how the new Keenadu backdoor exposed links between major Andr
// STIX ID  : bundle--b93284fe-270c-4b66-9f27-6bd90eb54618
// Scenario : MALWARE
// Generated: 2026-03-12T16:57:49.253263 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Divide_and_conquer_how_the_new_Keenadu_backdoor_ex_Generic {
    meta:
        description = "Generic behavioral detection for: Divide and conquer how the new Keenadu backdoor exposed links between major Andr"
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
