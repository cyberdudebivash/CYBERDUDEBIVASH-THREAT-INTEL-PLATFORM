// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3683 - bufanyun HotGo Endpoint uploadgo ImageTransferStorage server-sid
// STIX ID  : bundle--b8c402d2-2a1f-4adc-b8ff-3a071434c1fc
// Scenario : VULNERABILITY
// Generated: 2026-03-08T02:49:51.571161 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3683___bufanyun_HotGo_Endpoint_uploadgo_I_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-3683 - bufanyun HotGo Endpoint uploadgo ImageTransferStorage server-sid"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-08"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
