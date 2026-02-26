// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : The Post-RAMP Era Allegations Fragmentation and the Rebuilding of the Ransomware
// STIX ID  : bundle--ffd8b509-ea3d-42ab-9431-754899a1f035
// Scenario : RANSOMWARE
// Generated: 2026-02-26T04:27:43.337867 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_The_Post_RAMP_Era_Allegations_Fragmentation_and_th_Ransomware {
    meta:
        description = "Behavioral ransomware detection for: The Post-RAMP Era Allegations Fragmentation and the Rebuilding of the Ransomware"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-26"
    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "Delete Shadows /All" ascii wide nocase
        $enc1 = ".encrypted" ascii wide nocase
        $enc2 = ".locked" ascii wide nocase
        $note = "HOW_TO_DECRYPT" ascii wide nocase
    condition:
        any of ($vss*) or 2 of ($enc*) or any of ($note*)
}
