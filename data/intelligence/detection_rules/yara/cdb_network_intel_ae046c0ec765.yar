rule CDB_SENTINEL_Network_Intel_ae046c0ec765
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-06-15"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "ae046c0ec765"
        ioc_count = 4

    strings:
        $ip_0 = "5.5.13.0" ascii wide nocase
        $dom_1 = "kodak.com" ascii wide nocase
        $dom_2 = "metacpan.org" ascii wide nocase
        $dom_3 = "theorangeblowfish.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}