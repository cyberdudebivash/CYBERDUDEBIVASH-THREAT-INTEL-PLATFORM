rule CDB_SENTINEL_Network_Intel_25a3f6600d81
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-06-09"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "25a3f6600d81"
        ioc_count = 4

    strings:
        $ip_0 = "16.03.53.12" ascii wide nocase
        $ip_1 = "15.03.05.19" ascii wide nocase
        $dom_2 = "java.net" ascii wide nocase
        $dom_3 = "rsync.samba.org" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}