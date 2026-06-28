rule CDB_SENTINEL_Network_Intel_59fba5608107
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-06-28"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "59fba5608107"
        ioc_count = 9

    strings:
        $ip_0 = "4.0.4.1" ascii wide nocase
        $ip_1 = "1.0.0.41" ascii wide nocase
        $ip_2 = "1.0.9.4" ascii wide nocase
        $ip_3 = "1.3.4.3" ascii wide nocase
        $ip_4 = "169.254.169.254" ascii wide nocase
        $ip_5 = "2.7.9.8" ascii wide nocase
        $ip_6 = "0.0.0.0" ascii wide nocase
        $dom_7 = "kubevirt.io" ascii wide nocase
        $dom_8 = "evil.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}