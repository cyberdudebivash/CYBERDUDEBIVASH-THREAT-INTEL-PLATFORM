rule CDB_SENTINEL_Network_Intel_0221f6c766f1
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-27"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "0221f6c766f1"
        ioc_count = 26

    strings:
        $ip_0 = "1.53.114.181" ascii wide nocase
        $ip_1 = "104.28.160.197" ascii wide nocase
        $ip_2 = "114.10.99.126" ascii wide nocase
        $ip_3 = "124.248.183.139" ascii wide nocase
        $ip_4 = "130.12.182.154" ascii wide nocase
        $ip_5 = "157.15.40.74" ascii wide nocase
        $ip_6 = "202.56.2.126" ascii wide nocase
        $ip_7 = "209.146.60.26" ascii wide nocase
        $ip_8 = "49.156.40.126" ascii wide nocase
        $ip_9 = "83.147.12.83" ascii wide nocase
        $ip_10 = "1.26.0.138" ascii wide nocase
        $ip_11 = "1.26.0.134" ascii wide nocase
        $ip_12 = "21.1.1.50" ascii wide nocase
        $dom_13 = "docs.metasploit.com" ascii wide nocase
        $dom_14 = "gmail.com" ascii wide nocase
        $dom_15 = "metasploit.com" ascii wide nocase
        $dom_16 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_17 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_18 = "cyberdudebivash.com" ascii wide nocase
        $dom_19 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_20 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_21 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_22 = "java.io" ascii wide nocase
        $dom_23 = "file.io" ascii wide nocase
        $dom_24 = "security.snyk.io" ascii wide nocase
        $dom_25 = "blog.hartwork.org" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}