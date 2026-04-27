rule CDB_SENTINEL_Network_Intel_2128a8906d9c
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-27"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "2128a8906d9c"
        ioc_count = 28

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
        $ip_10 = "62.60.226.200" ascii wide nocase
        $ip_11 = "21.1.1.50" ascii wide nocase
        $dom_12 = "docs.metasploit.com" ascii wide nocase
        $dom_13 = "gmail.com" ascii wide nocase
        $dom_14 = "metasploit.com" ascii wide nocase
        $dom_15 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_16 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_17 = "cyberdudebivash.com" ascii wide nocase
        $dom_18 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_19 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_20 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_21 = "file.io" ascii wide nocase
        $dom_22 = "java.io" ascii wide nocase
        $dom_23 = "vibing-api-ccegdhbrg2d6bsd7.b02.azurefd.net" ascii wide nocase
        $dom_24 = "security.snyk.io" ascii wide nocase
        $dom_25 = "raw.githubusercontent.com" ascii wide nocase
        $dom_26 = "issues.apache.org" ascii wide nocase
        $dom_27 = "blog.hartwork.org" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}