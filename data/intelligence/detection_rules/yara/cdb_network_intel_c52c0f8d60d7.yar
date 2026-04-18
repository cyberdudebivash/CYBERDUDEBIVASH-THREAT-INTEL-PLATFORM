rule CDB_SENTINEL_Network_Intel_c52c0f8d60d7
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-18"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "c52c0f8d60d7"
        ioc_count = 38

    strings:
        $ip_0 = "124.108.54.86" ascii wide nocase
        $ip_1 = "124.248.183.139" ascii wide nocase
        $ip_2 = "143.198.143.185" ascii wide nocase
        $ip_3 = "152.42.221.239" ascii wide nocase
        $ip_4 = "160.202.35.137" ascii wide nocase
        $ip_5 = "168.144.32.17" ascii wide nocase
        $ip_6 = "182.9.35.168" ascii wide nocase
        $ip_7 = "185.213.83.150" ascii wide nocase
        $ip_8 = "37.19.205.247" ascii wide nocase
        $ip_9 = "82.29.88.44" ascii wide nocase
        $ip_10 = "94.232.46.16" ascii wide nocase
        $ip_11 = "13.5.2.1" ascii wide nocase
        $ip_12 = "7.8.10.2" ascii wide nocase
        $ip_13 = "46.6.14.135" ascii wide nocase
        $ip_14 = "2.55.255.255" ascii wide nocase
        $ip_15 = "212.150.255.255" ascii wide nocase
        $ip_16 = "79.191.255.255" ascii wide nocase
        $dom_17 = "malware-traffic-analysis.net" ascii wide nocase
        $dom_18 = "gmail.com" ascii wide nocase
        $dom_19 = "www.brighttalk.com" ascii wide nocase
        $dom_20 = "ecp.yusercontent.com" ascii wide nocase
        $dom_21 = "softwaresupportsp.aveva.com" ascii wide nocase
        $dom_22 = "www.aveva.com" ascii wide nocase
        $dom_23 = "docs.metasploit.com" ascii wide nocase
        $dom_24 = "leakix.net" ascii wide nocase
        $dom_25 = "module.info" ascii wide nocase
        $dom_26 = "ledger.com" ascii wide nocase
        $dom_27 = "orbitalstress.net" ascii wide nocase
        $dom_28 = "starkstresser.net" ascii wide nocase
        $dom_29 = "zdstresser.net" ascii wide nocase
        $dom_30 = "www.anviz.com" ascii wide nocase
        $dom_31 = "slack.com" ascii wide nocase
        $dom_32 = "vsccode-modetx.hf.space" ascii wide nocase
        $dom_33 = "pdfl.io" ascii wide nocase
        $dom_34 = "hornerautomation.com" ascii wide nocase
        $dom_35 = "dahuawiki.com" ascii wide nocase
        $dom_36 = "www.abuseipdb.com" ascii wide nocase
        $dom_37 = "www.shodan.io" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}