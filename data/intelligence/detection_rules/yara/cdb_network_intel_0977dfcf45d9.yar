rule CDB_SENTINEL_Network_Intel_0977dfcf45d9
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-20"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "0977dfcf45d9"
        ioc_count = 72

    strings:
        $ip_0 = "147.45.178.61" ascii wide nocase
        $ip_1 = "94.232.46.16" ascii wide nocase
        $ip_2 = "198.187.29.19" ascii wide nocase
        $ip_3 = "13.5.2.1" ascii wide nocase
        $ip_4 = "7.8.10.2" ascii wide nocase
        $ip_5 = "46.6.14.135" ascii wide nocase
        $ip_6 = "124.108.54.86" ascii wide nocase
        $ip_7 = "124.248.183.139" ascii wide nocase
        $ip_8 = "143.198.143.185" ascii wide nocase
        $ip_9 = "152.42.221.239" ascii wide nocase
        $ip_10 = "160.202.35.137" ascii wide nocase
        $ip_11 = "168.144.32.17" ascii wide nocase
        $ip_12 = "182.9.35.168" ascii wide nocase
        $ip_13 = "185.213.83.150" ascii wide nocase
        $ip_14 = "37.19.205.247" ascii wide nocase
        $ip_15 = "82.29.88.44" ascii wide nocase
        $ip_16 = "1.53.114.181" ascii wide nocase
        $ip_17 = "104.28.160.197" ascii wide nocase
        $ip_18 = "114.10.99.126" ascii wide nocase
        $ip_19 = "130.12.182.154" ascii wide nocase
        $ip_20 = "157.15.40.74" ascii wide nocase
        $ip_21 = "202.56.2.126" ascii wide nocase
        $ip_22 = "209.146.60.26" ascii wide nocase
        $ip_23 = "49.156.40.126" ascii wide nocase
        $ip_24 = "83.147.12.83" ascii wide nocase
        $ip_25 = "2.55.255.255" ascii wide nocase
        $ip_26 = "212.150.255.255" ascii wide nocase
        $ip_27 = "79.191.255.255" ascii wide nocase
        $dom_28 = "rockwellautomation.com" ascii wide nocase
        $dom_29 = "orbitalstress.net" ascii wide nocase
        $dom_30 = "starkstresser.net" ascii wide nocase
        $dom_31 = "zdstresser.net" ascii wide nocase
        $dom_32 = "cpuid.com" ascii wide nocase
        $dom_33 = "welcome.supp0v3.com" ascii wide nocase
        $dom_34 = "filecenter.deltaww.com" ascii wide nocase
        $dom_35 = "www.deltaww.com" ascii wide nocase
        $dom_36 = "slack.com" ascii wide nocase
        $dom_37 = "malware-traffic-analysis.net" ascii wide nocase
        $dom_38 = "gmail.com" ascii wide nocase
        $dom_39 = "hornerautomation.com" ascii wide nocase
        $dom_40 = "docs.metasploit.com" ascii wide nocase
        $dom_41 = "leakix.net" ascii wide nocase
        $dom_42 = "module.info" ascii wide nocase
        $dom_43 = "api.qpft5.com" ascii wide nocase
        $dom_44 = "softwaresupportsp.aveva.com" ascii wide nocase
        $dom_45 = "www.aveva.com" ascii wide nocase
        $dom_46 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_47 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_48 = "cyberdudebivash.com" ascii wide nocase
        $dom_49 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_50 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_51 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_52 = "pdfl.io" ascii wide nocase
        $dom_53 = "company.com" ascii wide nocase
        $dom_54 = "0x666.info" ascii wide nocase
        $dom_55 = "ecp.yusercontent.com" ascii wide nocase
        $dom_56 = "dahuawiki.com" ascii wide nocase
        $dom_57 = "www.abuseipdb.com" ascii wide nocase
        $dom_58 = "www.shodan.io" ascii wide nocase
        $dom_59 = "format.com" ascii wide nocase
        $dom_60 = "larozada.com" ascii wide nocase
        $dom_61 = "login.microsoftonline.com" ascii wide nocase
        $dom_62 = "office.com" ascii wide nocase
        $dom_63 = "saicares.com" ascii wide nocase
        $dom_64 = "securedocsportal.com" ascii wide nocase
        $dom_65 = "www.brighttalk.com" ascii wide nocase
        $dom_66 = "www.anviz.com" ascii wide nocase
        $dom_67 = "blog.calif.io" ascii wide nocase
        $dom_68 = "blogs.oracle.com" ascii wide nocase
        $dom_69 = "www.npmjs.com" ascii wide nocase
        $dom_70 = "ledger.com" ascii wide nocase
        $dom_71 = "vsccode-modetx.hf.space" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}