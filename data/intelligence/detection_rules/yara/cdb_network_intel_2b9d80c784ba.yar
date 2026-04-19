rule CDB_SENTINEL_Network_Intel_2b9d80c784ba
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-19"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "2b9d80c784ba"
        ioc_count = 72

    strings:
        $ip_0 = "147.45.178.61" ascii wide nocase
        $ip_1 = "13.5.2.1" ascii wide nocase
        $ip_2 = "7.8.10.2" ascii wide nocase
        $ip_3 = "94.232.46.16" ascii wide nocase
        $ip_4 = "46.6.14.135" ascii wide nocase
        $ip_5 = "124.108.54.86" ascii wide nocase
        $ip_6 = "124.248.183.139" ascii wide nocase
        $ip_7 = "143.198.143.185" ascii wide nocase
        $ip_8 = "152.42.221.239" ascii wide nocase
        $ip_9 = "160.202.35.137" ascii wide nocase
        $ip_10 = "168.144.32.17" ascii wide nocase
        $ip_11 = "182.9.35.168" ascii wide nocase
        $ip_12 = "185.213.83.150" ascii wide nocase
        $ip_13 = "37.19.205.247" ascii wide nocase
        $ip_14 = "82.29.88.44" ascii wide nocase
        $ip_15 = "1.53.114.181" ascii wide nocase
        $ip_16 = "104.28.160.197" ascii wide nocase
        $ip_17 = "114.10.99.126" ascii wide nocase
        $ip_18 = "130.12.182.154" ascii wide nocase
        $ip_19 = "157.15.40.74" ascii wide nocase
        $ip_20 = "202.56.2.126" ascii wide nocase
        $ip_21 = "209.146.60.26" ascii wide nocase
        $ip_22 = "49.156.40.126" ascii wide nocase
        $ip_23 = "83.147.12.83" ascii wide nocase
        $ip_24 = "198.187.29.19" ascii wide nocase
        $ip_25 = "2.55.255.255" ascii wide nocase
        $ip_26 = "212.150.255.255" ascii wide nocase
        $ip_27 = "79.191.255.255" ascii wide nocase
        $dom_28 = "rockwellautomation.com" ascii wide nocase
        $dom_29 = "orbitalstress.net" ascii wide nocase
        $dom_30 = "starkstresser.net" ascii wide nocase
        $dom_31 = "zdstresser.net" ascii wide nocase
        $dom_32 = "filecenter.deltaww.com" ascii wide nocase
        $dom_33 = "www.deltaww.com" ascii wide nocase
        $dom_34 = "malware-traffic-analysis.net" ascii wide nocase
        $dom_35 = "gmail.com" ascii wide nocase
        $dom_36 = "cpuid.com" ascii wide nocase
        $dom_37 = "welcome.supp0v3.com" ascii wide nocase
        $dom_38 = "docs.metasploit.com" ascii wide nocase
        $dom_39 = "leakix.net" ascii wide nocase
        $dom_40 = "module.info" ascii wide nocase
        $dom_41 = "api.qpft5.com" ascii wide nocase
        $dom_42 = "softwaresupportsp.aveva.com" ascii wide nocase
        $dom_43 = "www.aveva.com" ascii wide nocase
        $dom_44 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_45 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_46 = "cyberdudebivash.com" ascii wide nocase
        $dom_47 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_48 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_49 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_50 = "company.com" ascii wide nocase
        $dom_51 = "0x666.info" ascii wide nocase
        $dom_52 = "pdfl.io" ascii wide nocase
        $dom_53 = "slack.com" ascii wide nocase
        $dom_54 = "dahuawiki.com" ascii wide nocase
        $dom_55 = "www.abuseipdb.com" ascii wide nocase
        $dom_56 = "www.shodan.io" ascii wide nocase
        $dom_57 = "www.brighttalk.com" ascii wide nocase
        $dom_58 = "hornerautomation.com" ascii wide nocase
        $dom_59 = "www.anviz.com" ascii wide nocase
        $dom_60 = "format.com" ascii wide nocase
        $dom_61 = "larozada.com" ascii wide nocase
        $dom_62 = "login.microsoftonline.com" ascii wide nocase
        $dom_63 = "office.com" ascii wide nocase
        $dom_64 = "saicares.com" ascii wide nocase
        $dom_65 = "securedocsportal.com" ascii wide nocase
        $dom_66 = "blog.calif.io" ascii wide nocase
        $dom_67 = "blogs.oracle.com" ascii wide nocase
        $dom_68 = "ecp.yusercontent.com" ascii wide nocase
        $dom_69 = "www.npmjs.com" ascii wide nocase
        $dom_70 = "ledger.com" ascii wide nocase
        $dom_71 = "vsccode-modetx.hf.space" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}