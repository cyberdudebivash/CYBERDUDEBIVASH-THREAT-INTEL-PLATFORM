rule CDB_SENTINEL_Network_Intel_567432bb2bbf
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-25"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "567432bb2bbf"
        ioc_count = 69

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
        $ip_10 = "4.3.2.8" ascii wide nocase
        $ip_11 = "9.1.08.001" ascii wide nocase
        $ip_12 = "172.66.171.73" ascii wide nocase
        $ip_13 = "38.242.246.176" ascii wide nocase
        $ip_14 = "69.49.241.120" ascii wide nocase
        $ip_15 = "124.108.54.86" ascii wide nocase
        $ip_16 = "143.198.143.185" ascii wide nocase
        $ip_17 = "152.42.221.239" ascii wide nocase
        $ip_18 = "160.202.35.137" ascii wide nocase
        $ip_19 = "168.144.32.17" ascii wide nocase
        $ip_20 = "182.9.35.168" ascii wide nocase
        $ip_21 = "185.213.83.150" ascii wide nocase
        $ip_22 = "37.19.205.247" ascii wide nocase
        $ip_23 = "82.29.88.44" ascii wide nocase
        $ip_24 = "147.45.178.61" ascii wide nocase
        $ip_25 = "1.26.0.138" ascii wide nocase
        $ip_26 = "198.37.119.56" ascii wide nocase
        $ip_27 = "198.187.29.19" ascii wide nocase
        $ip_28 = "1.26.0.134" ascii wide nocase
        $dom_29 = "docs.metasploit.com" ascii wide nocase
        $dom_30 = "gmail.com" ascii wide nocase
        $dom_31 = "metasploit.com" ascii wide nocase
        $dom_32 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_33 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_34 = "cyberdudebivash.com" ascii wide nocase
        $dom_35 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_36 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_37 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_38 = "rockwellautomation.com" ascii wide nocase
        $dom_39 = "www.xiongmaitech.com" ascii wide nocase
        $dom_40 = "yadea.com" ascii wide nocase
        $dom_41 = "getsession.org" ascii wide nocase
        $dom_42 = "www.torproject.org" ascii wide nocase
        $dom_43 = "x.com" ascii wide nocase
        $dom_44 = "0x666.info" ascii wide nocase
        $dom_45 = "boomplay.com" ascii wide nocase
        $dom_46 = "index.crates.io" ascii wide nocase
        $dom_47 = "nuevaprodeciencia.club" ascii wide nocase
        $dom_48 = "odaracani.online" ascii wide nocase
        $dom_49 = "pastebin.com" ascii wide nocase
        $dom_50 = "vmi3003111.contaboserver.net" ascii wide nocase
        $dom_51 = "www.brighttalk.com" ascii wide nocase
        $dom_52 = "beeble.com" ascii wide nocase
        $dom_53 = "www.imperva.com" ascii wide nocase
        $dom_54 = "www.silobreaker.com" ascii wide nocase
        $dom_55 = "www.sonicwall.com" ascii wide nocase
        $dom_56 = "www.kaspersky.com" ascii wide nocase
        $dom_57 = "leakix.net" ascii wide nocase
        $dom_58 = "module.info" ascii wide nocase
        $dom_59 = "open.substack.com" ascii wide nocase
        $dom_60 = "otx.alienvault.com" ascii wide nocase
        $dom_61 = "cpuid.com" ascii wide nocase
        $dom_62 = "welcome.supp0v3.com" ascii wide nocase
        $dom_63 = "api.qpft5.com" ascii wide nocase
        $dom_64 = "security.snyk.io" ascii wide nocase
        $dom_65 = "www.carlsonsw.com" ascii wide nocase
        $dom_66 = "api.telegram.org" ascii wide nocase
        $dom_67 = "web.telegram.org" ascii wide nocase
        $dom_68 = "api.trongrid.io" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}