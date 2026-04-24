rule CDB_SENTINEL_Network_Intel_21141cb27a3f
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-24"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "21141cb27a3f"
        ioc_count = 80

    strings:
        $ip_0 = "198.187.29.19" ascii wide nocase
        $ip_1 = "4.3.2.8" ascii wide nocase
        $ip_2 = "9.1.08.001" ascii wide nocase
        $ip_3 = "124.108.54.86" ascii wide nocase
        $ip_4 = "124.248.183.139" ascii wide nocase
        $ip_5 = "143.198.143.185" ascii wide nocase
        $ip_6 = "152.42.221.239" ascii wide nocase
        $ip_7 = "160.202.35.137" ascii wide nocase
        $ip_8 = "168.144.32.17" ascii wide nocase
        $ip_9 = "182.9.35.168" ascii wide nocase
        $ip_10 = "185.213.83.150" ascii wide nocase
        $ip_11 = "37.19.205.247" ascii wide nocase
        $ip_12 = "82.29.88.44" ascii wide nocase
        $ip_13 = "147.45.178.61" ascii wide nocase
        $ip_14 = "1.53.114.181" ascii wide nocase
        $ip_15 = "104.28.160.197" ascii wide nocase
        $ip_16 = "114.10.99.126" ascii wide nocase
        $ip_17 = "130.12.182.154" ascii wide nocase
        $ip_18 = "157.15.40.74" ascii wide nocase
        $ip_19 = "202.56.2.126" ascii wide nocase
        $ip_20 = "209.146.60.26" ascii wide nocase
        $ip_21 = "49.156.40.126" ascii wide nocase
        $ip_22 = "83.147.12.83" ascii wide nocase
        $ip_23 = "198.37.119.56" ascii wide nocase
        $ip_24 = "172.66.171.73" ascii wide nocase
        $ip_25 = "38.242.246.176" ascii wide nocase
        $ip_26 = "69.49.241.120" ascii wide nocase
        $ip_27 = "13.5.2.1" ascii wide nocase
        $ip_28 = "7.8.10.2" ascii wide nocase
        $dom_29 = "rockwellautomation.com" ascii wide nocase
        $dom_30 = "firebaseio.com" ascii wide nocase
        $dom_31 = "www.xiongmaitech.com" ascii wide nocase
        $dom_32 = "open.substack.com" ascii wide nocase
        $dom_33 = "otx.alienvault.com" ascii wide nocase
        $dom_34 = "getsession.org" ascii wide nocase
        $dom_35 = "www.torproject.org" ascii wide nocase
        $dom_36 = "x.com" ascii wide nocase
        $dom_37 = "beeble.com" ascii wide nocase
        $dom_38 = "www.imperva.com" ascii wide nocase
        $dom_39 = "www.silobreaker.com" ascii wide nocase
        $dom_40 = "www.sonicwall.com" ascii wide nocase
        $dom_41 = "www.kaspersky.com" ascii wide nocase
        $dom_42 = "cpuid.com" ascii wide nocase
        $dom_43 = "welcome.supp0v3.com" ascii wide nocase
        $dom_44 = "www.brighttalk.com" ascii wide nocase
        $dom_45 = "boomplay.com" ascii wide nocase
        $dom_46 = "index.crates.io" ascii wide nocase
        $dom_47 = "search.defillama.com" ascii wide nocase
        $dom_48 = "senselive.io" ascii wide nocase
        $dom_49 = "www.carlsonsw.com" ascii wide nocase
        $dom_50 = "0x666.info" ascii wide nocase
        $dom_51 = "documentation.wazuh.com" ascii wide nocase
        $dom_52 = "www.cvedetails.com" ascii wide nocase
        $dom_53 = "www.first.org" ascii wide nocase
        $dom_54 = "api.first.org" ascii wide nocase
        $dom_55 = "support.industry.siemens.com" ascii wide nocase
        $dom_56 = "www.siemens.com" ascii wide nocase
        $dom_57 = "cloud.flowiseai.com" ascii wide nocase
        $dom_58 = "docs.metasploit.com" ascii wide nocase
        $dom_59 = "leakix.net" ascii wide nocase
        $dom_60 = "module.info" ascii wide nocase
        $dom_61 = "yadea.com" ascii wide nocase
        $dom_62 = "api.qpft5.com" ascii wide nocase
        $dom_63 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_64 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_65 = "cyberdudebivash.com" ascii wide nocase
        $dom_66 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_67 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_68 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_69 = "metacpan.org" ascii wide nocase
        $dom_70 = "obfuscator.io" ascii wide nocase
        $dom_71 = "support.sw.siemens.com" ascii wide nocase
        $dom_72 = "www.sw.siemens.com" ascii wide nocase
        $dom_73 = "nuevaprodeciencia.club" ascii wide nocase
        $dom_74 = "odaracani.online" ascii wide nocase
        $dom_75 = "pastebin.com" ascii wide nocase
        $dom_76 = "vmi3003111.contaboserver.net" ascii wide nocase
        $dom_77 = "pdfl.io" ascii wide nocase
        $dom_78 = "polygon.drpc.org" ascii wide nocase
        $dom_79 = "raw.githubusercontent.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}