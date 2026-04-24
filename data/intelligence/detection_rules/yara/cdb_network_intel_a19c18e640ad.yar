rule CDB_SENTINEL_Network_Intel_a19c18e640ad
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-24"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "a19c18e640ad"
        ioc_count = 82

    strings:
        $ip_0 = "198.187.29.19" ascii wide nocase
        $ip_1 = "13.5.2.1" ascii wide nocase
        $ip_2 = "7.8.10.2" ascii wide nocase
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
        $ip_24 = "4.3.2.8" ascii wide nocase
        $ip_25 = "9.1.08.001" ascii wide nocase
        $dom_26 = "0x666.info" ascii wide nocase
        $dom_27 = "www.brighttalk.com" ascii wide nocase
        $dom_28 = "senselive.io" ascii wide nocase
        $dom_29 = "firebaseio.com" ascii wide nocase
        $dom_30 = "api.qpft5.com" ascii wide nocase
        $dom_31 = "open.substack.com" ascii wide nocase
        $dom_32 = "otx.alienvault.com" ascii wide nocase
        $dom_33 = "pdfl.io" ascii wide nocase
        $dom_34 = "rockwellautomation.com" ascii wide nocase
        $dom_35 = "support.industry.siemens.com" ascii wide nocase
        $dom_36 = "www.siemens.com" ascii wide nocase
        $dom_37 = "beeble.com" ascii wide nocase
        $dom_38 = "www.imperva.com" ascii wide nocase
        $dom_39 = "www.silobreaker.com" ascii wide nocase
        $dom_40 = "www.sonicwall.com" ascii wide nocase
        $dom_41 = "www.kaspersky.com" ascii wide nocase
        $dom_42 = "cpuid.com" ascii wide nocase
        $dom_43 = "welcome.supp0v3.com" ascii wide nocase
        $dom_44 = "getsession.org" ascii wide nocase
        $dom_45 = "www.torproject.org" ascii wide nocase
        $dom_46 = "x.com" ascii wide nocase
        $dom_47 = "company.com" ascii wide nocase
        $dom_48 = "www.xiongmaitech.com" ascii wide nocase
        $dom_49 = "docs.metasploit.com" ascii wide nocase
        $dom_50 = "leakix.net" ascii wide nocase
        $dom_51 = "module.info" ascii wide nocase
        $dom_52 = "boomplay.com" ascii wide nocase
        $dom_53 = "index.crates.io" ascii wide nocase
        $dom_54 = "support.sw.siemens.com" ascii wide nocase
        $dom_55 = "www.sw.siemens.com" ascii wide nocase
        $dom_56 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_57 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_58 = "cyberdudebivash.com" ascii wide nocase
        $dom_59 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_60 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_61 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_62 = "search.defillama.com" ascii wide nocase
        $dom_63 = "www.npmjs.com" ascii wide nocase
        $dom_64 = "www.carlsonsw.com" ascii wide nocase
        $dom_65 = "documentation.wazuh.com" ascii wide nocase
        $dom_66 = "www.cvedetails.com" ascii wide nocase
        $dom_67 = "www.first.org" ascii wide nocase
        $dom_68 = "api.first.org" ascii wide nocase
        $dom_69 = "format.com" ascii wide nocase
        $dom_70 = "larozada.com" ascii wide nocase
        $dom_71 = "login.microsoftonline.com" ascii wide nocase
        $dom_72 = "office.com" ascii wide nocase
        $dom_73 = "saicares.com" ascii wide nocase
        $dom_74 = "securedocsportal.com" ascii wide nocase
        $dom_75 = "cloud.flowiseai.com" ascii wide nocase
        $dom_76 = "facil.io" ascii wide nocase
        $dom_77 = "yadea.com" ascii wide nocase
        $dom_78 = "metacpan.org" ascii wide nocase
        $dom_79 = "digitalocean.com" ascii wide nocase
        $dom_80 = "polygon.drpc.org" ascii wide nocase
        $dom_81 = "raw.githubusercontent.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}