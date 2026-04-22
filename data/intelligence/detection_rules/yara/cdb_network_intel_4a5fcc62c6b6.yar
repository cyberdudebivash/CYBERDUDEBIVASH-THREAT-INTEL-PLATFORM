rule CDB_SENTINEL_Network_Intel_4a5fcc62c6b6
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-22"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "4a5fcc62c6b6"
        ioc_count = 75

    strings:
        $ip_0 = "198.187.29.19" ascii wide nocase
        $ip_1 = "124.108.54.86" ascii wide nocase
        $ip_2 = "124.248.183.139" ascii wide nocase
        $ip_3 = "143.198.143.185" ascii wide nocase
        $ip_4 = "152.42.221.239" ascii wide nocase
        $ip_5 = "160.202.35.137" ascii wide nocase
        $ip_6 = "168.144.32.17" ascii wide nocase
        $ip_7 = "182.9.35.168" ascii wide nocase
        $ip_8 = "185.213.83.150" ascii wide nocase
        $ip_9 = "37.19.205.247" ascii wide nocase
        $ip_10 = "82.29.88.44" ascii wide nocase
        $ip_11 = "13.5.2.1" ascii wide nocase
        $ip_12 = "7.8.10.2" ascii wide nocase
        $ip_13 = "1.53.114.181" ascii wide nocase
        $ip_14 = "104.28.160.197" ascii wide nocase
        $ip_15 = "114.10.99.126" ascii wide nocase
        $ip_16 = "130.12.182.154" ascii wide nocase
        $ip_17 = "157.15.40.74" ascii wide nocase
        $ip_18 = "202.56.2.126" ascii wide nocase
        $ip_19 = "209.146.60.26" ascii wide nocase
        $ip_20 = "49.156.40.126" ascii wide nocase
        $ip_21 = "83.147.12.83" ascii wide nocase
        $ip_22 = "147.45.178.61" ascii wide nocase
        $dom_23 = "www.brighttalk.com" ascii wide nocase
        $dom_24 = "senselive.io" ascii wide nocase
        $dom_25 = "api.qpft5.com" ascii wide nocase
        $dom_26 = "pdfl.io" ascii wide nocase
        $dom_27 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_28 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_29 = "cyberdudebivash.com" ascii wide nocase
        $dom_30 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_31 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_32 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_33 = "open.substack.com" ascii wide nocase
        $dom_34 = "otx.alienvault.com" ascii wide nocase
        $dom_35 = "support.industry.siemens.com" ascii wide nocase
        $dom_36 = "www.siemens.com" ascii wide nocase
        $dom_37 = "rockwellautomation.com" ascii wide nocase
        $dom_38 = "format.com" ascii wide nocase
        $dom_39 = "larozada.com" ascii wide nocase
        $dom_40 = "login.microsoftonline.com" ascii wide nocase
        $dom_41 = "office.com" ascii wide nocase
        $dom_42 = "saicares.com" ascii wide nocase
        $dom_43 = "securedocsportal.com" ascii wide nocase
        $dom_44 = "0x666.info" ascii wide nocase
        $dom_45 = "company.com" ascii wide nocase
        $dom_46 = "docs.metasploit.com" ascii wide nocase
        $dom_47 = "leakix.net" ascii wide nocase
        $dom_48 = "module.info" ascii wide nocase
        $dom_49 = "metacpan.org" ascii wide nocase
        $dom_50 = "boomplay.com" ascii wide nocase
        $dom_51 = "index.crates.io" ascii wide nocase
        $dom_52 = "support.sw.siemens.com" ascii wide nocase
        $dom_53 = "www.sw.siemens.com" ascii wide nocase
        $dom_54 = "www.npmjs.com" ascii wide nocase
        $dom_55 = "softwaresupportsp.aveva.com" ascii wide nocase
        $dom_56 = "www.aveva.com" ascii wide nocase
        $dom_57 = "cpuid.com" ascii wide nocase
        $dom_58 = "welcome.supp0v3.com" ascii wide nocase
        $dom_59 = "hornerautomation.com" ascii wide nocase
        $dom_60 = "facil.io" ascii wide nocase
        $dom_61 = "beeble.com" ascii wide nocase
        $dom_62 = "www.imperva.com" ascii wide nocase
        $dom_63 = "www.silobreaker.com" ascii wide nocase
        $dom_64 = "www.sonicwall.com" ascii wide nocase
        $dom_65 = "www.kaspersky.com" ascii wide nocase
        $dom_66 = "documentation.wazuh.com" ascii wide nocase
        $dom_67 = "www.cvedetails.com" ascii wide nocase
        $dom_68 = "www.first.org" ascii wide nocase
        $dom_69 = "api.first.org" ascii wide nocase
        $dom_70 = "filecenter.deltaww.com" ascii wide nocase
        $dom_71 = "www.deltaww.com" ascii wide nocase
        $dom_72 = "getsession.org" ascii wide nocase
        $dom_73 = "www.torproject.org" ascii wide nocase
        $dom_74 = "x.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}