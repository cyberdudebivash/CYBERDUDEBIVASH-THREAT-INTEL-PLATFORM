rule CDB_SENTINEL_Network_Intel_f0e468738ef1
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-22"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "f0e468738ef1"
        ioc_count = 71

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
        $ip_11 = "147.45.178.61" ascii wide nocase
        $ip_12 = "1.53.114.181" ascii wide nocase
        $ip_13 = "104.28.160.197" ascii wide nocase
        $ip_14 = "114.10.99.126" ascii wide nocase
        $ip_15 = "130.12.182.154" ascii wide nocase
        $ip_16 = "157.15.40.74" ascii wide nocase
        $ip_17 = "202.56.2.126" ascii wide nocase
        $ip_18 = "209.146.60.26" ascii wide nocase
        $ip_19 = "49.156.40.126" ascii wide nocase
        $ip_20 = "83.147.12.83" ascii wide nocase
        $ip_21 = "13.5.2.1" ascii wide nocase
        $ip_22 = "7.8.10.2" ascii wide nocase
        $dom_23 = "documentation.wazuh.com" ascii wide nocase
        $dom_24 = "www.cvedetails.com" ascii wide nocase
        $dom_25 = "www.first.org" ascii wide nocase
        $dom_26 = "api.first.org" ascii wide nocase
        $dom_27 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_28 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_29 = "cyberdudebivash.com" ascii wide nocase
        $dom_30 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_31 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_32 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_33 = "rockwellautomation.com" ascii wide nocase
        $dom_34 = "support.industry.siemens.com" ascii wide nocase
        $dom_35 = "www.siemens.com" ascii wide nocase
        $dom_36 = "api.qpft5.com" ascii wide nocase
        $dom_37 = "format.com" ascii wide nocase
        $dom_38 = "larozada.com" ascii wide nocase
        $dom_39 = "login.microsoftonline.com" ascii wide nocase
        $dom_40 = "office.com" ascii wide nocase
        $dom_41 = "saicares.com" ascii wide nocase
        $dom_42 = "securedocsportal.com" ascii wide nocase
        $dom_43 = "0x666.info" ascii wide nocase
        $dom_44 = "filecenter.deltaww.com" ascii wide nocase
        $dom_45 = "www.deltaww.com" ascii wide nocase
        $dom_46 = "softwaresupportsp.aveva.com" ascii wide nocase
        $dom_47 = "www.aveva.com" ascii wide nocase
        $dom_48 = "open.substack.com" ascii wide nocase
        $dom_49 = "otx.alienvault.com" ascii wide nocase
        $dom_50 = "senselive.io" ascii wide nocase
        $dom_51 = "metacpan.org" ascii wide nocase
        $dom_52 = "cpuid.com" ascii wide nocase
        $dom_53 = "welcome.supp0v3.com" ascii wide nocase
        $dom_54 = "boomplay.com" ascii wide nocase
        $dom_55 = "index.crates.io" ascii wide nocase
        $dom_56 = "support.sw.siemens.com" ascii wide nocase
        $dom_57 = "www.sw.siemens.com" ascii wide nocase
        $dom_58 = "pdfl.io" ascii wide nocase
        $dom_59 = "www.npmjs.com" ascii wide nocase
        $dom_60 = "docs.metasploit.com" ascii wide nocase
        $dom_61 = "leakix.net" ascii wide nocase
        $dom_62 = "module.info" ascii wide nocase
        $dom_63 = "hornerautomation.com" ascii wide nocase
        $dom_64 = "getsession.org" ascii wide nocase
        $dom_65 = "www.torproject.org" ascii wide nocase
        $dom_66 = "x.com" ascii wide nocase
        $dom_67 = "www.brighttalk.com" ascii wide nocase
        $dom_68 = "company.com" ascii wide nocase
        $dom_69 = "trafficreqort.com" ascii wide nocase
        $dom_70 = "gmail.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}