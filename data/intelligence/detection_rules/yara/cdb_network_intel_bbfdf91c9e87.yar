rule CDB_SENTINEL_Network_Intel_bbfdf91c9e87
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-21"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "bbfdf91c9e87"
        ioc_count = 67

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
        $ip_10 = "198.187.29.19" ascii wide nocase
        $ip_11 = "1.53.114.181" ascii wide nocase
        $ip_12 = "104.28.160.197" ascii wide nocase
        $ip_13 = "114.10.99.126" ascii wide nocase
        $ip_14 = "130.12.182.154" ascii wide nocase
        $ip_15 = "157.15.40.74" ascii wide nocase
        $ip_16 = "202.56.2.126" ascii wide nocase
        $ip_17 = "209.146.60.26" ascii wide nocase
        $ip_18 = "49.156.40.126" ascii wide nocase
        $ip_19 = "83.147.12.83" ascii wide nocase
        $ip_20 = "147.45.178.61" ascii wide nocase
        $ip_21 = "13.5.2.1" ascii wide nocase
        $ip_22 = "7.8.10.2" ascii wide nocase
        $dom_23 = "getsession.org" ascii wide nocase
        $dom_24 = "www.torproject.org" ascii wide nocase
        $dom_25 = "x.com" ascii wide nocase
        $dom_26 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_27 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_28 = "cyberdudebivash.com" ascii wide nocase
        $dom_29 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_30 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_31 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_32 = "documentation.wazuh.com" ascii wide nocase
        $dom_33 = "www.cvedetails.com" ascii wide nocase
        $dom_34 = "www.first.org" ascii wide nocase
        $dom_35 = "api.first.org" ascii wide nocase
        $dom_36 = "www.brighttalk.com" ascii wide nocase
        $dom_37 = "gmail.com" ascii wide nocase
        $dom_38 = "rockwellautomation.com" ascii wide nocase
        $dom_39 = "api.qpft5.com" ascii wide nocase
        $dom_40 = "softwaresupportsp.aveva.com" ascii wide nocase
        $dom_41 = "www.aveva.com" ascii wide nocase
        $dom_42 = "ecp.yusercontent.com" ascii wide nocase
        $dom_43 = "filecenter.deltaww.com" ascii wide nocase
        $dom_44 = "www.deltaww.com" ascii wide nocase
        $dom_45 = "110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com" ascii wide nocase
        $dom_46 = "open.substack.com" ascii wide nocase
        $dom_47 = "otx.alienvault.com" ascii wide nocase
        $dom_48 = "cpuid.com" ascii wide nocase
        $dom_49 = "welcome.supp0v3.com" ascii wide nocase
        $dom_50 = "format.com" ascii wide nocase
        $dom_51 = "larozada.com" ascii wide nocase
        $dom_52 = "login.microsoftonline.com" ascii wide nocase
        $dom_53 = "office.com" ascii wide nocase
        $dom_54 = "saicares.com" ascii wide nocase
        $dom_55 = "securedocsportal.com" ascii wide nocase
        $dom_56 = "company.com" ascii wide nocase
        $dom_57 = "pdfl.io" ascii wide nocase
        $dom_58 = "0x666.info" ascii wide nocase
        $dom_59 = "hornerautomation.com" ascii wide nocase
        $dom_60 = "docs.metasploit.com" ascii wide nocase
        $dom_61 = "leakix.net" ascii wide nocase
        $dom_62 = "module.info" ascii wide nocase
        $dom_63 = "www.npmjs.com" ascii wide nocase
        $dom_64 = "trafficreqort.com" ascii wide nocase
        $dom_65 = "discord.com" ascii wide nocase
        $dom_66 = "malware-traffic-analysis.net" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}