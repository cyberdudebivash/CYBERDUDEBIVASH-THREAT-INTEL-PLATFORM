rule CDB_SENTINEL_Network_Intel_eef55f783fab
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-05-23"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "eef55f783fab"
        ioc_count = 69

    strings:
        $ip_0 = "20.12.5.4" ascii wide nocase
        $ip_1 = "20.12.6.1" ascii wide nocase
        $ip_2 = "20.12.6.2" ascii wide nocase
        $ip_3 = "20.12.7.1" ascii wide nocase
        $ip_4 = "20.15.4.4" ascii wide nocase
        $ip_5 = "20.15.5.2" ascii wide nocase
        $ip_6 = "20.18.2.2" ascii wide nocase
        $ip_7 = "20.9.9.1" ascii wide nocase
        $ip_8 = "26.1.1.1" ascii wide nocase
        $ip_9 = "149.50.97.144" ascii wide nocase
        $ip_10 = "5.5.0.85" ascii wide nocase
        $ip_11 = "147.45.178.61" ascii wide nocase
        $ip_12 = "179.43.185.226" ascii wide nocase
        $ip_13 = "104.194.152.246" ascii wide nocase
        $ip_14 = "140.82.6.45" ascii wide nocase
        $ip_15 = "144.172.111.49" ascii wide nocase
        $ip_16 = "144.172.88.18" ascii wide nocase
        $ip_17 = "144.172.99.68" ascii wide nocase
        $ip_18 = "149.248.78.202" ascii wide nocase
        $ip_19 = "149.28.96.170" ascii wide nocase
        $ip_20 = "207.246.114.50" ascii wide nocase
        $ip_21 = "45.59.122.231" ascii wide nocase
        $ip_22 = "45.76.241.51" ascii wide nocase
        $ip_23 = "46.225.231.170" ascii wide nocase
        $ip_24 = "64.190.113.187" ascii wide nocase
        $ip_25 = "64.94.85.158" ascii wide nocase
        $ip_26 = "87.120.186.229" ascii wide nocase
        $ip_27 = "96.9.125.29" ascii wide nocase
        $dom_28 = "investors.SentinelOne.com" ascii wide nocase
        $dom_29 = "rockwellautomation.com" ascii wide nocase
        $dom_30 = "malicious-site.com" ascii wide nocase
        $dom_31 = "helper.zulipchat.com" ascii wide nocase
        $dom_32 = "tutamail.com" ascii wide nocase
        $dom_33 = "kaspersky.com" ascii wide nocase
        $dom_34 = "apps.googleusercontent.com" ascii wide nocase
        $dom_35 = "internal.com" ascii wide nocase
        $dom_36 = "my.salesforce.com" ascii wide nocase
        $dom_37 = "www.googleapis.com" ascii wide nocase
        $dom_38 = "rapid7.com" ascii wide nocase
        $dom_39 = "getsession.org" ascii wide nocase
        $dom_40 = "www.torproject.org" ascii wide nocase
        $dom_41 = "x.com" ascii wide nocase
        $dom_42 = "docs.metasploit.com" ascii wide nocase
        $dom_43 = "nothink.org" ascii wide nocase
        $dom_44 = "cpuid.com" ascii wide nocase
        $dom_45 = "welcome.supp0v3.com" ascii wide nocase
        $dom_46 = "issue.net" ascii wide nocase
        $dom_47 = "amazonses.com" ascii wide nocase
        $dom_48 = "company.com" ascii wide nocase
        $dom_49 = "company.sharepoint.com" ascii wide nocase
        $dom_50 = "gmail.com" ascii wide nocase
        $dom_51 = "organization.com" ascii wide nocase
        $dom_52 = "organization.sharepoint.com" ascii wide nocase
        $dom_53 = "golang.org" ascii wide nocase
        $dom_54 = "onmicrosoft.com" ascii wide nocase
        $dom_55 = "UCICasociacion.onmicrosoft.com" ascii wide nocase
        $dom_56 = "breakdream.com" ascii wide nocase
        $dom_57 = "cmailer.pro" ascii wide nocase
        $dom_58 = "dreamdie.com" ascii wide nocase
        $dom_59 = "group.com" ascii wide nocase
        $dom_60 = "mylingocoin.com" ascii wide nocase
        $dom_61 = "supportzm.com" ascii wide nocase
        $dom_62 = "zmsupport.com" ascii wide nocase
        $dom_63 = "chamd5.org" ascii wide nocase
        $dom_64 = "cve.org" ascii wide nocase
        $dom_65 = "www.brighttalk.com" ascii wide nocase
        $dom_66 = "news.sophos.com" ascii wide nocase
        $dom_67 = "simple-help.com" ascii wide nocase
        $dom_68 = "go.recordedfuture.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}