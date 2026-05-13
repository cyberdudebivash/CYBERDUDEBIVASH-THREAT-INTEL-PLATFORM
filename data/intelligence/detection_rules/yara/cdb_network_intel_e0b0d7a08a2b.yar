rule CDB_SENTINEL_Network_Intel_e0b0d7a08a2b
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-05-13"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "e0b0d7a08a2b"
        ioc_count = 75

    strings:
        $ip_0 = "45.78.214.188" ascii wide nocase
        $ip_1 = "49.51.68.143" ascii wide nocase
        $ip_2 = "5.9.8.4" ascii wide nocase
        $ip_3 = "147.45.178.61" ascii wide nocase
        $ip_4 = "5.1.7.10" ascii wide nocase
        $ip_5 = "149.50.97.144" ascii wide nocase
        $ip_6 = "4.4.04.4" ascii wide nocase
        $ip_7 = "4.4.54.4" ascii wide nocase
        $dom_8 = "00857cca77b615c369f48ead5f8eb7f3.com" ascii wide nocase
        $dom_9 = "0aa0cf0637d66c0d.com" ascii wide nocase
        $dom_10 = "31d58c226fc5a0aa976e13ca9ecebcc8.com" ascii wide nocase
        $dom_11 = "3k7m1n9p4q2r6s8t0v5w2x4y6z8u9.com" ascii wide nocase
        $dom_12 = "442fe7151fb1e9b5.com" ascii wide nocase
        $dom_13 = "6b86b273ff34fce1.online" ascii wide nocase
        $dom_14 = "7x2k9n4p1q0r5s8t3v6w0y2z4u7b9.com" ascii wide nocase
        $dom_15 = "8b21a945159f23b740c836eb50953818.com" ascii wide nocase
        $dom_16 = "8f00b204e9800998.com" ascii wide nocase
        $dom_17 = "a7b37115ce3cc2eb.com" ascii wide nocase
        $dom_18 = "a8d3b9e1f5c7024d6e0b7a2c9f1d83e5.com" ascii wide nocase
        $dom_19 = "aa86a52a98162b7d.com" ascii wide nocase
        $dom_20 = "af4760df2c08896a9638e26e7dd20aae.com" ascii wide nocase
        $dom_21 = "asdk2.com" ascii wide nocase
        $dom_22 = "b5e9a2d7f4c8e3b1a0d6f2e9c5b8a7d.com" ascii wide nocase
        $dom_23 = "cfe47df26c8eaf0a7c136b50c703e173.com" ascii wide nocase
        $dom_24 = "e4f8c1b9a2d7e3f6c0b5a8d9e2f1c4d.com" ascii wide nocase
        $dom_25 = "www.abb.com" ascii wide nocase
        $dom_26 = "tp-link.com" ascii wide nocase
        $dom_27 = "veracara.digicert.com" ascii wide nocase
        $dom_28 = "www.brighttalk.com" ascii wide nocase
        $dom_29 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_30 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_31 = "cyberdudebivash.com" ascii wide nocase
        $dom_32 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_33 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_34 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_35 = "library.e.abb.com" ascii wide nocase
        $dom_36 = "publisher.hitachienergy.com" ascii wide nocase
        $dom_37 = "www.hitachienergy.com" ascii wide nocase
        $dom_38 = "search.abb.com" ascii wide nocase
        $dom_39 = "helper.zulipchat.com" ascii wide nocase
        $dom_40 = "tutamail.com" ascii wide nocase
        $dom_41 = "kaspersky.com" ascii wide nocase
        $dom_42 = "rockwellautomation.com" ascii wide nocase
        $dom_43 = "cpuid.com" ascii wide nocase
        $dom_44 = "welcome.supp0v3.com" ascii wide nocase
        $dom_45 = "ranchermanager.docs.rancher.com" ascii wide nocase
        $dom_46 = "amazonses.com" ascii wide nocase
        $dom_47 = "chamd5.org" ascii wide nocase
        $dom_48 = "psirt.abb.com" ascii wide nocase
        $dom_49 = "www.johnsoncontrols.com" ascii wide nocase
        $dom_50 = "news.sophos.com" ascii wide nocase
        $dom_51 = "simple-help.com" ascii wide nocase
        $dom_52 = "abb.com" ascii wide nocase
        $dom_53 = "getsession.org" ascii wide nocase
        $dom_54 = "www.torproject.org" ascii wide nocase
        $dom_55 = "x.com" ascii wide nocase
        $dom_56 = "cve.org" ascii wide nocase
        $dom_57 = "gitlab.freedesktop.org" ascii wide nocase
        $dom_58 = "issue.net" ascii wide nocase
        $dom_59 = "www.maxhub.com" ascii wide nocase
        $dom_60 = "apps.googleusercontent.com" ascii wide nocase
        $dom_61 = "internal.com" ascii wide nocase
        $dom_62 = "my.salesforce.com" ascii wide nocase
        $dom_63 = "www.googleapis.com" ascii wide nocase
        $dom_64 = "de.com" ascii wide nocase
        $dom_65 = "wrned.com" ascii wide nocase
        $dom_66 = "subnet.com" ascii wide nocase
        $dom_67 = "breakdream.com" ascii wide nocase
        $dom_68 = "cmailer.pro" ascii wide nocase
        $dom_69 = "dreamdie.com" ascii wide nocase
        $dom_70 = "group.com" ascii wide nocase
        $dom_71 = "mylingocoin.com" ascii wide nocase
        $dom_72 = "supportzm.com" ascii wide nocase
        $dom_73 = "zmsupport.com" ascii wide nocase
        $dom_74 = "go.recordedfuture.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}