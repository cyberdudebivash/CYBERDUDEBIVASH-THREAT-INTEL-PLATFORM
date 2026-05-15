rule CDB_SENTINEL_Network_Intel_59a620d1eeaa
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-05-15"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "59a620d1eeaa"
        ioc_count = 79

    strings:
        $ip_0 = "47.252.11.99" ascii wide nocase
        $ip_1 = "47.90.180.205" ascii wide nocase
        $ip_2 = "149.50.97.144" ascii wide nocase
        $ip_3 = "45.78.214.188" ascii wide nocase
        $ip_4 = "49.51.68.143" ascii wide nocase
        $ip_5 = "147.45.178.61" ascii wide nocase
        $ip_6 = "11.136.0.8" ascii wide nocase
        $ip_7 = "4.3.04.7" ascii wide nocase
        $ip_8 = "4.9.04.16" ascii wide nocase
        $ip_9 = "5.0.05.4" ascii wide nocase
        $ip_10 = "5.1.05.8" ascii wide nocase
        $ip_11 = "5.9.05.12" ascii wide nocase
        $dom_12 = "amazonses.com" ascii wide nocase
        $dom_13 = "cve.org" ascii wide nocase
        $dom_14 = "getsession.org" ascii wide nocase
        $dom_15 = "www.torproject.org" ascii wide nocase
        $dom_16 = "x.com" ascii wide nocase
        $dom_17 = "support.industry.siemens.com" ascii wide nocase
        $dom_18 = "www.siemens.com" ascii wide nocase
        $dom_19 = "breakdream.com" ascii wide nocase
        $dom_20 = "cmailer.pro" ascii wide nocase
        $dom_21 = "dreamdie.com" ascii wide nocase
        $dom_22 = "group.com" ascii wide nocase
        $dom_23 = "mylingocoin.com" ascii wide nocase
        $dom_24 = "supportzm.com" ascii wide nocase
        $dom_25 = "zmsupport.com" ascii wide nocase
        $dom_26 = "www.trendmicro.com" ascii wide nocase
        $dom_27 = "support.sw.siemens.com" ascii wide nocase
        $dom_28 = "go.recordedfuture.com" ascii wide nocase
        $dom_29 = "chamd5.org" ascii wide nocase
        $dom_30 = "www.brighttalk.com" ascii wide nocase
        $dom_31 = "artemis.apache.org" ascii wide nocase
        $dom_32 = "helper.zulipchat.com" ascii wide nocase
        $dom_33 = "tutamail.com" ascii wide nocase
        $dom_34 = "kaspersky.com" ascii wide nocase
        $dom_35 = "apps.googleusercontent.com" ascii wide nocase
        $dom_36 = "internal.com" ascii wide nocase
        $dom_37 = "my.salesforce.com" ascii wide nocase
        $dom_38 = "www.googleapis.com" ascii wide nocase
        $dom_39 = "rockwellautomation.com" ascii wide nocase
        $dom_40 = "news.sophos.com" ascii wide nocase
        $dom_41 = "simple-help.com" ascii wide nocase
        $dom_42 = "www.universal-robots.com" ascii wide nocase
        $dom_43 = "issue.net" ascii wide nocase
        $dom_44 = "gmail.com" ascii wide nocase
        $dom_45 = "linuxtesting.org" ascii wide nocase
        $dom_46 = "lore.kernel.org" ascii wide nocase
        $dom_47 = "redhat.com" ascii wide nocase
        $dom_48 = "rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org" ascii wide nocase
        $dom_49 = "rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org" ascii wide nocase
        $dom_50 = "abb.com" ascii wide nocase
        $dom_51 = "00857cca77b615c369f48ead5f8eb7f3.com" ascii wide nocase
        $dom_52 = "0aa0cf0637d66c0d.com" ascii wide nocase
        $dom_53 = "31d58c226fc5a0aa976e13ca9ecebcc8.com" ascii wide nocase
        $dom_54 = "3k7m1n9p4q2r6s8t0v5w2x4y6z8u9.com" ascii wide nocase
        $dom_55 = "442fe7151fb1e9b5.com" ascii wide nocase
        $dom_56 = "6b86b273ff34fce1.online" ascii wide nocase
        $dom_57 = "7x2k9n4p1q0r5s8t3v6w0y2z4u7b9.com" ascii wide nocase
        $dom_58 = "8b21a945159f23b740c836eb50953818.com" ascii wide nocase
        $dom_59 = "8f00b204e9800998.com" ascii wide nocase
        $dom_60 = "a7b37115ce3cc2eb.com" ascii wide nocase
        $dom_61 = "a8d3b9e1f5c7024d6e0b7a2c9f1d83e5.com" ascii wide nocase
        $dom_62 = "aa86a52a98162b7d.com" ascii wide nocase
        $dom_63 = "af4760df2c08896a9638e26e7dd20aae.com" ascii wide nocase
        $dom_64 = "asdk2.com" ascii wide nocase
        $dom_65 = "b5e9a2d7f4c8e3b1a0d6f2e9c5b8a7d.com" ascii wide nocase
        $dom_66 = "cfe47df26c8eaf0a7c136b50c703e173.com" ascii wide nocase
        $dom_67 = "e4f8c1b9a2d7e3f6c0b5a8d9e2f1c4d.com" ascii wide nocase
        $dom_68 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_69 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_70 = "cyberdudebivash.com" ascii wide nocase
        $dom_71 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_72 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_73 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_74 = "cpuid.com" ascii wide nocase
        $dom_75 = "welcome.supp0v3.com" ascii wide nocase
        $dom_76 = "calif.io" ascii wide nocase
        $dom_77 = "tp-link.com" ascii wide nocase
        $dom_78 = "veracara.digicert.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}