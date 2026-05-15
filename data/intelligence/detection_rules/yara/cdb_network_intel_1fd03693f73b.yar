rule CDB_SENTINEL_Network_Intel_1fd03693f73b
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-05-15"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "1fd03693f73b"
        ioc_count = 81

    strings:
        $ip_0 = "147.45.178.61" ascii wide nocase
        $ip_1 = "83.142.209.194" ascii wide nocase
        $ip_2 = "4.3.04.7" ascii wide nocase
        $ip_3 = "4.9.04.16" ascii wide nocase
        $ip_4 = "5.0.05.4" ascii wide nocase
        $ip_5 = "5.1.05.8" ascii wide nocase
        $ip_6 = "5.9.05.12" ascii wide nocase
        $ip_7 = "149.50.97.144" ascii wide nocase
        $ip_8 = "45.78.214.188" ascii wide nocase
        $ip_9 = "49.51.68.143" ascii wide nocase
        $ip_10 = "20.12.5.4" ascii wide nocase
        $ip_11 = "20.12.6.2" ascii wide nocase
        $ip_12 = "20.12.7.1" ascii wide nocase
        $ip_13 = "20.15.4.4" ascii wide nocase
        $ip_14 = "20.15.5.2" ascii wide nocase
        $ip_15 = "20.18.2.2" ascii wide nocase
        $ip_16 = "26.1.1.1" ascii wide nocase
        $dom_17 = "cpuid.com" ascii wide nocase
        $dom_18 = "welcome.supp0v3.com" ascii wide nocase
        $dom_19 = "evil.com" ascii wide nocase
        $dom_20 = "cdn.tailwindcss.com" ascii wide nocase
        $dom_21 = "support.industry.siemens.com" ascii wide nocase
        $dom_22 = "www.siemens.com" ascii wide nocase
        $dom_23 = "support.sw.siemens.com" ascii wide nocase
        $dom_24 = "artemis.apache.org" ascii wide nocase
        $dom_25 = "www.universal-robots.com" ascii wide nocase
        $dom_26 = "helper.zulipchat.com" ascii wide nocase
        $dom_27 = "tutamail.com" ascii wide nocase
        $dom_28 = "kaspersky.com" ascii wide nocase
        $dom_29 = "www.brighttalk.com" ascii wide nocase
        $dom_30 = "breakdream.com" ascii wide nocase
        $dom_31 = "cmailer.pro" ascii wide nocase
        $dom_32 = "dreamdie.com" ascii wide nocase
        $dom_33 = "group.com" ascii wide nocase
        $dom_34 = "mylingocoin.com" ascii wide nocase
        $dom_35 = "supportzm.com" ascii wide nocase
        $dom_36 = "zmsupport.com" ascii wide nocase
        $dom_37 = "tp-link.com" ascii wide nocase
        $dom_38 = "veracara.digicert.com" ascii wide nocase
        $dom_39 = "abb.com" ascii wide nocase
        $dom_40 = "cve.org" ascii wide nocase
        $dom_41 = "apps.googleusercontent.com" ascii wide nocase
        $dom_42 = "internal.com" ascii wide nocase
        $dom_43 = "my.salesforce.com" ascii wide nocase
        $dom_44 = "www.googleapis.com" ascii wide nocase
        $dom_45 = "00857cca77b615c369f48ead5f8eb7f3.com" ascii wide nocase
        $dom_46 = "0aa0cf0637d66c0d.com" ascii wide nocase
        $dom_47 = "31d58c226fc5a0aa976e13ca9ecebcc8.com" ascii wide nocase
        $dom_48 = "3k7m1n9p4q2r6s8t0v5w2x4y6z8u9.com" ascii wide nocase
        $dom_49 = "442fe7151fb1e9b5.com" ascii wide nocase
        $dom_50 = "6b86b273ff34fce1.online" ascii wide nocase
        $dom_51 = "7x2k9n4p1q0r5s8t3v6w0y2z4u7b9.com" ascii wide nocase
        $dom_52 = "8b21a945159f23b740c836eb50953818.com" ascii wide nocase
        $dom_53 = "8f00b204e9800998.com" ascii wide nocase
        $dom_54 = "a7b37115ce3cc2eb.com" ascii wide nocase
        $dom_55 = "a8d3b9e1f5c7024d6e0b7a2c9f1d83e5.com" ascii wide nocase
        $dom_56 = "aa86a52a98162b7d.com" ascii wide nocase
        $dom_57 = "af4760df2c08896a9638e26e7dd20aae.com" ascii wide nocase
        $dom_58 = "asdk2.com" ascii wide nocase
        $dom_59 = "b5e9a2d7f4c8e3b1a0d6f2e9c5b8a7d.com" ascii wide nocase
        $dom_60 = "cfe47df26c8eaf0a7c136b50c703e173.com" ascii wide nocase
        $dom_61 = "e4f8c1b9a2d7e3f6c0b5a8d9e2f1c4d.com" ascii wide nocase
        $dom_62 = "amazonses.com" ascii wide nocase
        $dom_63 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_64 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_65 = "cyberdudebivash.com" ascii wide nocase
        $dom_66 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_67 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_68 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_69 = "gmail.com" ascii wide nocase
        $dom_70 = "linuxtesting.org" ascii wide nocase
        $dom_71 = "lore.kernel.org" ascii wide nocase
        $dom_72 = "redhat.com" ascii wide nocase
        $dom_73 = "rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org" ascii wide nocase
        $dom_74 = "rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org" ascii wide nocase
        $dom_75 = "getsession.org" ascii wide nocase
        $dom_76 = "www.torproject.org" ascii wide nocase
        $dom_77 = "x.com" ascii wide nocase
        $dom_78 = "raw.githubusercontent.com" ascii wide nocase
        $dom_79 = "issue.net" ascii wide nocase
        $dom_80 = "chamd5.org" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}