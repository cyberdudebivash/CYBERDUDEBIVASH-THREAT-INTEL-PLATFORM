rule CDB_SENTINEL_Network_Intel_4cd3dc6e9576
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-05-01"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "4cd3dc6e9576"
        ioc_count = 60

    strings:
        $ip_0 = "45.78.214.188" ascii wide nocase
        $ip_1 = "49.51.68.143" ascii wide nocase
        $ip_2 = "149.50.97.144" ascii wide nocase
        $ip_3 = "6.5.0.4" ascii wide nocase
        $ip_4 = "8.2.0.25" ascii wide nocase
        $ip_5 = "7.3.1.1" ascii wide nocase
        $ip_6 = "6.5.5.1" ascii wide nocase
        $ip_7 = "6.5.5.2" ascii wide nocase
        $dom_8 = "www.carlsonsw.com" ascii wide nocase
        $dom_9 = "intrado.com" ascii wide nocase
        $dom_10 = "psirt.abb.com" ascii wide nocase
        $dom_11 = "search.abb.com" ascii wide nocase
        $dom_12 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_13 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_14 = "cyberdudebivash.com" ascii wide nocase
        $dom_15 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_16 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_17 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_18 = "company.com" ascii wide nocase
        $dom_19 = "breakdream.com" ascii wide nocase
        $dom_20 = "cmailer.pro" ascii wide nocase
        $dom_21 = "dreamdie.com" ascii wide nocase
        $dom_22 = "group.com" ascii wide nocase
        $dom_23 = "mylingocoin.com" ascii wide nocase
        $dom_24 = "supportzm.com" ascii wide nocase
        $dom_25 = "zmsupport.com" ascii wide nocase
        $dom_26 = "00857cca77b615c369f48ead5f8eb7f3.com" ascii wide nocase
        $dom_27 = "0aa0cf0637d66c0d.com" ascii wide nocase
        $dom_28 = "31d58c226fc5a0aa976e13ca9ecebcc8.com" ascii wide nocase
        $dom_29 = "3k7m1n9p4q2r6s8t0v5w2x4y6z8u9.com" ascii wide nocase
        $dom_30 = "442fe7151fb1e9b5.com" ascii wide nocase
        $dom_31 = "6b86b273ff34fce1.online" ascii wide nocase
        $dom_32 = "7x2k9n4p1q0r5s8t3v6w0y2z4u7b9.com" ascii wide nocase
        $dom_33 = "8b21a945159f23b740c836eb50953818.com" ascii wide nocase
        $dom_34 = "8f00b204e9800998.com" ascii wide nocase
        $dom_35 = "a7b37115ce3cc2eb.com" ascii wide nocase
        $dom_36 = "a8d3b9e1f5c7024d6e0b7a2c9f1d83e5.com" ascii wide nocase
        $dom_37 = "aa86a52a98162b7d.com" ascii wide nocase
        $dom_38 = "af4760df2c08896a9638e26e7dd20aae.com" ascii wide nocase
        $dom_39 = "asdk2.com" ascii wide nocase
        $dom_40 = "b5e9a2d7f4c8e3b1a0d6f2e9c5b8a7d.com" ascii wide nocase
        $dom_41 = "cfe47df26c8eaf0a7c136b50c703e173.com" ascii wide nocase
        $dom_42 = "e4f8c1b9a2d7e3f6c0b5a8d9e2f1c4d.com" ascii wide nocase
        $dom_43 = "accuvant.com" ascii wide nocase
        $dom_44 = "docs.metasploit.com" ascii wide nocase
        $dom_45 = "gmail.com" ascii wide nocase
        $dom_46 = "apps.googleusercontent.com" ascii wide nocase
        $dom_47 = "internal.com" ascii wide nocase
        $dom_48 = "my.salesforce.com" ascii wide nocase
        $dom_49 = "www.googleapis.com" ascii wide nocase
        $dom_50 = "academy.canonical.com" ascii wide nocase
        $dom_51 = "archive.ubuntu.com" ascii wide nocase
        $dom_52 = "assets.ubuntu.com" ascii wide nocase
        $dom_53 = "blog.ubuntu.com" ascii wide nocase
        $dom_54 = "canonical.com" ascii wide nocase
        $dom_55 = "developer.ubuntu.com" ascii wide nocase
        $dom_56 = "maas.io" ascii wide nocase
        $dom_57 = "portal.canonical.com" ascii wide nocase
        $dom_58 = "security.ubuntu.com" ascii wide nocase
        $dom_59 = "ubuntu.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}