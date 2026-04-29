rule CDB_SENTINEL_Network_Intel_8abbecff2521
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-29"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "8abbecff2521"
        ioc_count = 66

    strings:
        $ip_0 = "13.5.2.1" ascii wide nocase
        $ip_1 = "7.8.10.2" ascii wide nocase
        $ip_2 = "65.111.25.67" ascii wide nocase
        $ip_3 = "65.111.27.132" ascii wide nocase
        $ip_4 = "1.53.114.181" ascii wide nocase
        $ip_5 = "104.28.160.197" ascii wide nocase
        $ip_6 = "114.10.99.126" ascii wide nocase
        $ip_7 = "124.248.183.139" ascii wide nocase
        $ip_8 = "130.12.182.154" ascii wide nocase
        $ip_9 = "157.15.40.74" ascii wide nocase
        $ip_10 = "202.56.2.126" ascii wide nocase
        $ip_11 = "209.146.60.26" ascii wide nocase
        $ip_12 = "49.156.40.126" ascii wide nocase
        $ip_13 = "83.147.12.83" ascii wide nocase
        $ip_14 = "21.235.92.139" ascii wide nocase
        $ip_15 = "45.8.0.2" ascii wide nocase
        $ip_16 = "48.8.0.4" ascii wide nocase
        $ip_17 = "51.7.0.77" ascii wide nocase
        $ip_18 = "52.8.0.4" ascii wide nocase
        $ip_19 = "61.8.0.5" ascii wide nocase
        $ip_20 = "62.8.0.4" ascii wide nocase
        $ip_21 = "63.8.0.4" ascii wide nocase
        $ip_22 = "63.8.0.5" ascii wide nocase
        $dom_23 = "li.protechts.net" ascii wide nocase
        $dom_24 = "company.com" ascii wide nocase
        $dom_25 = "issue.net" ascii wide nocase
        $dom_26 = "docs.metasploit.com" ascii wide nocase
        $dom_27 = "gmail.com" ascii wide nocase
        $dom_28 = "metasploit.com" ascii wide nocase
        $dom_29 = "intrado.com" ascii wide nocase
        $dom_30 = "pdfl.io" ascii wide nocase
        $dom_31 = "support.industry.siemens.com" ascii wide nocase
        $dom_32 = "www.siemens.com" ascii wide nocase
        $dom_33 = "corporate.spicejet.com" ascii wide nocase
        $dom_34 = "blog.gitguardian.com" ascii wide nocase
        $dom_35 = "checkmarx.com" ascii wide nocase
        $dom_36 = "cybernews.com" ascii wide nocase
        $dom_37 = "cybernewsweekly.substack.com" ascii wide nocase
        $dom_38 = "labs.cloudsecurityalliance.org" ascii wide nocase
        $dom_39 = "ransomware.live" ascii wide nocase
        $dom_40 = "research.jfrog.com" ascii wide nocase
        $dom_41 = "thehackernews.com" ascii wide nocase
        $dom_42 = "www.darkreading.com" ascii wide nocase
        $dom_43 = "www.docker.com" ascii wide nocase
        $dom_44 = "www.endorlabs.com" ascii wide nocase
        $dom_45 = "www.esecurityplanet.com" ascii wide nocase
        $dom_46 = "www.helpnetsecurity.com" ascii wide nocase
        $dom_47 = "www.mend.io" ascii wide nocase
        $dom_48 = "vercel.com" ascii wide nocase
        $dom_49 = "milesight.com" ascii wide nocase
        $dom_50 = "www.milesight.com" ascii wide nocase
        $dom_51 = "attacker.com" ascii wide nocase
        $dom_52 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_53 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_54 = "cyberdudebivash.com" ascii wide nocase
        $dom_55 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_56 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_57 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_58 = "news.sophos.com" ascii wide nocase
        $dom_59 = "simple-help.com" ascii wide nocase
        $dom_60 = "go.recordedfuture.com" ascii wide nocase
        $dom_61 = "leakix.net" ascii wide nocase
        $dom_62 = "module.info" ascii wide nocase
        $dom_63 = "documents.info" ascii wide nocase
        $dom_64 = "senselive.io" ascii wide nocase
        $dom_65 = "ghcr.io" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}