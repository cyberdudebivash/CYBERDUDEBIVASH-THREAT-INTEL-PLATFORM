rule CDB_SENTINEL_Network_Intel_c93d37696f1a
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-28"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "c93d37696f1a"
        ioc_count = 74

    strings:
        $ip_0 = "45.8.0.2" ascii wide nocase
        $ip_1 = "48.8.0.4" ascii wide nocase
        $ip_2 = "51.7.0.77" ascii wide nocase
        $ip_3 = "52.8.0.4" ascii wide nocase
        $ip_4 = "61.8.0.5" ascii wide nocase
        $ip_5 = "62.8.0.4" ascii wide nocase
        $ip_6 = "63.8.0.4" ascii wide nocase
        $ip_7 = "63.8.0.5" ascii wide nocase
        $ip_8 = "1.53.114.181" ascii wide nocase
        $ip_9 = "104.28.160.197" ascii wide nocase
        $ip_10 = "114.10.99.126" ascii wide nocase
        $ip_11 = "124.248.183.139" ascii wide nocase
        $ip_12 = "130.12.182.154" ascii wide nocase
        $ip_13 = "157.15.40.74" ascii wide nocase
        $ip_14 = "202.56.2.126" ascii wide nocase
        $ip_15 = "209.146.60.26" ascii wide nocase
        $ip_16 = "49.156.40.126" ascii wide nocase
        $ip_17 = "83.147.12.83" ascii wide nocase
        $ip_18 = "13.5.2.1" ascii wide nocase
        $ip_19 = "7.8.10.2" ascii wide nocase
        $ip_20 = "198.187.29.19" ascii wide nocase
        $dom_21 = "li.protechts.net" ascii wide nocase
        $dom_22 = "format.com" ascii wide nocase
        $dom_23 = "larozada.com" ascii wide nocase
        $dom_24 = "login.microsoftonline.com" ascii wide nocase
        $dom_25 = "office.com" ascii wide nocase
        $dom_26 = "saicares.com" ascii wide nocase
        $dom_27 = "securedocsportal.com" ascii wide nocase
        $dom_28 = "ecp.yusercontent.com" ascii wide nocase
        $dom_29 = "gmail.com" ascii wide nocase
        $dom_30 = "news.sophos.com" ascii wide nocase
        $dom_31 = "simple-help.com" ascii wide nocase
        $dom_32 = "docs.metasploit.com" ascii wide nocase
        $dom_33 = "metasploit.com" ascii wide nocase
        $dom_34 = "file.io" ascii wide nocase
        $dom_35 = "githab.com" ascii wide nocase
        $dom_36 = "grow.com" ascii wide nocase
        $dom_37 = "milesight.com" ascii wide nocase
        $dom_38 = "www.milesight.com" ascii wide nocase
        $dom_39 = "pdfl.io" ascii wide nocase
        $dom_40 = "blog.gitguardian.com" ascii wide nocase
        $dom_41 = "checkmarx.com" ascii wide nocase
        $dom_42 = "cybernews.com" ascii wide nocase
        $dom_43 = "cybernewsweekly.substack.com" ascii wide nocase
        $dom_44 = "labs.cloudsecurityalliance.org" ascii wide nocase
        $dom_45 = "ransomware.live" ascii wide nocase
        $dom_46 = "research.jfrog.com" ascii wide nocase
        $dom_47 = "thehackernews.com" ascii wide nocase
        $dom_48 = "www.darkreading.com" ascii wide nocase
        $dom_49 = "www.docker.com" ascii wide nocase
        $dom_50 = "www.endorlabs.com" ascii wide nocase
        $dom_51 = "www.esecurityplanet.com" ascii wide nocase
        $dom_52 = "www.helpnetsecurity.com" ascii wide nocase
        $dom_53 = "www.mend.io" ascii wide nocase
        $dom_54 = "accuvant.com" ascii wide nocase
        $dom_55 = "support.industry.siemens.com" ascii wide nocase
        $dom_56 = "www.siemens.com" ascii wide nocase
        $dom_57 = "go.recordedfuture.com" ascii wide nocase
        $dom_58 = "intrado.com" ascii wide nocase
        $dom_59 = "documentation.wazuh.com" ascii wide nocase
        $dom_60 = "www.cvedetails.com" ascii wide nocase
        $dom_61 = "www.first.org" ascii wide nocase
        $dom_62 = "api.first.org" ascii wide nocase
        $dom_63 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_64 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_65 = "cyberdudebivash.com" ascii wide nocase
        $dom_66 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_67 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_68 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_69 = "adobe-pdfreader.b-cdn.net" ascii wide nocase
        $dom_70 = "leakix.net" ascii wide nocase
        $dom_71 = "module.info" ascii wide nocase
        $dom_72 = "corporate.spicejet.com" ascii wide nocase
        $dom_73 = "company.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}