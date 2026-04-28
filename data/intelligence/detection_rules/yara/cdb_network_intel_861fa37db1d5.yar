rule CDB_SENTINEL_Network_Intel_861fa37db1d5
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects network IOCs from threat intelligence feeds"
        date = "2026-04-28"
        severity = "high"
        reference = "https://intel.cyberdudebivash.com"
        batch_id = "861fa37db1d5"
        ioc_count = 72

    strings:
        $ip_0 = "13.5.2.1" ascii wide nocase
        $ip_1 = "7.8.10.2" ascii wide nocase
        $ip_2 = "45.8.0.2" ascii wide nocase
        $ip_3 = "48.8.0.4" ascii wide nocase
        $ip_4 = "51.7.0.77" ascii wide nocase
        $ip_5 = "52.8.0.4" ascii wide nocase
        $ip_6 = "61.8.0.5" ascii wide nocase
        $ip_7 = "62.8.0.4" ascii wide nocase
        $ip_8 = "63.8.0.4" ascii wide nocase
        $ip_9 = "63.8.0.5" ascii wide nocase
        $ip_10 = "1.53.114.181" ascii wide nocase
        $ip_11 = "104.28.160.197" ascii wide nocase
        $ip_12 = "114.10.99.126" ascii wide nocase
        $ip_13 = "124.248.183.139" ascii wide nocase
        $ip_14 = "130.12.182.154" ascii wide nocase
        $ip_15 = "157.15.40.74" ascii wide nocase
        $ip_16 = "202.56.2.126" ascii wide nocase
        $ip_17 = "209.146.60.26" ascii wide nocase
        $ip_18 = "49.156.40.126" ascii wide nocase
        $ip_19 = "83.147.12.83" ascii wide nocase
        $ip_20 = "21.235.92.139" ascii wide nocase
        $dom_21 = "corporate.spicejet.com" ascii wide nocase
        $dom_22 = "documentation.wazuh.com" ascii wide nocase
        $dom_23 = "www.cvedetails.com" ascii wide nocase
        $dom_24 = "www.first.org" ascii wide nocase
        $dom_25 = "api.first.org" ascii wide nocase
        $dom_26 = "company.com" ascii wide nocase
        $dom_27 = "intrado.com" ascii wide nocase
        $dom_28 = "blog.gitguardian.com" ascii wide nocase
        $dom_29 = "checkmarx.com" ascii wide nocase
        $dom_30 = "cybernews.com" ascii wide nocase
        $dom_31 = "cybernewsweekly.substack.com" ascii wide nocase
        $dom_32 = "labs.cloudsecurityalliance.org" ascii wide nocase
        $dom_33 = "ransomware.live" ascii wide nocase
        $dom_34 = "research.jfrog.com" ascii wide nocase
        $dom_35 = "thehackernews.com" ascii wide nocase
        $dom_36 = "www.darkreading.com" ascii wide nocase
        $dom_37 = "www.docker.com" ascii wide nocase
        $dom_38 = "www.endorlabs.com" ascii wide nocase
        $dom_39 = "www.esecurityplanet.com" ascii wide nocase
        $dom_40 = "www.helpnetsecurity.com" ascii wide nocase
        $dom_41 = "www.mend.io" ascii wide nocase
        $dom_42 = "go.recordedfuture.com" ascii wide nocase
        $dom_43 = "pdfl.io" ascii wide nocase
        $dom_44 = "support.industry.siemens.com" ascii wide nocase
        $dom_45 = "www.siemens.com" ascii wide nocase
        $dom_46 = "file.io" ascii wide nocase
        $dom_47 = "accuvant.com" ascii wide nocase
        $dom_48 = "docs.metasploit.com" ascii wide nocase
        $dom_49 = "gmail.com" ascii wide nocase
        $dom_50 = "api.cyberdudebivash.com" ascii wide nocase
        $dom_51 = "blog.cyberdudebivash.com" ascii wide nocase
        $dom_52 = "cyberdudebivash.com" ascii wide nocase
        $dom_53 = "intel.cyberdudebivash.com" ascii wide nocase
        $dom_54 = "tools.cyberdudebivash.com" ascii wide nocase
        $dom_55 = "www.cyberdudebivash.com" ascii wide nocase
        $dom_56 = "milesight.com" ascii wide nocase
        $dom_57 = "www.milesight.com" ascii wide nocase
        $dom_58 = "news.sophos.com" ascii wide nocase
        $dom_59 = "simple-help.com" ascii wide nocase
        $dom_60 = "metasploit.com" ascii wide nocase
        $dom_61 = "attacker.com" ascii wide nocase
        $dom_62 = "leakix.net" ascii wide nocase
        $dom_63 = "module.info" ascii wide nocase
        $dom_64 = "li.protechts.net" ascii wide nocase
        $dom_65 = "ghcr.io" ascii wide nocase
        $dom_66 = "mcp.railway.com" ascii wide nocase
        $dom_67 = "vercel.com" ascii wide nocase
        $dom_68 = "issue.net" ascii wide nocase
        $dom_69 = "adobe-pdfreader.b-cdn.net" ascii wide nocase
        $dom_70 = "githab.com" ascii wide nocase
        $dom_71 = "grow.com" ascii wide nocase

    condition:
        filesize < 100MB and any of them
}