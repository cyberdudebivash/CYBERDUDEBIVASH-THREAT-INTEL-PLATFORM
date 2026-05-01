rule CDB_SENTINEL_Hash_Intel_cca5cebd4156
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects files referencing known malicious hashes"
        date = "2026-05-01"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
        $h_0 = "cd531ebe1014bfd18185bf21585ca5cdb16fbcb07703ebc47949a1b4e4e36bc3" ascii nocase
        $h_1 = "421a4ad2615941b177b6ec4ab5e239c14e62af2ab07c6df1741e2a62223223c4" ascii nocase
        $h_2 = "61aca585687ec21a182342a40de3eaa12d3fc0d92577456cae0df37c3ed28e99" ascii nocase
        $h_3 = "2b99ade9224add2ce86eb836dcf70040315f6dc95e772ea98f24a30cdf4fdb97" ascii nocase
        $h_4 = "ee07a74d12c0bb3594965b51d0e45b6f" ascii nocase

    condition:
        filesize < 100MB and any of them
}