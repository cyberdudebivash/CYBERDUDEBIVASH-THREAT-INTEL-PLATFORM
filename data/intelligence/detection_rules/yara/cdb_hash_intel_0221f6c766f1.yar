rule CDB_SENTINEL_Hash_Intel_0221f6c766f1
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects files referencing known malicious hashes"
        date = "2026-04-27"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
        $h_0 = "1b62b7c2ed7cc296ce821f977ef7b22bae59ef1dcdb9a34ae19467ee39bcf168" ascii nocase
        $h_1 = "97c275e3406ad6576529f41604ad138c5bdc4297d195bf61b049e14f6b30adfd" ascii nocase

    condition:
        filesize < 100MB and any of them
}