rule CDB_SENTINEL_Hash_Intel_c52c0f8d60d7
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects files referencing known malicious hashes"
        date = "2026-04-18"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
        $h_0 = "353ddce78d58aef2083ca0ac271af93659cf0039b0b29d0d169fc015bd3610bc" ascii nocase
        $h_1 = "4849f76dafbef516df91fecfc23a72afffaf77ade51f805eae5ad552bed88923" ascii nocase
        $h_2 = "c7489e3bf546c5f2d958ac833cc7dbca4368dfba03a792849bc99c48a6b2a14f" ascii nocase
        $h_3 = "d9b576eb6827f38e33eda037d2cda4261307511303254a8509eeb28048433b2f" ascii nocase
        $h_4 = "2b99ade9224add2ce86eb836dcf70040315f6dc95e772ea98f24a30cdf4fdb97" ascii nocase
        $h_5 = "08fd0a82cdeb0a963b7416cf57446564dfed5de5c6f66dee94b36d28bfefec9d" ascii nocase
        $h_6 = "cfd2e466ea5ac50f9d9267f3535a68a23e4ff62e3fe3e20a30ec52024553c564" ascii nocase
        $h_7 = "90de84bb542adb54766fec66ee554475b7e1a56a9d8b30e3598230f9ef6d6ac7" ascii nocase
        $h_8 = "66B553A8B94CE37C16F4EBC863D51FCC" ascii nocase
        $h_9 = "c7c37f314ae926822d38ce089fab13e0" ascii nocase
        $h_10 = "db78ca341aeff5b26f2d062cc1f7c16a" ascii nocase

    condition:
        filesize < 100MB and any of them
}