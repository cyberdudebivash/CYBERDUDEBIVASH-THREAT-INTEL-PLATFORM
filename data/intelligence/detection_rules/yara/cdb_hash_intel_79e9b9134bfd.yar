rule CDB_SENTINEL_Hash_Intel_79e9b9134bfd
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
        $h_4 = "08fd0a82cdeb0a963b7416cf57446564dfed5de5c6f66dee94b36d28bfefec9d" ascii nocase
        $h_5 = "cfd2e466ea5ac50f9d9267f3535a68a23e4ff62e3fe3e20a30ec52024553c564" ascii nocase
        $h_6 = "90de84bb542adb54766fec66ee554475b7e1a56a9d8b30e3598230f9ef6d6ac7" ascii nocase
        $h_7 = "2b99ade9224add2ce86eb836dcf70040315f6dc95e772ea98f24a30cdf4fdb97" ascii nocase
        $h_8 = "4f2b7d46148b786fae75ab511dc27b6a530f63669d4fe9908e5f22801dea9202" ascii nocase
        $h_9 = "33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f" ascii nocase
        $h_10 = "6a85736b64761a8b2aaeadc1c0087e1897d16cc5a9d49c6a6ea1164233bad206" ascii nocase
        $h_11 = "70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980" ascii nocase
        $h_12 = "9e3890d43366faec26523edaf91712640056ea2481cdefe2f5dfa6b2b642085d" ascii nocase
        $h_13 = "66B553A8B94CE37C16F4EBC863D51FCC" ascii nocase
        $h_14 = "107484d66423cb601f418344cd648f12" ascii nocase
        $h_15 = "34a0f70ab100c47caaba7a5c85448e3d" ascii nocase
        $h_16 = "7528bf597fd7764fcb7ec06512e073e0" ascii nocase
        $h_17 = "8354223cd6198b05904337b5dff7772b" ascii nocase
        $h_18 = "c7c37f314ae926822d38ce089fab13e0" ascii nocase
        $h_19 = "db78ca341aeff5b26f2d062cc1f7c16a" ascii nocase
        $h_20 = "346272f0582541ae5dd08429bb4dc4ff" ascii nocase
        $h_21 = "A6FA4ADFC20E8E6B77E2DD631DC8FF18" ascii nocase
        $h_22 = "dcf5a9b27cbeedb769ccc8635d204af9" ascii nocase
        $h_23 = "f77c8e40dfc17be5e74d8679d5b35341" ascii nocase
        $h_24 = "808c87015194c51d74356854dfb10d9e" ascii nocase
        $h_25 = "d7a68749635604d6d7297e4fa2530eb6" ascii nocase

    condition:
        filesize < 100MB and any of them
}