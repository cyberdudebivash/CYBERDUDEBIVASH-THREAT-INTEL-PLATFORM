rule CDB_SENTINEL_Hash_Intel_3a6432478380
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects files referencing known malicious hashes"
        date = "2026-04-20"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
        $h_0 = "2b99ade9224add2ce86eb836dcf70040315f6dc95e772ea98f24a30cdf4fdb97" ascii nocase
        $h_1 = "08fd0a82cdeb0a963b7416cf57446564dfed5de5c6f66dee94b36d28bfefec9d" ascii nocase
        $h_2 = "cfd2e466ea5ac50f9d9267f3535a68a23e4ff62e3fe3e20a30ec52024553c564" ascii nocase
        $h_3 = "353ddce78d58aef2083ca0ac271af93659cf0039b0b29d0d169fc015bd3610bc" ascii nocase
        $h_4 = "4849f76dafbef516df91fecfc23a72afffaf77ade51f805eae5ad552bed88923" ascii nocase
        $h_5 = "c7489e3bf546c5f2d958ac833cc7dbca4368dfba03a792849bc99c48a6b2a14f" ascii nocase
        $h_6 = "d9b576eb6827f38e33eda037d2cda4261307511303254a8509eeb28048433b2f" ascii nocase
        $h_7 = "4f2b7d46148b786fae75ab511dc27b6a530f63669d4fe9908e5f22801dea9202" ascii nocase
        $h_8 = "33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f" ascii nocase
        $h_9 = "6a85736b64761a8b2aaeadc1c0087e1897d16cc5a9d49c6a6ea1164233bad206" ascii nocase
        $h_10 = "70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980" ascii nocase
        $h_11 = "9e3890d43366faec26523edaf91712640056ea2481cdefe2f5dfa6b2b642085d" ascii nocase
        $h_12 = "90de84bb542adb54766fec66ee554475b7e1a56a9d8b30e3598230f9ef6d6ac7" ascii nocase
        $h_13 = "025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a" ascii nocase
        $h_14 = "078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b" ascii nocase
        $h_15 = "1eece1e1ba4b96e6c784729f0608ad2939cfb67bc4236dfababbe1d09268960c" ascii nocase
        $h_16 = "22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67" ascii nocase
        $h_17 = "2ed9494e9b7b68415b4eb151c922c82c0191294d0aa443dd2cb5133e6bfe3d5d" ascii nocase
        $h_18 = "3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235" ascii nocase
        $h_19 = "48d9b2ce4fcd6854a3164ce395d7140014e0b58b77680623f3e4ca22d3a6e7fd" ascii nocase
        $h_20 = "5dc607c8990841139768884b1b43e1403496d5a458788a1937be139594f01dca" ascii nocase
        $h_21 = "62c2c24937d67fdeb43f2c9690ab10e8bb90713af46945048db9a94a465ffcb8" ascii nocase
        $h_22 = "788ba200f776a188c248d6c2029f00b5d34be45d4444f7cb89ffe838c39b8b19" ascii nocase
        $h_23 = "808c87015194c51d74356854dfb10d9e" ascii nocase
        $h_24 = "d7a68749635604d6d7297e4fa2530eb6" ascii nocase
        $h_25 = "66B553A8B94CE37C16F4EBC863D51FCC" ascii nocase
        $h_26 = "107484d66423cb601f418344cd648f12" ascii nocase
        $h_27 = "34a0f70ab100c47caaba7a5c85448e3d" ascii nocase
        $h_28 = "7528bf597fd7764fcb7ec06512e073e0" ascii nocase
        $h_29 = "8354223cd6198b05904337b5dff7772b" ascii nocase
        $h_30 = "346272f0582541ae5dd08429bb4dc4ff" ascii nocase
        $h_31 = "A6FA4ADFC20E8E6B77E2DD631DC8FF18" ascii nocase
        $h_32 = "dcf5a9b27cbeedb769ccc8635d204af9" ascii nocase
        $h_33 = "f77c8e40dfc17be5e74d8679d5b35341" ascii nocase
        $h_34 = "c7c37f314ae926822d38ce089fab13e0" ascii nocase
        $h_35 = "db78ca341aeff5b26f2d062cc1f7c16a" ascii nocase
        $h_36 = "0565364633b5acdd24a498a6a9ab4eca" ascii nocase
        $h_37 = "114721fbc23ff9d188535bd736a0d30e" ascii nocase
        $h_38 = "19733e0dfa804e3676f97eff90f2e467" ascii nocase
        $h_39 = "31d25ddf2697b9e13ee883fff328b22f" ascii nocase
        $h_40 = "4126348d783393dd85ede3468e48405d" ascii nocase
        $h_41 = "417ae7f384c49de8c672aec86d5a2860" ascii nocase
        $h_42 = "5bdae6cb778d002c806bb7ed130985f3" ascii nocase
        $h_43 = "686989d97cf0d70346cbde2031207cbf" ascii nocase
        $h_44 = "79fe383f0963ae741193989c12aefacc" ascii nocase
        $h_45 = "7b4c61ff418f6fe80cf8adb474278311" ascii nocase

    condition:
        filesize < 100MB and any of them
}