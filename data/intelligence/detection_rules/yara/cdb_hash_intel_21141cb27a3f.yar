rule CDB_SENTINEL_Hash_Intel_21141cb27a3f
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects files referencing known malicious hashes"
        date = "2026-04-24"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
        $h_0 = "0f41fd82cac71e27c36eb90c0bf305d6006b4f3d59e8ba55faeacbe62aadef90" ascii nocase
        $h_1 = "24af069b8899893cfc7347a4e5b46d717d77994a4b140d58de0be029dba686c9" ascii nocase
        $h_2 = "4b08a9e221a20b8024cf778d113732b3e12d363250231e78bae13b1f1dc1495b" ascii nocase
        $h_3 = "85bed283ba95d40d99e79437e6a3161336c94ec0acbc0cd38599d0fc9b2e393c" ascii nocase
        $h_4 = "871d8f92b008a75607c9f1feb4922b9a02ac7bd2ed61b71ca752a5bed5448bf3" ascii nocase
        $h_5 = "89616a503ffee8fc70f13c82c4a5e4fa4efafa61410971f4327ed38328af2938" ascii nocase
        $h_6 = "a73ce18952b40fd621789e43c56b2af08d1497ce3560b2481fa973d8265ce491" ascii nocase
        $h_7 = "a9562ab6bce06e92d4e428088eacc1e990e67ceae6f6940047360261b5599614" ascii nocase
        $h_8 = "cc31b3dc8aeed0af9dd24b7e739f183527d55d5b5ecd3d93ba45dd4aaa8ba260" ascii nocase
        $h_9 = "dfee6ea9cafc674b93a8460b9e6beea7f0eb0c28e28d1190309347fd1514dbb6" ascii nocase
        $h_10 = "025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a" ascii nocase
        $h_11 = "078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b" ascii nocase
        $h_12 = "1eece1e1ba4b96e6c784729f0608ad2939cfb67bc4236dfababbe1d09268960c" ascii nocase
        $h_13 = "22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67" ascii nocase
        $h_14 = "2ed9494e9b7b68415b4eb151c922c82c0191294d0aa443dd2cb5133e6bfe3d5d" ascii nocase
        $h_15 = "3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235" ascii nocase
        $h_16 = "48d9b2ce4fcd6854a3164ce395d7140014e0b58b77680623f3e4ca22d3a6e7fd" ascii nocase
        $h_17 = "5dc607c8990841139768884b1b43e1403496d5a458788a1937be139594f01dca" ascii nocase
        $h_18 = "62c2c24937d67fdeb43f2c9690ab10e8bb90713af46945048db9a94a465ffcb8" ascii nocase
        $h_19 = "788ba200f776a188c248d6c2029f00b5d34be45d4444f7cb89ffe838c39b8b19" ascii nocase
        $h_20 = "0d10a6472facabf7d7a8cfd2492fc990b890754c3d90888ef9fe5b2d2cca41c0" ascii nocase
        $h_21 = "95dcac62fc15e99d112d812f7687292e34de0e8e0a39e4f12082f726fa1b50ed" ascii nocase
        $h_22 = "2fa987b9ed6ec6d09c7451abd994249dfaba1c5a7da1c22b8407c461e62f7e49" ascii nocase
        $h_23 = "691f7258f212fa8908a8bf06bcf9e027d2177276e13e10ff56bd434ff3755cc4" ascii nocase
        $h_24 = "6e6dab993f99505646051d2772701e3c4740096ff9be63c92713bcb7fcddf9f7" ascii nocase
        $h_25 = "7f1d71e1e079f3244a69205588d504ed830d4c473747bb1b5c520634cc5a2477" ascii nocase
        $h_26 = "c8940de8cb917abe158a826a1d08f1083af517351d01642e6c7f324d0bba1eb8" ascii nocase
        $h_27 = "ca390b86793922555c84abc3b34406da2899382c617f9dcf83a74ac09dd18190" ascii nocase
        $h_28 = "de200b79ad2bd9db37baeba5e4d183498d450494c71c8929433681e848c3807f" ascii nocase
        $h_29 = "45bff0df2c408b3f589aed984cc331b617021ecbea57171dac719b5f545f5e8d" ascii nocase
        $h_30 = "4ed176edb75ae2114cda8cfb3f83ac2ecdc4476fa1ef30ad8c81a54c0a223a29" ascii nocase
        $h_31 = "6ccacb7567b6c0bd2ca8e68ff59d5ef21e8f47fc1af70d4d88a421f1fc5280fc" ascii nocase
        $h_32 = "61aca585687ec21a182342a40de3eaa12d3fc0d92577456cae0df37c3ed28e99" ascii nocase
        $h_33 = "33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f" ascii nocase
        $h_34 = "6a85736b64761a8b2aaeadc1c0087e1897d16cc5a9d49c6a6ea1164233bad206" ascii nocase
        $h_35 = "70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980" ascii nocase
        $h_36 = "9e3890d43366faec26523edaf91712640056ea2481cdefe2f5dfa6b2b642085d" ascii nocase
        $h_37 = "90de84bb542adb54766fec66ee554475b7e1a56a9d8b30e3598230f9ef6d6ac7" ascii nocase
        $h_38 = "4f2b7d46148b786fae75ab511dc27b6a530f63669d4fe9908e5f22801dea9202" ascii nocase
        $h_39 = "5fd682cdfdf2de867be2a4bd378a2c206370c18a598975a11c99dba121e36b1b" ascii nocase
        $h_40 = "0565364633b5acdd24a498a6a9ab4eca" ascii nocase
        $h_41 = "114721fbc23ff9d188535bd736a0d30e" ascii nocase
        $h_42 = "19733e0dfa804e3676f97eff90f2e467" ascii nocase
        $h_43 = "31d25ddf2697b9e13ee883fff328b22f" ascii nocase
        $h_44 = "4126348d783393dd85ede3468e48405d" ascii nocase
        $h_45 = "417ae7f384c49de8c672aec86d5a2860" ascii nocase
        $h_46 = "5bdae6cb778d002c806bb7ed130985f3" ascii nocase
        $h_47 = "686989d97cf0d70346cbde2031207cbf" ascii nocase
        $h_48 = "79fe383f0963ae741193989c12aefacc" ascii nocase
        $h_49 = "7b4c61ff418f6fe80cf8adb474278311" ascii nocase
        $h_50 = "c7c37f314ae926822d38ce089fab13e0" ascii nocase
        $h_51 = "db78ca341aeff5b26f2d062cc1f7c16a" ascii nocase
        $h_52 = "107484d66423cb601f418344cd648f12" ascii nocase
        $h_53 = "34a0f70ab100c47caaba7a5c85448e3d" ascii nocase
        $h_54 = "7528bf597fd7764fcb7ec06512e073e0" ascii nocase
        $h_55 = "8354223cd6198b05904337b5dff7772b" ascii nocase
        $h_56 = "346272f0582541ae5dd08429bb4dc4ff" ascii nocase
        $h_57 = "A6FA4ADFC20E8E6B77E2DD631DC8FF18" ascii nocase
        $h_58 = "dcf5a9b27cbeedb769ccc8635d204af9" ascii nocase
        $h_59 = "f77c8e40dfc17be5e74d8679d5b35341" ascii nocase
        $h_60 = "808c87015194c51d74356854dfb10d9e" ascii nocase
        $h_61 = "d7a68749635604d6d7297e4fa2530eb6" ascii nocase
        $h_62 = "15af977ce25de452b96affa2addb1036" ascii nocase
        $h_63 = "285fea57345d838916153c4d8f43ab6c" ascii nocase
        $h_64 = "826d6350724f203b911aa6c8c4626391" ascii nocase
        $h_65 = "a48c0d5f95b1ef98f560f324fd275da1" ascii nocase

    condition:
        filesize < 100MB and any of them
}