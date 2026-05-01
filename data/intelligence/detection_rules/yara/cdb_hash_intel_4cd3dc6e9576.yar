rule CDB_SENTINEL_Hash_Intel_4cd3dc6e9576
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects files referencing known malicious hashes"
        date = "2026-05-01"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
        $h_0 = "272c86c6db95f1ef8b83f672b65e64df16494cae261e1aba1aeb1e59dcb68524" ascii nocase
        $h_1 = "29f89486bb820d40c9bee8bf70ee8664ea270b16e486af4a53ab703996943256" ascii nocase
        $h_2 = "2c40e7cf613bf2806ff6e9bc396058fe4f85926493979189dbdbc7d615b7cb14" ascii nocase
        $h_3 = "33580073680016f23bf474e6e62c61bf6a776e561385bfb06788a4713114ba9d" ascii nocase
        $h_4 = "3b47df790abb4eb3ac570b50bf96bb1943d4b46851430ebf3fc36f645061491b" ascii nocase
        $h_5 = "3b85d0261ab2531aba9e2992eb85273be0e26fe61e4592862d8f45d6807ceee4" ascii nocase
        $h_6 = "498961237cf1c48f1e7764829818c5ba0af24a234c2f29c4420fb80276aec676" ascii nocase
        $h_7 = "4f4567abe9ff520797b04b04255bbbe07ecdddb594559d436ac53314ec62c1b3" ascii nocase
        $h_8 = "53f1b841d323c211c715b8f80d0efb9529440caae921a60340de027052946dd9" ascii nocase
        $h_9 = "54305c7b95d8105601461bb18de87f1f679d833f15e38a9ee7895a0c8605c0d0" ascii nocase
        $h_10 = "61aca585687ec21a182342a40de3eaa12d3fc0d92577456cae0df37c3ed28e99" ascii nocase
        $h_11 = "2b99ade9224add2ce86eb836dcf70040315f6dc95e772ea98f24a30cdf4fdb97" ascii nocase
        $h_12 = "03f00a143b8929585c122d490b6a3895d639c17d92C2223917e3a9ca1b8d30f9" ascii nocase
        $h_13 = "1a30d6cdb0b98feed62563be8050db55ae0156ed437701d36a7b46aabf086ede" ascii nocase
        $h_14 = "603848f37ab932dccef98ee27e3c5af9221d3b6ccfe457ccf93cb572495ac325" ascii nocase
        $h_15 = "b452C2da7c012eda25a1403b3313444b5eb7C2c3e25eee489f1bd256f8434735" ascii nocase
        $h_16 = "b525837273dde06b86b5f93f9aeC2C29665324105b0b66f6df81884754f8080d" ascii nocase
        $h_17 = "c3e5d878a30a6c46e22d1dd2089b32086c91f13f8b9c413aa84e1dbaa03b9375" ascii nocase
        $h_18 = "c8f7608d4e19f6cb03680941bbd09fe969668bcb09c7ca985048a22e014dffcd" ascii nocase
        $h_19 = "01ac6012d4316b68bb3165ee451f2fcc494e4e37011a73b8cf2680de3364fcf4" ascii nocase
        $h_20 = "2d1891b6d0c158ad7280f0f30f3c9d913960a793c6abcda249f9c76e13014e45" ascii nocase
        $h_21 = "59cbdecfc01eba859d12fbeb48f96fe3fe841ac1aafa6bd38eff92f0dcfd4554" ascii nocase
        $h_22 = "aef34f14456358db91840c416e55acc7d10185ff2beb362ea24697d7cdad321f" ascii nocase
        $h_23 = "b0726bdd53083968870d0b147b72dad422d6d04f27cd52a7891d038ee83aef5b" ascii nocase
        $h_24 = "ba9b1f4cc2c7f4aeda7a1280bbc901671f4ec3edaa17f1db676e17651e9bff5f" ascii nocase
        $h_25 = "3712793d3847dd0962361aa528fa124c" ascii nocase
        $h_26 = "4e4f2dfe143ba261fd8a18d1c4b58f2e" ascii nocase
        $h_27 = "c91725905b273e81e9cc6983a11c8d60" ascii nocase
        $h_28 = "eb7635f4836c9e0aa4c315b18b051cb5" ascii nocase
        $h_29 = "00857cca77b615c369f48ead5f8eb7f3" ascii nocase
        $h_30 = "31d58c226fc5a0aa976e13ca9ecebcc8" ascii nocase
        $h_31 = "8b21a945159f23b740c836eb50953818" ascii nocase
        $h_32 = "a8d3b9e1f5c7024d6e0b7a2c9f1d83e5" ascii nocase
        $h_33 = "af4760df2c08896a9638e26e7dd20aae" ascii nocase
        $h_34 = "cfe47df26c8eaf0a7c136b50c703e173" ascii nocase
        $h_35 = "0c855f87a7574b28df383eca5084fcdc" ascii nocase
        $h_36 = "8a9bd7e7a806b2cc606b7a1d8f495662" ascii nocase
        $h_37 = "993AE4FE78B879239BDC14DFBC0963CD" ascii nocase
        $h_38 = "c8eb024c053f82831f2738bd48afc256" ascii nocase

    condition:
        filesize < 100MB and any of them
}