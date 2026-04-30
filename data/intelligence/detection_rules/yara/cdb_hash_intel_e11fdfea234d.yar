rule CDB_SENTINEL_Hash_Intel_e11fdfea234d
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects files referencing known malicious hashes"
        date = "2026-04-30"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
        $h_0 = "cd531ebe1014bfd18185bf21585ca5cdb16fbcb07703ebc47949a1b4e4e36bc3" ascii nocase
        $h_1 = "421a4ad2615941b177b6ec4ab5e239c14e62af2ab07c6df1741e2a62223223c4" ascii nocase
        $h_2 = "61aca585687ec21a182342a40de3eaa12d3fc0d92577456cae0df37c3ed28e99" ascii nocase
        $h_3 = "58e17dd61d4d55fa77c7f2dd28dd51875b0ce900c1e43b368b349e65f27d6fdd" ascii nocase
        $h_4 = "8ee4ec425bc0d8db050d13bbff98f483fff020050d49f40c5055ca2b9f6b1c4d" ascii nocase
        $h_5 = "9c745f95a09b37bc0486bf0f92aad4a3d5548a939c086b93d6235d34648e683f" ascii nocase
        $h_6 = "a7eadcf81dd6fda0dd6affefaffcb33b1d8f64ddec6e5a1772d028ef2a7da0f2" ascii nocase
        $h_7 = "e1fc59c7ece6e9a7fb262fc8529e3c4905503a1ca44630f9724b2ccc518d0c06" ascii nocase
        $h_8 = "e512d22d2bd989f35ebaccb63615434870dc0642b0f60e6d4bda0bb89adee27a" ascii nocase
        $h_9 = "19CC41A0A056E503CC2137E19E952814FBDF14F8D83F799AEA9B96ABFF11EFBB" ascii nocase
        $h_10 = "2F31D00FEEFE181F2D8B69033B382462FF19C35367753E6906ED80F815A7924F" ascii nocase
        $h_11 = "325daeb781f3416a383343820064c8e98f2e31753cd71d76a886fe0dbb4fe59a" ascii nocase
        $h_12 = "4D74F8E12FF69318BE5EB383B4E56178817E84E83D3607213160276A7328AB5D" ascii nocase
        $h_13 = "76e4962b8ccd2e6fd6972d9c3264ccb6738ddb16066588dfcb223222aaa88f3c" ascii nocase
        $h_14 = "7a35008a1a1ae3d093703c3a34a21993409af42eb61161aad1b6ae4afa8bbb70" ascii nocase
        $h_15 = "a9e9d7770ff948bb65c0db24431f75dd934a803181afa22b6b014fac9a162dab" ascii nocase
        $h_16 = "b287c0bc239b434b90eef01bcbd00ff48192b7cbeb540e568b8cdcdc26f90959" ascii nocase
        $h_17 = "ca47c8710c4ffb4908a42bd986b14cddcca39e30bb0b11ed5ca16fe8922a468b" ascii nocase
        $h_18 = "2b99ade9224add2ce86eb836dcf70040315f6dc95e772ea98f24a30cdf4fdb97" ascii nocase
        $h_19 = "1d9e4ece8e13c8eaf94cb858470d1bd8f81bb58f62583552303774fa1579edee" ascii nocase
        $h_20 = "258257560fe2f1c2cc3924eae40718c829085b52ae3436b4e46d2565f6996271" ascii nocase
        $h_21 = "4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34" ascii nocase
        $h_22 = "86282ebcd3bebf50f087f2c6b00c62caa667cdcb53558033d85acd39e3d88b41" ascii nocase
        $h_23 = "a1da198bb4e883d077a0e13351bf2c3acdea10497152292e873d79d4f7420211" ascii nocase
        $h_24 = "eb6eb4154b03ec73218727dc643d26f4e14dfda2438112926bb5daf37ae8bcdb" ascii nocase
        $h_25 = "ee07a74d12c0bb3594965b51d0e45b6f" ascii nocase
        $h_26 = "c6eed09fc8b174b0f3eebedcceb1e792" ascii nocase
        $h_27 = "4AFDC05708B8B39C82E60ABE3ACE55DB" ascii nocase
        $h_28 = "C7610AE28655D6C1BCE88B5D09624FEF" ascii nocase
        $h_29 = "E05DF8EE759E2C955ACC8D8A47A08F42" ascii nocase

    condition:
        filesize < 100MB and any of them
}