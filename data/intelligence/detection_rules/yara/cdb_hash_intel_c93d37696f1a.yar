rule CDB_SENTINEL_Hash_Intel_c93d37696f1a
{
    meta:
        author = "CyberDudeBivash SENTINEL APEX v51"
        description = "Detects files referencing known malicious hashes"
        date = "2026-04-28"
        severity = "critical"
        reference = "https://intel.cyberdudebivash.com"

    strings:
        $h_0 = "2b99ade9224add2ce86eb836dcf70040315f6dc95e772ea98f24a30cdf4fdb97" ascii nocase
        $h_1 = "b2d9a99de44a7cd8faf396d0482268369d14a315edaf18a36fa273ffd5500108" ascii nocase
        $h_2 = "61aca585687ec21a182342a40de3eaa12d3fc0d92577456cae0df37c3ed28e99" ascii nocase
        $h_3 = "d4c184f4389d710c8aefe296486d4d3e430da609d86fa6289a8cea9fde4a1166" ascii nocase
        $h_4 = "19CC41A0A056E503CC2137E19E952814FBDF14F8D83F799AEA9B96ABFF11EFBB" ascii nocase
        $h_5 = "2F31D00FEEFE181F2D8B69033B382462FF19C35367753E6906ED80F815A7924F" ascii nocase
        $h_6 = "325daeb781f3416a383343820064c8e98f2e31753cd71d76a886fe0dbb4fe59a" ascii nocase
        $h_7 = "4D74F8E12FF69318BE5EB383B4E56178817E84E83D3607213160276A7328AB5D" ascii nocase
        $h_8 = "76e4962b8ccd2e6fd6972d9c3264ccb6738ddb16066588dfcb223222aaa88f3c" ascii nocase
        $h_9 = "7a35008a1a1ae3d093703c3a34a21993409af42eb61161aad1b6ae4afa8bbb70" ascii nocase
        $h_10 = "a9e9d7770ff948bb65c0db24431f75dd934a803181afa22b6b014fac9a162dab" ascii nocase
        $h_11 = "b287c0bc239b434b90eef01bcbd00ff48192b7cbeb540e568b8cdcdc26f90959" ascii nocase
        $h_12 = "ca47c8710c4ffb4908a42bd986b14cddcca39e30bb0b11ed5ca16fe8922a468b" ascii nocase
        $h_13 = "5c3bf036ab8aadddb2428d27f3917b86" ascii nocase
        $h_14 = "4AFDC05708B8B39C82E60ABE3ACE55DB" ascii nocase
        $h_15 = "C7610AE28655D6C1BCE88B5D09624FEF" ascii nocase
        $h_16 = "E05DF8EE759E2C955ACC8D8A47A08F42" ascii nocase

    condition:
        filesize < 100MB and any of them
}