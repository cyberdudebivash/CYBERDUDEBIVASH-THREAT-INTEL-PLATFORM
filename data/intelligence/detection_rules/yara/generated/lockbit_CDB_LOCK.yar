/*
 * CYBERDUDEBIVASH® SENTINEL APEX — YARA Rule
 * Generated: 2026-04-04
 * Rule ID:   CDB_LOCKBIT_9499DB
 * Severity:  CRITICAL
 * MITRE:     T1486, T1490
 * Source:    https://intel.cyberdudebivash.com
 *
 * PRODUCTION DEPLOYMENT:
 *   yara -r this_rule.yar /path/to/scan/
 *   or import into EDR platform (CrowdStrike, SentinelOne, etc.)
 */
rule CDB_Malware_Lockbit_9499DB {
    meta:
        description = "Detects Lockbit malware behavioral artifacts"
        author = "CYBERDUDEBIVASH SENTINEL APEX v82.0"
        date = "2026-04-04"
        malware_family = "Lockbit"
        severity = "CRITICAL"
    strings:
        $lb1 = "LockBit" ascii wide nocase
        $lb2 = ".lockbit" ascii wide nocase
        $lb3 = "vssadmin delete shadows" ascii wide nocase
        $lb4 = "Restore-My-Files.txt" ascii wide
    condition:
        2 of them
}
