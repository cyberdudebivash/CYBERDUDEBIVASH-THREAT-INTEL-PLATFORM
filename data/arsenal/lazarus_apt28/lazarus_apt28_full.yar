/*
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — YARA Arsenal v143.0.0                   ║
║  Campaign: LAZARUS GROUP (DPRK) + APT28 (FANCY BEAR / RUSSIA)            ║
║  Phase IV Asset 7 — Full Arsenal Bundle ($197)                            ║
║                                                                            ║
║  Coverage:                                                                 ║
║    - Lazarus DPRK: AppleJeus, BlindingCan, DTrack, NukeSped,             ║
║                    BeagleBoyz C2, Operation Dream Job                     ║
║    - APT28: X-Agent, Sofacy/GAMEFISH, Zebrocy, LOJAX UEFI,              ║
║             Fancy Bear dropper TTPs                                        ║
║                                                                            ║
║  MITRE ATT&CK: T1566 T1059 T1547 T1195 T1567 T1078 T1190                ║
║  Verified against: public malware samples Q1-Q2 2026                     ║
║                                                                            ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP           ║
║  License: Enterprise — see COMMERCIAL_LICENSE.md                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/

import "pe"
import "math"

// ══════════════════════════════════════════════════════════════════════════════
// LAZARUS GROUP — APPLJEUZ CRYPTOCURRENCY STEALER FAMILY
// MITRE: T1566.001 (Spearphishing), T1059.003 (Windows Command Shell)
// ══════════════════════════════════════════════════════════════════════════════

rule CDB_Lazarus_AppleJeus_Loader {
    meta:
        description     = "Detects AppleJeus cryptocurrency stealer loader stage"
        author          = "CyberDudeBivash SENTINEL APEX"
        platform        = "SENTINEL-APEX/143.0.0"
        threat_actor    = "Lazarus Group (DPRK)"
        mitre_attack    = "T1566.001, T1059.003, T1547.001"
        tlp             = "TLP:AMBER"
        severity        = "CRITICAL"
        confidence      = 85
        gstin           = "21ARKPN8270G1ZP"
        reference       = "https://www.us-cert.gov/ncas/alerts/aa21-048a"
        created         = "2026-01-01"
        modified        = "2026-05-01"

    strings:
        // AppleJeus dropper markers
        $s1 = "CryptoNeuro" ascii wide nocase
        $s2 = "JMT Trading" ascii wide nocase
        $s3 = "Celas Trade Pro" ascii wide nocase
        $s4 = "Union Crypto" ascii wide nocase

        // C2 beacon pattern
        $c1 = { 47 45 54 20 2F 6C 69 76 65 75 70 64 61 74 65 }  // "GET /liveupdate"
        $c2 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 34 }

        // Crypto wallet scraping
        $w1 = "wallet.dat" ascii wide nocase
        $w2 = "keystore" ascii wide nocase
        $w3 = ".electrum" ascii wide nocase

        // Persistence via Run key
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide

        // Obfuscation indicators
        $x1 = { 90 90 90 90 90 90 90 90 }  // NOP sled
        $x2 = { 60 9C 9D 61 }               // PUSHAD/PUSHFD...POPFD/POPAD

    condition:
        uint16(0) == 0x5A4D and                 // MZ header
        filesize < 15MB and
        (
            (2 of ($s*)) or
            ($c1 and $w1) or
            ($c2 and any of ($w*)) or
            (any of ($s*) and any of ($r*) and any of ($x*))
        )
}


rule CDB_Lazarus_BlindingCan_RAT {
    meta:
        description  = "Detects BlindingCan RAT used by Lazarus in Operation Dream Job"
        author       = "CyberDudeBivash SENTINEL APEX"
        threat_actor = "Lazarus Group (DPRK)"
        mitre_attack = "T1055.001, T1059.001, T1071.001, T1547.001"
        tlp          = "TLP:AMBER"
        severity     = "CRITICAL"
        confidence   = 88
        reference    = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-232a"

    strings:
        // BlindingCan capabilities
        $cmd1 = "GetDriveType" ascii
        $cmd2 = "EnumWindows" ascii
        $cmd3 = "WNetAddConnection2" ascii
        $cmd4 = "LookupPrivilegeValue" ascii

        // Encrypted channel markers
        $enc1 = { 68 ?? ?? ?? ?? 6A 00 FF 15 }  // push offset; call [import]
        $enc2 = { 83 EC 0C 53 55 56 57 8B }      // Common prolog pattern

        // C2 config structure
        $cfg1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 }

        // String obfuscation pattern (XOR decode loop)
        $xor1 = { 8A 04 0? 34 ?? 88 04 0? 4? 75 F? }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (3 of ($cmd*)) or
            (2 of ($cmd*) and ($enc1 or $enc2)) or
            ($xor1 and any of ($cmd*))
        )
}


rule CDB_Lazarus_DTrack_Keylogger {
    meta:
        description  = "Detects DTrack / Dacls infostealer — Lazarus Group"
        author       = "CyberDudeBivash SENTINEL APEX"
        threat_actor = "Lazarus Group (DPRK)"
        mitre_attack = "T1056.001, T1005, T1041"
        tlp          = "TLP:AMBER"
        severity     = "HIGH"
        confidence   = 80

    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "GetKeyState" ascii
        $k3 = "SetWindowsHookEx" ascii nocase
        $k4 = { 53 65 74 57 69 6E 64 6F 77 73 48 6F 6F 6B 45 78 57 }  // SetWindowsHookExW

        // Exfil pattern
        $e1 = { 50 4F 53 54 20 2F 75 70 6C 6F 61 64 }  // "POST /upload"
        $e2 = "Content-Type: application/octet-stream" ascii

        // Self-delete artefact
        $d1 = "cmd.exe /c del" ascii nocase

    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and
        (2 of ($k*)) and (any of ($e*) or $d1)
}


rule CDB_Lazarus_BeagleBoyz_C2_Traffic {
    meta:
        description  = "Detects BeagleBoyz (FASTCash) C2 communication patterns in network traffic"
        author       = "CyberDudeBivash SENTINEL APEX"
        threat_actor = "Lazarus Group — BeagleBoyz"
        mitre_attack = "T1071.001, T1573.001"
        tlp          = "TLP:RED"
        severity     = "CRITICAL"
        confidence   = 75
        type         = "network"

    strings:
        // Encoded beacon URI patterns
        $u1 = { 2F 61 70 69 2F 76 31 2F 75 73 65 72 73 2F }  // "/api/v1/users/"
        $u2 = { 2F 75 70 64 61 74 65 2F 63 68 65 63 6B }     // "/update/check"

        // Custom HTTP headers
        $h1 = "X-Forwarded-Host: " ascii
        $h2 = "CF-Connecting-IP: " ascii

        // RC4 key schedule marker
        $rc4 = { 8A 04 0A 00 D0 88 04 0B 40 41 3B C1 7C F3 }

    condition:
        any of ($u*) and any of ($h*) and $rc4
}


// ══════════════════════════════════════════════════════════════════════════════
// APT28 / FANCY BEAR (RUSSIAN GRU — UNIT 26165 / 74455)
// MITRE: T1566 T1078 T1059 T1547 T1190 T1203
// ══════════════════════════════════════════════════════════════════════════════

rule CDB_APT28_XAgent_Implant {
    meta:
        description  = "Detects X-Agent (Sofacy) modular implant used by APT28/Fancy Bear"
        author       = "CyberDudeBivash SENTINEL APEX"
        threat_actor = "APT28 (Fancy Bear / GRU Unit 26165)"
        mitre_attack = "T1059.003, T1071.001, T1547.001, T1027"
        tlp          = "TLP:AMBER"
        severity     = "CRITICAL"
        confidence   = 90
        reference    = "https://www.welivesecurity.com/2016/10/25/lifting-lid-sednit-espionage-group/"

    strings:
        // X-Agent module identifiers
        $m1 = "xagent" ascii wide nocase
        $m2 = "x-agent" ascii wide nocase
        $m3 = "Sofacy" ascii wide nocase

        // Plugin system markers
        $p1 = { 69 6E 66 6F 72 6D 65 72 }      // "informer"
        $p2 = { 72 65 6D 6F 74 65 63 6F 6E 74 72 6F 6C }  // "remotecontrol"

        // C2 protocol (custom HTTP over 443/80)
        $c1 = { 2F 78 6D 6C 2F 73 74 61 74 75 73 }  // "/xml/status"
        $c2 = { 55 73 65 72 2D 41 67 65 6E 74 }      // "User-Agent"

        // Anti-analysis: PEB check
        $a1 = { 64 A1 30 00 00 00 8B 40 0C 8B 40 14 }

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        (
            (any of ($m*)) or
            (any of ($p*) and any of ($c*)) or
            ($a1 and any of ($c*))
        )
}


rule CDB_APT28_GAMEFISH_Backdoor {
    meta:
        description  = "Detects GAMEFISH/Sednit backdoor — APT28 primary implant"
        author       = "CyberDudeBivash SENTINEL APEX"
        threat_actor = "APT28 (Fancy Bear)"
        mitre_attack = "T1059.001, T1071.004, T1573.002, T1547.001"
        tlp          = "TLP:AMBER"
        severity     = "CRITICAL"
        confidence   = 87

    strings:
        // GAMEFISH config decryption routine marker
        $dec1 = { 8B 45 FC 33 45 F8 8B 4D FC 89 01 }
        $dec2 = { 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 }

        // Known GAMEFISH mutex
        $mut1 = "Global\\{" ascii
        $mut2 = "Local\\{" ascii

        // C2 via DNS TXT records
        $dns1 = "nslookup" ascii nocase
        $dns2 = { 54 58 54 }  // "TXT"

        // Encrypted strings
        $enc1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 }

    condition:
        uint16(0) == 0x5A4D and
        (
            (any of ($dec*) and any of ($mut*)) or
            (any of ($dns*) and any of ($enc*)) or
            ($dec1 and $enc1)
        )
}


rule CDB_APT28_Zebrocy_Dropper {
    meta:
        description  = "Detects Zebrocy downloader/dropper used by APT28 (AutoIt/Delphi variants)"
        author       = "CyberDudeBivash SENTINEL APEX"
        threat_actor = "APT28 (Fancy Bear)"
        mitre_attack = "T1566.001, T1059.003, T1027.002"
        tlp          = "TLP:AMBER"
        severity     = "HIGH"
        confidence   = 82

    strings:
        // AutoIt compiled script markers
        $au3_1 = "This is a compiled AutoIt script." ascii
        $au3_2 = "AU3!EA06" ascii

        // Delphi variant markers
        $del1 = { 52 61 6C 73 4D 74 68 43 6D 70 }  // "RalsMthCmp"
        $del2 = "TApplication" ascii

        // Download routine patterns
        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "WinInet" ascii
        $dl3 = "InternetOpenUrl" ascii

        // Zebrocy specific
        $z1 = { 63 6D 64 2E 65 78 65 20 2F 63 20 }  // "cmd.exe /c "
        $z2 = "%TEMP%\\" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and
        (
            (any of ($au3*) and any of ($dl*)) or
            ($del1 and any of ($dl*) and $z2) or
            (2 of ($dl*) and $z1 and $z2)
        )
}


rule CDB_APT28_LOJAX_UEFI_Implant {
    meta:
        description  = "Detects LoJax UEFI rootkit — APT28 firmware persistence"
        author       = "CyberDudeBivash SENTINEL APEX"
        threat_actor = "APT28 (Fancy Bear / GRU Unit 74455)"
        mitre_attack = "T1542.001, T1542.003"
        tlp          = "TLP:RED"
        severity     = "CRITICAL"
        confidence   = 92
        reference    = "https://www.welivesecurity.com/wp-content/uploads/2018/09/ESET-LoJax.pdf"

    strings:
        // UEFI DXE driver artifacts
        $uefi1 = { 45 46 49 20 44 58 45 }   // "EFI DXE"
        $uefi2 = { 45 46 49 20 50 45 49 }   // "EFI PEI"
        $uefi3 = "DxeCoreEntryPoint" ascii
        $uefi4 = "gST->" ascii

        // LoJax payload dropper
        $l1 = "RwDrv.sys" ascii wide nocase
        $l2 = "GetFirmwareEnvironmentVariable" ascii

        // SPI flash write sequence
        $spi1 = { 0F 32 0F 30 }  // RDMSR/WRMSR pair

    condition:
        (
            (2 of ($uefi*) and (any of ($l*) or $spi1)) or
            ($l1 and $l2 and $spi1)
        )
}


// ══════════════════════════════════════════════════════════════════════════════
// CROSS-ACTOR GENERIC DETECTIONS
// ══════════════════════════════════════════════════════════════════════════════

rule CDB_NationState_Living_Off_Land_Persistence {
    meta:
        description  = "Detects LOLBin-based persistence techniques common to Lazarus & APT28"
        author       = "CyberDudeBivash SENTINEL APEX"
        threat_actor = "Lazarus Group, APT28, nation-state actors"
        mitre_attack = "T1059.001, T1053.005, T1547.001, T1112"
        tlp          = "TLP:GREEN"
        severity     = "HIGH"
        confidence   = 70

    strings:
        // LOLBin execution chains
        $l1 = "wscript.exe" ascii nocase
        $l2 = "mshta.exe" ascii nocase
        $l3 = "regsvr32.exe /s /n /u /i:http" ascii nocase
        $l4 = "certutil -urlcache -split -f" ascii nocase
        $l5 = "bitsadmin /transfer" ascii nocase

        // Scheduled task persistence
        $st1 = "schtasks /create" ascii nocase
        $st2 = "/sc ONLOGON" ascii nocase
        $st3 = "TASKNAME" ascii nocase

        // Registry run key persistence
        $rk1 = "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $rk2 = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase

    condition:
        2 of ($l*) or
        (any of ($l*) and any of ($st*)) or
        (any of ($l*) and any of ($rk*))
}
