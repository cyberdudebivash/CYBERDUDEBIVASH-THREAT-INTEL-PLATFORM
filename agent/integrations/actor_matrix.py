#!/usr/bin/env python3
"""
actor_matrix.py - CyberDudeBivash v12.0 (SENTINEL APEX ULTRA)
EXPANDED: 10+ threat actor profiles with keyword-based attribution
covering APTs, FIN groups, and common threat categories.
"""


class ActorMatrix:
    def __init__(self):
        self.actor_db = {
            "CDB-APT-22": {
                "alias": ["Volt Typhoon", "Vanguard Panda", "Bronze Silhouette"],
                "origin": "East Asia",
                "motivation": "Critical Infrastructure Espionage",
                "tooling": ["Living-off-the-land", "KV-Botnet", "LOTL"],
                "confidence_score": "High (Telemetry Correlated)",
                "keywords": ["volt typhoon", "critical infrastructure", "living off the land"],
            },
            "CDB-FIN-09": {
                "alias": ["Lazarus", "Hidden Cobra", "Zinc", "Diamond Sleet"],
                "origin": "North Korea",
                "motivation": "Financial Gain / Espionage",
                "tooling": ["FastCash", "AppleJeus", "TraderTraitor"],
                "confidence_score": "High (OSINT Correlated)",
                "keywords": ["lazarus", "hidden cobra", "cryptocurrency theft", "north korea"],
            },
            "CDB-APT-28": {
                "alias": ["Fancy Bear", "APT28", "Strontium", "Forest Blizzard"],
                "origin": "Russia",
                "motivation": "Political Espionage / Disruption",
                "tooling": ["X-Agent", "Zebrocy", "Drovorub"],
                "confidence_score": "High",
                "keywords": ["fancy bear", "apt28", "gru", "forest blizzard"],
            },
            "CDB-APT-41": {
                "alias": ["Double Dragon", "APT41", "Barium", "Brass Typhoon"],
                "origin": "China",
                "motivation": "Espionage + Financial Crime",
                "tooling": ["ShadowPad", "Winnti", "KEYPLUG"],
                "confidence_score": "High",
                "keywords": ["apt41", "double dragon", "winnti", "shadowpad"],
            },
            "CDB-FIN-11": {
                "alias": ["Cl0p", "TA505", "FIN11"],
                "origin": "Eastern Europe",
                "motivation": "Ransomware / Extortion",
                "tooling": ["Cl0p Ransomware", "MOVEit", "GoAnywhere"],
                "confidence_score": "High",
                "keywords": ["cl0p", "clop", "ta505", "moveit", "fin11"],
            },
            "CDB-RAN-01": {
                "alias": ["LockBit", "LockBit 3.0"],
                "origin": "Eastern Europe / Russia",
                "motivation": "Ransomware-as-a-Service",
                "tooling": ["LockBit Ransomware", "StealBit"],
                "confidence_score": "High",
                "keywords": ["lockbit", "lock bit"],
            },
            "CDB-RAN-02": {
                "alias": ["BlackCat", "ALPHV", "Noberus"],
                "origin": "Eastern Europe",
                "motivation": "Ransomware / Double Extortion",
                "tooling": ["BlackCat Ransomware (Rust)", "ExMatter"],
                "confidence_score": "High",
                "keywords": ["blackcat", "alphv", "noberus"],
            },
            "CDB-FIN-07": {
                "alias": ["ShinyHunters"],
                "origin": "Unknown / Multi-National",
                "motivation": "Data Theft / Sale",
                "tooling": ["Custom scrapers", "API exploitation"],
                "confidence_score": "Medium",
                "keywords": ["shinyhunters", "shiny hunters", "data marketplace"],
            },
            "CDB-APT-29": {
                "alias": ["Cozy Bear", "APT29", "Nobelium", "Midnight Blizzard"],
                "origin": "Russia",
                "motivation": "Intelligence Collection",
                "tooling": ["EnvyScout", "SUNBURST", "FoggyWeb"],
                "confidence_score": "High",
                "keywords": ["cozy bear", "apt29", "nobelium", "midnight blizzard", "solarwinds"],
            },
            "CDB-FIN-12": {
                "alias": ["Scattered Spider", "UNC3944", "Octo Tempest", "0ktapus", "Oktapus"],
                "origin": "US / UK / Multi-National",
                "motivation": "Financial Gain / Identity Compromise / SIM Swapping",
                "tooling": ["Social Engineering", "SIM Swap", "MFA Fatigue", "Okta Phishing Kits"],
                "confidence_score": "Medium-High",
                "keywords": ["scattered spider", "octo tempest", "sim swap", "mfa fatigue",
                             "0ktapus", "oktapus", "unc3944", "okta phishing", "okta identity",
                             "mfa bypass", "mfa codes"],
            },
            # v15.0: Mobile malware actor clusters
            "CDB-MOB-01": {
                "alias": ["Triada", "KeenAdu", "BADBOX", "Lemon Group"],
                "origin": "China / Southeast Asia",
                "motivation": "Supply Chain Compromise / Ad Fraud / Data Theft",
                "tooling": ["Firmware Backdoor", "Zygote Hooking", "System Partition Implant",
                            "Pre-installed Trojans", "OTA Update Hijacking"],
                "confidence_score": "High (Kaspersky / TrendMicro Correlated)",
                "keywords": ["triada", "keenadu", "badbox", "lemon group",
                             "firmware backdoor", "zygote", "system partition",
                             "counterfeit android", "preinstalled malware",
                             "pre-installed", "counterfeit device"],
            },
            "CDB-MOB-02": {
                "alias": ["Vo1d", "Android.Vo1d", "Void Backdoor"],
                "origin": "Unknown / Under Investigation",
                "motivation": "Botnet Recruitment / Ad Fraud / Proxy Network",
                "tooling": ["TV Box Firmware Implant", "Android Debug Bridge Exploit",
                            "Vo1d Backdoor Module"],
                "confidence_score": "Medium-High (Dr.Web / ESET Correlated)",
                "keywords": ["vo1d", "void backdoor", "android tv box", "tv box malware",
                             "set-top box", "android tv", "ott box"],
            },
            # -- v75.3 NEW: Iran-linked, Hacktivists, Cybercrime clusters --
            "CDB-IR-01": {
                "alias": ["Nasir Security", "NasirSec"],
                "origin": "Iran",
                "motivation": "Hacktivism / Financial Extortion / Geopolitical",
                "tooling": ["Custom exfil tools", "Telegram C2", "Web defacement"],
                "confidence_score": "Medium (Resecurity Research)",
                "keywords": ["nasir security", "nasirsec", "nasir sec"],
            },
            "CDB-IR-02": {
                "alias": ["Handala Hack", "Handala"],
                "origin": "Iran",
                "motivation": "Hacktivism / Anti-Israeli Operations",
                "tooling": ["Wiper malware", "Telegram delivery", "Data leak"],
                "confidence_score": "Medium (CrowdStrike / Recorded Future)",
                "keywords": ["handala", "handala hack"],
            },
            "CDB-IR-03": {
                "alias": ["APT34", "OilRig", "MOIS Cyber"],
                "origin": "Iran (MOIS)",
                "motivation": "State Espionage / Disruption",
                "tooling": ["DNSpionage", "TONEDEAF", "VALUEVAULT"],
                "confidence_score": "High (CISA / NSA Correlated)",
                "keywords": ["oilrig", "apt34", "iranian ministry of intelligence",
                             "mois", "iranian intelligence", "iran-linked actors",
                             "pro-iranian", "iran-backed"],
            },
            "CDB-RU-01": {
                "alias": ["Sandworm", "Voodoo Bear", "IRIDIUM"],
                "origin": "Russia (GRU Unit 74455)",
                "motivation": "Destructive Attacks / Critical Infrastructure",
                "tooling": ["NotPetya", "Industroyer", "Cyclops Blink"],
                "confidence_score": "High (NCSC / CISA Correlated)",
                "keywords": ["sandworm", "voodoo bear", "industroyer", "notpetya"],
            },
            "CDB-RU-02": {
                "alias": ["Turla", "Snake", "Venomous Bear"],
                "origin": "Russia (FSB)",
                "motivation": "Cyber Espionage / Intelligence Collection",
                "tooling": ["Carbon", "Kazuar", "HyperStack"],
                "confidence_score": "High",
                "keywords": ["turla", "snake malware", "venomous bear", "kazuar"],
            },
            "CDB-CN-01": {
                "alias": ["Salt Typhoon", "FamousSparrow"],
                "origin": "China",
                "motivation": "Telecom Espionage / Wiretapping",
                "tooling": ["SparrowDoor", "Demodex rootkit"],
                "confidence_score": "High (CISA / FBI)",
                "keywords": ["salt typhoon", "famousSparrow", "telecom espionage"],
            },
            "CDB-CN-02": {
                "alias": ["Hafnium", "Silk Typhoon"],
                "origin": "China",
                "motivation": "Government/Defense Espionage",
                "tooling": ["China Chopper", "ASPXSPY"],
                "confidence_score": "High (Microsoft Attributed)",
                "keywords": ["hafnium", "silk typhoon"],
            },
            "CDB-CYB-01": {
                "alias": ["TeamPCP"],
                "origin": "Unknown / Eastern Europe (suspected)",
                "motivation": "Financial Extortion / Data Destruction / Hacktivism",
                "tooling": ["CanisterWorm", "Docker API exploit", "Redis exploit",
                            "Kubernetes exploit", "React2Shell"],
                "confidence_score": "Medium (Flare / Aikido Research)",
                "keywords": ["teampcp", "team pcp", "canisterworm", "canister worm",
                             "react2shell", "docker api worm"],
            },
            "CDB-CYB-02": {
                "alias": ["FriendlyDealer"],
                "origin": "Unknown",
                "motivation": "Affiliate Fraud / Gambling Commission Scam",
                "tooling": ["Fake app store sites", "Web app PWA", "Affiliate redirect"],
                "confidence_score": "Medium (Malwarebytes Research)",
                "keywords": ["friendlydealer", "friendly dealer"],
            },
            "CDB-CYB-03": {
                "alias": ["Tycoon2FA", "Tycoon 2FA"],
                "origin": "Unknown / Cybercrime-as-a-Service",
                "motivation": "MFA Bypass / Credential Theft",
                "tooling": ["AitM phishing kit", "Telegram bot", "MFA relay proxy"],
                "confidence_score": "High (Sekoia / Proofpoint)",
                "keywords": ["tycoon2fa", "tycoon 2fa", "tycoon phishing"],
            },
            "CDB-NK-01": {
                "alias": ["Kimsuky", "Velvet Chollima", "Black Banshee"],
                "origin": "North Korea",
                "motivation": "Espionage / Technology Theft",
                "tooling": ["AppleSeed", "BabyShark", "GoldDragon"],
                "confidence_score": "High",
                "keywords": ["kimsuky", "velvet chollima", "black banshee"],
            },
            "CDB-RAN-03": {
                "alias": ["Akira", "Akira Ransomware"],
                "origin": "Eastern Europe / Russia",
                "motivation": "Ransomware / Double Extortion",
                "tooling": ["Akira Encryptor", "AnyDesk", "WinRAR exfil"],
                "confidence_score": "High (CISA Advisory AA23-272A)",
                "keywords": ["akira ransomware", "akira gang"],
            },
            "CDB-TA-01": {
                "alias": ["Muddled Libra", "Scattered Spider", "UNC3944"],
                "origin": "US / UK",
                "motivation": "Financial + Data Theft via Social Engineering",
                "tooling": ["Vishing", "SIM swap", "Helpdesk impersonation"],
                "confidence_score": "High (Palo Alto Unit 42 / CrowdStrike)",
                "keywords": ["muddled libra", "unc3944", "vishing attack",
                             "helpdesk impersonation", "phone call phishing",
                             "voice phishing", "social engineering call",
                             "phone is new phishing"],
            },
            "CDB-CYB-04": {
                "alias": ["Beast Gang", "Beast Ransomware"],
                "origin": "Unknown",
                "motivation": "Ransomware / RaaS",
                "tooling": ["Beast Ransomware"],
                "confidence_score": "Medium",
                "keywords": ["beast gang", "beast ransomware"],
            },
        }

    def correlate_actor(self, corpus, iocs):
        """
        Identifies the likely actor cluster based on infrastructure,
        aliases, keywords, and tooling matches.
        """
        corpus_lower = corpus.lower()

        best_match = None
        best_score = 0

        for tracking_id, profile in self.actor_db.items():
            score = 0

            # Check alias matches (strongest signal)
            for alias in profile.get('alias', []):
                if alias.lower() in corpus_lower:
                    score += 3

            # Check keyword matches
            for kw in profile.get('keywords', []):
                if kw in corpus_lower:
                    score += 2

            # Check tooling matches
            for tool in profile.get('tooling', []):
                if tool.lower() in corpus_lower:
                    score += 1

            if score > best_score:
                best_score = score
                best_match = (tracking_id, profile)

        if best_match and best_score >= 2:
            return {
                "tracking_id": best_match[0],
                "profile": best_match[1],
            }

        # Default for unknown clusters
        return {
            "tracking_id": "UNC-UNKNOWN",
            "profile": {
                "alias": ["Unattributed Threat Actor"],
                "origin": "Not Yet Attributed",
                "motivation": "Under Analysis",
                "tooling": ["Varies - see technical analysis"],
                "confidence_score": "Insufficient data for attribution",
                "_is_unknown": True,
            }
        }


actor_matrix = ActorMatrix()
