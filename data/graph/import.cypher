// SENTINEL APEX — Adversary Graph Neo4j Import
// Generated: 2026-06-01T13:50:07.046038+00:00
// Graph: APEX-GRAPH-61EE507F

// === NODES ===
MERGE (n:Technique {id: 'ttp-t1059'}) SET n.label = 'T1059: Command and Scripting Interpreter', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1059.001'}) SET n.label = 'T1059.001: PowerShell', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1059.003'}) SET n.label = 'T1059.003: Windows Command Shell', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1566'}) SET n.label = 'T1566: Phishing', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1566.001'}) SET n.label = 'T1566.001: Spearphishing Attachment', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1190'}) SET n.label = 'T1190: Exploit Public-Facing Application', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1078'}) SET n.label = 'T1078: Valid Accounts', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1055'}) SET n.label = 'T1055: Process Injection', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1547'}) SET n.label = 'T1547: Boot or Logon Autostart Execution', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1486'}) SET n.label = 'T1486: Data Encrypted for Impact', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1041'}) SET n.label = 'T1041: Exfiltration Over C2 Channel', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1071'}) SET n.label = 'T1071: Application Layer Protocol', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1071.004'}) SET n.label = 'T1071.004: DNS', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1003'}) SET n.label = 'T1003: OS Credential Dumping', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1560'}) SET n.label = 'T1560: Archive Collected Data', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1021'}) SET n.label = 'T1021: Remote Services', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1105'}) SET n.label = 'T1105: Ingress Tool Transfer', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1027'}) SET n.label = 'T1027: Obfuscated Files or Information', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1574'}) SET n.label = 'T1574: Hijack Execution Flow', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1562'}) SET n.label = 'T1562: Impair Defenses', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1110'}) SET n.label = 'T1110: Brute Force', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1098'}) SET n.label = 'T1098: Account Manipulation', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1195'}) SET n.label = 'T1195: Supply Chain Compromise', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1568'}) SET n.label = 'T1568: Dynamic Resolution', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1568.002'}) SET n.label = 'T1568.002: Domain Generation Algorithms', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1496'}) SET n.label = 'T1496: Resource Hijacking', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1548'}) SET n.label = 'T1548: Abuse Elevation Control Mechanism', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1210'}) SET n.label = 'T1210: Exploitation of Remote Services', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1083'}) SET n.label = 'T1083: File and Directory Discovery', n.confidence = 1.0, n.tlp = 'TLP:GREEN';
MERGE (n:Technique {id: 'ttp-t1135'}) SET n.label = 'T1135: Network Share Discovery', n.confidence = 1.0, n.tlp = 'TLP:GREEN';

// === RELATIONSHIPS ===