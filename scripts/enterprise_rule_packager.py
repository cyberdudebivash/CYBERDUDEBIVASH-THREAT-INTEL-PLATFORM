#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/enterprise_rule_packager.py — Enterprise Rule Packaging System v162.0
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PURPOSE:
  Packages validated, normalized detection rules into enterprise-grade
  deployment bundles. Supports MSSP multi-tenant distribution.

PACKAGE FORMATS:
  - Sigma Rule Repository ZIP (all advisories)
  - KQL Analytics Rules JSON (Sentinel ARM template)
  - Splunk ESCU Content Bundle
  - YARA Rule Repository ZIP
  - Suricata Rules File (.rules)
  - Enterprise Coverage Report (HTML + JSON)
  - MSSP Multi-Tenant Distribution Bundle
  - ATT&CK Navigator Layer JSON
================================================================================
"""
from __future__ import annotations
import hashlib,io,json,logging,os,zipfile
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
from typing import Any,Dict,List,Optional

ENGINE_VERSION = "162.0.0"
ENGINE_ID      = "APEX-ERP"
log = logging.getLogger("apex.rule_packager")


@dataclass
class PackageManifest:
    package_id: str
    package_type: str
    created_at: str
    total_rules: int = 0
    advisory_count: int = 0
    techniques_covered: List[str] = field(default_factory=list)
    formats_included: List[str]   = field(default_factory=list)
    platform_targets: List[str]   = field(default_factory=list)
    quality_score: float = 0.0
    production_ready_count: int = 0
    tier: str = "ENTERPRISE"  # ENTERPRISE | MSSP | FREE
    checksum_sha256: str = ""
    file_size_bytes: int = 0
    package_version: str = ENGINE_VERSION
    deployment_guide: str = ""

    def to_dict(self): return asdict(self)


class SentinelARMTemplateBuilder:
    """Generates Microsoft Sentinel ARM template for analytics rules."""

    def build(self, kql_rules:List[Dict]) -> Dict:
        resources=[]
        for rule in kql_rules:
            adv_id = rule.get("advisory_id","unknown")
            title  = rule.get("title","APEX Detection Rule")
            kql    = rule.get("kql","")
            techs  = rule.get("techniques",[])
            level  = rule.get("level","Medium")
            if not kql: continue

            severity_map = {"critical":"High","high":"High","medium":"Medium","low":"Low"}
            severity = severity_map.get(level.lower(),"Medium")
            tactic_map = {
                "T1190":"InitialAccess","T1566":"InitialAccess","T1059":"Execution",
                "T1055":"PrivilegeEscalation","T1486":"Impact","T1562":"DefenseEvasion",
                "T1078":"DefenseEvasion","T1110":"CredentialAccess","T1021":"LateralMovement",
                "T1071":"CommandAndControl","T1003":"CredentialAccess","T1548":"PrivilegeEscalation",
            }
            tactics = list(set(tactic_map.get(t,"InitialAccess") for t in techs[:3]))

            resources.append({
                "type": "Microsoft.SecurityInsights/alertRules",
                "apiVersion": "2023-05-01-preview",
                "name": f"[guid('{adv_id}')]",
                "kind": "Scheduled",
                "properties": {
                    "displayName": f"APEX - {title[:100]}",
                    "description": f"CYBERDUDEBIVASH SENTINEL APEX detection rule. Advisory: {adv_id}. Techniques: {', '.join(techs[:5])}",
                    "severity": severity,
                    "enabled": True,
                    "query": kql,
                    "queryFrequency": "PT1H",
                    "queryPeriod": "P1D",
                    "triggerOperator": "GreaterThan",
                    "triggerThreshold": 0,
                    "suppressionDuration": "PT1H",
                    "suppressionEnabled": False,
                    "tactics": tactics,
                    "techniques": techs[:5],
                    "alertRuleTemplateName": None,
                    "incidentConfiguration": {
                        "createIncident": True,
                        "groupingConfiguration": {
                            "enabled": True,
                            "reopenClosedIncident": False,
                            "lookbackDuration": "PT5H",
                            "matchingMethod": "AnyAlert",
                            "groupByEntities": ["Account","Host"],
                        }
                    }
                }
            })

        return {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {"workspaceName":{"type":"string"},"workspaceResourceGroup":{"type":"string"}},
            "resources": resources,
            "outputs": {"ruleCount":{"type":"int","value":len(resources)}}
        }


class SplunkContentBundleBuilder:
    """Generates Splunk ESCU-compatible content bundle."""

    def build(self, spl_rules:List[Dict]) -> Dict:
        searches=[]
        for rule in spl_rules:
            adv_id = rule.get("advisory_id","")
            title  = rule.get("title","APEX Detection")
            spl    = rule.get("spl","")
            techs  = rule.get("techniques",[])
            level  = rule.get("level","medium")
            if not spl: continue

            searches.append({
                "name": f"APEX - {title[:80]}",
                "id": hashlib.md5(adv_id.encode()).hexdigest()[:8],
                "type": "detection",
                "datamodel": ["Endpoint","Network_Traffic"],
                "description": f"APEX detection for advisory {adv_id}. ATT&CK: {', '.join(techs[:5])}",
                "search": spl,
                "how_to_implement": "Enable relevant Windows Event Logs and Sysmon. Configure APEX SIEM webhook for automated ingestion.",
                "known_false_positives": "Security scanning tools, administrative scripts in privileged contexts.",
                "references": [f"https://intel.cyberdudebivash.com/reports/{adv_id}"],
                "tags": {
                    "analytic_story": ["APEX Intelligence","CYBERDUDEBIVASH Detections"],
                    "asset_type": "Endpoint",
                    "confidence": 75,
                    "impact": 80,
                    "message": f"APEX alert: {title[:80]} on $dest$",
                    "mitre_attack_id": techs[:5],
                    "observable": [{"name":"dest","type":"Hostname","role":["Victim"]},
                                   {"name":"user","type":"User","role":["Victim"]}],
                    "product": ["CYBERDUDEBIVASH SENTINEL APEX"],
                    "required_fields": ["_time","process_name","CommandLine","dest","user"],
                    "risk_score": 72,
                    "security_domain": "endpoint",
                    "severity": level,
                }
            })
        return {
            "author": "CYBERDUDEBIVASH SENTINEL APEX",
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "description": f"CYBERDUDEBIVASH SENTINEL APEX detection content bundle v{ENGINE_VERSION}",
            "id": hashlib.md5(f"apex-{datetime.now().date()}".encode()).hexdigest()[:12],
            "version": 1,
            "searches": searches
        }


class EnterpriseRulePackager:
    """Main packaging engine — creates deployment-ready rule bundles."""

    def __init__(self, output_dir:str="api/detections"):
        self.output_dir = output_dir
        self.arm_builder    = SentinelARMTemplateBuilder()
        self.splunk_builder = SplunkContentBundleBuilder()

    def package(self, normalized_rulesets:List[Dict], package_type:str="ENTERPRISE") -> Dict:
        """Create full enterprise rule package from normalized rulesets."""
        os.makedirs(self.output_dir, exist_ok=True)

        package_id = f"apex-pkg-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        manifest   = PackageManifest(
            package_id=package_id,
            package_type=package_type,
            created_at=datetime.now(timezone.utc).isoformat(),
            tier=package_type
        )

        # Collect rules by format
        sigma_rules=[]
        kql_rules=[]
        spl_rules=[]
        yara_rules=[]
        suricata_rules=[]
        all_techniques=set()

        for rs in normalized_rulesets:
            adv_id = rs.get("advisory_id","")
            title  = rs.get("title","")
            rules  = rs.get("rules",{})
            techs  = rs.get("techniques",[]) or []
            level  = rs.get("level","medium")
            all_techniques.update(techs)

            if "sigma" in rs.get("sigma_source","") or rs.get("sigma_source"):
                sigma_rules.append({"advisory_id":adv_id,"title":title,
                                   "content":rs.get("sigma_source","")})
            if rules.get("kql"):
                kql_rules.append({"advisory_id":adv_id,"title":title,
                                  "kql":rules["kql"],"techniques":techs,"level":level})
            if rules.get("spl"):
                spl_rules.append({"advisory_id":adv_id,"title":title,
                                  "spl":rules["spl"],"techniques":techs,"level":level})
            if rules.get("yara"):
                yara_rules.append({"advisory_id":adv_id,"title":title,"content":rules["yara"]})
            if rules.get("suricata"):
                suricata_rules.append(rules["suricata"])

        # Build individual output files
        outputs = {}

        # 1. Sigma repository
        if sigma_rules:
            sigma_zip_path = os.path.join(self.output_dir,"apex-sigma-rules.zip")
            self._write_sigma_zip(sigma_rules, sigma_zip_path)
            outputs["sigma_zip"] = sigma_zip_path

        # 2. Sentinel ARM template
        if kql_rules:
            arm_path = os.path.join(self.output_dir,"apex-sentinel-arm-template.json")
            arm = self.arm_builder.build(kql_rules)
            self._write_json(arm, arm_path)
            outputs["sentinel_arm"] = arm_path

        # 3. Splunk content bundle
        if spl_rules:
            splunk_path = os.path.join(self.output_dir,"apex-splunk-content-bundle.json")
            bundle = self.splunk_builder.build(spl_rules)
            self._write_json(bundle, splunk_path)
            outputs["splunk_bundle"] = splunk_path

        # 4. YARA rules file
        if yara_rules:
            yara_path = os.path.join(self.output_dir,"apex-yara-rules.yar")
            yara_content = "\n\n".join(r["content"] for r in yara_rules)
            with open(yara_path,"w",encoding="utf-8") as f:
                f.write(f"// CYBERDUDEBIVASH SENTINEL APEX YARA Rules v{ENGINE_VERSION}\n")
                f.write(f"// Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
                f.write(yara_content)
            outputs["yara_rules"] = yara_path

        # 5. Suricata rules file
        if suricata_rules:
            suricata_path = os.path.join(self.output_dir,"apex-suricata.rules")
            with open(suricata_path,"w",encoding="utf-8") as f:
                f.write(f"# CYBERDUDEBIVASH SENTINEL APEX Suricata Rules v{ENGINE_VERSION}\n")
                f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
                f.write("\n".join(suricata_rules))
            outputs["suricata_rules"] = suricata_path

        # 6. Master package manifest
        manifest.total_rules       = len(sigma_rules)+len(kql_rules)+len(spl_rules)+len(yara_rules)
        manifest.advisory_count    = len(normalized_rulesets)
        manifest.techniques_covered= list(all_techniques)
        manifest.formats_included  = list(set(
            list(normalized_rulesets[0].get("rules",{}).keys()) if normalized_rulesets else []
        ))
        manifest.platform_targets  = ["Microsoft Sentinel","Splunk ES","Elastic SIEM",
                                      "IBM QRadar","Google Chronicle","Suricata IDS"]
        manifest.quality_score     = 0.0
        manifest.deployment_guide  = (
            f"DEPLOYMENT GUIDE — APEX Detection Package {package_id}\n"
            "1. Sentinel: Import apex-sentinel-arm-template.json via ARM deployment\n"
            "2. Splunk: Import apex-splunk-content-bundle.json via ES Content Manager\n"
            "3. YARA: Deploy apex-yara-rules.yar to CrowdStrike/CarbonBlack/Velociraptor\n"
            "4. Suricata: Copy apex-suricata.rules to /etc/suricata/rules/ and reload\n"
            "5. Sigma: Use sigma-cli to convert to target SIEM format\n"
        )

        manifest_path = os.path.join(self.output_dir,"apex-package-manifest.json")
        self._write_json(manifest.to_dict(), manifest_path)
        outputs["manifest"] = manifest_path

        # 7. Write master rules index
        index = {"generated_at":datetime.now(timezone.utc).isoformat(),
                 "package_id":package_id,"engine_version":ENGINE_VERSION,
                 "total_advisories":len(normalized_rulesets),
                 "rule_counts":{"sigma":len(sigma_rules),"kql":len(kql_rules),
                                "spl":len(spl_rules),"yara":len(yara_rules),
                                "suricata":len(suricata_rules)},
                 "techniques_covered":list(all_techniques),
                 "outputs":outputs}
        index_path = os.path.join(self.output_dir,"apex-detection-index.json")
        self._write_json(index, index_path)

        log.info(f"[ERP] Package {package_id}: {manifest.total_rules} rules, "
                 f"{len(normalized_rulesets)} advisories → {self.output_dir}")

        return {"status":"PACKAGED","package_id":package_id,
                "manifest":manifest.to_dict(),"outputs":outputs,"index":index}

    def _write_sigma_zip(self, sigma_rules:List[Dict], path:str):
        with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as zf:
            for rule in sigma_rules:
                adv_id = rule["advisory_id"].replace("--","-").replace("/","_")
                fname  = f"sigma/{adv_id}.yml"
                content= (f"# Advisory: {rule['advisory_id']}\n"
                          f"# Title: {rule['title']}\n"
                          f"# CYBERDUDEBIVASH SENTINEL APEX v{ENGINE_VERSION}\n\n"
                          + rule.get("content","# No Sigma rule content"))
                zf.writestr(fname, content.encode("utf-8"))
            zf.writestr("README.md",
                f"# CYBERDUDEBIVASH SENTINEL APEX Sigma Rules\n\n"
                f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
                f"Version: {ENGINE_VERSION}\n\n"
                f"Use sigma-cli to convert to your target SIEM format:\n"
                f"```\nsigma convert -t splunk apex/*.yml\n"
                f"sigma convert -t microsoft365defender apex/*.yml\n```\n")

    def _write_json(self, data:Any, path:str):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path,"w",encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        log.info(f"[ERP] Written: {path}")


if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    packager = EnterpriseRulePackager(output_dir="/tmp/apex_test_pkg")
    test_rulesets = [
        {
            "advisory_id":"intel--test001","title":"Test Detection",
            "sigma_source":"title: Test\nid: apex-test\nlogsource:\n  category: process_creation\ndetection:\n  test:\n    CommandLine|contains: 'evil'\n  condition: test\nlevel: high\n",
            "rules":{"kql":"DeviceProcessEvents | where ProcessCommandLine contains 'evil'",
                    "spl":"index=windows CommandLine='*evil*'"},
            "techniques":["T1059.001"],"level":"high"
        }
    ]
    result = packager.package(test_rulesets,"ENTERPRISE")
    print(f"[ERP] Package created: {result['package_id']}")
    print(f"[ERP] Outputs: {list(result['outputs'].keys())}")
