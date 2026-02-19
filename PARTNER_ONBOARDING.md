# 🚀 CYBERDUDEBIVASH® PARTNER ONBOARDING GUIDE
**Target Platforms:** Microsoft Sentinel, Splunk ES, CrowdStrike, Palo Alto XSOAR
**Integrity Standard:** STIX 2.1 via RSA-2048 Secure Transport

## 1. PRE-REQUISITES
Before integration, ensure your SOC team has access to:
1. Your **Commercial License Key** (from your contract).
2. The **CDB Public RSA Key** (`cdb_public_key.pem`) for asset verification.
3. Access to our **Automated STIX Feed URL**.

## 2. MICROSOFT SENTINEL INTEGRATION
Sentinel users can ingest CDB Intelligence via the **Threat Intelligence - TAXII** data connector.

1. **Install Solution**: Go to **Content Hub** > Search "Threat Intelligence" > Install.
2. **Connect Feed**:
   - Navigate to **Data Connectors** > **Threat Intelligence - TAXII**.
   - **API Root URL**: `https://api.cyberdudebivash.com/taxii2`
   - **Collection ID**: `CDB_SENTINEL_APEX_CRITICAL`
   - **Username/Password**: Use your unique License Credentials.
3. **Verify**: Check the `ThreatIntelligenceIndicator` table in Logs to see signed CDB objects.

## 3. SPLUNK ENTERPRISE SECURITY (ES) INTEGRATION
Splunk users leverage the **Threat Intelligence Framework**.

1. **Configuration**: Navigate to **Enterprise Security** > **Configure** > **Data Enrichment** > **Threat Intelligence Management**.
2. **Add New Source**:
   - Select **New** > **Threat Download**.
   - **URL**: `https://api.cyberdudebivash.com/feeds/stix2.json`
   - **Weight**: Set to `10` (Highest Priority).
3. **Enforcement**: Enable the **Threat Activity Detected** correlation search to trigger notable events from CDB IOCs.

## 4. VERIFYING ASSET INTEGRITY
For every high-priority alert, our engine attaches a **Technical Signature**. Use our verifier to ensure the data is untampered:
```bash
python tools/verification_tool.py <path_to_rule_or_playbook> <signature_hex>
