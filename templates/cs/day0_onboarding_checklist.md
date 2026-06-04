# DAY 0 ONBOARDING CHECKLIST
## SENTINEL APEX Customer Success — Activation Day

**Customer:** [NAME] | **Company:** [COMPANY] | **Ref:** [SA-YYYYMMDD-XXXX]
**Tier:** [PRO/ENTERPRISE/MSSP] | **Key issued:** [DATETIME]

---

## OPERATOR CHECKLIST (complete within 4 hours of key issuance)

- [ ] Key delivery email sent (template: 06_api_key_delivered.txt)
- [ ] Customer reference logged in data/customers/active.json
- [ ] Subscription logged in data/subscriptions/ledger.json
- [ ] For ENTERPRISE/MSSP: WhatsApp message sent
- [ ] Health score initialized at 0 in customer record

## CUSTOMER FIRST STEPS (from quickstart.html)

1. Make first API call:
   `curl -H "X-API-Key: [THEIR_KEY]" https://intel.cyberdudebivash.com/api/feed`

2. Confirm response received (JSON with advisories)

3. For SIEM integration: follow quickstart.html guide for their specific platform

## SUCCESS SIGNAL

Customer makes first API call within 4 hours = ACTIVATED
No call within 24 hours = TRIGGER DAY 3 early check-in
