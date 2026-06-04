# REVENUE OPERATIONS PLAYBOOK
## SENTINEL APEX v175.0 — Phase 5 Commercial Readiness Sprint
**Authored:** 2026-06-04 | **Auditor Role:** Principal Revenue Operations Architect

---

## PURPOSE

This playbook defines the end-to-end revenue operations pipeline for SENTINEL APEX. Every step is auditable, repeatable, and executable without automated infrastructure (Phase 1), with a clear migration path to automation (Phase 2+).

**Pipeline:**
```
Payment Received → Verification → Approval → Provisioning → Customer Activation → Support Assignment
```

---

## CURRENT STATE ASSESSMENT

| Stage | Current Status | Gap |
|-------|---------------|-----|
| Payment Received | ⚠️ Partial — Formspree receives UTR | Missing plan, amount, method from form |
| Verification | ❌ Manual only — no workflow defined | No SLA, no checklist |
| Approval | ❌ Undefined — no approval record | No audit trail |
| Provisioning | ❌ Manual only — no automation | Bottleneck: operator must generate key by hand |
| Customer Activation | ❌ Manual email only | No confirmation system |
| Support Assignment | ⚠️ Partial — WhatsApp / email known | No ticket system, no SLA |

**Assessment: Revenue Operations pipeline is NOT production-ready.**

---

## PHASE 1 PLAYBOOK (IMMEDIATE — NO-CODE)

### Tools Required
- Formspree (existing)
- Google Sheets (free — CRM tracker)
- Gmail (existing)
- WhatsApp Business (existing — +91 8179881447)
- Any blockchain explorer (Etherscan, Tronscan, Bitcoin.com)

---

## STEP 1 — PAYMENT RECEIVED

**Trigger:** Formspree email arrives at bivash@cyberdudebivash.com

**Operator Action:**
1. Open Formspree notification email
2. Create new row in Google Sheets CRM tracker with columns:
   ```
   | Ref ID | Timestamp | Name | Email | Company | Plan | Method | Amount | Transaction ID | Status |
   ```
3. Auto-generate Reference ID: `SA-[YYYYMMDD]-[4-char random]` (e.g., `SA-20260604-A7X2`)
4. Set Status = `PENDING_VERIFICATION`
5. Send auto-acknowledgement to customer (template below)

**SLA: Within 30 minutes of Formspree notification**

**Acknowledgement Email Template:**
```
Subject: SENTINEL APEX — Payment Received | Ref: SA-20260604-XXXX

Hi [Name],

We've received your payment submission for SENTINEL APEX [PLAN] plan.
Reference ID: SA-20260604-XXXX

We're verifying your payment now. Your API key will be delivered to this email
within 2 hours of verification.

Urgent? WhatsApp: +91 8179881447

— CYBERDUDEBIVASH SENTINEL APEX Team
```

---

## STEP 2 — VERIFICATION

**Operator Action by Payment Method:**

### UPI / NEFT Verification
1. Open PhonePe / GPay / Net Banking transaction history
2. Search by UTR number provided by customer
3. Verify:
   - [ ] UTR exists in your account
   - [ ] Amount received matches plan price (±₹0)
   - [ ] Date within last 7 days
   - [ ] Sender name / account matches submitted name (spot check)
4. Screenshot or note confirmation details

**SLA: 15 minutes for UPI, 30 minutes for NEFT**

### PayPal Verification
1. Open PayPal Business dashboard → Activity
2. Search by Transaction ID provided by customer
3. Verify:
   - [ ] Transaction ID exists and shows "Completed"
   - [ ] Amount matches plan price in USD equivalent
   - [ ] Sender email matches submitted email (or note if different)
4. Note PayPal Transaction ID in CRM row

**SLA: 10 minutes**

### Crypto Verification
1. Open blockchain explorer:
   - BTC: blockchain.com/explorer
   - USDT TRC20: tronscan.org
   - USDT ERC20/BSC: etherscan.io / bscscan.com
2. Search by TX Hash provided
3. Verify:
   - [ ] TX Hash exists and shows "Confirmed"
   - [ ] Destination address matches your published wallet
   - [ ] Amount matches plan price in USD/USDT
   - [ ] Minimum confirmations: BTC=3, ETH=12, TRX=20
4. Note confirmation count and block height in CRM

**SLA: 30 minutes (allow time for blockchain confirmations)**

### Verification Result
- **PASS:** Update CRM Status = `VERIFIED`. Proceed to Step 3.
- **FAIL:** Update CRM Status = `VERIFICATION_FAILED`. Email customer (template below). Ask for correct UTR or resubmission.
- **WRONG AMOUNT:** Update CRM Status = `AMOUNT_MISMATCH`. Email customer with shortfall and payment instructions.

**Verification Failure Email Template:**
```
Subject: SENTINEL APEX — Payment Verification Issue | Ref: SA-XXXX

Hi [Name],

We were unable to verify your payment using the reference provided:
Transaction ID: [ID]
Reason: [UTR not found / Amount mismatch: received ₹X, expected ₹Y]

Please re-check your payment and provide the correct UTR, or contact us:
WhatsApp: +91 8179881447 | Email: bivash@cyberdudebivash.com

Reference: SA-XXXX
```

---

## STEP 3 — APPROVAL

**Operator Action:**
1. In CRM, update Status = `APPROVED`
2. Note approved by: `BIVASH` (or team member name)
3. Note approved at: timestamp
4. Cross-check customer is not on a blocklist or duplicate submission

**Approval Blocklist Check (Phase 1):**
- Search CRM for same email — if already an active subscriber, check if renewal or duplicate payment
- Search CRM for same Transaction ID — reject if already used

**SLA: Immediate upon verification**

---

## STEP 4 — PROVISIONING

### API Key Generation Protocol

**Phase 1 (Manual):**

1. Open `agent/config.py` (or wherever API keys are stored)
2. Generate a new API key using the generation function:
   ```python
   python3 -c "
   import secrets, hashlib
   key = 'SA-PRO-' + secrets.token_hex(16).upper()
   print(key)
   "
   ```
   Example output: `SA-PRO-A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6`

3. Assign key to correct tier in config:
   ```python
   # In agent/config.py
   CDB_PRO_API_KEYS = ["SA-PRO-A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"]
   ```

4. Record key details in CRM:
   - API Key (hashed SHA-256, not plaintext)
   - Key issued at: timestamp
   - Key expires at: today + 30 days (monthly) or today + 365 days (annual)
   - Tier: PRO / ENTERPRISE / MSSP

5. Note: never store plaintext API keys in CRM — store SHA-256 hash only.

**Rate Limits by Tier (from rate_limiter.py):**

| Tier | API Calls/day | Calls/min |
|------|-------------|-----------|
| FREE | 100 | 10 |
| STANDARD | 500 | 30 |
| PRO/PREMIUM | 5,000 | 100 |
| ENTERPRISE | 50,000 | 1,000 |

### Provisioning SLA

| Plan | Target Provisioning Time |
|------|------------------------|
| Community | Automated (future) / 30 min manual |
| PRO | 2 hours from verification |
| Enterprise | 4 hours from verification |
| MSSP | 24 hours (requires sub-tenant setup) |

---

## STEP 5 — CUSTOMER ACTIVATION

**Operator Action:**
1. Update CRM Status = `ACTIVE`
2. Send API Key Delivery Email:

```
Subject: SENTINEL APEX API Key — [PLAN] Activated | Ref: SA-XXXX

Hi [Name],

Your SENTINEL APEX [PLAN] subscription is now active!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
YOUR API KEY: SA-PRO-[KEY]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ Keep this key confidential. Do not share it publicly.
This key is tied to your account. Misuse will result in suspension.

QUICK START:
curl -H "Authorization: Bearer SA-PRO-[KEY]" \
  https://intel.cyberdudebivash.com/api/intel?severity=critical

DOCUMENTATION: https://intel.cyberdudebivash.com/api-docs.html
INTEGRATION GUIDE: https://intel.cyberdudebivash.com/onboarding.html

PLAN DETAILS:
• Plan: [PLAN NAME]
• Billing: [Monthly / Annual]
• API Quota: [X] calls/day
• Subscription Start: [DATE]
• Next Renewal: [DATE]
• Invoice/Receipt: Attached (PDF)

SUPPORT:
• WhatsApp: +91 8179881447
• Email: bivash@cyberdudebivash.com

Thank you for choosing SENTINEL APEX.
— CYBERDUDEBIVASH Team
```

3. Attach proforma invoice (PDF) to activation email
4. Add customer to Google Contacts / address book for WhatsApp group (if applicable)

---

## STEP 6 — SUPPORT ASSIGNMENT

| Plan | Support Channel | Response SLA | Escalation |
|------|----------------|-------------|-----------|
| Community | Email only | 72 hours | None |
| PRO | Email + WhatsApp | 24 hours | Bivash direct |
| Enterprise | Email + WhatsApp + Telegram | 4 hours | Bivash direct + video call |
| MSSP | Dedicated WhatsApp group | 2 hours | Bivash direct + priority queue |

**Support Assignment Action:**
1. For Enterprise/MSSP: Create dedicated WhatsApp group `SENTINEL-[COMPANY]-SUPPORT`
2. Add customer's WhatsApp number to group
3. Send welcome message in group with support contacts
4. Note group name in CRM

---

## REVENUE OPERATIONS AUDIT TRAIL

### CRM Tracker Schema (Google Sheets)

| Column | Description |
|--------|-----------|
| Reference ID | SA-YYYYMMDD-XXXX |
| Created At | Submission timestamp |
| Name | Customer full name |
| Email | Customer email |
| Company | Organization |
| Country | ISO code |
| Plan | community / pro / enterprise / mssp |
| Billing | monthly / annual |
| Amount INR | Integer |
| Payment Method | upi / neft / paypal / crypto / amazopay |
| Transaction ID | UTR / PayPal TxID / Crypto TxHash |
| Verification Status | pending / verified / failed / mismatch |
| Verified At | Timestamp |
| Approved By | Operator name |
| API Key Hash | SHA-256 of issued key |
| Key Issued At | Timestamp |
| Expires At | Expiry timestamp |
| Subscription Status | active / expired / suspended / cancelled |
| Support Channel | email / whatsapp / group |
| Renewal Notified | Y/N + date |
| Notes | Free text |

---

## RENEWAL OPERATIONS

### Renewal Reminder Schedule

| Days Before Expiry | Action |
|-------------------|--------|
| D-14 | Email: "Your subscription renews in 14 days" |
| D-7 | Email + WhatsApp: "Subscription expiring in 7 days" |
| D-3 | WhatsApp direct message: "Urgent: renew in 3 days" |
| D-0 | Email: "Subscription expired — renew to restore access" |
| D+3 | Grace period — key still active but marked `GRACE` |
| D+7 | Key suspended — status = `SUSPENDED` |

**Renewal Email Template (D-14):**
```
Subject: SENTINEL APEX Subscription Renews in 14 Days | Ref: SA-XXXX

Hi [Name],

Your [PLAN] subscription (Ref: SA-XXXX) expires on [DATE].

To continue uninterrupted access, renew at:
https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html

Plan: [PLAN] | Amount: [₹AMOUNT]
Simply pay and submit your transaction ID — key extended within 2 hours.

Questions? WhatsApp +91 8179881447

— SENTINEL APEX Team
```

---

## SCALABILITY NOTES

This Phase 1 playbook handles up to approximately 20–30 customers/month manually. At 30+ customers/month, automation is required:

| Phase | Trigger | Automation |
|-------|---------|-----------|
| Phase 2 | >30 customers/month | Formspree webhook → Zapier → Supabase + automated key generation script |
| Phase 3 | >100 customers/month | FastAPI backend + database + automated email + API key issuance |
| Phase 4 | >500 customers/month | Full SaaS platform with customer portal auth, self-service billing |

---

*Playbook authored: 2026-06-04 | SENTINEL APEX v175.0 Commercial Readiness Sprint*
