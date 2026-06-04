# CUSTOMER INTAKE SYSTEM
## SENTINEL APEX v175.0 — Phase 4 Commercial Readiness Sprint
**Audited:** 2026-06-04 | **Auditor Role:** Principal Enterprise Onboarding Architect

---

## AUDIT SCOPE

Audit and design the complete customer purchase intake system: form design, data collection, storage, tracking, and handoff to provisioning.

Files audited: `get-api-key.html`, `sentinel-onboarding.html`, `onboarding.html`, `PAYMENT-GATEWAY.html`, `upgrade.html`, Formspree endpoints.

---

## CURRENT STATE AUDIT

### Existing Forms

| Form | Location | Formspree Endpoint | Status |
|------|----------|-------------------|--------|
| API Key Request | get-api-key.html | `xpzgkqly` | Active |
| Payment Tracker | PAYMENT-GATEWAY.html | `xpzgkqly` | Active |
| Lead Autoresponder | .github/workflows/lead_autoresponder.yml | Webhook | Active (CI) |
| Enterprise Contact | contact-enterprise.html | Unknown | Unverified |
| Onboarding Form | sentinel-onboarding.html | None found | UI only — no backend |

### Fields Currently Collected (get-api-key.html)

| Field | Present | Required | Notes |
|-------|---------|---------|-------|
| First Name | ✅ | ✅ | |
| Last Name | ✅ | ✅ | |
| Work Email | ✅ | ✅ | |
| Company | Unclear | Unclear | Not confirmed in grep |
| Country | Unclear | Unclear | Not confirmed in grep |
| Plan | ✅ (hidden) | Auto-set | Pre-filled from plan selector |
| Payment Method | ❌ | ❌ | Not collected at API key stage |
| Transaction ID | ❌ | ❌ | Separate form on PAYMENT-GATEWAY.html |
| Intended Use Case | ✅ | ✅ (Enterprise only) | Shown for Enterprise tier |
| Notes | ✅ | ❌ | Optional |

### Fields Currently Collected (PAYMENT-GATEWAY.html — Payment Tracker)

| Field | Present | Required | Notes |
|-------|---------|---------|-------|
| Email | ✅ | ✅ | |
| UTR / Transaction ID / TxHash | ✅ | ✅ | |
| Plan Selected | ❌ | ❌ | **MISSING — critical gap** |
| Payment Method | ❌ | ❌ | **MISSING — critical gap** |
| Amount Paid | ❌ | ❌ | **MISSING — critical gap** |
| Full Name | ❌ | ❌ | Cannot link to API key request |
| Company | ❌ | ❌ | |
| Date of Payment | ❌ | ❌ | |

---

## GAPS IN CURRENT INTAKE SYSTEM

| Gap | Severity | Impact |
|-----|---------|--------|
| Two separate forms (API key request + payment tracker) are not linked — operator cannot match payment to customer without manual email lookup | P0 | Every sale requires manual reconciliation |
| Payment Tracker missing Plan, Amount, Method — operator cannot verify correct payment | P0 | Wrong-amount payments go undetected |
| Company name not collected on main form | P1 | Cannot issue GST invoices, cannot qualify enterprise leads |
| Country not confirmed as required field | P1 | Cannot apply appropriate tax rules or payment routing |
| Intended use case only for Enterprise — PRO customers have no use case field | P2 | Cannot segment customers by use case |
| `sentinel-onboarding.html` has a full multi-step UI with no backend — data goes nowhere | P0 | Visual onboarding with no data capture |
| No customer ID / reference number generated at submission | P0 | Cannot reference specific submissions for support |
| No GSTIN field for Indian business customers | P1 | Cannot generate GST-compliant invoices |

---

## DESIGNED CUSTOMER INTAKE SYSTEM v1.0

### Design Principles
1. **One form, one submission** — customer fills a single intake form that captures all data needed for provisioning and invoicing
2. **Progressive disclosure** — form adapts based on plan and payment method selected
3. **Immediate reference number** — customer receives a reference ID on submission
4. **Operator-ready handoff** — form data arrives at operator inbox pre-structured for action

---

### MASTER CUSTOMER INTAKE FORM — FIELD SPECIFICATION

#### Section A: Identity (All Plans)

| Field | Type | Required | Validation |
|-------|------|---------|-----------|
| Full Name | Text | Yes | Min 2 chars |
| Work Email | Email | Yes | Valid email format |
| Company / Organization | Text | Yes (PRO+) | Optional for Community |
| Job Title | Text | No | e.g., "SOC Analyst", "CISO" |
| Country | Dropdown | Yes | ISO country list |
| WhatsApp / Phone | Tel | No | For urgent support routing |

#### Section B: Plan Selection (All Plans)

| Field | Type | Required | Validation |
|-------|------|---------|-----------|
| Plan | Radio (Free/PRO/Enterprise/MSSP) | Yes | Auto-populated from referring page |
| Billing Period | Radio (Monthly/Annual) | Yes | Hidden for Free |
| Amount to Pay | Display (read-only) | — | Auto-calculated: plan × period |

#### Section C: Payment (Paid Plans Only)

| Field | Type | Required | Validation |
|-------|------|---------|-----------|
| Payment Method | Dropdown | Yes | UPI / NEFT / PayPal / Crypto (BTC/USDT) / Amazon Pay |
| Transaction ID / UTR / TxHash | Text | Yes (after payment) | Min 8 chars |
| Date of Payment | Date | Yes | Today or recent |
| Amount Paid (self-declared) | Number | Yes | Cross-reference with plan |
| Screenshot (optional) | File | No | JPG/PNG, max 5MB |

#### Section D: Business Details (Enterprise + MSSP)

| Field | Type | Required | Validation |
|-------|------|---------|-----------|
| GSTIN | Text | No (India) | 15-char GST format if provided |
| PAN / Tax ID | Text | No | For invoice |
| Billing Address | Textarea | Yes (Enterprise+) | Street, City, State, PIN |
| Number of Users / Seats | Number | Yes (MSSP) | For sub-tenant provisioning |
| Primary Integration (SIEM) | Dropdown | No | Splunk / Sentinel / Elastic / QRadar / Other |

#### Section E: Use Case (All Plans — adapted by tier)

| Field | Type | Required | Notes |
|-------|------|---------|-------|
| Intended Use Case | Dropdown | Yes | SOC Operations / Threat Hunting / Incident Response / Compliance / Research / MSSP Client Coverage |
| Brief Description | Textarea (200 chars) | No | "How will you use SENTINEL APEX?" |

#### Section F: Agreements

| Field | Type | Required |
|-------|------|---------|
| Accept Terms of Service | Checkbox | Yes |
| Accept Privacy Policy | Checkbox | Yes |
| Accept EULA | Checkbox | Yes (Enterprise+) |
| Opt-in to product updates | Checkbox | No |

---

### FORM SUBMISSION FLOW

```
Customer fills Master Intake Form
        ↓
Client-side validation (required fields, format checks)
        ↓
Submit to Formspree (or future backend endpoint)
        ↓
Formspree generates submission ID
        ↓
Auto-response email sent to customer:
  "Thank you, [Name]. Your request reference is: SA-[TIMESTAMP]-[RANDOM4].
   Plan: PRO Monthly | Payment: ₹4,100 via UPI | Status: Pending Verification.
   We will activate your API key within 2 hours of payment verification.
   Questions? WhatsApp +91 8179881447 | Email: bivash@cyberdudebivash.com"
        ↓
Operator notification email to bivash@cyberdudebivash.com:
  "[PRIORITY: PAID] New SA-2026-XXXX | Plan: PRO | Method: UPI | UTR: XXXXXX | Email: customer@company.com"
        ↓
Operator verifies payment → triggers API key provisioning
```

---

### DATA STORAGE DESIGN

#### Phase 1 (Current — No-Code)

**Google Sheets as CRM** (via Formspree → Zapier → Google Sheets)

Columns:
```
Reference ID | Timestamp | Name | Email | Company | Country | Plan | Billing | Amount | Method | Transaction ID | Verification Status | API Key Issued | Key Issued At | Notes
```

Row statuses: `PENDING_VERIFICATION` → `VERIFIED` → `KEY_ISSUED` → `ACTIVE` → `RENEWAL_DUE`

**Why Google Sheets:** Zero cost, accessible from any device, filterable, shareable with future team members. Can export to CSV for invoicing.

#### Phase 2 (Recommended — 30 days)

PostgreSQL table (via Supabase free tier):

```sql
CREATE TABLE customers (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reference_id    VARCHAR(20) UNIQUE,  -- SA-20260604-A7X2
  created_at      TIMESTAMPTZ DEFAULT now(),
  name            TEXT NOT NULL,
  email           TEXT NOT NULL,
  company         TEXT,
  country         VARCHAR(2),
  plan            VARCHAR(20),  -- community | pro | enterprise | mssp
  billing_period  VARCHAR(10),  -- monthly | annual
  amount_inr      INTEGER,
  payment_method  VARCHAR(20),
  transaction_id  TEXT,
  payment_date    DATE,
  gstin           TEXT,
  use_case        TEXT,
  status          VARCHAR(30) DEFAULT 'pending_verification',
  api_key_hash    TEXT,
  key_issued_at   TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ,
  notes           TEXT
);
```

---

### TRACKING & HANDOFF

#### Event Tracking (Client-side — apex-track.js)

Add these events to the intake form:
```javascript
// Form field interactions
trackEvent('intake_form_started', { plan, billing_period });
trackEvent('intake_form_payment_entered', { payment_method });
trackEvent('intake_form_submitted', { plan, method, amount });
trackEvent('intake_form_confirmed', { reference_id });
```

#### Handoff to Provisioning

Upon Formspree webhook receipt, trigger provisioning workflow:

```
Formspree webhook POST →
  Parse: email, plan, transaction_id, method →
  Log to Google Sheets / Supabase →
  Send acknowledgement email →
  Flag for manual verification (Phase 1)
  OR
  Trigger automated verification (Phase 2)
```

---

## IMPLEMENTATION CHECKLIST

- [ ] Merge `get-api-key.html` + `PAYMENT-GATEWAY.html` payment tracker into single intake form
- [ ] Add required fields: Company, Country, Plan (passed from URL param), Payment Method, Amount, Transaction ID
- [ ] Add GSTIN field for Indian business customers
- [ ] Implement client-side validation for all required fields
- [ ] Configure Formspree auto-response email with reference ID
- [ ] Configure Formspree webhook → Google Sheets via Zapier
- [ ] Populate `sentinel-onboarding.html` backend submission (currently UI-only)
- [ ] Add tracking events to apex-track.js for intake form milestones
- [ ] Test all 7 payment method paths end-to-end with test submissions

---

*Audit completed: 2026-06-04 | SENTINEL APEX v175.0 Commercial Readiness Sprint*
