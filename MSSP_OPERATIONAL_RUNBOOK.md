# SENTINEL APEX — MSSP OPERATIONAL RUNBOOK
## v176.0 | Phase 1: First 5 MSSP Clients

---

## PURPOSE

Step-by-step procedures for acquiring, onboarding, provisioning, and supporting MSSP partners. This runbook covers the full MSSP lifecycle for up to 5 concurrent MSSP partners.

---

## PART 1: MSSP ACQUISITION WORKFLOW

### Stage 1 — Prospect Contacts (via mssp.html contact form)

**Trigger:** Formspree notification arrives with "MSSP inquiry" in subject.

**Action (within 24 hours):**
1. Open inquiry, note: company name, contact name, email, client count estimate
2. Create CRM row in Google Sheets CUSTOMERS tab with Status = `MSSP_PROSPECT`
3. Send personalized discovery email (template below)

**MSSP Discovery Email Template:**
```
Subject: Re: SENTINEL APEX MSSP Partnership — [COMPANY NAME]

Hi [NAME],

Thanks for your interest in the SENTINEL APEX MSSP program.

I'm Bivash — I manage all MSSP partnerships directly.

A few quick questions to scope your needs:
1. How many client organizations do you currently provide security services for?
2. Which SIEM platforms do your clients use? (Splunk / Sentinel / Elastic / QRadar / Other)
3. What sectors are your clients in? (Financial, Healthcare, Government, etc.)
4. Are you looking to start with a few pilot clients or roll out across your full client base?

Our MSSP program: $1,999/month for unlimited clients, 500,000 API calls/day,
white-label Intel Data, sub-client keys on request, 2-hour support SLA.

Full details: https://intel.cyberdudebivash.com/mssp.html

Happy to jump on a 20-minute call this week to walk you through everything.
Reply with your availability.

— Bivash
bivash@cyberdudebivash.com | +91 8179881447
```

---

### Stage 2 — Discovery Call (30 minutes)

**Agenda:**
- 5 min: Understand MSSP's current CTI workflow
- 10 min: Live demo of SENTINEL APEX platform
- 10 min: Walk through MSSP integration (API → SIEM → client reports)
- 5 min: Pricing, agreement, next steps

**Tools:** Google Meet or Zoom (share screen to show live dashboard)

**Qualification criteria (any 2 = qualified):**
- [ ] 5+ active managed clients
- [ ] Uses a SIEM (Splunk / Sentinel / Elastic / QRadar)
- [ ] Has an existing CTI process (even if manual)
- [ ] Budget authority confirmed (decision maker on call)

---

### Stage 3 — MSSP Proposal

After qualification, send within 24 hours:

```
Subject: SENTINEL APEX MSSP Proposal — [COMPANY NAME] | [DATE]

Hi [NAME],

As discussed, here's the SENTINEL APEX MSSP proposal for [COMPANY]:

PLAN: MSSP Master Subscription
PRICE: $1,999/month (≈ ₹1,65,000/month)
      OR $19,990/year (save $1,998 — recommended)

WHAT'S INCLUDED:
• Master API key (500,000 calls/day — covers all your clients)
• Sub-keys for each client (issued on request, 2 hours)
• White-label Intel Data (your branding on reports)
• STIX 2.1 / TAXII / Sigma / YARA / IOC exports
• Dedicated WhatsApp support group (2-hour SLA)
• Monthly usage report per client
• MSSP Agreement (PDF attached)

TO START:
1. Review and sign the MSSP Agreement (attached)
2. Pay via: https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html?plan=mssp
3. Submit your payment reference + signed agreement to bivash@cyberdudebivash.com
4. Your Master Key + onboarding session scheduled within 24 hours

Questions? Reply here or WhatsApp +91 8179881447.

— Bivash
```

---

## PART 2: MSSP PROVISIONING WORKFLOW

### Step 1 — Agreement Signed + Payment Received

**Checklist:**
- [ ] MSSP Agreement signed (PDF received via email)
- [ ] Payment transaction ID submitted and verified
- [ ] MSSP company name, primary contact, WhatsApp number confirmed

**Action:**
1. Log in CRM: Status = `MSSP_PAYMENT_VERIFIED`
2. Generate MSSP master key:
   ```bash
   cd /path/to/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
   python3 agent/tools/generate_key.py generate \
     --tier mssp \
     --email [PARTNER_EMAIL] \
     --ref [REFERENCE_ID] \
     --days 30 \
     --name "[PARTNER_NAME]" \
     --company "[MSSP_COMPANY]"
   ```
3. Record key hash in CRM (never record plaintext)
4. Note expiry date in CRM

---

### Step 2 — Master Key Delivery

1. Send email using template: `templates/email/08_mssp_welcome.txt`
2. Attach signed MSSP Agreement (countersigned)
3. Attach GST invoice PDF
4. Create WhatsApp group: `SENTINEL-MSSP-[COMPANY_SHORT]`
   - Add: Bivash + MSSP primary contact (WhatsApp number)
   - Send welcome message in group:
     ```
     Hi [NAME]! Welcome to SENTINEL APEX MSSP. I'm Bivash.
     This is your dedicated support channel (2-hour SLA).
     Your Master Key has been delivered to your email.
     Let's schedule the onboarding call — what time works for you this week?
     ```
5. Update CRM: Status = `MSSP_ACTIVE`, support_channel = `whatsapp_group`

---

### Step 3 — MSSP Onboarding Call (60 minutes)

**Schedule within 48 hours of Master Key delivery.**

**Agenda:**
1. (10 min) Master key test: live API call from MSSP's machine
2. (15 min) Client #1 sub-key provisioning walkthrough
3. (20 min) SIEM integration for first client ([SIEM_PLATFORM])
4. (10 min) White-label: how to use SENTINEL APEX data under MSSP brand
5. (5 min) Support process: WhatsApp group SLA, how to request sub-keys

**Post-call action:**
- Send meeting notes + action items to MSSP via email + WhatsApp group
- Provision first 3 sub-keys (if client names provided on call)

---

### Step 4 — Sub-Client Provisioning

**Trigger:** MSSP emails or WhatsApps with new client details.

**Required information per sub-client:**
- Client company name
- Client primary contact email (to CC on key delivery)
- Client SIEM platform
- Coverage start date

**Action:**
```bash
python3 agent/tools/generate_key.py generate \
  --tier enterprise \         # Sub-clients get ENTERPRISE tier quota (50k/day)
  --email [CLIENT_EMAIL] \
  --ref [MSSP_REF]-C[N] \   # e.g. SA-20260604-A7X2-C1 for client 1
  --days 30 \
  --name "[CLIENT_COMPANY]" \
  --company "[CLIENT_COMPANY] via [MSSP_COMPANY]" \
  --notes "Sub-client of MSSP:[MSSP_COMPANY] | MSSP-REF:[MSSP_REF]"
```

Email sub-key to: MSSP primary contact (who delivers to their client).

---

## PART 3: MSSP SUPPORT PROCEDURES

### Escalation Matrix

| Severity | Examples | Response | Channel |
|---------|---------|---------|---------|
| P0 | Master key stops working, API unreachable | 2h, 24x7 | WhatsApp group |
| P1 | Feed missing, wrong data, integration broken | 2h, 9am–7pm IST | WhatsApp group |
| P2 | Sub-client key request, integration question | 4h, business hours | WhatsApp or email |
| P3 | General questions, feature requests | 8h, business hours | Email |

### Sub-Key Management Log

Maintain a sub-client log per MSSP (in Google Sheets):
```
MSSP: [COMPANY] | Ref: [SA-XXXX]
─────────────────────────────────────────────────────────────────
Client # | Client Name  | Key Hash[:12] | Issued    | Expires   | Status
1        | Acme Corp    | 61e439f75354  | 2026-06-04 | 2026-07-04 | active
2        | BankSec Ltd  | 7a2b3c4d5e6f  | 2026-06-05 | 2026-07-05 | active
```

---

## PART 4: MSSP RENEWAL WORKFLOW

**D-14 before expiry:**
- Send renewal reminder (email template 04) to MSSP primary contact
- WhatsApp group message: "Hi [NAME], your SENTINEL APEX MSSP subscription renews in 14 days (expires [DATE]). Renewal link: [URL]. Same amount: $1,999."

**D-7:**
- Follow-up WhatsApp if no payment response

**D-3:**
- Direct call or WhatsApp voice message

**On Renewal Payment:**
1. Verify payment per standard RevOps playbook
2. Extend key expiry in `data/keys/active_keys.json` (update `expires_at` field)
3. Send renewal confirmation email (template 06)
4. Update CRM: `last_renewed_at`, `renewal_count +1`
5. Sub-client keys: extend individually (coordinate with MSSP on which clients renew)

---

## PART 5: MSSP MONTHLY REPORTING

Send a monthly usage report to each MSSP partner on the 1st of each month:

```
Subject: SENTINEL APEX MSSP — Monthly Report [MONTH YEAR] | [COMPANY]

Hi [NAME],

Here is your SENTINEL APEX MSSP usage report for [MONTH YEAR].

MASTER KEY USAGE:
• Total API calls: [X]
• Peak usage day: [DATE] ([N] calls)
• Average daily: [N] calls

THREAT INTELLIGENCE DELIVERED:
• New CVEs processed: [N]
• Critical severity advisories: [N]
• IOCs published: [N]
• Sigma rules updated: [N]

CLIENT COVERAGE:
• Active sub-keys: [N]
• Client #1 [COMPANY]: [N] calls
• Client #2 [COMPANY]: [N] calls
[etc.]

Next renewal: [DATE] | Amount: $1,999
Renewal link: https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html?plan=mssp

Any questions? WhatsApp the support group or reply here.

— Bivash
```

---

## PART 6: MSSP CAPACITY NOTES

This Phase 1 runbook supports **up to 5 concurrent MSSP partners** with manual processes.

At 6+ MSSP partners, automate:
- Sub-key generation via POST /api/admin/provision (requires backend API endpoint)
- Monthly reports via GitHub Actions workflow
- Renewal reminders via scheduled email script

Target: First MSSP partner within 60 days of v176.0 launch.

---

*Runbook authored: 2026-06-04 | SENTINEL APEX v176.0*
