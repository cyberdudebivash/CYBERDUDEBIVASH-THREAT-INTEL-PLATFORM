# CYBERDUDEBIVASH® SENTINEL APEX — INCIDENT RESPONSE GUIDE
## Version: v145.0 | Last Updated: 2026-05-08

---

## INCIDENT CLASSIFICATION

| P0 CRITICAL | Platform fully down → immediate response |
| P1 HIGH | Pipeline failure or data quality regression |
| P2 MEDIUM | Non-customer-facing issue, no SLA breach |
| P3 LOW | Monitoring alert, cosmetic issue |

---

## INCIDENT RESPONSE WORKFLOW

```
DETECT → CLASSIFY → COMMUNICATE → MITIGATE → RESOLVE → POST-MORTEM
```

### 1. DETECT

Triggers for incident declaration:
- UptimeRobot alert email (intel.cyberdudebivash.com down)
- GitHub Actions failure email notification
- Customer email to enterprise@cyberdudebivash.com reporting issue
- Self-discovery during daily ops checklist

### 2. CLASSIFY

Use severity table above. When in doubt, classify up (i.e., use P0 if unsure between P0/P1).

### 3. COMMUNICATE

For P0/P1:
- Post immediate status update to intel.cyberdudebivash.com/status.html
- If enterprise customer subscriptions exist: email within 30 minutes of detection

For P2/P3:
- No customer communication required unless issue persists > 4 hours

### 4. MITIGATE

See ops/RUNBOOK.md for specific mitigation steps per incident type.

### 5. RESOLVE

- Verify fix is deployed and live
- Check report sizes are > 60KB
- Verify intel.cyberdudebivash.com loads correctly
- Verify all GitHub Actions are green

### 6. POST-MORTEM

After every P0/P1 incident:
- Create `ops/post-mortems/YYYY-MM-DD-[slug].md`
- Use template from ops/RUNBOOK.md Section 10
- Document timeline, root cause, impact, resolution, prevention

---

## SECURITY INCIDENT RESPONSE

### Compromised GitHub PAT

```powershell
# IMMEDIATE ACTIONS (within 15 minutes):
# 1. Go to GitHub Settings → Developer Settings → Personal access tokens
# 2. Delete the compromised token immediately
# 3. Rotate per ops/SECRETS-ROTATION.md
# 4. Review recent commits for unauthorized changes:
git log --oneline -50 --format="%H %ae %s"
# 5. Check for unauthorized files:
git diff HEAD~50 --name-only
# 6. If unauthorized commits exist: create rollback
.\ops\ROLLBACK.ps1 -Tag "v145.0-production-20260508"
```

### XSS in Published Report

```
1. Identify the affected report URL
2. Lock pipeline immediately: .\ops\LOCK-PIPELINE.ps1
3. Delete the affected report from the repo
4. Push the deletion: git add -A && git commit -m "sec: remove XSS-affected report [skip ci]"
5. .\ops\PUSH-GODMODE.ps1
6. Purge Cloudflare CDN cache for the affected URL
7. Review report_generator.py IOC sanitization (_esc() function)
8. Root cause: if IOC data contained <script> tags and _esc() was bypassed
9. Fix and re-verify before unlocking pipeline
```

### Unauthorized API Key Usage

```
1. Immediately revoke the compromised key in Cloudflare Worker KV
2. Check ANALYTICS_KV for suspicious usage patterns
3. Rate limits were in place — check if rate limit was exhausted
4. Issue new API key to affected customer
5. Review API auth logs in SECURITY_HUB_KV
```

---

## CONTACT DIRECTORY

| Role | Contact | Priority |
|------|---------|----------|
| Platform Operator | enterprise@cyberdudebivash.com | P0/P1/P2/P3 |
| Intel Contact | enterprise@cyberdudebivash.com | Customer-facing |
| GitHub Support | https://support.github.com | Repository issues |
| Cloudflare Support | https://support.cloudflare.com | CDN/Worker issues |

---

*SENTINEL APEX Incident Response Guide v145.0 | © 2026 CyberDudeBivash Pvt. Ltd.*
