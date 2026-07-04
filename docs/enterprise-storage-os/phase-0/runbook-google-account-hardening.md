# Phase 0 Runbook — Google Account Hardening (RB-8 Baseline)
## Applies to all 7 continuity-plane accounts | Est. 20 minutes per account

Execute top-to-bottom **per account**, starting with the Control Tower
(`iambivash.bn@gmail.com`). Do this from a trusted device on a trusted
network. Record completion in the table at the bottom (commit via PR —
record **only** checkmarks and dates, never credentials).

---

## Per-Account Procedure

### 1. Password
1. Generate a unique ≥ 20-character random password in the password manager.
2. Change at https://myaccount.google.com/security → "Password".
3. Confirm the password manager entry is saved under vault folder
   `CyberDudeBivash/Continuity-Plane/<account>`.

### 2. Two-Step Verification (strongest available factors)
1. https://myaccount.google.com/security → "2-Step Verification" → ON.
2. Add a **passkey and/or hardware security key** as the primary factor.
   The same hardware key may be registered on all 7 accounts.
3. Add Google Authenticator (TOTP) as secondary factor; store the TOTP seed
   in the password manager.
4. **Remove SMS as a 2FA factor** once passkey + TOTP are confirmed working
   (SIM-swap resistance). Keep the phone number only as recovery info if
   desired.
5. Download backup codes → store in password manager + print one copy for
   the sealed continuity dossier (item 0.9).

### 3. Recovery Information
1. Security → "Recovery email": set to `iambivash.bn@gmail.com` for the six
   secondary accounts. For the Control Tower itself, use a non-Google
   address you control (e.g. `root@cyberdudebivash.in`).
2. Verify recovery phone is current, or remove it if backup codes + hardware
   key are in place and printed.

### 4. Access Review
1. https://myaccount.google.com/permissions — remove every third-party app
   you don't recognize or no longer use. (rclone OAuth will be added later,
   in Phase 2, per-account.)
2. https://myaccount.google.com/device-activity — sign out unknown devices.
3. Security → "Your devices" → confirm only current devices remain.

### 5. Sharing Hygiene (Drive)
1. In Drive, review "Shared with me" and shared-by-me items.
2. Remove any "Anyone with the link" sharing on non-PUBLIC material
   (Vol. 4 §3 classification).

### 6. Quota Baseline
1. Note current storage usage (Drive → storage indicator) in the completion
   table — this is the Phase 0 quota baseline for the Vol. 9 KPI
   "continuity plane quota headroom ≥ 20%".

---

## Completion Table (fill in via PR)

| Account | Role | Pwd rotated | Passkey/HW key | TOTP | SMS 2FA removed | Backup codes stored | Recovery set | Apps reviewed | Quota used / 15 GB | Date |
|---|---|---|---|---|---|---|---|---|---|---|
| iambivash.bn@gmail.com | Control Tower | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | — | — |
| bivashnayak.ai007@gmail.com | Vault 1 — Threat Intel | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | — | — |
| cyberdudebivashpro@gmail.com | Vault 2 — AI Security | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | — | — |
| bivashnayak.ai07@gmail.com | Vault 3 — Products | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | — | — |
| bivashkumar521@gmail.com | Vault 4 — Marketing | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | — | — |
| bivashan127001@gmail.com | Vault 5 — MSSP (encrypted-only) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | — | — |
| bivash.kmr007@gmail.com | Cold Archive | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | — | — |

**Standing rule (Vol. 7 §3.3):** repeat the access-review steps (§4–§5)
quarterly; the quarterly check is logged as a run record once Phase 2
automation is live.
