# CYBERDUDEBIVASH® SENTINEL APEX — SECRETS ROTATION GUIDE
## Version: v145.0 | Last Updated: 2026-05-08

---

## ROTATION SCHEDULE

| Secret | Storage | Frequency | Last Rotated | Next Due |
|--------|---------|-----------|-------------|----------|
| GitHub PAT (push) | Windows Credential Manager | 90 days | 2026-05-08 | 2026-08-06 |
| CDB_JWT_SECRET | GitHub Actions Secrets | 90 days | 2026-05-08 | 2026-08-06 |
| ADMIN_SECRET (Cloudflare Worker) | wrangler secret | 90 days | 2026-05-08 | 2026-08-06 |
| Cloudflare API Token | Cloudflare Dashboard | 180 days | 2026-05-08 | 2026-11-04 |
| STRIPE_WEBHOOK_SECRET | GitHub Actions Secrets | 180 days | — | — |
| TG_BOT_TOKEN | GitHub Actions Secrets | 365 days | — | — |

---

## ROTATION PROCEDURES

### GitHub PAT Rotation

1. Go to: https://github.com/settings/tokens?type=beta
2. Delete the old fine-grained token named "SENTINEL-APEX-PUSH"
3. Create new token:
   - Name: SENTINEL-APEX-PUSH-[DATE]
   - Repository access: Only selected → cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
   - Permissions: Contents → Read and Write (nothing else)
   - Expiration: 90 days
4. Update Windows Credential Manager:
   - Control Panel → Credential Manager → Windows Credentials
   - Remove old git:https://github.com entry
   - Run: git push origin main (prompts for new token)
5. Update this table with new rotation date

### CDB_JWT_SECRET Rotation

```bash
# Generate new secret (32+ chars, cryptographically random)
openssl rand -hex 32
```

1. Copy the output
2. Go to: https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/settings/secrets/actions
3. Update CDB_JWT_SECRET with new value
4. Update Cloudflare Worker:
   ```bash
   cd workers/intel-gateway
   npx wrangler secret put CDB_JWT_SECRET
   # paste the new value
   ```
5. Note: All existing JWTs are immediately invalidated. No customer impact since JWTs are generated fresh per API call.

### ADMIN_SECRET Rotation (Cloudflare Worker)

```bash
cd workers/intel-gateway
npx wrangler secret put ADMIN_SECRET
# Enter a new random 32-char string
```

### Cloudflare API Token Rotation

1. Go to: https://dash.cloudflare.com/profile/api-tokens
2. Create new token with Zone:Edit, Cache:Purge permissions for intel.cyberdudebivash.com
3. Update any scripts that use the Cloudflare API token
4. Revoke the old token

---

## SECRET SCANNING VERIFICATION

Run monthly to confirm no secrets are in the repository:

```bash
# Check for accidentally committed tokens
git log --all --full-history -- "*.env" "*.pem" "*.key" "token.json" "credentials.json"

# Search for high-entropy strings (potential tokens)
grep -r --include="*.py" --include="*.js" --include="*.yml" \
  -E "[a-zA-Z0-9]{40,}" . \
  --exclude-dir=.git --exclude-dir=node_modules \
  | grep -v "# " | grep -v "hash" | grep -v "sha" | head -20
```

---

## SECURITY NOTES

- **Never commit** .env, token.json, credentials.json, *.pem, *.key files
- **Never hardcode** API keys, PATs, or JWT secrets in Python/JS/PowerShell files
- **Never paste** secrets into chat interfaces (Claude, ChatGPT, etc.)
- **Always use** GitHub Actions Secrets for pipeline credentials
- **Always use** `wrangler secret put` for Cloudflare Worker secrets

---

*SENTINEL APEX Secrets Rotation Guide v145.0 | © 2026 CyberDudeBivash Pvt. Ltd.*
