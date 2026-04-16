# SENTINEL APEX v109 — GitHub Secrets Setup
## Required for R2 Auto-Sync + Worker Cache Busting

These secrets must be added to your GitHub repo before the pipeline can sync intel to R2.

---

## Step 1: Create Cloudflare API Token (CF_API_TOKEN)

1. Go to: https://dash.cloudflare.com/profile/api-tokens
2. Click **Create Token**
3. Use template: **Edit Cloudflare Workers**
4. Under **Permissions**, add:
   - Workers R2 Storage: **Edit**
   - Workers Scripts: **Edit** (already included)
5. Under **Account Resources**: Select your account
6. Click **Continue to summary** → **Create Token**
7. Copy the token value — you will only see it once

---

## Step 2: Get Your Cloudflare Account ID

1. Go to: https://dash.cloudflare.com
2. Select any domain (e.g. cyberdudebivash.com)
3. On the right sidebar, copy your **Account ID**

---

## Step 3: Add Secrets to GitHub Repo

1. Go to: https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/settings/secrets/actions
2. Click **New repository secret** for each:

| Secret Name | Value | Purpose |
|------------|-------|---------|
| `CF_API_TOKEN` | Token from Step 1 | Wrangler auth for R2 upload |
| `CF_ACCOUNT_ID` | Account ID from Step 2 | Wrangler account targeting |
| `WORKER_ADMIN_SECRET` | Your ADMIN_SECRET value | Cache busting after R2 sync |

> **Note**: `WORKER_ADMIN_SECRET` must match the ADMIN_SECRET you set via `npx wrangler secret put ADMIN_SECRET` during Worker deployment.

---

## Step 4: Manually Trigger R2 Sync (First Time)

After adding secrets:

1. Go to: https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions
2. Click **R2 Intel Data Sync v109** (left sidebar)
3. Click **Run workflow** → **Run workflow**
4. Wait 2-3 minutes
5. Test: `curl https://intel.cyberdudebivash.com/api/preview`

---

## Step 5: Verify Full Pipeline

After the first successful r2-data-sync run:

```bash
# Should return 10 preview items (public)
curl https://intel.cyberdudebivash.com/api/preview

# Should return 401 api_key_required
curl https://intel.cyberdudebivash.com/api/feed

# Should show r2_intel: "ok"
curl https://intel.cyberdudebivash.com/api/health
```

---

## Architecture (Post-Fix)

```
sentinel-blogger (every 4h)
    ↓ generates data/stix/feed_manifest.json
    ↓ Direct R2 Upload (Stage 3.5 — failsafe)
    → uploads to R2 in same pipeline run
    ↓
r2-data-sync.yml (triggered after sentinel-blogger)
    → uploads ALL intel files to R2
    → busts Worker KV cache
    ↓
Worker (intel.cyberdudebivash.com/api/*)
    → reads from R2 (primary)
    → serves /api/preview (public)
    → serves /api/feed (API key required)
    ↓
Dashboard (intel.cyberdudebivash.com)
    → fetches /api/preview → shows 10 items (all users)
    → fetches /api/feed with stored API key → full 2000+ items (authenticated)
```
