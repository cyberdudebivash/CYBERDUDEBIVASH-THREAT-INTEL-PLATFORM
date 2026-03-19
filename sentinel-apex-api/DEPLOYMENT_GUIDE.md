# SENTINEL APEX API — DEPLOYMENT OPERATIONS GUIDE
## CYBERDUDEBIVASH PVT LTD | Version 1.0 | March 2026

---

## ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────┐
│  TIER 1: INTELLIGENCE PIPELINE (Existing — Untouched)          │
│  GitHub Actions → Python Enrichment → STIX + Manifest          │
│  ↓ NEW: Stage 7.5 writes to Supabase PG via v65_persistence   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│  TIER 2: API & COMPUTE (NEW — This Deployment)                 │
│  FastAPI on Railway.app                                        │
│  Supabase PostgreSQL + Auth                                    │
│  Endpoints: /auth, /api/v1/feed, /api/v1/keys, /api/v1/usage  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│  TIER 3: FRONTEND (Existing + Future app.cyberdudebivash.com)  │
│  intel.cyberdudebivash.com → Public dashboard (existing)       │
│  app.cyberdudebivash.com → Authenticated SaaS app (Week 7-8)  │
└─────────────────────────────────────────────────────────────────┘
```

**Monthly Cost: $0 (free tiers) → $50-70/mo at scale**

---

## STEP 1: SUPABASE PROJECT SETUP (~15 minutes)

### 1.1 Create Project
1. Go to https://supabase.com/dashboard
2. Click "New Project"
3. Settings:
   - **Organization**: Create or select "CyberDudeBivash Pvt Ltd"
   - **Project name**: `sentinel-apex`
   - **Database password**: Generate strong password → SAVE THIS
   - **Region**: `ap-south-1` (Mumbai) for lowest latency to India
   - **Plan**: Free (500MB DB, 50K auth users)
4. Wait for project provisioning (~2 minutes)

### 1.2 Run Schema Migration
1. Go to: Supabase Dashboard → **SQL Editor** → **New Query**
2. Copy the ENTIRE contents of `migrations/001_foundation_schema.sql`
3. Paste into the SQL editor
4. Click **Run**
5. Expected: All statements succeed with no errors
6. Verify: Go to **Table Editor** — you should see these tables:
   - `organizations`
   - `user_profiles`
   - `api_keys`
   - `advisories`
   - `api_usage`
   - `audit_log`
   - `tier_config` (should have 4 rows: free, pro, enterprise, mssp)

### 1.3 Configure Auth Providers
1. Go to: **Authentication** → **Providers**
2. **Email**: Already enabled by default
   - Disable "Confirm email" for faster testing (re-enable in production)
3. **Google OAuth** (optional but recommended):
   - Enable Google provider
   - Client ID + Secret from Google Cloud Console
   - Redirect URL: `https://YOUR_PROJECT.supabase.co/auth/v1/callback`
4. **GitHub OAuth** (optional):
   - Same pattern as Google

### 1.4 Collect API Keys
Go to: **Settings** → **API** and note:
- **Project URL**: `https://xxxxxxxx.supabase.co`
- **anon public key**: `eyJ...` (safe for frontend)
- **service_role key**: `eyJ...` (SECRET — backend only)
- **JWT Secret**: Found in **Settings** → **API** → **JWT Settings**

---

## STEP 2: RAILWAY DEPLOYMENT (~10 minutes)

### 2.1 Create Railway Project
1. Go to https://railway.app/dashboard
2. Click **"New Project"** → **"Deploy from GitHub Repo"**
3. Connect your GitHub account if not already
4. Select repository: `cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM`
5. Set **Root Directory**: `sentinel-apex-api`

### 2.2 Configure Environment Variables
In Railway dashboard → your service → **Variables** tab, add:

```
APP_VERSION=1.0.0
ENVIRONMENT=production
LOG_LEVEL=INFO

SUPABASE_URL=https://xxxxxxxx.supabase.co
SUPABASE_ANON_KEY=eyJ...your-anon-key
SUPABASE_SERVICE_KEY=eyJ...your-service-key
SUPABASE_JWT_SECRET=your-jwt-secret-from-supabase

CORS_ORIGINS=https://intel.cyberdudebivash.com,https://app.cyberdudebivash.com,http://localhost:3000

PIPELINE_SECRET=<generate with: python3 -c "import secrets; print(secrets.token_hex(32))">
```

### 2.3 Deploy
1. Railway auto-deploys on push to main
2. Or: Click **"Deploy"** manually
3. Wait for build + deploy (~3-5 minutes)
4. Railway assigns a URL like: `sentinel-apex-api-production.up.railway.app`

### 2.4 Custom Domain (Optional)
1. In Railway → **Settings** → **Networking** → **Custom Domain**
2. Add: `api.cyberdudebivash.com`
3. Add CNAME record in your DNS:
   ```
   api.cyberdudebivash.com  CNAME  sentinel-apex-api-production.up.railway.app
   ```

### 2.5 Verify Deployment
```bash
# Health check
curl https://YOUR_RAILWAY_URL/health

# Expected:
# {"status":"healthy","version":"1.0.0","environment":"production",...}

# Root endpoint
curl https://YOUR_RAILWAY_URL/

# OpenAPI docs
# Open: https://YOUR_RAILWAY_URL/docs
```

---

## STEP 3: VERIFY AUTH FLOW (~5 minutes)

### 3.1 Test Signup
```bash
curl -X POST https://YOUR_RAILWAY_URL/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "bivash@cyberdudebivash.com",
    "password": "YourStrong1Pass!",
    "full_name": "Bivash Kumar Nayak"
  }'
```

Expected: 201 response with access_token + user profile.

### 3.2 Test Signin
```bash
curl -X POST https://YOUR_RAILWAY_URL/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "bivash@cyberdudebivash.com",
    "password": "YourStrong1Pass!"
  }'
```

Save the `access_token` from the response.

### 3.3 Test Profile
```bash
curl https://YOUR_RAILWAY_URL/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 3.4 Create API Key
```bash
curl -X POST https://YOUR_RAILWAY_URL/api/v1/keys \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Production Key"}'
```

**SAVE THE `api_key` FROM THE RESPONSE — it is shown only once.**

### 3.5 Test API Key Auth
```bash
curl https://YOUR_RAILWAY_URL/api/v1/feed \
  -H "X-API-Key: cdb_sk_live_YOUR_KEY_HERE"
```

---

## STEP 4: CONNECT PIPELINE TO SUPABASE (~10 minutes)

### 4.1 Add GitHub Secrets
In your repo: **Settings** → **Secrets and variables** → **Actions**, add:
- `SUPABASE_URL` — Your Supabase project URL
- `SUPABASE_SERVICE_KEY` — Service role key
- `SENTINEL_API_URL` — Your Railway URL
- `PIPELINE_SECRET` — Same value as in Railway env vars

### 4.2 Copy v65 Persistence Module
Copy the `agent/v65_persistence/` directory into your existing repo:
```
your-repo/
├── agent/
│   ├── v65_persistence/
│   │   ├── __init__.py
│   │   └── pg_writer.py      ← NEW
│   ├── v56_publish_guard/
│   ├── sentinel_blogger.py
│   └── ...
```

### 4.3 Add Pipeline Stage
In `sentinel-blogger.yml`, add this step AFTER STIX export, BEFORE Blogger publish:

```yaml
      - name: "STAGE 7.5: Persist to Supabase PG"
        env:
          SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
          SUPABASE_SERVICE_KEY: ${{ secrets.SUPABASE_SERVICE_KEY }}
          SENTINEL_API_URL: ${{ secrets.SENTINEL_API_URL }}
          PIPELINE_SECRET: ${{ secrets.PIPELINE_SECRET }}
        run: |
          echo "=== STAGE 7.5: PERSIST TO POSTGRESQL ==="
          pip install httpx --quiet
          python -m agent.v65_persistence.pg_writer \
            --manifest data/feed_manifest.json \
            --mode auto
          echo "=== PG PERSISTENCE COMPLETE ==="
```

### 4.4 Trigger Pipeline
Manually trigger the sentinel-blogger workflow and verify:
1. Stage 7.5 completes without errors
2. Check Supabase Table Editor → `advisories` → data appears
3. Check API: `curl YOUR_RAILWAY_URL/api/v1/feed` returns advisories

---

## STEP 5: POST-DEPLOYMENT CHECKLIST

### Security
- [ ] Supabase "Confirm email" re-enabled in production
- [ ] All secrets rotated from any test values
- [ ] CORS_ORIGINS does NOT include localhost in production
- [ ] Pipeline secret is unique, not shared with any other service
- [ ] Railway environment set to `production`

### Monitoring
- [ ] Railway provides built-in logging (Observability tab)
- [ ] Health endpoint returns "healthy"
- [ ] Set up UptimeRobot or Better Uptime for /health polling
- [ ] Supabase Dashboard → Database → shows query activity

### DNS (when ready)
- [ ] `api.cyberdudebivash.com` → Railway CNAME
- [ ] `app.cyberdudebivash.com` → Future React SPA (Vercel/Netlify)
- [ ] SSL certificates auto-provisioned by Railway

---

## API ENDPOINT REFERENCE

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/` | GET | None | Platform info |
| `/health` | GET | None | Health check |
| `/docs` | GET | None | OpenAPI Swagger UI |
| `/auth/signup` | POST | None | Register new user |
| `/auth/signin` | POST | None | Login with email/password |
| `/auth/refresh` | POST | None | Refresh access token |
| `/auth/oauth` | POST | None | Get OAuth URL |
| `/auth/me` | GET | JWT | Get current user profile |
| `/api/v1/feed` | GET | Optional | Paginated threat feed |
| `/api/v1/feed/{id}` | GET | Optional | Advisory detail |
| `/api/v1/search` | GET | Pro+ | Full-text search |
| `/api/v1/mitre/coverage` | GET | Optional | MITRE ATT&CK stats |
| `/api/v1/keys` | POST | JWT | Create API key |
| `/api/v1/keys` | GET | JWT | List API keys |
| `/api/v1/keys/{id}` | DELETE | JWT | Revoke API key |
| `/api/v1/usage` | GET | JWT/Key | Usage statistics |
| `/api/v1/ingest` | POST | Pipeline | Batch advisory ingest |
| `/api/v1/ingest/single` | POST | Pipeline | Single advisory ingest |

---

## TROUBLESHOOTING

### "Database unhealthy" in /health
- Verify SUPABASE_URL and SUPABASE_SERVICE_KEY are correct
- Check Supabase Dashboard → is project active (not paused)?
- Free tier pauses after 7 days of inactivity

### 401 on authenticated endpoints
- JWT expired → use /auth/refresh
- API key revoked → create new key
- Wrong header format → must be `Authorization: Bearer TOKEN` or `X-API-Key: KEY`

### Pipeline Stage 7.5 fails
- Check GitHub Actions logs for the specific error
- Verify SUPABASE_URL secret is set correctly (no trailing slash)
- Test: `curl YOUR_RAILWAY_URL/health` from a browser

### Railway deployment fails
- Check build logs in Railway dashboard
- Ensure Dockerfile or Procfile is at root of sentinel-apex-api/
- Verify Python 3.12 compatibility

---

## COST PROJECTION

| Component | Free Tier | Phase 1 ($) | Notes |
|---|---|---|---|
| Supabase | 500MB DB, 50K users | $25/mo Pro | Upgrade when >500MB |
| Railway | 500 hrs/mo, 8GB RAM | $7-25/mo | Auto-scales |
| Upstash Redis | 10K cmds/day | $10/mo | Add when multi-instance |
| Cloudflare | DNS + CDN | $0 | Free tier sufficient |
| **Total** | **$0** | **$42-60/mo** | |

---

## FILE MANIFEST

```
sentinel-apex-api/
├── app/
│   ├── main.py                      # FastAPI entry point
│   ├── api/v1/endpoints/
│   │   ├── auth.py                  # Signup, signin, OAuth, profile
│   │   ├── feed.py                  # Threat feed, search, MITRE
│   │   ├── keys.py                  # API key CRUD
│   │   └── usage.py                 # Usage stats + pipeline ingest
│   ├── auth/
│   │   └── dependencies.py          # JWT + API key auth
│   ├── core/
│   │   ├── config.py                # Pydantic settings
│   │   └── security.py              # JWT, hashing, key generation
│   ├── db/
│   │   └── client.py                # Supabase REST + Auth client
│   ├── middleware/
│   │   └── rate_limit.py            # In-memory rate limiter
│   └── schemas/
│       └── models.py                # Pydantic request/response models
├── agent/v65_persistence/
│   ├── pg_writer.py                 # Pipeline → PG persistence
│   └── PIPELINE_PATCH.yml           # YAML snippet for sentinel-blogger.yml
├── migrations/
│   └── 001_foundation_schema.sql    # Supabase PG schema
├── scripts/
│   └── verify_supabase.py           # Schema verification tool
├── tests/
│   └── test_api.py                  # 30-test suite (all passing)
├── .github/workflows/
│   └── sentinel-apex-api.yml        # CI/CD pipeline
├── Dockerfile                       # Production container
├── Procfile                         # Railway/Render start command
├── railway.toml                     # Railway config
├── render.yaml                      # Render.com config (alternative)
├── requirements.txt                 # Python dependencies
├── pytest.ini                       # Test configuration
├── .env.example                     # Environment template
└── .gitignore
```
