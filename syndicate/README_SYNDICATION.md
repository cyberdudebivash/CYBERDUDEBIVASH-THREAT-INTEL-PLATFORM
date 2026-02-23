# 🔐 CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE v1.0
## RSS → Multi-Platform Social Media Automation | 100% Free | GitHub Actions

Replace Make.com with zero cost. Posts your threat intel reports from  
`cyberbivash.blogspot.com` to all social platforms automatically, every 2 hours.

---

## 📋 PLATFORMS SUPPORTED

| Platform | API Cost | Notes |
|---|---|---|
| LinkedIn (Showcase Page) | FREE | Needs OAuth app |
| Twitter / X | FREE | Free tier: 1,500 posts/month |
| Mastodon | FREE | Instant access token |
| Bluesky | FREE | App password only |
| Facebook Page | FREE | Graph API |
| Tumblr | FREE | OAuth app |
| Reddit (Profile) | FREE | Script app |
| Threads | FREE | Meta Developers |

---

## 🚀 DEPLOYMENT — STEP BY STEP

### STEP 1: Add files to your GitHub repo

Option A: Add to existing `CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM` repo (recommended)
Option B: Create new repo: `CYBERDUDEBIVASH-SYNDICATION-ENGINE`

Copy the entire `syndicate/` folder into the root of your chosen repo.  
Your repo structure should look like:
```
your-repo/
├── syndicate/
│   ├── syndicate/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── rss_poller.py
│   │   ├── state_manager.py
│   │   ├── formatter.py
│   │   └── platforms/
│   │       ├── linkedin.py
│   │       ├── twitter.py
│   │       ├── mastodon.py
│   │       ├── bluesky.py
│   │       ├── facebook.py
│   │       ├── tumblr.py
│   │       ├── reddit.py
│   │       └── threads.py
│   ├── data/
│   │   └── syndication_state.json
│   ├── requirements_syndicate.txt
│   └── .github/workflows/syndicate.yml
```

> ⚠️ Move `.github/workflows/syndicate.yml` to the ROOT `.github/workflows/` folder of your repo.

---

### STEP 2: Add GitHub Secrets

Go to: `GitHub Repo > Settings > Secrets and variables > Actions > New repository secret`

Add secrets for each platform you want to use. **Platforms with empty secrets are auto-skipped.**

---

### 🔑 PLATFORM CREDENTIAL SETUP

#### ✅ MASTODON (Easiest — 2 minutes)
1. Log in to `mastodon.social`
2. Go to `Preferences > Development > New Application`
3. Name: `CyberDudeBivash Syndication`, Scopes: `write:statuses`
4. Copy **Your access token**

**GitHub Secrets:**
```
MASTODON_ACCESS_TOKEN = <your token>
MASTODON_INSTANCE_URL = https://mastodon.social
```

---

#### ✅ BLUESKY (2 minutes)
1. Log in to `bsky.app`
2. Go to `Settings > Privacy and Security > App Passwords`
3. Click `Add App Password`, name it `syndication-bot`
4. Copy the generated password

**GitHub Secrets:**
```
BLUESKY_HANDLE       = cyberdudebivash.bsky.social
BLUESKY_APP_PASSWORD = <your app password>
```

---

#### ✅ TWITTER / X (10 minutes)
1. Go to `developer.twitter.com > Projects & Apps > New App`
2. App type: `Web App, Automated App or Bot`
3. In `App Settings > Keys and Tokens`:
   - Copy `API Key` and `API Key Secret`
   - Generate `Access Token` and `Access Token Secret` (with Read+Write permissions)

**GitHub Secrets:**
```
TWITTER_API_KEY       = <API Key>
TWITTER_API_SECRET    = <API Key Secret>
TWITTER_ACCESS_TOKEN  = <Access Token>
TWITTER_ACCESS_SECRET = <Access Token Secret>
```

---

#### ✅ LINKEDIN (15 minutes)
1. Go to `linkedin.com/developers > Create App`
2. App name: `CyberDudeBivash Syndication`
3. LinkedIn Page: Select your Company/Showcase page
4. In Products tab: Request `Marketing Developer Platform`
5. In Auth tab: Add OAuth 2.0 scope: `w_organization_social`, `r_organization_social`
6. Use OAuth flow to get access token (use https://www.linkedin.com/developers/tools/oauth/token-generator)

**Get your Organization URN:**
- Showcase page URL is: `linkedin.com/showcase/cyberdudebivash-sentinel-apex/`
- Go to: `https://api.linkedin.com/v2/organizationalEntityFollowerStatistics?q=organizationalEntity&organizationalEntity=urn:li:organization:XXXXXXX`
- Or check via Graph Explorer after auth

**GitHub Secrets:**
```
LINKEDIN_ACCESS_TOKEN = <access token>
LINKEDIN_AUTHOR_URN   = urn:li:organization:XXXXXXX   ← Showcase page ID
LINKEDIN_PERSONAL_URN = urn:li:person:XXXXXXX          ← Optional personal profile
```

---

#### ✅ FACEBOOK (15 minutes)
1. Go to `developers.facebook.com > My Apps > Create App`
2. Type: `Business`
3. Add product: `Facebook Login` + `Pages API`
4. Go to Graph API Explorer
5. Get User Access Token with: `pages_manage_posts`, `pages_read_engagement`
6. Exchange for Long-Lived Token (valid 60 days, renewable):
   ```
   GET https://graph.facebook.com/oauth/access_token
     ?grant_type=fb_exchange_token
     &client_id={app-id}
     &client_secret={app-secret}
     &fb_exchange_token={short-lived-token}
   ```
7. Get your Page Access Token:
   ```
   GET https://graph.facebook.com/me/accounts?access_token={long-lived-token}
   ```
8. Find your Page ID and Page Access Token in the response

**GitHub Secrets:**
```
FACEBOOK_PAGE_ID           = <numeric page ID>
FACEBOOK_PAGE_ACCESS_TOKEN = <page access token>
```

---

#### ✅ TUMBLR (10 minutes)
1. Go to `tumblr.com/oauth/apps > Register App`
2. Application Website: `https://cyberdudebivash.com`
3. Copy Consumer Key and Consumer Secret
4. Run OAuth dance (Python one-liner below):

```python
# pip install requests-oauthlib
from requests_oauthlib import OAuth1Session
consumer_key = "YOUR_KEY"
consumer_secret = "YOUR_SECRET"
oauth = OAuth1Session(consumer_key, client_secret=consumer_secret,
                      callback_uri='https://cyberdudebivash.com')
r = oauth.fetch_request_token('https://www.tumblr.com/oauth/request_token')
print("Go to:", oauth.authorization_url('https://www.tumblr.com/oauth/authorize'))
verifier = input("Enter verifier: ")
oauth_tokens = oauth.fetch_access_token('https://www.tumblr.com/oauth/access_token', verifier)
print("OAUTH_TOKEN:", oauth_tokens['oauth_token'])
print("OAUTH_SECRET:", oauth_tokens['oauth_token_secret'])
```

**GitHub Secrets:**
```
TUMBLR_CONSUMER_KEY    = <consumer key>
TUMBLR_CONSUMER_SECRET = <consumer secret>
TUMBLR_OAUTH_TOKEN     = <oauth token>
TUMBLR_OAUTH_SECRET    = <oauth secret>
TUMBLR_BLOG_NAME       = cyberdudebivash-news
```

---

#### ✅ REDDIT (10 minutes)
1. Go to `reddit.com/prefs/apps > Create another app`
2. Type: `script`
3. Name: `CyberDudeBivash Syndication`
4. Redirect URI: `https://cyberdudebivash.com`
5. Copy Client ID (under app name) and Client Secret

**GitHub Secrets:**
```
REDDIT_CLIENT_ID     = <client id>
REDDIT_CLIENT_SECRET = <client secret>
REDDIT_USERNAME      = Immediate_Gold9789
REDDIT_PASSWORD      = <your reddit password>
REDDIT_SUBREDDIT     = u_Immediate_Gold9789
```

---

#### ✅ THREADS (20 minutes)
1. Go to `developers.facebook.com > Create App > Business`
2. Add `Threads API` product
3. Complete OAuth flow for `threads_basic` + `threads_content_publish` scopes
4. Exchange for long-lived token (valid 60 days)
5. Get your User ID: `GET https://graph.threads.net/v1.0/me?access_token={token}`

**GitHub Secrets:**
```
THREADS_ACCESS_TOKEN = <long-lived access token>
THREADS_USER_ID      = <numeric user ID>
```

---

### STEP 3: Move workflow file

```bash
mkdir -p .github/workflows
cp syndicate/.github/workflows/syndicate.yml .github/workflows/syndicate.yml
```

Or manually move `syndicate.yml` to root `.github/workflows/` in your repo.

---

### STEP 4: Commit and push

```bash
git add .
git commit -m "feat: Add Sentinel Syndication Engine v1.0 — RSS to Social Media"
git push
```

The workflow will run automatically every 2 hours. First run will post any recent unsynced posts.

---

### STEP 5: Manual test run

Go to: `GitHub Repo > Actions > CyberDudeBivash Sentinel Syndication Engine > Run workflow`

Check the logs to confirm each platform posts successfully.

---

## 📊 HOW IT WORKS

```
[cron: every 2h]
       │
       ▼
  GitHub Actions
       │
       ▼
  Fetch RSS Feed ──► Parse new items ──► Compare with state.json
       │
       ▼
  For each new post:
    ├── LinkedIn (Showcase Page)
    ├── Twitter/X
    ├── Mastodon
    ├── Bluesky
    ├── Facebook Page
    ├── Tumblr
    ├── Reddit (Profile)
    └── Threads
       │
       ▼
  Update state.json ──► Git commit ──► Push to repo
```

State is stored in `data/syndication_state.json` — committed back to repo after each run.  
If a platform fails, it's **not** marked as posted → will retry on next run.

---

## 🔄 CUSTOMIZATION

**Change run frequency** — Edit `cron:` in `syndicate.yml`:
- Every 1 hour: `0 * * * *`
- Every 30 min: `*/30 * * * *`
- 4x daily: `0 6,12,18,0 * * *`

**Change hashtags** — Edit `HASHTAGS_COMMON` and `HASHTAGS_EXTRA` in `config.py`

**Add second blog** — Duplicate job in workflow with different `RSS_URL` env var

**Platform post format** — Customize in `formatter.py` per platform

---

## 🛡️ SECURITY

- All credentials are GitHub Secrets — never in code
- State file contains only post metadata (no credentials)
- Each platform module fails gracefully — one failure doesn't break others
- Run logs archived as GitHub Actions artifacts (30 day retention)

---

*CYBERDUDEBIVASH PVT. LTD. | Bhubaneswar, Odisha, India | © 2026*  
*intel.cyberdudebivash.com | cyberdudebivash.com*
