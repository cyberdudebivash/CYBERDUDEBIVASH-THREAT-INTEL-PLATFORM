# CDB-SENTINEL-BLOGGER - Complete Setup Guide
**© 2026 CyberDudeBivash Pvt Ltd**

Automated Cyber Threat Intelligence Blogger for https://cyberbivash.blogspot.com

---

## 🎯 What This Does

Automatically monitors global cyber threats and publishes professional, branded blog posts to your Blogger:

- ✅ Fetches latest CVEs from NVD
- ✅ Fetches CISA Known Exploited Vulnerabilities
- ✅ Generates complete, professional blog posts
- ✅ Full CyberDudeBivash branding throughout
- ✅ Includes ecosystem links, services, products
- ✅ Posts automatically to cyberbivash.blogspot.com
- ✅ Runs every 6 hours on GitHub Actions

---

## 🚀 Complete Setup (Step-by-Step)

### Step 1: Get Blogger API Credentials

1. **Go to Google Cloud Console:**
   https://console.cloud.google.com/

2. **Create New Project:**
   - Click "Create Project"
   - Name: "CDB-SENTINEL-BLOGGER"
   - Create

3. **Enable Blogger API:**
   - Search for "Blogger API"
   - Click "Enable"

4. **Create OAuth2 Credentials:**
   - APIs & Services → Credentials
   - Create Credentials → OAuth client ID
   - Application type: **Desktop app**
   - Name: "CDB-SENTINEL-BLOGGER"
   - Download JSON (this is your `credentials.json`)

5. **Get Your Blog ID:**
   - Go to: https://www.blogger.com/blogger.g?blogID=YOUR_BLOG_ID
   - Your Blog ID is in the URL after `blogID=`
   - For cyberbivash.blogspot.com: `1735779547938854877`

### Step 2: Generate OAuth Token Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Create credentials folder
mkdir -p credentials

# Put your credentials.json in credentials/
cp /path/to/downloaded/credentials.json credentials/

# Run locally ONCE to generate token
python agent/sentinel_blogger.py

# This will:
# 1. Open browser for OAuth consent
# 2. Sign in with enterprise@cyberdudebivash.com
# 3. Grant permissions
# 4. Generate credentials/token.json
```

### Step 3: Setup GitHub Repository

1. **Create New Repo:**
   - Name: `CDB-SENTINEL-BLOGGER`
   - Private or Public

2. **Upload Files:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/cyberdudebivash/CDB-SENTINEL-BLOGGER.git
   git push -u origin main
   ```

### Step 4: Configure GitHub Secrets

Go to: `Settings → Secrets and variables → Actions`

Add these secrets:

1. **BLOGGER_BLOG_ID**
   ```
   1735779547938854877
   ```

2. **BLOGGER_CREDENTIALS**
   - Copy entire contents of `credentials/credentials.json`
   - Paste as secret value

3. **BLOGGER_TOKEN**
   - Copy entire contents of `credentials/token.json` (generated in Step 2)
   - Paste as secret value

4. **NVD_API_KEY** (Optional but recommended)
   - Get from: https://nvd.nist.gov/developers/request-an-api-key
   - Paste your API key

### Step 5: Run First Time

1. Go to: **Actions** tab
2. Click: **CDB-SENTINEL-BLOGGER**
3. Click: **Run workflow**
4. Check logs for success

---

## 📊 What Gets Posted

Each blog post includes:

### Structure:
1. **CyberDudeBivash Header** - Branded banner
2. **Alert Banner** - Severity, ID, source
3. **Executive Summary** - Professional overview
4. **Technical Analysis** - Detailed vulnerability info
5. **Impact Assessment** - Risk evaluation
6. **CyberDudeBivash Recommendations** - Action items
7. **Services Promotion** - Your SOC/services
8. **Resources Section** - Links to advisories
9. **Ecosystem Section** - Tools, apps, blogs
10. **Author Bio** - Threat Intel Team
11. **Contact & Social** - All your links
12. **Footer** - Copyright, publisher ID

### Branding Throughout:
- ✅ CyberDudeBivash logo/header
- ✅ Company information
- ✅ Website: www.cyberdudebivash.com
- ✅ Email: enterprise@cyberdudebivash.com
- ✅ Phone: +918179881447
- ✅ Location: Bhubaneswar, Odisha, India
- ✅ All ecosystem links
- ✅ All social media
- ✅ All products/services
- ✅ Publisher ID: pub-8343951291888650
- ✅ Copyright: © 2026 CyberDudeBivash Pvt Ltd

---

## ⏰ Automation Schedule

**Default:** Every 6 hours (4 posts per day maximum)

To change frequency, edit `.github/workflows/blogger.yml`:

```yaml
schedule:
  - cron: '0 */6 * * *'  # Every 6 hours
  # OR
  - cron: '0 */3 * * *'  # Every 3 hours
  # OR
  - cron: '0 */12 * * *' # Every 12 hours
```

---

## 🎯 Post Filtering

Only posts **HIGH and CRITICAL** severity:
- CVE with CVSS ≥ 7.0
- All CISA KEVs (always critical)

Maximum 5 posts per run to avoid spam.

---

## 📁 File Structure

```
CDB-SENTINEL-BLOGGER/
├── agent/
│   └── sentinel_blogger.py    # Main agent
├── .github/workflows/
│   └── blogger.yml            # GitHub Actions
├── credentials/
│   ├── credentials.json       # OAuth credentials (local only)
│   └── token.json             # OAuth token (local only)
├── data/
│   └── blogger_processed.json # State tracking
├── requirements.txt
├── README.md
└── SETUP.md                   # This file
```

---

## 🔧 Local Testing

```bash
# Setup
pip install -r requirements.txt

# Add credentials
cp /path/to/credentials.json credentials/
cp /path/to/token.json credentials/

# Set blog ID
export BLOGGER_BLOG_ID="1735779547938854877"

# Optional: NVD API key
export NVD_API_KEY="your-key"

# Run
python agent/sentinel_blogger.py
```

---

## ✅ Verification

After setup, check:

1. **GitHub Actions:**
   - Actions tab shows green ✓
   - Logs show "✓ Published!" messages

2. **Your Blog:**
   - Visit: https://cyberbivash.blogspot.com
   - See new posts appearing
   - Check branding is correct

3. **State File:**
   - `data/blogger_processed.json` gets updated
   - Prevents duplicate posts

---

## 🛡️ Security Notes

**Credentials:**
- ✅ Store in GitHub Secrets (encrypted)
- ✅ Never commit credentials/*.json to repo
- ✅ `.gitignore` already configured

**Permissions:**
- Only needs Blogger API access
- Scoped to your blog only
- Can revoke anytime at: https://myaccount.google.com/permissions

---

## 📞 Support

**Issues?**
- Email: enterprise@cyberdudebivash.com
- GitHub: https://github.com/cyberdudebivash

---

## 🎉 You're Done!

Your automated cyber threat intelligence blogger is now running!

**What happens next:**
1. System monitors NVD + CISA every 6 hours
2. New HIGH/CRITICAL incidents get detected
3. Professional blog posts auto-generate
4. Posts publish to cyberbivash.blogspot.com
5. Full CyberDudeBivash branding included
6. Ecosystem integrated throughout

**Zero manual work required!** 🚀

---

**© 2026 CyberDudeBivash Pvt Ltd. All Rights Reserved.**
