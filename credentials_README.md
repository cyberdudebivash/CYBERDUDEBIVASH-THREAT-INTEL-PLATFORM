# Credentials Setup

## ⚠️ SECURITY WARNING
Never commit real credentials to version control!

## Setup Instructions

1. Copy the example files:
   ```bash
   cp credentials.json.example credentials.json
   cp token.json.example token.json
   ```

2. Get credentials from Google Cloud Console:
   - Go to https://console.cloud.google.com/
   - Create OAuth 2.0 credentials
   - Download and replace values in credentials.json

3. Run the auth flow:
   ```bash
   python agent/blogger_engine.py --auth
   ```

4. The token.json will be generated automatically.

## Environment Variables (Recommended)
Instead of JSON files, use environment variables:
```bash
export GOOGLE_CLIENT_ID=your_client_id
export GOOGLE_CLIENT_SECRET=your_client_secret
export BLOGGER_API_KEY=your_api_key
```
