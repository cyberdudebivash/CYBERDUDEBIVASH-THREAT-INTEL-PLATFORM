#!/bin/bash
# SENTINEL APEX v28.0 FORTRESS — Deployment Script
# =================================================
# Run this in your repository root

echo "🛡️ SENTINEL APEX v28.0 FORTRESS — Applying Updates"
echo "=================================================="

# Backup current files
mkdir -p .backup_v27
cp index.html .backup_v27/ 2>/dev/null
cp VERSION .backup_v27/ 2>/dev/null
cp .gitignore .backup_v27/ 2>/dev/null

# Apply updates
cp index.html.new index.html 2>/dev/null || true
cp VERSION.new VERSION 2>/dev/null || true
cp .gitignore.new .gitignore 2>/dev/null || true

# Create directories
mkdir -p core tests data/stix data/enrichment data/ai_predictions

# Copy new files
cp -r core/* core/ 2>/dev/null || true
cp -r tests/* tests/ 2>/dev/null || true
cp CHANGELOG_v28.md . 2>/dev/null || true
cp SECURITY.md . 2>/dev/null || true

# Create .gitkeep files
touch data/stix/.gitkeep
touch data/enrichment/.gitkeep
touch data/ai_predictions/.gitkeep

# Remove sensitive files from git tracking
git rm --cached credentials/credentials.json credentials/token.json 2>/dev/null || true
git rm --cached data/audit_log.json data/telemetry_log.json data/revenue_log.json 2>/dev/null || true
git rm --cached data/blogger_processed.json data/sync_marker.json 2>/dev/null || true

echo ""
echo "✅ v28.0 FORTRESS applied!"
echo ""
echo "Next steps:"
echo "  git add -A"
echo "  git commit -m 'Upgrade to v28.0 FORTRESS'"
echo "  git push"
