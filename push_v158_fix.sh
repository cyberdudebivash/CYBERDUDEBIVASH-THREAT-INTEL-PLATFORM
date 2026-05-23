#!/usr/bin/env bash
# SENTINEL APEX v158.0.1  -  Production commit script
# Run from repo root: bash push_v158_fix.sh

set -e

echo "=== Staging changed files ==="
git add index.html
git add scripts/dashboard_frontend_guard.py
git add .github/workflows/sentinel-blogger.yml

echo "=== Diff stat ==="
git diff --cached --stat

echo "=== Committing ==="
git commit -F commit_v158_phase2_fix.txt

echo "=== Pushing to main ==="
git push origin main

echo "=== Done  -  monitor sentinel-blogger.yml workflow run on GitHub Actions ==="
