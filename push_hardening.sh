#!/bin/bash
# CYBERDUDEBIVASH v149 Hardening Push Script
# Run this from the repo root to push all hardened changes

echo "[CDB] Verifying commit..."
git log --oneline -3

echo ""
echo "[CDB] Pushing to origin/main..."
git push origin main

echo ""
echo "[CDB] Push complete. Verify at:"
echo "      https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions"
