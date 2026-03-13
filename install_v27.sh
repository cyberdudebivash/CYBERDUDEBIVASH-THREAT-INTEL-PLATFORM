#!/bin/bash
# SENTINEL APEX v27.0 Installation Script
# ========================================

echo "========================================"
echo "SENTINEL APEX v27.0 ENTERPRISE UPGRADE"
echo "========================================"

# Check if in correct directory
if [ ! -d "agent" ]; then
    echo "❌ Error: Run this script from the platform root directory"
    exit 1
fi

# Backup existing v27 if present
if [ -d "agent/v27" ]; then
    echo "📦 Backing up existing v27..."
    mv agent/v27 agent/v27.backup.$(date +%Y%m%d_%H%M%S)
fi

# Copy new v27 modules
echo "📁 Installing v27 modules..."
cp -r agent/v27 ../agent/ 2>/dev/null || cp -r agent/v27 agent/

# Copy tests
echo "🧪 Installing tests..."
cp tests/test_v27_modules.py tests/ 2>/dev/null || mkdir -p tests && cp tests/test_v27_modules.py tests/

# Update requirements
echo "📋 Updating requirements..."
cat requirements_v27.txt >> requirements.txt 2>/dev/null || cp requirements_v27.txt .

# Update version in index.html
echo "🔄 Updating version strings..."
python3 apply_v27_version.py

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "  1. pip install -r requirements_v27.txt"
echo "  2. pytest tests/test_v27_modules.py -v"
echo "  3. Review index.html changes"
echo "  4. git add . && git commit -m 'Upgrade to v27.0 Enterprise'"
echo "  5. git push"
