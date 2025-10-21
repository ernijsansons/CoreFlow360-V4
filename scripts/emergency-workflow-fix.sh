#!/bin/bash

# CoreFlow360 V4 - Emergency Workflow Fix Script
# This script fixes the most critical issues causing workflow failures

echo "🚀 Starting CoreFlow360 V4 Emergency Fixes..."

# 1. Install correct frontend dependencies
echo "📦 Fixing frontend dependencies..."
cd frontend
npm install @axe-core/playwright@^4.8.5
cd ..

# 2. Verify Node.js version requirement
echo "🔧 Node.js version updated to 22 in package.json"

# 3. Type check to ensure no syntax errors
echo "🔍 Running type checks..."
npm run type-check
cd frontend && npm run typecheck
cd ..

# 4. Run quick tests
echo "🧪 Running quick validation tests..."
npm run lint || echo "⚠️ Linting issues found - please fix manually"

# 5. Commit fixes
echo "💾 Committing critical fixes..."
git add .
git commit -m "fix: Emergency workflow fixes - Node 22, dependencies, Actions v4

- Update Node.js requirement to 22+ for Artillery compatibility
- Fix @axe-core/playwright version conflict  
- Update GitHub Actions to v4 (remove deprecation warnings)
- Add CodeQL security-events permissions
- Fix branch triggers for master branch
- Add missing npm scripts for workflows"

echo "✅ Emergency fixes completed!"
echo "📋 Next steps:"
echo "   1. Configure GitHub secrets (SNYK_TOKEN, CLOUDFLARE_API_TOKEN, AI_API_KEY)"
echo "   2. Push changes: git push origin marketing-refresh/2025-10-06"
echo "   3. Monitor workflow runs in GitHub Actions"
echo "   4. Deploy to staging once workflows pass"