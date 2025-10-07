#!/bin/bash
# ESLint Auto-Fix Script - Phase 1
# Fixes: unused variables, useless escapes, and other auto-fixable issues
# Expected: ~340 warnings removed

set -e  # Exit on error

echo "=================================================="
echo "🦴 GRUG'S ESLINT AUTO-FIX - PHASE 1"
echo "=================================================="
echo ""
echo "Target: Fix ~340 auto-fixable warnings"
echo "Issues: unused variables, useless escapes, formatting"
echo ""

# Store current directory
FRONTEND_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$FRONTEND_DIR"

echo "📊 Counting current warnings..."
BEFORE_COUNT=$(npm run lint 2>&1 | grep -oE "[0-9]+ problems" | grep -oE "[0-9]+" || echo "unknown")
echo "Before: $BEFORE_COUNT problems detected"
echo ""

echo "🔧 Running ESLint auto-fix..."
npm run lint:fix || {
  echo "⚠️  Some files could not be auto-fixed"
  echo "This is normal - some issues require manual fixes"
}
echo ""

echo "📊 Counting remaining warnings..."
AFTER_COUNT=$(npm run lint 2>&1 | grep -oE "[0-9]+ problems" | grep -oE "[0-9]+" || echo "0")
echo "After: $AFTER_COUNT problems remaining"
echo ""

if [ "$BEFORE_COUNT" != "unknown" ] && [ "$AFTER_COUNT" != "unknown" ]; then
  FIXED=$((BEFORE_COUNT - AFTER_COUNT))
  echo "✅ Fixed: $FIXED warnings!"
else
  echo "✅ Auto-fix complete!"
fi

echo ""
echo "🔍 Running TypeScript check..."
npm run typecheck && echo "✅ Type check passed!" || {
  echo "⚠️  Type errors found - these need manual fixes"
  echo "See ESLINT-AUDIT-AND-FIX-PLAN.md for guidance"
}

echo ""
echo "=================================================="
echo "📋 NEXT STEPS:"
echo "=================================================="
echo ""
echo "1. Review changes: git diff"
echo "2. Test the app: npm run dev"
echo "3. Commit if good: git add . && git commit -m 'fix: ESLint auto-fixes'"
echo ""
echo "4. Continue with manual fixes:"
echo "   - See ESLINT-AUDIT-AND-FIX-PLAN.md"
echo "   - Phase 2: React Refresh violations (51 files)"
echo "   - Phase 3: Type safety (342 any types)"
echo "   - Phase 4: React hooks (32 files)"
echo ""
echo "🦴 Grug say: Good start, but more work needed!"
echo "Target: 0 warnings. Current: $AFTER_COUNT"
echo ""
