# Production Recovery & Feature Restoration Plan

**Status**: Production RESTORED ✅
**Working Commit**: 6495a5d
**Lost Commits**: 20+ commits (ca1e58f through b39aa74)
**Root Cause**: Circular dependency in `use-entity-context.tsx`

---

## Phase 1: Safeguards (COMPLETE ✅)

### 1.1 Dependency Cycle Detection
- ✅ Installed `madge` for circular dependency detection
- ✅ Identified existing circular dependencies in working code:
  - `DataVisualizationEngine.tsx ↔ ChartRenderer.tsx`
  - `MigrationDashboard.tsx ↔ MigrationList.tsx`
- ⚠️ These are in isolated components and don't affect core initialization

### 1.2 Safety Scripts (COMPLETE ✅)
Added to `frontend/package.json`:

```json
{
  "scripts": {
    "check:circular": "madge --circular --extensions ts,tsx src/",
    "check:circular:strict": "madge --circular --extensions ts,tsx src/ && exit 1",
    "build:safe": "npm run check:circular && npm run build",
    "deploy:safe": "npm run build:safe && npm run test:prod-bundle"
  }
}
```

### 1.3 Pre-commit Hook (TODO)
Update `.husky/pre-commit`:

```bash
#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

# Existing checks
npm run lint-staged

# Add circular dependency check
cd frontend && npm run check:circular || {
  echo "❌ Circular dependencies detected!"
  echo "Fix dependencies before committing."
  exit 1
}
```

---

## Phase 2: Lost Commits Analysis

### Commit Inventory (ca1e58f → b39aa74)

**High Priority - Business Critical**:
1. `dcda338` - Landing page navigation fixes
2. `322bf9c` - React mounting timeout fix attempts
3. `d63ac39` - Inline CSS design tokens (production loading fix)

**Medium Priority - Features**:
1. `ca1e58f` - Phase 6: Massive parallel agent wave (118 errors fixed) ⚠️ CONTAINS BREAKING CHANGE
2. `d06ebe1` - Phase 7: ValidationError + service layer (150+ errors fixed)
3. `51ff917` - UX/UI critical fixes (auth flow, routing, dialog)
4. `6b7b99c` - Performance optimizations (fonts, bundle splitting)

**Low Priority - Improvements**:
1. `0312b27` - Brand colors migration (13 components)
2. `23c6c3e` - Brand colors for AIAgentInterface
3. `1aaf24d` - ESLint global declarations (3838 errors resolved)
4. `5f47523` - Wrangler production config update

**Already Fixed in Other Ways**:
1. Security commits (5647db3, 4396652, 0931aaf) - Password cleanup
2. Environment variable fixes (b7e4c86, 3582738) - May be obsolete

---

## Phase 3: Restoration Strategy

### 3.1 Fix the Root Cause FIRST

**Problem**: `use-entity-context.tsx` importing `useAuthStore` creates circular dependency

**File**: `frontend/src/hooks/use-entity-context.tsx`

**Breaking Import**:
```typescript
import { useEntityStore, useAuthStore } from '@/stores'
```

**Resolution Options**:

**Option A: Remove useAuthStore from hook (Recommended)**
```typescript
// use-entity-context.tsx
import { useEntityStore } from '@/stores'
// Remove useAuthStore - get auth state from components directly
```

**Option B: Create intermediate layer**
```typescript
// Create: src/core/auth-facade.ts
export const getAuthState = () => {
  // Access auth without importing the full store
  return window.__AUTH_STATE__
}

// use-entity-context.tsx
import { getAuthState } from '@/core/auth-facade'
```

**Option C: Dependency Injection**
```typescript
// EntityProvider accepts authStore as prop
export const EntityProvider = ({ authStore, children }) => {
  // No direct import of useAuthStore
}
```

### 3.2 Cherry-Pick Strategy

**Step 1: Critical Fixes Only**
```bash
# Start from working commit
git checkout 6495a5d

# Cherry-pick critical fixes (test each)
git cherry-pick d63ac39  # Inline CSS tokens
git cherry-pick 322bf9c  # React mounting attempts
git cherry-pick dcda338  # Landing page navigation

# Test production build after EACH cherry-pick
cd frontend && npm run build
node ../test-local-build.mjs
```

**Step 2: Agent System WITHOUT Breaking Change**
```bash
# Extract ca1e58f changes WITHOUT the useAuthStore import
git show ca1e58f > /tmp/phase6-changes.patch

# Manually apply, excluding use-entity-context.tsx changes
# Or rewrite the feature without the circular dependency
```

**Step 3: Incremental Feature Restoration**
For each remaining commit:
1. Create feature branch
2. Cherry-pick commit
3. Run: `npm run check:circular`
4. Run: `npm run build && node test-local-build.mjs`
5. If tests pass → merge
6. If tests fail → debug and fix before merging

---

## Phase 4: Architectural Improvements

### 4.1 Module Dependency Rules

**Enforce One-Way Flow**:
```
core/         (No dependencies on anything)
  ↓
stores/       (Depends on: core only)
  ↓
hooks/        (Depends on: core, stores)
  ↓
components/   (Depends on: everything)
```

**File**: `.eslintrc.js` - Add import restrictions:

```javascript
{
  "rules": {
    "import/no-restricted-paths": ["error", {
      "zones": [
        {
          "target": "./src/stores",
          "from": "./src/hooks",
          "message": "Stores cannot import from hooks"
        },
        {
          "target": "./src/stores",
          "from": "./src/components",
          "message": "Stores cannot import from components"
        },
        {
          "target": "./src/hooks",
          "from": "./src/components",
          "message": "Hooks cannot import from components"
        }
      ]
    }]
  }
}
```

### 4.2 Automated Testing

**Add to CI/CD** (`.github/workflows/ci.yml`):

```yaml
- name: Check Circular Dependencies
  run: |
    cd frontend
    npm run check:circular:strict

- name: Test Production Build
  run: |
    cd frontend
    npm run build
    cd ..
    node test-local-build.mjs
```

### 4.3 Documentation

**Create**: `frontend/ARCHITECTURE.md`

```markdown
# Frontend Architecture Rules

## Module Import Rules

### ✅ ALLOWED
- Components → hooks, stores, core
- Hooks → stores, core
- Stores → core

### ❌ FORBIDDEN
- Stores → hooks, components
- Hooks → components
- Core → anything

## Before Adding Imports

1. Check: `npm run check:circular`
2. Build: `npm run build`
3. Test: `node ../test-local-build.mjs`
4. Commit only if all pass
```

---

## Phase 5: Implementation Checklist

### Week 1: Safeguards & Foundation
- [ ] Add circular dependency check scripts to frontend/package.json
- [ ] Update pre-commit hook with circular dependency check
- [ ] Add ESLint import restrictions
- [ ] Document architecture rules in frontend/ARCHITECTURE.md
- [ ] Add CI/CD checks for circular dependencies

### Week 2: Root Cause Fix
- [ ] Analyze use-entity-context.tsx usage of useAuthStore
- [ ] Choose fix strategy (Option A/B/C)
- [ ] Implement fix
- [ ] Test in production build
- [ ] Document the fix

### Week 3: Critical Features
- [ ] Cherry-pick d63ac39 (CSS tokens)
- [ ] Cherry-pick 322bf9c (React mounting)
- [ ] Cherry-pick dcda338 (Landing navigation)
- [ ] Test each thoroughly

### Week 4: Agent System Rebuild
- [ ] Rewrite Phase 6 agent features without circular dependency
- [ ] Test extensively in production builds
- [ ] Apply Phase 7 improvements

### Week 5: Remaining Features
- [ ] Restore brand color migrations
- [ ] Restore performance optimizations
- [ ] Restore UX improvements
- [ ] Final comprehensive testing

---

## Phase 6: Monitoring & Validation

### Success Criteria
- ✅ Production site loads without errors
- ✅ No circular dependencies in critical paths
- ✅ All 20+ commits features restored
- ✅ Automated checks prevent future issues

### Ongoing Monitoring
```bash
# Daily check
npm run check:circular

# Before each deploy
npm run build:safe
node test-local-build.mjs

# Weekly architecture audit
npm run check:circular | tee reports/dependency-audit-$(date +%Y%m%d).txt
```

---

## Emergency Rollback Plan

If issues arise during restoration:

```bash
# Immediate rollback
git reset --hard 6495a5d
git push origin master --force

# Or rollback specific feature
git revert <commit-hash>
git push origin master
```

---

## Key Learnings

1. **Test Production Builds**: Dev mode hides circular dependency issues
2. **Enforce Architecture**: Use ESLint to prevent bad imports
3. **Automate Checks**: CI/CD should catch these before deployment
4. **Incremental Restoration**: Don't bulk-apply commits without testing
5. **Document Dependencies**: Architecture rules prevent future issues

---

## Current Status

✅ **Production**: Live and stable at commit 6495a5d
✅ **Safeguards**: Circular dependency detection installed and tested
⚠️ **Features**: 20+ commits need careful restoration
🔧 **Next Step**: Update pre-commit hook with circular dependency check (Phase 1.3)
📅 **Timeline**: 5 weeks for complete recovery

---

**Last Updated**: October 22, 2025
**Point of Contact**: See PRODUCTION_BREAKAGE_ANALYSIS.md for technical details
