# Claude Code Assistant Guide - CoreFlow360 V4

**Purpose**: Complete guide for AI assistants to understand and help with this project
**Last Updated**: October 24, 2025
**System Status**: ✅ Production Ready
**Recovery**: COMPLETE

---

## 🎯 Quick Context for AI Assistants

### What This Project Is
CoreFlow360 V4 is an **AI-first entrepreneurial scaling platform** for managing multiple businesses. The frontend is React + TypeScript + Vite, deployed on Cloudflare Pages. The backend is Cloudflare Workers with D1 database.

### Current System State
- ✅ **Production**: LIVE at https://8eb14753.coreflow360-frontend.pages.dev/
- ✅ **Recovery**: COMPLETE (just finished comprehensive recovery on Oct 24, 2025)
- ✅ **Safeguards**: 6/6 active and tested
- ✅ **Documentation**: 11 comprehensive files + 4 automation scripts
- ✅ **Code Quality**: 0 circular dependencies, 0 TypeScript errors
- ✅ **Git**: 13 commits pushed to master, synced with remote

### What Just Happened (Recovery Summary)
The system had a production-breaking circular dependency. We completed a 3-4 hour recovery that:
1. Fixed the circular dependency (MigrationDashboard ↔ MigrationList)
2. Implemented 6 comprehensive safeguards to prevent recurrence
3. Optimized pre-commit hook from 60+s to 3-5s (20x faster)
4. Removed Google Fonts for ~1000ms FCP improvement
5. Created 11 documentation files
6. Created 4 automation scripts (deployment + health checks)
7. Verified all systems operational

---

## 📁 Essential File Locations

### User Should Read First
1. **README_RECOVERY.md** - Master recovery documentation
2. **DEVELOPER_REFERENCE.md** - Quick command reference
3. **QUICK_START.md** - Quick start guide

### Documentation Structure
```
Root Directory:
├── README_RECOVERY.md              # Master recovery doc - START HERE
├── CHANGELOG.md                    # Change history (Keep a Changelog format)
├── QUICK_START.md                  # Quick reference
├── DEVELOPER_REFERENCE.md          # Developer commands
├── SESSION_COMPLETE.md             # Full session summary
├── INTEGRATION_TEST.md             # Integration test results
├── DEPLOYMENT_VERIFICATION.md      # Deployment status
├── MONITORING_CHECKLIST.md         # Daily/weekly/monthly tasks
├── MAINTENANCE_GUIDE.md            # Maintenance procedures
├── PHASE2_ASSESSMENT.md            # Lost commits analysis
├── RECOVERY_PLAN.md                # Recovery tracking
└── frontend/ARCHITECTURE.md        # CRITICAL - Dependency flow rules

Scripts Directory:
└── scripts/
    ├── README.md                   # Scripts guide
    ├── deploy-pages.sh             # Bash deployment
    ├── deploy-pages.ps1            # PowerShell deployment
    ├── health-check.sh             # Bash health check
    └── health-check.ps1            # PowerShell health check
```

---

## 🛡️ THE 6 SAFEGUARDS (CRITICAL TO UNDERSTAND)

### 1. Circular Dependency Detection
**What**: Prevents import cycles that break production builds
**Tool**: madge v7.0.0
**Command**: `cd frontend && npm run check:circular`
**Expected Result**: "No circular dependency found!" (220 files scanned)
**Integration**: Pre-commit hook + CI/CD

**How It Works**:
- Scans all TypeScript/TSX files in frontend/src/
- Detects circular import chains
- Blocks commits if found (via pre-commit hook)
- Runs on every CI/CD pipeline run

**If User Reports Circular Dependency**:
1. Ask them to run: `cd frontend && npm run check:circular`
2. Identify the circular dependency from output
3. Solution: Extract shared types to a new file
4. See frontend/ARCHITECTURE.md for examples

### 2. Pre-commit Hook (Optimized)
**What**: Runs checks before every commit
**Location**: `.husky/pre-commit`
**Runtime**: 3-5 seconds (optimized from 60+ seconds)
**Checks**:
- Large files (>5MB blocked)
- Security issues (.env, secrets, node_modules)
- Build artifacts
- Circular dependencies

**How It Works**:
- Uses Husky + lint-staged
- Checks ONLY staged files (not entire directory)
- Runs circular dependency check on commit
- Exits with error if any check fails

**If User Reports Slow Pre-commit**:
1. Check runtime: `time git commit --allow-empty -m "test"`
2. Should be 3-5s, if >10s there's an issue
3. Verify it checks only staged files, not entire directory
4. See .husky/pre-commit file

### 3. ESLint Import Restrictions
**What**: Enforces one-way dependency flow
**Location**: `frontend/eslint.config.js`
**Rules**: Prevents:
- stores importing from hooks
- stores importing from components
- hooks importing from components

**How It Works**:
```javascript
'import/no-restricted-paths': ['error', {
  zones: [
    { target: './src/stores', from: './src/hooks' },
    { target: './src/stores', from: './src/components' },
    { target: './src/hooks', from: './src/components' }
  ]
}]
```

**Dependency Flow**:
```
core/ → No dependencies
  ↓
stores/ → Depends only on core
  ↓
hooks/ → Depends on core, stores
  ↓
components/ → Can use everything
```

**If User Gets Import Error**:
1. Check if they're violating dependency flow
2. Reference frontend/ARCHITECTURE.md
3. Solution: Restructure imports or extract to correct layer

### 4. Architecture Documentation
**What**: Complete dependency flow rules and examples
**Location**: `frontend/ARCHITECTURE.md`
**Contains**:
- Dependency flow diagram
- Import rules
- Good vs bad examples
- Testing procedures

**When User Asks About Imports**:
- Always reference this file
- Show them the dependency flow
- Provide examples from the doc

### 5. Safety Scripts
**What**: Helper scripts for safe development
**Commands**:
```bash
npm run check:circular          # Check for circular deps
npm run check:circular:strict   # CI/CD mode (exits with error)
npm run build:safe              # Build with circular check first
```

**When User Wants to Build**:
- Recommend `npm run build:safe` instead of `npm run build`
- This checks circular deps before building

### 6. CI/CD Integration
**What**: GitHub Actions workflow that runs all checks
**Location**: `.github/workflows/ci.yml`
**Runs On**: Push to main/develop, pull requests
**Checks**:
- ESLint
- TypeScript type checking
- Circular dependency detection (line 36-39)
- Formatting check
- Security scan

**If User Asks About CI/CD**:
- Point to .github/workflows/ci.yml
- Explain it runs same checks as pre-commit hook
- Blocks merges if checks fail

---

## 🚀 Common User Requests & How to Help

### Request: "Help me add a new component"

**Steps**:
1. **Ask where the component should go**:
   - `frontend/src/components/[category]/ComponentName.tsx`

2. **Check dependency rules**:
   - Components can import from: stores, hooks, core
   - Components CANNOT be imported by: stores, hooks

3. **Create the component**:
   ```typescript
   // Good imports for components
   import { useAuthStore } from '@/stores'
   import { useCustomHook } from '@/hooks'
   ```

4. **Verify no circular dependencies**:
   ```bash
   cd frontend && npm run check:circular
   ```

5. **Commit** (pre-commit hook will verify):
   ```bash
   git add .
   git commit -m "feat: Add ComponentName component"
   ```

### Request: "Build is failing"

**Diagnostic Steps**:
1. **Check TypeScript**:
   ```bash
   cd frontend && npm run typecheck
   ```

2. **Check circular dependencies**:
   ```bash
   cd frontend && npm run check:circular
   ```

3. **Check ESLint**:
   ```bash
   cd frontend && npm run lint
   ```

4. **Try clean build**:
   ```bash
   cd frontend
   rm -rf node_modules dist
   npm ci
   npm run build
   ```

5. **Check recent changes**:
   ```bash
   git log --oneline -5
   git diff HEAD~1
   ```

### Request: "Getting circular dependency error"

**Solution Steps**:
1. **Identify the dependency**:
   ```bash
   cd frontend && npm run check:circular
   ```

2. **Understand the pattern**:
   - Usually File A imports File B, File B imports File A

3. **Fix by extracting shared types**:
   ```typescript
   // Before: FileA.tsx ↔ FileB.tsx (circular)

   // Create shared-types.ts
   export interface SharedType { id: string; name: string }

   // FileA.tsx
   import type { SharedType } from './shared-types'

   // FileB.tsx
   import type { SharedType } from './shared-types'
   ```

4. **Verify fix**:
   ```bash
   cd frontend && npm run check:circular
   # Should show: No circular dependency found!
   ```

5. **See frontend/ARCHITECTURE.md** for detailed examples

### Request: "How do I deploy?"

**Automated Deployment**:
```bash
# Using provided script (recommended)
./scripts/deploy-pages.sh          # Bash
.\scripts\deploy-pages.ps1         # PowerShell
```

**Script does**:
1. Checks circular dependencies
2. Validates TypeScript
3. Checks git status
4. Builds production bundle
5. Deploys to Cloudflare Pages
6. Verifies deployment

**Requirements**:
- `CLOUDFLARE_API_TOKEN` environment variable set

**Manual Deployment**:
```bash
# 1. Run pre-checks
cd frontend
npm run check:circular
npm run typecheck

# 2. Build
npm run build

# 3. Deploy
wrangler pages deploy dist --project-name=coreflow360-frontend
```

### Request: "Run health check"

**Using Script**:
```bash
./scripts/health-check.sh          # Bash
.\scripts\health-check.ps1         # PowerShell
```

**What it checks**:
- ✅ Production URL (HTTP 200)
- ✅ Circular dependencies (0 expected)
- ✅ TypeScript compilation (0 errors)
- ✅ Production build (should pass)
- ⚠️ NPM audit (security)
- ⚠️ Git status (clean expected)

**Manual Health Check**:
```bash
# Production
curl -I https://8eb14753.coreflow360-frontend.pages.dev/

# Code quality
cd frontend
npm run check:circular
npm run typecheck
npm run build

# Security
npm audit
```

### Request: "How do I update dependencies?"

**Safe Update Process**:
```bash
# 1. Check what's outdated
npm outdated
cd frontend && npm outdated

# 2. Update minor/patch (safer)
npm update
cd frontend && npm update

# 3. Verify after update
cd frontend
npm run check:circular
npm run typecheck
npm run build:safe

# 4. Run tests if available
npm test

# 5. Commit if all checks pass
git add .
git commit -m "chore: Update dependencies"
```

**For Major Updates** (one at a time):
```bash
# Update individually
npm install package@latest

# Test thoroughly after each
npm run check:circular
npm run typecheck
npm run build:safe

# Commit after each successful update
```

**See MAINTENANCE_GUIDE.md** for detailed procedures

---

## 🔧 Important Commands Reference

### Development
```bash
cd frontend

npm run dev                    # Start dev server (port 3000)
npm run build                  # Production build
npm run build:safe             # Safe build (with circular check)
npm run preview                # Preview production build
```

### Code Quality
```bash
cd frontend

npm run lint                   # Run ESLint
npm run lint:fix               # Auto-fix ESLint issues
npm run typecheck              # TypeScript type checking
npm run format                 # Format with Prettier
npm run format:check           # Check formatting
```

### Circular Dependency Checks
```bash
cd frontend

npm run check:circular         # Check for circular deps
npm run check:circular:strict  # Strict mode (CI/CD)
```

### Testing
```bash
cd frontend

npm run test                   # Run unit tests
npm run test:ui                # Run UI tests (Playwright)
npm run test:a11y              # Accessibility tests
```

### Automation Scripts
```bash
# Health check
./scripts/health-check.sh      # Bash
.\scripts\health-check.ps1     # PowerShell

# Deployment
./scripts/deploy-pages.sh      # Bash
.\scripts\deploy-pages.ps1     # PowerShell
```

---

## 📊 Performance Targets & Metrics

### Current Metrics (As of Oct 24, 2025)
- **Circular Dependencies**: 0 (target: 0)
- **Pre-commit Speed**: 3-5s (target: <10s)
- **Build Time**: 14.56s (target: <20s)
- **TypeScript Errors**: 0 (target: 0)
- **First Contentful Paint**: ~1s (target: <2s)
- **Chunk Size Limit**: 200KB (target: <200KB except vendor)

### If User Reports Performance Issues

**Slow Build (>20s)**:
1. Check for large dependencies added recently
2. Review bundle splitting config in `frontend/vite.config.ts`
3. Check for circular dependencies
4. Try clean build: `rm -rf node_modules && npm ci`

**Slow Pre-commit (>10s)**:
1. Check number of staged files
2. Verify .husky/pre-commit only checks staged files
3. Review recent hook changes

**Slow Runtime**:
1. Check Cloudflare Analytics
2. Review bundle sizes: `cd frontend && npm run build`
3. Check for new heavy dependencies
4. Verify code splitting is working

---

## 🚨 Troubleshooting Guide

### Issue: Circular Dependencies Detected

**Symptoms**:
```
npm run check:circular
✖ Found 1 circular dependency!
```

**Diagnosis**:
1. Run check to see which files
2. Review the import chain shown
3. Identify what's being shared

**Solution**:
1. Create a shared types file (e.g., `shared-types.ts`)
2. Extract shared interfaces/types to it
3. Update both files to import from shared file
4. Use `type` imports for types only:
   ```typescript
   import type { MyType } from './shared-types'
   ```

**Verify**:
```bash
cd frontend && npm run check:circular
# Should show: No circular dependency found!
```

**Example** (see frontend/ARCHITECTURE.md for full examples):
```typescript
// Before: FileA.tsx imports FileB.tsx, FileB.tsx imports FileA.tsx

// Solution: Create shared-types.ts
export interface Migration {
  id: string;
  name: string;
  status: string;
}

// FileA.tsx
import type { Migration } from './shared-types'

// FileB.tsx
import type { Migration } from './shared-types'
```

### Issue: TypeScript Errors

**Diagnosis**:
```bash
cd frontend && npm run typecheck
```

**Common Causes**:
1. Missing type definitions
2. Incorrect imports
3. Circular type dependencies
4. Any types that should be specific

**Solution**:
1. Review error messages carefully
2. Check imports are correct
3. Use `type` imports for types:
   ```typescript
   import type { MyType } from './module'
   ```
4. Fix any type mismatches

### Issue: Build Failures

**Diagnosis**:
```bash
cd frontend
npm run typecheck          # Check TypeScript
npm run check:circular     # Check circular deps
npm run lint              # Check ESLint
git log --oneline -5      # Check recent changes
```

**Solution**:
1. Fix TypeScript errors first
2. Fix circular dependencies second
3. Fix ESLint errors third
4. Try clean build:
   ```bash
   rm -rf node_modules dist
   npm ci
   npm run build
   ```

### Issue: Pre-commit Hook Failing

**Common Causes**:
1. Large files staged (>5MB)
2. .env files staged
3. node_modules staged
4. Circular dependencies detected

**Diagnosis**:
```bash
git status                    # See what's staged
cat .husky/pre-commit        # Check hook
```

**Solution**:
1. Unstage problematic files
2. Fix circular dependencies
3. Ensure no .env or secrets staged
4. Re-commit

**Never bypass unless absolutely necessary**:
```bash
git commit --no-verify        # NOT RECOMMENDED
```

### Issue: Import Errors from ESLint

**Error Example**:
```
Stores cannot import from hooks - creates circular dependency risk
```

**Cause**: Violating dependency flow rules

**Solution**:
1. Check frontend/ARCHITECTURE.md for rules
2. Understand dependency flow:
   ```
   core/ → stores/ → hooks/ → components/
   ```
3. Move import to correct layer
4. Or extract to a lower layer (e.g., core/)

**Allowed Imports**:
- ✅ Components can import: stores, hooks, core
- ✅ Hooks can import: stores, core
- ✅ Stores can import: core only
- ❌ Stores CANNOT import: hooks, components
- ❌ Hooks CANNOT import: components

---

## 📚 Documentation Quick Reference

### For Different User Needs

**User Wants to Get Started**:
→ README_RECOVERY.md (master doc)
→ QUICK_START.md (quick reference)

**User Wants Daily Commands**:
→ DEVELOPER_REFERENCE.md (command reference card)

**User Asks About Architecture/Imports**:
→ frontend/ARCHITECTURE.md (CRITICAL - dependency rules)

**User Wants to Deploy**:
→ DEPLOYMENT_VERIFICATION.md (deployment guide)
→ scripts/README.md (automation scripts)

**User Wants to Monitor**:
→ MONITORING_CHECKLIST.md (daily/weekly/monthly tasks)

**User Wants to Maintain**:
→ MAINTENANCE_GUIDE.md (maintenance procedures)

**User Asks What Changed**:
→ CHANGELOG.md (change history)

**User Asks About Recovery**:
→ SESSION_COMPLETE.md (full session summary)

---

## 🎯 Step-by-Step Assistance Patterns

### Pattern 1: User Wants to Add Feature

**Steps**:
1. **Understand the feature**
   - Ask clarifying questions
   - Identify which components/files affected

2. **Check architecture implications**
   - Will it need new stores? → Create in `frontend/src/stores/`
   - Will it need new hooks? → Create in `frontend/src/hooks/`
   - Will it need new components? → Create in `frontend/src/components/`

3. **Verify dependency flow compliance**
   - Check imports follow core → stores → hooks → components
   - Ensure no circular dependencies introduced

4. **Implementation**
   - Create files with proper imports
   - Follow TypeScript best practices
   - Use type imports for types

5. **Verification**
   ```bash
   cd frontend
   npm run check:circular      # Must pass
   npm run typecheck          # Must pass
   npm run build:safe         # Must pass
   ```

6. **Commit**
   ```bash
   git add .
   git commit -m "feat: Add [feature name]"
   # Pre-commit hook will verify
   ```

### Pattern 2: User Reports Error

**Steps**:
1. **Gather Information**
   - What error message?
   - What were they doing?
   - Recent changes?

2. **Run Diagnostics**
   ```bash
   cd frontend
   npm run typecheck          # Check TypeScript
   npm run check:circular     # Check circular deps
   npm run lint              # Check ESLint
   git log --oneline -5      # Check recent commits
   ```

3. **Identify Root Cause**
   - TypeScript error? → Fix types
   - Circular dependency? → Extract shared types
   - Import restriction? → Fix dependency flow
   - Build error? → Check configuration

4. **Provide Solution**
   - Give specific fix with code examples
   - Reference relevant documentation
   - Verify solution will work

5. **Verify Fix**
   ```bash
   npm run check:circular
   npm run typecheck
   npm run build:safe
   ```

### Pattern 3: User Wants to Understand System

**Steps**:
1. **Start with overview**
   - Direct to README_RECOVERY.md
   - Explain recovery was just completed
   - All safeguards are active

2. **Explain current state**
   - Production is live and stable
   - 0 circular dependencies
   - All documentation is current
   - All scripts are ready to use

3. **Provide relevant docs**
   - For commands: DEVELOPER_REFERENCE.md
   - For architecture: frontend/ARCHITECTURE.md
   - For monitoring: MONITORING_CHECKLIST.md
   - For maintenance: MAINTENANCE_GUIDE.md

4. **Offer to help with specific tasks**

---

## 🔐 Security Considerations

### What User Should NEVER Commit
- ❌ `.env` files
- ❌ API keys or secrets
- ❌ `node_modules/`
- ❌ `.env.local`, `.env.production`
- ❌ Private keys
- ❌ Database credentials

### Pre-commit Hook Checks For
The pre-commit hook automatically blocks these, but remind user anyway.

### If User Accidentally Commits Secret
```bash
# Remove from history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch .env" \
  --prune-empty --tag-name-filter cat -- --all

# Force push (DANGEROUS - warn user)
git push origin --force --all
```

**Better**: Use environment variables and never commit secrets.

---

## 📈 Monitoring & Maintenance

### Daily Tasks (User Should Do)
```bash
# Quick health check
./scripts/health-check.sh

# Or manual
curl -I https://8eb14753.coreflow360-frontend.pages.dev/
cd frontend && npm run check:circular
```

### Weekly Tasks
```bash
# Update dependencies
npm update
cd frontend && npm update

# Run checks
cd frontend
npm run check:circular
npm run typecheck
npm run build:safe

# Security audit
npm audit
cd frontend && npm audit
```

### Monthly Tasks
- Full dependency audit
- Review documentation for accuracy
- Check bundle sizes
- Review performance metrics

**See MONITORING_CHECKLIST.md** for complete schedule.

---

## 🎓 Teaching the User

### When User Violates Best Practices

**Don't just fix - teach**:
1. Explain what they did wrong
2. Show why it matters (e.g., circular deps break builds)
3. Show correct way with example
4. Reference documentation
5. Verify they understand

**Example**:
```
User: "I'm getting an import error from ESLint"

Bad Response: "Change this import"

Good Response: "You're importing a hook into a store, which violates
the dependency flow rules. This creates a risk of circular dependencies.

The dependency flow is: core → stores → hooks → components

Stores can only import from core, not from hooks.

Solution: Either:
1. Move the shared code to core/ layer
2. Or restructure so the hook imports from the store instead

See frontend/ARCHITECTURE.md for detailed examples and rules."
```

---

## 🚀 Advanced Topics

### Architecture Deep Dive

**Why These Rules**:
- Prevents circular dependencies (which break production)
- Creates clear separation of concerns
- Makes codebase easier to understand and maintain
- Enforces single direction of data flow

**Layers Explained**:
```
core/        → Utilities, types, constants (no dependencies)
stores/      → State management (Zustand stores)
hooks/       → Custom React hooks (can use stores)
components/  → UI components (can use everything)
```

**Import Flow**:
```
components  →  hooks  →  stores  →  core
             ↑          ↑          ↑
         Can import  Can import  Can import
```

### Performance Optimization

**Bundle Splitting Strategy** (frontend/vite.config.ts):
- React vendor chunk: ~336KB (core React libs)
- Vendor misc: ~200KB (other deps)
- Feature chunks: <60KB each (code split by feature)

**Why 200KB Chunk Limit**:
- Optimal for HTTP/2
- Better browser caching
- Faster parallel downloads

**System Fonts vs Web Fonts**:
- Before: 2 Google Font requests (blocking)
- After: 0 requests (system fonts instant)
- Impact: ~1000ms FCP improvement

---

## 📞 Emergency Procedures

### Production Down

**Steps**:
1. **Verify**:
   ```bash
   curl -I https://8eb14753.coreflow360-frontend.pages.dev/
   ```

2. **Check Cloudflare Status**:
   - Visit Cloudflare Dashboard

3. **Check Recent Deployments**:
   ```bash
   git log --oneline -5
   ```

4. **Rollback if needed**:
   ```bash
   git revert HEAD
   git push origin master
   # Or deploy previous commit
   ```

5. **Verify fix**:
   ```bash
   curl -I https://8eb14753.coreflow360-frontend.pages.dev/
   ```

### Critical Build Failure

**Steps**:
1. **Check all diagnostics**:
   ```bash
   cd frontend
   npm run typecheck
   npm run check:circular
   npm run lint
   ```

2. **Review recent changes**:
   ```bash
   git diff HEAD~1
   git log --oneline -5
   ```

3. **Try clean build**:
   ```bash
   rm -rf node_modules dist
   npm ci
   npm run build
   ```

4. **If still failing, revert**:
   ```bash
   git revert HEAD
   ```

---

## ✅ Verification Checklist for AI Assistants

Before saying "done" to user, verify:

### Code Changes
- [ ] No circular dependencies: `npm run check:circular`
- [ ] TypeScript passes: `npm run typecheck`
- [ ] Build succeeds: `npm run build`
- [ ] Follows architecture rules (check frontend/ARCHITECTURE.md)

### Git
- [ ] Changes committed with clear message
- [ ] Pre-commit hook passed
- [ ] No secrets in commit

### Documentation
- [ ] Updated CHANGELOG.md if significant change
- [ ] User knows where to find relevant docs
- [ ] Explained why, not just what

### User Understanding
- [ ] User understands what was done
- [ ] User knows how to verify it works
- [ ] User can maintain it going forward

---

## 🎯 Success Metrics for AI Assistance

### Good Assistance Looks Like:
- ✅ User problem solved
- ✅ No circular dependencies introduced
- ✅ All checks passing
- ✅ User understands the solution
- ✅ User can maintain the code
- ✅ Referenced relevant documentation
- ✅ Followed architecture rules

### Bad Assistance Looks Like:
- ❌ Fixed issue but introduced circular dependency
- ❌ Violated architecture rules
- ❌ Just provided code without explanation
- ❌ Didn't verify solution works
- ❌ User doesn't understand what was done
- ❌ Didn't reference documentation

---

## 📋 Quick Reference Card

### Most Important Files
1. **frontend/ARCHITECTURE.md** - Dependency rules (CRITICAL)
2. **README_RECOVERY.md** - Master doc
3. **DEVELOPER_REFERENCE.md** - Commands
4. **MONITORING_CHECKLIST.md** - Daily tasks

### Most Important Commands
```bash
cd frontend && npm run check:circular    # Check circular deps
cd frontend && npm run typecheck         # Check TypeScript
cd frontend && npm run build:safe        # Safe build
./scripts/health-check.sh               # Health check
```

### Most Important Rules
1. NO circular dependencies (check every time)
2. Follow dependency flow (core → stores → hooks → components)
3. Use type imports for types: `import type { X } from 'y'`
4. Run checks before committing
5. Reference documentation

### Most Common User Issues
1. Circular dependencies → Extract shared types
2. Import restrictions → Check dependency flow
3. Build failures → Run diagnostics (typecheck, circular, lint)
4. Slow pre-commit → Check if it's checking only staged files

---

## 🎉 Final Notes for AI Assistants

### Context You Have
- System just completed comprehensive recovery
- All safeguards are NEW and actively protecting
- Documentation is CURRENT and ACCURATE
- All 13 commits are in production
- User has complete automation scripts ready

### User's Mindset
- May be cautious after recovery
- Wants to maintain quality
- Appreciates detailed explanations
- Values automation and safeguards

### Your Goals
1. **Protect the recovery** - Don't break what was just fixed
2. **Teach, don't just fix** - Help user understand
3. **Maintain quality** - All checks must pass
4. **Reference docs** - Use the comprehensive docs
5. **Verify everything** - Check before saying done

### Remember
- This system has 6 active safeguards
- Pre-commit hook will catch many issues
- CI/CD will catch more
- But AI assistant should catch them FIRST
- Prevention > Detection > Remediation

---

**Guide Created**: October 24, 2025
**Last Updated**: October 24, 2025
**System Status**: ✅ Production Ready
**For**: AI Assistants (Claude Code)
**Version**: 1.0

**This guide contains everything an AI assistant needs to effectively help maintain and enhance CoreFlow360 V4.** 🚀
