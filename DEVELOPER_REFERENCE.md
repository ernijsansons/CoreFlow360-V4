# Developer Quick Reference Card

**Last Updated**: October 24, 2025
**Status**: ✅ Production Ready

---

## 🚀 Quick Commands

### Development
```bash
cd frontend
npm run dev              # Start dev server (http://localhost:3000)
npm run build            # Production build
npm run build:safe       # Build with circular dependency check
npm run preview          # Preview production build
```

### Code Quality
```bash
npm run lint             # Run ESLint
npm run lint:fix         # Auto-fix ESLint issues
npm run typecheck        # TypeScript type checking
npm run format           # Format code with Prettier
npm run format:check     # Check formatting
```

### Circular Dependency Checks
```bash
npm run check:circular          # Check for circular deps
npm run check:circular:strict   # Strict mode (exits with error)
```

### Testing
```bash
npm run test             # Run unit tests (Vitest)
npm run test:ui          # Run UI tests (Playwright)
npm run test:a11y        # Accessibility tests
```

---

## 📁 Project Structure

```
CoreFlow360-V4/
├── frontend/                    # React application
│   ├── src/
│   │   ├── components/         # UI components
│   │   ├── stores/            # Zustand state management
│   │   ├── hooks/             # Custom React hooks
│   │   ├── routes/            # TanStack Router routes
│   │   ├── lib/               # Utilities
│   │   └── styles/            # Global styles
│   ├── ARCHITECTURE.md        # Dependency flow rules
│   └── package.json
├── src/                        # Backend (Cloudflare Workers)
│   ├── modules/
│   │   ├── auth/
│   │   ├── agents/
│   │   └── ...
│   └── index.production.ts
└── database/                   # D1 migrations
```

---

## 🛡️ Safeguards (Auto-Protected)

### Pre-commit Hook (Automatic)
Every commit automatically checks:
- ✓ Large files (>5MB blocked)
- ✓ Security issues (.env, secrets)
- ✓ Circular dependencies
- ✓ ESLint + Prettier

**Performance**: 3-5 seconds per commit

### Import Rules (ESLint Enforced)
```typescript
// ✅ GOOD
import { useAuthStore } from '@/stores'  // Components can import stores

// ❌ BAD - Will fail ESLint
// stores/authStore.ts
import { useUserData } from '@/hooks'    // Stores cannot import hooks
```

### Dependency Flow
```
core/ → No dependencies
  ↓
stores/ → Depends only on core
  ↓
hooks/ → Depends on core, stores
  ↓
components/ → Can use everything
```

---

## 🔧 Common Tasks

### Adding a New Component
```bash
# 1. Create component file
touch frontend/src/components/MyComponent.tsx

# 2. Follow dependency rules (see ARCHITECTURE.md)
# 3. Import only from allowed layers
# 4. Commit (pre-commit hook will verify)
git add .
git commit -m "feat: Add MyComponent"
```

### Fixing Circular Dependencies
```bash
# 1. Check for circular deps
cd frontend
npm run check:circular

# 2. If found, extract shared types/interfaces
# Create: src/components/shared-types.ts
# Move shared interfaces there

# 3. Update imports in both files
# 4. Verify fix
npm run check:circular  # Should show 0 circular deps
```

### Running Production Build
```bash
# Safe build (recommended)
cd frontend
npm run build:safe       # Checks circular deps first

# Standard build
npm run build            # Direct build

# Test build locally
npm run preview          # Starts preview server
```

---

## 🚨 Troubleshooting

### Build Fails
```bash
# Check TypeScript errors
npm run typecheck

# Check for circular dependencies
npm run check:circular

# Clean and rebuild
rm -rf node_modules dist
npm ci
npm run build
```

### Pre-commit Hook Slow
```bash
# Current hook is optimized (~3-5s)
# If slower, check:
cat .husky/pre-commit

# Should check only staged files, not entire directory
```

### Import Errors
```bash
# Check ESLint rules
cat frontend/eslint.config.js

# Verify import paths follow dependency flow
# See frontend/ARCHITECTURE.md for rules
```

---

## 📊 Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Build Time | <20s | 14.56s ✅ |
| Pre-commit | <10s | 3-5s ✅ |
| Circular Deps | 0 | 0 ✅ |
| TypeScript Errors | 0 | 0 ✅ |
| First Contentful Paint | <2s | ~1s ✅ |

---

## 🔗 Important Files

### Must Read
- `QUICK_START.md` - Getting started guide
- `frontend/ARCHITECTURE.md` - Dependency rules (CRITICAL)
- `SESSION_COMPLETE.md` - Recovery summary
- `DEPLOYMENT_VERIFICATION.md` - Current deployment status

### Reference
- `PHASE2_ASSESSMENT.md` - Lost commits analysis
- `INTEGRATION_TEST.md` - Integration test results
- `.github/workflows/ci.yml` - CI/CD configuration

---

## ⚡ Pro Tips

### 1. Use Safe Build Before Deployment
```bash
npm run build:safe  # Always use this for production
```

### 2. Check Dependencies Before Importing
```bash
# Before adding import in stores/*, check if it's allowed
# Stores can only import from core/, not hooks/ or components/
```

### 3. Pre-commit Hook is Your Friend
```bash
# Let the hook catch issues before you push
# Don't use --no-verify unless absolutely necessary
git commit -m "message"  # Let hook run
```

### 4. Monitor Bundle Size
```bash
# Build outputs chunk sizes
npm run build

# Watch for warnings about >200KB chunks
# Consider code splitting if needed
```

---

## 🎯 Key Metrics to Watch

### During Development
- TypeScript errors: Should always be 0
- Circular dependencies: Should always be 0
- Build time: Should stay around 14-15s
- Pre-commit time: Should be 3-5s

### In Production
- HTTP 200 status on https://8eb14753.coreflow360-frontend.pages.dev/
- Cloudflare Analytics for performance
- Error rate in Sentry (if configured)

---

## 📞 Quick Links

- **Production**: https://8eb14753.coreflow360-frontend.pages.dev/
- **GitHub**: https://github.com/ernijsansons/CoreFlow360-V4.git
- **Branch**: master

---

## 🆘 Emergency Contacts

**Production Issues**:
1. Check deployment status: `curl -I https://8eb14753.coreflow360-frontend.pages.dev/`
2. Check latest commit: `git log -1`
3. Review DEPLOYMENT_VERIFICATION.md

**Build Issues**:
1. Check QUICK_START.md for verification steps
2. Run `npm run build:safe` to see errors
3. Check ARCHITECTURE.md for import rules

---

**Developer Reference Card**
**Version**: 1.0
**Last Updated**: October 24, 2025
**System Status**: ✅ OPERATIONAL
