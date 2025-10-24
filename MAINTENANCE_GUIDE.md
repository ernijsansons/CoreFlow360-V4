# Maintenance Guide

**System**: CoreFlow360 V4
**Recovery Date**: October 24, 2025
**Status**: ✅ Production Ready
**Maintainers**: Development Team

---

## 🎯 Maintenance Philosophy

The system is protected by **6 active safeguards** that automatically prevent regressions. Your job is to:
1. Monitor system health (see MONITORING_CHECKLIST.md)
2. Keep dependencies updated
3. Address technical debt systematically
4. Maintain documentation

---

## 🔧 Regular Maintenance Tasks

### Daily Tasks (Automated)

These run automatically on every commit via pre-commit hook:
- ✅ **Circular Dependency Check** (3-5s)
- ✅ **Large File Detection** (>5MB blocked)
- ✅ **Security Scan** (.env, secrets, node_modules)
- ✅ **ESLint + Prettier** (auto-fix on commit)

**You don't need to run these manually!**

### Weekly Tasks (15 minutes)

#### 1. Security Updates
```bash
# Check for vulnerabilities
npm audit
cd frontend && npm audit

# Update dependencies (if needed)
npm update
cd frontend && npm update

# Re-run checks
npm run check:circular
npm run typecheck
npm run build:safe
```

#### 2. Code Quality Review
```bash
# Check TypeScript
cd frontend && npm run typecheck

# Review lint warnings
cd frontend && npm run lint 2>&1 | grep "error"

# Check build health
cd frontend && npm run build
```

#### 3. Documentation Update
- [ ] Review CHANGELOG.md - Add any changes
- [ ] Update version numbers if releasing
- [ ] Review README_RECOVERY.md - Ensure accuracy

### Monthly Tasks (30 minutes)

#### 1. Dependency Audit
```bash
# Check outdated packages
npm outdated
cd frontend && npm outdated

# Review major version updates
npm outdated | grep -v "^Package"

# Update dependencies systematically
# Test after each update!
```

#### 2. Performance Review
```bash
# Build and check sizes
cd frontend && npm run build

# Review bundle sizes
ls -lh frontend/dist/assets/

# Compare with previous month
# Document any increases > 10%
```

#### 3. Security Review
- [ ] Review npm audit results
- [ ] Check GitHub security advisories
- [ ] Update Cloudflare API tokens (rotate)
- [ ] Review access logs for anomalies

---

## 🛡️ Safeguard Maintenance

### 1. Circular Dependency Detection

**Status Check**:
```bash
cd frontend && npm run check:circular
```

**Expected**: "No circular dependency found!" with ~220 files scanned

**If Issues Found**:
1. Review recent file changes: `git log --oneline -10`
2. Check ARCHITECTURE.md for dependency rules
3. Extract shared types/interfaces if needed
4. Re-run check after fixing

**Maintenance**:
- **Monthly**: Verify madge is up to date
- **Quarterly**: Review exemptions (if any)

### 2. Pre-commit Hook

**Status Check**:
```bash
cat .husky/pre-commit
# Test performance
time git commit --allow-empty -m "test"
```

**Expected**: 3-5 second runtime, all checks passing

**If Slow (>10s)**:
1. Check number of staged files
2. Verify it's not scanning entire directory
3. Review recent hook changes
4. Ensure it only checks staged files

**Maintenance**:
- **Monthly**: Verify hook is running
- **Quarterly**: Review hook performance
- **Annually**: Update to latest Husky version

### 3. ESLint Import Restrictions

**Status Check**:
```bash
cat frontend/eslint.config.js | grep "import/no-restricted-paths"
```

**Expected**: Rules preventing:
- stores ← hooks
- stores ← components
- hooks ← components

**Maintenance**:
- **Monthly**: Verify rules are enforced
- **Quarterly**: Review for new patterns
- **Annually**: Update ESLint and plugins

### 4. Architecture Documentation

**Status Check**:
```bash
cat frontend/ARCHITECTURE.md
```

**Maintenance**:
- **Monthly**: Review for accuracy
- **Quarterly**: Add new examples if needed
- **Annually**: Full review and update

### 5. CI/CD Integration

**Status Check**:
```bash
cat .github/workflows/ci.yml | grep "circular"
```

**Expected**: Circular dependency check on line 36-39

**Maintenance**:
- **Monthly**: Verify CI/CD is passing
- **Quarterly**: Review workflow efficiency
- **Annually**: Update GitHub Actions versions

### 6. Safety Scripts

**Status Check**:
```bash
cd frontend
npm run check:circular
npm run check:circular:strict
npm run build:safe
```

**Maintenance**:
- **Weekly**: Test one script
- **Monthly**: Test all scripts
- **Quarterly**: Review script logic

---

## 📦 Dependency Management

### Update Strategy

#### Minor/Patch Updates (Low Risk)
```bash
# Safe to do weekly
npm update
cd frontend && npm update

# Always verify after
npm run check:circular
npm run typecheck
npm run build:safe
```

#### Major Updates (Higher Risk)
```bash
# Do one at a time
npm outdated | grep "MAJOR"

# Update individually
npm install package@latest

# Test thoroughly
npm run test
npm run build:safe
npm run check:circular
```

### Critical Dependencies

These require extra care when updating:

#### Build Tools
- **vite**: Test build thoroughly
- **typescript**: May break type checking
- **eslint**: May change lint rules

#### Framework
- **react**: May break components
- **@tanstack/router**: May affect routing

#### State Management
- **zustand**: May affect stores
- **immer**: May affect state updates

### Update Checklist
- [ ] Run `npm outdated` to see available updates
- [ ] Review changelogs for breaking changes
- [ ] Update one package at a time
- [ ] Run full test suite after each update
- [ ] Test circular dependency check
- [ ] Test TypeScript compilation
- [ ] Test production build
- [ ] Commit after each successful update

---

## 🐛 Troubleshooting Common Issues

### Issue: Circular Dependencies Detected

**Symptoms**:
```
npm run check:circular
✖ Found 1 circular dependency!
```

**Fix**:
1. Identify the circular dependency
2. Extract shared types/interfaces to a new file
3. Update imports in both files
4. Verify fix: `npm run check:circular`

**Example**:
```typescript
// Before: FileA.tsx ↔ FileB.tsx (circular)

// After: Create shared-types.ts
export interface SharedType { ... }

// FileA.tsx
import type { SharedType } from './shared-types'

// FileB.tsx
import type { SharedType } from './shared-types'
```

### Issue: Pre-commit Hook Slow

**Symptoms**: Hook takes > 10 seconds

**Fix**:
1. Check if it's scanning entire directory (should only check staged files)
2. Review `.husky/pre-commit` file
3. Ensure it uses `git diff --cached --name-only`
4. Not `find . -type f`

### Issue: Build Failures

**Symptoms**:
```
npm run build
Error: Build failed
```

**Fix**:
1. Check TypeScript errors: `npm run typecheck`
2. Check circular dependencies: `npm run check:circular`
3. Check ESLint: `npm run lint`
4. Review recent changes: `git log --oneline -5`
5. Try clean build:
```bash
rm -rf node_modules dist
npm ci
npm run build
```

### Issue: TypeScript Errors

**Symptoms**:
```
npm run typecheck
error TS2xxx: ...
```

**Fix**:
1. Review error messages carefully
2. Check recent type changes
3. Verify imports are correct
4. Check for circular type dependencies
5. Consider using `type` imports for types:
```typescript
import type { MyType } from './module'
```

---

## 📊 Performance Maintenance

### Build Performance

**Target**: 14-16 seconds

**Monitor**:
```bash
time npm run build
```

**If Slow (>20s)**:
1. Check for large dependencies added
2. Review bundle splitting config
3. Check for circular dependencies
4. Consider cleaning node_modules

### Pre-commit Performance

**Target**: 3-5 seconds

**Monitor**:
```bash
time git commit --allow-empty -m "test"
```

**If Slow (>10s)**:
1. Check number of staged files
2. Verify only checking staged files
3. Review hook logic

### Runtime Performance

**Target**: First Contentful Paint < 2s

**Monitor**:
- Cloudflare Analytics
- Lighthouse scores
- WebPageTest results

**If Slow**:
1. Review bundle sizes
2. Check for new heavy dependencies
3. Verify code splitting is working
4. Check CDN caching

---

## 🔐 Security Maintenance

### Regular Security Tasks

#### Weekly
```bash
npm audit
cd frontend && npm audit
```
- Fix critical vulnerabilities immediately
- Plan fixes for high vulnerabilities

#### Monthly
- Review GitHub security advisories
- Update dependencies with security patches
- Rotate API tokens (if policy requires)

#### Quarterly
- Full security audit
- Review access logs
- Update security documentation

### Security Incident Response

1. **Identify**: Run `npm audit` to find vulnerabilities
2. **Assess**: Determine severity and impact
3. **Fix**: Update affected packages
4. **Test**: Full test suite
5. **Deploy**: Deploy fixes immediately for critical issues
6. **Document**: Update CHANGELOG.md

---

## 📝 Documentation Maintenance

### Weekly
- [ ] Update CHANGELOG.md with changes
- [ ] Review MONITORING_CHECKLIST.md results

### Monthly
- [ ] Review README_RECOVERY.md - Ensure accuracy
- [ ] Update DEPLOYMENT_VERIFICATION.md - Update metrics
- [ ] Check DEVELOPER_REFERENCE.md - Verify commands work

### Quarterly
- [ ] Full documentation review
- [ ] Update screenshots/examples
- [ ] Add new patterns/examples
- [ ] Remove outdated information

---

## 🚀 Deployment Maintenance

### Before Each Deployment

```bash
# Run pre-deployment checks
cd frontend

# 1. Check circular dependencies
npm run check:circular

# 2. Check TypeScript
npm run typecheck

# 3. Safe build
npm run build:safe

# 4. Run tests (if available)
npm test

# 5. Verify git status
git status
```

### After Each Deployment

```bash
# 1. Verify production
curl -I https://8eb14753.coreflow360-frontend.pages.dev/

# 2. Check for errors in logs
# Visit Cloudflare Dashboard

# 3. Monitor for 30 minutes
# Watch error rates, performance

# 4. Update documentation
# Update CHANGELOG.md
```

---

## 📋 Maintenance Schedule

### Daily (Automated)
- ✅ Pre-commit hooks run automatically
- ✅ CI/CD runs on pushes

### Weekly (15 min)
- Security updates
- Code quality review
- Documentation updates

### Monthly (30 min)
- Dependency audit
- Performance review
- Security review
- All safeguards check

### Quarterly (1 hour)
- Full system review
- Documentation deep dive
- Dependency major updates
- Performance optimization

### Annually (2-4 hours)
- Complete audit
- Technology review
- Architecture review
- Safeguard optimization

---

## 🎯 Maintenance Success Criteria

### Daily
- ✅ All commits pass pre-commit hooks
- ✅ CI/CD pipeline green

### Weekly
- ✅ 0 critical vulnerabilities
- ✅ 0 TypeScript errors
- ✅ 0 circular dependencies

### Monthly
- ✅ All safeguards active
- ✅ Documentation current
- ✅ Performance within targets

### Quarterly
- ✅ No technical debt backlog growth
- ✅ All dependencies up to date
- ✅ Security audit clean

---

## 📞 Getting Help

### Documentation
- **Quick Start**: QUICK_START.md
- **Developer Reference**: DEVELOPER_REFERENCE.md
- **Architecture Rules**: frontend/ARCHITECTURE.md
- **Monitoring**: MONITORING_CHECKLIST.md

### Common Issues
- **Circular Dependencies**: See ARCHITECTURE.md
- **Build Failures**: See DEVELOPER_REFERENCE.md
- **Deployment Issues**: See DEPLOYMENT_VERIFICATION.md

---

**Guide Created**: October 24, 2025
**Last Updated**: October 24, 2025
**Status**: ✅ Active
**Next Review**: November 24, 2025
