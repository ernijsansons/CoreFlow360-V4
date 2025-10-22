# CoreFlow360 V4 - Production Deployment Checklist

**Last Updated**: 2025-10-21
**Version**: 4.0.0

Use this checklist before every production deployment to ensure quality and reliability.

---

## Pre-Deployment Checks

### 1. Code Quality ✅

- [ ] **Build Success**
  ```bash
  npm run build:production
  cd frontend && npm run build
  ```
  - ✅ Backend build completes without errors
  - ✅ Frontend build completes without errors
  - ✅ Bundle sizes are reasonable (<200 kB for marketing chunk)

- [ ] **Type Checking**
  ```bash
  npm run type-check
  cd frontend && npm run typecheck
  ```
  - ✅ No TypeScript errors
  - ✅ All types are properly defined

- [ ] **Linting**
  ```bash
  npm run lint
  cd frontend && npm run lint
  ```
  - ✅ No ESLint errors
  - ✅ No critical warnings

- [ ] **Code Formatting**
  ```bash
  npm run format:check
  cd frontend && npm run format:check
  ```
  - ✅ All files are properly formatted with Prettier

---

### 2. Testing ✅

- [ ] **Unit Tests**
  ```bash
  npm test
  ```
  - ✅ All unit tests pass
  - ✅ Coverage meets target (95%+)

- [ ] **End-to-End Tests**
  ```bash
  cd frontend
  npm run test:e2e
  npm run test:a11y
  npm run test:auth
  npm run test:perf
  ```
  - ✅ All E2E tests pass
  - ✅ Accessibility tests pass (WCAG A/AA)
  - ✅ Authentication flows work
  - ✅ Performance meets targets (LCP <2.5s, CLS <0.1)

- [ ] **Security Tests**
  ```bash
  npm run test:security
  npm audit
  ```
  - ✅ No critical security vulnerabilities
  - ✅ No high severity vulnerabilities
  - ✅ JWT authentication properly secured

---

### 3. Environment Configuration ✅

- [ ] **Production Secrets**
  ```bash
  # Verify all secrets are set
  wrangler secret list --env production
  ```
  - ✅ `JWT_SECRET` is set (minimum 32 characters)
  - ✅ `ANTHROPIC_API_KEY` is set
  - ✅ `OPENAI_API_KEY` is set (if using)
  - ✅ `STRIPE_SECRET_KEY` is set (if using payments)
  - ✅ `ENCRYPTION_KEY` is set

- [ ] **Environment Variables**
  - ✅ `wrangler.toml` has correct production bindings
  - ✅ `ENVIRONMENT=production`
  - ✅ `ALLOWED_ORIGINS` includes production domains
  - ✅ `LOG_LEVEL=info`

- [ ] **Database Migrations**
  ```bash
  wrangler d1 migrations list coreflow360-agents --env production
  wrangler d1 migrations apply coreflow360-agents --env production
  ```
  - ✅ All migrations applied successfully
  - ✅ No pending migrations (unless intentional)

---

### 4. Performance Validation ✅

- [ ] **Bundle Analysis**
  ```bash
  cd frontend
  npm run build
  ls -lh dist/assets/*.js
  ```
  - ✅ Marketing chunk <100 kB
  - ✅ Auth chunk <30 kB
  - ✅ Vendor chunks properly split
  - ✅ Total initial load <500 kB (gzipped)

- [ ] **Lighthouse Audit** (if applicable)
  ```bash
  npm run audit:lighthouse
  ```
  - ✅ Performance score >90
  - ✅ Accessibility score >95
  - ✅ Best Practices score >90
  - ✅ SEO score >90

- [ ] **Worker Latency**
  ```bash
  npm run audit:worker-latency
  ```
  - ✅ P50 latency <100ms
  - ✅ P95 latency <200ms
  - ✅ P99 latency <500ms

---

### 5. Security Validation ✅

- [ ] **Security Headers**
  - ✅ Content-Security-Policy configured
  - ✅ X-Content-Type-Options: nosniff
  - ✅ X-Frame-Options: DENY
  - ✅ Referrer-Policy configured

- [ ] **Authentication**
  - ✅ JWT secret is not a fallback value
  - ✅ Token blacklist is enabled
  - ✅ Session expiration is configured (8h)
  - ✅ MFA is available (if required)

- [ ] **Rate Limiting**
  - ✅ Rate limiting is enabled
  - ✅ DDoS protection is active
  - ✅ Suspicious activity detection works

---

## Deployment Steps

### 1. Backend Deployment 🚀

```bash
# 1. Verify you're on the correct branch
git status
git log -1

# 2. Build for production
npm run build:production

# 3. Deploy to Cloudflare Workers
wrangler deploy --env production

# 4. Verify deployment
curl https://coreflow360-v4-prod.your-account.workers.dev/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-21T...",
  "services": {
    "database": "connected",
    "ai": "ready"
  }
}
```

---

### 2. Frontend Deployment 🚀

```bash
# 1. Navigate to frontend
cd frontend

# 2. Build for production
npm run build

# 3. Deploy to Cloudflare Pages
wrangler pages deploy dist --project-name=coreflow360-frontend --branch=production

# 4. Verify deployment
curl https://coreflow360-frontend.pages.dev
```

**Expected**: Landing page loads successfully

---

### 3. Database Migrations 🗄️

```bash
# 1. Check pending migrations
wrangler d1 migrations list coreflow360-agents --env production

# 2. Apply migrations (if any)
wrangler d1 migrations apply coreflow360-agents --env production

# 3. Verify database integrity
wrangler d1 execute coreflow360-agents --env production --command "SELECT COUNT(*) FROM users"
```

---

## Post-Deployment Validation

### 1. Smoke Tests ✅

- [ ] **Landing Page**
  - Visit https://coreflow360-frontend.pages.dev
  - ✅ Page loads within 3 seconds
  - ✅ Hero CTA buttons work
  - ✅ Navigation links work
  - ✅ Testimonials section visible

- [ ] **Authentication**
  - Go to https://coreflow360-frontend.pages.dev/auth/login
  - ✅ Login form renders
  - ✅ Validation works
  - ✅ Can submit form (test with invalid credentials to check error handling)

- [ ] **API Health**
  - Visit https://coreflow360-v4-prod.your-account.workers.dev/api/v1/health
  - ✅ Returns 200 OK
  - ✅ All services show "connected" or "ready"

- [ ] **Analytics Dashboard**
  - Visit https://coreflow360-v4-prod.your-account.workers.dev/api/v1/analytics/dashboard-url
  - ✅ Returns Cloudflare dashboard URLs
  - ✅ Links are accessible

---

### 2. Performance Monitoring 📊

- [ ] **Cloudflare Analytics**
  - Open Cloudflare Dashboard
  - Navigate to Workers > coreflow360-v4-prod > Analytics
  - ✅ Requests are being logged
  - ✅ Error rate is <1%
  - ✅ P95 response time is <200ms

- [ ] **Web Vitals**
  - Open Cloudflare Dashboard or custom analytics
  - Check web-vitals data from `/api/v1/observability/telemetry/web-vitals`
  - ✅ LCP <2.5s
  - ✅ CLS <0.1
  - ✅ FID/INP <100ms

- [ ] **Error Tracking**
  - Check Sentry (if configured)
  - ✅ No new critical errors
  - ✅ Error rate is within baseline

---

### 3. Rollback Plan 🔄

If deployment fails or critical issues are discovered:

```bash
# 1. Rollback backend
wrangler rollback --env production

# 2. Rollback frontend
wrangler pages deployment list --project-name=coreflow360-frontend
wrangler pages deployment rollback <deployment-id> --project-name=coreflow360-frontend

# 3. Rollback database (if needed)
# Manually revert migrations or restore from backup

# 4. Verify rollback
curl https://coreflow360-v4-prod.your-account.workers.dev/health
curl https://coreflow360-frontend.pages.dev
```

---

## Post-Deployment Tasks

### 1. Communication 📣

- [ ] Notify team in Slack: #deployments channel
- [ ] Update deployment log: `deployments.md`
- [ ] Tag release in Git: `git tag v4.0.x && git push --tags`

### 2. Monitoring 👀

- [ ] Monitor Cloudflare Analytics for 30 minutes post-deployment
- [ ] Watch error rate for spikes
- [ ] Check response time trends
- [ ] Review user feedback channels

### 3. Documentation 📚

- [ ] Update CHANGELOG.md with new features/fixes
- [ ] Update API documentation if endpoints changed
- [ ] Update user-facing documentation if UI changed

---

## Common Issues & Solutions

### Issue: Build fails with "Module not found"

**Solution:**
```bash
rm -rf node_modules package-lock.json
npm install
npm run build:production
```

### Issue: TypeScript errors in production

**Solution:**
```bash
npm run type-check
# Fix errors, then rebuild
npm run build:production
```

### Issue: Wrangler deployment fails

**Solution:**
```bash
# Check authentication
wrangler whoami

# Verify wrangler.toml configuration
cat wrangler.toml | grep -A 10 "env.production"

# Try deploying with verbose logging
wrangler deploy --env production --verbose
```

### Issue: Database migration fails

**Solution:**
```bash
# Check migration status
wrangler d1 migrations list coreflow360-agents --env production

# Check database logs
wrangler d1 execute coreflow360-agents --env production --command "SELECT * FROM d1_migrations ORDER BY id DESC LIMIT 5"

# If needed, manually fix migration and retry
```

### Issue: High error rate post-deployment

**Solution:**
1. Check Cloudflare Analytics for error details
2. Review Sentry for stack traces
3. Check worker logs: `wrangler tail --env production`
4. If critical: Execute rollback plan
5. If non-critical: Hot-fix and redeploy

---

## Emergency Contacts

- **DevOps Lead**: [Name] - [Email/Slack]
- **Backend Lead**: [Name] - [Email/Slack]
- **Frontend Lead**: [Name] - [Email/Slack]
- **On-Call Engineer**: Check PagerDuty

---

## Deployment Approval

- [ ] **Code Review**: All changes reviewed and approved
- [ ] **QA Sign-off**: All tests pass
- [ ] **Security Review**: No critical vulnerabilities
- [ ] **Performance Review**: Meets performance targets
- [ ] **Product Owner Approval**: Features approved

**Deployment By**: ___________________
**Date**: ___________________
**Time**: ___________________
**Version**: v4.0.x

---

## Additional Notes

Use this section for deployment-specific notes, warnings, or special considerations for this particular release.

---

**Generated by**: CoreFlow360 V4 Audit Implementation
**Template Version**: 1.0.0
