# CI/CD Pipeline Setup - Automated Testing & Deployment

**Created**: 2025-10-22
**Purpose**: Configure continuous integration and deployment for backend-to-UI features
**Audience**: DevOps engineers, engineering leads

---

## Table of Contents

1. [Overview](#overview)
2. [GitHub Actions Workflows](#github-actions-workflows)
3. [Cloudflare Pages CI/CD](#cloudflare-pages-cicd)
4. [Environment Management](#environment-management)
5. [Automated Testing Pipeline](#automated-testing-pipeline)
6. [Deployment Pipeline](#deployment-pipeline)
7. [Quality Gates](#quality-gates)
8. [Troubleshooting](#troubleshooting)

---

## Overview

### CI/CD Architecture

```
Code Push → GitHub Actions → Quality Gates → Deploy
    │
    ├─► Run Tests (Unit, E2E, Accessibility)
    ├─► Run Linting (ESLint, Prettier)
    ├─► Run Type Checking (TypeScript)
    ├─► Build Application
    ├─► Security Scan
    │
    └─► If All Pass → Deploy to Environment
            │
            ├─► Development (Auto-deploy on push to dev)
            ├─► Staging (Auto-deploy on push to main)
            └─► Production (Manual approval required)
```

### Environments

| Environment | Branch | Deploy Trigger | Approval | URL |
|-------------|--------|----------------|----------|-----|
| Development | `dev` | Automatic on push | None | https://dev.coreflow360.com |
| Staging | `main` | Automatic on push | None | https://staging.coreflow360.com |
| Production | `main` | Manual (after staging verification) | Required | https://coreflow360.com |

---

## GitHub Actions Workflows

### Workflow Structure

```
.github/workflows/
├── ci.yml                    # Continuous integration (tests, linting)
├── deploy-dev.yml           # Auto-deploy to development
├── deploy-staging.yml       # Auto-deploy to staging
├── deploy-production.yml    # Manual deploy to production
├── e2e-tests.yml           # E2E tests (runs on PR)
└── security-scan.yml       # Security vulnerability scanning
```

---

### 1. Continuous Integration Workflow

**File**: `.github/workflows/ci.yml`

```yaml
name: CI - Tests and Quality Checks

on:
  push:
    branches: [dev, main]
  pull_request:
    branches: [dev, main]

jobs:
  # Job 1: Lint and Type Check
  lint-and-typecheck:
    name: Lint and Type Check
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run ESLint
        run: npm run lint

      - name: Run Prettier check
        run: npm run format:check

      - name: TypeScript type check
        run: npm run type-check

  # Job 2: Unit Tests
  unit-tests:
    name: Unit Tests
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run unit tests
        run: npm run test:ci

      - name: Upload coverage reports
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/coverage-final.json
          flags: unittests
          name: unit-tests-coverage

  # Job 3: Build Check
  build:
    name: Build Application
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build frontend
        run: npm run build
        working-directory: ./frontend

      - name: Check bundle size
        run: |
          BUNDLE_SIZE=$(du -sh frontend/dist | cut -f1)
          echo "Bundle size: $BUNDLE_SIZE"
          # Fail if bundle > 5MB
          if [ $(du -s frontend/dist | cut -f1) -gt 5120 ]; then
            echo "Bundle size exceeds 5MB limit!"
            exit 1
          fi

  # Job 4: Security Scan
  security-scan:
    name: Security Vulnerability Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Run npm audit
        run: npm audit --audit-level=high
        continue-on-error: true

      - name: Run Snyk security scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
        continue-on-error: true
```

**Usage**:
- Runs automatically on every push and pull request
- All jobs must pass for PR to be mergeable
- Coverage reports uploaded to Codecov

---

### 2. E2E Tests Workflow

**File**: `.github/workflows/e2e-tests.yml`

```yaml
name: E2E Tests

on:
  pull_request:
    branches: [main]
  workflow_dispatch:  # Allow manual trigger

jobs:
  e2e-tests:
    name: Playwright E2E Tests
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: |
          npm ci
          cd frontend && npm ci

      - name: Install Playwright browsers
        run: npx playwright install --with-deps
        working-directory: ./frontend

      - name: Start backend (dev mode)
        run: |
          npm run dev &
          sleep 10  # Wait for backend to start

      - name: Start frontend (dev mode)
        run: |
          npm run dev &
          sleep 10  # Wait for frontend to start
        working-directory: ./frontend

      - name: Run Playwright tests
        run: npx playwright test
        working-directory: ./frontend

      - name: Upload Playwright report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: playwright-report
          path: frontend/playwright-report/
          retention-days: 30

      - name: Upload test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: playwright-results
          path: frontend/test-results/
          retention-days: 30

  # Accessibility Tests (separate job)
  accessibility-tests:
    name: Accessibility Tests
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: |
          npm ci
          cd frontend && npm ci

      - name: Install Playwright
        run: npx playwright install --with-deps
        working-directory: ./frontend

      - name: Start application
        run: |
          npm run dev &
          cd frontend && npm run dev &
          sleep 15

      - name: Run accessibility tests
        run: npx playwright test accessibility.spec.ts
        working-directory: ./frontend

      - name: Run Lighthouse CI
        run: |
          npm install -g @lhci/cli
          lhci autorun
        env:
          LHCI_GITHUB_APP_TOKEN: ${{ secrets.LHCI_GITHUB_APP_TOKEN }}
```

**Usage**:
- Runs on every pull request to `main`
- Can be manually triggered via GitHub Actions UI
- Uploads test reports as artifacts

---

### 3. Deploy to Development

**File**: `.github/workflows/deploy-dev.yml`

```yaml
name: Deploy to Development

on:
  push:
    branches: [dev]

jobs:
  deploy-dev:
    name: Deploy to Development
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Install Wrangler
        run: npm install -g wrangler

      - name: Deploy backend to Cloudflare Workers (dev)
        run: wrangler deploy --env development
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}

      - name: Deploy frontend to Cloudflare Pages (dev)
        run: |
          cd frontend
          npm ci
          npm run build
          wrangler pages publish dist --project-name=coreflow360-frontend --branch=dev
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}

      - name: Notify Slack
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "✅ Development deployment complete",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "✅ *Development Deployment Complete*\n\nCommit: ${{ github.sha }}\nAuthor: ${{ github.actor }}\nURL: https://dev.coreflow360.com"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

---

### 4. Deploy to Staging

**File**: `.github/workflows/deploy-staging.yml`

```yaml
name: Deploy to Staging

on:
  push:
    branches: [main]

jobs:
  # First, run all tests
  run-tests:
    name: Run All Tests
    uses: ./.github/workflows/ci.yml

  # Deploy only if tests pass
  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: run-tests

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run database migrations (staging)
        run: |
          npm install -g wrangler
          wrangler d1 migrations apply coreflow360-staging
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}

      - name: Deploy backend to Cloudflare Workers (staging)
        run: wrangler deploy --env staging
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}

      - name: Deploy frontend to Cloudflare Pages (staging)
        run: |
          cd frontend
          npm ci
          npm run build
          wrangler pages publish dist --project-name=coreflow360-frontend --branch=main
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}

      - name: Run smoke tests
        run: |
          sleep 30  # Wait for deployment to propagate
          npm run test:smoke
        env:
          BASE_URL: https://staging.coreflow360.com

      - name: Notify Slack
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "✅ Staging deployment complete - Ready for production",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "✅ *Staging Deployment Complete*\n\nCommit: ${{ github.sha }}\nAuthor: ${{ github.actor }}\nURL: https://staging.coreflow360.com\n\n*Next Step*: Verify on staging, then deploy to production"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

---

### 5. Deploy to Production

**File**: `.github/workflows/deploy-production.yml`

```yaml
name: Deploy to Production

on:
  workflow_dispatch:  # Manual trigger only
    inputs:
      confirm:
        description: 'Type "deploy-to-production" to confirm'
        required: true

jobs:
  # Validate confirmation
  validate-confirmation:
    name: Validate Deployment Confirmation
    runs-on: ubuntu-latest

    steps:
      - name: Check confirmation
        run: |
          if [ "${{ github.event.inputs.confirm }}" != "deploy-to-production" ]; then
            echo "Deployment cancelled - confirmation string incorrect"
            exit 1
          fi

  # Deploy to production
  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: validate-confirmation
    environment:
      name: production
      url: https://coreflow360.com

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Create database backup
        run: |
          npm install -g wrangler
          BACKUP_ID=$(wrangler d1 backup create coreflow360-production | grep "Backup ID" | awk '{print $3}')
          echo "BACKUP_ID=$BACKUP_ID" >> $GITHUB_ENV
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}

      - name: Run database migrations (production)
        run: wrangler d1 migrations apply coreflow360-production
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}

      - name: Deploy backend to Cloudflare Workers (production)
        run: wrangler deploy --env production
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}

      - name: Deploy frontend to Cloudflare Pages (production)
        run: |
          cd frontend
          npm ci
          npm run build
          wrangler pages publish dist --project-name=coreflow360-frontend --branch=production
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}

      - name: Wait for deployment to propagate
        run: sleep 60

      - name: Run production smoke tests
        run: npm run test:smoke
        env:
          BASE_URL: https://coreflow360.com

      - name: Notify Slack (Success)
        if: success()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "🚀 Production deployment successful",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "🚀 *Production Deployment Successful*\n\nCommit: ${{ github.sha }}\nAuthor: ${{ github.actor }}\nBackup ID: ${{ env.BACKUP_ID }}\nURL: https://coreflow360.com\n\n*Action*: Monitor for next 30 minutes"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}

      - name: Notify Slack (Failure)
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "❌ Production deployment FAILED",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "❌ *Production Deployment FAILED*\n\nCommit: ${{ github.sha }}\nBackup ID: ${{ env.BACKUP_ID }}\n\n*Action*: Investigate immediately, rollback if needed"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

**Usage**:
- **Manual trigger only** via GitHub Actions UI
- Requires typing "deploy-to-production" to confirm
- Creates database backup before deployment
- Runs smoke tests after deployment
- Notifies Slack on success/failure

---

## Cloudflare Pages CI/CD

### Cloudflare Pages Configuration

**File**: `frontend/.pages.toml` (Cloudflare Pages config)

```toml
[build]
command = "npm run build"
destination = "dist"

[build.environment]
NODE_VERSION = "20"

# Development environment
[env.development]
VITE_API_URL = "https://dev-api.coreflow360.com"
VITE_ENVIRONMENT = "development"

# Staging environment
[env.staging]
VITE_API_URL = "https://staging-api.coreflow360.com"
VITE_ENVIRONMENT = "staging"

# Production environment
[env.production]
VITE_API_URL = "https://api.coreflow360.com"
VITE_ENVIRONMENT = "production"
```

---

## Environment Management

### GitHub Secrets Configuration

Required secrets in GitHub repository settings:

```
Settings → Secrets and variables → Actions → New repository secret
```

**Cloudflare Secrets**:
- `CLOUDFLARE_API_TOKEN` - Cloudflare API token with Workers and Pages permissions
- `CLOUDFLARE_ACCOUNT_ID` - Cloudflare account ID

**Third-Party Services**:
- `SNYK_TOKEN` - Snyk security scanning token
- `CODECOV_TOKEN` - Code coverage reporting token
- `SLACK_WEBHOOK_URL` - Slack webhook for deployment notifications
- `LHCI_GITHUB_APP_TOKEN` - Lighthouse CI token

**Application Secrets** (for production deployment):
- `JWT_SECRET` - JWT signing secret
- `ANTHROPIC_API_KEY` - Anthropic API key
- `OPENAI_API_KEY` - OpenAI API key
- `STRIPE_SECRET_KEY` - Stripe secret key
- `SENDGRID_API_KEY` - SendGrid API key

---

### Wrangler Configuration

**File**: `wrangler.toml`

```toml
name = "coreflow360-v4"
main = "src/index.ts"
compatibility_date = "2024-01-01"
node_compat = true

# Development environment
[env.development]
name = "coreflow360-dev"
vars = { ENVIRONMENT = "development" }

[[env.development.d1_databases]]
binding = "DB_MAIN"
database_name = "coreflow360-dev"
database_id = "your-dev-database-id"

[[env.development.kv_namespaces]]
binding = "KV_CACHE"
id = "your-dev-kv-id"

# Staging environment
[env.staging]
name = "coreflow360-staging"
vars = { ENVIRONMENT = "staging" }

[[env.staging.d1_databases]]
binding = "DB_MAIN"
database_name = "coreflow360-staging"
database_id = "your-staging-database-id"

[[env.staging.kv_namespaces]]
binding = "KV_CACHE"
id = "your-staging-kv-id"

# Production environment
[env.production]
name = "coreflow360-production"
vars = { ENVIRONMENT = "production" }

[[env.production.d1_databases]]
binding = "DB_MAIN"
database_name = "coreflow360-production"
database_id = "your-production-database-id"

[[env.production.kv_namespaces]]
binding = "KV_CACHE"
id = "your-production-kv-id"
```

---

## Automated Testing Pipeline

### Test Execution Order

```
1. Lint & Type Check (fastest, fail early)
   ├─► ESLint (JavaScript/TypeScript)
   ├─► Prettier (code formatting)
   └─► TypeScript (type checking)

2. Unit Tests (fast, isolated)
   └─► Vitest (all *.test.ts files)

3. Build Check (medium speed)
   ├─► Frontend build
   ├─► Backend build
   └─► Bundle size check

4. Integration Tests (medium speed)
   └─► API integration tests

5. E2E Tests (slow, comprehensive)
   ├─► Playwright (critical user flows)
   └─► Accessibility tests (axe, Lighthouse)

6. Security Scan (slow)
   ├─► npm audit
   └─► Snyk scan
```

### Test Scripts

**Add to `package.json`**:

```json
{
  "scripts": {
    "test": "vitest",
    "test:ci": "vitest run --coverage",
    "test:e2e": "playwright test",
    "test:e2e:ui": "playwright test --ui",
    "test:accessibility": "playwright test accessibility.spec.ts",
    "test:smoke": "node scripts/smoke-test.js",
    "lint": "eslint . --ext .ts,.tsx",
    "lint:fix": "eslint . --ext .ts,.tsx --fix",
    "format": "prettier --write \"**/*.{ts,tsx,json,md}\"",
    "format:check": "prettier --check \"**/*.{ts,tsx,json,md}\"",
    "type-check": "tsc --noEmit"
  }
}
```

### Smoke Test Script

**File**: `scripts/smoke-test.js`

```javascript
#!/usr/bin/env node

/**
 * Smoke Test - Verify critical functionality after deployment
 */

const BASE_URL = process.env.BASE_URL || 'http://localhost:5173'

async function smokeTest() {
  console.log('🔍 Running smoke tests...\n')

  const tests = [
    {
      name: 'Health Check',
      url: `${BASE_URL}/health`,
      expectedStatus: 200
    },
    {
      name: 'API Status',
      url: `${BASE_URL}/api/status`,
      expectedStatus: 200
    },
    {
      name: 'Frontend Homepage',
      url: BASE_URL,
      expectedStatus: 200
    }
  ]

  let passed = 0
  let failed = 0

  for (const test of tests) {
    try {
      const response = await fetch(test.url)
      if (response.status === test.expectedStatus) {
        console.log(`✅ ${test.name}: PASS`)
        passed++
      } else {
        console.log(`❌ ${test.name}: FAIL (status ${response.status})`)
        failed++
      }
    } catch (error) {
      console.log(`❌ ${test.name}: FAIL (${error.message})`)
      failed++
    }
  }

  console.log(`\n📊 Results: ${passed} passed, ${failed} failed`)

  if (failed > 0) {
    process.exit(1)
  }
}

smokeTest().catch(error => {
  console.error('Smoke test failed:', error)
  process.exit(1)
})
```

---

## Deployment Pipeline

### Deployment Flow

```
Developer → Git Push → GitHub Actions → Quality Gates → Deploy
                                              │
                                              ├─► Tests Pass?
                                              ├─► Lint Pass?
                                              ├─► Build Success?
                                              ├─► Security OK?
                                              │
                                              └─► All Pass → Deploy
                                                      │
                                                      ├─► Dev (auto)
                                                      ├─► Staging (auto)
                                                      └─► Production (manual approval)
```

### Manual Production Deployment Steps

1. **Verify Staging**:
```bash
# Check staging deployment
curl -f https://staging.coreflow360.com/health

# Run manual tests on staging
# - Test compliance guidelines CRUD
# - Test authentication
# - Test critical user flows
```

2. **Trigger Production Deployment**:
```
GitHub → Actions → Deploy to Production → Run workflow
→ Type "deploy-to-production" → Confirm
```

3. **Monitor Deployment**:
```bash
# Watch deployment logs in GitHub Actions

# After deployment, verify health
curl -f https://coreflow360.com/health

# Check error rates
curl https://api.coreflow360.com/api/metrics/errors?last=15m
```

4. **Post-Deployment Verification**:
```bash
# Run smoke tests
npm run test:smoke

# Check Sentry for errors
# Open: https://sentry.io/organizations/coreflow360/

# Monitor Cloudflare Analytics
# Open: https://dash.cloudflare.com/analytics
```

---

## Quality Gates

### Pre-Merge Requirements (Pull Requests)

**All of the following must pass**:
- ✅ ESLint (no errors)
- ✅ Prettier (formatting correct)
- ✅ TypeScript (no type errors)
- ✅ Unit tests (all passing, coverage ≥ 80%)
- ✅ Build succeeds
- ✅ Security scan (no high-severity vulnerabilities)
- ✅ Code review approved (at least 1 reviewer)

### Pre-Deployment Requirements (Staging)

**All of the following must pass**:
- ✅ All pre-merge requirements
- ✅ E2E tests (all passing)
- ✅ Accessibility tests (Lighthouse ≥ 95)
- ✅ Database migrations tested
- ✅ Bundle size check (< 5MB)

### Pre-Deployment Requirements (Production)

**All of the following must pass**:
- ✅ All staging requirements
- ✅ Staging environment verified (manual testing)
- ✅ Database backup created
- ✅ Rollback plan documented
- ✅ Engineering lead approval
- ✅ Product manager approval (for feature releases)

---

## Troubleshooting

### Common CI/CD Issues

#### Issue 1: Tests Failing in CI but Pass Locally

**Symptoms**: Tests pass on local machine but fail in GitHub Actions

**Causes**:
- Environment variable missing
- Timezone differences
- Different Node.js version
- Race condition in tests

**Solutions**:
```bash
# 1. Check Node.js version matches
node --version  # Must be 20.x

# 2. Run tests with same environment
CI=true npm run test

# 3. Check for flaky tests
npm run test -- --repeat-each=10

# 4. Add environment variables to GitHub Secrets
# Settings → Secrets → Add missing variables
```

#### Issue 2: Deployment Fails

**Symptoms**: Deployment to Cloudflare fails

**Causes**:
- Wrangler authentication failed
- Database migration failed
- Build errors

**Solutions**:
```bash
# 1. Verify Cloudflare API token
wrangler whoami

# 2. Test deployment locally
wrangler deploy --dry-run

# 3. Check migration syntax
wrangler d1 migrations list coreflow360-staging

# 4. Review deployment logs in GitHub Actions
```

#### Issue 3: E2E Tests Timeout

**Symptoms**: Playwright tests timeout in CI

**Causes**:
- Application not starting in time
- Slow network in CI environment
- Test expecting specific timing

**Solutions**:
```typescript
// 1. Increase timeout for CI
test.setTimeout(process.env.CI ? 60000 : 30000)

// 2. Wait for app to be ready
await page.waitForLoadState('networkidle')

// 3. Use explicit waits instead of sleeps
await page.waitForSelector('[data-testid="loaded"]')
```

---

## Best Practices

### 1. Fast Feedback Loop

- Run fastest tests first (lint, type-check)
- Fail early if basic checks don't pass
- Parallelize independent test jobs

### 2. Secure Secrets Management

- Never commit secrets to repository
- Use GitHub Secrets for all sensitive data
- Rotate secrets regularly (quarterly)
- Use different secrets for each environment

### 3. Rollback Ready

- Always create database backup before production deployment
- Keep previous deployment ID accessible for rollback
- Test rollback procedure regularly (monthly)

### 4. Monitoring

- Set up Slack notifications for all deployments
- Monitor error rates after each deployment
- Use feature flags for gradual rollouts

### 5. Documentation

- Document all deployment steps
- Keep runbooks up-to-date
- Track all production deployments in changelog

---

## Deployment Checklist

**Before Every Production Deployment**:
- [ ] All tests passing on staging
- [ ] Manual verification on staging completed
- [ ] Database backup created
- [ ] Rollback plan documented
- [ ] Stakeholders notified (PM, support team)
- [ ] Monitoring dashboards open and ready
- [ ] On-call engineer identified and available
- [ ] Feature flag created (if new feature)

**After Production Deployment**:
- [ ] Smoke tests passed
- [ ] Error rates normal (< 0.1%)
- [ ] Response times normal (P95 < 500ms)
- [ ] No customer complaints (first 15 minutes)
- [ ] Status page updated (if applicable)
- [ ] Deployment logged in changelog

---

## Additional Resources

### GitHub Actions Documentation
- https://docs.github.com/en/actions

### Cloudflare Workers/Pages Docs
- https://developers.cloudflare.com/workers/
- https://developers.cloudflare.com/pages/

### Playwright CI Documentation
- https://playwright.dev/docs/ci

### Wrangler CLI Reference
- https://developers.cloudflare.com/workers/wrangler/

---

**Document Version**: 1.0
**Last Updated**: 2025-10-22
**Maintained By**: DevOps Team
**Review Cycle**: Monthly

**Questions?** Contact: devops@coreflow360.com
