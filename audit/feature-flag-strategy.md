# Feature Flag Strategy - Safe Deployment Guide

**Created**: 2025-10-22
**Purpose**: Strategy for using feature flags to deploy safely and roll out gradually
**Audience**: All team members (Engineering, Product, QA)

---

## Overview

Every new feature MUST be behind a feature flag. This allows us to:
- ✅ Deploy to production with features OFF
- ✅ Test in production with internal users only
- ✅ Gradual rollout (10% → 50% → 100% of users)
- ✅ Instant rollback without redeployment
- ✅ A/B testing and experimentation

---

## Feature Flag Naming Convention

### Format: `enable{FeatureName}`

```typescript
// ✅ GOOD
enableComplianceAdmin
enableInvoiceApprovalWorkflow
enableAIInsightsPanel
enableDataQualityDashboard

// ❌ BAD
compliance_admin        // Use camelCase, not snake_case
showCompliance         // Use 'enable' prefix
complianceFeature      // Be specific
```

---

## Feature Flag Lifecycle

###  1. Creation (Before Development)

```bash
# Create flag in your feature flag system (LaunchDarkly, custom, etc.)
# Default: OFF for all users
# Environments: development, staging, production
```

**Configuration**:
```json
{
  "key": "enableComplianceAdmin",
  "name": "Compliance Admin UI",
  "description": "Enable compliance guidelines and policy management UI",
  "environments": {
    "development": { "enabled": true },
    "staging": { "enabled": false },
    "production": { "enabled": false }
  },
  "tags": ["backend-ui-integration", "phase-1a", "compliance"],
  "created_by": "engineering-lead",
  "created_at": "2025-11-01"
}
```

---

### 2. Development (Dev Environment)

**Flag: ON** for all users in development

```typescript
// hooks/useFeatureFlag.ts
export function useFeatureFlag(flagKey: string): boolean {
  // In development, read from environment variable or always return true
  if (import.meta.env.DEV) {
    return true // All flags ON in dev
  }

  // In production, check flag service
  return checkFeatureFlag(flagKey)
}

// Usage in component
export function AdminNav() {
  const complianceEnabled = useFeatureFlag('enableComplianceAdmin')

  return (
    <nav>
      <NavItem href="/dashboard">Dashboard</NavItem>
      {complianceEnabled && (
        <NavItem href="/admin/compliance">Compliance</NavItem>
      )}
      <NavItem href="/settings">Settings</NavItem>
    </nav>
  )
}
```

---

### 3. Staging Deployment (Staging Environment)

**Flag: ON** for QA team and internal testers

```bash
# Deploy to staging
npm run deploy:staging

# Enable flag for QA team
# Option 1: Enable for specific users
ff-cli enable enableComplianceAdmin --users qa@company.com --env staging

# Option 2: Enable for all staging users
ff-cli enable enableComplianceAdmin --env staging --all
```

**QA Testing Checklist**:
- [ ] Feature works with flag ON
- [ ] Feature hidden with flag OFF
- [ ] No errors when flag is OFF
- [ ] Acceptance criteria met
- [ ] Performance acceptable

---

### 4. Production Deployment (Flag OFF)

**Flag: OFF** for all users initially

```bash
# Deploy to production (feature code deployed but hidden)
npm run deploy:prod

# Verify flag is OFF
ff-cli status enableComplianceAdmin --env production
# Output: Status: OFF for all users

# Smoke test: Feature should be hidden
# Visit /admin/compliance → Should 404 or redirect
```

---

### 5. Internal Beta (Internal Users Only)

**Flag: ON** for company employees

```bash
# Enable for internal users only
ff-cli enable enableComplianceAdmin \
  --env production \
  --rule "email ends with @company.com"

# Or target specific users
ff-cli enable enableComplianceAdmin \
  --env production \
  --users "john@company.com,sarah@company.com,alex@company.com"
```

**Internal Testing** (24-48 hours):
- [ ] No errors in Sentry
- [ ] Performance metrics normal
- [ ] Positive feedback from internal users
- [ ] No data integrity issues

---

### 6. Gradual Rollout (10% → 50% → 100%)

#### Phase 1: 10% of Users (Low Risk)

```bash
# Enable for 10% of users
ff-cli enable enableComplianceAdmin \
  --env production \
  --percentage 10

# Monitor for 48 hours
```

**Monitoring** (48 hours):
- [ ] Error rate < 0.1%
- [ ] Response time < 500ms P95
- [ ] No spike in support tickets
- [ ] User adoption > 5% (of those who see it)

#### Phase 2: 50% of Users (Medium Risk)

```bash
# Increase to 50% after 48 hours of stability
ff-cli enable enableComplianceAdmin \
  --env production \
  --percentage 50

# Monitor for 1 week
```

**Monitoring** (1 week):
- [ ] Error rate remains stable
- [ ] Positive user feedback
- [ ] Feature usage growing
- [ ] No performance degradation

#### Phase 3: 100% of Users (Full Rollout)

```bash
# Enable for all users after 1 week of stability
ff-cli enable enableComplianceAdmin \
  --env production \
  --percentage 100

# Monitor for 2 weeks before cleanup
```

**Monitoring** (2 weeks):
- [ ] Feature widely adopted
- [ ] No major issues reported
- [ ] Success metrics met (see user story)

---

### 7. Cleanup (Remove Flag)

**After 2 weeks of 100% rollout with no issues**:

```bash
# 1. Remove flag checks from code
# Before:
if (useFeatureFlag('enableComplianceAdmin')) {
  return <ComplianceNav />
}

# After:
return <ComplianceNav /> // Always show

# 2. Remove flag from flag service
ff-cli delete enableComplianceAdmin --env production

# 3. Create cleanup PR
git checkout -b chore/remove-compliance-flag
# ... make changes ...
git commit -m "chore: Remove enableComplianceAdmin feature flag"
git push
```

---

## Implementation Patterns

### Pattern 1: Route-Level Flag

```typescript
// routes.tsx
import { Navigate } from 'react-router-dom'

export function ProtectedRoute({ flagKey, element }: Props) {
  const flagEnabled = useFeatureFlag(flagKey)

  if (!flagEnabled) {
    return <Navigate to="/404" replace />
  }

  return element
}

// Usage
const routes = [
  {
    path: '/admin/compliance',
    element: (
      <ProtectedRoute
        flagKey="enableComplianceAdmin"
        element={<CompliancePage />}
      />
    ),
  },
]
```

---

### Pattern 2: Component-Level Flag

```typescript
// components/AdminNav.tsx
export function AdminNav() {
  const complianceEnabled = useFeatureFlag('enableComplianceAdmin')
  const invoiceApprovalEnabled = useFeatureFlag('enableInvoiceApprovalWorkflow')

  return (
    <nav>
      <NavItem href="/dashboard">Dashboard</NavItem>

      {complianceEnabled && (
        <>
          <NavItem href="/admin/compliance/guidelines">Guidelines</NavItem>
          <NavItem href="/admin/compliance/policies">Policies</NavItem>
        </>
      )}

      {invoiceApprovalEnabled && (
        <NavItem href="/finance/approvals">Approvals</NavItem>
      )}
    </nav>
  )
}
```

---

### Pattern 3: Feature-Level Flag (API Calls)

```typescript
// services/compliance.service.ts
export async function listGuidelines() {
  // Backend also checks flag - defense in depth
  const response = await apiClient.get('/api/compliance/guidelines', {
    headers: {
      'X-Feature-Flag': 'enableComplianceAdmin',
    },
  })

  return response.data
}

// Backend (Hono)
app.get('/api/compliance/guidelines', async (c) => {
  const flagEnabled = await checkFeatureFlag(
    'enableComplianceAdmin',
    c.get('user')
  )

  if (!flagEnabled) {
    return c.json({ error: 'Feature not available' }, 403)
  }

  // ... normal logic
})
```

---

## Feature Flag Service Implementation

### Option 1: LaunchDarkly (Recommended for Enterprise)

```typescript
// lib/feature-flags.ts
import { LDClient, initialize } from 'launchdarkly-js-client-sdk'

const client: LDClient = initialize(
  import.meta.env.VITE_LAUNCHDARKLY_CLIENT_ID,
  {
    kind: 'user',
    key: 'anonymous',
  }
)

export async function checkFeatureFlag(
  flagKey: string,
  user?: User
): Promise<boolean> {
  if (user) {
    await client.identify({
      kind: 'user',
      key: user.id,
      email: user.email,
      custom: {
        businessId: user.business_id,
        role: user.role,
      },
    })
  }

  return client.variation(flagKey, false)
}

// React Hook
export function useFeatureFlag(flagKey: string): boolean {
  const [enabled, setEnabled] = useState(false)
  const user = useAuthStore((state) => state.user)

  useEffect(() => {
    checkFeatureFlag(flagKey, user ?? undefined).then(setEnabled)
  }, [flagKey, user])

  return enabled
}
```

---

### Option 2: Custom Feature Flag System

```typescript
// lib/feature-flags.ts
interface FeatureFlag {
  key: string
  enabled: boolean
  rules?: {
    percentage?: number // 0-100
    users?: string[]    // Specific user IDs
    roles?: string[]    // Specific roles
  }
}

// Stored in backend or KV store
const featureFlags: Record<string, FeatureFlag> = {
  enableComplianceAdmin: {
    key: 'enableComplianceAdmin',
    enabled: true,
    rules: {
      percentage: 50, // 50% rollout
      users: ['user-123', 'user-456'], // Always enabled for these users
      roles: ['admin'], // Always enabled for admins
    },
  },
}

export function checkFeatureFlag(
  flagKey: string,
  user?: User
): boolean {
  const flag = featureFlags[flagKey]

  if (!flag || !flag.enabled) {
    return false
  }

  // Always enabled for specific users
  if (flag.rules?.users?.includes(user?.id ?? '')) {
    return true
  }

  // Always enabled for specific roles
  if (flag.rules?.roles?.includes(user?.role ?? '')) {
    return true
  }

  // Percentage-based rollout (consistent hashing)
  if (flag.rules?.percentage) {
    const hash = hashString(user?.id ?? 'anonymous')
    const bucket = hash % 100
    return bucket < flag.rules.percentage
  }

  return flag.enabled
}

function hashString(str: string): number {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i)
    hash = hash & hash // Convert to 32-bit integer
  }
  return Math.abs(hash)
}
```

---

## Rollback Strategy

### Immediate Rollback (< 5 minutes)

```bash
# If critical issue detected, disable flag immediately
ff-cli disable enableComplianceAdmin --env production --now

# Or set percentage to 0
ff-cli enable enableComplianceAdmin --env production --percentage 0

# Verify
ff-cli status enableComplianceAdmin --env production
# Output: Status: OFF for all users
```

**No redeployment needed!** Feature instantly hidden for all users.

---

## Feature Flag Dashboard

### Monitoring Dashboard (Example)

```
┌──────────────────────────────────────────────────┐
│  Feature Flags - Production                      │
├──────────────────────────────────────────────────┤
│  Flag: enableComplianceAdmin                     │
│  Status: ON (50% rollout)                        │
│  Users affected: 5,234 (of 10,468)              │
│  Error rate: 0.02% ✅                            │
│  Response time: 245ms (P95) ✅                   │
│  Support tickets: 2 (low) ✅                     │
│  Created: 2025-11-01 | Rollout: 2025-11-15      │
├──────────────────────────────────────────────────┤
│  Flag: enableInvoiceApprovalWorkflow             │
│  Status: ON (10% rollout)                        │
│  Users affected: 1,047 (of 10,468)              │
│  Error rate: 0.05% ✅                            │
│  Response time: 312ms (P95) ✅                   │
│  Support tickets: 0 ✅                           │
│  Created: 2025-12-01 | Rollout: 2025-12-02      │
└──────────────────────────────────────────────────┘
```

---

## Best Practices

### DO ✅

1. **Always use feature flags for new features**
   - Even small features should be flagged
   - Deploy dark (OFF) to production

2. **Test with flags OFF**
   - Ensure feature is completely hidden
   - No errors when flag is disabled

3. **Monitor during rollout**
   - Error rates, performance, user feedback
   - Have rollback plan ready

4. **Clean up old flags**
   - Remove flags after 2 weeks of 100% rollout
   - Don't accumulate flag debt

5. **Document rollout plan**
   - Timeline for 10% → 50% → 100%
   - Success criteria for each phase

### DON'T ❌

1. **Don't skip gradual rollout**
   - Never go 0% → 100% immediately
   - Always test with 10% first

2. **Don't forget cleanup**
   - Old flags create technical debt
   - Schedule cleanup 2 weeks after full rollout

3. **Don't use flags for A/B testing**
   - Use proper A/B testing tools for experiments
   - Flags are for rollout control, not experimentation

4. **Don't nest flags deeply**
   - Keep flag checks simple
   - Avoid `if (flagA && (flagB || flagC))` logic

5. **Don't hardcode flag values**
   - Always use flag service
   - Never `const enabled = true` in code

---

## Feature Flag Checklist

### Before Development
- [ ] Feature flag created in flag service
- [ ] Flag default: OFF in production
- [ ] Flag naming follows convention (`enable{FeatureName}`)
- [ ] Flag documented in ticket/PR

### During Development
- [ ] Flag checks added to code (routes, components, API)
- [ ] Feature hidden when flag is OFF
- [ ] No errors when flag is OFF
- [ ] Tests include flag ON and OFF scenarios

### Before Staging Deployment
- [ ] Flag enabled for staging environment
- [ ] QA can toggle flag for testing
- [ ] Smoke tests pass with flag ON and OFF

### Before Production Deployment
- [ ] Flag OFF by default in production
- [ ] Rollout plan documented (10% → 50% → 100%)
- [ ] Success metrics defined
- [ ] Monitoring dashboard set up
- [ ] Rollback plan documented

### During Rollout
- [ ] 10% rollout for 48 hours (monitor)
- [ ] 50% rollout for 1 week (monitor)
- [ ] 100% rollout for 2 weeks (monitor)
- [ ] No critical issues detected

### Cleanup (After 2 Weeks)
- [ ] Flag enabled 100% with no issues
- [ ] Feature widely adopted
- [ ] Flag checks removed from code
- [ ] Flag deleted from flag service
- [ ] Cleanup PR merged

---

## Troubleshooting

### Issue: Flag not taking effect

**Symptoms**: Feature visible even though flag is OFF

**Diagnosis**:
```bash
# 1. Check flag status
ff-cli status enableComplianceAdmin --env production

# 2. Check user's flag value
ff-cli check enableComplianceAdmin --user user@example.com --env production

# 3. Clear cache (if caching flags)
ff-cli cache clear
```

**Solution**:
- Verify flag is actually OFF
- Check for caching issues
- Verify user is not in "always enabled" group

---

### Issue: Flag causes errors

**Symptoms**: Errors in Sentry when flag is enabled

**Diagnosis**:
```bash
# 1. Disable flag immediately
ff-cli disable enableComplianceAdmin --env production --now

# 2. Check error logs
sentry-cli search "enableComplianceAdmin"

# 3. Review recent deployments
git log --oneline --since="1 week ago" | grep compliance
```

**Solution**:
- Rollback flag to 0%
- Fix bugs in staging
- Re-test before re-enabling

---

## Examples from Phase 1A Features

### Compliance Guidelines (Story #1)

```typescript
// Flag: enableComplianceAdmin
// Rollout: Nov 18 (deploy) → Nov 22 (10%) → Nov 29 (50%) → Dec 6 (100%)

// Route protection
{
  path: '/admin/compliance/guidelines',
  element: (
    <ProtectedRoute
      flagKey="enableComplianceAdmin"
      element={<GuidelinesPage />}
    />
  ),
}

// Navigation item
{complianceEnabled && (
  <NavGroup title="Compliance">
    <NavItem href="/admin/compliance/guidelines">Guidelines</NavItem>
    <NavItem href="/admin/compliance/policies">Policies</NavItem>
  </NavGroup>
)}
```

---

### Invoice Approval Workflow (Story #5)

```typescript
// Flag: enableInvoiceApprovalWorkflow
// Rollout: Dec 2 (deploy) → Dec 5 (10%) → Dec 12 (50%) → Dec 19 (100%)

// Route protection
{
  path: '/finance/approvals',
  element: (
    <ProtectedRoute
      flagKey="enableInvoiceApprovalWorkflow"
      element={<ApprovalsPage />}
    />
  ),
}

// Backend API protection
app.get('/api/finance/invoices/pending-approval', async (c) => {
  const enabled = await checkFeatureFlag(
    'enableInvoiceApprovalWorkflow',
    c.get('user')
  )

  if (!enabled) {
    return c.json({ error: 'Feature not available' }, 403)
  }

  // ... normal logic
})
```

---

## Summary

**Feature flags are mandatory for all new features.**

**Lifecycle**:
1. Create flag (OFF by default)
2. Develop with flag ON in dev
3. Test with flag ON in staging
4. Deploy with flag OFF in production
5. Enable for internal users (beta)
6. Gradual rollout (10% → 50% → 100%)
7. Monitor for 2 weeks
8. Clean up (remove flag)

**Timeline**: ~4 weeks from deploy to cleanup
**Benefit**: Zero-downtime deployments, instant rollback, gradual risk mitigation

---

**Feature Flag Strategy Complete** ✅

**Questions?** Contact DevOps team or Engineering Lead.

