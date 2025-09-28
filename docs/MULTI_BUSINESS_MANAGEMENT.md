# Multi-Business Management Architecture

## Overview

CoreFlow360 V4 provides comprehensive multi-business (multi-tenant) management capabilities, allowing a single deployment to serve multiple businesses with complete data isolation, security, and customization.

## Core Concepts

### 1. Tenant Isolation

Each business operates in complete isolation with:
- **Separate databases**: Logical or physical separation
- **Isolated KV namespaces**: Per-tenant caching and storage
- **Independent configurations**: Business-specific settings
- **Segregated audit logs**: Compliance and security tracking

### 2. Business Context

Every request carries business context through the system:

```typescript
interface BusinessContext {
  businessId: string;       // Unique business identifier
  tenantId: string;        // Tenant namespace
  userId: string;          // Current user
  sessionId: string;       // Active session
  role: string;            // User role in business
  permissions: string[];   // Granted permissions
  metadata: {
    subscription: string;  // Subscription tier
    features: string[];    // Enabled features
    limits: Record<string, number>;  // Resource limits
  };
}
```

## Architecture Components

### 1. Tenant Router
**Location**: `src/middleware/tenant-isolation.ts`

Routes requests to appropriate tenant resources:

```typescript
export function tenantIsolation(): MiddlewareHandler {
  return async (c, next) => {
    const businessId = extractBusinessId(c);
    const tenantContext = await loadTenantContext(businessId);

    // Inject tenant-specific resources
    c.set('db', getTenantDatabase(tenantContext));
    c.set('kv', getTenantKV(tenantContext));
    c.set('businessContext', tenantContext);

    await next();
  };
}
```

### 2. Database Isolation
**Location**: `src/database/tenant-isolated-db.ts`

Multiple isolation strategies:

#### Strategy 1: Schema Isolation (Recommended)
```typescript
class SchemaIsolatedDB {
  async query(sql: string, businessId: string) {
    // Prefix all tables with business ID
    const isolatedSQL = sql.replace(
      /FROM (\w+)/g,
      `FROM ${businessId}.$1`
    );
    return this.db.prepare(isolatedSQL).all();
  }
}
```

#### Strategy 2: Row-Level Security
```typescript
class RowLevelSecurityDB {
  async query(sql: string, businessId: string) {
    // Add business_id filter to all queries
    return this.db.prepare(`
      ${sql} AND business_id = ?
    `).bind(businessId).all();
  }
}
```

#### Strategy 3: Database per Tenant
```typescript
class DatabasePerTenant {
  getDatabase(businessId: string): D1Database {
    return this.databases.get(businessId);
  }
}
```

### 3. Business Switching
**Location**: `src/modules/business-switch/client.ts`

Seamless switching between businesses for users with multiple memberships:

```typescript
class BusinessSwitchClient {
  async switchBusiness(userId: string, targetBusinessId: string) {
    // Validate user has access
    const membership = await this.validateMembership(userId, targetBusinessId);

    // Clear current session data
    await this.clearCurrentSession();

    // Load new business context
    const newContext = await this.loadBusinessContext(targetBusinessId);

    // Update session
    await this.updateSession({
      businessId: targetBusinessId,
      role: membership.role,
      permissions: membership.permissions
    });

    // Prefetch common data
    await this.prefetchBusinessData(targetBusinessId);

    return newContext;
  }
}
```

### 4. Permission Management
**Location**: `src/modules/abac/service.ts`

Attribute-Based Access Control per business:

```typescript
interface BusinessPermissions {
  // Owner permissions
  owner: ['*'];

  // Admin permissions
  admin: [
    'users:*',
    'settings:*',
    'finance:view',
    'finance:create',
    'finance:edit'
  ];

  // Manager permissions
  manager: [
    'users:view',
    'settings:view',
    'finance:view',
    'reports:*'
  ];

  // User permissions
  user: [
    'profile:*',
    'tasks:own',
    'reports:view'
  ];
}
```

## API Patterns

### 1. Business-Scoped Endpoints

All endpoints automatically scope to current business:

```typescript
// Routes automatically filtered by business
app.get('/api/customers', authenticate(), async (c) => {
  const businessId = c.get('businessId');
  const customers = await db.customers
    .where('business_id', businessId)
    .select();
  return c.json({ customers });
});
```

### 2. Cross-Business Operations

Special endpoints for cross-business operations:

```typescript
// List all businesses user has access to
app.get('/api/businesses', authenticate(), async (c) => {
  const userId = c.get('userId');
  const businesses = await db.businessMemberships
    .where('user_id', userId)
    .where('status', 'active')
    .join('businesses', 'id', 'business_id')
    .select();
  return c.json({ businesses });
});

// Switch active business
app.post('/api/businesses/switch', authenticate(), async (c) => {
  const { targetBusinessId } = await c.req.json();
  const result = await businessSwitch.switch(
    c.get('userId'),
    targetBusinessId
  );
  return c.json({ success: true, context: result });
});
```

### 3. Business Administration

Owner-only endpoints for business management:

```typescript
// Update business settings
app.put('/api/business/settings', requireRole('owner'), async (c) => {
  const businessId = c.get('businessId');
  const settings = await c.req.json();

  await db.businesses
    .where('id', businessId)
    .update(settings);

  await auditLog('business.settings.updated', {
    businessId,
    changes: settings
  });

  return c.json({ success: true });
});

// Manage team members
app.post('/api/business/members', requireRole('admin'), async (c) => {
  const { email, role } = await c.req.json();

  const invitation = await inviteUser({
    businessId: c.get('businessId'),
    email,
    role,
    invitedBy: c.get('userId')
  });

  return c.json({ invitation });
});
```

## Data Models

### 1. Business Entity

```typescript
interface Business {
  id: string;
  name: string;
  industry: string;
  employeeCount: string;
  subscription_tier: 'free' | 'starter' | 'professional' | 'enterprise';
  subscription_status: 'active' | 'past_due' | 'cancelled';
  settings: {
    timezone: string;
    currency: string;
    fiscal_year_start: string;
    tax_id?: string;
    address?: Address;
  };
  limits: {
    max_users: number;
    max_transactions: number;
    max_storage_gb: number;
    max_api_calls: number;
  };
  features: string[];  // Enabled features
  created_at: Date;
  updated_at: Date;
}
```

### 2. Business Membership

```typescript
interface BusinessMembership {
  id: string;
  business_id: string;
  user_id: string;
  role: 'owner' | 'admin' | 'manager' | 'user';
  department?: string;
  job_title?: string;
  permissions: string[];  // Additional custom permissions
  status: 'active' | 'invited' | 'suspended';
  invited_by?: string;
  joined_at?: Date;
  last_active?: Date;
}
```

### 3. Subscription Management

```typescript
interface Subscription {
  business_id: string;
  plan_id: string;
  status: 'trialing' | 'active' | 'past_due' | 'cancelled';
  current_period_start: Date;
  current_period_end: Date;
  cancel_at?: Date;
  cancelled_at?: Date;
  payment_method?: PaymentMethod;
  usage: {
    users: number;
    transactions: number;
    storage_gb: number;
    api_calls: number;
  };
}
```

## Security Considerations

### 1. Data Isolation Enforcement

```typescript
// Middleware ensures all queries are business-scoped
async function enforceDataIsolation(c: Context, next: Next) {
  const originalPrepare = c.env.DB.prepare;

  c.env.DB.prepare = function(query: string) {
    // Inject business_id into all queries
    const businessId = c.get('businessId');
    const safeQuery = injectBusinessFilter(query, businessId);
    return originalPrepare.call(this, safeQuery);
  };

  await next();
}
```

### 2. Cross-Tenant Attack Prevention

```typescript
// Validate business access on every request
async function validateBusinessAccess(c: Context) {
  const businessId = c.req.header('X-Business-ID');
  const userId = c.get('userId');

  const membership = await db.businessMemberships
    .where('user_id', userId)
    .where('business_id', businessId)
    .where('status', 'active')
    .first();

  if (!membership) {
    throw new UnauthorizedError('No access to this business');
  }

  return membership;
}
```

### 3. Audit Logging

```typescript
// Comprehensive audit logging per business
async function auditLog(event: string, data: any) {
  await db.auditLogs.insert({
    business_id: getCurrentBusinessId(),
    user_id: getCurrentUserId(),
    event,
    data,
    ip_address: getClientIP(),
    user_agent: getUserAgent(),
    timestamp: new Date()
  });
}
```

## Resource Management

### 1. Quota Enforcement

```typescript
class QuotaManager {
  async checkQuota(businessId: string, resource: string) {
    const usage = await this.getCurrentUsage(businessId);
    const limits = await this.getBusinessLimits(businessId);

    if (usage[resource] >= limits[resource]) {
      throw new QuotaExceededError(
        `${resource} quota exceeded. Current: ${usage[resource]}, Limit: ${limits[resource]}`
      );
    }
  }

  async incrementUsage(businessId: string, resource: string, amount = 1) {
    await this.kv.put(
      `usage:${businessId}:${resource}`,
      await this.getCurrentUsage(businessId, resource) + amount
    );
  }
}
```

### 2. Performance Isolation

```typescript
// Ensure one business cannot impact others
class PerformanceIsolator {
  async executeWithLimits(businessId: string, operation: Function) {
    const limits = await this.getBusinessLimits(businessId);

    return withTimeout(
      withMemoryLimit(
        withCPUThrottle(
          operation,
          limits.cpu_shares
        ),
        limits.memory_mb
      ),
      limits.timeout_ms
    );
  }
}
```

## Billing Integration

### 1. Usage Tracking

```typescript
class UsageTracker {
  async trackAPICall(businessId: string, endpoint: string) {
    const key = `usage:${businessId}:api:${getMonth()}`;
    await this.kv.increment(key);

    // Check if approaching limit
    const usage = await this.kv.get(key);
    const limit = await this.getAPILimit(businessId);

    if (usage > limit * 0.8) {
      await this.notifyApproachingLimit(businessId, 'api_calls', usage, limit);
    }
  }
}
```

### 2. Subscription Upgrades

```typescript
class SubscriptionManager {
  async upgradeSubscription(businessId: string, newPlan: string) {
    // Validate upgrade path
    const currentPlan = await this.getCurrentPlan(businessId);
    if (!this.canUpgrade(currentPlan, newPlan)) {
      throw new Error('Invalid upgrade path');
    }

    // Update subscription
    await this.updateSubscription(businessId, newPlan);

    // Apply new limits immediately
    await this.applyPlanLimits(businessId, newPlan);

    // Enable new features
    await this.enablePlanFeatures(businessId, newPlan);

    // Notify users
    await this.notifyUpgrade(businessId, newPlan);
  }
}
```

## Migration Support

### 1. Onboarding New Businesses

```typescript
class BusinessOnboarding {
  async onboardNewBusiness(data: OnboardingData) {
    // Create business record
    const business = await this.createBusiness(data);

    // Set up database schema
    await this.initializeDatabase(business.id);

    // Create default accounts (Chart of Accounts)
    await this.createDefaultAccounts(business.id);

    // Set up default workflows
    await this.createDefaultWorkflows(business.id);

    // Initialize AI agents
    await this.initializeAgents(business.id);

    // Send welcome emails
    await this.sendWelcomeKit(business);

    return business;
  }
}
```

### 2. Data Import/Export

```typescript
class DataMigration {
  async importBusinessData(businessId: string, data: ImportData) {
    // Validate import format
    await this.validateImportData(data);

    // Create backup point
    const backupId = await this.createBackup(businessId);

    try {
      // Import in transaction
      await this.db.transaction(async (tx) => {
        await this.importCustomers(tx, businessId, data.customers);
        await this.importTransactions(tx, businessId, data.transactions);
        await this.importInvoices(tx, businessId, data.invoices);
      });

      // Verify data integrity
      await this.verifyImportedData(businessId);

    } catch (error) {
      // Rollback on error
      await this.restoreBackup(businessId, backupId);
      throw error;
    }
  }

  async exportBusinessData(businessId: string) {
    return {
      business: await this.exportBusinessInfo(businessId),
      users: await this.exportUsers(businessId),
      customers: await this.exportCustomers(businessId),
      transactions: await this.exportTransactions(businessId),
      documents: await this.exportDocuments(businessId)
    };
  }
}
```

## Monitoring & Analytics

### 1. Business Health Dashboard

```typescript
interface BusinessHealth {
  businessId: string;
  metrics: {
    activeUsers: number;
    apiUsage: number;
    storageUsed: number;
    errorRate: number;
    responseTime: number;
  };
  alerts: Alert[];
  recommendations: string[];
}
```

### 2. Cross-Business Analytics (Admin Only)

```typescript
class AdminAnalytics {
  async getSystemOverview() {
    return {
      totalBusinesses: await this.countActiveBusinesses(),
      totalUsers: await this.countActiveUsers(),
      revenueMetrics: await this.calculateRevenue(),
      usagePatterns: await this.analyzeUsagePatterns(),
      growthMetrics: await this.calculateGrowth()
    };
  }
}
```

## Best Practices

### 1. Business Context Handling
- Always validate business context on every request
- Never trust client-provided business IDs without verification
- Use middleware for consistent context injection

### 2. Data Isolation
- Implement multiple layers of isolation (database, application, network)
- Regular audits to ensure no data leakage
- Use database views for additional security

### 3. Performance
- Cache business context for session duration
- Use connection pooling per tenant for database efficiency
- Implement fair resource scheduling

### 4. Compliance
- Maintain separate audit logs per business
- Implement data retention policies per business requirements
- Support data export for GDPR compliance

### 5. Scaling
- Design for horizontal scaling from day one
- Use sharding strategies for large deployments
- Implement gradual rollout for feature updates

## Troubleshooting

### Common Issues

1. **Cross-tenant data visibility**
   - Check middleware configuration
   - Verify database query isolation
   - Review audit logs for access patterns

2. **Performance degradation**
   - Check resource quotas
   - Review query patterns
   - Analyze cache hit rates

3. **Permission errors**
   - Verify user membership status
   - Check role assignments
   - Review ABAC policies

4. **Business switching issues**
   - Clear browser cache
   - Verify session management
   - Check prefetch operations

## Support Resources

- **Documentation**: `/docs/multi-tenant`
- **API Reference**: `/docs/openapi.yaml`
- **Support**: support@coreflow360.com
- **Status Page**: status.coreflow360.com