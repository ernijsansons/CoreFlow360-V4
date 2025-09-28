# Deployment & Operations Guide

## Prerequisites

### Required Accounts
- **Cloudflare Account** with Workers subscription
- **Anthropic API Key** for Claude integration
- **GitHub Account** for source control
- **Domain Name** configured with Cloudflare DNS

### Development Tools
```bash
# Required versions
node >= 18.0.0
npm >= 9.0.0
wrangler >= 3.0.0

# Install Wrangler CLI
npm install -g wrangler

# Authenticate with Cloudflare
wrangler login
```

## Environment Setup

### 1. Clone Repository
```bash
git clone https://github.com/your-org/coreflow360-v4.git
cd coreflow360-v4
npm install
```

### 2. Environment Configuration

Create `.env` files for each environment:

#### `.env.development`
```env
# Core Configuration
ENVIRONMENT=development
APP_URL=http://localhost:8787
FRONTEND_URL=http://localhost:5173

# Security Keys (Generate secure keys for production)
JWT_SECRET=development-secret-min-32-chars-required-change-this
ENCRYPTION_KEY=development-encryption-key-32-chars-minimum
SESSION_SECRET=development-session-secret-32-chars

# AI Integration
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
OPENAI_API_KEY=sk-xxxxx  # Optional

# Database Configuration
DATABASE_URL=file:./dev.db
```

#### `.env.production`
```env
# Core Configuration
ENVIRONMENT=production
APP_URL=https://api.coreflow360.com
FRONTEND_URL=https://app.coreflow360.com

# Security Keys (Use secure generation)
JWT_SECRET=${SECRET_JWT_KEY}
ENCRYPTION_KEY=${SECRET_ENCRYPTION_KEY}
SESSION_SECRET=${SECRET_SESSION_KEY}

# AI Integration
ANTHROPIC_API_KEY=${SECRET_ANTHROPIC_KEY}

# External Services
STRIPE_SECRET_KEY=${SECRET_STRIPE_KEY}
SENDGRID_API_KEY=${SECRET_SENDGRID_KEY}
TWILIO_AUTH_TOKEN=${SECRET_TWILIO_TOKEN}
```

### 3. Wrangler Configuration

#### `wrangler.toml`
```toml
name = "coreflow360-v4"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[env.production]
name = "coreflow360-v4-prod"
routes = [
  { pattern = "api.coreflow360.com/*", zone_name = "coreflow360.com" }
]

[[kv_namespaces]]
binding = "KV_CACHE"
id = "your-kv-namespace-id"

[[kv_namespaces]]
binding = "KV_SESSION"
id = "your-session-kv-id"

[[d1_databases]]
binding = "DB_MAIN"
database_name = "coreflow360-main"
database_id = "your-d1-database-id"

[[r2_buckets]]
binding = "R2_STORAGE"
bucket_name = "coreflow360-storage"

[[durable_objects.bindings]]
name = "WORKFLOW_ENGINE"
class_name = "WorkflowEngine"
script_name = "coreflow360-v4"

[[durable_objects.bindings]]
name = "REALTIME_COORDINATOR"
class_name = "RealtimeCoordinator"
script_name = "coreflow360-v4"

[build]
command = "npm run build"

[build.upload]
format = "modules"
main = "./dist/index.js"

[[migrations]]
tag = "v1"
new_classes = ["WorkflowEngine", "RealtimeCoordinator"]
```

## Deployment Process

### 1. Local Development
```bash
# Start development server
npm run dev

# Run tests
npm test

# Type checking
npm run type-check

# Linting
npm run lint
```

### 2. Database Setup

#### Initialize D1 Database
```bash
# Create database
wrangler d1 create coreflow360-main

# Run migrations
wrangler d1 execute coreflow360-main --file=./migrations/001_initial.sql
wrangler d1 execute coreflow360-main --file=./migrations/002_indexes.sql
wrangler d1 execute coreflow360-main --file=./migrations/003_audit_tables.sql
```

#### Migration Scripts
```sql
-- migrations/001_initial.sql
CREATE TABLE IF NOT EXISTS businesses (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  industry TEXT,
  employee_count TEXT,
  subscription_tier TEXT DEFAULT 'free',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  first_name TEXT,
  last_name TEXT,
  business_id TEXT REFERENCES businesses(id),
  role TEXT DEFAULT 'user',
  two_factor_enabled BOOLEAN DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_business ON users(business_id);
```

### 3. Build & Deploy

#### Staging Deployment
```bash
# Build the application
npm run build

# Deploy to staging
wrangler deploy --env staging

# Run smoke tests
npm run test:e2e:staging
```

#### Production Deployment
```bash
# Create production build
npm run build:production

# Run pre-deployment checks
npm run predeploy:check

# Deploy to production
wrangler deploy --env production

# Verify deployment
npm run verify:production
```

### 4. Secret Management

```bash
# Add secrets to Cloudflare Workers
wrangler secret put JWT_SECRET --env production
wrangler secret put ENCRYPTION_KEY --env production
wrangler secret put ANTHROPIC_API_KEY --env production
wrangler secret put STRIPE_SECRET_KEY --env production
```

## Monitoring & Operations

### 1. Health Checks

#### Automated Health Monitoring
```typescript
// Health check endpoint
app.get('/health', async (c) => {
  const checks = {
    api: 'healthy',
    database: await checkDatabase(),
    cache: await checkCache(),
    ai: await checkAIService(),
    queues: await checkQueues()
  };

  const healthy = Object.values(checks).every(s => s === 'healthy');

  return c.json({
    status: healthy ? 'healthy' : 'degraded',
    checks,
    timestamp: new Date().toISOString()
  }, healthy ? 200 : 503);
});
```

### 2. Logging & Monitoring

#### Cloudflare Analytics
```bash
# View real-time logs
wrangler tail --env production

# Get analytics data
wrangler analytics --env production
```

#### Custom Logging
```typescript
class Logger {
  log(level: string, message: string, metadata?: any) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      ...metadata,
      environment: env.ENVIRONMENT
    };

    // Send to logging service
    if (env.ENVIRONMENT === 'production') {
      this.sendToLogService(logEntry);
    }

    console.log(JSON.stringify(logEntry));
  }
}
```

### 3. Performance Monitoring

```typescript
class PerformanceMonitor {
  async trackRequest(request: Request, response: Response) {
    const metrics = {
      url: request.url,
      method: request.method,
      status: response.status,
      duration: performance.now() - request.startTime,
      timestamp: Date.now()
    };

    // Send to analytics
    await env.ANALYTICS.writeDataPoint(metrics);

    // Alert on slow requests
    if (metrics.duration > 3000) {
      await this.alertSlowRequest(metrics);
    }
  }
}
```

## Scaling Strategies

### 1. Database Sharding

```typescript
class DatabaseSharding {
  getDatabase(businessId: string): D1Database {
    const shard = this.calculateShard(businessId);
    return this.databases[`DB_SHARD_${shard}`];
  }

  calculateShard(businessId: string): number {
    const hash = this.hashString(businessId);
    return hash % this.totalShards;
  }
}
```

### 2. Cache Strategy

```typescript
const CacheStrategy = {
  // Short-lived cache for frequently changing data
  session: { ttl: 900 },        // 15 minutes
  userProfile: { ttl: 3600 },   // 1 hour

  // Long-lived cache for stable data
  businessConfig: { ttl: 86400 }, // 24 hours
  staticAssets: { ttl: 2592000 }, // 30 days

  // Invalidation patterns
  invalidateOnUpdate: [
    'userProfile',
    'businessConfig'
  ]
};
```

### 3. Rate Limiting Configuration

```typescript
const RateLimits = {
  // Per IP limits
  global: { requests: 1000, window: 60 },

  // Per user limits
  authenticated: { requests: 5000, window: 60 },

  // Per business limits based on tier
  tiers: {
    free: { requests: 1000, window: 60 },
    starter: { requests: 5000, window: 60 },
    professional: { requests: 20000, window: 60 },
    enterprise: { requests: 100000, window: 60 }
  }
};
```

## Troubleshooting Guide

### Common Issues

#### 1. Database Connection Errors
```bash
# Check D1 status
wrangler d1 list

# Test database connection
wrangler d1 execute DB_MAIN --command="SELECT 1"

# Reset database connection
wrangler d1 execute DB_MAIN --file=./scripts/reset-connections.sql
```

#### 2. High Memory Usage
```typescript
// Memory optimization
class MemoryManager {
  async optimizeMemory() {
    // Clear unused caches
    await this.clearExpiredCaches();

    // Garbage collection hint
    if (global.gc) {
      global.gc();
    }

    // Monitor memory usage
    const usage = process.memoryUsage();
    if (usage.heapUsed / usage.heapTotal > 0.9) {
      await this.emergencyCleanup();
    }
  }
}
```

#### 3. AI Service Timeouts
```typescript
// Retry logic for AI services
class AIServiceWithRetry {
  async execute(task: any, maxRetries = 3) {
    for (let i = 0; i < maxRetries; i++) {
      try {
        const timeout = 30000 * (i + 1); // Increase timeout
        return await this.executeWithTimeout(task, timeout);
      } catch (error) {
        if (i === maxRetries - 1) throw error;
        await this.delay(1000 * Math.pow(2, i)); // Exponential backoff
      }
    }
  }
}
```

#### 4. Authentication Issues
```bash
# Verify JWT secret is set
wrangler secret list --env production

# Test authentication endpoint
curl -X POST https://api.coreflow360.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test"}'

# Check session storage
wrangler kv:key list --binding=KV_SESSION --env production
```

## Rollback Procedures

### 1. Quick Rollback
```bash
# List deployments
wrangler deployments list --env production

# Rollback to previous version
wrangler rollback --env production

# Verify rollback
curl https://api.coreflow360.com/health
```

### 2. Database Rollback
```sql
-- Backup before changes
CREATE TABLE businesses_backup AS SELECT * FROM businesses;

-- Rollback procedure
BEGIN TRANSACTION;
DROP TABLE businesses;
ALTER TABLE businesses_backup RENAME TO businesses;
COMMIT;
```

### 3. Emergency Response
```typescript
class EmergencyResponse {
  async activateMaintenanceMode() {
    // Set maintenance flag
    await env.KV_CONFIG.put('maintenance_mode', 'true');

    // Return maintenance response
    return new Response('System maintenance in progress', {
      status: 503,
      headers: {
        'Retry-After': '300'
      }
    });
  }

  async disableFeature(feature: string) {
    const config = await env.KV_CONFIG.get('features', 'json');
    config[feature] = false;
    await env.KV_CONFIG.put('features', JSON.stringify(config));
  }
}
```

## Security Checklist

### Pre-Deployment
- [ ] All secrets are properly configured
- [ ] JWT_SECRET is unique and secure (32+ characters)
- [ ] Database migrations completed successfully
- [ ] Security headers configured
- [ ] Rate limiting enabled
- [ ] Input validation active
- [ ] Audit logging functional

### Post-Deployment
- [ ] Health checks passing
- [ ] Authentication working
- [ ] Database queries optimized
- [ ] Monitoring alerts configured
- [ ] Backup procedures tested
- [ ] Rollback plan documented
- [ ] Team trained on procedures

## Performance Optimization

### 1. Edge Caching
```typescript
const EdgeCache = {
  // Cache static assets at edge
  cacheStaticAssets(request: Request, response: Response) {
    if (this.isStaticAsset(request.url)) {
      response.headers.set('Cache-Control', 'public, max-age=31536000');
      response.headers.set('CDN-Cache-Control', 'max-age=31536000');
    }
    return response;
  }
};
```

### 2. Query Optimization
```typescript
// Use prepared statements
const preparedQueries = {
  getUser: db.prepare('SELECT * FROM users WHERE id = ?'),
  getBusinessUsers: db.prepare('SELECT * FROM users WHERE business_id = ?'),
  updateUserActivity: db.prepare('UPDATE users SET last_active = ? WHERE id = ?')
};
```

### 3. Connection Pooling
```typescript
class ConnectionPool {
  constructor(private maxConnections = 10) {
    this.connections = [];
  }

  async getConnection() {
    if (this.connections.length > 0) {
      return this.connections.pop();
    }
    return this.createConnection();
  }

  releaseConnection(conn: Connection) {
    if (this.connections.length < this.maxConnections) {
      this.connections.push(conn);
    }
  }
}
```

## Support Resources

- **Documentation**: https://docs.coreflow360.com
- **Status Page**: https://status.coreflow360.com
- **Support Portal**: https://support.coreflow360.com
- **Emergency Hotline**: +1-XXX-XXX-XXXX

## Appendix

### A. Environment Variable Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| JWT_SECRET | Yes | JWT signing secret | 32+ char random string |
| ENCRYPTION_KEY | Yes | Data encryption key | 32+ char random string |
| ANTHROPIC_API_KEY | Yes | Claude API key | sk-ant-api03-xxx |
| DATABASE_URL | Yes | Database connection | file:./db.sqlite |
| ENVIRONMENT | Yes | Environment name | production |
| APP_URL | Yes | API base URL | https://api.domain.com |

### B. Useful Commands

```bash
# View logs
wrangler tail --env production --format pretty

# Database operations
wrangler d1 backup create DB_MAIN
wrangler d1 backup list DB_MAIN
wrangler d1 backup restore DB_MAIN backup-id

# KV operations
wrangler kv:key list --binding=KV_CACHE
wrangler kv:key get --binding=KV_CACHE "key-name"
wrangler kv:key delete --binding=KV_CACHE "key-name"

# Performance analysis
wrangler analytics --env production --date-start 2024-01-01
```