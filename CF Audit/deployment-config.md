# CoreFlow360 V4 - Production Deployment Configuration

## wrangler.toml - Production Configuration

```toml
name = "coreflow360-v4-prod"
main = "src/index.ts"
compatibility_date = "2025-09-28"
compatibility_flags = ["nodejs_compat"]

[env.production]
workers_dev = false
route = { pattern = "api.coreflow360.com/*", zone_name = "coreflow360.com" }

[env.production.vars]
ENVIRONMENT = "production"
ALLOWED_ORIGINS = "https://app.coreflow360.com,https://dashboard.coreflow360.com"
LOG_LEVEL = "error"
ENABLE_ANALYTICS = "true"
ENABLE_SECURITY_HEADERS = "true"
RATE_LIMIT_ENABLED = "true"
MAINTENANCE_MODE = "false"

# Sensitive vars should be set via wrangler secret
# wrangler secret put JWT_SECRET --env production
# wrangler secret put ENCRYPTION_KEY --env production
# wrangler secret put STRIPE_SECRET_KEY --env production
# wrangler secret put STRIPE_WEBHOOK_SECRET --env production
# wrangler secret put ANTHROPIC_API_KEY --env production
# wrangler secret put OPENAI_API_KEY --env production
# wrangler secret put SENDGRID_API_KEY --env production
# wrangler secret put TURNSTILE_SECRET --env production
# wrangler secret put SENTRY_DSN --env production

[[env.production.d1_databases]]
binding = "DB"
database_name = "coreflow360-prod"
database_id = "your-d1-database-id"

[[env.production.kv_namespaces]]
binding = "KV_AUTH"
id = "your-kv-auth-namespace-id"

[[env.production.kv_namespaces]]
binding = "KV_CACHE"
id = "your-kv-cache-namespace-id"

[[env.production.kv_namespaces]]
binding = "KV_SESSIONS"
id = "your-kv-sessions-namespace-id"

[[env.production.r2_buckets]]
binding = "R2_STORAGE"
bucket_name = "coreflow360-documents"

[[env.production.r2_buckets]]
binding = "R2_BACKUPS"
bucket_name = "coreflow360-backups"

[[env.production.durable_objects]]
binding = "RATE_LIMITER"
class_name = "RateLimiter"

[[env.production.durable_objects]]
binding = "WEBSOCKET_HANDLER"
class_name = "WebSocketHandler"

[[env.production.queues]]
binding = "EMAIL_QUEUE"
queue = "email-queue"

[[env.production.queues]]
binding = "ANALYTICS_QUEUE"
queue = "analytics-queue"

[[env.production.services]]
binding = "AI_GATEWAY"
service = "coreflow360-ai-gateway"

[env.production.ai]
binding = "AI"

[env.staging]
workers_dev = true
route = { pattern = "staging-api.coreflow360.com/*", zone_name = "coreflow360.com" }

[env.staging.vars]
ENVIRONMENT = "staging"
ALLOWED_ORIGINS = "https://staging.coreflow360.com"
LOG_LEVEL = "info"
ENABLE_ANALYTICS = "true"
ENABLE_SECURITY_HEADERS = "true"
RATE_LIMIT_ENABLED = "true"

[[env.staging.d1_databases]]
binding = "DB"
database_name = "coreflow360-staging"
database_id = "your-staging-d1-database-id"

[env.development]
workers_dev = true

[env.development.vars]
ENVIRONMENT = "development"
ALLOWED_ORIGINS = "*"
LOG_LEVEL = "debug"
ENABLE_ANALYTICS = "false"
ENABLE_SECURITY_HEADERS = "true"
RATE_LIMIT_ENABLED = "false"

[[env.development.d1_databases]]
binding = "DB"
database_name = "coreflow360-dev"
database_id = "your-dev-d1-database-id"
```

## Environment Setup Script

```bash
#!/bin/bash

# setup-environment.sh
# Run this script to configure a new environment

set -e

ENVIRONMENT=${1:-development}

echo "Setting up CoreFlow360 V4 environment: $ENVIRONMENT"

# Create D1 Database
echo "Creating D1 database..."
wrangler d1 create coreflow360-$ENVIRONMENT

# Create KV Namespaces
echo "Creating KV namespaces..."
wrangler kv:namespace create KV_AUTH --env $ENVIRONMENT
wrangler kv:namespace create KV_CACHE --env $ENVIRONMENT
wrangler kv:namespace create KV_SESSIONS --env $ENVIRONMENT

# Create R2 Buckets
echo "Creating R2 buckets..."
wrangler r2 bucket create coreflow360-documents-$ENVIRONMENT
wrangler r2 bucket create coreflow360-backups-$ENVIRONMENT

# Create Queues
echo "Creating queues..."
wrangler queues create email-queue-$ENVIRONMENT
wrangler queues create analytics-queue-$ENVIRONMENT

# Set Secrets (Interactive)
echo "Setting up secrets..."
read -p "Enter JWT_SECRET: " JWT_SECRET
wrangler secret put JWT_SECRET --env $ENVIRONMENT <<< "$JWT_SECRET"

read -p "Enter ENCRYPTION_KEY (32 chars): " ENCRYPTION_KEY
wrangler secret put ENCRYPTION_KEY --env $ENVIRONMENT <<< "$ENCRYPTION_KEY"

read -p "Enter STRIPE_SECRET_KEY: " STRIPE_SECRET_KEY
wrangler secret put STRIPE_SECRET_KEY --env $ENVIRONMENT <<< "$STRIPE_SECRET_KEY"

read -p "Enter STRIPE_WEBHOOK_SECRET: " STRIPE_WEBHOOK_SECRET
wrangler secret put STRIPE_WEBHOOK_SECRET --env $ENVIRONMENT <<< "$STRIPE_WEBHOOK_SECRET"

read -p "Enter ANTHROPIC_API_KEY: " ANTHROPIC_API_KEY
wrangler secret put ANTHROPIC_API_KEY --env $ENVIRONMENT <<< "$ANTHROPIC_API_KEY"

read -p "Enter TURNSTILE_SECRET: " TURNSTILE_SECRET
wrangler secret put TURNSTILE_SECRET --env $ENVIRONMENT <<< "$TURNSTILE_SECRET"

echo "Environment setup complete!"
```

## Database Migrations

```sql
-- migrations/001_initial_schema.sql
-- Run with: wrangler d1 execute coreflow360-prod --file migrations/001_initial_schema.sql

-- Businesses table
CREATE TABLE IF NOT EXISTS businesses (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT,
  plan TEXT DEFAULT 'starter',
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  trial_ends_at INTEGER,
  is_active INTEGER DEFAULT 1,
  settings TEXT DEFAULT '{}',
  metadata TEXT DEFAULT '{}',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER
);

CREATE INDEX idx_businesses_stripe_customer ON businesses(stripe_customer_id);
CREATE INDEX idx_businesses_plan ON businesses(plan);
CREATE INDEX idx_businesses_deleted_at ON businesses(deleted_at);

-- Users table with enhanced security
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  email_normalized TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  business_id TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_version INTEGER DEFAULT 2,
  salt TEXT NOT NULL,
  roles TEXT NOT NULL DEFAULT '["user"]',
  permissions TEXT NOT NULL DEFAULT '[]',
  is_active INTEGER DEFAULT 1,
  email_verified INTEGER DEFAULT 0,
  email_verification_token TEXT,
  email_verification_expires INTEGER,
  two_factor_enabled INTEGER DEFAULT 0,
  two_factor_secret TEXT,
  backup_codes TEXT,
  failed_login_attempts INTEGER DEFAULT 0,
  locked_until INTEGER,
  password_reset_token TEXT,
  password_reset_expires INTEGER,
  last_password_change INTEGER,
  password_history TEXT DEFAULT '[]',
  security_questions TEXT,
  avatar_url TEXT,
  phone TEXT,
  phone_verified INTEGER DEFAULT 0,
  timezone TEXT DEFAULT 'UTC',
  locale TEXT DEFAULT 'en',
  metadata TEXT DEFAULT '{}',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER,
  deleted_at INTEGER,
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_users_email_normalized ON users(email_normalized);
CREATE INDEX idx_users_business_id ON users(business_id);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token);
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token);

-- Sessions with enhanced tracking
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  fingerprint_hash TEXT NOT NULL,
  refresh_token_hash TEXT,
  expires_at INTEGER NOT NULL,
  idle_timeout INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_activity INTEGER NOT NULL,
  ip_address TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  device_id TEXT,
  device_name TEXT,
  location TEXT,
  risk_score INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  revoked_at INTEGER,
  revoked_reason TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_is_active ON sessions(is_active);

-- API Keys with comprehensive tracking
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  key_version INTEGER DEFAULT 1,
  permissions TEXT NOT NULL DEFAULT '[]',
  scopes TEXT DEFAULT '[]',
  rate_limit INTEGER DEFAULT 1000,
  rate_limit_window INTEGER DEFAULT 3600,
  allowed_ips TEXT,
  allowed_origins TEXT,
  allowed_methods TEXT DEFAULT '["GET","POST","PUT","DELETE"]',
  expires_at INTEGER,
  is_active INTEGER DEFAULT 1,
  last_used_at INTEGER,
  last_used_ip TEXT,
  usage_count INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  rotated_at INTEGER,
  rotated_from TEXT,
  revoked_at INTEGER,
  revoked_reason TEXT,
  revoked_by TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_api_keys_key_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_business_id ON api_keys(business_id);
CREATE INDEX idx_api_keys_is_active ON api_keys(is_active);

-- Comprehensive audit logging
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  event_category TEXT NOT NULL,
  severity TEXT DEFAULT 'info',
  user_id TEXT,
  business_id TEXT,
  session_id TEXT,
  api_key_id TEXT,
  resource_type TEXT,
  resource_id TEXT,
  action TEXT NOT NULL,
  result TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  request_method TEXT,
  request_path TEXT,
  request_body TEXT,
  response_status INTEGER,
  response_time INTEGER,
  details TEXT,
  error_message TEXT,
  stack_trace TEXT,
  risk_score INTEGER DEFAULT 0,
  threat_indicators TEXT,
  compliance_flags TEXT,
  timestamp INTEGER NOT NULL
);

CREATE INDEX idx_audit_business_id ON audit_logs(business_id);
CREATE INDEX idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_severity ON audit_logs(severity);
CREATE INDEX idx_audit_risk_score ON audit_logs(risk_score);

-- Security events for threat detection
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  threat_level TEXT NOT NULL, -- 'low', 'medium', 'high', 'critical'
  user_id TEXT,
  business_id TEXT,
  ip_address TEXT,
  geo_location TEXT,
  details TEXT NOT NULL,
  indicators TEXT,
  mitigated INTEGER DEFAULT 0,
  mitigation_action TEXT,
  mitigation_timestamp INTEGER,
  false_positive INTEGER DEFAULT 0,
  reviewed_by TEXT,
  reviewed_at INTEGER,
  timestamp INTEGER NOT NULL
);

CREATE INDEX idx_security_events_threat_level ON security_events(threat_level);
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
CREATE INDEX idx_security_events_mitigated ON security_events(mitigated);

-- Encryption key management
CREATE TABLE IF NOT EXISTS encryption_keys (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  key_type TEXT NOT NULL, -- 'master', 'data', 'pii', 'backup'
  key_version INTEGER NOT NULL,
  encrypted_key TEXT NOT NULL,
  key_metadata TEXT,
  algorithm TEXT NOT NULL,
  key_size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  rotated_from TEXT,
  rotated_at INTEGER,
  expires_at INTEGER,
  is_active INTEGER DEFAULT 1,
  destroyed_at INTEGER,
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_encryption_keys_business_id ON encryption_keys(business_id);
CREATE INDEX idx_encryption_keys_key_type ON encryption_keys(key_type);
CREATE INDEX idx_encryption_keys_version ON encryption_keys(key_version);
CREATE INDEX idx_encryption_keys_is_active ON encryption_keys(is_active);

-- Rate limiting configuration
CREATE TABLE IF NOT EXISTS rate_limit_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  endpoint_pattern TEXT NOT NULL,
  method_pattern TEXT DEFAULT '*',
  max_requests INTEGER NOT NULL,
  window_seconds INTEGER NOT NULL,
  burst_size INTEGER,
  applies_to TEXT NOT NULL, -- 'ip', 'user', 'api_key', 'business', 'global'
  tier TEXT, -- 'free', 'starter', 'pro', 'enterprise'
  priority INTEGER DEFAULT 0,
  action TEXT DEFAULT 'block', -- 'block', 'throttle', 'challenge'
  custom_response TEXT,
  bypass_tokens TEXT,
  is_active INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  created_by TEXT NOT NULL
);

CREATE INDEX idx_rate_limit_rules_endpoint ON rate_limit_rules(endpoint_pattern);
CREATE INDEX idx_rate_limit_rules_applies_to ON rate_limit_rules(applies_to);
CREATE INDEX idx_rate_limit_rules_priority ON rate_limit_rules(priority);
CREATE INDEX idx_rate_limit_rules_is_active ON rate_limit_rules(is_active);

-- Compliance and data governance
CREATE TABLE IF NOT EXISTS compliance_logs (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  compliance_type TEXT NOT NULL, -- 'GDPR', 'CCPA', 'HIPAA', 'SOC2', 'ISO27001'
  requirement TEXT NOT NULL,
  action TEXT NOT NULL,
  user_id TEXT,
  data_subject_id TEXT,
  data_categories TEXT,
  lawful_basis TEXT,
  consent_id TEXT,
  retention_period INTEGER,
  status TEXT NOT NULL, -- 'pending', 'in_progress', 'completed', 'failed'
  evidence TEXT,
  auditor_notes TEXT,
  verified_by TEXT,
  verified_at INTEGER,
  expires_at INTEGER,
  timestamp INTEGER NOT NULL,
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_compliance_business_id ON compliance_logs(business_id);
CREATE INDEX idx_compliance_type ON compliance_logs(compliance_type);
CREATE INDEX idx_compliance_status ON compliance_logs(status);
CREATE INDEX idx_compliance_timestamp ON compliance_logs(timestamp);

-- Data processing activities (GDPR Article 30)
CREATE TABLE IF NOT EXISTS data_processing_activities (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  activity_name TEXT NOT NULL,
  purpose TEXT NOT NULL,
  legal_basis TEXT NOT NULL,
  data_categories TEXT NOT NULL,
  data_subjects TEXT NOT NULL,
  recipients TEXT,
  international_transfers TEXT,
  retention_period TEXT NOT NULL,
  security_measures TEXT NOT NULL,
  dpia_required INTEGER DEFAULT 0,
  dpia_completed INTEGER DEFAULT 0,
  dpia_document_url TEXT,
  is_active INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  reviewed_at INTEGER,
  next_review_date INTEGER,
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_dpa_business_id ON data_processing_activities(business_id);
CREATE INDEX idx_dpa_is_active ON data_processing_activities(is_active);

-- Feature flags for gradual rollouts
CREATE TABLE IF NOT EXISTS feature_flags (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  flag_type TEXT NOT NULL, -- 'boolean', 'percentage', 'variant'
  value TEXT NOT NULL,
  rules TEXT, -- JSON rules for targeting
  environments TEXT DEFAULT '["all"]',
  enabled_for_users TEXT, -- JSON array of user IDs
  enabled_for_businesses TEXT, -- JSON array of business IDs
  percentage_rollout INTEGER DEFAULT 0,
  variants TEXT, -- JSON for A/B testing
  is_active INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  expires_at INTEGER
);

CREATE INDEX idx_feature_flags_name ON feature_flags(name);
CREATE INDEX idx_feature_flags_is_active ON feature_flags(is_active);

-- Request logs for analytics
CREATE TABLE IF NOT EXISTS request_logs (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  response_time INTEGER NOT NULL,
  response_size INTEGER,
  user_id TEXT,
  business_id TEXT,
  api_key_id TEXT,
  ip_address TEXT,
  country TEXT,
  user_agent TEXT,
  referer TEXT,
  cache_status TEXT,
  error_code TEXT,
  error_message TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_request_logs_endpoint ON request_logs(endpoint);
CREATE INDEX idx_request_logs_user_id ON request_logs(user_id);
CREATE INDEX idx_request_logs_business_id ON request_logs(business_id);
CREATE INDEX idx_request_logs_created_at ON request_logs(created_at);
CREATE INDEX idx_request_logs_status_code ON request_logs(status_code);

-- Webhooks configuration
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events TEXT NOT NULL, -- JSON array of event types
  headers TEXT, -- JSON custom headers
  retry_policy TEXT DEFAULT '{"max_attempts": 3, "backoff": "exponential"}',
  is_active INTEGER DEFAULT 1,
  last_triggered_at INTEGER,
  last_success_at INTEGER,
  last_failure_at INTEGER,
  failure_count INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_webhooks_business_id ON webhooks(business_id);
CREATE INDEX idx_webhooks_is_active ON webhooks(is_active);

-- Webhook delivery logs
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  webhook_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  response_status INTEGER,
  response_body TEXT,
  response_time INTEGER,
  attempt_number INTEGER DEFAULT 1,
  next_retry_at INTEGER,
  delivered_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
);

CREATE INDEX idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_created_at ON webhook_deliveries(created_at);
CREATE INDEX idx_webhook_deliveries_next_retry_at ON webhook_deliveries(next_retry_at);
```

## Security Headers Configuration

```typescript
// security-headers.ts
export const SECURITY_HEADERS = {
  // Prevent XSS attacks
  'X-XSS-Protection': '1; mode=block',
  
  // Prevent clickjacking
  'X-Frame-Options': 'DENY',
  
  // Prevent MIME type sniffing
  'X-Content-Type-Options': 'nosniff',
  
  // Referrer policy for privacy
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  
  // Permissions policy
  'Permissions-Policy': [
    'accelerometer=()',
    'ambient-light-sensor=()',
    'autoplay=()',
    'battery=()',
    'camera=()',
    'cross-origin-isolated=()',
    'display-capture=()',
    'document-domain=()',
    'encrypted-media=()',
    'execution-while-not-rendered=()',
    'execution-while-out-of-viewport=()',
    'fullscreen=()',
    'geolocation=()',
    'gyroscope=()',
    'keyboard-map=()',
    'magnetometer=()',
    'microphone=()',
    'midi=()',
    'navigation-override=()',
    'payment=()',
    'picture-in-picture=()',
    'publickey-credentials-get=()',
    'screen-wake-lock=()',
    'sync-xhr=()',
    'usb=()',
    'web-share=()',
    'xr-spatial-tracking=()'
  ].join(', '),
  
  // Content Security Policy
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self' data:",
    "connect-src 'self' https://api.stripe.com https://api.anthropic.com",
    "frame-src 'self' https://challenges.cloudflare.com https://checkout.stripe.com",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
    "block-all-mixed-content"
  ].join('; '),
  
  // CORS headers
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  
  // HSTS
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  
  // Cache control for security
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
  'Pragma': 'no-cache',
  'Expires': '0',
  
  // Remove server identification
  'Server': 'CoreFlow360',
  
  // Report violations
  'Report-To': JSON.stringify({
    group: 'csp-violations',
    max_age: 10886400,
    endpoints: [{ url: 'https://api.coreflow360.com/csp-report' }]
  })
};
```

## Deployment Checklist

```markdown
# Pre-Deployment Checklist

## Security
- [ ] All secrets stored in Cloudflare Workers Secrets
- [ ] JWT secret rotation configured
- [ ] Encryption keys generated (min 256-bit)
- [ ] SSL/TLS certificates valid
- [ ] DNSSEC enabled on domain
- [ ] Cloudflare WAF rules configured
- [ ] Rate limiting rules active
- [ ] DDoS protection enabled
- [ ] Bot protection configured
- [ ] IP allowlisting for admin endpoints

## Database
- [ ] All migrations executed
- [ ] Indexes created and optimized
- [ ] Backup strategy implemented
- [ ] Point-in-time recovery tested
- [ ] Row-level security verified
- [ ] Connection pooling configured

## Authentication
- [ ] Password complexity requirements enforced
- [ ] Account lockout policy active
- [ ] 2FA available for all users
- [ ] Session management tested
- [ ] Token rotation working
- [ ] API key management functional

## Compliance
- [ ] GDPR endpoints functional
- [ ] CCPA compliance verified
- [ ] Data retention policies configured
- [ ] Audit logging enabled
- [ ] PII encryption active
- [ ] Cookie consent implemented
- [ ] Privacy policy updated
- [ ] Terms of service updated

## Monitoring
- [ ] Error tracking configured (Sentry)
- [ ] Performance monitoring active
- [ ] Uptime monitoring configured
- [ ] Log aggregation setup
- [ ] Alerting rules defined
- [ ] Security monitoring active
- [ ] Analytics tracking enabled

## Testing
- [ ] Unit tests passing (>80% coverage)
- [ ] Integration tests passing
- [ ] Security tests passing
- [ ] Performance tests passing
- [ ] Load testing completed
- [ ] Penetration testing scheduled
- [ ] Disaster recovery tested

## Documentation
- [ ] API documentation complete
- [ ] Security procedures documented
- [ ] Incident response plan ready
- [ ] Runbook created
- [ ] Architecture diagrams updated
- [ ] Deployment guide finalized

## Infrastructure
- [ ] Auto-scaling configured
- [ ] CDN cache rules set
- [ ] DNS records configured
- [ ] Health checks active
- [ ] Backup regions configured
- [ ] Failover tested

## Final Steps
- [ ] Production secrets rotated
- [ ] Staging environment validated
- [ ] Rollback plan documented
- [ ] Team training completed
- [ ] Support channels ready
- [ ] Launch communications prepared
```

## Post-Deployment Monitoring

```typescript
// monitoring.ts
export class ProductionMonitor {
  async checkHealth(): Promise<HealthStatus> {
    const checks = await Promise.all([
      this.checkDatabase(),
      this.checkCache(),
      this.checkAuth(),
      this.checkRateLimiting(),
      this.checkExternalAPIs(),
      this.checkStorage()
    ]);
    
    return {
      healthy: checks.every(c => c.healthy),
      checks,
      timestamp: new Date().toISOString()
    };
  }
  
  async checkSecurity(): Promise<SecurityStatus> {
    const [
      recentAttacks,
      failedLogins,
      anomalies,
      vulnerabilities
    ] = await Promise.all([
      this.getRecentAttacks(),
      this.getFailedLogins(),
      this.detectAnomalies(),
      this.scanVulnerabilities()
    ]);
    
    return {
      threatLevel: this.calculateThreatLevel(recentAttacks, anomalies),
      attacks: recentAttacks,
      failedLogins,
      anomalies,
      vulnerabilities,
      recommendations: this.generateRecommendations()
    };
  }
}
```
