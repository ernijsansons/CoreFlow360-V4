# CoreFlow360 V4 - Deployment Guide

## 🚀 Launch Checklist

### Pre-Launch Requirements

#### 1. Environment Setup
- [ ] Production Cloudflare account configured
- [ ] Custom domain(s) configured (app.coreflow360.com, api.coreflow360.com)
- [ ] SSL certificates active
- [ ] DNS records properly configured

#### 2. Secrets Configuration
Set these secrets in Cloudflare (via `wrangler secret put`):

```bash
# Authentication & Security
wrangler secret put JWT_SECRET --env production
wrangler secret put ENCRYPTION_KEY --env production
wrangler secret put AUTH_SECRET --env production

# Payment Processing
wrangler secret put STRIPE_SECRET_KEY --env production
wrangler secret put STRIPE_WEBHOOK_SECRET --env production

# AI Services
wrangler secret put ANTHROPIC_API_KEY --env production
wrangler secret put OPENAI_API_KEY --env production

# Email Service
wrangler secret put EMAIL_API_KEY --env production

# Monitoring
wrangler secret put SENTRY_DSN --env production

# Cloudflare API
wrangler secret put CLOUDFLARE_API_TOKEN --env production
wrangler secret put CLOUDFLARE_ACCOUNT_ID --env production
wrangler secret put CLOUDFLARE_ZONE_ID --env production
```

#### 3. Database Setup
```bash
# Create production D1 databases
wrangler d1 create coreflow360-prod
wrangler d1 create coreflow360-analytics-prod

# Update wrangler.production.toml with database IDs
# Run migrations
wrangler d1 migrations apply coreflow360-prod --env production
```

#### 4. KV Namespaces
```bash
# Create production KV namespaces
wrangler kv:namespace create "KV_CACHE" --env production
wrangler kv:namespace create "KV_SESSION" --env production
wrangler kv:namespace create "KV_AUTH" --env production
wrangler kv:namespace create "KV_RATE_LIMIT_METRICS" --env production

# Update wrangler.production.toml with namespace IDs
```

#### 5. R2 Buckets
```bash
# Create production R2 buckets
wrangler r2 bucket create coreflow360-prod-documents
wrangler r2 bucket create coreflow360-prod-backups

# Configure CORS if needed
wrangler r2 bucket cors put coreflow360-prod-documents --file ./r2-cors.json
```

## 📋 Deployment Process

### Automated Deployment (Recommended)

The CI/CD pipeline automatically deploys when:
- Commits are pushed to `main` branch (deploys to staging)
- Manual trigger with production environment (deploys to production)

#### GitHub Actions Secrets
Configure these in GitHub repository settings:

```
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
CLOUDFLARE_ACCOUNT_ID=your_account_id
SLACK_WEBHOOK_STAGING=https://hooks.slack.com/...
SLACK_WEBHOOK_PRODUCTION=https://hooks.slack.com/...
SNYK_TOKEN=your_snyk_token (optional)
CODECOV_TOKEN=your_codecov_token (optional)
```

### Manual Deployment

#### Backend (Cloudflare Workers)
```bash
# Install dependencies
npm ci

# Build for production
npm run build:production

# Deploy to production
wrangler deploy --config wrangler.production.toml --env production
```

#### Frontend (Cloudflare Pages)
```bash
cd frontend

# Install dependencies
npm ci

# Set environment variables
export VITE_API_URL=https://api.coreflow360.com
export VITE_ENVIRONMENT=production

# Build for production
npm run build

# Deploy to Cloudflare Pages
npx wrangler pages deploy dist --project-name coreflow360-frontend
```

## 🔧 Configuration

### Environment Variables

#### Backend (.env)
```bash
# API Configuration
API_BASE_URL=https://api.coreflow360.com
ALLOWED_ORIGINS=https://app.coreflow360.com
ENVIRONMENT=production
LOG_LEVEL=info

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=1000
RATE_LIMIT_BURST=100

# Feature Flags
ENABLE_AI_FEATURES=true
ENABLE_ADVANCED_ANALYTICS=true
ENABLE_BETA_FEATURES=false
```

#### Frontend (.env.production)
```bash
# API Configuration
VITE_API_URL=https://api.coreflow360.com
VITE_SSE_URL=https://api.coreflow360.com/sse
VITE_ENVIRONMENT=production

# Payment Processing
VITE_STRIPE_PUBLIC_KEY=pk_live_...

# Analytics
VITE_GOOGLE_ANALYTICS_ID=GA_MEASUREMENT_ID
VITE_SENTRY_DSN=https://...@sentry.io/...

# Feature Flags
VITE_ENABLE_AI_FEATURES=true
VITE_ENABLE_ADVANCED_ANALYTICS=true
VITE_ENABLE_BETA_FEATURES=false
```

## 🗄️ Database Management

### Initial Setup
```bash
# Run initial migrations
wrangler d1 migrations apply coreflow360-prod --env production

# Seed with initial data (if needed)
wrangler d1 execute coreflow360-prod --env production --file ./database/seeds/initial-data.sql
```

### Backup Strategy
```bash
# Automated backups (set up as Cloudflare Cron Trigger)
# Runs daily at 2 AM UTC
wrangler d1 backup create coreflow360-prod --env production

# Manual backup
wrangler d1 export coreflow360-prod --env production --output backup-$(date +%Y%m%d).sql
```

### Migration Process
```bash
# 1. Create migration
wrangler d1 migrations create add_new_feature --env production

# 2. Test migration on staging
wrangler d1 migrations apply coreflow360-staging --env staging

# 3. Deploy to production (during maintenance window)
wrangler d1 migrations apply coreflow360-prod --env production
```

## 📊 Monitoring & Observability

### Health Checks
```bash
# API Health Check
curl -f https://api.coreflow360.com/health

# Frontend Health Check
curl -f https://app.coreflow360.com

# Database Health Check
curl -f https://api.coreflow360.com/api/health/database
```

### Monitoring Setup

#### Cloudflare Analytics
- Workers Analytics enabled
- Real User Monitoring (RUM) configured
- Custom metrics tracking business KPIs

#### Sentry Error Tracking
```javascript
// Automatically configured in production
// Monitors both frontend and backend errors
// Performance monitoring enabled
```

#### Custom Metrics Dashboard
Access at: https://api.coreflow360.com/metrics (authenticated)

### Log Aggregation
```bash
# View real-time logs
wrangler tail --env production

# Search logs (requires Cloudflare Enterprise)
wrangler logs --env production --search "error"
```

## 🔐 Security

### SSL/TLS Configuration
- Cloudflare SSL/TLS encryption mode: Full (strict)
- HSTS headers enabled
- Security headers configured in wrangler.toml

### Rate Limiting
- Durable Objects handle rate limiting
- Per-user and per-IP limits
- Configurable limits in production

### Content Security Policy
```
default-src 'self';
script-src 'self' 'unsafe-inline' https://js.stripe.com;
style-src 'self' 'unsafe-inline';
img-src 'self' data: https:;
connect-src 'self' https://api.stripe.com;
```

## 🚨 Incident Response

### Rollback Procedure
```bash
# 1. Identify last working commit
git log --oneline -n 10

# 2. Trigger rollback via GitHub Actions
# Go to Actions > Deploy CoreFlow360 V4 > Run workflow
# Select "rollback" environment
# Enter commit hash to rollback to

# 3. Or manual rollback
git checkout <last-working-commit>
wrangler deploy --config wrangler.production.toml --env production
```

### Emergency Contacts
- **Primary On-Call**: [Contact Information]
- **Secondary On-Call**: [Contact Information]
- **Escalation**: [Contact Information]

### Incident Communication
1. **Slack**: #incidents channel
2. **Status Page**: https://status.coreflow360.com
3. **Email**: incidents@coreflow360.com

## 📈 Performance Optimization

### Cloudflare Optimizations
- Argo Smart Routing enabled
- Image optimization configured
- Rocket Loader disabled (conflicts with React)
- Minification enabled

### Caching Strategy
```javascript
// API responses cached for 5 minutes
// Static assets cached for 1 year
// HTML cached for 10 minutes
```

### Performance Targets
- **Time to Interactive**: < 3 seconds
- **Largest Contentful Paint**: < 2.5 seconds
- **Cumulative Layout Shift**: < 0.1
- **API Response Time**: < 200ms (p95)

## 🧪 Testing

### Pre-Deployment Tests
```bash
# Run full test suite
npm run test:all

# Run integration tests
npm run test:integration

# Run end-to-end tests
npm run test:e2e

# Performance tests
npm run test:performance
```

### Post-Deployment Verification
```bash
# Smoke tests
npm run test:smoke --env production

# API health checks
npm run test:health --env production

# User journey tests
npm run test:journey --env production
```

## 📱 Mobile Considerations

### PWA Configuration
- Service worker enabled
- App manifest configured
- Install prompts configured
- Offline functionality for critical features

### Mobile Performance
- Images optimized for different screen sizes
- Touch targets minimum 44px
- Responsive design tested on all breakpoints

## 🔄 Maintenance

### Regular Maintenance Tasks

#### Daily
- Monitor error rates in Sentry
- Check system health metrics
- Review security alerts

#### Weekly
- Update dependencies (automated via Dependabot)
- Review performance metrics
- Check backup integrity

#### Monthly
- Security audit
- Performance optimization review
- Capacity planning review

### Scheduled Maintenance
- **Window**: Sundays 2-4 AM UTC
- **Notification**: 24 hours advance notice
- **Communication**: Status page + email notifications

## 📞 Support

### Documentation
- **API Docs**: https://docs.coreflow360.com
- **User Guide**: https://help.coreflow360.com
- **Developer Docs**: https://dev.coreflow360.com

### Contact Information
- **Technical Support**: tech@coreflow360.com
- **Business Support**: support@coreflow360.com
- **Emergency**: +1-XXX-XXX-XXXX

---

## Quick Reference Commands

```bash
# Deploy to production
wrangler deploy --config wrangler.production.toml --env production

# View logs
wrangler tail --env production

# Database migration
wrangler d1 migrations apply coreflow360-prod --env production

# Create backup
wrangler d1 backup create coreflow360-prod --env production

# Health check
curl -f https://api.coreflow360.com/health

# Rollback
git checkout <commit> && wrangler deploy --config wrangler.production.toml --env production
```

**Last Updated**: $(date)
**Version**: 4.1.0
**Environment**: Production