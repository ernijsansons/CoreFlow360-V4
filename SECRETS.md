# CoreFlow360 V4 - Secrets Management

## Overview
This document lists all required secrets for CoreFlow360 V4 deployment. **NEVER commit actual secret values to git.**

---

## Required Secrets

### 1. JWT_SECRET
**Purpose**: JSON Web Token signing and verification for user authentication
**Format**: Base64-encoded random string (64+ bytes)
**Generate**:
```bash
openssl rand -base64 64
```
**Set**:
```bash
wrangler secret put JWT_SECRET --env production
wrangler secret put JWT_SECRET --env staging
```
**Used in**: Authentication system, session management
**Critical**: ✅ YES - App won't start without it

---

### 2. ENCRYPTION_KEY
**Purpose**: Encrypt sensitive data at rest (PII, payment info)
**Format**: Base64-encoded 32-byte key
**Generate**:
```bash
openssl rand -base64 32
```
**Set**:
```bash
wrangler secret put ENCRYPTION_KEY --env production
wrangler secret put ENCRYPTION_KEY --env staging
```
**Used in**: Data encryption, secure storage
**Critical**: ✅ YES - Required for security compliance

---

### 3. AUTH_SECRET
**Purpose**: Additional authentication layer for API key generation
**Format**: Base64-encoded random string (32+ bytes)
**Generate**:
```bash
openssl rand -base64 32
```
**Set**:
```bash
wrangler secret put AUTH_SECRET --env production
wrangler secret put AUTH_SECRET --env staging
```
**Used in**: API key management, 2FA
**Critical**: ✅ YES - Auth features fail without it

---

### 4. ANTHROPIC_API_KEY
**Purpose**: Claude AI model access for autonomous agents
**Format**: `sk-ant-api03-...` (from Anthropic Console)
**Obtain**: https://console.anthropic.com/settings/keys
**Set**:
```bash
wrangler secret put ANTHROPIC_API_KEY --env production
wrangler secret put ANTHROPIC_API_KEY --env staging  # Use lower tier key for staging
```
**Used in**: AI agent system, document processing, chat
**Critical**: ✅ YES - Core AI features won't work

---

### 5. OPENAI_API_KEY
**Purpose**: Fallback AI model when Claude unavailable
**Format**: `sk-...` (from OpenAI Platform)
**Obtain**: https://platform.openai.com/api-keys
**Set**:
```bash
wrangler secret put OPENAI_API_KEY --env production
wrangler secret put OPENAI_API_KEY --env staging
```
**Used in**: Backup AI processing
**Critical**: ⚠️ Optional but recommended

---

### 6. STRIPE_SECRET_KEY
**Purpose**: Payment processing and subscription management
**Format**: `sk_live_...` (production) or `sk_test_...` (staging)
**Obtain**: https://dashboard.stripe.com/apikeys
**Set**:
```bash
wrangler secret put STRIPE_SECRET_KEY --env production  # Use sk_live_xxx
wrangler secret put STRIPE_SECRET_KEY --env staging     # Use sk_test_xxx
```
**Used in**: Payment processing, billing
**Critical**: ✅ YES - Payment features require it

---

### 7. STRIPE_WEBHOOK_SECRET
**Purpose**: Verify Stripe webhook authenticity
**Format**: `whsec_...`
**Obtain**: Stripe Dashboard → Webhooks → Add endpoint
**Set**:
```bash
wrangler secret put STRIPE_WEBHOOK_SECRET --env production
wrangler secret put STRIPE_WEBHOOK_SECRET --env staging
```
**Used in**: Webhook validation
**Critical**: ✅ YES - Prevents webhook spoofing

---

### 8. SENTRY_DSN
**Purpose**: Error tracking and monitoring
**Format**: `https://...@sentry.io/...`
**Obtain**: Sentry.io → Project Settings → Client Keys
**Set**:
```bash
wrangler secret put SENTRY_DSN --env production
wrangler secret put SENTRY_DSN --env staging
```
**Used in**: Error reporting, performance monitoring
**Critical**: ⚠️ Recommended - App works without it but no error tracking

---

### 9. EMAIL_API_KEY
**Purpose**: Transactional email sending (SendGrid/Mailgun/etc)
**Format**: Provider-specific API key
**Obtain**: Your email service provider dashboard
**Set**:
```bash
wrangler secret put EMAIL_API_KEY --env production
wrangler secret put EMAIL_API_KEY --env staging
```
**Used in**: User registration, password reset, notifications
**Critical**: ✅ YES - Email features fail without it

---

## Verification

### Check which secrets are set:
```bash
wrangler secret list --env production
wrangler secret list --env staging
```

### Expected output:
```
[
  { "name": "JWT_SECRET", "type": "secret_text" },
  { "name": "ENCRYPTION_KEY", "type": "secret_text" },
  { "name": "AUTH_SECRET", "type": "secret_text" },
  { "name": "ANTHROPIC_API_KEY", "type": "secret_text" },
  { "name": "OPENAI_API_KEY", "type": "secret_text" },
  { "name": "STRIPE_SECRET_KEY", "type": "secret_text" },
  { "name": "STRIPE_WEBHOOK_SECRET", "type": "secret_text" },
  { "name": "SENTRY_DSN", "type": "secret_text" },
  { "name": "EMAIL_API_KEY", "type": "secret_text" }
]
```

---

## Security Best Practices

### ✅ DO:
- Generate secrets using cryptographically secure methods (`openssl rand`)
- Use different secrets for production vs staging
- Store secrets in password manager (1Password, LastPass, etc.)
- Rotate secrets quarterly or after suspected compromise
- Use least-privilege API keys (read-only where possible)

### ❌ DON'T:
- Hardcode secrets in source code
- Commit secrets to git (even in .env files)
- Share secrets via email/Slack
- Use same secrets across environments
- Store secrets in plain text files

---

## Secret Rotation

If you need to rotate a secret:

1. Generate new secret value
2. Set new secret in Cloudflare:
   ```bash
   wrangler secret put SECRET_NAME --env production
   ```
3. Deploy updated worker
4. Verify new secret works
5. Revoke old secret at provider (if applicable)

---

## Emergency: Leaked Secret

If a secret is compromised:

1. **Immediately** revoke at source (Anthropic/Stripe/etc dashboard)
2. Generate new secret
3. Update Cloudflare secret
4. Deploy immediately
5. Audit access logs for unauthorized use
6. File incident report if customer data affected

---

## Storage

**Production Secrets Location**: Team Password Manager → CoreFlow360 V4 → Production Secrets
**Staging Secrets Location**: Team Password Manager → CoreFlow360 V4 → Staging Secrets

**Responsible Team**: DevOps + Security
**Review Schedule**: Quarterly

---

**Last Updated**: $(date)
**Document Owner**: DevOps Team
