# API Keys Setup Guide - CoreFlow360 V4

## Quick Start (15 Minutes to Production)

This guide walks you through setting up all required API keys for CoreFlow360 V4. Follow each section carefully to ensure your production environment is properly configured.

**Time Required:** 15-30 minutes
**Difficulty:** Intermediate
**Prerequisites:** Admin access to Cloudflare, Stripe, and SendGrid accounts

## Why This Matters

API keys connect CoreFlow360 to essential services:
- **Payment Processing** - Accept customer payments via Stripe
- **Email Delivery** - Send transactional emails via SendGrid
- **AI Capabilities** - Power intelligent features with Claude/GPT
- **Security** - Protect your application and customer data

## 1. Stripe Configuration (Payment Processing)

### Step 1: Get Your Stripe Keys

1. **Login to Stripe Dashboard**
   - Navigate to https://dashboard.stripe.com
   - Switch to **Live Mode** (toggle in top-right)

2. **Access API Keys**
   - Go to Developers → API Keys
   - You'll need three keys:

```bash
# Copy these values:
STRIPE_SECRET_KEY = sk_live_51... (starts with sk_live_)
STRIPE_PUBLISHABLE_KEY = pk_live_51... (starts with pk_live_)
```

3. **Configure Webhook Endpoint**
   - Go to Developers → Webhooks
   - Click "Add endpoint"
   - Endpoint URL: `https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/webhooks/stripe`
   - Select events:
     - `payment_intent.succeeded`
     - `payment_intent.failed`
     - `customer.subscription.created`
     - `customer.subscription.updated`
     - `customer.subscription.deleted`
     - `invoice.paid`
     - `invoice.payment_failed`
   - Copy the signing secret: `whsec_...`

### Step 2: Add to Wrangler Secrets

```bash
# Add Stripe secret key
wrangler secret put STRIPE_SECRET_KEY
# Paste: sk_live_... (press Enter)

# Add publishable key
wrangler secret put STRIPE_PUBLISHABLE_KEY
# Paste: pk_live_... (press Enter)

# Add webhook secret
wrangler secret put STRIPE_WEBHOOK_SECRET
# Paste: whsec_... (press Enter)
```

### Step 3: Verify Stripe Setup

```bash
# Test Stripe connection
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/payments/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{"action": "verify_connection"}'

# Expected response:
{
  "status": "connected",
  "mode": "live",
  "webhook_configured": true
}
```

### Troubleshooting Stripe

**Error: "Invalid API Key"**
- Ensure you're using Live mode keys (not Test mode)
- Check for extra spaces when pasting

**Error: "Webhook signature verification failed"**
- Verify webhook secret starts with `whsec_`
- Ensure endpoint URL is exactly correct

## 2. SendGrid Configuration (Email Service)

### Step 1: Get SendGrid API Key

1. **Login to SendGrid**
   - Navigate to https://app.sendgrid.com
   - Go to Settings → API Keys

2. **Create API Key**
   - Click "Create API Key"
   - Name: `CoreFlow360-Production`
   - API Key Permissions: **Full Access**
   - Click "Create & View"
   - **IMPORTANT:** Copy the key immediately (shown only once)

3. **Configure Sender Authentication**
   - Go to Settings → Sender Authentication
   - Domain Authentication:
     - Add your domain
     - Add DNS records as instructed
     - Verify domain
   - Single Sender Verification (alternative):
     - Add sender email
     - Verify email address

### Step 2: Add to Wrangler Secrets

```bash
# Add SendGrid API key
wrangler secret put SENDGRID_API_KEY
# Paste: SG.xxxxx... (press Enter)

# Add sender email
wrangler secret put EMAIL_FROM
# Enter: noreply@yourdomain.com (press Enter)
```

### Step 3: Verify SendGrid Setup

```bash
# Test email sending
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/email/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{
    "to": "test@example.com",
    "subject": "Test Email",
    "action": "send_test"
  }'

# Expected response:
{
  "status": "sent",
  "messageId": "...",
  "provider": "sendgrid"
}
```

### Troubleshooting SendGrid

**Error: "The from address does not match a verified Sender Identity"**
- Complete domain authentication or single sender verification
- Ensure EMAIL_FROM matches verified address

**Error: "Invalid API Key"**
- Regenerate API key with Full Access permissions
- Check for line breaks when pasting

## 3. AI Services Configuration

### Step 1: Anthropic Claude API

1. **Get Anthropic API Key**
   - Navigate to https://console.anthropic.com
   - Go to API Keys section
   - Create new key: `coreflow360-production`
   - Copy the key

```bash
# Add Anthropic API key
wrangler secret put ANTHROPIC_API_KEY
# Paste key (press Enter)
```

### Step 2: OpenAI GPT API

1. **Get OpenAI API Key**
   - Navigate to https://platform.openai.com
   - Go to API Keys
   - Create new key: `CoreFlow360 Production`
   - Copy the key

```bash
# Add OpenAI API key
wrangler secret put OPENAI_API_KEY
# Paste: sk-... (press Enter)
```

### Step 3: Configure AI Models

```bash
# Set primary AI model
wrangler secret put AI_MODEL_PRIMARY
# Enter: claude-3-sonnet-20240229 (press Enter)

# Set secondary AI model
wrangler secret put AI_MODEL_SECONDARY
# Enter: gpt-4-turbo-preview (press Enter)
```

### Step 4: Verify AI Setup

```bash
# Test AI connection
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/ai/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{"prompt": "Hello, are you operational?"}'

# Expected response:
{
  "status": "operational",
  "primary_model": "claude-3-sonnet",
  "secondary_model": "gpt-4-turbo",
  "response": "Yes, I am fully operational..."
}
```

## 4. Security Keys Configuration

### Step 1: Generate Secure Keys

```bash
# Generate JWT secret (32+ characters)
openssl rand -base64 32
# Example output: 7Kxm9RgPQr3Np5Zt8WvLc2Jh6Ys4Bf1Ua0De7Ig3Mq5Xn8=

# Generate encryption key
openssl rand -base64 32
# Example output: 9Hy4Kt2Wn8Lp5Qr7Xm3Jv6Bc1Zs0Fg9Ud4Ia7Oe2Tn5Rk8=

# Generate auth secret
openssl rand -base64 32
# Example output: 3Nf8Yw2Kp5Rm9Qt1Ls7Jx4Bv6Zc0Hg3Ud8Ia2Oe5Tn7Wk9=
```

### Step 2: Add Security Secrets

```bash
# Add JWT secret
wrangler secret put JWT_SECRET
# Paste generated secret (press Enter)

# Add encryption key
wrangler secret put ENCRYPTION_KEY
# Paste generated key (press Enter)

# Add auth secret
wrangler secret put AUTH_SECRET
# Paste generated secret (press Enter)
```

### Security Best Practices

- **Never commit secrets to Git**
- **Rotate keys every 90 days**
- **Use different keys for each environment**
- **Enable audit logging for key usage**
- **Implement key expiration warnings**

## 5. Optional Services Configuration

### Twilio (SMS/Voice)

```bash
# Only if using SMS features
wrangler secret put TWILIO_ACCOUNT_SID
# Enter: ACxxxxx... (press Enter)

wrangler secret put TWILIO_AUTH_TOKEN
# Enter token (press Enter)

wrangler secret put TWILIO_PHONE_NUMBER
# Enter: +1234567890 (press Enter)
```

### Sentry (Error Tracking)

```bash
# For production error monitoring
wrangler secret put SENTRY_DSN
# Enter: https://xxx@xxx.ingest.sentry.io/xxx (press Enter)

wrangler secret put SENTRY_ENVIRONMENT
# Enter: production (press Enter)
```

### Analytics Services

```bash
# Google Analytics
wrangler secret put GOOGLE_ANALYTICS_ID
# Enter: G-XXXXXXXXXX (press Enter)

# Cloudflare Analytics
wrangler secret put CLOUDFLARE_ANALYTICS_TOKEN
# Enter token (press Enter)
```

## 6. Verification Checklist

Run this complete verification suite:

```bash
# Create verification script
cat > verify-api-keys.sh << 'EOF'
#!/bin/bash

echo "CoreFlow360 V4 - API Key Verification"
echo "======================================"

API_URL="https://coreflow360-v4-prod.ernijs-ansons.workers.dev"
TOKEN="YOUR_ADMIN_TOKEN"

echo -n "1. Health Check... "
curl -s $API_URL/health | grep -q "ok" && echo "✓ PASS" || echo "✗ FAIL"

echo -n "2. Stripe Connection... "
curl -s -X POST $API_URL/api/v1/payments/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"verify_connection"}' | grep -q "connected" && echo "✓ PASS" || echo "✗ FAIL"

echo -n "3. SendGrid Connection... "
curl -s -X POST $API_URL/api/v1/email/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"verify_connection"}' | grep -q "connected" && echo "✓ PASS" || echo "✗ FAIL"

echo -n "4. AI Services... "
curl -s -X POST $API_URL/api/v1/ai/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"ping"}' | grep -q "operational" && echo "✓ PASS" || echo "✗ FAIL"

echo -n "5. Security Keys... "
curl -s -X POST $API_URL/api/v1/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"test":true}' | grep -q "configured" && echo "✓ PASS" || echo "✗ FAIL"

echo ""
echo "Verification complete!"
EOF

# Run verification
chmod +x verify-api-keys.sh
./verify-api-keys.sh
```

## 7. Troubleshooting Common Issues

### Issue: "Secrets not found in production"

```bash
# List all secrets to verify
wrangler secret list

# If missing, re-add the secret
wrangler secret delete SECRET_NAME
wrangler secret put SECRET_NAME
```

### Issue: "API key format invalid"

Common format requirements:
- **Stripe**: Must start with `sk_live_` (secret) or `pk_live_` (publishable)
- **SendGrid**: Must start with `SG.`
- **OpenAI**: Must start with `sk-`
- **No spaces or line breaks**: Clean paste without formatting

### Issue: "Rate limit exceeded"

```bash
# Check rate limit configuration
wrangler secret put RATE_LIMIT_PER_MINUTE
# Enter: 60 (for production)
```

### Issue: "Webhook not receiving events"

```bash
# Test webhook endpoint directly
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/webhooks/stripe \
  -H "Stripe-Signature: test" \
  -H "Content-Type: application/json" \
  -d '{"type":"test"}'

# Should return validation error (expected)
```

## 8. Security Considerations

### Key Rotation Schedule

Set calendar reminders for:
- **Every 30 days**: Review key usage and access logs
- **Every 90 days**: Rotate security keys (JWT, encryption)
- **Every 180 days**: Rotate API keys (Stripe, SendGrid)
- **Immediately**: If any breach or suspicious activity

### Key Rotation Process

```bash
# 1. Generate new key
openssl rand -base64 32

# 2. Add new key without removing old
wrangler secret put NEW_JWT_SECRET

# 3. Update application to accept both keys

# 4. Monitor for 24 hours

# 5. Remove old key
wrangler secret delete JWT_SECRET
wrangler secret put JWT_SECRET  # Add new value
```

### Access Control

Limit who can manage secrets:
- **Production secrets**: Only DevOps Lead
- **Staging secrets**: DevOps + Senior Engineers
- **Development secrets**: All engineers

### Audit Logging

Enable audit logging for all secret access:

```bash
# Configure audit webhook
wrangler secret put AUDIT_WEBHOOK_URL
# Enter: https://your-audit-system.com/webhook
```

## 9. Post-Setup Validation

### Customer Journey Test

After all keys are configured, test the complete customer journey:

1. **Registration Flow**
```bash
curl -X POST $API_URL/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "businessName": "Test Corp"
  }'
```

2. **Payment Flow**
```bash
curl -X POST $API_URL/api/v1/payments/create-subscription \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "priceId": "price_xxxxx",
    "customerId": "cus_xxxxx"
  }'
```

3. **Email Delivery**
```bash
# Check email logs in SendGrid dashboard
# Verify emails are being delivered
```

## 10. Support & Resources

### Getting Help

**Cloudflare Workers Support**
- Documentation: https://developers.cloudflare.com/workers/
- Community: https://community.cloudflare.com/

**Stripe Support**
- Documentation: https://stripe.com/docs
- Support: https://support.stripe.com/

**SendGrid Support**
- Documentation: https://docs.sendgrid.com/
- Support: https://support.sendgrid.com/

### Quick Reference

```bash
# Essential commands
wrangler secret list              # List all secrets
wrangler secret delete KEY_NAME   # Remove a secret
wrangler secret put KEY_NAME      # Add/update secret
wrangler tail                     # Live log streaming
wrangler deployment list          # View deployments
```

### Emergency Rollback

If API keys cause issues:

```bash
# 1. Immediate rollback
wrangler rollback --env production

# 2. Fix configuration
# Update secrets as needed

# 3. Redeploy
wrangler deploy --env production
```

---

**Last Updated:** October 2024
**Estimated Setup Time:** 15-30 minutes
**Support Contact:** support@coreflow360.com

Remember: Take your time. A properly configured system is worth the extra minute of verification.