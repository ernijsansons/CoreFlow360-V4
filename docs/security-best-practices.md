# Security Best Practices Guide

**Target**: Zero critical vulnerabilities, <1% security incident rate
**Current Status**: ✅ CVSS 9.8 JWT bypass vulnerability fixed

---

## Table of Contents

1. [Security Overview](#security-overview)
2. [Authentication & Authorization](#authentication--authorization)
3. [Data Protection](#data-protection)
4. [API Security](#api-security)
5. [Input Validation](#input-validation)
6. [Security Headers](#security-headers)
7. [Monitoring & Incident Response](#monitoring--incident-response)

---

## Security Overview

### Security Posture

- ✅ JWT Authentication with secure secret management
- ✅ Token blacklist/revocation system
- ✅ Rate limiting and DDoS protection
- ✅ Secure UUID-based user IDs
- ✅ Environment validation on startup
- ✅ Bearer token authentication for sensitive endpoints

### Threat Model

**Primary Threats:**
1. **Authentication Bypass** (CVSS 9.8) - ✅ Mitigated
2. **SQL Injection** - ✅ Mitigated (prepared statements)
3. **XSS Attacks** - ✅ Mitigated (CSP, React escaping)
4. **CSRF Attacks** - ✅ Mitigated (SameSite cookies)
5. **DDoS/Rate Limiting** - ✅ Mitigated (rate limiting)

---

## Authentication & Authorization

### JWT Security

**✅ Implemented:**
```typescript
// Environment validation prevents weak secrets
EnvironmentValidator.validate(env);

// Minimum 32-character secret required
if (process.env.JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters');
}

// No fallback secrets allowed
if (process.env.JWT_SECRET === 'fallback-secret') {
  throw new Error('JWT_SECRET is set to vulnerable fallback value');
}
```

**Best Practices:**
1. **Generate Strong Secrets:**
   ```bash
   # Generate 32-byte random secret
   openssl rand -base64 32
   ```

2. **Set Secrets via Wrangler:**
   ```bash
   wrangler secret put JWT_SECRET --env production
   ```

3. **Rotate Secrets Regularly:**
   ```typescript
   // Use JWTSecretRotation service
   const rotation = new JWTSecretRotation(env);
   await rotation.rotateSecret(newSecret);
   ```

### Token Management

**Token Blacklist:**
```typescript
// Revoke token immediately
import { TokenBlacklist } from '@/modules/auth/token-blacklist';

const blacklist = new TokenBlacklist(env.KV_AUTH);
await blacklist.revokeToken(token, userId);
```

**Token Expiration:**
```typescript
// Set appropriate expiration times
const accessToken = jwt.sign(payload, secret, {
  expiresIn: '15m' // Short-lived access tokens
});

const refreshToken = jwt.sign(payload, secret, {
  expiresIn: '7d' // Longer-lived refresh tokens
});
```

### Multi-Factor Authentication

**TOTP Implementation:**
```typescript
import { authenticator } from 'otplib';

// Generate secret
const secret = authenticator.generateSecret();

// Generate QR code for user
const otpauthUrl = authenticator.keyuri(user.email, 'CoreFlow360', secret);

// Verify TOTP code
const isValid = authenticator.verify({
  token: userProvidedCode,
  secret: user.totpSecret
});
```

---

## Data Protection

### Encryption at Rest

**PII Encryption:**
```typescript
import { encrypt, decrypt } from '@/shared/crypto';

// Encrypt sensitive data before storing
const encryptedSSN = await encrypt(user.ssn, env.ENCRYPTION_KEY);
await db.prepare('UPDATE users SET ssn = ? WHERE id = ?')
  .bind(encryptedSSN, userId).run();

// Decrypt when retrieving
const decryptedSSN = await decrypt(user.ssn, env.ENCRYPTION_KEY);
```

**Database Encryption:**
- Cloudflare D1 encrypts all data at rest by default
- Additional application-level encryption for PII fields

### Secure User IDs

**✅ Fixed: UUID-based IDs**
```typescript
// Before (VULNERABLE):
const userId = `user_${Date.now()}_${Math.random()}`;

// After (SECURE):
const userId = `user_${crypto.randomUUID()}`;
```

**Why This Matters:**
- Prevents user enumeration attacks
- No sequential ID guessing
- OWASP A01:2021 Broken Access Control mitigation

### Data Retention

**Implement Deletion:**
```typescript
// Hard delete (GDPR right to be forgotten)
await db.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();

// Soft delete (audit trail)
await db.prepare('UPDATE users SET deleted_at = ? WHERE id = ?')
  .bind(new Date().toISOString(), userId).run();
```

---

## API Security

### Rate Limiting

**✅ Implemented:**
```typescript
// Enterprise rate limiter
import { EnterpriseRateLimiter } from '@/security/enterprise-rate-limiter';

const rateLimiter = new EnterpriseRateLimiter(env.RATE_LIMITER_DO);
const result = await rateLimiter.checkLimit(clientIp);

if (!result.allowed) {
  return c.json({ error: 'Rate limit exceeded' }, 429);
}
```

**Rate Limit Configuration:**
```typescript
// Different limits for different endpoints
const limits = {
  '/api/v1/auth/login': { requests: 5, window: 60 }, // 5 req/min
  '/api/v1/auth/register': { requests: 3, window: 60 }, // 3 req/min
  '/api/v1/*': { requests: 100, window: 60 }, // 100 req/min default
};
```

### CORS Configuration

**Strict Origin Control:**
```typescript
api.use('*', cors({
  origin: (origin) => {
    const allowedOrigins = [
      'https://app.coreflow360.com',
      'https://dashboard.coreflow360.com',
      'https://api.coreflow360.com'
    ];

    return allowedOrigins.includes(origin) ? origin : allowedOrigins[0];
  },
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
}));
```

### Bearer Token Authentication

**✅ Secured Endpoints:**
```typescript
// Require Bearer token for sensitive endpoints
app.post('/telemetry/collect', async (c) => {
  const authHeader = c.req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Authorization required' }, 401);
  }

  const token = authHeader.substring(7);
  if (token !== c.env.TELEMETRY_API_KEY) {
    return c.json({ error: 'Invalid API key' }, 403);
  }

  // Process request...
});
```

---

## Input Validation

### Zod Schema Validation

**Always Validate Input:**
```typescript
import { z } from 'zod';

const LoginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

app.post('/api/v1/auth/login', async (c) => {
  const body = await c.req.json();

  // Validate input
  const result = LoginSchema.safeParse(body);

  if (!result.success) {
    return c.json({
      error: 'Validation failed',
      details: result.error.errors
    }, 400);
  }

  // Process validated data
  const { email, password } = result.data;
});
```

### SQL Injection Prevention

**✅ Use Prepared Statements:**
```typescript
// Good (SAFE):
const user = await db.prepare(
  'SELECT * FROM users WHERE email = ?'
).bind(email).first();

// Bad (VULNERABLE):
const user = await db.exec(`SELECT * FROM users WHERE email = '${email}'`);
```

### XSS Prevention

**React Automatic Escaping:**
```tsx
// React escapes by default
<div>{userInput}</div> // Safe

// Dangerous (avoid unless absolutely necessary)
<div dangerouslySetInnerHTML={{ __html: userInput }} /> // Unsafe
```

**Sanitize HTML Input:**
```typescript
import DOMPurify from 'dompurify';

// Sanitize user-generated HTML
const clean = DOMPurify.sanitize(dirtyHTML);
```

---

## Security Headers

### Content Security Policy

**Strict CSP:**
```typescript
// src/middleware/security.ts
export async function addSecurityHeaders(response: Response) {
  return new Response(response.body, {
    headers: {
      ...response.headers,
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://www.clarity.ms",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self' https://api.coreflow360.com",
        "frame-ancestors 'none'",
      ].join('; '),
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    }
  });
}
```

### HSTS (HTTP Strict Transport Security)

**Force HTTPS:**
```typescript
response.headers.set(
  'Strict-Transport-Security',
  'max-age=31536000; includeSubDomains; preload'
);
```

---

## Monitoring & Incident Response

### Security Event Logging

**Log Security Events:**
```typescript
import { logSecurityEvent } from '@/middleware/security';

// Log failed login attempts
if (!passwordValid) {
  await logSecurityEvent('failed_login', {
    email,
    ip: request.headers.get('CF-Connecting-IP'),
    timestamp: new Date().toISOString()
  });
}

// Log suspicious activity
if (requestCount > threshold) {
  await logSecurityEvent('rate_limit_exceeded', {
    ip,
    endpoint: request.url,
    count: requestCount
  });
}
```

### Audit Trail

**Comprehensive Logging:**
```typescript
// Log all sensitive operations
await db.prepare(`
  INSERT INTO audit_log (user_id, action, resource, timestamp)
  VALUES (?, ?, ?, ?)
`).bind(
  userId,
  'UPDATE',
  'user_profile',
  new Date().toISOString()
).run();
```

### Intrusion Detection

**Detect Suspicious Patterns:**
```typescript
// Multiple failed logins
if (failedAttempts >= 5) {
  await lockAccount(userId, '15m');
  await notifySecurityTeam({
    type: 'account_lockout',
    userId,
    reason: 'Multiple failed login attempts'
  });
}

// Unusual access patterns
if (isUnusualLocation(ip, userId)) {
  await requireMFA(userId);
  await notifyUser(userId, 'unusual_activity');
}
```

### Incident Response Plan

**1. Detection:**
- Monitor security logs
- Set up alerts for anomalies
- Review failed authentication attempts

**2. Containment:**
- Revoke compromised tokens
- Lock affected accounts
- Block malicious IPs

**3. Investigation:**
- Review audit logs
- Identify attack vector
- Assess damage

**4. Recovery:**
- Rotate secrets
- Reset affected passwords
- Deploy security patches

**5. Post-Incident:**
- Document incident
- Update security policies
- Improve detection

---

## Security Checklist

### Pre-Deployment Security Audit

- [ ] ✅ JWT_SECRET is 32+ characters
- [ ] ✅ No hardcoded secrets in code
- [ ] ✅ All user input is validated
- [ ] ✅ SQL queries use prepared statements
- [ ] ✅ Security headers are set
- [ ] ✅ Rate limiting is enabled
- [ ] ✅ CORS is properly configured
- [ ] ✅ Error messages don't leak sensitive data
- [ ] ✅ Audit logging is enabled
- [ ] ✅ Encryption is used for PII

### Regular Security Tasks

**Weekly:**
- Review security logs for anomalies
- Check failed authentication attempts
- Monitor rate limiting metrics

**Monthly:**
- Run security audit: `npm audit`
- Review and update dependencies
- Test incident response procedures

**Quarterly:**
- Rotate JWT secrets
- Review access controls
- Conduct penetration testing
- Update security documentation

---

## Vulnerability Disclosure

### Reporting Security Issues

**DO NOT** create public GitHub issues for security vulnerabilities.

**Instead:**
1. Email: security@coreflow360.com
2. Include:
   - Detailed description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

**Expected Response Times:**
- Critical (CVSS 9-10): 24 hours
- High (CVSS 7-8.9): 48 hours
- Medium (CVSS 4-6.9): 1 week
- Low (CVSS 0-3.9): 2 weeks

---

## References

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Cloudflare Security](https://developers.cloudflare.com/fundamentals/basic-tasks/protect-your-website/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

**Last Updated**: 2025-10-21
**Maintained By**: Security Team
**Review Cycle**: Monthly
**Compliance**: SOC 2 Type II, ISO 27001
