# Security Architecture

## Overview

CoreFlow360 V4 implements enterprise-grade security with multiple layers of defense, comprehensive audit logging, and compliance with industry standards. The system is designed with security-first principles and zero-trust architecture.

## Security Layers

### 1. Authentication Layer

#### JWT-Based Authentication
**Location**: `src/modules/auth/jwt.ts`

```typescript
interface JWTPayload {
  sub: string;          // User ID
  email: string;        // User email
  businessId: string;   // Current business
  role: string;         // User role
  permissions: string[]; // Granted permissions
  sessionId: string;    // Session identifier
  iat: number;          // Issued at
  exp: number;          // Expiration
  jti: string;          // JWT ID for revocation
}
```

**Security Features**:
- RS256 signing algorithm
- Short-lived access tokens (15 minutes)
- Refresh token rotation
- JWT blacklisting for revocation
- Secure token storage (HttpOnly cookies)

#### Multi-Factor Authentication (MFA)
**Location**: `src/modules/auth/mfa-service.ts`

Supported methods:
- **TOTP**: Time-based One-Time Passwords
- **SMS**: Text message verification
- **Email**: Email-based codes
- **WebAuthn**: Biometric authentication (planned)

```typescript
class MFAService {
  async setupTOTP(userId: string): Promise<TOTPSetup> {
    const secret = generateSecret();
    const qrCode = await generateQRCode(secret);

    await this.kv.put(`mfa:${userId}`, {
      type: 'totp',
      secret: encrypt(secret),
      backupCodes: generateBackupCodes()
    });

    return { qrCode, backupCodes };
  }

  async verifyTOTP(userId: string, code: string): Promise<boolean> {
    const config = await this.kv.get(`mfa:${userId}`);
    const secret = decrypt(config.secret);
    return verifyTOTPCode(secret, code);
  }
}
```

### 2. Authorization Layer

#### Attribute-Based Access Control (ABAC)
**Location**: `src/modules/abac/service.ts`

Dynamic permission evaluation based on:
- User attributes (role, department)
- Resource attributes (type, owner)
- Environmental attributes (time, location)
- Action attributes (read, write, delete)

```typescript
interface ABACPolicy {
  id: string;
  name: string;
  effect: 'allow' | 'deny';
  subjects: SubjectMatcher[];
  resources: ResourceMatcher[];
  actions: string[];
  conditions?: Condition[];
}

class ABACService {
  async evaluateAccess(request: AccessRequest): Promise<AccessDecision> {
    const policies = await this.loadPolicies(request);

    for (const policy of policies) {
      if (this.matchesPolicy(request, policy)) {
        if (policy.effect === 'deny') {
          return { allowed: false, reason: 'Explicit deny' };
        }
        if (await this.evaluateConditions(request, policy.conditions)) {
          return { allowed: true, policy: policy.id };
        }
      }
    }

    return { allowed: false, reason: 'No matching allow policy' };
  }
}
```

#### Role-Based Permissions

```typescript
const RolePermissions = {
  owner: {
    inherits: ['admin'],
    permissions: [
      'business:*',
      'billing:*',
      'users:delete'
    ]
  },
  admin: {
    inherits: ['manager'],
    permissions: [
      'users:*',
      'settings:*',
      'audit:view'
    ]
  },
  manager: {
    inherits: ['user'],
    permissions: [
      'reports:*',
      'team:manage',
      'workflows:*'
    ]
  },
  user: {
    permissions: [
      'profile:*',
      'tasks:own:*',
      'documents:read'
    ]
  }
};
```

### 3. Data Protection

#### Encryption at Rest
**Location**: `src/security/encryption.ts`

```typescript
class EncryptionService {
  private algorithm = 'aes-256-gcm';

  async encryptSensitiveData(data: any, context: EncryptionContext) {
    const key = await this.deriveKey(context);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const cipher = crypto.subtle.encrypt(
      { name: this.algorithm, iv },
      key,
      new TextEncoder().encode(JSON.stringify(data))
    );

    return {
      encrypted: base64Encode(cipher),
      iv: base64Encode(iv),
      version: 1
    };
  }

  async decryptSensitiveData(encrypted: EncryptedData, context: EncryptionContext) {
    const key = await this.deriveKey(context);
    const decrypted = await crypto.subtle.decrypt(
      { name: this.algorithm, iv: base64Decode(encrypted.iv) },
      key,
      base64Decode(encrypted.encrypted)
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
  }
}
```

#### Field-Level Encryption

Sensitive fields encrypted individually:

```typescript
const SensitiveFields = {
  users: ['ssn', 'tax_id', 'bank_account'],
  customers: ['credit_card', 'personal_id'],
  financial: ['account_number', 'routing_number']
};

class FieldEncryption {
  async encryptFields(table: string, record: any) {
    const fields = SensitiveFields[table] || [];

    for (const field of fields) {
      if (record[field]) {
        record[field] = await this.encrypt(record[field]);
      }
    }

    return record;
  }
}
```

### 4. Network Security

#### Rate Limiting
**Location**: `src/middleware/rate-limit.ts`

Multi-tier rate limiting:

```typescript
const RateLimits = {
  authentication: {
    register: { points: 5, duration: 3600 },    // 5 per hour
    login: { points: 10, duration: 900 },        // 10 per 15 min
    passwordReset: { points: 3, duration: 3600 } // 3 per hour
  },
  api: {
    standard: { points: 100, duration: 60 },     // 100 per minute
    ai: { points: 20, duration: 60 },            // 20 per minute
    export: { points: 5, duration: 300 }         // 5 per 5 minutes
  }
};

class EnterpriseRateLimiter {
  async checkLimit(key: string, category: string) {
    const limit = RateLimits[category];
    const current = await this.redis.incr(key);

    if (current === 1) {
      await this.redis.expire(key, limit.duration);
    }

    if (current > limit.points) {
      throw new RateLimitExceeded({
        limit: limit.points,
        reset: await this.redis.ttl(key)
      });
    }
  }
}
```

#### DDoS Protection

Cloudflare integration for edge protection:

```typescript
class DDoSProtection {
  async analyzeRequest(request: Request) {
    const signals = {
      ip: request.headers.get('CF-Connecting-IP'),
      country: request.headers.get('CF-IPCountry'),
      asn: request.headers.get('CF-ASN'),
      threatScore: request.headers.get('CF-Threat-Score')
    };

    if (parseInt(signals.threatScore) > 30) {
      await this.challenge(request);
    }

    if (await this.isBlacklisted(signals.ip)) {
      throw new SecurityException('Access denied');
    }

    await this.trackRequestPattern(signals);
  }
}
```

### 5. Input Validation & Sanitization

#### Request Validation
**Location**: `src/middleware/validation.ts`

```typescript
class InputValidator {
  validateRequest(schema: ZodSchema, data: any) {
    const result = schema.safeParse(data);

    if (!result.success) {
      throw new ValidationError({
        errors: result.error.flatten(),
        input: this.sanitizeForLog(data)
      });
    }

    // Additional security checks
    this.checkForInjection(result.data);
    this.checkForXSS(result.data);
    this.checkForPathTraversal(result.data);

    return result.data;
  }

  private checkForInjection(data: any) {
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER)\b)/i,
      /(-{2}|\/\*|\*\/|;|'|")/
    ];

    const stringValues = this.extractStrings(data);
    for (const value of stringValues) {
      for (const pattern of sqlPatterns) {
        if (pattern.test(value)) {
          throw new SecurityException('Potential injection detected');
        }
      }
    }
  }
}
```

#### XSS Prevention

```typescript
class XSSProtection {
  sanitizeHTML(input: string): string {
    return DOMPurify.sanitize(input, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
      ALLOWED_ATTR: ['href'],
      ALLOW_DATA_ATTR: false
    });
  }

  escapeForDisplay(text: string): string {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;'
    };
    return text.replace(/[&<>"'/]/g, (s) => map[s]);
  }
}
```

### 6. Session Management

#### Secure Session Handling
**Location**: `src/modules/auth/session.ts`

```typescript
class SessionManager {
  async createSession(userId: string, metadata: SessionMetadata) {
    const sessionId = generateSecureId();
    const fingerprint = await this.generateFingerprint(metadata);

    const session = {
      id: sessionId,
      userId,
      fingerprint,
      ipAddress: metadata.ipAddress,
      userAgent: metadata.userAgent,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      expiresAt: Date.now() + SESSION_DURATION
    };

    await this.kv.put(`session:${sessionId}`, session, {
      expirationTtl: SESSION_DURATION
    });

    return sessionId;
  }

  async validateSession(sessionId: string, metadata: SessionMetadata) {
    const session = await this.kv.get(`session:${sessionId}`);

    if (!session) {
      throw new UnauthorizedError('Invalid session');
    }

    // Validate fingerprint
    const fingerprint = await this.generateFingerprint(metadata);
    if (session.fingerprint !== fingerprint) {
      await this.terminateSession(sessionId);
      throw new SecurityException('Session hijacking detected');
    }

    // Check expiration
    if (session.expiresAt < Date.now()) {
      await this.terminateSession(sessionId);
      throw new UnauthorizedError('Session expired');
    }

    // Update last activity
    session.lastActivity = Date.now();
    await this.kv.put(`session:${sessionId}`, session);

    return session;
  }
}
```

### 7. Audit Logging

#### Comprehensive Audit Trail
**Location**: `src/modules/audit/audit-service.ts`

```typescript
interface AuditLog {
  id: string;
  timestamp: Date;
  businessId: string;
  userId: string;
  sessionId: string;
  action: string;
  resource: string;
  resourceId?: string;
  oldValue?: any;
  newValue?: any;
  ipAddress: string;
  userAgent: string;
  result: 'success' | 'failure';
  errorMessage?: string;
  metadata?: Record<string, any>;
}

class AuditService {
  async log(event: AuditEvent) {
    const log: AuditLog = {
      id: generateUUID(),
      timestamp: new Date(),
      ...event,
      ipAddress: this.getClientIP(),
      userAgent: this.getUserAgent()
    };

    // Store in database
    await this.db.auditLogs.insert(log);

    // Stream to SIEM if configured
    if (this.siemEndpoint) {
      await this.streamToSIEM(log);
    }

    // Alert on suspicious activity
    await this.detectAnomalies(log);
  }

  async detectAnomalies(log: AuditLog) {
    const patterns = [
      this.checkRapidPrivilegeEscalation,
      this.checkUnusualAccessPattern,
      this.checkDataExfiltration,
      this.checkBruteForceAttempt
    ];

    for (const pattern of patterns) {
      const anomaly = await pattern(log);
      if (anomaly) {
        await this.alertSecurityTeam(anomaly);
      }
    }
  }
}
```

### 8. Vulnerability Management

#### Security Headers
**Location**: `src/middleware/security.ts`

```typescript
const SecurityHeaders = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self' data:",
    "connect-src 'self' https://api.anthropic.com",
    "frame-ancestors 'none'"
  ].join('; '),
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
};
```

#### Dependency Scanning

```typescript
class SecurityScanner {
  async scanDependencies() {
    const vulnerabilities = await this.runAudit();

    for (const vuln of vulnerabilities) {
      if (vuln.severity === 'critical' || vuln.severity === 'high') {
        await this.alertAndLog(vuln);

        if (vuln.fixAvailable) {
          await this.attemptAutoFix(vuln);
        }
      }
    }

    return vulnerabilities;
  }
}
```

### 9. Secrets Management

#### Environment Variable Security
**Location**: `src/shared/environment-validator.ts`

```typescript
class EnvironmentValidator {
  static validate(env: Env) {
    // Check for required secrets
    if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters');
    }

    if (!env.ENCRYPTION_KEY || !this.isValidKey(env.ENCRYPTION_KEY)) {
      throw new Error('Invalid ENCRYPTION_KEY');
    }

    // Validate API keys
    if (env.ANTHROPIC_API_KEY && !env.ANTHROPIC_API_KEY.startsWith('sk-')) {
      throw new Error('Invalid ANTHROPIC_API_KEY format');
    }

    // Check for default/development values in production
    if (env.ENVIRONMENT === 'production') {
      this.checkNoDefaultSecrets(env);
    }
  }

  private static checkNoDefaultSecrets(env: Env) {
    const defaults = ['secret', 'password', 'changeme', 'default'];
    const secrets = [env.JWT_SECRET, env.ENCRYPTION_KEY, env.ADMIN_PASSWORD];

    for (const secret of secrets) {
      if (defaults.some(d => secret?.toLowerCase().includes(d))) {
        throw new Error('Default secrets detected in production');
      }
    }
  }
}
```

#### Secret Rotation
**Location**: `src/modules/auth/jwt-secret-rotation.ts`

```typescript
class JWTSecretRotation {
  async rotateSecret() {
    // Generate new secret
    const newSecret = await this.generateSecureSecret();

    // Store with version
    const version = Date.now();
    await this.kv.put(`jwt_secret_v${version}`, newSecret);

    // Keep old secret for grace period
    await this.kv.put('jwt_secret_current', newSecret);
    await this.kv.put('jwt_secret_previous', this.currentSecret);

    // Schedule cleanup
    setTimeout(() => {
      this.kv.delete('jwt_secret_previous');
    }, ROTATION_GRACE_PERIOD);

    // Notify services
    await this.notifyRotation(version);
  }
}
```

### 10. Compliance & Privacy

#### GDPR Compliance

```typescript
class GDPRCompliance {
  async handleDataRequest(userId: string, type: 'access' | 'portability' | 'erasure') {
    switch (type) {
      case 'access':
        return this.exportUserData(userId);

      case 'portability':
        return this.exportPortableData(userId);

      case 'erasure':
        await this.validateErasureRequest(userId);
        return this.eraseUserData(userId);
    }
  }

  async eraseUserData(userId: string) {
    // Anonymize instead of delete for audit trail
    await this.db.transaction(async (tx) => {
      await tx.users.update(userId, {
        email: `deleted-${userId}@example.com`,
        firstName: 'DELETED',
        lastName: 'USER',
        personalData: null
      });

      // Remove from all non-essential tables
      await tx.personalInfo.delete({ userId });
      await tx.preferences.delete({ userId });
    });

    // Schedule complete removal after retention period
    await this.scheduleCompleteRemoval(userId, RETENTION_PERIOD);
  }
}
```

#### Data Retention Policies

```typescript
const RetentionPolicies = {
  auditLogs: 7 * 365,      // 7 years
  financialRecords: 7 * 365, // 7 years
  userSessions: 90,        // 90 days
  tempFiles: 1,            // 1 day
  cacheData: 7,            // 7 days
  backups: 30              // 30 days
};

class DataRetention {
  async enforceRetention() {
    for (const [dataType, days] of Object.entries(RetentionPolicies)) {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - days);

      await this.purgeOldData(dataType, cutoffDate);
    }
  }
}
```

## Security Monitoring

### Real-time Threat Detection

```typescript
class ThreatDetection {
  async analyzeActivity(activity: UserActivity) {
    const threats = [];

    // Check for suspicious patterns
    if (await this.isPasswordSpray(activity)) {
      threats.push({ type: 'password_spray', severity: 'high' });
    }

    if (await this.isAccountTakeover(activity)) {
      threats.push({ type: 'account_takeover', severity: 'critical' });
    }

    if (await this.isDataExfiltration(activity)) {
      threats.push({ type: 'data_exfiltration', severity: 'critical' });
    }

    if (threats.length > 0) {
      await this.respondToThreats(threats, activity);
    }

    return threats;
  }
}
```

### Security Dashboard

```typescript
interface SecurityMetrics {
  failedLogins: number;
  suspiciousActivities: number;
  blockedRequests: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  compliance: {
    gdpr: boolean;
    pci: boolean;
    soc2: boolean;
  };
}
```

## Incident Response

### Response Plan

```typescript
class IncidentResponse {
  async handleIncident(incident: SecurityIncident) {
    // 1. Contain
    await this.containThreat(incident);

    // 2. Assess
    const impact = await this.assessImpact(incident);

    // 3. Notify
    await this.notifyStakeholders(incident, impact);

    // 4. Remediate
    await this.remediateThreat(incident);

    // 5. Document
    await this.documentIncident(incident);

    // 6. Review
    await this.schedulePostMortem(incident);
  }
}
```

## Best Practices

1. **Defense in Depth**: Multiple security layers
2. **Least Privilege**: Minimal necessary permissions
3. **Zero Trust**: Verify everything, trust nothing
4. **Secure by Default**: Security enabled out of the box
5. **Regular Audits**: Continuous security assessment
6. **Incident Preparation**: Ready response procedures
7. **Security Training**: Regular team education
8. **Compliance Focus**: Meet regulatory requirements

## Support

- **Security Issues**: security@coreflow360.com
- **Bug Bounty**: bounty.coreflow360.com
- **Documentation**: docs.coreflow360.com/security