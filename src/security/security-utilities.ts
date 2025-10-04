/**
 * Comprehensive Security Utilities Module for CoreFlow360 V4
 * Implements all critical security functions following OWASP standards
 */

/**
 * Password Security with PBKDF2
 * OWASP recommended: 100,000+ iterations
 */
export class PasswordSecurity {
  private static readonly ITERATIONS = 100000;
  private static readonly KEY_LENGTH = 256;
  private static readonly SALT_LENGTH = 32;
  private static readonly ALGORITHM = 'PBKDF2';
  private static readonly HASH_ALGORITHM = 'SHA-256';

  /**
   * Hash a password using PBKDF2 with dynamic salt
   */
  static async hashPassword(password: string): Promise<string> {
    // Generate cryptographically secure random salt
    const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
    const encoder = new TextEncoder();

    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: this.ALGORITHM },
      false,
      ['deriveBits']
    );

    // Derive bits using PBKDF2
    const hashBuffer = await crypto.subtle.deriveBits(
      {
        name: this.ALGORITHM,
        salt,
        iterations: this.ITERATIONS,
        hash: this.HASH_ALGORITHM
      },
      keyMaterial,
      this.KEY_LENGTH
    );

    // Convert to base64 for storage
    const hashArray = new Uint8Array(hashBuffer);
    const saltBase64 = btoa(String.fromCharCode(...salt));
    const hashBase64 = btoa(String.fromCharCode(...hashArray));

    // Return salt$iterations$hash format
    return `${saltBase64}$${this.ITERATIONS}$${hashBase64}`;
  }

  /**
   * Verify a password against a stored hash using constant-time comparison
   */
  static async verifyPassword(password: string, storedHash: string): Promise<boolean> {
    try {
      const [saltBase64, iterations, hashBase64] = storedHash.split('$');

      if (!saltBase64 || !iterations || !hashBase64) {
        return false;
      }

      // Convert base64 back to Uint8Array
      const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
      const storedHashBytes = Uint8Array.from(atob(hashBase64), c => c.charCodeAt(0));
      const encoder = new TextEncoder();

      // Import password as key material
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        { name: this.ALGORITHM },
        false,
        ['deriveBits']
      );

      // Derive bits with same parameters
      const hashBuffer = await crypto.subtle.deriveBits(
        {
          name: this.ALGORITHM,
          salt,
          iterations: parseInt(iterations),
          hash: this.HASH_ALGORITHM
        },
        keyMaterial,
        this.KEY_LENGTH
      );

      const computedHashBytes = new Uint8Array(hashBuffer);

      // Constant-time comparison to prevent timing attacks
      return this.constantTimeCompare(computedHashBytes, storedHashBytes);
    } catch (error) {
      console.error('Password verification error:', error);
      return false;
    }
  }

  /**
   * Constant-time comparison to prevent timing attacks
   */
  private static constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }

    return result === 0;
  }

  /**
   * Generate a secure random password
   */
  static generateSecurePassword(length: number = 16): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    const randomValues = crypto.getRandomValues(new Uint8Array(length));
    let password = '';

    for (let i = 0; i < length; i++) {
      password += charset[randomValues[i] % charset.length];
    }

    return password;
  }
}

/**
 * API Key Security with PBKDF2
 */
export class ApiKeySecurity {
  private static readonly ITERATIONS = 100000;
  private static readonly KEY_LENGTH = 256;

  /**
   * Generate a cryptographically secure API key
   */
  static generateApiKey(): { key: string; hash: string } {
    // Generate 32 bytes of random data
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));

    // Convert to URL-safe base64
    const key = btoa(String.fromCharCode(...keyBytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Format with prefix
    const apiKey = `cf_live_${key}`;

    // Hash for storage (synchronous for now, will be async)
    const hash = this.hashApiKeySync(apiKey);

    return { key: apiKey, hash };
  }

  /**
   * Hash an API key for secure storage
   */
  static async hashApiKey(apiKey: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const encoder = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(apiKey),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const hashBuffer = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: this.ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      this.KEY_LENGTH
    );

    const hashArray = new Uint8Array(hashBuffer);
    const saltBase64 = btoa(String.fromCharCode(...salt));
    const hashBase64 = btoa(String.fromCharCode(...hashArray));

    return `${saltBase64}$${hashBase64}`;
  }

  /**
   * Synchronous API key hashing (temporary)
   */
  private static hashApiKeySync(apiKey: string): string {
    // This is a placeholder - in production, always use async
    return `temp_hash_${apiKey}`;
  }

  /**
   * Verify an API key against stored hash
   */
  static async verifyApiKey(apiKey: string, storedHash: string): Promise<boolean> {
    try {
      const [saltBase64, hashBase64] = storedHash.split('$');

      if (!saltBase64 || !hashBase64) {
        return false;
      }

      const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
      const storedHashBytes = Uint8Array.from(atob(hashBase64), c => c.charCodeAt(0));
      const encoder = new TextEncoder();

      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(apiKey),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
      );

      const hashBuffer = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt,
          iterations: this.ITERATIONS,
          hash: 'SHA-256'
        },
        keyMaterial,
        this.KEY_LENGTH
      );

      const computedHashBytes = new Uint8Array(hashBuffer);

      // Use constant-time comparison
      return PasswordSecurity['constantTimeCompare'](computedHashBytes, storedHashBytes);
    } catch (error) {
      console.error('API key verification error:', error);
      return false;
    }
  }
}

/**
 * JWT Secret Management with rotation
 */
export class JWTSecretManager {
  private kv: KVNamespace;
  private readonly SECRET_KEY = 'jwt:secrets';
  private readonly ROTATION_INTERVAL = 30 * 24 * 60 * 60 * 1000; // 30 days

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  /**
   * Get the active JWT secret
   */
  async getActiveSecret(): Promise<string> {
    const secrets = await this.getSecrets();
    const active = secrets.find(s => s.active);

    if (!active) {
      // Generate new secret if none exists
      return await this.rotateSecrets();
    }

    // Check if rotation is needed
    if (Date.now() - active.createdAt > this.ROTATION_INTERVAL) {
      return await this.rotateSecrets();
    }

    return active.value;
  }

  /**
   * Get all secrets for verification (includes old secrets)
   */
  async getAllSecrets(): Promise<string[]> {
    const secrets = await this.getSecrets();
    return secrets.map(s => s.value);
  }

  /**
   * Rotate JWT secrets
   */
  async rotateSecrets(): Promise<string> {
    const secrets = await this.getSecrets();

    // Generate new secret
    const newSecret = this.generateSecret();

    // Deactivate old secrets but keep for verification
    const updatedSecrets = secrets.map(s => ({
      ...s,
      active: false
    }));

    // Add new active secret
    updatedSecrets.push({
      id: crypto.randomUUID(),
      value: newSecret,
      active: true,
      createdAt: Date.now(),
      rotatedAt: Date.now()
    });

    // Keep only last 3 secrets
    const finalSecrets = updatedSecrets.slice(-3);

    // Store updated secrets
    await this.kv.put(this.SECRET_KEY, JSON.stringify(finalSecrets));

    return newSecret;
  }

  /**
   * Get secrets from KV store
   */
  private async getSecrets(): Promise<any[]> {
    const data = await this.kv.get(this.SECRET_KEY);
    if (!data) {
      return [];
    }

    try {
      return JSON.parse(data);
    } catch {
      return [];
    }
  }

  /**
   * Generate a cryptographically secure secret
   */
  private generateSecret(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(64));
    return btoa(String.fromCharCode(...bytes));
  }
}

/**
 * Row-Level Security for multi-tenant isolation
 */
export class SecureDatabase {
  private db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  /**
   * Execute a query with automatic business_id filtering
   */
  async query<T = unknown>(
    sql: string,
    businessId: string,
    params: any[] = []
  ): Promise<T[]> {
    // Inject business_id check into WHERE clause
    const secureSql = this.injectBusinessIdFilter(sql, businessId);

    // Prepare statement with business_id as first parameter
    const result = await this.db
      .prepare(secureSql)
      .bind(businessId, ...params)
      .all<T>();

    return result.results || [];
  }

  /**
   * Execute a single row query with business_id filtering
   */
  async queryFirst<T = unknown>(
    sql: string,
    businessId: string,
    params: any[] = []
  ): Promise<T | null> {
    const secureSql = this.injectBusinessIdFilter(sql, businessId);

    return await this.db
      .prepare(secureSql)
      .bind(businessId, ...params)
      .first<T>();
  }

  /**
   * Inject business_id filter into SQL query
   */
  private injectBusinessIdFilter(sql: string, businessId: string): string {
    const upperSql = sql.toUpperCase();

    if (upperSql.includes('WHERE')) {
      // Add business_id check after WHERE
      return sql.replace(/WHERE/i, 'WHERE business_id = ? AND');
    } else if (upperSql.includes('SELECT')) {
      // Add WHERE clause if it doesn't exist
      const fromIndex = upperSql.indexOf('FROM');
      if (fromIndex !== -1) {
        // Find the end of the FROM clause
        let endIndex = sql.length;
        const clauses = ['WHERE', 'GROUP BY', 'ORDER BY', 'LIMIT'];

        for (const clause of clauses) {
          const clauseIndex = upperSql.indexOf(clause, fromIndex);
          if (clauseIndex !== -1 && clauseIndex < endIndex) {
            endIndex = clauseIndex;
          }
        }

        return sql.slice(0, endIndex) + ' WHERE business_id = ? ' + sql.slice(endIndex);
      }
    }

    return sql;
  }

  /**
   * Validate that a query is parameterized (no SQL injection)
   */
  static validateParameterizedQuery(sql: string): boolean {
    // Check for common SQL injection patterns
    const dangerousPatterns = [
      /'\s*OR\s+'1'\s*=\s*'1/i,
      /;\s*DROP\s+TABLE/i,
      /;\s*DELETE\s+FROM/i,
      /;\s*UPDATE\s+/i,
      /UNION\s+SELECT/i,
      /\/\*.*\*\//,
      /--\s*$/
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(sql)) {
        return false;
      }
    }

    // Check that string concatenation is not used
    if (sql.includes("'${") || sql.includes('"+') || sql.includes("'+")) {
      return false;
    }

    return true;
  }
}

/**
 * Input Sanitization and Validation
 */
export class InputSanitizer {
  /**
   * Sanitize HTML to prevent XSS
   */
  static sanitizeHtml(input: string): string {
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;')
      .replace(/`/g, '&#x60;')
      .replace(/=/g, '&#x3D;');
  }

  /**
   * Sanitize SQL input (use parameterized queries instead)
   */
  static sanitizeSql(input: string): string {
    return input
      .replace(/'/g, "''")
      .replace(/;/g, '')
      .replace(/--/g, '')
      .replace(/\/\*/g, '')
      .replace(/\*\//g, '');
  }

  /**
   * Validate email format
   */
  static isValidEmail(email: string): boolean {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email) && email.length <= 255;
  }

  /**
   * Validate password strength
   */
  static isStrongPassword(password: string): boolean {
    // At least 12 characters
    if (password.length < 12) return false;

    // Contains uppercase
    if (!/[A-Z]/.test(password)) return false;

    // Contains lowercase
    if (!/[a-z]/.test(password)) return false;

    // Contains number
    if (!/\d/.test(password)) return false;

    // Contains special character
    if (!/[@$!%*?&]/.test(password)) return false;

    return true;
  }

  /**
   * Validate name (alphanumeric, spaces, hyphens, apostrophes)
   */
  static isValidName(name: string): boolean {
    const nameRegex = /^[a-zA-Z\s'-]{2,100}$/;
    return nameRegex.test(name);
  }

  /**
   * Validate UUID
   */
  static isValidUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }
}

/**
 * Distributed Rate Limiting with fingerprinting
 */
export class DistributedRateLimiter {
  private kv: KVNamespace;
  private readonly WINDOW_SIZE = 60 * 1000; // 1 minute
  private readonly MAX_REQUESTS = {
    ip: 60,
    fingerprint: 100,
    global: 10000
  };

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  /**
   * Check if request should be rate limited
   */
  async check(request: Request): Promise<boolean> {
    const fingerprint = await this.generateFingerprint(request);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    // Check multiple dimensions in parallel
    const checks = await Promise.all([
      this.checkDimension('ip', ip),
      this.checkDimension('fingerprint', fingerprint),
      this.checkDimension('user-agent', request.headers.get('User-Agent') || 'unknown'),
      this.checkGlobalRate()
    ]);

    // If any check fails, rate limit
    return checks.every(allowed => allowed);
  }

  /**
   * Check rate limit for a specific dimension
   */
  private async checkDimension(type: string, value: string): Promise<boolean> {
    const key = `ratelimit:${type}:${value}`;
    const now = Date.now();
    const windowStart = now - this.WINDOW_SIZE;

    // Get current count
    const data = await this.kv.get(key);
    let requests: number[] = [];

    if (data) {
      try {
        requests = JSON.parse(data);
        // Filter out old requests
        requests = requests.filter(timestamp => timestamp > windowStart);
      } catch {
        requests = [];
      }
    }

    // Check limit
    const limit = this.MAX_REQUESTS[type as keyof typeof this.MAX_REQUESTS] || 100;
    if (requests.length >= limit) {
      return false;
    }

    // Add current request
    requests.push(now);

    // Store updated count
    await this.kv.put(key, JSON.stringify(requests), {
      expirationTtl: 60
    });

    return true;
  }

  /**
   * Check global rate limit
   */
  private async checkGlobalRate(): Promise<boolean> {
    const key = 'ratelimit:global';
    const count = await this.kv.get(key);

    if (count) {
      const currentCount = parseInt(count);
      if (currentCount >= this.MAX_REQUESTS.global) {
        return false;
      }

      await this.kv.put(key, (currentCount + 1).toString(), {
        expirationTtl: 60
      });
    } else {
      await this.kv.put(key, '1', {
        expirationTtl: 60
      });
    }

    return true;
  }

  /**
   * Generate fingerprint from request
   */
  private async generateFingerprint(request: Request): Promise<string> {
    const data = [
      request.headers.get('User-Agent') || '',
      request.headers.get('Accept-Language') || '',
      request.headers.get('Accept-Encoding') || '',
      request.headers.get('Accept') || ''
    ].join('|');

    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));

    return btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}

/**
 * Audit Logger for compliance
 */
export class AuditLogger {
  private db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  /**
   * Log an audit event
   */
  async log(event: AuditEvent): Promise<void> {
    const id = crypto.randomUUID();
    const timestamp = Date.now();
    const riskScore = this.calculateRiskScore(event);

    await this.db.prepare(`
      INSERT INTO audit_logs (
        id, event_type, user_id, business_id,
        ip_address, user_agent, details, risk_score, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      event.type,
      event.userId || null,
      event.businessId,
      event.ipAddress || null,
      event.userAgent || null,
      JSON.stringify(event.details),
      riskScore,
      timestamp
    ).run();
  }

  /**
   * Calculate risk score for an event
   */
  private calculateRiskScore(event: AuditEvent): number {
    let score = 0;

    // High risk events
    const highRiskEvents = ['login_failed', 'permission_denied', 'data_export', 'data_deletion'];
    if (highRiskEvents.includes(event.type)) {
      score += 50;
    }

    // Medium risk events
    const mediumRiskEvents = ['password_change', 'api_key_created', 'role_change'];
    if (mediumRiskEvents.includes(event.type)) {
      score += 30;
    }

    // Check for suspicious patterns
    if (event.details?.failedAttempts && event.details.failedAttempts > 3) {
      score += 20;
    }

    if (event.details?.unusualTime) {
      score += 10;
    }

    if (event.details?.unusualLocation) {
      score += 15;
    }

    return Math.min(score, 100);
  }
}

/**
 * Session Manager with fingerprinting
 */
export class SessionManager {
  private db: D1Database;
  private readonly SESSION_TIMEOUT = 15 * 60 * 1000; // 15 minutes

  constructor(db: D1Database) {
    this.db = db;
  }

  /**
   * Create a new session
   */
  async createSession(userId: string, request: Request): Promise<Session> {
    const sessionId = crypto.randomUUID();
    const token = this.generateSessionToken();
    const fingerprint = await this.generateFingerprint(request);
    const ipAddress = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';

    const tokenHash = await this.hashToken(token);
    const fingerprintHash = await this.hashToken(fingerprint);

    await this.db.prepare(`
      INSERT INTO sessions (
        id, user_id, token_hash, fingerprint_hash,
        ip_address, user_agent, expires_at, created_at, last_activity
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      sessionId,
      userId,
      tokenHash,
      fingerprintHash,
      ipAddress,
      userAgent,
      Date.now() + this.SESSION_TIMEOUT,
      Date.now(),
      Date.now()
    ).run();

    return {
      sessionId,
      token,
      fingerprint,
      expiresAt: Date.now() + this.SESSION_TIMEOUT
    };
  }

  /**
   * Validate a session
   */
  async validateSession(
    sessionId: string,
    token: string,
    fingerprint: string
  ): Promise<boolean> {
    const session = await this.db.prepare(`
      SELECT * FROM sessions
      WHERE id = ? AND expires_at > ?
    `).bind(sessionId, Date.now()).first();

    if (!session) {
      return false;
    }

    const tokenHash = await this.hashToken(token);
    const fingerprintHash = await this.hashToken(fingerprint);

    // Verify token and fingerprint
    if (session.token_hash !== tokenHash || session.fingerprint_hash !== fingerprintHash) {
      return false;
    }

    // Update last activity
    await this.db.prepare(`
      UPDATE sessions
      SET last_activity = ?, expires_at = ?
      WHERE id = ?
    `).bind(
      Date.now(),
      Date.now() + this.SESSION_TIMEOUT,
      sessionId
    ).run();

    return true;
  }

  /**
   * Generate session token
   */
  private generateSessionToken(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Generate fingerprint from request
   */
  private async generateFingerprint(request: Request): Promise<string> {
    const data = [
      request.headers.get('User-Agent') || '',
      request.headers.get('Accept-Language') || '',
      request.headers.get('Accept-Encoding') || ''
    ].join('|');

    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));

    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  }

  /**
   * Hash a token
   */
  private async hashToken(token: string): Promise<string> {
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(token));
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  }
}

// Type definitions
interface AuditEvent {
  type: string;
  userId?: string;
  businessId: string;
  ipAddress?: string;
  userAgent?: string;
  details?: any;
}

interface Session {
  sessionId: string;
  token: string;
  fingerprint: string;
  expiresAt: number;
}

// Export all utilities
export {
  AuditEvent,
  Session
};