/**
 * Enhanced API Key Security with PBKDF2 (Cloudflare Workers Compatible)
 * SECURITY: Replaces weak SHA-256 hashing with PBKDF2
 * Fixes: CVSS 6.5 vulnerability - Weak cryptographic hashing
 * Note: Uses PBKDF2 instead of Argon2 for Cloudflare Workers compatibility
 */

export interface ApiKeyConfig {
  prefix: string; // API key prefix (e.g., 'cf_')
  keyLength: number; // Length of random part
  iterations: number; // PBKDF2 iterations
  keySize: number; // PBKDF2 key size in bits
  saltLength: number; // Salt length in bytes
}

export interface ApiKeyData {
  id: string;
  userId: string;
  businessId: string;
  name: string;
  keyHash: string;
  permissions: string[];
  rateLimit: {
    requests: number;
    window: number; // seconds
  };
  createdAt: number;
  lastUsedAt?: number;
  expiresAt?: number;
  isActive: boolean;
  metadata?: Record<string, any>;
}

export interface ApiKeyValidation {
  valid: boolean;
  keyData?: ApiKeyData;
  error?: string;
  remainingRequests?: number;
  resetTime?: number;
}

export class EnhancedApiKeySecurity {
  private readonly kv: KVNamespace;
  private readonly config: ApiKeyConfig;
  private readonly keyPrefix = 'api_key:';
  private readonly rateLimitPrefix = 'api_key:rate:';
  private readonly blacklistPrefix = 'api_key:blacklist:';

  constructor(kv: KVNamespace, config?: Partial<ApiKeyConfig>) {
    this.kv = kv;
    this.config = {
      prefix: config?.prefix || 'cf_',
      keyLength: config?.keyLength || 32,
      iterations: config?.iterations || 300000, // 300k iterations (OWASP recommended minimum)
      keySize: config?.keySize || 256, // 256 bits
      saltLength: config?.saltLength || 16
    };
  }

  /**
   * Generate a new API key with PBKDF2 hashing
   */
  async generateApiKey(
    userId: string,
    businessId: string,
    name: string,
    permissions: string[],
    expiresInDays?: number
  ): Promise<{ apiKey: string; keyData: ApiKeyData }> {
    // Generate secure random key
    const rawKey = this.generateSecureKey();
    const apiKey = `${this.config.prefix}${rawKey}`;

    // Hash with Argon2id
    const keyHash = await this.hashApiKey(apiKey);

    // Create key data
    const keyData: ApiKeyData = {
      id: crypto.randomUUID(),
      userId,
      businessId,
      name,
      keyHash,
      permissions,
      rateLimit: {
        requests: this.determineRateLimit(permissions),
        window: 3600 // 1 hour
      },
      createdAt: Date.now(),
      expiresAt: expiresInDays ? Date.now() + (expiresInDays * 24 * 60 * 60 * 1000) : undefined,
      isActive: true,
      metadata: {
        createdBy: 'api',
        environment: 'production'
      }
    };

    // Store key data
    await this.storeApiKey(keyData);

    // Log key creation
    await this.logApiKeyEvent(keyData.id, 'created', userId);

    return { apiKey, keyData };
  }

  /**
   * Validate API key with enhanced security checks
   */
  async validateApiKey(apiKey: string): Promise<ApiKeyValidation> {
    try {
      // Check blacklist first
      if (await this.isBlacklisted(apiKey)) {
        return { valid: false, error: 'API key is blacklisted' };
      }

      // Check format
      if (!apiKey.startsWith(this.config.prefix)) {
        return { valid: false, error: 'Invalid API key format' };
      }

      // Get all API keys (in production, use proper indexing)
      const { keys } = await this.kv.list({ prefix: this.keyPrefix });

      for (const key of keys) {
        const keyDataJson = await this.kv.get(key.name);
        if (!keyDataJson) continue;

        const keyData: ApiKeyData = JSON.parse(keyDataJson);

        // Skip inactive keys
        if (!keyData.isActive) continue;

        // Verify hash with Argon2
        const matches = await this.verifyApiKey(apiKey, keyData.keyHash);

        if (matches) {
          // Check expiration
          if (keyData.expiresAt && keyData.expiresAt <= Date.now()) {
            await this.deactivateApiKey(keyData.id);
            return { valid: false, error: 'API key expired' };
          }

          // Check rate limit
          const rateLimitCheck = await this.checkRateLimit(keyData.id, keyData.rateLimit);
          if (!rateLimitCheck.allowed) {
            return {
              valid: false,
              error: 'Rate limit exceeded',
              remainingRequests: 0,
              resetTime: rateLimitCheck.resetTime
            };
          }

          // Update last used timestamp
          keyData.lastUsedAt = Date.now();
          await this.storeApiKey(keyData);

          // Log successful validation
          await this.logApiKeyEvent(keyData.id, 'validated', keyData.userId);

          return {
            valid: true,
            keyData,
            remainingRequests: rateLimitCheck.remaining,
            resetTime: rateLimitCheck.resetTime
          };
        }
      }

      // No matching key found
      await this.logApiKeyEvent('unknown', 'validation_failed', 'unknown', { apiKey: apiKey.substring(0, 10) + '...' });
      return { valid: false, error: 'Invalid API key' };

    } catch (error: any) {
      console.error('API key validation error:', error);
      return { valid: false, error: 'Validation failed' };
    }
  }

  /**
   * Rotate API key (generate new key, deprecate old)
   */
  async rotateApiKey(
    oldApiKey: string,
    gracePeriodDays = 7
  ): Promise<{ apiKey: string; keyData: ApiKeyData } | null> {
    const validation = await this.validateApiKey(oldApiKey);

    if (!validation.valid || !validation.keyData) {
      return null;
    }

    const oldKeyData = validation.keyData;

    // Generate new key
    const result = await this.generateApiKey(
      oldKeyData.userId,
      oldKeyData.businessId,
      `${oldKeyData.name} (Rotated)`,
      oldKeyData.permissions,
      oldKeyData.expiresAt ? Math.ceil((oldKeyData.expiresAt - Date.now()) / (24 * 60 * 60 * 1000)) : undefined
    );

    // Set grace period for old key
    oldKeyData.expiresAt = Date.now() + (gracePeriodDays * 24 * 60 * 60 * 1000);
    oldKeyData.metadata = oldKeyData.metadata || {};
    oldKeyData.metadata.rotatedAt = Date.now();
    oldKeyData.metadata.replacedBy = result.keyData.id;
    await this.storeApiKey(oldKeyData);

    // Log rotation
    await this.logApiKeyEvent(result.keyData.id, 'rotated', oldKeyData.userId, {
      oldKeyId: oldKeyData.id
    });

    return result;
  }

  /**
   * Revoke API key immediately
   */
  async revokeApiKey(apiKey: string, reason: string): Promise<boolean> {
    const validation = await this.validateApiKey(apiKey);

    if (!validation.valid || !validation.keyData) {
      return false;
    }

    const keyData = validation.keyData;

    // Deactivate key
    keyData.isActive = false;
    keyData.metadata = keyData.metadata || {};
    keyData.metadata.revokedAt = Date.now();
    keyData.metadata.revokeReason = reason;
    await this.storeApiKey(keyData);

    // Add to blacklist
    await this.blacklistApiKey(apiKey);

    // Log revocation
    await this.logApiKeyEvent(keyData.id, 'revoked', keyData.userId, { reason });

    return true;
  }

  /**
   * Generate cryptographically secure API key
   */
  private generateSecureKey(): string {
    const bytes = new Uint8Array(this.config.keyLength);
    crypto.getRandomValues(bytes);

    // Convert to URL-safe base64
    const base64 = btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    return base64.substring(0, this.config.keyLength);
  }

  /**
   * Hash API key using PBKDF2 (Web Crypto API compatible)
   */
  private async hashApiKey(apiKey: string): Promise<string> {
    // Generate salt
    const salt = crypto.getRandomValues(new Uint8Array(this.config.saltLength));

    // Import API key as key material
    const keyBuffer = new TextEncoder().encode(apiKey);
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    // Derive hash using PBKDF2
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: this.config.iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      this.config.keySize
    );

    // Convert to storable format
    const hashBytes = new Uint8Array(derivedBits);
    const saltB64 = btoa(String.fromCharCode(...salt));
    const hashB64 = btoa(String.fromCharCode(...hashBytes));

    // Return in format: algorithm$iterations$salt$hash
    return `pbkdf2-sha256$${this.config.iterations}$${saltB64}$${hashB64}`;
  }

  /**
   * Verify API key against hash using PBKDF2
   */
  private async verifyApiKey(apiKey: string, keyHash: string): Promise<boolean> {
    try {
      const parts = keyHash.split('$');

      if (parts.length !== 4) {
        return false;
      }

      const [algorithm, iterations, saltB64, hashB64] = parts;

      if (algorithm !== 'pbkdf2-sha256') {
        return false;
      }

      const iterationCount = parseInt(iterations, 10);
      if (isNaN(iterationCount) || iterationCount < 100000) {
        return false;
      }

      // Decode salt and hash
      const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
      const storedHashBytes = Uint8Array.from(atob(hashB64), c => c.charCodeAt(0));

      // Derive key with same parameters
      const keyBuffer = new TextEncoder().encode(apiKey);
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
      );

      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: iterationCount,
          hash: 'SHA-256'
        },
        keyMaterial,
        storedHashBytes.length * 8
      );

      const computedHashBytes = new Uint8Array(derivedBits);

      // Constant-time comparison
      return this.constantTimeEquals(computedHashBytes, storedHashBytes);

    } catch (error) {
      return false;
    }
  }

  /**
   * Check rate limiting for API key
   */
  private async checkRateLimit(
    keyId: string,
    limit: { requests: number; window: number }
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = Math.floor(now / limit.window) * limit.window;
    const windowEnd = windowStart + limit.window;

    const rateLimitKey = `${this.rateLimitPrefix}${keyId}:${windowStart}`;

    // Get current count
    const currentCountStr = await this.kv.get(rateLimitKey);
    const currentCount = currentCountStr ? parseInt(currentCountStr) : 0;

    if (currentCount >= limit.requests) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: windowEnd
      };
    }

    // Increment counter
    await this.kv.put(
      rateLimitKey,
      (currentCount + 1).toString(),
      { expirationTtl: limit.window * 2 } // Keep for 2 windows for safety
    );

    return {
      allowed: true,
      remaining: limit.requests - currentCount - 1,
      resetTime: windowEnd
    };
  }

  /**
   * Determine rate limit based on permissions
   */
  private determineRateLimit(permissions: string[]): number {
    // Higher limits for more privileged keys
    if (permissions.includes('admin')) return 10000;
    if (permissions.includes('write')) return 5000;
    if (permissions.includes('read')) return 1000;
    return 100; // Default low limit
  }

  /**
   * Store API key data
   */
  private async storeApiKey(keyData: ApiKeyData): Promise<void> {
    const key = `${this.keyPrefix}${keyData.id}`;
    const ttl = keyData.expiresAt
      ? Math.ceil((keyData.expiresAt - Date.now()) / 1000)
      : 365 * 24 * 60 * 60; // 1 year default

    await this.kv.put(key, JSON.stringify(keyData), {
      expirationTtl: Math.max(ttl, 60) // Minimum 1 minute
    });
  }

  /**
   * Deactivate API key
   */
  private async deactivateApiKey(keyId: string): Promise<void> {
    const key = `${this.keyPrefix}${keyId}`;
    const dataStr = await this.kv.get(key);

    if (dataStr) {
      const keyData: ApiKeyData = JSON.parse(dataStr);
      keyData.isActive = false;
      await this.storeApiKey(keyData);
    }
  }

  /**
   * Blacklist API key
   */
  private async blacklistApiKey(apiKey: string): Promise<void> {
    // Hash the API key for storage (don't store plaintext)
    const hashedKey = await this.hashForBlacklist(apiKey);
    const blacklistKey = `${this.blacklistPrefix}${hashedKey}`;

    await this.kv.put(blacklistKey, JSON.stringify({
      addedAt: Date.now(),
      keyPrefix: apiKey.substring(0, 10) // Store prefix for debugging
    }), {
      expirationTtl: 90 * 24 * 60 * 60 // 90 days
    });
  }

  /**
   * Check if API key is blacklisted
   */
  private async isBlacklisted(apiKey: string): Promise<boolean> {
    const hashedKey = await this.hashForBlacklist(apiKey);
    const blacklistKey = `${this.blacklistPrefix}${hashedKey}`;
    const data = await this.kv.get(blacklistKey);
    return data !== null;
  }

  /**
   * Hash for blacklist (faster than Argon2)
   */
  private async hashForBlacklist(apiKey: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(apiKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Log API key events
   */
  private async logApiKeyEvent(
    keyId: string,
    event: string,
    userId: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    const logEntry = {
      keyId,
      event,
      userId,
      timestamp: Date.now(),
      metadata
    };

    await this.kv.put(
      `api_key:log:${Date.now()}_${keyId}`,
      JSON.stringify(logEntry),
      { expirationTtl: 30 * 24 * 60 * 60 } // 30 days
    );
  }

  /**
   * Constant-time comparison to prevent timing attacks
   */
  private constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
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
   * Get API key metrics
   */
  async getApiKeyMetrics(businessId?: string): Promise<{
    totalKeys: number;
    activeKeys: number;
    expiredKeys: number;
    revokedKeys: number;
    averageRequestsPerKey: number;
  }> {
    const { keys } = await this.kv.list({ prefix: this.keyPrefix });
    let totalKeys = 0;
    let activeKeys = 0;
    let expiredKeys = 0;
    let revokedKeys = 0;

    for (const key of keys) {
      const dataStr = await this.kv.get(key.name);
      if (!dataStr) continue;

      const keyData: ApiKeyData = JSON.parse(dataStr);

      if (businessId && keyData.businessId !== businessId) continue;

      totalKeys++;
      if (keyData.isActive) activeKeys++;
      if (keyData.expiresAt && keyData.expiresAt <= Date.now()) expiredKeys++;
      if (!keyData.isActive && keyData.metadata?.revokeReason) revokedKeys++;
    }

    return {
      totalKeys,
      activeKeys,
      expiredKeys,
      revokedKeys,
      averageRequestsPerKey: 0 // Would need to aggregate from rate limit data
    };
  }
}

// Export factory function
export function createEnhancedApiKeySecurity(kv: KVNamespace, config?: Partial<ApiKeyConfig>): EnhancedApiKeySecurity {
  return new EnhancedApiKeySecurity(kv, config);
}

// PBKDF2-based API Key Security for Cloudflare Workers
// Provides strong cryptographic security while maintaining compatibility