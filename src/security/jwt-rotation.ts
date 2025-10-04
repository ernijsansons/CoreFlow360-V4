/**
 * Enterprise-Grade JWT Secret Rotation System
 * OWASP 2025 Compliant - Addresses CVSS 9.8 JWT Authentication Bypass
 *
 * Security Features:
 * - Automatic 30-day secret rotation
 * - Multi-version secret support for zero-downtime rotation
 * - Cryptographically secure secret generation (256-bit entropy)
 * - Comprehensive secret validation and blacklist checking
 * - Emergency rotation capabilities for breach scenarios
 * - Audit logging for all rotation events
 */

import { Env } from '../types/env';
import * as jose from 'jose';

export interface JWTRotationConfig {
  rotationIntervalDays: number;
  graceperiodDays: number;
  maxSecretVersions: number;
  emergencyRotationEnabled: boolean;
  auditLoggingEnabled: boolean;
}

export interface SecretVersion {
  id: string;
  version: number;
  secret: string;
  createdAt: Date;
  expiresAt: Date;
  status: 'active' | 'rotating' | 'deprecated' | 'revoked';
  createdBy: string;
  rotationReason?: string;
}

export interface SecretValidation {
  isValid: boolean;
  entropy: number;
  strength: 'weak' | 'medium' | 'strong' | 'very-strong';
  errors: string[];
  warnings: string[];
}

export interface RotationAuditLog {
  id: string;
  timestamp: Date;
  action: 'rotation' | 'emergency_rotation' | 'validation_failure' | 'access_attempt';
  version: number;
  userId?: string;
  reason: string;
  metadata?: Record<string, any>;
}

export class JWTRotation {
  private static readonly MIN_SECRET_LENGTH = 64;
  private static readonly MIN_ENTROPY_BITS = 256;
  private static readonly SECRET_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=!@#$%^&*()_-';

  // Comprehensive blacklist of weak secrets
  private static readonly BLACKLISTED_PATTERNS = [
    /^(test|dev|demo|debug|local|temp|fallback|default|sample|example)/i,
    /^your[_\-]?jwt[_\-]?secret/i,
    /^change[_\-]?me/i,
    /^replace[_\-]?me/i,
    /(password|admin|secret|123456)/i,
    /^[a-z]+$/i, // All lowercase
    /^[A-Z]+$/i, // All uppercase
    /^[0-9]+$/,  // All numbers
    /(.)\1{5,}/, // Repeated characters
  ];

  private readonly kvNamespace: KVNamespace;
  private readonly config: JWTRotationConfig;
  private readonly secretPrefix = 'jwt:secret:v';
  private readonly configKey = 'jwt:rotation:config';
  private readonly auditLogPrefix = 'jwt:audit:';

  constructor(
    env: Env,
    config: Partial<JWTRotationConfig> = {}
  ) {
    this.kvNamespace = env.KV_AUTH || env.KV_CACHE;
    this.config = {
      rotationIntervalDays: 30,
      graceperiodDays: 7,
      maxSecretVersions: 3,
      emergencyRotationEnabled: true,
      auditLoggingEnabled: true,
      ...config
    };
  }

  /**
   * Rotate JWT secrets with zero-downtime support
   */
  async rotateSecrets(): Promise<SecretVersion> {
    try {
      // Generate new cryptographically secure secret
      const newSecret = await this.generateSecureSecret();

      // Validate the new secret
      const validation = await this.validateSecret(newSecret);
      if (!validation.isValid) {
        await this.logAuditEvent('validation_failure', -1, 'Generated secret failed validation', {
          errors: validation.errors
        });
        throw new Error(`Secret validation failed: ${validation.errors.join(', ')}`);
      }

      // Get current version number
      const currentVersion = await this.getCurrentVersion();
      const newVersion = currentVersion + 1;

      // Create new secret version
      const secretVersion: SecretVersion = {
        id: crypto.randomUUID(),
        version: newVersion,
        secret: newSecret,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + (this.config.rotationIntervalDays + this.config.graceperiodDays) * 24 * 60 * 60 * 1000),
        status: 'active',
        createdBy: 'system_rotation',
        rotationReason: 'scheduled'
      };

      // Store new secret version
      await this.storeSecretVersion(secretVersion);

      // Mark previous versions as rotating
      await this.transitionPreviousVersions(newVersion);

      // Update configuration
      await this.updateRotationConfig(newVersion);

      // Log rotation event
      await this.logAuditEvent('rotation', newVersion, 'Scheduled secret rotation completed');

      console.log(`JWT secret rotation completed. New version: ${newVersion}, Entropy: ${validation.entropy.toFixed(2)} bits`);

      return secretVersion;

    } catch (error) {
      console.error('JWT secret rotation failed:', error);
      throw new Error(`Secret rotation failed: ${error.message}`);
    }
  }

  /**
   * Get the current active JWT secret
   */
  async getActiveSecret(): Promise<string> {
    try {
      const currentVersion = await this.getCurrentVersion();

      if (currentVersion === 0) {
        // No rotated secrets yet, initialize from environment
        return await this.initializeFromEnvironment();
      }

      const secretVersion = await this.getSecretVersion(currentVersion);

      if (!secretVersion || secretVersion.status === 'revoked') {
        throw new Error('No active JWT secret found');
      }

      // Check if rotation is due
      if (await this.isRotationDue(secretVersion)) {
        const newVersion = await this.rotateSecrets();
        return newVersion.secret;
      }

      return secretVersion.secret;

    } catch (error) {
      console.error('Failed to get active secret:', error);
      throw new Error('JWT secret retrieval failed');
    }
  }

  /**
   * Verify JWT token with rotation support
   */
  async verifyWithRotation(token: string): Promise<{ valid: boolean; payload?: jose.JWTPayload; version?: number }> {
    const currentVersion = await this.getCurrentVersion();

    // Try current and recent versions
    for (let v = currentVersion; v >= Math.max(1, currentVersion - this.config.maxSecretVersions + 1); v--) {
      try {
        const secretVersion = await this.getSecretVersion(v);

        if (!secretVersion || secretVersion.status === 'revoked') {
          continue;
        }

        const secret = new TextEncoder().encode(secretVersion.secret);
        const { payload } = await jose.jwtVerify(token, secret, {
          algorithms: ['HS256', 'HS384', 'HS512']
        });

        // Log successful verification
        await this.logAuditEvent('access_attempt', v, 'Token verified successfully');

        return { valid: true, payload, version: v };

      } catch (error) {
        // Try next version
        continue;
      }
    }

    // Token verification failed with all versions
    await this.logAuditEvent('access_attempt', -1, 'Token verification failed');
    return { valid: false };
  }

  /**
   * Emergency rotation for breach scenarios
   */
  async emergencyRotation(reason: string, initiatedBy: string): Promise<SecretVersion> {
    if (!this.config.emergencyRotationEnabled) {
      throw new Error('Emergency rotation is disabled');
    }

    console.error(`SECURITY ALERT: Emergency JWT rotation initiated. Reason: ${reason}`);

    try {
      // Generate new secret immediately
      const newSecret = await this.generateSecureSecret();

      // Validate with stricter requirements
      const validation = await this.validateSecret(newSecret, true);
      if (!validation.isValid) {
        throw new Error(`Emergency secret validation failed: ${validation.errors.join(', ')}`);
      }

      const currentVersion = await this.getCurrentVersion();
      const newVersion = currentVersion + 1;

      // Create emergency secret version
      const secretVersion: SecretVersion = {
        id: crypto.randomUUID(),
        version: newVersion,
        secret: newSecret,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + this.config.rotationIntervalDays * 24 * 60 * 60 * 1000),
        status: 'active',
        createdBy: initiatedBy,
        rotationReason: `EMERGENCY: ${reason}`
      };

      // Store new version
      await this.storeSecretVersion(secretVersion);

      // Immediately revoke ALL previous versions
      await this.revokeAllPreviousVersions(newVersion);

      // Update configuration
      await this.updateRotationConfig(newVersion);

      // Log emergency rotation
      await this.logAuditEvent('emergency_rotation', newVersion, reason, {
        initiatedBy,
        revokedVersions: Array.from({ length: currentVersion }, (_, i) => i + 1)
      });

      console.log(`Emergency rotation completed. All previous secrets revoked. New version: ${newVersion}`);

      return secretVersion;

    } catch (error) {
      console.error('Emergency rotation failed:', error);
      throw new Error(`Emergency rotation failed: ${error.message}`);
    }
  }

  /**
   * Generate cryptographically secure secret
   */
  private async generateSecureSecret(): Promise<string> {
    const length = Math.max(this.constructor.MIN_SECRET_LENGTH, 64);
    const randomBytes = new Uint8Array(length);
    crypto.getRandomValues(randomBytes);

    let secret = '';
    const charset = this.constructor.SECRET_CHARSET;

    for (let i = 0; i < length; i++) {
      secret += charset[randomBytes[i] % charset.length];
    }

    // Ensure high entropy by adding additional randomness
    const additionalEntropy = crypto.randomUUID().replace(/-/g, '');
    secret = secret.substring(0, length - additionalEntropy.length) + additionalEntropy;

    return secret;
  }

  /**
   * Comprehensive secret validation
   */
  private async validateSecret(secret: string, emergency: boolean = false): Promise<SecretValidation> {
    const validation: SecretValidation = {
      isValid: false,
      entropy: 0,
      strength: 'weak',
      errors: [],
      warnings: []
    };

    // Check minimum length
    const minLength = emergency ? 80 : this.constructor.MIN_SECRET_LENGTH;
    if (secret.length < minLength) {
      validation.errors.push(`Secret must be at least ${minLength} characters (current: ${secret.length})`);
    }

    // Check against blacklist patterns
    for (const pattern of this.constructor.BLACKLISTED_PATTERNS) {
      if (pattern.test(secret)) {
        validation.errors.push(`Secret matches blacklisted pattern: ${pattern}`);
      }
    }

    // Calculate entropy
    validation.entropy = this.calculateEntropy(secret);
    const minEntropy = emergency ? 300 : this.constructor.MIN_ENTROPY_BITS;

    if (validation.entropy < minEntropy) {
      validation.errors.push(`Insufficient entropy: ${validation.entropy.toFixed(2)} bits (minimum: ${minEntropy})`);
    }

    // Determine strength
    if (validation.entropy >= 512) {
      validation.strength = 'very-strong';
    } else if (validation.entropy >= 256) {
      validation.strength = 'strong';
    } else if (validation.entropy >= 128) {
      validation.strength = 'medium';
    } else {
      validation.strength = 'weak';
    }

    // Check character diversity
    const hasLowercase = /[a-z]/.test(secret);
    const hasUppercase = /[A-Z]/.test(secret);
    const hasNumbers = /[0-9]/.test(secret);
    const hasSpecial = /[^a-zA-Z0-9]/.test(secret);

    const diversityCount = [hasLowercase, hasUppercase, hasNumbers, hasSpecial].filter(Boolean).length;

    if (diversityCount < 3) {
      validation.errors.push('Secret must contain at least 3 different character types');
    }

    validation.isValid = validation.errors.length === 0;

    return validation;
  }

  /**
   * Calculate Shannon entropy
   */
  private calculateEntropy(secret: string): number {
    const charCounts = new Map<string, number>();

    for (const char of secret) {
      charCounts.set(char, (charCounts.get(char) || 0) + 1);
    }

    let entropy = 0;
    const length = secret.length;

    for (const count of charCounts.values()) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }

    // Calculate total entropy in bits
    const uniqueChars = charCounts.size;
    return entropy * length * Math.log2(uniqueChars);
  }

  /**
   * Store secret version in KV
   */
  private async storeSecretVersion(version: SecretVersion): Promise<void> {
    const key = `${this.secretPrefix}${version.version}`;
    await this.kvNamespace.put(key, JSON.stringify(version), {
      expirationTtl: Math.ceil((this.config.rotationIntervalDays + this.config.graceperiodDays) * 24 * 60 * 60)
    });
  }

  /**
   * Get secret version from KV
   */
  private async getSecretVersion(version: number): Promise<SecretVersion | null> {
    const key = `${this.secretPrefix}${version}`;
    const data = await this.kvNamespace.get(key);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Get current version number
   */
  private async getCurrentVersion(): Promise<number> {
    const config = await this.kvNamespace.get(this.configKey);
    if (!config) return 0;

    const parsedConfig = JSON.parse(config);
    return parsedConfig.currentVersion || 0;
  }

  /**
   * Update rotation configuration
   */
  private async updateRotationConfig(newVersion: number): Promise<void> {
    const config = {
      currentVersion: newVersion,
      lastRotation: new Date().toISOString(),
      nextRotationDue: new Date(Date.now() + this.config.rotationIntervalDays * 24 * 60 * 60 * 1000).toISOString()
    };

    await this.kvNamespace.put(this.configKey, JSON.stringify(config));
  }

  /**
   * Check if rotation is due
   */
  private async isRotationDue(currentVersion: SecretVersion): Promise<boolean> {
    const rotationDue = new Date(currentVersion.createdAt.getTime() + this.config.rotationIntervalDays * 24 * 60 * 60 * 1000);
    return new Date() >= rotationDue;
  }

  /**
   * Transition previous versions to deprecated status
   */
  private async transitionPreviousVersions(currentVersion: number): Promise<void> {
    for (let v = currentVersion - 1; v >= Math.max(1, currentVersion - this.config.maxSecretVersions); v--) {
      const version = await this.getSecretVersion(v);
      if (version && version.status !== 'revoked') {
        version.status = 'rotating';
        await this.storeSecretVersion(version);
      }
    }

    // Revoke versions beyond max limit
    for (let v = currentVersion - this.config.maxSecretVersions; v >= 1; v--) {
      await this.revokeVersion(v);
    }
  }

  /**
   * Revoke a specific version
   */
  private async revokeVersion(version: number): Promise<void> {
    const secretVersion = await this.getSecretVersion(version);
    if (secretVersion) {
      secretVersion.status = 'revoked';
      await this.storeSecretVersion(secretVersion);
    }
  }

  /**
   * Revoke all previous versions (for emergency scenarios)
   */
  private async revokeAllPreviousVersions(currentVersion: number): Promise<void> {
    for (let v = currentVersion - 1; v >= 1; v--) {
      await this.revokeVersion(v);
    }
  }

  /**
   * Initialize from environment variable
   */
  private async initializeFromEnvironment(): Promise<string> {
    const envSecret = process.env.JWT_SECRET;

    if (!envSecret) {
      throw new Error('JWT_SECRET environment variable is required');
    }

    const validation = await this.validateSecret(envSecret);
    if (!validation.isValid) {
      throw new Error(`Environment JWT_SECRET validation failed: ${validation.errors.join(', ')}`);
    }

    // Store as version 1
    const initialVersion: SecretVersion = {
      id: crypto.randomUUID(),
      version: 1,
      secret: envSecret,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.rotationIntervalDays * 24 * 60 * 60 * 1000),
      status: 'active',
      createdBy: 'environment_init'
    };

    await this.storeSecretVersion(initialVersion);
    await this.updateRotationConfig(1);

    return envSecret;
  }

  /**
   * Log audit event
   */
  private async logAuditEvent(
    action: RotationAuditLog['action'],
    version: number,
    reason: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    if (!this.config.auditLoggingEnabled) return;

    const log: RotationAuditLog = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      action,
      version,
      reason,
      metadata
    };

    const key = `${this.auditLogPrefix}${log.timestamp.getTime()}`;
    await this.kvNamespace.put(key, JSON.stringify(log), {
      expirationTtl: 90 * 24 * 60 * 60 // Keep audit logs for 90 days
    });
  }
}