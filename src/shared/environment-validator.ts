/**
 * Environment Variable Validation System - SECURITY ENHANCED
 * SECURITY FIXES:
 * - Prevents JWT Authentication Bypass (CVSS 9.8)
 * - Blocks insecure fallback secrets
 * - Validates cryptographic entropy
 * - Environment-specific security rules
 */

import { SecurityError } from './errors/app-error';
import { JWTSecretManager } from './security/jwt-secret-manager';

export interface RequiredSecrets {
  JWT_SECRET: string;
  AUTH_SECRET: string;
  ENCRYPTION_KEY: string;
  API_KEY: string;
  WEBHOOK_SECRET: string;
}

export interface OptionalSecrets {
  EMAIL_API_KEY?: string;
  ORCHESTRATOR_TOKEN?: string;
  GATEWAY_TOKEN?: string;
  CACHE_TOKEN?: string;
  BIGQUERY_TOKEN?: string;
  R2_TOKEN?: string;
  DATADOG_API_KEY?: string;
  CLICKHOUSE_TOKEN?: string;
}

/**
 * Validates that all required environment variables are present and secure
 */
export class EnvironmentValidator {
  private static readonly REQUIRED_SECRETS: (keyof RequiredSecrets)[] = [
    'JWT_SECRET',
    'AUTH_SECRET',
    'ENCRYPTION_KEY',
    'API_KEY',
    'WEBHOOK_SECRET'
  ];

  private static readonly INSECURE_VALUES = [
    'fallback-secret',      // CRITICAL: The exact vulnerable value from the codebase
    'dev-secret',
    'development-secret',
    'test-secret',
    'development',
    'test',
    'default',
    'secret',
    'password',
    '123456',
    'changeme',
    'admin',
    'your-secret-here',
    'change-me',
    'insecure-secret',
    'example-secret',
    'localhost',
    'development-only'
  ];

  private static readonly MIN_SECRET_LENGTH = 32;

  /**
   * Validates all required secrets are present and secure
   */
  static validateSecrets(env: any): RequiredSecrets {
    const validated: Partial<RequiredSecrets> = {};
    const errors: string[] = [];

    for (const secretName of this.REQUIRED_SECRETS) {
      const value = env[secretName];

      if (!value) {
        errors.push(`Missing required environment variable: ${secretName}`);
        continue;
      }

      if (typeof value !== 'string') {
        errors.push(`Environment variable ${secretName} must be a string`);
        continue;
      }

      // CRITICAL SECURITY CHECK: Block fallback secrets that cause JWT bypass
      if (this.isInsecureValue(value)) {
        errors.push(`SECURITY CRITICAL: Environment variable ${secretName} contains insecure value '${value.substring(0, 10)}...'. This causes JWT Authentication Bypass vulnerability (CVSS 9.8). Use a cryptographically secure random value.`);
        continue;
      }

      // Check minimum length
      if (value.length < this.MIN_SECRET_LENGTH) {
        errors.push(`Environment variable ${secretName} must be at least ${this.MIN_SECRET_LENGTH} characters long`);
        continue;
      }

      // Enhanced entropy validation
      if (!this.hasSufficientEntropy(value)) {
        errors.push(`SECURITY CRITICAL: Environment variable ${secretName} lacks sufficient entropy. This can lead to cryptographic vulnerabilities. Use a cryptographically secure random value with at least 256 bits of entropy.`);
        continue;
      }

      validated[secretName] = value;
    }

    if (errors.length > 0) {
      throw new SecurityError(`Environment validation failed: ${errors.join(', ')}`);
    }

    return validated as RequiredSecrets;
  }

  /**
   * Validates optional secrets if present
   */
  static validateOptionalSecrets(env: any): OptionalSecrets {
    const validated: OptionalSecrets = {};
    const warnings: string[] = [];

    const optionalSecrets: (keyof OptionalSecrets)[] = [
      'EMAIL_API_KEY',
      'ORCHESTRATOR_TOKEN',
      'GATEWAY_TOKEN',
      'CACHE_TOKEN',
      'BIGQUERY_TOKEN',
      'R2_TOKEN',
      'DATADOG_API_KEY',
      'CLICKHOUSE_TOKEN'
    ];

    for (const secretName of optionalSecrets) {
      const value = env[secretName];

      if (!value) {
        continue; // Optional, skip if not present
      }

      if (typeof value !== 'string') {
        warnings.push(`Optional environment variable ${secretName} should be a string`);
        continue;
      }

      if (this.isInsecureValue(value)) {
        warnings.push(`Optional environment variable ${secretName} contains insecure value`);
        continue;
      }

      validated[secretName] = value;
    }

    if (warnings.length > 0) {
    }

    return validated;
  }

  /**
   * Checks if a value is considered insecure
   */
  private static isInsecureValue(value: string): boolean {
    const lowerValue = value.toLowerCase();
    return this.INSECURE_VALUES.some(insecure => lowerValue.includes(insecure));
  }

  /**
   * Basic entropy check - ensures the secret isn't too repetitive
   */
  private static hasSufficientEntropy(value: string): boolean {
    // Check for repeated characters
    const charCounts = new Map<string, number>();
    for (const char of value) {
      charCounts.set(char, (charCounts.get(char) || 0) + 1);
    }

    // If any character appears more than 30% of the time, it's low entropy
    const maxCount = Math.max(...Array.from(charCounts.values()));
    const maxFrequency = maxCount / value.length;

    if (maxFrequency > 0.3) {
      return false;
    }

    // Check for variety of character types
    const hasLower = /[a-z]/.test(value);
    const hasUpper = /[A-Z]/.test(value);
    const hasDigit = /[0-9]/.test(value);
    const hasSpecial = /[^a-zA-Z0-9]/.test(value);

    const varietyCount = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;

    // Require at least 3 types of characters for sufficient entropy
    return varietyCount >= 3;
  }

  /**
   * Environment-specific validation
   */
  static validateEnvironment(env: any): void {
    const environment = env.ENVIRONMENT;

    if (!environment) {
      throw new SecurityError('ENVIRONMENT variable is required');
    }

    // Production-specific checks
    if (environment === 'production') {
      this.validateProductionEnvironment(env);
    }

    // Development-specific warnings
    if (environment === 'development') {
      this.validateDevelopmentEnvironment(env);
    }
  }

  /**
   * Production environment validation
   */
  private static validateProductionEnvironment(env: any): void {
    const prodChecks = [
      { key: 'LOG_LEVEL', expected: ['error', 'warn', 'info'], message: 'Production should use appropriate log level' },
      { key: 'APP_NAME', required: true, message: 'APP_NAME is required in production' },
      { key: 'API_VERSION', required: true, message: 'API_VERSION is required in production' }
    ];

    const errors: string[] = [];

    for (const check of prodChecks) {
      const value = env[check.key];

      if (check.required && !value) {
        errors.push(check.message);
        continue;
      }

      if (check.expected && value && !check.expected.includes(value)) {
        errors.push(`${check.key} should be one of: ${check.expected.join(', ')}`);
      }
    }

    if (errors.length > 0) {
      throw new SecurityError(`Production environment validation failed: ${errors.join(', ')}`);
    }
  }

  /**
   * Development environment warnings
   */
  private static validateDevelopmentEnvironment(env: any): void {
    const warnings: string[] = [];

    // Check for potential security issues in development
    if (!env.JWT_SECRET) {
      warnings.push('JWT_SECRET should be set even in development for consistency');
    }

    if (env.LOG_LEVEL === 'debug') {
      warnings.push('Debug logging may expose sensitive information');
    }

    if (warnings.length > 0) {
    }
  }

  /**
   * Complete environment validation with JWT bypass protection
   */
  static validate(env: any): { required: RequiredSecrets; optional: OptionalSecrets } {
    // CRITICAL: Use comprehensive JWT secret validation to prevent authentication bypass
    this.validateJWTSecret(env.JWT_SECRET);

    // Validate environment setup
    this.validateEnvironment(env);

    // Validate all secrets
    const required = this.validateSecrets(env);
    const optional = this.validateOptionalSecrets(env);

    console.log('✅ Environment validation passed - JWT Authentication Bypass vulnerability mitigated');
    return { required, optional };
  }

  /**
   * Generate cryptographically secure random secret
   * Uses crypto.getRandomValues for true randomness
   */
  static generateSecureSecret(length: number = 64): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    let result = '';

    // Use cryptographically secure randomness
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);

    for (let i = 0; i < length; i++) {
      result += chars.charAt(randomValues[i] % chars.length);
    }

    return result;
  }

  /**
   * Validate JWT_SECRET using comprehensive security validation
   */
  static validateJWTSecret(jwtSecret: string | undefined): void {
    const validation = JWTSecretManager.validateJWTSecret(jwtSecret, process.env.ENVIRONMENT || 'development');

    if (!validation.isValid) {
      const errorMessage = [
        'CRITICAL JWT SECRET VALIDATION FAILED:',
        ...validation.errors,
        '',
        'This vulnerability can lead to JWT Authentication Bypass (CVSS 9.8).',
        'Generate a secure secret: openssl rand -base64 64'
      ].join('\n');

      throw new SecurityError(errorMessage);
    }

    // Log warnings if any
    if (validation.warnings.length > 0) {
      console.warn('JWT Secret Warnings:', validation.warnings.join(', '));
    }
  }
}