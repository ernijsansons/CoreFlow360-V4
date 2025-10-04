/**
 * Environment Configuration and Validation
 * Addresses CWE-362: Environment Variable Race Condition
 */

import type { Env } from '../types/environment';
import { createLogger } from '../utils/logger';

const logger = createLogger('environment');

export interface EnvironmentValidation {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Critical Security: Atomic environment validation
 * Prevents JWT Authentication Bypass (CVSS 9.8)
 */
export async function validateEnvironment(env: Env): Promise<EnvironmentValidation> {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Critical: JWT Secret validation
  if (!env.JWT_SECRET) {
    errors.push('JWT_SECRET is required - Authentication bypass vulnerability');
  } else if (env.JWT_SECRET.length < 32) {
    errors.push('JWT_SECRET must be at least 32 characters for security');
  } else if (env.JWT_SECRET === 'your_secure_jwt_secret' || env.JWT_SECRET === 'default') {
    errors.push('JWT_SECRET must not use default/example values');
  }

  // Database validation
  if (!env.DB && !env.DB_MAIN) {
    errors.push('Database binding is required (DB or DB_MAIN)');
  }

  // KV validation
  if (!env.KV_AUTH) {
    errors.push('KV_AUTH namespace is required for authentication');
  }

  // Environment-specific validation
  if (env.ENVIRONMENT === 'production') {
    // Production-specific requirements
    if (!env.ALLOWED_ORIGINS || env.ALLOWED_ORIGINS.includes('*')) {
      errors.push('ALLOWED_ORIGINS must be explicitly set in production (no wildcards)');
    }

    if (!env.ENCRYPTION_KEY) {
      errors.push('ENCRYPTION_KEY is required in production');
    }

    // Warn about development settings in production
    if (env.DEBUG === 'true') {
      warnings.push('DEBUG mode should be disabled in production');
    }
  }

  // API Keys validation
  if (!env.ANTHROPIC_API_KEY && !env.OPENAI_API_KEY) {
    warnings.push('No AI API keys configured - AI features will be disabled');
  }

  // Rate limiting validation
  if (!env.KV_RATE_LIMIT_METRICS && !env.RATE_LIMITER_DO) {
    warnings.push('No rate limiting storage configured');
  }

  logger.info('Environment validation completed', {
    errors: errors.length,
    warnings: warnings.length,
    environment: env.ENVIRONMENT
  });

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

/**
 * Get configuration with secure defaults
 */
export function getSecureConfig(env: Env) {
  return {
    // Security settings
    jwtSecret: env.JWT_SECRET!,
    encryptionKey: env.ENCRYPTION_KEY,
    allowedOrigins: env.ALLOWED_ORIGINS ?
      env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) :
      ['https://app.coreflow360.com'],

    // Performance settings
    maxRequestSize: parseInt(env.MAX_REQUEST_SIZE || '1048576'), // 1MB
    requestTimeout: parseInt(env.REQUEST_TIMEOUT || '30000'), // 30s

    // Rate limiting
    globalRateLimit: parseInt(env.GLOBAL_RATE_LIMIT || '1000'),
    userRateLimit: parseInt(env.USER_RATE_LIMIT || '100'),

    // Environment
    environment: env.ENVIRONMENT || 'production',
    debug: env.ENVIRONMENT === 'development' && env.DEBUG === 'true',

    // Feature flags
    enableAI: !!(env.ANTHROPIC_API_KEY || env.OPENAI_API_KEY),
    enableAnalytics: !!env.ANALYTICS,
    enableMFA: env.ENABLE_MFA !== 'false'
  };
}