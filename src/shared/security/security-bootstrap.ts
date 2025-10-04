/**
 * Security Bootstrap System - Application Startup Security Validation
 *
 * CRITICAL SECURITY FEATURES:
 * - Mandatory security validation before application start
 * - Fail-fast pattern for security misconfigurations
 * - Comprehensive startup security checks
 * - Environment-specific security requirements
 * - Zero-tolerance for production security issues
 */

import { JWTSecretManager } from './jwt-secret-manager';
import { SecurityError } from '../errors/app-error';

export interface SecurityBootstrapConfig {
  environment: 'development' | 'staging' | 'production';
  enforcementLevel: 'strict' | 'warning' | 'permissive';
  requiredSecrets: string[];
  optionalSecrets: string[];
  enableHealthChecks: boolean;
}

export interface SecurityValidationResult {
  passed: boolean;
  criticalIssues: string[];
  warnings: string[];
  recommendations: string[];
  blocksStartup: boolean;
}

export class SecurityBootstrap {
  private static readonly CRITICAL_SECRETS = [
    'JWT_SECRET',
    'ENCRYPTION_KEY',
    'AUTH_SECRET'
  ];

  private static readonly PRODUCTION_REQUIRED_SECRETS = [
    'JWT_SECRET',
    'ENCRYPTION_KEY',
    'AUTH_SECRET',
    'STRIPE_SECRET_KEY',
    'SENDGRID_API_KEY'
  ];

  /**
   * Perform comprehensive security validation before application startup
   */
  static async validateStartupSecurity(env: any, config?: Partial<SecurityBootstrapConfig>): Promise<SecurityValidationResult> {
    const fullConfig: SecurityBootstrapConfig = {
      environment: env.ENVIRONMENT || 'development',
      enforcementLevel: env.ENVIRONMENT === 'production' ? 'strict' : 'warning',
      requiredSecrets: this.getRequiredSecrets(env.ENVIRONMENT),
      optionalSecrets: ['SENTRY_DSN', 'DATADOG_API_KEY'],
      enableHealthChecks: true,
      ...config
    };

    console.log(`🔒 Starting security validation for ${fullConfig.environment} environment...`);

    const result: SecurityValidationResult = {
      passed: true,
      criticalIssues: [],
      warnings: [],
      recommendations: [],
      blocksStartup: false
    };

    try {
      // 1. Validate JWT Secret (Highest Priority - CVSS 9.8 vulnerability)
      await this.validateJWTSecurityBootstrap(env, result);

      // 2. Validate all required secrets
      await this.validateRequiredSecrets(env, fullConfig, result);

      // 3. Environment-specific validations
      await this.validateEnvironmentSecurity(env, fullConfig, result);

      // 4. Security configuration checks
      await this.validateSecurityConfiguration(env, fullConfig, result);

      // 5. Runtime security checks
      if (fullConfig.enableHealthChecks) {
        await this.performStartupHealthChecks(env, result);
      }

      // Determine if startup should be blocked
      this.determineStartupBlocking(result, fullConfig);

      // Log validation results
      this.logValidationResults(result, fullConfig);

      return result;
    } catch (error) {
      result.passed = false;
      result.blocksStartup = true;
      result.criticalIssues.push(`Security validation failed: ${(error as any).message}`);

      console.error('🚨 SECURITY VALIDATION FAILED - APPLICATION STARTUP BLOCKED');
      console.error(error);

      return result;
    }
  }

  /**
   * Validate JWT secret with fail-fast pattern
   */
  private static async validateJWTSecurityBootstrap(env: any, result: SecurityValidationResult): Promise<void> {
    try {
      console.log('🔐 Validating JWT secret security...');

      const jwtSecret = env.JWT_SECRET;
      const environment = env.ENVIRONMENT || 'development';

      // Use comprehensive JWT secret validation
      const validation = JWTSecretManager.validateJWTSecret(jwtSecret, environment);

      if (!validation.isValid) {
        result.passed = false;
        result.criticalIssues.push('CRITICAL: JWT Secret validation failed');
        validation.errors.forEach(error => result.criticalIssues.push(`  - ${error}`));

        // This is a blocking issue for all environments
        result.blocksStartup = true;

        result.recommendations.push('Generate a secure JWT secret: openssl rand -base64 64');
        result.recommendations.push('Set the secret: export JWT_SECRET="<generated-secret>"');
        result.recommendations.push('Verify the secret passes validation before deployment');
      } else {
        console.log(`✅ JWT secret validation passed (Strength: ${validation.strength})`);

        // Add warnings if any
        validation.warnings.forEach(warning => result.warnings.push(warning));

        // Recommendations for medium strength secrets
        if (validation.strength === 'medium') {
          result.recommendations.push('Consider generating a stronger JWT secret for enhanced security');
        }
      }
    } catch (error) {
      result.passed = false;
      result.blocksStartup = true;
      result.criticalIssues.push(`JWT secret validation system error: ${(error as any).message}`);
    }
  }

  /**
   * Validate all required secrets are present and secure
   */
  private static async validateRequiredSecrets(
    env: any,
    config: SecurityBootstrapConfig,
    result: SecurityValidationResult
  ): Promise<void> {
    console.log('🔑 Validating required secrets...');

    for (const secretName of config.requiredSecrets) {
      const secretValue = env[secretName];

      if (!secretValue) {
        const message = `Missing required secret: ${secretName}`;

        if (config.environment === 'production') {
          result.criticalIssues.push(message);
          result.blocksStartup = true;
        } else {
          result.warnings.push(message);
        }

        result.recommendations.push(`Set ${secretName} environment variable`);
        continue;
      }

      // Basic validation for non-JWT secrets
      if (secretName !== 'JWT_SECRET') {
        if (secretValue.length < 16) {
          const message = `Secret ${secretName} is too short (minimum 16 characters)`;

          if (config.environment === 'production') {
            result.criticalIssues.push(message);
          } else {
            result.warnings.push(message);
          }
        }

        // Check for obvious weak values
        const weakPatterns = ['test', 'dev', 'demo', 'example', 'changeme', 'default'];
        const isWeak = weakPatterns.some(pattern =>
          secretValue.toLowerCase().includes(pattern)
        );

        if (isWeak) {
          const message = `Secret ${secretName} appears to contain weak patterns`;

          if (config.environment === 'production') {
            result.criticalIssues.push(message);
          } else {
            result.warnings.push(message);
          }
        }
      }
    }
  }

  /**
   * Environment-specific security validations
   */
  private static async validateEnvironmentSecurity(
    env: any,
    config: SecurityBootstrapConfig,
    result: SecurityValidationResult
  ): Promise<void> {
    console.log(`🌍 Validating ${config.environment} environment security...`);

    switch (config.environment) {
      case 'production':
        await this.validateProductionSecurity(env, result);
        break;

      case 'staging':
        await this.validateStagingSecurity(env, result);
        break;

      case 'development':
        await this.validateDevelopmentSecurity(env, result);
        break;
    }
  }

  /**
   * Production environment security validation
   */
  private static async validateProductionSecurity(env: any, result: SecurityValidationResult): Promise<void> {
    // Production must have debug disabled
    if (env.DEBUG === 'true' || env.LOG_LEVEL === 'debug') {
      result.criticalIssues.push('PRODUCTION SECURITY: Debug logging must be disabled in production');
      result.blocksStartup = true;
    }

    // Production must have HTTPS enforced
    if (env.FORCE_HTTPS !== 'true') {
      result.warnings.push('PRODUCTION SECURITY: HTTPS should be enforced');
      result.recommendations.push('Set FORCE_HTTPS=true');
    }

    // Production must have security headers enabled
    if (env.SECURITY_HEADERS_ENABLED !== 'true') {
      result.warnings.push('PRODUCTION SECURITY: Security headers should be enabled');
      result.recommendations.push('Set SECURITY_HEADERS_ENABLED=true');
    }

    // Check for development secrets in production
    const secrets = ['JWT_SECRET', 'ENCRYPTION_KEY', 'AUTH_SECRET'];
    for (const secretName of secrets) {
      const secret = env[secretName];
      if (secret && /dev|test|demo|local/i.test(secret)) {
        result.criticalIssues.push(`PRODUCTION SECURITY: ${secretName} contains development patterns`);
        result.blocksStartup = true;
      }
    }
  }

  /**
   * Staging environment security validation
   */
  private static async validateStagingSecurity(env: any, result: SecurityValidationResult): Promise<void> {
    // Staging should mirror production as closely as possible
    if (env.DEBUG === 'true') {
      result.warnings.push('STAGING SECURITY: Debug mode enabled - should match production');
    }

    // Staging should use production-like secrets
    if (env.JWT_SECRET && /dev|test/i.test(env.JWT_SECRET)) {
      result.warnings.push('STAGING SECURITY: JWT_SECRET should use production-strength secret');
    }
  }

  /**
   * Development environment security validation
   */
  private static async validateDevelopmentSecurity(env: any, result: SecurityValidationResult): Promise<void> {
    // Development warnings (non-blocking)
    if (!env.JWT_SECRET) {
      result.warnings.push('DEVELOPMENT: JWT_SECRET should be set for consistency');
      result.recommendations.push('Generate development JWT secret: openssl rand -base64 64');
    }

    // Warn about production-like secrets in development
    if (env.STRIPE_SECRET_KEY && env.STRIPE_SECRET_KEY.startsWith('sk_live_')) {
      result.warnings.push('DEVELOPMENT: Using live Stripe keys in development');
      result.recommendations.push('Use test Stripe keys (sk_test_) in development');
    }
  }

  /**
   * Security configuration validation
   */
  private static async validateSecurityConfiguration(
    env: any,
    config: SecurityBootstrapConfig,
    result: SecurityValidationResult
  ): Promise<void> {
    console.log('⚙️ Validating security configuration...');

    // Rate limiting configuration
    if (config.environment === 'production' && !env.RATE_LIMIT_ENABLED) {
      result.warnings.push('Production should have rate limiting enabled');
      result.recommendations.push('Set RATE_LIMIT_ENABLED=true');
    }

    // CORS configuration
    if (config.environment === 'production' && env.CORS_ORIGIN === '*') {
      result.criticalIssues.push('PRODUCTION SECURITY: CORS origin cannot be wildcard (*)');
      result.blocksStartup = true;
    }

    // Session configuration
    const sessionTimeout = parseInt(env.SESSION_TIMEOUT_MINUTES || '480');
    if (config.environment === 'production' && sessionTimeout > 480) {
      result.warnings.push('Production session timeout is very long (>8 hours)');
    }
  }

  /**
   * Startup health checks
   */
  private static async performStartupHealthChecks(env: any, result: SecurityValidationResult): Promise<void> {
    console.log('🏥 Performing startup health checks...');

    try {
      // JWT secret health check
      const jwtSecret = env.JWT_SECRET;
      if (jwtSecret) {
        const secretValidation = JWTSecretManager.validateJWTSecret(jwtSecret, env.ENVIRONMENT);
        if (!secretValidation.isValid) {
          result.criticalIssues.push('Health Check Failed: JWT secret validation');
        }
      }

      // Memory and system checks could go here
      console.log('✅ Startup health checks completed');
    } catch (error) {
      result.warnings.push(`Health check error: ${(error as any).message}`);
    }
  }

  /**
   * Determine if security issues should block startup
   */
  private static determineStartupBlocking(result: SecurityValidationResult, config: SecurityBootstrapConfig): void {
    // Critical issues always block in strict mode
    if (config.enforcementLevel === 'strict' && result.criticalIssues.length > 0) {
      result.blocksStartup = true;
    }

    // Production always blocks on critical issues
    if (config.environment === 'production' && result.criticalIssues.length > 0) {
      result.blocksStartup = true;
    }

    // Update passed status
    result.passed = result.criticalIssues.length === 0;
  }

  /**
   * Log validation results
   */
  private static logValidationResults(result: SecurityValidationResult, config: SecurityBootstrapConfig): void {
    console.log('\n' + '='.repeat(60));
    console.log('🔒 SECURITY VALIDATION RESULTS');
    console.log('='.repeat(60));

    if (result.passed) {
      console.log('✅ PASSED: Security validation successful');
    } else {
      console.log('❌ FAILED: Security validation failed');
    }

    if (result.criticalIssues.length > 0) {
      console.log('\n🚨 CRITICAL ISSUES:');
      result.criticalIssues.forEach(issue => console.log(`  - ${issue}`));
    }

    if (result.warnings.length > 0) {
      console.log('\n⚠️ WARNINGS:');
      result.warnings.forEach(warning => console.log(`  - ${warning}`));
    }

    if (result.recommendations.length > 0) {
      console.log('\n💡 RECOMMENDATIONS:');
      result.recommendations.forEach(rec => console.log(`  - ${rec}`));
    }

    if (result.blocksStartup) {
      console.log('\n🛑 APPLICATION STARTUP BLOCKED due to security issues');
      console.log('Fix critical issues before proceeding.');
    } else {
      console.log('\n🚀 Application startup approved');
    }

    console.log('='.repeat(60) + '\n');
  }

  /**
   * Get required secrets based on environment
   */
  private static getRequiredSecrets(environment: string): string[] {
    switch (environment) {
      case 'production':
        return this.PRODUCTION_REQUIRED_SECRETS;
      case 'staging':
        return [...this.CRITICAL_SECRETS, 'STRIPE_SECRET_KEY'];
      default:
        return this.CRITICAL_SECRETS;
    }
  }

  /**
   * Emergency startup bypass (use with extreme caution)
   */
  static emergencyBypass(reason: string): SecurityValidationResult {
    console.warn('🚨 EMERGENCY SECURITY BYPASS ACTIVATED');
    console.warn(`Reason: ${reason}`);
    console.warn('This should only be used in extreme circumstances!');

    return {
      passed: true,
      criticalIssues: [`EMERGENCY BYPASS: ${reason}`],
      warnings: ['Emergency bypass is active - security validation skipped'],
      recommendations: ['Remove emergency bypass as soon as possible'],
      blocksStartup: false
    };
  }
}