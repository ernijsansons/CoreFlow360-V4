/**
 * Security Configuration
 * Implements enterprise-grade security settings with OWASP compliance
 */

import type { Env } from '../types/environment';
import { createLogger } from '../utils/logger';

const logger = createLogger('security');

export interface CSPConfig {
  defaultSrc: string[];
  scriptSrc: string[];
  styleSrc: string[];
  imgSrc: string[];
  connectSrc: string[];
  fontSrc: string[];
  objectSrc: string[];
  mediaSrc: string[];
  frameSrc: string[];
}

export interface SecurityOptions {
  enableHSTS: boolean;
  hstsMaxAge: number;
  enableCSP: boolean;
  cspReportOnly: boolean;
  allowedOrigins: string[];
  jwtSecret: string;
  enableCsrfProtection: boolean;
  csrfTokenExpiry: number;
  sessionTimeout: number;
  maxLoginAttempts: number;
  loginLockoutDuration: number;
}

export class SecurityConfig {
  private readonly env: Env;
  private readonly options: SecurityOptions;

  constructor(env: Env) {
    this.env = env;
    this.options = this.buildSecurityOptions(env);
  }

  private buildSecurityOptions(env: Env): SecurityOptions {
    return {
      enableHSTS: env.ENVIRONMENT === 'production',
      hstsMaxAge: 31536000, // 1 year
      enableCSP: true,
      cspReportOnly: env.ENVIRONMENT === 'development',
      allowedOrigins: this.parseAllowedOrigins(env),
      jwtSecret: env.JWT_SECRET!,
      enableCsrfProtection: true,
      csrfTokenExpiry: 3600, // 1 hour
      sessionTimeout: 86400, // 24 hours
      maxLoginAttempts: 5,
      loginLockoutDuration: 900 // 15 minutes
    };
  }

  private parseAllowedOrigins(env: Env): string[] {
    if (!env.ALLOWED_ORIGINS) {
      return env.ENVIRONMENT === 'development'
        ? ['http://localhost:3000', 'https://localhost:3000']
        : ['https://app.coreflow360.com'];
    }

    const origins = env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim());

    // Security: Remove wildcards in production
    if (env.ENVIRONMENT === 'production') {
      return origins.filter(origin => origin !== '*');
    }

    return origins;
  }

  /**
   * Get Content Security Policy configuration
   * Addresses CWE-79: Cross-site Scripting
   */
  getCSPConfig(): CSPConfig {
    const isProduction = this.env.ENVIRONMENT === 'production';

    return {
      defaultSrc: ["'self'"],
      scriptSrc: isProduction
        ? ["'self'", "'strict-dynamic'"] // No unsafe-inline in production
        : ["'self'", "'unsafe-inline'", 'https://cdn.cloudflare.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      imgSrc: ["'self'", 'data:', 'https:', 'blob:'],
      connectSrc: [
        "'self'",
        'https://api.anthropic.com',
        'https://api.openai.com',
        'https://api.cloudflare.com',
        'wss:'
      ],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'", 'https:'],
      frameSrc: ["'none'"]
    };
  }

  /**
   * Build CSP header string
   */
  buildCSPHeader(): string {
    const csp = this.getCSPConfig();

    const directives = Object.entries(csp).map(([directive, sources]) => {
      const kebabDirective = directive.replace(/([A-Z])/g, '-$1').toLowerCase();
      return `${kebabDirective} ${sources.join(' ')}`;
    });

    // Add additional directives
    directives.push('base-uri \'self\'');
    directives.push('form-action \'self\'');
    directives.push('upgrade-insecure-requests');

    if (this.env.CSP_REPORT_URI) {
      directives.push(`report-uri ${this.env.CSP_REPORT_URI}`);
    }

    return directives.join('; ');
  }

  /**
   * Get security headers
   * Implements defense-in-depth security
   */
  getSecurityHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      // XSS Protection
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',

      // Referrer Policy
      'Referrer-Policy': 'strict-origin-when-cross-origin',

      // Content Security Policy
      'Content-Security-Policy': this.buildCSPHeader(),

      // Permissions Policy
      'Permissions-Policy': this.buildPermissionsPolicy(),

      // Cross-Origin Policies
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'cross-origin',

      // Remove server information
      'Server': 'CoreFlow360'
    };

    // HSTS in production only
    if (this.options.enableHSTS) {
      headers['Strict-Transport-Security'] =
        `max-age=${this.options.hstsMaxAge}; includeSubDomains; preload`;
    }

    // CSP Report-Only in development
    if (this.options.cspReportOnly) {
      headers['Content-Security-Policy-Report-Only'] = headers['Content-Security-Policy'];
      delete headers['Content-Security-Policy'];
    }

    return headers;
  }

  private buildPermissionsPolicy(): string {
    const policies = [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
      'usb=()',
      'magnetometer=()',
      'gyroscope=()',
      'accelerometer=()',
      'ambient-light-sensor=()',
      'autoplay=()',
      'encrypted-media=()',
      'fullscreen=(self)',
      'picture-in-picture=()'
    ];

    return policies.join(', ');
  }

  /**
   * Get CORS configuration
   */
  getCorsConfig() {
    return {
      allowedOrigins: this.options.allowedOrigins,
      allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-Business-ID',
        'X-User-ID',
        'X-Request-ID',
        'X-API-Key',
        'X-CSRF-Token'
      ],
      allowCredentials: true,
      maxAge: 86400
    };
  }

  /**
   * Get rate limiting configuration
   */
  getRateLimitConfig() {
    return {
      global: {
        requests: parseInt(this.env.GLOBAL_RATE_LIMIT || '1000'),
        window: 3600 // 1 hour
      },
      perUser: {
        requests: parseInt(this.env.USER_RATE_LIMIT || '100'),
        window: 3600
      },
      perIP: {
        requests: parseInt(this.env.IP_RATE_LIMIT || '200'),
        window: 3600
      },
      apiKey: {
        requests: parseInt(this.env.API_KEY_RATE_LIMIT || '10000'),
        window: 3600
      }
    };
  }

  /**
   * Get authentication configuration
   */
  getAuthConfig() {
    return {
      jwtSecret: this.options.jwtSecret,
      jwtExpiry: parseInt(this.env.JWT_EXPIRY || '86400'), // 24 hours
      sessionTimeout: this.options.sessionTimeout,
      maxLoginAttempts: this.options.maxLoginAttempts,
      lockoutDuration: this.options.loginLockoutDuration,
      enableMFA: this.env.ENABLE_MFA !== 'false',
      csrfProtection: this.options.enableCsrfProtection,
      csrfTokenExpiry: this.options.csrfTokenExpiry
    };
  }

  /**
   * Validate configuration
   */
  validate(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!this.options.jwtSecret || this.options.jwtSecret.length < 32) {
      errors.push('JWT secret must be at least 32 characters');
    }

    if (this.env.ENVIRONMENT === 'production' && this.options.allowedOrigins.includes('*')) {
      errors.push('Wildcard origins not allowed in production');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}