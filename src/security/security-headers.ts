/**
 * Security Headers Middleware
 * Comprehensive security headers with dynamic configuration
 */

import { z } from 'zod';
import { Logger } from '../shared/logger';
import { CSPGenerator, RequestContext } from './csp-generator';

export interface SecurityHeadersConfig {
  csp?: {
    enabled: boolean;
    reportOnly?: boolean;
    reportUri?: string;
  };
  hsts?: {
    enabled: boolean;
    maxAge?: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  };
  frameOptions?: {
    enabled: boolean;
    policy?: 'DENY' | 'SAMEORIGIN';
  };
  contentTypeOptions?: {
    enabled: boolean;
  };
  xssProtection?: {
    enabled: boolean;
    mode?: 'block' | 'report';
  };
  referrerPolicy?: {
    enabled: boolean;
    policy?: string;
  };
  permissionsPolicy?: {
    enabled: boolean;
    directives?: Record<string, string[]>;
  };
  customHeaders?: Record<string, string>;
}

export class SecurityHeaders {
  private logger = new Logger();
  private cspGenerator = new CSPGenerator();

  constructor(private config: SecurityHeadersConfig = {}) {
    this.setDefaults();
  }

  /**
   * Apply security headers to response
   */
  async apply(response: Response, context: RequestContext): Promise<Response> {
    const headers = new Headers(response.headers);

    // Content Security Policy
    if (this.config.csp?.enabled !== false) {
      const csp = await this.cspGenerator.generateCSP(context);
      const cspHeader = this.config.csp?.reportOnly ?
        'Content-Security-Policy-Report-Only' :
        'Content-Security-Policy';

      headers.set(cspHeader, csp);

      // Add Report-To header if CSP reporting is enabled
      if (this.config.csp?.reportUri) {
        headers.set('Report-To', this.cspGenerator.generateReportTo());
      }
    }

    // HTTP Strict Transport Security
    if (this.config.hsts?.enabled !== false) {
      const hsts = this.buildHSTSHeader();
      headers.set('Strict-Transport-Security', hsts);
    }

    // X-Frame-Options
    if (this.config.frameOptions?.enabled !== false) {
      headers.set('X-Frame-Options', this.config.frameOptions?.policy || 'DENY');
    }

    // X-Content-Type-Options
    if (this.config.contentTypeOptions?.enabled !== false) {
      headers.set('X-Content-Type-Options', 'nosniff');
    }

    // X-XSS-Protection
    if (this.config.xssProtection?.enabled !== false) {
      const mode = this.config.xssProtection?.mode || 'block';
      headers.set('X-XSS-Protection', `1; mode=${mode}`);
    }

    // Referrer Policy
    if (this.config.referrerPolicy?.enabled !== false) {
      const policy = this.config.referrerPolicy?.policy || 'strict-origin-when-cross-origin';
      headers.set('Referrer-Policy', policy);
    }

    // Permissions Policy
    if (this.config.permissionsPolicy?.enabled !== false) {
      const permissionsPolicy = this.buildPermissionsPolicyHeader();
      headers.set('Permissions-Policy', permissionsPolicy);
    }

    // Security-specific headers
    headers.set('X-Request-ID', context.correlationId || 'unknown');
    headers.set('X-Tenant-Isolated', 'true');
    headers.set('X-Security-Version', '1.0');

    // Remove potentially dangerous headers
    headers.delete('Server');
    headers.delete('X-Powered-By');
    headers.delete('X-AspNet-Version');
    headers.delete('X-AspNetMvc-Version');

    // Custom headers
    if (this.config.customHeaders) {
      for (const [name, value] of Object.entries(this.config.customHeaders)) {
        headers.set(name, value);
      }
    }

    // Environment-specific headers
    if (process.env.NODE_ENV === 'development') {
      headers.set('X-Debug-Mode', 'enabled');
    } else {
      // Production-only security headers
      headers.set('X-Robots-Tag', 'noindex, nofollow');
    }

    // Module-specific security headers
    this.applyModuleSpecificHeaders(headers, context);

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  }

  /**
   * Build HSTS header
   */
  private buildHSTSHeader(): string {
    const maxAge = this.config.hsts?.maxAge || 31536000; // 1 year
    const includeSubDomains = this.config.hsts?.includeSubDomains !== false;
    const preload = this.config.hsts?.preload !== false;

    let hsts = `max-age=${maxAge}`;

    if (includeSubDomains) {
      hsts += '; includeSubDomains';
    }

    if (preload) {
      hsts += '; preload';
    }

    return hsts;
  }

  /**
   * Build Permissions Policy header
   */
  private buildPermissionsPolicyHeader(): string {
    const defaultDirectives = {
      camera: [],
      microphone: [],
      geolocation: [],
      payment: [],
      usb: [],
      midi: [],
      accelerometer: [],
      gyroscope: [],
      magnetometer: [],
      'picture-in-picture': [],
      'display-capture': [],
      autoplay: ['self'],
      'encrypted-media': ['self'],
      fullscreen: ['self']
    };

    const directives = {
      ...defaultDirectives,
      ...this.config.permissionsPolicy?.directives
    };

    return Object.entries(directives)
      .map(([directive, allowlist]) => {
        if (allowlist.length === 0) {
          return `${directive}=()`;
        }
        const sources = allowlist.map((source: any) =>
          source === 'self' ? '"self"' : `"${source}"`
        ).join(' ');
        return `${directive}=(${sources})`;
      })
      .join(', ');
  }

  /**
   * Apply module-specific security headers
   */
  private applyModuleSpecificHeaders(headers: Headers, context: RequestContext): void {
    switch (context.module) {
      case 'finance':
        // Extra security for financial module
        headers.set('X-Finance-Security', 'enabled');
        headers.set('X-Frame-Options', 'DENY'); // Override to be more strict
        headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        headers.set('Pragma', 'no-cache');
        headers.set('Expires', '0');
        break;

      case 'admin':
        // Admin interface security
        headers.set('X-Admin-Security', 'enabled');
        headers.set('X-Frame-Options', 'DENY');
        headers.set('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
        break;

      case 'auth':
        // Authentication security
        headers.set('X-Auth-Security', 'enabled');
        headers.set('Cache-Control', 'no-store');
        headers.set('Clear-Site-Data', '"cache", "storage"');
        break;

      case 'api':
        // API security
        headers.set('X-API-Version', process.env.API_VERSION || 'v4');
        headers.set('X-RateLimit-Policy', 'adaptive');
        break;

      case 'chat':
        // Real-time features
        headers.set('X-WebSocket-Policy', 'secure');
        break;

      default:
        break;
    }

    // Role-based headers
    switch (context.role) {
      case 'admin':
      case 'owner':
        headers.set('X-Privileged-Access', 'true');
        break;

      case 'viewer':
        headers.set('X-Read-Only-Access', 'true');
        break;

      default:
        break;
    }
  }

  /**
   * Validate response for security issues
   */
  async validateResponse(response: Response): Promise<SecurityValidationResult> {
    const issues: SecurityIssue[] = [];
    const warnings: string[] = [];

    // Check for sensitive data in headers
    for (const [name, value] of response.headers.entries()) {
      if (this.containsSensitiveData(name, value)) {
        issues.push({
          type: 'sensitive_data_exposure',
          severity: 'high',
          description: `Sensitive data detected in header: ${name}`,
          recommendation: 'Remove or mask sensitive data from headers'
        });
      }
    }

    // Check for missing security headers
    const requiredHeaders = [
      'Content-Security-Policy',
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Strict-Transport-Security'
    ];

    for (const header of requiredHeaders) {
      if (!response.headers.has(header)) {
        issues.push({
          type: 'missing_security_header',
          severity: 'medium',
          description: `Missing security header: ${header}`,
          recommendation: `Add ${header} header for better security`
        });
      }
    }

    // Check for insecure header values
    const csp = response.headers.get('Content-Security-Policy');
    if (csp && csp.includes("'unsafe-inline'")) {
      warnings.push("CSP contains 'unsafe-inline' directive");
    }

    const frameOptions = response.headers.get('X-Frame-Options');
    if (frameOptions && frameOptions.toUpperCase() === 'ALLOWALL') {
      issues.push({
        type: 'insecure_header_value',
        severity: 'high',
        description: 'X-Frame-Options set to ALLOWALL',
        recommendation: 'Use DENY or SAMEORIGIN instead'
      });
    }

    // Check for information disclosure
    if (response.headers.has('Server') || response.headers.has('X-Powered-By')) {
      issues.push({
        type: 'information_disclosure',
        severity: 'low',
        description: 'Server information disclosed in headers',
        recommendation: 'Remove server identification headers'
      });
    }

    return {
      secure: issues.filter((i: any) => i.severity === 'high' || i.severity === 'critical').length === 0,
      issues,
      warnings,
      score: this.calculateSecurityScore(issues, warnings)
    };
  }

  /**
   * Check if header contains sensitive data
   */
  private containsSensitiveData(name: string, value: string): boolean {
    const sensitivePatterns = [
      /password/i,
      /secret/i,
      /token/i,
      /key/i,
      /api[_-]key/i,
      /authorization/i,
      /session/i,
      /cookie/i
    ];

    // Check header name
    if (sensitivePatterns.some(pattern => pattern.test(name))) {
      return true;
    }

    // Check header value for patterns
    const valuePatterns = [
      /[a-zA-Z0-9]{32,}/,  // Long alphanumeric strings (potential tokens)
      /Bearer\s+[a-zA-Z0-9._-]+/,  // Bearer tokens
      /sk_[a-zA-Z0-9]+/,  // Stripe secret keys
      /pk_[a-zA-Z0-9]+/   // Stripe public keys
    ];

    return valuePatterns.some(pattern => pattern.test(value));
  }

  /**
   * Calculate security score
   */
  private calculateSecurityScore(issues: SecurityIssue[], warnings: string[]): number {
    let score = 100;

    for (const issue of issues) {
      switch (issue.severity) {
        case 'critical':
          score -= 30;
          break;
        case 'high':
          score -= 20;
          break;
        case 'medium':
          score -= 10;
          break;
        case 'low':
          score -= 5;
          break;
      }
    }

    score -= warnings.length * 2;

    return Math.max(0, score);
  }

  /**
   * Set default configuration
   */
  private setDefaults(): void {
    this.config = {
      csp: { enabled: true, reportOnly: false, ...this.config.csp },
      hsts: { enabled: true, maxAge: 31536000, includeSubDomains: true, preload: true, ...this.config.hsts },
      frameOptions: { enabled: true, policy: 'DENY', ...this.config.frameOptions },
      contentTypeOptions: { enabled: true, ...this.config.contentTypeOptions },
      xssProtection: { enabled: true, mode: 'block', ...this.config.xssProtection },
      referrerPolicy: { enabled: true, policy: 'strict-origin-when-cross-origin', ...this.config.referrerPolicy },
      permissionsPolicy: { enabled: true, ...this.config.permissionsPolicy },
      customHeaders: this.config.customHeaders || {}
    };
  }

  /**
   * Get security headers as object
   */
  async getSecurityHeaders(context: RequestContext): Promise<Record<string, string>> {
    const headers: Record<string, string> = {};

    // Build all headers
    if (this.config.csp?.enabled !== false) {
      const csp = await this.cspGenerator.generateCSP(context);
      headers['Content-Security-Policy'] = csp;
    }

    if (this.config.hsts?.enabled !== false) {
      headers['Strict-Transport-Security'] = this.buildHSTSHeader();
    }

    if (this.config.frameOptions?.enabled !== false) {
      headers['X-Frame-Options'] = this.config.frameOptions?.policy || 'DENY';
    }

    if (this.config.contentTypeOptions?.enabled !== false) {
      headers['X-Content-Type-Options'] = 'nosniff';
    }

    if (this.config.xssProtection?.enabled !== false) {
      const mode = this.config.xssProtection?.mode || 'block';
      headers['X-XSS-Protection'] = `1; mode=${mode}`;
    }

    if (this.config.referrerPolicy?.enabled !== false) {
      const policy = this.config.referrerPolicy?.policy || 'strict-origin-when-cross-origin';
      headers['Referrer-Policy'] = policy;
    }

    if (this.config.permissionsPolicy?.enabled !== false) {
      headers['Permissions-Policy'] = this.buildPermissionsPolicyHeader();
    }

    // Add custom headers
    if (this.config.customHeaders) {
      Object.assign(headers, this.config.customHeaders);
    }

    return headers;
  }
}

export interface SecurityIssue {
  type: 'missing_security_header' | 'insecure_header_value' | 'sensitive_data_exposure' | 'information_disclosure';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  recommendation: string;
}

export interface SecurityValidationResult {
  secure: boolean;
  issues: SecurityIssue[];
  warnings: string[];
  score: number;
}