/**
 * SECURITY UTILITIES
 * Production-ready security headers and utilities for Cloudflare Workers
 */

import type { KVNamespace } from '../types/cloudflare';

export interface SecurityConfig {
  csp?: string;
  frameOptions?: 'DENY' | 'SAMEORIGIN' | string;
  contentTypeOptions?: boolean;
  xssProtection?: boolean;
  referrerPolicy?: string;
  permissionsPolicy?: string;
  hsts?: {
    maxAge: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  };
  reportUri?: string;
}

/**
 * Create security headers response
 */
export function createSecurityHeaders(response: Response, env?: any): Response {
  const headers = new Headers(response.headers);

  const config: SecurityConfig = {
    csp: env?.CSP_POLICY || getDefaultCSP(env),
    frameOptions: 'DENY',
    contentTypeOptions: true,
    xssProtection: true,
    referrerPolicy: 'strict-origin-when-cross-origin',
    permissionsPolicy: 'geolocation=(), microphone=(), camera=(), payment=(), usb=()',
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true
    }
  };

  // Content Security Policy
  if (config.csp) {
    headers.set('Content-Security-Policy', config.csp);
  }

  // X-Frame-Options
  if (config.frameOptions) {
    headers.set('X-Frame-Options', config.frameOptions);
  }

  // X-Content-Type-Options
  if (config.contentTypeOptions) {
    headers.set('X-Content-Type-Options', 'nosniff');
  }

  // X-XSS-Protection
  if (config.xssProtection) {
    headers.set('X-XSS-Protection', '1; mode=block');
  }

  // Referrer-Policy
  if (config.referrerPolicy) {
    headers.set('Referrer-Policy', config.referrerPolicy);
  }

  // Permissions-Policy
  if (config.permissionsPolicy) {
    headers.set('Permissions-Policy', config.permissionsPolicy);
  }

  // Strict-Transport-Security
  if (config.hsts) {
    let hstsValue = `max-age=${config.hsts.maxAge}`;
    if (config.hsts.includeSubDomains) {
      hstsValue += '; includeSubDomains';
    }
    if (config.hsts.preload) {
      hstsValue += '; preload';
    }
    headers.set('Strict-Transport-Security', hstsValue);
  }

  // Additional security headers
  headers.set('X-Permitted-Cross-Domain-Policies', 'none');
  headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');

  // Remove sensitive headers
  headers.delete('Server');
  headers.delete('X-Powered-By');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

/**
 * Get default Content Security Policy
 */
function getDefaultCSP(env?: any): string {
  const nonce = generateNonce();

  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' https://challenges.cloudflare.com`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self' data:",
    "connect-src 'self' https://api.coreflow360.com wss://api.coreflow360.com",
    "media-src 'self' https:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ];

  // Add report URI if configured
  if (env?.CSP_REPORT_URI) {
    csp.push(`report-uri ${env.CSP_REPORT_URI}`);
  }

  return csp.join('; ');
}

/**
 * Generate nonce for CSP
 */
function generateNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, Array.from(array)));
}

/**
 * Security middleware for request validation
 */
export class SecurityMiddleware {
  private config: SecurityConfig;

  constructor(config: SecurityConfig = {}) {
    this.config = config;
  }

  /**
   * Validate request security
   */
  async validateRequest(request: Request): Promise<SecurityValidationResult> {
    const validations = await Promise.all([
      this.validateOrigin(request),
      this.validateUserAgent(request),
      this.validateHeaders(request),
      this.validatePath(request),
      this.detectSuspiciousPatterns(request)
    ]);

    const failed = validations.filter(v => !v.passed);

    return {
      passed: failed.length === 0,
      validations,
      failedChecks: failed.length,
      riskLevel: this.calculateRiskLevel(failed)
    };
  }

  /**
   * Validate request origin
   */
  private async validateOrigin(request: Request): Promise<SecurityCheck> {
    const origin = request.headers.get('Origin');
    const referer = request.headers.get('Referer');
    const host = request.headers.get('Host');

    // Skip validation for same-origin requests
    if (!origin && !referer) {
      return {
        name: 'origin_validation',
        passed: true,
        message: 'Same-origin request'
      };
    }

    // Validate origin against host
    if (origin) {
      try {
        const originUrl = new URL(origin);
        if (originUrl.host !== host) {
          return {
            name: 'origin_validation',
            passed: false,
            message: 'Origin mismatch',
            details: { origin, host }
          };
        }
      } catch {
        return {
          name: 'origin_validation',
          passed: false,
          message: 'Invalid origin header'
        };
      }
    }

    return {
      name: 'origin_validation',
      passed: true,
      message: 'Origin validated'
    };
  }

  /**
   * Validate User-Agent
   */
  private async validateUserAgent(request: Request): Promise<SecurityCheck> {
    const userAgent = request.headers.get('User-Agent');

    if (!userAgent) {
      return {
        name: 'user_agent_validation',
        passed: false,
        message: 'Missing User-Agent header'
      };
    }

    // Check for suspicious user agents
    const suspiciousPatterns = [
      /sqlmap/i,
      /nikto/i,
      /nmap/i,
      /masscan/i,
      /zap/i,
      /burp/i,
      /crawler/i,
      /bot/i,
      /spider/i
    ];

    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(userAgent));

    if (isSuspicious) {
      return {
        name: 'user_agent_validation',
        passed: false,
        message: 'Suspicious User-Agent detected',
        details: { userAgent }
      };
    }

    return {
      name: 'user_agent_validation',
      passed: true,
      message: 'User-Agent validated'
    };
  }

  /**
   * Validate request headers
   */
  private async validateHeaders(request: Request): Promise<SecurityCheck> {
    const suspiciousHeaders = [
      'X-Originating-IP',
      'X-Forwarded-Host',
      'X-Remote-IP',
      'X-Remote-Addr'
    ];

    for (const header of suspiciousHeaders) {
      if (request.headers.has(header)) {
        return {
          name: 'header_validation',
          passed: false,
          message: `Suspicious header detected: ${header}`
        };
      }
    }

    // Check for header injection attempts
    const headerEntries: [string, string][] = [];
    request.headers.forEach((value, name) => {
      headerEntries.push([name, value]);
    });

    for (const [name, value] of headerEntries) {
      if (value.includes('\n') || value.includes('\r')) {
        return {
          name: 'header_validation',
          passed: false,
          message: 'Header injection attempt detected',
          details: { header: name }
        };
      }
    }

    return {
      name: 'header_validation',
      passed: true,
      message: 'Headers validated'
    };
  }

  /**
   * Validate request path
   */
  private async validatePath(request: Request): Promise<SecurityCheck> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Check for path traversal
    if (path.includes('../') || path.includes('..\\')) {
      return {
        name: 'path_validation',
        passed: false,
        message: 'Path traversal attempt detected'
      };
    }

    // Check for suspicious file extensions
    const suspiciousExtensions = [
      '.php', '.asp', '.jsp', '.cgi', '.pl', '.py', '.rb', '.sh'
    ];

    const hasSuspiciousExtension = suspiciousExtensions.some(ext => path.includes(ext));

    if (hasSuspiciousExtension) {
      return {
        name: 'path_validation',
        passed: false,
        message: 'Suspicious file extension in path'
      };
    }

    return {
      name: 'path_validation',
      passed: true,
      message: 'Path validated'
    };
  }

  /**
   * Detect suspicious patterns
   */
  private async detectSuspiciousPatterns(request: Request): Promise<SecurityCheck> {
    const url = new URL(request.url);
    const fullUrl = request.url;

    // SQL injection patterns
    const sqlPatterns = [
      /union.*select/i,
      /drop.*table/i,
      /insert.*into/i,
      /delete.*from/i,
      /update.*set/i,
      /'.*or.*'/i,
      /1=1/i,
      /1'1/i
    ];

    // XSS patterns
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+=/i,
      /<iframe/i,
      /<object/i,
      /<embed/i
    ];

    // Command injection patterns
    const cmdPatterns = [
      /;.*cat/i,
      /\|.*ls/i,
      /&&.*whoami/i,
      /`.*id`/i,
      /\$\(.*\)/i
    ];

    const allPatterns = [...sqlPatterns, ...xssPatterns, ...cmdPatterns];

    const hasSuspiciousPattern = allPatterns.some(pattern => pattern.test(fullUrl));

    if (hasSuspiciousPattern) {
      return {
        name: 'pattern_detection',
        passed: false,
        message: 'Suspicious attack pattern detected'
      };
    }

    return {
      name: 'pattern_detection',
      passed: true,
      message: 'No suspicious patterns detected'
    };
  }

  /**
   * Calculate risk level based on failed checks
   */
  private calculateRiskLevel(failedChecks: SecurityCheck[]): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const criticalChecks = ['pattern_detection', 'header_validation'];
    const highChecks = ['user_agent_validation', 'path_validation'];

    const hasCritical = failedChecks.some(check => criticalChecks.includes(check.name));
    const hasHigh = failedChecks.some(check => highChecks.includes(check.name));

    if (hasCritical) return 'CRITICAL';
    if (hasHigh || failedChecks.length >= 3) return 'HIGH';
    if (failedChecks.length >= 2) return 'MEDIUM';
    return 'LOW';
  }
}

/**
 * Rate limiting utilities
 */
export class RateLimiter {
  private cache: KVNamespace;

  constructor(cache: KVNamespace) {
    this.cache = cache;
  }

  /**
   * Check rate limit
   */
  async checkRateLimit(
    key: string,
    limit: number,
    windowSeconds: number
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = now - (windowSeconds * 1000);

    // Get current count
    const current = await this.cache.get(key);
    const requests = current ? JSON.parse(current) : [];

    // Filter requests within window
    const validRequests = requests.filter((timestamp: number) => timestamp > windowStart);

    // Check if limit exceeded
    if (validRequests.length >= limit) {
      return {
        allowed: false,
        limit,
        remaining: 0,
        resetTime: windowStart + (windowSeconds * 1000)
      };
    }

    // Add current request
    validRequests.push(now);

    // Update cache
    await this.cache.put(key, JSON.stringify(validRequests), {
      expirationTtl: windowSeconds
    });

    return {
      allowed: true,
      limit,
      remaining: limit - validRequests.length,
      resetTime: windowStart + (windowSeconds * 1000)
    };
  }
}

// Type definitions
interface SecurityCheck {
  name: string;
  passed: boolean;
  message: string;
  details?: any;
}

interface SecurityValidationResult {
  passed: boolean;
  validations: SecurityCheck[];
  failedChecks: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetTime: number;
}