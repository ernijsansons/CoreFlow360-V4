// src/middleware/security.ts
import type { ExecutionContext } from '../cloudflare/types/cloudflare';

export interface SecurityConfig {
  enableHSTS?: boolean;
  hstsMaxAge?: number;
  allowedOrigins?: string[];
  allowedFrameAncestors?: string[];
  customCSP?: string;
  reportUri?: string;
  environment?: string;
}

export async function addSecurityHeaders(
  response: Response,
  config: SecurityConfig = {}
): Promise<Response> {
  const headers = new Headers(response.headers);

  // Core security headers
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', config.allowedFrameAncestors?.length ? 'SAMEORIGIN' : 'DENY');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions Policy - Restrictive by default
  headers.set('Permissions-Policy', [
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
    'fullscreen=()',
    'picture-in-picture=()'
  ].join(', '));

  // HSTS - Only for HTTPS
  if (config.enableHSTS !== false) {
    const maxAge = config.hstsMaxAge || 31536000; // 1 year
    headers.set('Strict-Transport-Security',
      `max-age=${maxAge}; includeSubDomains; preload`);
  }

  // Content Security Policy
  const csp = config.customCSP || buildCSP(config);
  headers.set('Content-Security-Policy', csp);

  // Report-Only CSP for testing in development
  if (config.environment === 'development' && config.reportUri) {
    headers.set('Content-Security-Policy-Report-Only', csp);
  }

  // Additional security headers
  headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');

  // Remove potentially sensitive headers
  headers.delete('Server');
  headers.delete('X-Powered-By');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

export function buildCSP(config: SecurityConfig): string {
  const policy = {
    'default-src': ["'self'"],
    'script-src': [
      "'self'",
      "'unsafe-inline'", // Required for some functionality
      'https://cdn.cloudflare.com',
      'https://challenges.cloudflare.com'
    ],
    'style-src': [
      "'self'",
      "'unsafe-inline'", // Required for dynamic styles
      'https://fonts.googleapis.com'
    ],
    'img-src': [
      "'self'",
      'data:',
      'https:',
      'blob:'
    ],
    'font-src': [
      "'self'",
      'https://fonts.gstatic.com'
    ],
    'connect-src': [
      "'self'",
      'https://api.anthropic.com',
      'https://api.openai.com',
      'https://api.cloudflare.com',
      'wss:', // For WebSocket connections
      'https:'
    ],
    'media-src': ["'self'", 'https:'],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': config.allowedFrameAncestors || ["'none'"],
    'upgrade-insecure-requests': [],
    'block-all-mixed-content': []
  };

  // Add report URI if configured
  if (config.reportUri) {
    policy['report-uri'] = [config.reportUri];
  }

  // Convert policy object to CSP string
  return Object.entries(policy)
    .map(([directive, sources]) =>
      sources.length ? `${directive} ${sources.join(' ')}` : directive
    )
    .join('; ');
}

export async function validateCSP(
  request: Request,
  reportUri: string
): Promise<void> {
  // Process CSP violation reports
  if (request.method === 'POST' && request.url.includes('/csp-report')) {
    try {
      const report = await request.json();

      // Send to monitoring service
      await fetch(reportUri, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'csp-violation',
          report,
          timestamp: new Date().toISOString(),
          userAgent: request.headers.get('User-Agent')
        })
      });
    } catch (error) {
    }
  }
}

export function corsHeaders(
  allowedOrigins: string[] = [],
  allowCredentials = false
): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': allowedOrigins.length === 1
      ? allowedOrigins[0]
      : '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-Business-ID',
      'X-User-ID'
    ].join(', '),
    'Access-Control-Max-Age': '86400',
    ...(allowCredentials && { 'Access-Control-Allow-Credentials': 'true' })
  };
}

export async function rateLimitByIP(
  request: Request,
  kv: KVNamespace,
  limit = 100,
  window = 60
): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = `rate_limit:${ip}`;
  const now = Date.now();
  const resetTime = now + (window * 1000);

  try {
    const current = await kv.get(key);
    const count = current ? parseInt(current) : 0;

    if (count >= limit) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: resetTime
      };
    }

    // Increment counter
    await kv.put(key, (count + 1).toString(), {
      expirationTtl: window
    });

    return {
      allowed: true,
      remaining: limit - count - 1,
      resetTime: resetTime
    };
  } catch (error) {
    // Fail open - allow request if rate limiting fails
    return {
      allowed: true,
      remaining: limit,
      resetTime: resetTime
    };
  }
}

export function addRateLimitHeaders(
  response: Response,
  rateLimit: {
    allowed: boolean;
    remaining: number;
    resetTime: number;
  }
): Response {
  const headers = new Headers(response.headers);

  headers.set('X-RateLimit-Limit', '100');
  headers.set('X-RateLimit-Remaining', rateLimit.remaining.toString());
  headers.set('X-RateLimit-Reset', Math.floor(rateLimit.resetTime / 1000).toString());

  if (!rateLimit.allowed) {
    headers.set('Retry-After', '60');
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

export async function validateJWT(
  token: string,
  secret: string
): Promise<{ valid: boolean; payload?: any; error?: string }> {
  try {
    // Simple JWT validation (in production, use a proper JWT library)
    const [header, payload, signature] = token.split('.');

    if (!header || !payload || !signature) {
      return { valid: false, error: 'Invalid token format`' };
    }

    // Decode payload
    const decodedPayload = JSON.parse(
      atob(payload.replace(/-/g, '').replace(/_/g, '`/'))
    );

    // Check expiration
    if (decodedPayload.exp && decodedPayload.exp < Date.now() / 1000) {
      return { valid: false, error: 'Token expired' };
    }

    // In production, verify signature with crypto.subtle
    // For now, simple validation
    return {
      valid: true,
      payload: decodedPayload
    };
  } catch (error) {
    return {
      valid: false,
      error: 'Token validation failed'
    };
  }
}

export function sanitizeInput(input: string): string {
  return input
    .replace(/[<>\"'&]/g, (char) => {
      const entities: Record<string, string> = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
      };
      return entities[char] || char;
    })
    .trim()
    .slice(0, 1000); // Limit length
}

export function validateBusinessId(businessId: string): boolean {
  // Business ID validation
  const pattern = /^[a-zA-Z0-9_-]{3,50}$/;
  return pattern.test(businessId);
}

export function detectSuspiciousActivity(
  request: Request
): { suspicious: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const userAgent = request.headers.get('User-Agent') || '';
  const url = new URL(request.url);

  // Check for suspicious patterns
  if (userAgent.length < 10 || userAgent.includes('bot') || userAgent.includes('curl')) {
    reasons.push('Suspicious user agent');
  }

  if (url.pathname.includes('..') || url.pathname.includes('%')) {
    reasons.push('Path traversal attempt');
  }

  if (request.method === 'POST' && !request.headers.get('Content-Type')) {
    reasons.push('Missing content type');
  }

  // Check for SQL injection patterns in query parameters
  const queryString = url.search.toLowerCase();
  const sqlPatterns = ['union', 'select', 'drop', 'insert', 'delete', 'update'];
  if (sqlPatterns.some(pattern => queryString.includes(pattern))) {
    reasons.push('Potential SQL injection');
  }

  return {
    suspicious: reasons.length > 0,
    reasons
  };
}

export async function logSecurityEvent(
  event: string,
  details: any,
  analytics: AnalyticsEngineDataset
): Promise<void> {
  try {
    await analytics.writeDataPoint({
      indexes: ['security', event, details.severity || 'medium'],
      blobs: [
        JSON.stringify(details),
        details.ip || 'unknown',
        details.userAgent || 'unknown'
      ],
      doubles: [Date.now(), 1]
    });
  } catch (error) {
  }
}

// Security middleware factory
export function createSecurityMiddleware(config: SecurityConfig) {
  return async (
    request: Request,
    response: Response,
    ctx: ExecutionContext
  ): Promise<Response> => {
    // Add security headers to response
    return addSecurityHeaders(response, config);
  };
}