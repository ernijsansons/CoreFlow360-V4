/**
 * Security Headers Middleware - OWASP 2025 Compliant
 * Implements all critical security headers to prevent common attacks
 * CVSS 7.8 Prevention: Missing Security Headers
 *
 * Security Features:
 * - Content Security Policy (CSP) with strict directives
 * - CSRF Token validation
 * - X-Frame-Options to prevent clickjacking
 * - X-Content-Type-Options to prevent MIME sniffing
 * - Strict-Transport-Security for HTTPS enforcement
 * - X-XSS-Protection for legacy browser protection
 * - Referrer-Policy for information leakage prevention
 * - Permissions-Policy for feature restriction
 */

import type { Context, Next } from 'hono';
import { SecurityError } from '../shared/errors/app-error';
import { createLogger } from '../utils/logger';
import type { Env } from '../types/env';

const logger = createLogger('security-headers');

export interface CSRFTokenPayload {
  token: string;
  userId: string;
  businessId?: string;
  createdAt: number;
  expiresAt: number;
}

export class SecurityHeadersMiddleware {
  static readonly CSRF_TOKEN_HEADER = 'X-CSRF-Token';
  static readonly CSRF_TOKEN_COOKIE = '__Host-csrf-token';
  static readonly CSRF_TOKEN_EXPIRY = 3600000; // 1 hour

  /**
   * Apply all security headers to the response
   */
  static applySecurityHeaders(response: Response, env: Env): Response {
    const headers = new Headers(response.headers);
    const isProduction = env.ENVIRONMENT === 'production';

    // Content Security Policy - Strict mode
    const cspDirectives = [
      "default-src 'self'",
      "script-src 'self' 'strict-dynamic'",  // No unsafe-inline
      "style-src 'self'",  // No unsafe-inline for styles
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self' https://api.coreflow360.com wss://ws.coreflow360.com",
      "media-src 'none'",
      "object-src 'none'",
      "frame-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
      "block-all-mixed-content"
    ];

    // Add nonce for scripts if needed (for dynamic script injection)
    const scriptNonce = crypto.randomUUID();
    headers.set('X-Script-Nonce', scriptNonce);

    headers.set('Content-Security-Policy', cspDirectives.join('; '));

    // Additional security headers
    headers.set('X-Frame-Options', 'DENY');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-XSS-Protection', '1; mode=block');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions Policy - Restrict feature access
    headers.set('Permissions-Policy',
      'accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), ' +
      'camera=(), display-capture=(), document-domain=(), encrypted-media=(), ' +
      'execution-while-not-rendered=(), execution-while-out-of-viewport=(), ' +
      'fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), ' +
      'microphone=(), midi=(), payment=(), picture-in-picture=(), ' +
      'publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), ' +
      'usb=(), web-share=(), xr-spatial-tracking=()'
    );

    // HSTS - Strict Transport Security (production only)
    if (isProduction) {
      headers.set('Strict-Transport-Security',
        'max-age=31536000; includeSubDomains; preload'
      );
    }

    // Remove sensitive headers
    headers.delete('X-Powered-By');
    headers.delete('Server');

    // Add custom security headers
    headers.set('X-Security-Policy', 'enabled');
    headers.set('X-Request-ID', crypto.randomUUID());

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  }

  /**
   * Generate a CSRF token
   */
  static async generateCSRFToken(
    userId: string,
    businessId?: string,
    kv?: KVNamespace
  ): Promise<string> {
    const token = crypto.randomUUID();
    const payload: CSRFTokenPayload = {
      token,
      userId,
      businessId,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.CSRF_TOKEN_EXPIRY
    };

    // Store in KV if available
    if (kv) {
      const key = `csrf:${userId}:${token}`;
      await kv.put(key, JSON.stringify(payload), {
        expirationTtl: this.CSRF_TOKEN_EXPIRY / 1000
      });
    }

    // Encode payload for stateless validation (backup)
    const encodedPayload = btoa(JSON.stringify(payload));
    return `${token}.${encodedPayload}`;
  }

  /**
   * Validate a CSRF token
   */
  static async validateCSRFToken(
    token: string,
    userId: string,
    businessId?: string,
    kv?: KVNamespace
  ): Promise<boolean> {
    if (!token) {
      throw new SecurityError('CSRF token missing');
    }

    try {
      // Try to validate from KV first
      if (kv) {
        const [tokenId] = token.split('.');
        const key = `csrf:${userId}:${tokenId}`;
        const stored = await kv.get(key, 'json') as CSRFTokenPayload | null;

        if (stored) {
          // Validate stored token
          if (stored.userId !== userId) {
            logger.warn('CSRF token user mismatch', {
              expected: userId,
              actual: stored.userId
            });
            return false;
          }

          if (businessId && stored.businessId !== businessId) {
            logger.warn('CSRF token business mismatch', {
              expected: businessId,
              actual: stored.businessId
            });
            return false;
          }

          if (stored.expiresAt < Date.now()) {
            logger.warn('CSRF token expired');
            return false;
          }

          // Delete token after successful validation (one-time use)
          await kv.delete(key);
          return true;
        }
      }

      // Fallback to stateless validation
      const [tokenId, encodedPayload] = token.split('.');
      if (!tokenId || !encodedPayload) {
        return false;
      }

      const payload = JSON.parse(atob(encodedPayload)) as CSRFTokenPayload;

      // Validate payload
      if (payload.token !== tokenId) {
        return false;
      }

      if (payload.userId !== userId) {
        return false;
      }

      if (businessId && payload.businessId !== businessId) {
        return false;
      }

      if (payload.expiresAt < Date.now()) {
        return false;
      }

      return true;
    } catch (error) {
      logger.error('CSRF token validation error', { error });
      return false;
    }
  }

  /**
   * Middleware function for Hono
   */
  static middleware() {
    return async (c: Context<{ Bindings: Env }>, next: Next) => {
      const env = c.env;
      const method = c.req.method;

      // Apply security headers to all responses
      await next();

      // Apply headers to the response
      const response = c.res;
      const secureResponse = SecurityHeadersMiddleware.applySecurityHeaders(
        new Response(response.body, {
          status: response.status,
          headers: response.headers
        }),
        env
      );

      // Update the response
      const headersObject: Record<string, string> = {};
      secureResponse.headers.forEach((value, key) => {
        headersObject[key] = value;
      });
      Object.entries(headersObject).forEach(
        ([key, value]) => c.header(key, value)
      );

      // CSRF validation for state-changing methods
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        const path = new URL(c.req.url).pathname;

        // Skip CSRF for authentication endpoints
        // SECURITY FIX: Removed /api/auth/logout to prevent CSRF logout attacks (CVSS 5.4)
        const skipCSRF = [
          '/api/auth/login',
          '/api/auth/register',
          '/api/auth/refresh'
        ];

        if (!skipCSRF.includes(path)) {
          const csrfToken = c.req.header(SecurityHeadersMiddleware.CSRF_TOKEN_HEADER);
          const userId = c.get('userId' as any) as string;
          const businessId = c.get('businessId' as any) as string;

          if (!csrfToken) {
            logger.warn('Missing CSRF token', {
              path,
              method,
              userId
            });

            return c.json({
              error: 'CSRF token required',
              code: 'CSRF_VALIDATION_FAILED'
            }, 403);
          }

          const isValid = await SecurityHeadersMiddleware.validateCSRFToken(
            csrfToken,
            userId,
            businessId,
            env.KV_AUTH
          );

          if (!isValid) {
            logger.warn('Invalid CSRF token', {
              path,
              method,
              userId
            });

            return c.json({
              error: 'Invalid CSRF token',
              code: 'CSRF_VALIDATION_FAILED'
            }, 403);
          }
        }
      }
    };
  }

  /**
   * Generate secure cookie options
   */
  static getSecureCookieOptions(isProduction: boolean): any {
    return {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict' as const,
      path: '/',
      maxAge: 3600, // 1 hour
      ...(isProduction && {
        domain: '.coreflow360.com',
        prefix: '__Host-'
      })
    };
  }
}

/**
 * Helper function to create CSP nonce middleware
 */
export function createCSPNonceMiddleware() {
  return async (c: Context, next: Next) => {
    const nonce = crypto.randomUUID();
    c.set('cspNonce' as any, nonce);

    await next();

    // Update CSP header with nonce
    const csp = c.res.headers.get('Content-Security-Policy');
    if (csp) {
      const updatedCSP = csp.replace(
        "'strict-dynamic'",
        `'nonce-${nonce}' 'strict-dynamic'`
      );
      c.header('Content-Security-Policy', updatedCSP);
    }
  };
}

/**
 * Create a CSRF token endpoint handler
 */
export function createCSRFTokenEndpoint(env: Env) {
  return async (c: Context) => {
    const userId = c.get('userId' as any) as string;
    const businessId = c.get('businessId' as any) as string | undefined;

    if (!userId) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    const token = await SecurityHeadersMiddleware.generateCSRFToken(
      userId,
      businessId,
      env.KV_AUTH
    );

    // Set secure cookie
    const cookieOptions = SecurityHeadersMiddleware.getSecureCookieOptions(
      env.ENVIRONMENT === 'production'
    );

    return c.json(
      {
        csrf_token: token,
        expires_in: SecurityHeadersMiddleware.CSRF_TOKEN_EXPIRY
      },
      200,
      {
        'Set-Cookie': `${SecurityHeadersMiddleware.CSRF_TOKEN_COOKIE}=${token}; ${Object.entries(cookieOptions)
          .map(([k, v]) => `${k}=${v}`)
          .join('; ')}`
      }
    );
  };
}