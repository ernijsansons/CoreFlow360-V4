/**
 * Security Middleware - First line of defense
 * Implements OWASP security headers and protection mechanisms
 */

import type { Context, Next } from 'hono';
import { SecurityConfig } from '../config/security';
import { createLogger } from '../utils/logger';
import { SuspiciousActivityDetector } from '../services/security-service';

const logger = createLogger('security-middleware');

export class SecurityMiddleware {
  private readonly securityConfig: SecurityConfig;
  private readonly detector: SuspiciousActivityDetector;

  constructor(securityConfig: SecurityConfig) {
    this.securityConfig = securityConfig;
    this.detector = new SuspiciousActivityDetector();
  }

  handler() {
    return async (c: Context, next: Next) => {
      const startTime = Date.now();
      const requestId = crypto.randomUUID();

      try {
        // Set request ID for tracing
        c.set('requestId', requestId);
        c.set('startTime', startTime);

        // Security checks before processing
        await this.performSecurityChecks(c);

        // Process request
        await next();

        // Add security headers to response
        this.addSecurityHeaders(c);

        // Log successful request
        const responseTime = Date.now() - startTime;
        if (responseTime > 100) {
          logger.warn('Slow request detected', {
            requestId,
            responseTime,
            path: c.req.path,
            method: c.req.method
          });
        }

        return;
      } catch (error: any) {
        logger.error('Security middleware error', {
          requestId,
          error: error.message,
          path: c.req.path,
          method: c.req.method
        });

        // Return secure error response
        return c.json({
          error: 'Security validation failed',
          requestId,
          timestamp: new Date().toISOString()
        }, 403);
      }
    };
  }

  private async performSecurityChecks(c: Context): Promise<void> {
    const request = c.req.raw;

    // 1. Suspicious activity detection
    const suspiciousCheck = await this.detector.analyzeRequest(request);
    if (suspiciousCheck.isSuspicious) {
      logger.warn('Suspicious activity detected', {
        reasons: suspiciousCheck.reasons,
        ip: request.headers.get('CF-Connecting-IP'),
        userAgent: request.headers.get('User-Agent')
      });

      // Block highly suspicious requests
      if (suspiciousCheck.riskScore > 0.8) {
        throw new Error('Suspicious activity blocked');
      }
    }

    // 2. Request size validation
    const contentLength = request.headers.get('Content-Length');
    if (contentLength && parseInt(contentLength) > 10 * 1024 * 1024) { // 10MB
      throw new Error('Request too large');
    }

    // 3. Content-Type validation for POST/PUT requests
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      const contentType = request.headers.get('Content-Type');
      if (!contentType) {
        throw new Error('Missing Content-Type header');
      }

      const allowedTypes = [
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/plain'
      ];

      const mainType = contentType.split(';')[0].trim();
      if (!allowedTypes.includes(mainType)) {
        throw new Error('Invalid Content-Type');
      }
    }

    // 4. Host header validation
    const host = request.headers.get('Host');
    const allowedHosts = [
      'api.coreflow360.com',
      'app.coreflow360.com',
      'localhost:8787',
      'localhost:3000'
    ];

    if (host && !allowedHosts.some(allowed => host.includes(allowed))) {
      logger.warn('Invalid host header', { host });
    }
  }

  private addSecurityHeaders(c: Context): void {
    const headers = this.securityConfig.getSecurityHeaders();

    Object.entries(headers).forEach(([name, value]) => {
      c.res.headers.set(name, value);
    });

    // Add custom security headers
    c.res.headers.set('X-Request-ID', c.get('requestId'));
    c.res.headers.set('X-Response-Time', `${Date.now() - c.get('startTime')}ms`);

    // Remove potentially sensitive headers
    c.res.headers.delete('X-Powered-By');
    c.res.headers.delete('Server');
  }
}