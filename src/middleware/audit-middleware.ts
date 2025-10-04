/**
 * Audit Middleware - Comprehensive audit logging middleware
 */

import { Context, Next } from 'hono';
import type { Env } from '../types/environment';

export class AuditMiddleware {
  private readonly auditLogger: Console;

  constructor(private env: Env) {
    this.auditLogger = console;
  }

  /**
   * Log audit trail for all requests
   */
  async middleware() {
    return async (c: Context<{ Bindings: Env }>, next: Next) => {
      const startTime = Date.now();
      const requestId = crypto.randomUUID();

      // Log request
      this.auditLogger.log('AUDIT', {
        type: 'REQUEST',
        requestId,
        timestamp: new Date().toISOString(),
        method: c.req.method,
        path: c.req.path,
        ip: c.req.header('CF-Connecting-IP') || 'unknown',
        userAgent: c.req.header('User-Agent'),
        userId: c.get('userId') || 'anonymous'
      });

      try {
        await next();

        // Log response
        this.auditLogger.log('AUDIT', {
          type: 'RESPONSE',
          requestId,
          timestamp: new Date().toISOString(),
          status: c.res.status,
          duration: Date.now() - startTime
        });
      } catch (error) {
        // Log error
        this.auditLogger.error('AUDIT', {
          type: 'ERROR',
          requestId,
          timestamp: new Date().toISOString(),
          error: error instanceof Error ? error.message : 'Unknown error',
          duration: Date.now() - startTime
        });
        throw error;
      }
    };
  }
}