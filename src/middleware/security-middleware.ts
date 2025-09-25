/**
 * Security Middleware Integration
 * Orchestrates all security measures for requests
 */

import { z } from 'zod';
import { Logger } from '../shared/logger';
import { CorrelationId } from '../shared/correlation-id';
import { ThreatDetectionEngine, ThreatAnalysis } from '../security/threat-detection-engine';
import { SQLInjectionGuard } from '../security/sql-injection-guard';
import { AdaptiveRateLimiter, RateLimitDecision } from '../security/adaptive-rate-limiter';
import { SecurityHeaders } from '../security/security-headers';
import { RequestContext } from '../security/csp-generator';

export interface SecurityConfig {
  threatDetection: {
    enabled: boolean;
    blockThreshold: number;
    challengeThreshold: number;
  };
  rateLimit: {
    enabled: boolean;
    adaptive: boolean;
  };
  sqlInjection: {
    enabled: boolean;
    strictMode: boolean;
  };
  headers: {
    enabled: boolean;
    reportOnly: boolean;
  };
  monitoring: {
    enabled: boolean;
    logLevel: 'debug' | 'info' | 'warn' | 'error';
  };
}

export interface SecurityResult {
  allowed: boolean;
  action: 'ALLOW' | 'BLOCK' | 'CHALLENGE';
  reason?: string;
  threatAnalysis?: ThreatAnalysis;
  rateLimitDecision?: RateLimitDecision;
  recommendations?: string[];
}

export class SecurityMiddleware {
  private logger = new Logger();
  private threatEngine = new ThreatDetectionEngine();
  private sqlGuard = new SQLInjectionGuard();
  private rateLimiter = new AdaptiveRateLimiter();
  private securityHeaders = new SecurityHeaders();

  constructor(private config: SecurityConfig) {}

  /**
   * Main security middleware function
   */
  middleware() {
    return async (c: any, next: () => Promise<void>) => {
      const correlationId = CorrelationId.generate();
      const startTime = Date.now();

      this.logger.debug('Security middleware started', {
        correlationId,
        url: c.req.url,
        method: c.req.method
      });

      try {
        // Build request context
        const context = await this.buildRequestContext(c, correlationId);

        // Run security checks
        const securityResult = await this.runSecurityChecks(c.req.raw, context);

        // Handle security decision
        if (!securityResult.allowed) {
          return this.handleSecurityBlock(c, securityResult, correlationId);
        }

        // Set security context for downstream middleware
        c.set('securityContext', {
          correlationId,
          threatLevel: securityResult.threatAnalysis?.score || 0,
          rateLimitRemaining: securityResult.rateLimitDecision?.allowedRequests,
          context
        });

        // Continue to next middleware
        await next();

        // Apply security headers to response
        if (this.config.headers.enabled) {
          c.res = await this.securityHeaders.apply(c.res, context);
        }

        // Log successful request
        this.logger.debug('Security middleware completed', {
          correlationId,
          duration: Date.now() - startTime,
          threatScore: securityResult.threatAnalysis?.score
        });

      } catch (error) {
        this.logger.error('Security middleware error', error, {
          correlationId
        });

        // Fail closed - block request on security error
        return c.json({
          error: 'Security validation failed',
          code: 'SECURITY_ERROR',
          correlationId
        }, 500);
      }
    };
  }

  /**
   * Build request context for security analysis
   */
  private async buildRequestContext(c: any, correlationId: string): Promise<RequestContext> {
    const url = new URL(c.req.url);

    return {
      businessId: c.req.header('x-tenant-id') || 'unknown',
      userId: c.req.header('x-user-id') || 'anonymous',
      module: this.extractModule(url.pathname),
      role: c.req.header('x-user-role') || 'user',
      endpoint: url.pathname,
      method: c.req.method,
      userAgent: c.req.header('user-agent'),
      correlationId
    };
  }

  /**
   * Extract module from URL path
   */
  private extractModule(path: string): string {
    if (path.startsWith('/api/v4/auth/')) return 'auth';
    if (path.startsWith('/api/v4/finance/')) return 'finance';
    if (path.startsWith('/api/v4/admin/')) return 'admin';
    if (path.startsWith('/api/v4/chat/')) return 'chat';
    if (path.startsWith('/api/v4/agents/')) return 'agents';
    if (path.startsWith('/api/v4/')) return 'api';
    if (path.startsWith('/dashboard/')) return 'dashboard';
    return 'general';
  }

  /**
   * Run all security checks
   */
  private async runSecurityChecks(
    request: Request,
    context: RequestContext
  ): Promise<SecurityResult> {
    const checks = await Promise.allSettled([
      // Rate limiting check
      this.config.rateLimit.enabled ?
        this.rateLimiter.shouldLimit(request) :
        Promise.resolve({ limited: false }),

      // Threat detection check
      this.config.threatDetection.enabled ?
        this.threatEngine.analyzeRequest(request) :
        Promise.resolve({ action: 'ALLOW', score: 0, threats: [] })
    ]);

    // Extract results
    const rateLimitResult = checks[0].status === 'fulfilled' ?
      checks[0].value : { limited: true, reason: 'Rate limit check failed' };

    const threatResult = checks[1].status === 'fulfilled' ?
      checks[1].value : { action: 'BLOCK', reason: 'Threat detection failed', score: 1, threats: [] };

    // Determine overall action
    let action: 'ALLOW' | 'BLOCK' | 'CHALLENGE' = 'ALLOW';
    let reason: string | undefined;

    // Rate limiting takes precedence
    if (rateLimitResult.limited) {
      action = 'BLOCK';
      reason = rateLimitResult.reason || 'Rate limit exceeded';
    }
    // Then threat detection
    else if (threatResult.score >= this.config.threatDetection.blockThreshold) {
      action = 'BLOCK';
      reason = threatResult.reason || 'High threat detected';
    }
    else if (threatResult.score >= this.config.threatDetection.challengeThreshold) {
      action = 'CHALLENGE';
      reason = threatResult.reason || 'Suspicious activity';
    }

    return {
      allowed: action === 'ALLOW',
      action,
      reason,
      threatAnalysis: threatResult,
      rateLimitDecision: rateLimitResult,
      recommendations: threatResult.recommendations
    };
  }

  /**
   * Handle security block/challenge
   */
  private async handleSecurityBlock(
    c: any,
    result: SecurityResult,
    correlationId: string
  ): Promise<Response> {
    this.logger.warn('Request blocked by security middleware', {
      correlationId,
      action: result.action,
      reason: result.reason,
      threatScore: result.threatAnalysis?.score
    });

    if (result.action === 'CHALLENGE') {
      return c.json({
        error: 'Security challenge required',
        code: 'SECURITY_CHALLENGE',
        challenge: result.threatAnalysis?.challenge,
        correlationId
      }, 429);
    }

    // Block response
    const status = result.rateLimitDecision?.limited ? 429 : 403;
    const retryAfter = result.rateLimitDecision?.retryAfter;

    const response = c.json({
      error: 'Request blocked',
      code: result.rateLimitDecision?.limited ? 'RATE_LIMITED' : 'SECURITY_BLOCK',
      reason: result.reason,
      correlationId
    }, status);

    if (retryAfter) {
      response.headers.set('Retry-After', retryAfter.toString());
    }

    return response;
  }

  /**
   * Validate SQL queries (called by database layer)
   */
  async validateSQL(query: string, params: any[], context: any): Promise<void> {
    if (!this.config.sqlInjection.enabled) return;

    const result = await this.sqlGuard.validate(query, {
      query,
      params,
      isParameterized: params.length > 0,
      expectedType: this.inferQueryType(query),
      maxLength: 10000,
      allowedPattern: /^[\w\s\-.,()=<>!?'"@#$%^&*+/\\:;|`~\[\]{}]*$/,
      businessId: context.businessId || 'unknown',
      userId: context.userId
    });

    if (!result.valid) {
      this.logger.error('SQL injection attempt blocked', {
        query: query.substring(0, 200),
        reason: result.reason,
        evidence: result.evidence,
        businessId: context.businessId
      });

      throw new Error(`SQL validation failed: ${result.reason}`);
    }
  }

  /**
   * Infer query type from SQL
   */
  private inferQueryType(query: string): 'select' | 'insert' | 'update' | 'delete' | 'other' {
    const trimmed = query.trim().toLowerCase();

    if (trimmed.startsWith('select')) return 'select';
    if (trimmed.startsWith('insert')) return 'insert';
    if (trimmed.startsWith('update')) return 'update';
    if (trimmed.startsWith('delete')) return 'delete';

    return 'other';
  }

  /**
   * Get security metrics
   */
  async getSecurityMetrics(): Promise<SecurityMetrics> {
    // This would aggregate metrics from all security components
    return {
      threatsBlocked: 0,
      rateLimitViolations: 0,
      sqlInjectionAttempts: 0,
      xssAttempts: 0,
      averageThreatScore: 0,
      securityScore: 95
    };
  }

  /**
   * Health check for security components
   */
  async healthCheck(): Promise<SecurityHealthCheck> {
    const checks = await Promise.allSettled([
      this.checkThreatDetection(),
      this.checkRateLimiter(),
      this.checkSQLGuard()
    ]);

    const threatDetection = checks[0].status === 'fulfilled' ? checks[0].value : false;
    const rateLimiter = checks[1].status === 'fulfilled' ? checks[1].value : false;
    const sqlGuard = checks[2].status === 'fulfilled' ? checks[2].value : false;

    const healthy = threatDetection && rateLimiter && sqlGuard;

    return {
      healthy,
      components: {
        threatDetection,
        rateLimiter,
        sqlGuard,
        securityHeaders: true // Headers are always available
      },
      timestamp: Date.now()
    };
  }

  /**
   * Component health checks
   */
  private async checkThreatDetection(): Promise<boolean> {
    try {
      // Simple test request
      const testRequest = new Request('https://example.com/test');
      const result = await this.threatEngine.analyzeRequest(testRequest);
      return typeof result.score === 'number';
    } catch {
      return false;
    }
  }

  private async checkRateLimiter(): Promise<boolean> {
    try {
      const testRequest = new Request('https://example.com/test');
      const result = await this.rateLimiter.shouldLimit(testRequest);
      return typeof result.limited === 'boolean';
    } catch {
      return false;
    }
  }

  private async checkSQLGuard(): Promise<boolean> {
    try {
      const result = await this.sqlGuard.validate('SELECT 1', {
        query: 'SELECT 1',
        isParameterized: false,
        expectedType: 'select',
        maxLength: 100,
        allowedPattern: /^[\w\s]*$/,
        businessId: 'test'
      });
      return typeof result.valid === 'boolean';
    } catch {
      return false;
    }
  }
}

export interface SecurityMetrics {
  threatsBlocked: number;
  rateLimitViolations: number;
  sqlInjectionAttempts: number;
  xssAttempts: number;
  averageThreatScore: number;
  securityScore: number;
}

export interface SecurityHealthCheck {
  healthy: boolean;
  components: {
    threatDetection: boolean;
    rateLimiter: boolean;
    sqlGuard: boolean;
    securityHeaders: boolean;
  };
  timestamp: number;
}

/**
 * Create security middleware with default configuration
 */
export function createSecurityMiddleware(config?: Partial<SecurityConfig>) {
  const defaultConfig: SecurityConfig = {
    threatDetection: {
      enabled: true,
      blockThreshold: 0.9,
      challengeThreshold: 0.7
    },
    rateLimit: {
      enabled: true,
      adaptive: true
    },
    sqlInjection: {
      enabled: true,
      strictMode: true
    },
    headers: {
      enabled: true,
      reportOnly: false
    },
    monitoring: {
      enabled: true,
      logLevel: 'info'
    }
  };

  const mergedConfig = { ...defaultConfig, ...config };
  return new SecurityMiddleware(mergedConfig);
}