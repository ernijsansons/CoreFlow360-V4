/**
 * Enhanced Enterprise Rate Limiting System
 * OWASP 2025 Compliant - DDoS and Abuse Prevention
 *
 * Security Features:
 * - Request fingerprinting to detect distributed attacks
 * - Multi-dimensional rate limiting (IP, User, Business, Global)
 * - Sliding window algorithm for accurate rate tracking
 * - Bypass detection and prevention
 * - Adaptive rate limiting based on threat level
 * - Automatic blocking of suspicious patterns
 */

import { Env } from '../types/env';
import crypto from 'crypto';

export interface RateLimitDimension {
  type: 'ip' | 'user' | 'business' | 'global' | 'fingerprint';
  identifier: string;
  limit: number;
  window: number; // milliseconds
}

export interface FingerprintComponents {
  ip: string;
  userAgent?: string;
  acceptLanguage?: string;
  acceptEncoding?: string;
  dnt?: string;
  connection?: string;
  secChUa?: string;
  secChUaPlatform?: string;
}

export interface RateLimitCheck {
  allowed: boolean;
  dimensions: {
    dimension: string;
    current: number;
    limit: number;
    remaining: number;
    resetTime: number;
  }[];
  blocked?: {
    reason: string;
    until: number;
    severity: 'temporary' | 'permanent';
  };
  riskScore: number;
  fingerprint: string;
}

export interface SlidingWindowData {
  requests: number[];
  blockedUntil?: number;
  suspiciousScore: number;
}

export interface ThreatIndicator {
  type: 'rapid_fire' | 'distributed' | 'credential_stuffing' | 'bot_pattern' | 'bypass_attempt';
  confidence: number;
  details: string;
}

export class EnhancedRateLimiter {
  private readonly kvNamespace: KVNamespace;
  private readonly durableObject?: DurableObjectNamespace;

  // Rate limit configurations
  private readonly configs = {
    global: { limit: 10000, window: 60000 }, // 10k requests per minute globally
    ip: { limit: 100, window: 60000 }, // 100 requests per minute per IP
    user: { limit: 300, window: 60000 }, // 300 requests per minute per user
    business: { limit: 1000, window: 60000 }, // 1000 requests per minute per business
    fingerprint: { limit: 50, window: 60000 }, // 50 requests per minute per fingerprint

    // Endpoint-specific limits
    auth: { limit: 5, window: 300000 }, // 5 auth attempts per 5 minutes
    ai: { limit: 10, window: 60000 }, // 10 AI calls per minute
    financial: { limit: 20, window: 60000 }, // 20 financial operations per minute
  };

  // Suspicious patterns
  private readonly suspiciousPatterns = {
    rapidFire: { threshold: 10, window: 1000 }, // 10 requests in 1 second
    distributed: { uniqueIps: 20, window: 10000 }, // 20 different IPs in 10 seconds
    credentialStuffing: { failedAttempts: 10, window: 60000 }, // 10 failed auth in 1 minute
    bypassAttempt: { patterns: [
      /X-Forwarded-For.*[;,]/, // Multiple forwarded IPs
      /X-Real-IP.*[;,]/, // Multiple real IPs
      /User-Agent.*bot/i, // Bot user agents
      /User-Agent.*crawler/i, // Crawler user agents
      /User-Agent.*spider/i, // Spider user agents
    ]},
  };

  constructor(env: Env) {
    this.kvNamespace = env.KV_RATE_LIMIT || env.KV_CACHE;
    this.durableObject = env.RATE_LIMITER as DurableObjectNamespace;
  }

  /**
   * Check request against multiple rate limit dimensions
   */
  async checkRequest(request: Request, context?: {
    userId?: string;
    businessId?: string;
    endpoint?: string;
  }): Promise<RateLimitCheck> {
    const startTime = Date.now();

    try {
      // Generate request fingerprint
      const fingerprint = await this.generateFingerprint(request);

      // Check for bypass attempts
      const bypassDetected = await this.detectBypassAttempt(request);
      if (bypassDetected) {
        await this.blockFingerprint(fingerprint, 'bypass_attempt', 3600000); // 1 hour block
        return {
          allowed: false,
          dimensions: [],
          blocked: {
            reason: 'Bypass attempt detected',
            until: Date.now() + 3600000,
            severity: 'temporary'
          },
          riskScore: 1.0,
          fingerprint
        };
      }

      // Check if fingerprint is blocked
      const blockStatus = await this.checkBlockStatus(fingerprint);
      if (blockStatus) {
        return {
          allowed: false,
          dimensions: [],
          blocked: blockStatus,
          riskScore: 1.0,
          fingerprint
        };
      }

      // Extract client information
      const clientInfo = this.extractClientInfo(request);

      // Build rate limit dimensions
      const dimensions: RateLimitDimension[] = [
        { type: 'global', identifier: 'global', limit: this.configs.global.limit, window: this.configs.global.window },
        { type: 'ip', identifier: clientInfo.ip, limit: this.configs.ip.limit, window: this.configs.ip.window },
        { type: 'fingerprint', identifier: fingerprint, limit: this.configs.fingerprint.limit, window: this.configs.fingerprint.window }
      ];

      if (context?.userId) {
        dimensions.push({
          type: 'user',
          identifier: context.userId,
          limit: this.configs.user.limit,
          window: this.configs.user.window
        });
      }

      if (context?.businessId) {
        dimensions.push({
          type: 'business',
          identifier: context.businessId,
          limit: this.configs.business.limit,
          window: this.configs.business.window
        });
      }

      // Add endpoint-specific limits
      if (context?.endpoint) {
        const endpointConfig = this.getEndpointConfig(context.endpoint);
        if (endpointConfig) {
          dimensions.push({
            type: 'fingerprint',
            identifier: `${fingerprint}:${context.endpoint}`,
            limit: endpointConfig.limit,
            window: endpointConfig.window
          });
        }
      }

      // Check all dimensions using sliding window
      const dimensionResults = await this.checkMultipleDimensions(dimensions);

      // Calculate risk score
      const riskScore = await this.calculateRiskScore(fingerprint, clientInfo, dimensionResults);

      // Detect threats
      const threats = await this.detectThreats(fingerprint, clientInfo, context);

      // Block if high risk
      if (riskScore > 0.8 || threats.some(t => t.confidence > 0.9)) {
        const blockDuration = this.calculateBlockDuration(riskScore, threats);
        await this.blockFingerprint(fingerprint, 'high_risk', blockDuration);

        return {
          allowed: false,
          dimensions: dimensionResults,
          blocked: {
            reason: `High risk detected: ${threats.map(t => t.type).join(', ')}`,
            until: Date.now() + blockDuration,
            severity: riskScore > 0.95 ? 'permanent' : 'temporary'
          },
          riskScore,
          fingerprint
        };
      }

      // Check if any dimension is exceeded
      const allowed = dimensionResults.every(d => d.remaining > 0);

      // Log suspicious activity
      if (!allowed || riskScore > 0.5) {
        await this.logSuspiciousActivity(fingerprint, clientInfo, context, riskScore, threats);
      }

      // Update sliding windows
      if (allowed) {
        await this.updateSlidingWindows(dimensions);
      }

      const processingTime = Date.now() - startTime;
      console.log(`Rate limit check completed in ${processingTime}ms. Risk score: ${riskScore.toFixed(2)}`);

      return {
        allowed,
        dimensions: dimensionResults,
        riskScore,
        fingerprint
      };

    } catch (error) {
      console.error('Rate limit check failed:', error);

      // Fail closed - deny on error
      return {
        allowed: false,
        dimensions: [],
        blocked: {
          reason: 'Rate limiting service error',
          until: Date.now() + 60000,
          severity: 'temporary'
        },
        riskScore: 1.0,
        fingerprint: 'error'
      };
    }
  }

  /**
   * Generate unique request fingerprint
   */
  async generateFingerprint(request: Request): Promise<string> {
    const components: FingerprintComponents = {
      ip: this.extractClientInfo(request).ip,
      userAgent: request.headers.get('user-agent') || undefined,
      acceptLanguage: request.headers.get('accept-language') || undefined,
      acceptEncoding: request.headers.get('accept-encoding') || undefined,
      dnt: request.headers.get('dnt') || undefined,
      connection: request.headers.get('connection') || undefined,
      secChUa: request.headers.get('sec-ch-ua') || undefined,
      secChUaPlatform: request.headers.get('sec-ch-ua-platform') || undefined,
    };

    // Create stable fingerprint
    const fingerprintData = Object.entries(components)
      .filter(([_, value]) => value !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}:${value}`)
      .join('|');

    // Hash the fingerprint for privacy
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprintData);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return `fp_${hashHex.substring(0, 16)}`;
  }

  /**
   * Check multiple rate limit dimensions
   */
  async checkMultipleDimensions(dimensions: RateLimitDimension[]): Promise<RateLimitCheck['dimensions']> {
    const results = await Promise.all(
      dimensions.map(async (dim) => {
        const key = `ratelimit:${dim.type}:${dim.identifier}`;
        const data = await this.getSlidingWindowData(key);
        const now = Date.now();

        // Clean old requests from sliding window
        const validRequests = data.requests.filter(t => t > now - dim.window);
        const current = validRequests.length;

        return {
          dimension: `${dim.type}:${dim.identifier}`,
          current,
          limit: dim.limit,
          remaining: Math.max(0, dim.limit - current),
          resetTime: validRequests.length > 0 ? validRequests[0] + dim.window : now + dim.window
        };
      })
    );

    return results;
  }

  /**
   * Detect bypass attempts
   */
  async detectBypassAttempt(request: Request): Promise<boolean> {
    const headers = Array.from(request.headers.entries());

    // Check for header manipulation
    const suspiciousHeaders = [
      'x-forwarded-for',
      'x-real-ip',
      'x-originating-ip',
      'cf-connecting-ip',
      'true-client-ip'
    ];

    let manipulationCount = 0;
    for (const [key, value] of headers) {
      const lowerKey = key.toLowerCase();

      // Check for multiple IPs in forwarding headers
      if (suspiciousHeaders.includes(lowerKey)) {
        if (value.includes(',') || value.includes(';')) {
          manipulationCount++;
        }

        // Check for private IPs being spoofed
        if (/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(value)) {
          manipulationCount++;
        }
      }

      // Check for bypass patterns in user agent
      if (lowerKey === 'user-agent') {
        for (const pattern of this.suspiciousPatterns.bypassAttempt.patterns) {
          if (pattern.test(value)) {
            return true;
          }
        }
      }
    }

    return manipulationCount >= 2;
  }

  /**
   * Calculate risk score based on multiple factors
   */
  async calculateRiskScore(
    fingerprint: string,
    clientInfo: { ip: string; userAgent?: string },
    dimensionResults: RateLimitCheck['dimensions']
  ): Promise<number> {
    let riskScore = 0;
    let factors = 0;

    // Check dimension usage
    for (const dim of dimensionResults) {
      const usage = dim.current / dim.limit;
      if (usage > 0.9) {
        riskScore += 0.3;
        factors++;
      } else if (usage > 0.7) {
        riskScore += 0.1;
        factors++;
      }
    }

    // Check request patterns
    const patternKey = `pattern:${fingerprint}`;
    const patternData = await this.getSlidingWindowData(patternKey);

    // Rapid fire detection
    const recentRequests = patternData.requests.filter(t => t > Date.now() - 1000);
    if (recentRequests.length > this.suspiciousPatterns.rapidFire.threshold) {
      riskScore += 0.4;
      factors++;
    }

    // Check suspicious score history
    if (patternData.suspiciousScore > 0.5) {
      riskScore += patternData.suspiciousScore * 0.3;
      factors++;
    }

    // Bot patterns in user agent
    if (clientInfo.userAgent) {
      const botPatterns = [/bot/i, /crawler/i, /spider/i, /scraper/i, /curl/i, /wget/i];
      if (botPatterns.some(p => p.test(clientInfo.userAgent))) {
        riskScore += 0.2;
        factors++;
      }
    }

    // Normalize risk score
    return factors > 0 ? Math.min(1, riskScore / factors * 2) : 0;
  }

  /**
   * Detect threat patterns
   */
  async detectThreats(
    fingerprint: string,
    clientInfo: { ip: string },
    context?: { userId?: string; endpoint?: string }
  ): Promise<ThreatIndicator[]> {
    const threats: ThreatIndicator[] = [];

    // Rapid fire detection
    const rapidKey = `rapid:${fingerprint}`;
    const rapidData = await this.getSlidingWindowData(rapidKey);
    const rapidRequests = rapidData.requests.filter(t => t > Date.now() - this.suspiciousPatterns.rapidFire.window);

    if (rapidRequests.length > this.suspiciousPatterns.rapidFire.threshold) {
      threats.push({
        type: 'rapid_fire',
        confidence: Math.min(1, rapidRequests.length / (this.suspiciousPatterns.rapidFire.threshold * 2)),
        details: `${rapidRequests.length} requests in ${this.suspiciousPatterns.rapidFire.window}ms`
      });
    }

    // Distributed attack detection
    const distributedKey = `distributed:${context?.endpoint || 'global'}`;
    const distributedData = await this.kvNamespace.get(distributedKey);

    if (distributedData) {
      const ips = JSON.parse(distributedData) as string[];
      const recentIps = ips.filter((_, i) => i < this.suspiciousPatterns.distributed.uniqueIps);

      if (recentIps.length >= this.suspiciousPatterns.distributed.uniqueIps) {
        threats.push({
          type: 'distributed',
          confidence: 0.8,
          details: `${recentIps.length} unique IPs detected`
        });
      }
    }

    // Credential stuffing detection (for auth endpoints)
    if (context?.endpoint?.includes('auth')) {
      const authKey = `auth:failed:${fingerprint}`;
      const authData = await this.getSlidingWindowData(authKey);
      const failedAttempts = authData.requests.filter(t => t > Date.now() - this.suspiciousPatterns.credentialStuffing.window);

      if (failedAttempts.length > this.suspiciousPatterns.credentialStuffing.failedAttempts) {
        threats.push({
          type: 'credential_stuffing',
          confidence: Math.min(1, failedAttempts.length / (this.suspiciousPatterns.credentialStuffing.failedAttempts * 1.5)),
          details: `${failedAttempts.length} failed authentication attempts`
        });
      }
    }

    return threats;
  }

  /**
   * Update sliding window data
   */
  async updateSlidingWindows(dimensions: RateLimitDimension[]): Promise<void> {
    const now = Date.now();

    await Promise.all(
      dimensions.map(async (dim) => {
        const key = `ratelimit:${dim.type}:${dim.identifier}`;
        const data = await this.getSlidingWindowData(key);

        // Add current request
        data.requests.push(now);

        // Clean old requests
        data.requests = data.requests.filter(t => t > now - dim.window);

        // Store updated data
        await this.kvNamespace.put(key, JSON.stringify(data), {
          expirationTtl: Math.ceil(dim.window / 1000) + 60
        });
      })
    );
  }

  /**
   * Get sliding window data
   */
  async getSlidingWindowData(key: string): Promise<SlidingWindowData> {
    const data = await this.kvNamespace.get(key);
    if (!data) {
      return {
        requests: [],
        suspiciousScore: 0
      };
    }
    return JSON.parse(data);
  }

  /**
   * Block a fingerprint
   */
  async blockFingerprint(fingerprint: string, reason: string, duration: number): Promise<void> {
    const blockKey = `block:${fingerprint}`;
    const blockData = {
      reason,
      blockedAt: Date.now(),
      blockedUntil: Date.now() + duration,
      severity: duration > 3600000 ? 'permanent' : 'temporary'
    };

    await this.kvNamespace.put(blockKey, JSON.stringify(blockData), {
      expirationTtl: Math.ceil(duration / 1000)
    });

    console.warn(`Blocked fingerprint ${fingerprint} for ${reason}. Duration: ${duration}ms`);
  }

  /**
   * Check if fingerprint is blocked
   */
  async checkBlockStatus(fingerprint: string): Promise<RateLimitCheck['blocked'] | null> {
    const blockKey = `block:${fingerprint}`;
    const blockData = await this.kvNamespace.get(blockKey);

    if (!blockData) return null;

    const block = JSON.parse(blockData);

    if (Date.now() < block.blockedUntil) {
      return {
        reason: block.reason,
        until: block.blockedUntil,
        severity: block.severity
      };
    }

    return null;
  }

  /**
   * Calculate block duration based on risk
   */
  calculateBlockDuration(riskScore: number, threats: ThreatIndicator[]): number {
    const baseDuration = 60000; // 1 minute base

    let multiplier = 1;

    if (riskScore > 0.95) {
      multiplier = 60; // 1 hour
    } else if (riskScore > 0.9) {
      multiplier = 30; // 30 minutes
    } else if (riskScore > 0.8) {
      multiplier = 10; // 10 minutes
    }

    // Increase for specific threats
    if (threats.some(t => t.type === 'credential_stuffing')) {
      multiplier *= 2;
    }

    if (threats.some(t => t.type === 'distributed')) {
      multiplier *= 3;
    }

    return baseDuration * multiplier;
  }

  /**
   * Extract client information from request
   */
  extractClientInfo(request: Request): { ip: string; userAgent?: string } {
    const ip =
      request.headers.get('CF-Connecting-IP') ||
      request.headers.get('X-Forwarded-For')?.split(',')[0].trim() ||
      request.headers.get('X-Real-IP') ||
      '0.0.0.0';

    return {
      ip,
      userAgent: request.headers.get('User-Agent') || undefined
    };
  }

  /**
   * Get endpoint-specific configuration
   */
  getEndpointConfig(endpoint: string): { limit: number; window: number } | null {
    if (endpoint.includes('auth') || endpoint.includes('login') || endpoint.includes('register')) {
      return this.configs.auth;
    }

    if (endpoint.includes('ai') || endpoint.includes('agent')) {
      return this.configs.ai;
    }

    if (endpoint.includes('finance') || endpoint.includes('payment') || endpoint.includes('invoice')) {
      return this.configs.financial;
    }

    return null;
  }

  /**
   * Log suspicious activity for analysis
   */
  async logSuspiciousActivity(
    fingerprint: string,
    clientInfo: { ip: string; userAgent?: string },
    context?: { userId?: string; businessId?: string; endpoint?: string },
    riskScore?: number,
    threats?: ThreatIndicator[]
  ): Promise<void> {
    const logKey = `suspicious:${Date.now()}:${fingerprint}`;
    const logData = {
      timestamp: new Date().toISOString(),
      fingerprint,
      clientInfo,
      context,
      riskScore,
      threats
    };

    await this.kvNamespace.put(logKey, JSON.stringify(logData), {
      expirationTtl: 7 * 24 * 60 * 60 // Keep logs for 7 days
    });
  }

  /**
   * Create rate limiting middleware
   */
  createMiddleware(endpointType?: string) {
    return async (c: any, next: any) => {
      const request = c.req.raw;
      const context = {
        userId: c.get('userId'),
        businessId: c.get('businessId'),
        endpoint: endpointType || c.req.path
      };

      const result = await this.checkRequest(request, context);

      // Add rate limit headers
      c.header('X-RateLimit-Fingerprint', result.fingerprint);
      c.header('X-RateLimit-Risk-Score', result.riskScore.toFixed(2));

      if (result.dimensions.length > 0) {
        const primary = result.dimensions[0];
        c.header('X-RateLimit-Limit', primary.limit.toString());
        c.header('X-RateLimit-Remaining', primary.remaining.toString());
        c.header('X-RateLimit-Reset', Math.ceil(primary.resetTime / 1000).toString());
      }

      if (!result.allowed) {
        if (result.blocked) {
          c.header('X-RateLimit-Block-Reason', result.blocked.reason);
          c.header('X-RateLimit-Block-Until', result.blocked.until.toString());
        }

        return c.json({
          error: 'Rate limit exceeded',
          message: result.blocked?.reason || 'Too many requests',
          fingerprint: result.fingerprint,
          riskScore: result.riskScore,
          retryAfter: result.blocked?.until ? Math.ceil((result.blocked.until - Date.now()) / 1000) : 60
        }, 429);
      }

      await next();
    };
  }
}