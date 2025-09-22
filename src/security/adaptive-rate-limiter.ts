/**
 * AI-Adaptive Rate Limiting System
 * Dynamic rate limiting based on behavior analysis and threat detection
 */

import { z } from 'zod';
import { Logger } from '../shared/logger';
import { CorrelationId } from '../shared/correlation-id';

export interface RateLimitDecision {
  limited: boolean;
  retryAfter?: number;
  message?: string;
  reason?: string;
  allowedRequests?: number;
  windowSize?: number;
}

export interface RateLimitKey {
  type: 'ip' | 'user' | 'tenant' | 'endpoint' | 'global';
  identifier: string;
  tenantId?: string;
  userId?: string;
  endpoint?: string;
  method?: string;
}

export interface RateLimitConfig {
  requests: number;
  window: number; // seconds
  burst?: number;
  adaptive?: boolean;
  escalation?: EscalationConfig;
}

export interface EscalationConfig {
  errorThreshold: number;      // Error rate to trigger escalation
  suspiciousThreshold: number; // Suspicious activity threshold
  escalationFactor: number;    // Reduce limits by this factor
  cooldownPeriod: number;      // Time before returning to normal
}

export interface UserBehavior {
  requestPattern: number[];    // Historical request rates
  errorRate: number;
  endpoints: Set<string>;
  geoLocations: Set<string>;
  userAgents: Set<string>;
  reputation: number;          // 0-1 score
  lastActivity: number;
  sessionDuration: number;
}

export interface GlobalPatterns {
  averageRequestRate: number;
  peakRequestRate: number;
  activeUsers: number;
  errorRate: number;
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface AIAnalysis {
  isLegitimateSpike: boolean;
  isMalicious: boolean;
  confidence: number;
  reason: string;
  recommendedAction: 'allow' | 'limit' | 'block';
  adjustmentFactor?: number;
}

export class AdaptiveRateLimiter {
  private logger = new Logger();
  private limits = new Map<string, RateLimitState>();
  private blacklist = new Set<string>();
  private whitelist = new Set<string>();
  private behaviorHistory = new Map<string, UserBehavior>();
  private globalPatterns: GlobalPatterns;

  constructor() {
    this.globalPatterns = {
      averageRequestRate: 10,
      peakRequestRate: 100,
      activeUsers: 1000,
      errorRate: 0.01,
      threatLevel: 'low'
    };

    this.startCleanupInterval();
    this.startPatternAnalysis();
  }

  /**
   * Main rate limiting decision
   */
  async shouldLimit(request: Request): Promise<RateLimitDecision> {
    const correlationId = CorrelationId.generate();

    try {
      // Generate rate limit keys
      const keys = await this.generateKeys(request);

      // Check blacklist first
      for (const key of keys) {
        if (this.blacklist.has(key.identifier)) {
          return {
            limited: true,
            retryAfter: 3600,
            message: 'IP address is blacklisted',
            reason: 'blacklisted'
          };
        }
      }

      // Check whitelist
      for (const key of keys) {
        if (this.whitelist.has(key.identifier)) {
          return { limited: false };
        }
      }

      // Check all rate limits
      const limitChecks = await Promise.all(
        keys.map(key => this.checkLimit(key, request))
      );

      // Find any exceeded limits
      const exceededLimits = limitChecks.filter(check => check.exceeded);

      if (exceededLimits.length === 0) {
        // No limits exceeded - update counters
        await Promise.all(keys.map(key => this.incrementCounter(key)));
        return { limited: false };
      }

      // Analyze with AI to determine if this is legitimate
      const analysis = await this.analyzeWithAI(keys, limitChecks, request);

      if (analysis.isLegitimateSpike) {
        // Temporarily increase limits
        await this.adjustLimits(keys, {
          multiplier: analysis.adjustmentFactor || 2,
          duration: 300 // 5 minutes
        });

        this.logger.info('Legitimate traffic spike detected, adjusting limits', {
          correlationId,
          keys: keys.map(k => `${k.type}:${k.identifier}`)
        });

        return { limited: false };
      }

      if (analysis.isMalicious) {
        // Add to blacklist and block
        await this.addToBlacklist(keys[0].identifier, {
          duration: 3600,
          reason: analysis.reason
        });

        this.logger.warn('Malicious activity detected, blacklisting', {
          correlationId,
          identifier: keys[0].identifier,
          reason: analysis.reason
        });

        return {
          limited: true,
          retryAfter: 3600,
          message: 'Suspicious activity detected',
          reason: analysis.reason
        };
      }

      // Standard rate limiting
      const mostRestrictive = exceededLimits.reduce((min, current) =>
        current.retryAfter < min.retryAfter ? current : min
      );

      return {
        limited: true,
        retryAfter: mostRestrictive.retryAfter,
        message: 'Rate limit exceeded',
        reason: mostRestrictive.reason,
        allowedRequests: mostRestrictive.allowedRequests,
        windowSize: mostRestrictive.windowSize
      };

    } catch (error) {
      this.logger.error('Rate limiting error', error, { correlationId });

      // Fail open - allow request but log error
      return { limited: false };
    }
  }

  /**
   * Generate rate limit keys for request
   */
  private async generateKeys(request: Request): Promise<RateLimitKey[]> {
    const url = new URL(request.url);
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => {
      headers[key] = value;
    });

    const ipAddress = headers['cf-connecting-ip'] ||
                     headers['x-forwarded-for']?.split(',')[0] ||
                     '0.0.0.0';

    const userId = headers['x-user-id'];
    const tenantId = headers['x-tenant-id'];
    const endpoint = url.pathname;
    const method = request.method;

    const keys: RateLimitKey[] = [];

    // Global rate limit
    keys.push({
      type: 'global',
      identifier: 'global'
    });

    // IP-based rate limit
    keys.push({
      type: 'ip',
      identifier: ipAddress
    });

    // User-based rate limit (if authenticated)
    if (userId) {
      keys.push({
        type: 'user',
        identifier: userId,
        tenantId
      });
    }

    // Tenant-based rate limit
    if (tenantId) {
      keys.push({
        type: 'tenant',
        identifier: tenantId,
        tenantId
      });
    }

    // Endpoint-based rate limit
    keys.push({
      type: 'endpoint',
      identifier: `${method}:${endpoint}`,
      endpoint,
      method
    });

    return keys;
  }

  /**
   * Check individual rate limit
   */
  private async checkLimit(key: RateLimitKey, request: Request): Promise<RateLimitCheck> {
    const config = this.getLimitConfig(key);
    const state = this.getOrCreateState(key);

    const now = Date.now();
    const windowStart = now - (config.window * 1000);

    // Clean old entries
    state.requests = state.requests.filter(timestamp => timestamp > windowStart);

    // Check burst limit first
    if (config.burst && state.requests.length >= config.burst) {
      return {
        exceeded: true,
        retryAfter: Math.ceil((state.requests[0] + config.window * 1000 - now) / 1000),
        reason: `Burst limit exceeded for ${key.type}`,
        allowedRequests: config.burst,
        windowSize: config.window
      };
    }

    // Check regular limit
    if (state.requests.length >= config.requests) {
      return {
        exceeded: true,
        retryAfter: Math.ceil((state.requests[0] + config.window * 1000 - now) / 1000),
        reason: `Rate limit exceeded for ${key.type}`,
        allowedRequests: config.requests,
        windowSize: config.window
      };
    }

    return {
      exceeded: false,
      retryAfter: 0,
      allowedRequests: config.requests,
      windowSize: config.window
    };
  }

  /**
   * Get rate limit configuration for key
   */
  private getLimitConfig(key: RateLimitKey): RateLimitConfig {
    const baseConfigs: Record<string, RateLimitConfig> = {
      global: {
        requests: 10000,
        window: 60,
        burst: 15000,
        adaptive: true
      },
      ip: {
        requests: 100,
        window: 60,
        burst: 150,
        adaptive: true,
        escalation: {
          errorThreshold: 0.3,
          suspiciousThreshold: 0.7,
          escalationFactor: 0.5,
          cooldownPeriod: 300
        }
      },
      user: {
        requests: 1000,
        window: 60,
        burst: 1500,
        adaptive: true
      },
      tenant: {
        requests: 5000,
        window: 60,
        burst: 7500,
        adaptive: true
      },
      endpoint: {
        requests: 50,
        window: 60,
        burst: 75,
        adaptive: false
      }
    };

    let config = baseConfigs[key.type] || baseConfigs.ip;

    // Endpoint-specific adjustments
    if (key.endpoint) {
      if (key.endpoint.includes('/api/auth/')) {
        // Stricter limits for auth endpoints
        config = {
          ...config,
          requests: 20,
          burst: 30
        };
      } else if (key.endpoint.includes('/api/export/')) {
        // More lenient for export endpoints
        config = {
          ...config,
          requests: 10,
          window: 300 // 5 minutes
        };
      } else if (key.endpoint.includes('/api/chat/')) {
        // Real-time chat needs higher limits
        config = {
          ...config,
          requests: 200,
          burst: 300
        };
      }
    }

    // Apply adaptive adjustments
    if (config.adaptive) {
      config = this.applyAdaptiveAdjustments(config, key);
    }

    return config;
  }

  /**
   * Apply adaptive adjustments based on current conditions
   */
  private applyAdaptiveAdjustments(config: RateLimitConfig, key: RateLimitKey): RateLimitConfig {
    const adjustedConfig = { ...config };

    // Adjust based on global threat level
    switch (this.globalPatterns.threatLevel) {
      case 'critical':
        adjustedConfig.requests = Math.floor(config.requests * 0.3);
        adjustedConfig.burst = Math.floor((config.burst || config.requests) * 0.3);
        break;
      case 'high':
        adjustedConfig.requests = Math.floor(config.requests * 0.5);
        adjustedConfig.burst = Math.floor((config.burst || config.requests) * 0.5);
        break;
      case 'medium':
        adjustedConfig.requests = Math.floor(config.requests * 0.8);
        adjustedConfig.burst = Math.floor((config.burst || config.requests) * 0.8);
        break;
      default:
        // No adjustment for low threat level
        break;
    }

    // Adjust based on current load
    const loadFactor = this.globalPatterns.activeUsers / 1000; // Baseline 1000 users
    if (loadFactor > 2) {
      adjustedConfig.requests = Math.floor(adjustedConfig.requests * 0.7);
      adjustedConfig.burst = Math.floor((adjustedConfig.burst || adjustedConfig.requests) * 0.7);
    }

    // Individual behavior adjustments
    if (key.type === 'ip' || key.type === 'user') {
      const behavior = this.behaviorHistory.get(key.identifier);
      if (behavior) {
        if (behavior.reputation < 0.3) {
          // Low reputation - reduce limits
          adjustedConfig.requests = Math.floor(adjustedConfig.requests * 0.5);
        } else if (behavior.reputation > 0.8) {
          // High reputation - increase limits
          adjustedConfig.requests = Math.floor(adjustedConfig.requests * 1.5);
        }
      }
    }

    return adjustedConfig;
  }

  /**
   * AI analysis of rate limiting situation
   */
  private async analyzeWithAI(
    keys: RateLimitKey[],
    limitChecks: RateLimitCheck[],
    request: Request
  ): Promise<AIAnalysis> {
    // Extract features for analysis
    const features = await this.extractAnalysisFeatures(keys, request);

    // Simple heuristic-based analysis (would be ML model in production)
    let legitimateSpike = false;
    let malicious = false;
    let confidence = 0;
    let reason = '';
    let adjustmentFactor = 1;

    // Check for legitimate traffic spikes
    if (features.isNewUser && features.reputationScore > 0.8) {
      legitimateSpike = true;
      confidence = 0.8;
      reason = 'High-reputation new user';
      adjustmentFactor = 2;
    }

    if (features.errorRate < 0.1 && features.diverseEndpoints && features.normalUserAgent) {
      legitimateSpike = true;
      confidence = 0.7;
      reason = 'Normal browsing pattern with low error rate';
      adjustmentFactor = 1.5;
    }

    // Check for malicious activity
    if (features.errorRate > 0.5 && features.highRequestRate) {
      malicious = true;
      confidence = 0.9;
      reason = 'High error rate with rapid requests (brute force)';
    }

    if (features.suspiciousUserAgent || features.knownBadIP) {
      malicious = true;
      confidence = 0.8;
      reason = 'Suspicious user agent or known bad IP';
    }

    if (features.singleEndpointFocus && features.highRequestRate) {
      malicious = true;
      confidence = 0.7;
      reason = 'Focused attack on single endpoint';
    }

    // Time-based analysis
    const hour = new Date().getHours();
    if (hour >= 2 && hour <= 6 && features.highRequestRate) {
      // Off-hours activity
      malicious = true;
      confidence = 0.6;
      reason = 'Unusual off-hours activity';
    }

    return {
      isLegitimateSpike: legitimateSpike,
      isMalicious: malicious,
      confidence,
      reason,
      recommendedAction: malicious ? 'block' : legitimateSpike ? 'allow' : 'limit',
      adjustmentFactor
    };
  }

  /**
   * Extract features for AI analysis
   */
  private async extractAnalysisFeatures(keys: RateLimitKey[], request: Request): Promise<any> {
    const url = new URL(request.url);
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => {
      headers[key] = value;
    });

    const userAgent = headers['user-agent'] || '';
    const ipKey = keys.find(k => k.type === 'ip');
    const userKey = keys.find(k => k.type === 'user');

    const behavior = userKey ? this.behaviorHistory.get(userKey.identifier) :
                     ipKey ? this.behaviorHistory.get(ipKey.identifier) : null;

    return {
      // Request characteristics
      method: request.method,
      endpoint: url.pathname,
      hasParams: url.search.length > 0,

      // User characteristics
      userAgent,
      normalUserAgent: this.isNormalUserAgent(userAgent),
      suspiciousUserAgent: this.isSuspiciousUserAgent(userAgent),

      // Behavioral characteristics
      isNewUser: !behavior,
      reputationScore: behavior?.reputation || 0.5,
      errorRate: behavior?.errorRate || 0,
      diverseEndpoints: (behavior?.endpoints.size || 1) > 5,
      singleEndpointFocus: (behavior?.endpoints.size || 10) === 1,
      highRequestRate: this.isHighRequestRate(keys),

      // Threat intelligence
      knownBadIP: await this.isKnownBadIP(ipKey?.identifier || ''),
      geoAnomaly: await this.checkGeoAnomaly(keys, headers),

      // Timing characteristics
      timeOfDay: new Date().getHours(),
      dayOfWeek: new Date().getDay()
    };
  }

  /**
   * Helper methods
   */
  private getOrCreateState(key: RateLimitKey): RateLimitState {
    const keyString = `${key.type}:${key.identifier}`;

    if (!this.limits.has(keyString)) {
      this.limits.set(keyString, {
        requests: [],
        firstRequest: Date.now(),
        lastRequest: Date.now(),
        violations: 0
      });
    }

    return this.limits.get(keyString)!;
  }

  private async incrementCounter(key: RateLimitKey): Promise<void> {
    const state = this.getOrCreateState(key);
    const now = Date.now();

    state.requests.push(now);
    state.lastRequest = now;

    // Update behavior tracking
    if (key.type === 'ip' || key.type === 'user') {
      this.updateBehaviorTracking(key, state);
    }
  }

  private updateBehaviorTracking(key: RateLimitKey, state: RateLimitState): void {
    const behavior = this.behaviorHistory.get(key.identifier) || {
      requestPattern: [],
      errorRate: 0,
      endpoints: new Set(),
      geoLocations: new Set(),
      userAgents: new Set(),
      reputation: 0.5,
      lastActivity: Date.now(),
      sessionDuration: 0
    };

    // Update patterns
    const now = Date.now();
    const minuteRequests = state.requests.filter(r => r > now - 60000).length;

    behavior.requestPattern.push(minuteRequests);
    if (behavior.requestPattern.length > 60) {
      behavior.requestPattern = behavior.requestPattern.slice(-60);
    }

    behavior.lastActivity = now;
    behavior.sessionDuration = now - (behavior.requestPattern.length > 0 ?
      behavior.requestPattern[0] : now);

    this.behaviorHistory.set(key.identifier, behavior);
  }

  private async adjustLimits(
    keys: RateLimitKey[],
    adjustment: { multiplier: number; duration: number }
  ): Promise<void> {
    // Store temporary limit adjustments
    for (const key of keys) {
      const keyString = `${key.type}:${key.identifier}:adjustment`;

      setTimeout(() => {
        this.limits.delete(keyString);
      }, adjustment.duration * 1000);
    }
  }

  private async addToBlacklist(
    identifier: string,
    options: { duration: number; reason: string }
  ): Promise<void> {
    this.blacklist.add(identifier);

    // Auto-remove after duration
    setTimeout(() => {
      this.blacklist.delete(identifier);
      this.logger.info('Removed from blacklist', { identifier });
    }, options.duration * 1000);

    this.logger.warn('Added to blacklist', {
      identifier,
      reason: options.reason,
      duration: options.duration
    });
  }

  private isNormalUserAgent(userAgent: string): boolean {
    const normalPatterns = [
      /Mozilla/,
      /Chrome/,
      /Safari/,
      /Firefox/,
      /Edge/
    ];

    return normalPatterns.some(pattern => pattern.test(userAgent));
  }

  private isSuspiciousUserAgent(userAgent: string): boolean {
    const suspiciousPatterns = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /curl/i,
      /wget/i,
      /python/i,
      /java/i,
      /postman/i
    ];

    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }

  private isHighRequestRate(keys: RateLimitKey[]): boolean {
    const ipKey = keys.find(k => k.type === 'ip');
    if (!ipKey) return false;

    const state = this.limits.get(`${ipKey.type}:${ipKey.identifier}`);
    if (!state) return false;

    const now = Date.now();
    const recentRequests = state.requests.filter(r => r > now - 60000);

    return recentRequests.length > 30; // More than 30 requests per minute
  }

  private async isKnownBadIP(ip: string): Promise<boolean> {
    // Would check threat intelligence feeds
    return false;
  }

  private async checkGeoAnomaly(keys: RateLimitKey[], headers: Record<string, string>): Promise<boolean> {
    // Would check if location is unusual for this user
    return false;
  }

  private startCleanupInterval(): void {
    setInterval(() => {
      const now = Date.now();
      const maxAge = 3600000; // 1 hour

      for (const [key, state] of this.limits.entries()) {
        if (now - state.lastRequest > maxAge) {
          this.limits.delete(key);
        }
      }
    }, 300000); // Every 5 minutes
  }

  private startPatternAnalysis(): void {
    setInterval(() => {
      this.updateGlobalPatterns();
    }, 30000); // Every 30 seconds
  }

  private updateGlobalPatterns(): void {
    // Update global patterns based on current activity
    let totalRequests = 0;
    let totalUsers = 0;
    let totalErrors = 0;

    for (const [key, state] of this.limits.entries()) {
      const recentRequests = state.requests.filter(r => r > Date.now() - 60000);
      totalRequests += recentRequests.length;

      if (key.includes('user:')) {
        totalUsers++;
      }
    }

    this.globalPatterns.averageRequestRate = totalRequests / Math.max(totalUsers, 1);
    this.globalPatterns.activeUsers = totalUsers;

    // Determine threat level
    if (this.globalPatterns.averageRequestRate > 50) {
      this.globalPatterns.threatLevel = 'critical';
    } else if (this.globalPatterns.averageRequestRate > 30) {
      this.globalPatterns.threatLevel = 'high';
    } else if (this.globalPatterns.averageRequestRate > 20) {
      this.globalPatterns.threatLevel = 'medium';
    } else {
      this.globalPatterns.threatLevel = 'low';
    }
  }
}

interface RateLimitState {
  requests: number[];
  firstRequest: number;
  lastRequest: number;
  violations: number;
}

interface RateLimitCheck {
  exceeded: boolean;
  retryAfter: number;
  reason?: string;
  allowedRequests?: number;
  windowSize?: number;
}