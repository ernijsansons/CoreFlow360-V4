import { Env } from '../types/env';

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyPrefix?: string;
  skipFailedRequests?: boolean;
  skipSuccessfulRequests?: boolean;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

export class EnterpriseRateLimiter {
  private readonly kvNamespace: KVNamespace;
  private readonly defaultConfig: RateLimitConfig = {
    windowMs: 60000, // 1 minute
    maxRequests: 100,
    keyPrefix: 'ratelimit:',
  };

  constructor(private readonly env: Env) {
    this.kvNamespace = env.KV_RATE_LIMIT || env.KV_AUTH;
  }

  async checkLimit(
    identifier: string,
    config?: Partial<RateLimitConfig>
  ): Promise<RateLimitResult> {
    const finalConfig = { ...this.defaultConfig, ...config };
    const key = `${finalConfig.keyPrefix}${identifier}`;

    // Get current window data
    const windowData = await this.getWindowData(key);
    const now = Date.now();

    // Check if we're in a new window
    if (!windowData || now - windowData.startTime > finalConfig.windowMs) {
      // Start new window
      await this.startNewWindow(key, finalConfig.windowMs);
      return {
        allowed: true,
        remaining: finalConfig.maxRequests - 1,
        resetTime: now + finalConfig.windowMs,
      };
    }

    // Check if limit exceeded
    if (windowData.count >= finalConfig.maxRequests) {
      const resetTime = windowData.startTime + finalConfig.windowMs;
      return {
        allowed: false,
        remaining: 0,
        resetTime,
        retryAfter: Math.ceil((resetTime - now) / 1000),
      };
    }

    // Increment counter
    await this.incrementCounter(key, windowData);

    return {
      allowed: true,
      remaining: finalConfig.maxRequests - windowData.count - 1,
      resetTime: windowData.startTime + finalConfig.windowMs,
    };
  }

  async resetLimit(identifier: string, config?: Partial<RateLimitConfig>): Promise<void> {
    const finalConfig = { ...this.defaultConfig, ...config };
    const key = `${finalConfig.keyPrefix}${identifier}`;
    await this.kvNamespace.delete(key);
  }

  private async getWindowData(key: string): Promise<{ startTime: number; count: number } | null> {
    const data = await this.kvNamespace.get(key);
    if (!data) return null;
    return JSON.parse(data);
  }

  private async startNewWindow(key: string, windowMs: number): Promise<void> {
    const data = {
      startTime: Date.now(),
      count: 1,
    };

    await this.kvNamespace.put(key, JSON.stringify(data), {
      expirationTtl: Math.ceil(windowMs / 1000) + 60, // Add buffer
    });
  }

  private async incrementCounter(
    key: string,
    currentData: { startTime: number; count: number }
  ): Promise<void> {
    const updatedData = {
      ...currentData,
      count: currentData.count + 1,
    };

    await this.kvNamespace.put(key, JSON.stringify(updatedData));
  }

  // Advanced rate limiting features

  async checkDistributedLimit(
    identifier: string,
    config: RateLimitConfig & { distributed: true; nodes: number }
  ): Promise<RateLimitResult> {
    // Implement distributed rate limiting across multiple nodes
    const nodeId = this.getNodeId();
    const nodeConfig = {
      ...config,
      maxRequests: Math.ceil(config.maxRequests / config.nodes),
      keyPrefix: `${config.keyPrefix}node:${nodeId}:`,
    };

    return this.checkLimit(identifier, nodeConfig);
  }

  async checkTieredLimit(
    identifier: string,
    tier: 'free' | 'basic' | 'premium' | 'enterprise'
  ): Promise<RateLimitResult> {
    const tierConfigs = {
      free: { maxRequests: 10, windowMs: 60000 },
      basic: { maxRequests: 100, windowMs: 60000 },
      premium: { maxRequests: 1000, windowMs: 60000 },
      enterprise: { maxRequests: 10000, windowMs: 60000 },
    };

    return this.checkLimit(identifier, tierConfigs[tier]);
  }

  private getNodeId(): string {
    // In Cloudflare Workers, we can use the colo or region
    // For now, return a static value
    return 'node-1';
  }

  async getUsageStats(identifier: string, config?: Partial<RateLimitConfig>): Promise<{
    currentUsage: number;
    limit: number;
    percentage: number;
    resetTime: number;
  } | null> {
    const finalConfig = { ...this.defaultConfig, ...config };
    const key = `${finalConfig.keyPrefix}${identifier}`;
    const windowData = await this.getWindowData(key);

    if (!windowData) {
      return null;
    }

    return {
      currentUsage: windowData.count,
      limit: finalConfig.maxRequests,
      percentage: (windowData.count / finalConfig.maxRequests) * 100,
      resetTime: windowData.startTime + finalConfig.windowMs,
    };
  }
}