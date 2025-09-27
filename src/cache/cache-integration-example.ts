import { createCacheService, CacheService } from './cache-service';
import { SmartCaching } from '../cloudflare/performance/SmartCaching';
import type { KVNamespace } from '@cloudflare/workers-types';

// Define a compatible interface that works with both systems
interface CacheEnv {
  CACHE: KVNamespace;
  ANALYTICS?: any;
  R2_CACHE?: any;
  ENVIRONMENT?: string;
}

/**
 * Example integration showing how to use both caching systems
 * Simple CacheService for basic needs, SmartCaching for advanced scenarios
 */

export class HybridCacheManager {
  private simpleCache: CacheService;
  private smartCache: SmartCaching;

  constructor(env: CacheEnv) {
    // Initialize both caching systems
    this.simpleCache = createCacheService(env.CACHE);
    this.smartCache = new SmartCaching(env as any); // Type assertion for compatibility
  }

  /**
   * User session data - use simple cache (fast, predictable)
   */
  async setUserSession(sessionId: string, sessionData: any): Promise<void> {
    const key = `session:${sessionId}`;
    await this.simpleCache.set(key, sessionData, 'user-data');
  }

  async getUserSession(sessionId: string): Promise<any> {
    const key = `session:${sessionId}`;
    return await this.simpleCache.get(key);
  }

  /**
   * User preferences - use simple cache (lightweight)
   */
  async setUserPreferences(userId: string, preferences: any): Promise<void> {
    const key = `prefs:${userId}`;
    await this.simpleCache.set(key, preferences, 'user-data');
  }

  async getUserPreferences(userId: string): Promise<any> {
    const key = `prefs:${userId}`;
    return await this.simpleCache.get(key);
  }

  /**
   * Analytics dashboard - use smart cache (complex, high-performance)
   */
  async setDashboardData(businessId: string, dashboardData: any): Promise<void> {
    const key = `dashboard:${businessId}`;
    await this.smartCache.set(key, dashboardData, {
      highFrequency: true,
      userSpecific: true,
      ttl: 300 // 5 minutes
    });
  }

  async getDashboardData(businessId: string): Promise<any> {
    const key = `dashboard:${businessId}`;
    const result = await this.smartCache.get(key);
    return result.hit ? result.data : null;
  }

  /**
   * Large reports - use smart cache (R2 backend for large files)
   */
  async setReport(reportId: string, reportData: any): Promise<void> {
    const key = `report:${reportId}`;
    await this.smartCache.set(key, reportData, {
      large: true,
      ttl: 86400 // 1 day
    });
  }

  async getReport(reportId: string): Promise<any> {
    const key = `report:${reportId}`;
    const result = await this.smartCache.get(key);
    return result.hit ? result.data : null;
  }

  /**
   * API responses - use smart cache (Cache API optimization)
   */
  async setApiResponse(endpoint: string, responseData: any): Promise<void> {
    const key = `api:${endpoint}`;
    await this.smartCache.set(key, responseData, {
      ttl: 1800 // 30 minutes
    });
  }

  async getApiResponse(endpoint: string): Promise<any> {
    const key = `api:${endpoint}`;
    const result = await this.smartCache.get(key);
    return result.hit ? result.data : null;
  }

  /**
   * Configuration data - use simple cache (predictable, long TTL)
   */
  async setConfig(configKey: string, configData: any): Promise<void> {
    const key = `config:${configKey}`;
    await this.simpleCache.set(key, configData, 'config');
  }

  async getConfig(configKey: string): Promise<any> {
    const key = `config:${configKey}`;
    return await this.simpleCache.get(key);
  }

  /**
   * Cache management and monitoring
   */
  async getCacheStats(): Promise<{
    simple: any;
    smart: any;
  }> {
    const [simpleStats, smartStats] = await Promise.all([
      this.simpleCache.getStats(),
      this.smartCache.getStats()
    ]);

    return {
      simple: simpleStats,
      smart: smartStats
    };
  }

  /**
   * Invalidate cached data across both systems
   */
  async invalidateUserData(userId: string): Promise<void> {
    await Promise.all([
      this.simpleCache.invalidate(`session:${userId}*`),
      this.simpleCache.invalidate(`prefs:${userId}`),
      this.smartCache.invalidate(`dashboard:*${userId}*`)
    ]);
  }

  async invalidateBusinessData(businessId: string): Promise<void> {
    await Promise.all([
      this.smartCache.invalidate(`dashboard:${businessId}`),
      this.smartCache.invalidate(`api:*${businessId}*`),
      this.smartCache.invalidate(`report:*${businessId}*`)
    ]);
  }

  /**
   * Health check for both caching systems
   */
  async healthCheck(): Promise<{
    simple: boolean;
    smart: boolean;
    overall: boolean;
  }> {
    const testKey = 'health-check';
    const testData = { timestamp: Date.now() };

    try {
      // Test simple cache
      await this.simpleCache.set(testKey, testData, 'default');
      const simpleResult = await this.simpleCache.get(testKey);
      const simpleHealthy = simpleResult !== null;

      // Test smart cache
      await this.smartCache.set(testKey, testData, { ttl: 60 });
      const smartResult = await this.smartCache.get(testKey);
      const smartHealthy = smartResult.hit;

      // Cleanup
      await Promise.all([
        this.simpleCache.invalidate(testKey),
        this.smartCache.invalidate(testKey)
      ]);

      return {
        simple: simpleHealthy,
        smart: smartHealthy,
        overall: simpleHealthy && smartHealthy
      };
    } catch (error: any) {
      console.error('Cache health check failed:', error);
      return {
        simple: false,
        smart: false,
        overall: false
      };
    }
  }
}

/**
 * Usage examples for different scenarios
 */
export class CacheUsageExamples {
  private cacheManager: HybridCacheManager;

  constructor(env: CacheEnv) {
    this.cacheManager = new HybridCacheManager(env);
  }

  /**
   * Example: User authentication flow
   */
  async handleUserLogin(userId: string, sessionData: any, preferences: any): Promise<void> {
    const sessionId = crypto.randomUUID();

    // Store session using simple cache (fast lookup needed)
    await this.cacheManager.setUserSession(sessionId, {
      userId,
      loginTime: Date.now(),
      ...sessionData
    });

    // Store preferences using simple cache (lightweight data)
    await this.cacheManager.setUserPreferences(userId, preferences);

    console.log(`User ${userId} logged in with session ${sessionId}`);
  }

  /**
   * Example: Dashboard data flow
   */
  async handleDashboardRequest(businessId: string): Promise<any> {
    // Try to get from smart cache first (optimized for complex data)
    let dashboardData = await this.cacheManager.getDashboardData(businessId);

    if (!dashboardData) {
      // Generate dashboard data (expensive operation)
      dashboardData = await this.generateDashboardData(businessId);

      // Cache using smart cache (high-frequency, user-specific)
      await this.cacheManager.setDashboardData(businessId, dashboardData);
    }

    return dashboardData;
  }

  /**
   * Example: API response caching
   */
  async handleApiRequest(endpoint: string): Promise<any> {
    // Check smart cache for API response (optimized for HTTP semantics)
    let response = await this.cacheManager.getApiResponse(endpoint);

    if (!response) {
      // Make API call (expensive operation)
      response = await this.makeApiCall(endpoint);

      // Cache using smart cache (Cache API optimization)
      await this.cacheManager.setApiResponse(endpoint, response);
    }

    return response;
  }

  /**
   * Example: Configuration management
   */
  async getApplicationConfig(configKey: string): Promise<any> {
    // Use simple cache for config (predictable, long TTL)
    let config = await this.cacheManager.getConfig(configKey);

    if (!config) {
      // Load from database or external source
      config = await this.loadConfigFromSource(configKey);

      // Cache using simple cache (long TTL, predictable)
      await this.cacheManager.setConfig(configKey, config);
    }

    return config;
  }

  // Helper methods (simulated)
  private async generateDashboardData(businessId: string): Promise<any> {
    // Simulate expensive dashboard generation
    return {
      businessId,
      metrics: { revenue: 100000, users: 500 },
      generated: Date.now()
    };
  }

  private async makeApiCall(endpoint: string): Promise<any> {
    // Simulate API call
    return {
      endpoint,
      data: { result: 'success' },
      timestamp: Date.now()
    };
  }

  private async loadConfigFromSource(configKey: string): Promise<any> {
    // Simulate config loading
    return {
      key: configKey,
      value: 'default-value',
      loaded: Date.now()
    };
  }
}

// Factory function for easy integration
export function createHybridCacheManager(env: CacheEnv): HybridCacheManager {
  return new HybridCacheManager(env);
}

export function createCacheUsageExamples(env: CacheEnv): CacheUsageExamples {
  return new CacheUsageExamples(env);
}