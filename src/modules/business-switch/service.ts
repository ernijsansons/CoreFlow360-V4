import type { Env } from '../../types/env';
import type {
  BusinessMembership,
  BusinessContext,
  SwitchResult,
  SwitchBusinessRequest,
} from './types';
import { BusinessCacheManager } from './cache';
import { PrefetchManager } from './prefetch';
import { switchPerformanceTracker } from './performance';
import { JWTService } from '../auth/jwt';
import { SessionManager } from '../auth/session';
import { AuthorizationError } from '../../shared/error-handler';

export // TODO: Consider splitting BusinessSwitchService into smaller, focused classes
class BusinessSwitchService {
  private db: D1Database;
  private kv: KVNamespace;
  private cache: BusinessCacheManager;
  private prefetch: PrefetchManager;
  private jwtService: JWTService;
  private sessionManager: SessionManager;

  constructor(env: Env) {
    // Validate required environment variables
    if (!env.JWT_SECRET) {
      throw new AuthorizationError('JWT_SECRET environment variable is required');
    }

    this.db = env.DB_MAIN;
    this.kv = env.KV_CACHE;
    this.cache = new BusinessCacheManager(this.kv);
    this.prefetch = new PrefetchManager(this.db);
    this.jwtService = new JWTService(env.JWT_SECRET);
    this.sessionManager = new SessionManager(env.KV_SESSION, this.jwtService);
  }

  /**
   * Get list of user's businesses
   */
  async getUserBusinesses(
    userId: string,
    forceRefresh = false
  ): Promise<{
    businesses: BusinessMembership[];
    fromCache: boolean;
    fetchTimeMs: number;
  }> {
    const timer = switchPerformanceTracker.trackSwitch(userId, '', '');
    const endCacheRead = timer.recordStep('cache_read');

    // Try cache first
    const cached = await this.cache.getCachedMemberships(userId, forceRefresh);
    endCacheRead();

    if (cached.cacheHit && cached.data) {
      timer.complete();
      return {
        businesses: cached.data,
        fromCache: true,
        fetchTimeMs: cached.readTimeMs,
      };
    }

    // Fetch from database
    const endDbQuery = timer.recordStep('db_query');
    const businesses = await this.fetchUserBusinesses(userId);
    endDbQuery();

    // Cache the results
    const endCacheWrite = timer.recordStep('cache_write');
    await this.cache.cacheMemberships(userId, businesses);
    endCacheWrite();

    timer.complete();

    return {
      businesses,
      fromCache: false,
      fetchTimeMs: cached.readTimeMs,
    };
  }

  /**
   * Switch to a different business
   */
  async switchBusiness(
    userId: string,
    currentSessionId: string,
    request: SwitchBusinessRequest,
    ipAddress: string,
    userAgent: string
  ): Promise<SwitchResult> {
    const tracker = switchPerformanceTracker.trackSwitch(
      userId,
      '', // Will be set after getting current business
      request.targetBusinessId
    );

    const metrics = {
      dbQueryMs: 0,
      cacheReadMs: 0,
      cacheWriteMs: 0,
      tokenGenerationMs: 0,
      prefetchMs: 0,
      totalMs: 0,
    };

    const totalStartTime = performance.now();

    try {
      // Step 1: Verify user has access to target business
      const endAccessCheck = tracker.recordStep('access_check');
      const membership = await this.verifyBusinessAccess(userId, request.targetBusinessId);
      endAccessCheck();
      metrics.dbQueryMs += performance.now() - totalStartTime;

      if (!membership) {
        throw new AuthorizationError('You do not have access to this business');
      }

      // Step 2: Check cache for business context
      const endCacheCheck = tracker.recordStep('cache_check');
      const cachedContext = await this.cache.getCachedContext(
        request.targetBusinessId,
        userId
      );
      metrics.cacheReadMs = cachedContext.readTimeMs;
      endCacheCheck();

      let businessContext: BusinessContext;
      let cacheHit = false;

      if (cachedContext.cacheHit && cachedContext.data) {
        businessContext = cachedContext.data;
        cacheHit = true;
      } else {
        // Step 3: Prefetch business context
        const endPrefetch = tracker.recordStep('prefetch');
        const prefetchResult = await this.prefetch.prefetchBusinessContext(
          request.targetBusinessId,
          userId,
          membership.role
        );
        businessContext = prefetchResult.context;
        metrics.prefetchMs = prefetchResult.prefetchTimeMs;
        endPrefetch();

        // Cache the context
        const endCacheWrite = tracker.recordStep('cache_write');
        const cacheWriteTime = await this.cache.cacheContext(
          request.targetBusinessId,
          userId,
          businessContext
        );
        metrics.cacheWriteMs = cacheWriteTime;
        endCacheWrite();
      }

      // Step 4: Generate new tokens with updated business context
      const endTokenGen = tracker.recordStep('token_generation');
      const tokenStartTime = performance.now();

      const tokens = await this.jwtService.generateTokenPair({
        sub: userId,
        email: membership.email,
        businessId: request.targetBusinessId,
        businessName: businessContext.businessName,
        role: membership.role as any,
        permissions: businessContext.permissions,
        sessionId: currentSessionId,
        ipAddress,
      });

      metrics.tokenGenerationMs = performance.now() - tokenStartTime;
      endTokenGen();

      // Step 5: Update session with new business context
      const endSessionUpdate = tracker.recordStep('session_update');
      const session = await this.sessionManager.getSession(currentSessionId);

      if (session) {
        session.businessId = request.targetBusinessId;
        session.role = membership.role;
        session.permissions = businessContext.permissions;
        session.accessToken = tokens.accessToken;
        session.refreshToken = tokens.refreshToken;
        session.accessTokenExp = tokens.accessTokenExp;
        session.refreshTokenExp = tokens.refreshTokenExp;
        session.lastActivityAt = Date.now();

        // Save updated session
        await this.sessionManager['saveSession'](session);
      }
      endSessionUpdate();

      // Step 6: Log the switch
      const endAuditLog = tracker.recordStep('audit_log');
      await this.logBusinessSwitch(userId, '', request.targetBusinessId, ipAddress);
      endAuditLog();

      // Step 7: Update last accessed timestamp
      this.updateLastAccessed(userId, request.targetBusinessId).catch(console.error);

      metrics.totalMs = performance.now() - totalStartTime;
      tracker.complete();

      // Log performance if over target
      if (metrics.totalMs > 100) {
      }

      return {
        success: true,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        businessContext,
        switchTimeMs: metrics.totalMs,
        cacheHit,
        metrics,
      };
    } catch (error) {
      tracker.complete();
      throw error;
    }
  }

  /**
   * Clear client state for previous business
   */
  generateClientStateClear(previousBusinessId: string): Record<string, any> {
    return {
      clearCache: [
        `business:${previousBusinessId}:*`,
        `user:${previousBusinessId}:*`,
        `settings:${previousBusinessId}:*`,
      ],
      clearStorage: [
        'currentDepartment',
        'currentProject',
        'dashboardLayout',
        'recentSearches',
      ],
      resetState: [
        'notifications',
        'pendingChanges',
        'unsavedWork',
      ],
    };
  }

  /**
   * Prefetch next likely business (for predictive loading)
   */
  async prefetchLikelyBusinesses(userId: string): Promise<void> {
    // Get recently accessed businesses
    const recentBusinesses = await this.db
      .prepare(`
        SELECT DISTINCT bm.business_id
        FROM business_memberships bm
        JOIN audit_logs al ON al.business_id = bm.business_id
        WHERE bm.user_id = ? AND al.user_id = ?
          AND al.event_name = 'business_switch'
          AND al.created_at > datetime('now', '-30 days')
        ORDER BY al.created_at DESC
        LIMIT 3
      `)
      .bind(userId, userId)
      .all();

    if (recentBusinesses.results && recentBusinesses.results.length > 0) {
      const businessIds = recentBusinesses.results.map((r: any) => r.business_id);
      const contexts = await this.prefetch.batchPrefetch(businessIds, userId);

      // Cache the prefetched contexts
      for (const [businessId, context] of contexts) {
        await this.cache.cacheContext(businessId, userId, context, 300); // 5 min TTL
      }
    }
  }

  /**
   * Fetch user's businesses from database
   */
  private async fetchUserBusinesses(userId: string): Promise<BusinessMembership[]> {
    const results = await this.db
      .prepare(`
        SELECT
          bm.business_id,
          bm.role,
          bm.is_primary,
          bm.joined_at,
          bm.status as membership_status,
          b.name as business_name,
          b.subscription_tier,
          b.subscription_status,
          b.subscription_expires_at,
          (SELECT COUNT(*)
  FROM business_memberships WHERE business_id = bm.business_id AND status = 'active') as user_count
        FROM business_memberships bm
        JOIN businesses b ON b.id = bm.business_id
        WHERE bm.user_id = ? AND bm.status = 'active' AND b.status = 'active'
        ORDER BY bm.is_primary DESC, b.name ASC
      `)
      .bind(userId)
      .all();

    return (results.results || []).map((row: any) => ({
      businessId: row.business_id,
      businessName: row.business_name,
      role: row.role,
      permissions: [], // Would be fetched separately
      isPrimary: Boolean(row.is_primary),
      isActive: row.membership_status === 'active',
      joinedAt: row.joined_at,
      subscription: {
        tier: row.subscription_tier,
        status: row.subscription_status,
        expiresAt: row.subscription_expires_at,
      },
      stats: {
        userCount: row.user_count,
        activeModules: [],
        storageUsed: 0,
      },
    }));
  }

  /**
   * Verify user has access to business
   */
  private async verifyBusinessAccess(
    userId: string,
    businessId: string
  ): Promise<any> {
    const result = await this.db
      .prepare(`
        SELECT
          bm.*,
          u.email
        FROM business_memberships bm
        JOIN users u ON u.id = bm.user_id
        WHERE bm.user_id = ? AND bm.business_id = ? AND bm.status = 'active'
      `)
      .bind(userId, businessId)
      .first();

    return result;
  }

  /**
   * Update last accessed timestamp
   */
  private async updateLastAccessed(userId: string, businessId: string): Promise<void> {
    await this.db
      .prepare(`
        UPDATE business_memberships
        SET updated_at = datetime('now')
        WHERE user_id = ? AND business_id = ?
      `)
      .bind(userId, businessId)
      .run();
  }

  /**
   * Log business switch event
   */
  private async logBusinessSwitch(
    userId: string,
    fromBusinessId: string,
    toBusinessId: string,
    ipAddress: string
  ): Promise<void> {
    await this.db
      .prepare(`
        INSERT INTO audit_logs (
          id, business_id, user_id, event_type, event_name,
          resource_type, resource_id, old_values, new_values,
          ip_address, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `)
      .bind(
        crypto.randomUUID(),
        toBusinessId,
        userId,
        'update',
        'business_switch',
        'business',
        toBusinessId,
        JSON.stringify({ previousBusinessId: fromBusinessId }),
        JSON.stringify({ currentBusinessId: toBusinessId }),
        ipAddress,
        'success'
      )
      .run();
  }

  /**
   * Get switch statistics
   */
  async getSwitchStatistics(userId: string): Promise<any> {
    const stats = await this.db
      .prepare(`
        SELECT
          COUNT(*) as total_switches,
          COUNT(DISTINCT resource_id) as unique_businesses,
          AVG(compute_time_ms) as avg_switch_time
        FROM audit_logs
        WHERE user_id = ? AND event_name = 'business_switch'
          AND created_at > datetime('now', '-30 days')
      `)
      .bind(userId)
      .first();

    return {
      ...stats,
      performanceMetrics: switchPerformanceTracker.getStatistics(),
    };
  }
}