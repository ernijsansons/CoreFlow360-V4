import type { BusinessContext } from './types';

/**
 * Prefetch manager for business context data
 */
export class PrefetchManager {
  private db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  /**
   * Prefetch essential business context data in parallel
   */
  async prefetchBusinessContext(
    businessId: string,
    userId: string,
    role: string
  ): Promise<{ context: BusinessContext; prefetchTimeMs: number }> {
    const startTime = performance.now();

    // Execute all queries in parallel for maximum speed
    const [
      businessData,
      userProfile,
      departments,
      settings,
      permissions,
      modules,
    ] = await Promise.all([
      this.fetchBusinessData(businessId),
      this.fetchUserProfile(businessId, userId),
      this.fetchDepartments(businessId),
      this.fetchBusinessSettings(businessId),
      this.fetchUserPermissions(businessId, userId),
      this.fetchActiveModules(businessId),
    ]);

    const context: BusinessContext = {
      businessId,
      businessName: businessData.name,
      role,
      permissions,
      settings,
      theme: businessData.theme,
      modules,
      departments,
      userProfile,
    };

    return {
      context,
      prefetchTimeMs: performance.now() - startTime,
    };
  }

  /**
   * Fetch core business data
   */
  private async fetchBusinessData(businessId: string): Promise<any> {
    const result = await this.db
      .prepare(`
        SELECT name, settings, metadata
        FROM businesses
        WHERE id = ? AND status = 'active'
      `)
      .bind(businessId)
      .first();

    return {
      name: result?.name || '',
      theme: this.parseJSON(result?.metadata)?.theme || {},
      settings: this.parseJSON(result?.settings) || {},
    };
  }

  /**
   * Fetch user profile within business
   */
  private async fetchUserProfile(
    businessId: string,
    userId: string
  ): Promise<any> {
    const result = await this.db
      .prepare(`
        SELECT
          employee_id,
          job_title,
          department,
          reports_to_user_id,
          can_approve_transactions,
          spending_limit
        FROM business_memberships
        WHERE business_id = ? AND user_id = ? AND status = 'active'
      `)
      .bind(businessId, userId)
      .first();

    return {
      employeeId: result?.employee_id,
      jobTitle: result?.job_title,
      department: result?.department,
      reportsTo: result?.reports_to_user_id,
      canApproveTransactions: Boolean(result?.can_approve_transactions),
      spendingLimit: result?.spending_limit || 0,
    };
  }

  /**
   * Fetch departments for quick access
   */
  private async fetchDepartments(businessId: string): Promise<any[]> {
    const results = await this.db
      .prepare(`
        SELECT id, name, code
        FROM departments
        WHERE business_id = ? AND status = 'active'
        ORDER BY name
        LIMIT 50
      `)
      .bind(businessId)
      .all();

    return results.results || [];
  }

  /**
   * Fetch business settings
   */
  private async fetchBusinessSettings(businessId: string): Promise<any> {
    const result = await this.db
      .prepare(`
        SELECT settings
        FROM businesses
        WHERE id = ?
      `)
      .bind(businessId)
      .first();

    return this.parseJSON(result?.settings) || {};
  }

  /**
   * Fetch user permissions
   */
  private async fetchUserPermissions(
    businessId: string,
    userId: string
  ): Promise<string[]> {
    const results = await this.db
      .prepare(`
        SELECT permission_key
        FROM user_permissions
        WHERE business_id = ? AND user_id = ? AND status = 'active'
        LIMIT 500
      `)
      .bind(businessId, userId)
      .all();

    return results.results?.map((r: any) => r.permission_key) || [];
  }

  /**
   * Fetch active modules
   */
  private async fetchActiveModules(businessId: string): Promise<string[]> {
    // This would normally query a modules table
    // For now, return default modules based on subscription
    const result = await this.db
      .prepare(`
        SELECT subscription_tier
        FROM businesses
        WHERE id = ?
      `)
      .bind(businessId)
      .first();

    const tier = result?.subscription_tier || 'trial';

    const modulesByTier: Record<string, string[]> = {
      trial: ['dashboard', 'contacts', 'invoices'],
      starter: ['dashboard', 'contacts', 'invoices', 'expenses', 'reports'],
      professional: [
        'dashboard',
        'contacts',
        'invoices',
        'expenses',
        'reports',
        'inventory',
        'projects',
        'hr',
      ],
      enterprise: [
        'dashboard',
        'contacts',
        'invoices',
        'expenses',
        'reports',
        'inventory',
        'projects',
        'hr',
        'manufacturing',
        'ai',
        'automation',
      ],
    };

    return modulesByTier[tier] || modulesByTier.trial;
  }

  /**
   * Prefetch critical data for UI rendering
   */
  async prefetchUIData(businessId: string): Promise<{
    notifications: any[];
    recentActivity: any[];
    quickStats: any;
    prefetchTimeMs: number;
  }> {
    const startTime = performance.now();

    const [notifications, recentActivity, quickStats] = await Promise.all([
      this.fetchNotifications(businessId),
      this.fetchRecentActivity(businessId),
      this.fetchQuickStats(businessId),
    ]);

    return {
      notifications,
      recentActivity,
      quickStats,
      prefetchTimeMs: performance.now() - startTime,
    };
  }

  /**
   * Fetch recent notifications
   */
  private async fetchNotifications(businessId: string): Promise<any[]> {
    // Placeholder - would query notifications table
    return [];
  }

  /**
   * Fetch recent activity
   */
  private async fetchRecentActivity(businessId: string): Promise<any[]> {
    const results = await this.db
      .prepare(`
        SELECT
          event_name,
          resource_type,
          created_at
        FROM audit_logs
        WHERE business_id = ? AND status = 'success'
        ORDER BY created_at DESC
        LIMIT 10
      `)
      .bind(businessId)
      .all();

    return results.results || [];
  }

  /**
   * Fetch quick stats for dashboard
   */
  private async fetchQuickStats(businessId: string): Promise<any> {
    // Execute multiple count queries in parallel
    const [userCount, documentCount, activeWorkflows] = await Promise.all([
      this.db
        .prepare(
          `SELECT COUNT(*) as count FROM business_memberships WHERE business_id = ? AND status = 'active'`
        )
        .bind(businessId)
        .first(),
      this.db
        .prepare(
          `SELECT COUNT(*) as count FROM journal_entries WHERE business_id = ? AND status = 'posted'`
        )
        .bind(businessId)
        .first(),
      this.db
        .prepare(
          `SELECT COUNT(*) as count FROM workflow_instances WHERE business_id = ? AND status = 'active'`
        )
        .bind(businessId)
        .first(),
    ]);

    return {
      userCount: userCount?.count || 0,
      documentCount: documentCount?.count || 0,
      activeWorkflows: activeWorkflows?.count || 0,
    };
  }

  /**
   * Batch prefetch for multiple businesses
   */
  async batchPrefetch(
    businessIds: string[],
    userId: string
  ): Promise<Map<string, BusinessContext>> {
    const contexts = new Map<string, BusinessContext>();

    // Limit concurrent prefetches to avoid overwhelming the database
    const batchSize = 3;
    for (let i = 0; i < businessIds.length; i += batchSize) {
      const batch = businessIds.slice(i, i + batchSize);
      const promises = batch.map(async (businessId) => {
        try {
          const { context } = await this.prefetchBusinessContext(
            businessId,
            userId,
            'employee' // Default role, would be fetched from membership
          );
          contexts.set(businessId, context);
        } catch (error) {
          console.error(`Failed to prefetch business ${businessId}:`, error);
        }
      });

      await Promise.all(promises);
    }

    return contexts;
  }

  /**
   * Parse JSON safely
   */
  private parseJSON(str: any): any {
    if (!str) return null;
    if (typeof str === 'object') return str;

    try {
      return JSON.parse(str);
    } catch {
      return null;
    }
  }
}