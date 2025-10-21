/**
 * Developer Analytics Service
 * Tracks and analyzes custom integration performance metrics
 * Provides insights for developers and marketplace administrators
 */

import { Logger } from '@/shared/logger';
import type { Env } from '@/types/env';
import type {
  IntegrationAnalytics,
  DeveloperAnalytics,
  IntegrationUsageStats,
  IntegrationPerformanceMetrics,
  MarketplaceInsights,
  DeveloperDashboard,
  AnalyticsTimeframe,
} from './developer.types';

/**
 * Analytics Service
 * Comprehensive analytics for developer platform
 */
export class AnalyticsService {
  private logger = new Logger({ component: 'AnalyticsService' });

  constructor(private env: Env) {}

  /**
   * Get Developer Dashboard Analytics
   * Overview of all developer's integrations performance
   */
  async getDeveloperDashboard(developerId: string): Promise<DeveloperDashboard> {
    try {
      // 1. Get developer summary
      const developer = await this.env.DB_MAIN.prepare(
        'SELECT * FROM developers WHERE id = ?'
      )
        .bind(developerId)
        .first() as any;

      if (!developer) {
        throw new Error('Developer not found');
      }

      // 2. Get integration count by status
      const integrationsByStatus = await this.env.DB_MAIN.prepare(
        `SELECT marketplace_status, COUNT(*) as count
         FROM custom_integrations
         WHERE developer_id = ?
         GROUP BY marketplace_status`
      )
        .bind(developerId)
        .all();

      // 3. Get total installs and active installs
      const installStats = await this.env.DB_MAIN.prepare(
        `SELECT
          COUNT(*) as total_installs,
          SUM(CASE WHEN install_status = 'active' THEN 1 ELSE 0 END) as active_installs
         FROM custom_integration_installs cii
         JOIN custom_integrations ci ON cii.custom_integration_id = ci.id
         WHERE ci.developer_id = ?`
      )
        .bind(developerId)
        .first() as any;

      // 4. Get usage stats for last 30 days
      const usageStats = await this.env.DB_MAIN.prepare(
        `SELECT
          COUNT(*) as total_requests,
          SUM(CASE WHEN response_success = 1 THEN 1 ELSE 0 END) as successful_requests,
          SUM(CASE WHEN response_success = 0 THEN 1 ELSE 0 END) as failed_requests,
          AVG(response_time_ms) as avg_response_time,
          SUM(cost_usd) as total_revenue
         FROM custom_integration_usage_logs ciul
         JOIN custom_integrations ci ON ciul.custom_integration_id = ci.id
         WHERE ci.developer_id = ? AND requested_at >= datetime('now', '-30 days')`
      )
        .bind(developerId)
        .first() as any;

      // 5. Get top integrations by usage
      const topIntegrations = await this.env.DB_MAIN.prepare(
        `SELECT
          ci.id,
          ci.integration_key,
          ci.integration_name,
          COUNT(ciil.id) as request_count,
          ci.install_count,
          ci.rating
         FROM custom_integrations ci
         LEFT JOIN custom_integration_usage_logs ciil ON ci.id = ciil.custom_integration_id
           AND ciil.requested_at >= datetime('now', '-30 days')
         WHERE ci.developer_id = ?
         GROUP BY ci.id
         ORDER BY request_count DESC
         LIMIT 5`
      )
        .bind(developerId)
        .all();

      // 6. Get quota usage
      const quotaUsage = {
        integrations: {
          used: developer.total_integrations,
          limit: developer.max_custom_integrations,
          percentage: (developer.total_integrations / developer.max_custom_integrations) * 100,
        },
        installs: {
          used: developer.total_installs,
          limit: developer.max_installs,
          percentage: (developer.total_installs / developer.max_installs) * 100,
        },
        api_calls_today: {
          used: await this.getApiCallsToday(developerId),
          limit: developer.max_api_calls_per_day,
          percentage: 0, // Will be calculated
        },
      };
      quotaUsage.api_calls_today.percentage =
        (quotaUsage.api_calls_today.used / quotaUsage.api_calls_today.limit) * 100;

      return {
        developer_tier: developer.developer_tier,
        total_integrations: developer.total_integrations,
        integrations_by_status: integrationsByStatus.results,
        total_installs: installStats?.total_installs || 0,
        active_installs: installStats?.active_installs || 0,
        total_requests_30d: usageStats?.total_requests || 0,
        successful_requests_30d: usageStats?.successful_requests || 0,
        failed_requests_30d: usageStats?.failed_requests || 0,
        avg_response_time_30d: usageStats?.avg_response_time || 0,
        total_revenue_30d: usageStats?.total_revenue || 0,
        top_integrations: topIntegrations.results,
        quota_usage: quotaUsage,
      };
    } catch (error) {
      this.logger.error('Developer dashboard error:', error);
      throw error;
    }
  }

  /**
   * Get Integration Analytics
   * Detailed analytics for specific integration
   */
  async getIntegrationAnalytics(
    integrationId: string,
    timeframe: AnalyticsTimeframe = '30d'
  ): Promise<IntegrationAnalytics> {
    try {
      const daysBack = this.timeframeToDays(timeframe);

      // 1. Get integration details
      const integration = await this.env.DB_MAIN.prepare(
        'SELECT * FROM custom_integrations WHERE id = ?'
      )
        .bind(integrationId)
        .first() as any;

      if (!integration) {
        throw new Error('Integration not found');
      }

      // 2. Get usage statistics
      const usageStats = await this.env.DB_MAIN.prepare(
        `SELECT
          COUNT(*) as total_requests,
          SUM(CASE WHEN response_success = 1 THEN 1 ELSE 0 END) as successful_requests,
          SUM(CASE WHEN response_success = 0 THEN 1 ELSE 0 END) as failed_requests,
          AVG(response_time_ms) as avg_response_time,
          MIN(response_time_ms) as min_response_time,
          MAX(response_time_ms) as max_response_time,
          COUNT(DISTINCT business_id) as unique_businesses,
          COUNT(DISTINCT user_id) as unique_users,
          SUM(cost_usd) as total_revenue
         FROM custom_integration_usage_logs
         WHERE custom_integration_id = ? AND requested_at >= datetime('now', '-${daysBack} days')`
      )
        .bind(integrationId)
        .first() as any;

      // 3. Get requests by day
      const requestsByDay = await this.env.DB_MAIN.prepare(
        `SELECT
          DATE(requested_at) as date,
          COUNT(*) as total_requests,
          SUM(CASE WHEN response_success = 1 THEN 1 ELSE 0 END) as successful,
          SUM(CASE WHEN response_success = 0 THEN 1 ELSE 0 END) as failed,
          AVG(response_time_ms) as avg_response_time
         FROM custom_integration_usage_logs
         WHERE custom_integration_id = ? AND requested_at >= datetime('now', '-${daysBack} days')
         GROUP BY DATE(requested_at)
         ORDER BY date DESC`
      )
        .bind(integrationId)
        .all();

      // 4. Get requests by action
      const requestsByAction = await this.env.DB_MAIN.prepare(
        `SELECT
          action_key,
          COUNT(*) as count,
          SUM(CASE WHEN response_success = 1 THEN 1 ELSE 0 END) as successful,
          AVG(response_time_ms) as avg_response_time
         FROM custom_integration_usage_logs
         WHERE custom_integration_id = ? AND requested_at >= datetime('now', '-${daysBack} days')
         GROUP BY action_key
         ORDER BY count DESC`
      )
        .bind(integrationId)
        .all();

      // 5. Get error breakdown
      const errorBreakdown = await this.env.DB_MAIN.prepare(
        `SELECT
          response_error,
          COUNT(*) as count
         FROM custom_integration_usage_logs
         WHERE custom_integration_id = ?
           AND response_success = 0
           AND requested_at >= datetime('now', '-${daysBack} days')
         GROUP BY response_error
         ORDER BY count DESC
         LIMIT 10`
      )
        .bind(integrationId)
        .all();

      // 6. Get install/uninstall trends
      const installTrends = await this.env.DB_MAIN.prepare(
        `SELECT
          DATE(installed_at) as date,
          COUNT(*) as installs
         FROM custom_integration_installs
         WHERE custom_integration_id = ? AND installed_at >= datetime('now', '-${daysBack} days')
         GROUP BY DATE(installed_at)
         ORDER BY date DESC`
      )
        .bind(integrationId)
        .all();

      const uninstallTrends = await this.env.DB_MAIN.prepare(
        `SELECT
          DATE(uninstalled_at) as date,
          COUNT(*) as uninstalls
         FROM custom_integration_installs
         WHERE custom_integration_id = ? AND uninstalled_at >= datetime('now', '-${daysBack} days')
         GROUP BY DATE(uninstalled_at)
         ORDER BY date DESC`
      )
        .bind(integrationId)
        .all();

      // 7. Calculate success rate
      const successRate =
        usageStats && usageStats.total_requests > 0
          ? (usageStats.successful_requests / usageStats.total_requests) * 100
          : 0;

      return {
        integration_id: integrationId,
        integration_key: integration.integration_key,
        integration_name: integration.integration_name,
        timeframe,
        total_requests: usageStats?.total_requests || 0,
        successful_requests: usageStats?.successful_requests || 0,
        failed_requests: usageStats?.failed_requests || 0,
        success_rate: successRate,
        avg_response_time: usageStats?.avg_response_time || 0,
        min_response_time: usageStats?.min_response_time || 0,
        max_response_time: usageStats?.max_response_time || 0,
        unique_businesses: usageStats?.unique_businesses || 0,
        unique_users: usageStats?.unique_users || 0,
        total_revenue: usageStats?.total_revenue || 0,
        current_installs: integration.install_count,
        active_installs: integration.active_install_count,
        rating: integration.rating,
        total_reviews: integration.total_reviews,
        requests_by_day: requestsByDay.results,
        requests_by_action: requestsByAction.results,
        error_breakdown: errorBreakdown.results,
        install_trends: installTrends.results,
        uninstall_trends: uninstallTrends.results,
      };
    } catch (error) {
      this.logger.error('Integration analytics error:', error);
      throw error;
    }
  }

  /**
   * Get Marketplace Insights
   * Admin-level marketplace analytics
   */
  async getMarketplaceInsights(timeframe: AnalyticsTimeframe = '30d'): Promise<MarketplaceInsights> {
    try {
      const daysBack = this.timeframeToDays(timeframe);

      // 1. Total published integrations
      const totalPublished = await this.env.DB_MAIN.prepare(
        `SELECT COUNT(*) as count FROM custom_integrations WHERE marketplace_status = 'published'`
      ).first() as any;

      // 2. Total active installs across marketplace
      const totalInstalls = await this.env.DB_MAIN.prepare(
        `SELECT
          COUNT(*) as total,
          SUM(CASE WHEN install_status = 'active' THEN 1 ELSE 0 END) as active
         FROM custom_integration_installs`
      ).first() as any;

      // 3. Total API requests
      const totalRequests = await this.env.DB_MAIN.prepare(
        `SELECT
          COUNT(*) as total,
          SUM(CASE WHEN response_success = 1 THEN 1 ELSE 0 END) as successful
         FROM custom_integration_usage_logs
         WHERE requested_at >= datetime('now', '-${daysBack} days')`
      ).first() as any;

      // 4. Top integrations by installs
      const topByInstalls = await this.env.DB_MAIN.prepare(
        `SELECT
          id, integration_key, integration_name, install_count, rating
         FROM custom_integrations
         WHERE marketplace_status = 'published'
         ORDER BY install_count DESC
         LIMIT 10`
      ).all();

      // 5. Top integrations by usage
      const topByUsage = await this.env.DB_MAIN.prepare(
        `SELECT
          ci.id,
          ci.integration_key,
          ci.integration_name,
          COUNT(ciil.id) as request_count
         FROM custom_integrations ci
         LEFT JOIN custom_integration_usage_logs ciil ON ci.id = ciil.custom_integration_id
           AND ciil.requested_at >= datetime('now', '-${daysBack} days')
         WHERE ci.marketplace_status = 'published'
         GROUP BY ci.id
         ORDER BY request_count DESC
         LIMIT 10`
      ).all();

      // 6. Top integrations by rating
      const topByRating = await this.env.DB_MAIN.prepare(
        `SELECT
          id, integration_key, integration_name, rating, total_reviews
         FROM custom_integrations
         WHERE marketplace_status = 'published' AND rating IS NOT NULL
         ORDER BY rating DESC, total_reviews DESC
         LIMIT 10`
      ).all();

      // 7. Category distribution
      const categoryDistribution = await this.env.DB_MAIN.prepare(
        `SELECT
          provider_category,
          COUNT(*) as count
         FROM custom_integrations
         WHERE marketplace_status = 'published'
         GROUP BY provider_category
         ORDER BY count DESC`
      ).all();

      // 8. New integrations this period
      const newIntegrations = await this.env.DB_MAIN.prepare(
        `SELECT COUNT(*) as count
         FROM custom_integrations
         WHERE published_at >= datetime('now', '-${daysBack} days')`
      ).first() as any;

      // 9. Developer statistics
      const developerStats = await this.env.DB_MAIN.prepare(
        `SELECT
          COUNT(*) as total_developers,
          SUM(CASE WHEN developer_tier = 'free' THEN 1 ELSE 0 END) as free_tier,
          SUM(CASE WHEN developer_tier = 'pro' THEN 1 ELSE 0 END) as pro_tier,
          SUM(CASE WHEN developer_tier = 'enterprise' THEN 1 ELSE 0 END) as enterprise_tier
         FROM developers
         WHERE status = 'active'`
      ).first() as any;

      // 10. Success rate across all integrations
      const successRate =
        totalRequests && totalRequests.total > 0
          ? (totalRequests.successful / totalRequests.total) * 100
          : 0;

      return {
        timeframe,
        total_published_integrations: totalPublished?.count || 0,
        total_installs: totalInstalls?.total || 0,
        active_installs: totalInstalls?.active || 0,
        total_requests: totalRequests?.total || 0,
        successful_requests: totalRequests?.successful || 0,
        success_rate: successRate,
        new_integrations: newIntegrations?.count || 0,
        total_developers: developerStats?.total_developers || 0,
        free_tier_developers: developerStats?.free_tier || 0,
        pro_tier_developers: developerStats?.pro_tier || 0,
        enterprise_tier_developers: developerStats?.enterprise_tier || 0,
        top_integrations_by_installs: topByInstalls.results,
        top_integrations_by_usage: topByUsage.results,
        top_integrations_by_rating: topByRating.results,
        category_distribution: categoryDistribution.results,
      };
    } catch (error) {
      this.logger.error('Marketplace insights error:', error);
      throw error;
    }
  }

  /**
   * Aggregate Daily Analytics
   * Run this as cron job to populate analytics table
   */
  async aggregateDailyAnalytics(): Promise<void> {
    try {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const analyticsDate = yesterday.toISOString().split('T')[0];

      // Get all published integrations
      const integrations = await this.env.DB_MAIN.prepare(
        `SELECT id FROM custom_integrations WHERE marketplace_status = 'published'`
      ).all();

      for (const integration of integrations.results) {
        const integrationId = (integration as any).id;

        // Calculate daily metrics
        const metrics = await this.env.DB_MAIN.prepare(
          `SELECT
            COUNT(*) as total_requests,
            SUM(CASE WHEN response_success = 1 THEN 1 ELSE 0 END) as successful_requests,
            SUM(CASE WHEN response_success = 0 THEN 1 ELSE 0 END) as failed_requests,
            AVG(response_time_ms) as avg_response_time,
            COUNT(DISTINCT business_id) as unique_businesses,
            COUNT(DISTINCT user_id) as unique_users,
            SUM(cost_usd) as revenue
           FROM custom_integration_usage_logs
           WHERE custom_integration_id = ? AND DATE(requested_at) = ?`
        )
          .bind(integrationId, analyticsDate)
          .first() as any;

        // Get install metrics
        const newInstalls = await this.env.DB_MAIN.prepare(
          `SELECT COUNT(*) as count FROM custom_integration_installs
           WHERE custom_integration_id = ? AND DATE(installed_at) = ?`
        )
          .bind(integrationId, analyticsDate)
          .first() as any;

        const uninstalls = await this.env.DB_MAIN.prepare(
          `SELECT COUNT(*) as count FROM custom_integration_installs
           WHERE custom_integration_id = ? AND DATE(uninstalled_at) = ?`
        )
          .bind(integrationId, analyticsDate)
          .first() as any;

        const activeInstalls = await this.env.DB_MAIN.prepare(
          `SELECT COUNT(*) as count FROM custom_integration_installs
           WHERE custom_integration_id = ? AND install_status = 'active'`
        )
          .bind(integrationId)
          .first() as any;

        // Get review metrics
        const newReviews = await this.env.DB_MAIN.prepare(
          `SELECT COUNT(*) as count, AVG(rating) as avg_rating
           FROM custom_integration_reviews
           WHERE custom_integration_id = ? AND DATE(created_at) = ?`
        )
          .bind(integrationId, analyticsDate)
          .first() as any;

        // Calculate error rate
        const errorRate =
          metrics && metrics.total_requests > 0
            ? (metrics.failed_requests / metrics.total_requests) * 100
            : 0;

        // Insert or update analytics record
        await this.env.DB_MAIN.prepare(
          `INSERT OR REPLACE INTO custom_integration_analytics (
            id, custom_integration_id, analytics_date, analytics_type,
            new_installs, uninstalls, active_installs,
            total_requests, successful_requests, failed_requests, avg_response_time_ms,
            revenue_usd, refunds_usd,
            unique_users, unique_businesses,
            new_reviews, avg_rating, error_rate,
            created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            crypto.randomUUID(),
            integrationId,
            analyticsDate,
            'daily',
            newInstalls?.count || 0,
            uninstalls?.count || 0,
            activeInstalls?.count || 0,
            metrics?.total_requests || 0,
            metrics?.successful_requests || 0,
            metrics?.failed_requests || 0,
            metrics?.avg_response_time || 0,
            metrics?.revenue || 0.0,
            0.0, // refunds (calculated separately)
            metrics?.unique_users || 0,
            metrics?.unique_businesses || 0,
            newReviews?.count || 0,
            newReviews?.avg_rating || null,
            errorRate,
            new Date().toISOString()
          )
          .run();
      }

      this.logger.info(`Aggregated analytics for ${integrations.results.length} integrations on ${analyticsDate}`);
    } catch (error) {
      this.logger.error('Daily analytics aggregation error:', error);
      throw error;
    }
  }

  /**
   * Get API Calls Today
   * For quota checking
   */
  private async getApiCallsToday(developerId: string): Promise<number> {
    const result = await this.env.DB_MAIN.prepare(
      `SELECT COUNT(*) as count
       FROM custom_integration_usage_logs ciil
       JOIN custom_integrations ci ON ciil.custom_integration_id = ci.id
       WHERE ci.developer_id = ? AND DATE(ciil.requested_at) = DATE('now')`
    )
      .bind(developerId)
      .first() as any;

    return result?.count || 0;
  }

  /**
   * Convert Timeframe to Days
   */
  private timeframeToDays(timeframe: AnalyticsTimeframe): number {
    switch (timeframe) {
      case '7d':
        return 7;
      case '30d':
        return 30;
      case '90d':
        return 90;
      default:
        return 30;
    }
  }
}
