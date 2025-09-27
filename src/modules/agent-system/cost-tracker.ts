/**
 * Cost Tracking & Governance System
 * Tracks costs across all agents with limits and analytics
 */

import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import {
  CostMetrics,
  CostBreakdown,
  CostLimits,
  ValidationError
} from './types';
import { Logger } from '../../shared/logger';
import { CorrelationId } from '../../shared/security-utils';
import {
  sanitizeBusinessId,
  sanitizeUserId,
  sanitizeSqlParam,
  sanitizeForLogging,
  checkRateLimit
} from './security-utils';

export class CostTracker {
  private logger: Logger;
  private kv: KVNamespace;
  private db: D1Database;
  private defaultLimits: CostLimits;
  private rateLimitStorage: Map<string, { count: number; resetTime: number }> = new Map();

  constructor(kv: KVNamespace, db: D1Database, defaultLimits?: CostLimits) {
    this.logger = new Logger();
    this.kv = kv;
    this.db = db;
    this.defaultLimits = defaultLimits || {
      daily: 100,
      monthly: 2000,
      perTask: 10,
      perAgent: 500,
      currency: 'USD',
    };
  }

  /**
   * Track cost metrics for a task execution
   */
  async track(metrics: CostMetrics): Promise<void> {
    const trackingId = CorrelationId.generate();

    try {
      // Validate and sanitize inputs
      const safeBusinessId = sanitizeBusinessId(metrics.businessId);
      const safeUserId = sanitizeUserId(metrics.userId);
      const safeAgentId = sanitizeSqlParam(metrics.agentId) as string;
      const safeTaskId = sanitizeSqlParam(metrics.taskId) as string;

      // Check rate limit
      const rateLimitAllowed = await checkRateLimit(
        `cost_tracking:${safeBusinessId}`,
        1000,
        60000,
        this.rateLimitStorage
      );
      if (!rateLimitAllowed) {
        this.logger.warn('Cost tracking rate limit exceeded', sanitizeForLogging({
          businessId: safeBusinessId
        }) as Record<string, unknown>);
        return;
      }

      // Create safe metrics object
      const safeMetrics: CostMetrics = {
        ...metrics,
        businessId: safeBusinessId,
        userId: safeUserId,
        agentId: safeAgentId,
        taskId: safeTaskId
      };
      // Update real-time tracking in KV
      await this.updateRealTimeTracking(safeMetrics);

      // Persist to D1 for analytics
      await this.persistToDatabase(safeMetrics, trackingId);

      // Check and alert on limits
      await this.checkLimitsAndAlert(safeMetrics);

      this.logger.debug('Cost metrics tracked', sanitizeForLogging({
        trackingId,
        businessId: safeBusinessId,
        agentId: safeAgentId,
        cost: metrics.cost,
        capability: metrics.capability,
      }) as Record<string, unknown>);

    } catch (error: any) {
      this.logger.error('Failed to track cost metrics', error, sanitizeForLogging({
        trackingId,
        businessId: metrics.businessId,
        taskId: metrics.taskId,
      }) as Record<string, unknown>);
    }
  }

  /**
   * Check if a business is within cost limits
   */
  async checkLimits(businessId: string, additionalCost: number): Promise<{
    withinLimits: boolean;
    reason?: string;
    current: { daily: number; monthly: number };
    limits: { daily: number; monthly: number };
  }> {
    try {
      // Validate business ID
      const safeBusinessId = sanitizeBusinessId(businessId);

      // Validate additional cost
      if (typeof additionalCost !== 'number' || additionalCost < 0 || !isFinite(additionalCost)) {
        throw new ValidationError('Invalid cost amount');
      }
      const [dailyCost, monthlyCost, limits] = await Promise.all([
        this.getDailyCost(safeBusinessId),
        this.getMonthlyCost(safeBusinessId),
        this.getBusinessLimits(safeBusinessId),
      ]);

      const newDaily = dailyCost + additionalCost;
      const newMonthly = monthlyCost + additionalCost;

      if (newDaily > limits.daily) {
        return {
          withinLimits: false,
          reason: `Daily limit exceeded: $${newDaily.toFixed(2)} > $${limits.daily}`,
          current: { daily: dailyCost, monthly: monthlyCost },
          limits: { daily: limits.daily, monthly: limits.monthly },
        };
      }

      if (newMonthly > limits.monthly) {
        return {
          withinLimits: false,
          reason: `Monthly limit exceeded: $${newMonthly.toFixed(2)} > $${limits.monthly}`,
          current: { daily: dailyCost, monthly: monthlyCost },
          limits: { daily: limits.daily, monthly: limits.monthly },
        };
      }

      return {
        withinLimits: true,
        current: { daily: dailyCost, monthly: monthlyCost },
        limits: { daily: limits.daily, monthly: limits.monthly },
      };

    } catch (error: any) {
      this.logger.error('Failed to check cost limits', error, { businessId });
      return {
        withinLimits: true, // Allow on error to prevent blocking
        current: { daily: 0, monthly: 0 },
        limits: { daily: this.defaultLimits.daily, monthly: this.defaultLimits.monthly },
      };
    }
  }

  /**
   * Get daily cost for a business
   */
  async getDailyCost(businessId: string): Promise<number> {
    const today = new Date().toISOString().slice(0, 10);
    const key = `cost:daily:${businessId}:${today}`;

    try {
      const cached = await this.kv.get(key);
      return cached ? parseFloat(cached) : 0;
    } catch (error: any) {
      this.logger.error('Failed to get daily cost', error, { businessId });
      return 0;
    }
  }

  /**
   * Get monthly cost for a business
   */
  async getMonthlyCost(businessId: string): Promise<number> {
    const currentMonth = new Date().toISOString().slice(0, 7);
    const key = `cost:monthly:${businessId}:${currentMonth}`;

    try {
      const cached = await this.kv.get(key);
      return cached ? parseFloat(cached) : 0;
    } catch (error: any) {
      this.logger.error('Failed to get monthly cost', error, { businessId });
      return 0;
    }
  }

  /**
   * Get cost breakdown for a business
   */
  async getCostBreakdown(businessId: string, period: 'daily' | 'monthly' = 'daily'): Promise<{
    total: number;
    byAgent: Record<string, number>;
    byCapability: Record<string, number>;
    byDepartment: Record<string, number>;
    successful: number;
    failed: number;
  }> {
    try {
      const timeRange = this.getTimeRange(period);

      const result = await this.db.prepare(`
        SELECT
          agent_id,
          capability,
          department,
          success,
          SUM(cost) as total_cost,
          COUNT(*) as task_count
        FROM agent_costs
        WHERE business_id = ? AND timestamp >= ? AND timestamp <= ?
        GROUP BY agent_id, capability, department, success
      `).bind(businessId, timeRange.start, timeRange.end).all();

      const breakdown = {
        total: 0,
        byAgent: {} as Record<string, number>,
        byCapability: {} as Record<string, number>,
        byDepartment: {} as Record<string, number>,
        successful: 0,
        failed: 0,
      };

      for (const row of result.results || []) {
        const cost = row.total_cost as number;
        const agentId = row.agent_id as string;
        const capability = row.capability as string;
        const department = (row.department as string) || 'unknown';
        const success = row.success as boolean;

        breakdown.total += cost;

        breakdown.byAgent[agentId] = (breakdown.byAgent[agentId] || 0) + cost;
        breakdown.byCapability[capability] = (breakdown.byCapability[capability] || 0) + cost;
        breakdown.byDepartment[department] = (breakdown.byDepartment[department] || 0) + cost;

        if (success) {
          breakdown.successful += cost;
        } else {
          breakdown.failed += cost;
        }
      }

      return breakdown;

    } catch (error: any) {
      this.logger.error('Failed to get cost breakdown', error, { businessId, period });
      return {
        total: 0,
        byAgent: {},
        byCapability: {},
        byDepartment: {},
        successful: 0,
        failed: 0,
      };
    }
  }

  /**
   * Get cost analytics for a business
   */
  async getCostAnalytics(businessId: string, days: number = 30): Promise<{
    trends: Array<{ date: string; cost: number; tasks: number }>;
    topAgents: Array<{ agentId: string; cost: number; tasks: number }>;
    topCapabilities: Array<{ capability: string; cost: number; tasks: number }>;
    efficiency: {
      costPerTask: number;
      successRate: number;
      avgLatency: number;
    };
    forecasts: {
      dailyForecast: number;
      monthlyForecast: number;
      confidenceLevel: number;
    };
  }> {
    try {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      // Get daily trends
      const trendsResult = await this.db.prepare(`
        SELECT
          DATE(timestamp / 1000, 'unixepoch') as date,
          SUM(cost) as total_cost,
          COUNT(*) as task_count,
          AVG(latency) as avg_latency,
          AVG(CASE WHEN success = 1 THEN 1.0 ELSE 0.0 END) as success_rate
        FROM agent_costs
        WHERE business_id = ? AND timestamp >= ?
        GROUP BY DATE(timestamp / 1000, 'unixepoch')
        ORDER BY date DESC
      `).bind(businessId, startDate.getTime()).all();

      // Get top agents
      const agentsResult = await this.db.prepare(`
        SELECT
          agent_id,
          SUM(cost) as total_cost,
          COUNT(*) as task_count
        FROM agent_costs
        WHERE business_id = ? AND timestamp >= ?
        GROUP BY agent_id
        ORDER BY total_cost DESC
        LIMIT 10
      `).bind(businessId, startDate.getTime()).all();

      // Get top capabilities
      const capabilitiesResult = await this.db.prepare(`
        SELECT
          capability,
          SUM(cost) as total_cost,
          COUNT(*) as task_count
        FROM agent_costs
        WHERE business_id = ? AND timestamp >= ?
        GROUP BY capability
        ORDER BY total_cost DESC
        LIMIT 10
      `).bind(businessId, startDate.getTime()).all();

      // Calculate trends
      const trends = (trendsResult.results || []).map((row: any) => ({
        date: row.date,
        cost: row.total_cost || 0,
        tasks: row.task_count || 0,
      }));

      // Calculate efficiency metrics
      const totalCost = trends.reduce((sum, t) => sum + t.cost, 0);
      const totalTasks = trends.reduce((sum, t) => sum + t.tasks, 0);
      const costPerTask = totalTasks > 0 ? totalCost / totalTasks : 0;

      const successRate = trendsResult.results?.length > 0
        ? (trendsResult.results[0] as any).success_rate || 0
        : 0;

      const avgLatency = trendsResult.results?.length > 0
        ? (trendsResult.results[0] as any).avg_latency || 0
        : 0;

      // Simple forecast based on recent trends
      const recentTrends = trends.slice(0, 7); // Last 7 days
      const avgDailyCost = recentTrends.length > 0
        ? recentTrends.reduce((sum, t) => sum + t.cost, 0) / recentTrends.length
        : 0;

      return {
        trends,
        topAgents: (agentsResult.results || []).map((row: any) => ({
          agentId: row.agent_id,
          cost: row.total_cost || 0,
          tasks: row.task_count || 0,
        })),
        topCapabilities: (capabilitiesResult.results || []).map((row: any) => ({
          capability: row.capability,
          cost: row.total_cost || 0,
          tasks: row.task_count || 0,
        })),
        efficiency: {
          costPerTask,
          successRate,
          avgLatency,
        },
        forecasts: {
          dailyForecast: avgDailyCost,
          monthlyForecast: avgDailyCost * 30,
          confidenceLevel: recentTrends.length >= 7 ? 0.8 : 0.5,
        },
      };

    } catch (error: any) {
      this.logger.error('Failed to get cost analytics', error, { businessId, days });
      return {
        trends: [],
        topAgents: [],
        topCapabilities: [],
        efficiency: { costPerTask: 0, successRate: 0, avgLatency: 0 },
        forecasts: { dailyForecast: 0, monthlyForecast: 0, confidenceLevel: 0 },
      };
    }
  }

  /**
   * Set cost limits for a business
   */
  async setBusinessLimits(businessId: string, limits: Partial<CostLimits>): Promise<void> {
    try {
      const currentLimits = await this.getBusinessLimits(businessId);
      const newLimits = { ...currentLimits, ...limits };

      await this.kv.put(
        `cost:limits:${businessId}`,
        JSON.stringify(newLimits),
        { expirationTtl: 86400 * 365 } // 1 year
      );

      this.logger.info('Business cost limits updated', {
        businessId,
        newLimits,
      });

    } catch (error: any) {
      this.logger.error('Failed to set business limits', error, { businessId });
      throw error;
    }
  }

  /**
   * Get cost limits for a business
   */
  async getBusinessLimits(businessId: string): Promise<CostLimits> {
    try {
      const cached = await this.kv.get(`cost:limits:${businessId}`, 'json');
      return cached ? { ...this.defaultLimits, ...cached } : this.defaultLimits;
    } catch (error: any) {
      this.logger.error('Failed to get business limits', error, { businessId });
      return this.defaultLimits;
    }
  }

  /**
   * Get system-wide cost statistics
   */
  async getSystemStatistics(): Promise<{
    totalBusinesses: number;
    totalCost: number;
    totalTasks: number;
    averageCostPerTask: number;
    topBusinesses: Array<{ businessId: string; cost: number; tasks: number }>;
  }> {
    try {
      const result = await this.db.prepare(`
        SELECT
          business_id,
          SUM(cost) as total_cost,
          COUNT(*) as task_count
        FROM agent_costs
        WHERE timestamp >= ?
        GROUP BY business_id
        ORDER BY total_cost DESC
      `).bind(Date.now() - (30 * 24 * 60 * 60 * 1000)).all(); // Last 30 days

      const businesses = result.results || [];
      const totalCost = businesses.reduce((sum, b: any) => sum + (b.total_cost || 0), 0);
      const totalTasks = businesses.reduce((sum, b: any) => sum + (b.task_count || 0), 0);

      return {
        totalBusinesses: businesses.length,
        totalCost,
        totalTasks,
        averageCostPerTask: totalTasks > 0 ? totalCost / totalTasks : 0,
        topBusinesses: businesses.slice(0, 10).map((row: any) => ({
          businessId: row.business_id,
          cost: row.total_cost || 0,
          tasks: row.task_count || 0,
        })),
      };

    } catch (error: any) {
      this.logger.error('Failed to get system statistics', error);
      return {
        totalBusinesses: 0,
        totalCost: 0,
        totalTasks: 0,
        averageCostPerTask: 0,
        topBusinesses: [],
      };
    }
  }

  /**
   * Get cost tracker statistics
   */
  getStatistics(): {
    totalTracked: number;
    defaultLimits: CostLimits;
  } {
    return {
      totalTracked: 0, // Would require maintaining counter
      defaultLimits: this.defaultLimits,
    };
  }

  /**
   * Cleanup old cost records
   */
  async cleanup(retentionDays: number = 365): Promise<void> {
    try {
      const cutoffTime = Date.now() - (retentionDays * 24 * 60 * 60 * 1000);

      const result = await this.db.prepare(`
        DELETE FROM agent_costs
        WHERE timestamp < ?
      `).bind(cutoffTime).run();

      this.logger.info('Cost records cleanup completed', {
        deletedRecords: result.meta.changes || 0,
        retentionDays,
      });

    } catch (error: any) {
      this.logger.error('Failed to cleanup cost records', error);
    }
  }

  /**
   * Private helper methods
   */

  private async updateRealTimeTracking(metrics: CostMetrics): Promise<void> {
    const today = new Date().toISOString().slice(0, 10);
    const currentMonth = new Date().toISOString().slice(0, 7);

    const promises = [
      // Update daily cost
      this.updateCostCounter(`cost:daily:${metrics.businessId}:${today}`, metrics.cost),
      // Update monthly cost
      this.updateCostCounter(`cost:monthly:${metrics.businessId}:${currentMonth}`, metrics.cost),
      // Update agent cost
      this.updateCostCounter(`cost:agent:${metrics.agentId}:${today}`, metrics.cost),
      // Update capability cost
      this.updateCostCounter(`cost:capability:${metrics.capability}:${today}`, metrics.cost),
    ];

    await Promise.allSettled(promises);
  }

  private async updateCostCounter(key: string, additionalCost: number): Promise<void> {
    try {
      const current = await this.kv.get(key);
      const newCost = (current ? parseFloat(current) : 0) + additionalCost;

      await this.kv.put(key, newCost.toString(), {
        expirationTtl: 86400 * 32, // 32 days
      });

    } catch (error: any) {
      this.logger.warn('Failed to update cost counter', error, { costKey: key });
    }
  }

  private async persistToDatabase(metrics: CostMetrics, trackingId: string): Promise<void> {
    try {
      // Use INSERT OR IGNORE for idempotency - prevents duplicate cost entries
      // The task_id should be unique per task to avoid double-charging
      const result = await this.db.prepare(`
        INSERT OR IGNORE INTO agent_costs (
          id, business_id, agent_id, task_id, user_id,
          cost, latency, timestamp, success, capability,
          department, tracking_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        CorrelationId.generate(),
        metrics.businessId,
        metrics.agentId,
        metrics.taskId,
        metrics.userId,
        metrics.cost,
        metrics.latency,
        metrics.timestamp,
        metrics.success ? 1 : 0,
        metrics.capability,
        metrics.department || null,
        trackingId
      ).run();

    } catch (error: any) {
      this.logger.error('Failed to persist cost metrics to database', error, {
        trackingId,
        businessId: metrics.businessId,
      });
    }
  }

  private async checkLimitsAndAlert(metrics: CostMetrics): Promise<void> {
    try {
      const limits = await this.getBusinessLimits(metrics.businessId);
      const [dailyCost, monthlyCost] = await Promise.all([
        this.getDailyCost(metrics.businessId),
        this.getMonthlyCost(metrics.businessId),
      ]);

      // Check alert thresholds (80% and 95% of limits)
      const dailyThreshold80 = limits.daily * 0.8;
      const dailyThreshold95 = limits.daily * 0.95;
      const monthlyThreshold80 = limits.monthly * 0.8;
      const monthlyThreshold95 = limits.monthly * 0.95;

      if (dailyCost >= dailyThreshold95) {
        this.logger.warn('Daily cost limit 95% threshold reached', {
          businessId: metrics.businessId,
          currentCost: dailyCost,
          limit: limits.daily,
          percentage: (dailyCost / limits.daily) * 100,
        });
      } else if (dailyCost >= dailyThreshold80) {
        this.logger.info('Daily cost limit 80% threshold reached', {
          businessId: metrics.businessId,
          currentCost: dailyCost,
          limit: limits.daily,
          percentage: (dailyCost / limits.daily) * 100,
        });
      }

      if (monthlyCost >= monthlyThreshold95) {
        this.logger.warn('Monthly cost limit 95% threshold reached', {
          businessId: metrics.businessId,
          currentCost: monthlyCost,
          limit: limits.monthly,
          percentage: (monthlyCost / limits.monthly) * 100,
        });
      } else if (monthlyCost >= monthlyThreshold80) {
        this.logger.info('Monthly cost limit 80% threshold reached', {
          businessId: metrics.businessId,
          currentCost: monthlyCost,
          limit: limits.monthly,
          percentage: (monthlyCost / limits.monthly) * 100,
        });
      }

    } catch (error: any) {
      this.logger.error('Failed to check limits and alert', error, {
        businessId: metrics.businessId,
      });
    }
  }

  private getTimeRange(period: 'daily' | 'monthly'): { start: number; end: number } {
    const now = new Date();
    const end = now.getTime();

    if (period === 'daily') {
      const start = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
      return { start, end };
    } else {
      const start = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
      return { start, end };
    }
  }
}