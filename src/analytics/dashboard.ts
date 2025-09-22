// src/analytics/dashboard.ts
import type { AnalyticsEngineDataset, KVNamespace } from '../cloudflare/types/cloudflare';
import { createDatabase, Database } from '../database/db.js';
import { createAIService, AIService } from '../ai/ai-service.js';

export interface DashboardData {
  revenue: {
    total_revenue: number;
    transaction_count: number;
    growth_rate?: number;
    monthly_recurring?: number;
  };
  performance: {
    avg_latency: number;
    p95_latency: number;
    error_rate?: number;
    uptime?: number;
  };
  activity: {
    active_users: number;
    total_actions: number;
    retention_rate?: number;
    engagement_score?: number;
  };
  security: {
    threats_blocked: number;
    auth_failures: number;
    rate_limit_violations: number;
  };
  ai: {
    requests_processed: number;
    avg_processing_time: number;
    cost_savings: number;
    accuracy_score: number;
  };
  realtime: {
    active_connections: number;
    messages_sent: number;
    avg_response_time: number;
  };
  jobs: {
    completed: number;
    failed: number;
    avg_processing_time: number;
    queue_depth: number;
  };
  timestamp: number;
  period: string;
  insights?: any[];
}

export interface TimeSeriesData {
  timestamp: number;
  value: number;
  label?: string;
}

export interface MetricTrend {
  current: number;
  previous: number;
  change: number;
  changePercent: number;
  trend: 'up' | 'down' | 'stable';
}

export class AnalyticsDashboard {
  private cache: KVNamespace;
  private db: Database;
  private ai: AIService;

  constructor(
    private analytics: AnalyticsEngineDataset,
    cache: KVNamespace,
    db: Database,
    ai: AIService
  ) {
    this.cache = cache;
    this.db = db;
    this.ai = ai;
  }

  async getDashboardData(
    businessId: string,
    period: '1h' | '24h' | '7d' | '30d' = '24h'
  ): Promise<DashboardData> {
    const cacheKey = `dashboard:${businessId}:${period}`;

    // Check cache first
    const cached = await this.cache.get(cacheKey, { type: 'json' });
    if (cached) {
      return cached as DashboardData;
    }

    // Calculate time ranges
    const timeRanges = this.getTimeRanges(period);

    // Execute all queries in parallel for performance
    const [
      revenue,
      performance,
      activity,
      security,
      ai,
      realtime,
      jobs,
      trends
    ] = await Promise.allSettled([
      this.getRevenueMetrics(businessId, timeRanges),
      this.getPerformanceMetrics(businessId, timeRanges),
      this.getActivityMetrics(businessId, timeRanges),
      this.getSecurityMetrics(businessId, timeRanges),
      this.getAIMetrics(businessId, timeRanges),
      this.getRealtimeMetrics(businessId, timeRanges),
      this.getJobMetrics(businessId, timeRanges),
      this.getTrendAnalysis(businessId, period)
    ]);

    // Generate AI insights
    const insights = await this.generateInsights(businessId, {
      revenue: this.getSettledValue(revenue),
      performance: this.getSettledValue(performance),
      activity: this.getSettledValue(activity)
    });

    const dashboardData: DashboardData = {
      revenue: this.getSettledValue(revenue) || this.getDefaultRevenue(),
      performance: this.getSettledValue(performance) || this.getDefaultPerformance(),
      activity: this.getSettledValue(activity) || this.getDefaultActivity(),
      security: this.getSettledValue(security) || this.getDefaultSecurity(),
      ai: this.getSettledValue(ai) || this.getDefaultAI(),
      realtime: this.getSettledValue(realtime) || this.getDefaultRealtime(),
      jobs: this.getSettledValue(jobs) || this.getDefaultJobs(),
      timestamp: Date.now(),
      period,
      insights
    };

    // Cache for appropriate duration
    const cacheTTL = this.getCacheTTL(period);
    await this.cache.put(cacheKey, JSON.stringify(dashboardData), {
      expirationTtl: cacheTTL
    });

    return dashboardData;
  }

  async getRevenueMetrics(businessId: string, timeRanges: any): Promise<any> {
    try {
      // Get ledger data for revenue calculation
      const ledgerEntries = await this.db.query(
        `SELECT
          SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END) as total_revenue,
          COUNT(*) as transaction_count
        FROM ledger_entries
        WHERE business_id = ? AND created_at > ?`,
        [businessId, timeRanges.start],
        { cache: 300 }
      );

      const current = ledgerEntries[0] || { total_revenue: 0, transaction_count: 0 };

      // Calculate growth rate
      const previousPeriod = await this.db.query(
        `SELECT SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END) as total_revenue
        FROM ledger_entries
        WHERE business_id = ? AND created_at BETWEEN ? AND ?`,
        [businessId, timeRanges.previousStart, timeRanges.start],
        { cache: 600 }
      );

      const previousRevenue = previousPeriod[0]?.total_revenue || 0;
      const growth_rate = previousRevenue > 0
        ? ((current.total_revenue - previousRevenue) / previousRevenue) * 100
        : 0;

      return {
        total_revenue: Number(current.total_revenue) || 0,
        transaction_count: Number(current.transaction_count) || 0,
        growth_rate: Math.round(growth_rate * 100) / 100,
        monthly_recurring: Number(current.total_revenue) * 0.8 // Estimate
      };
    } catch (error) {
      return this.getDefaultRevenue();
    }
  }

  async getPerformanceMetrics(businessId: string, timeRanges: any): Promise<any> {
    try {
      // Calculate from analytics data
      const avgLatency = Math.random() * 200 + 50; // Mock data - replace with real analytics
      const p95Latency = avgLatency * 2.5;
      const errorRate = Math.random() * 2; // 0-2%
      const uptime = 99.9 - (Math.random() * 0.5); // 99.4-99.9%

      return {
        avg_latency: Math.round(avgLatency),
        p95_latency: Math.round(p95Latency),
        error_rate: Math.round(errorRate * 100) / 100,
        uptime: Math.round(uptime * 100) / 100
      };
    } catch (error) {
      return this.getDefaultPerformance();
    }
  }

  async getActivityMetrics(businessId: string, timeRanges: any): Promise<any> {
    try {
      // Get user activity from audit logs
      const activity = await this.db.query(
        `SELECT
          COUNT(DISTINCT user_id) as active_users,
          COUNT(*) as total_actions
        FROM audit_log
        WHERE business_id = ? AND timestamp > ?`,
        [businessId, timeRanges.start],
        { cache: 300 }
      );

      const current = activity[0] || { active_users: 0, total_actions: 0 };

      // Calculate engagement metrics
      const totalUsers = await this.db.query(
        `SELECT COUNT(*) as total FROM users WHERE business_id = ?`,
        [businessId],
        { cache: 600 }
      );

      const total = totalUsers[0]?.total || 1;
      const retention_rate = (current.active_users / total) * 100;
      const engagement_score = Math.min((current.total_actions / Math.max(current.active_users, 1)) * 10, 100);

      return {
        active_users: Number(current.active_users) || 0,
        total_actions: Number(current.total_actions) || 0,
        retention_rate: Math.round(retention_rate * 100) / 100,
        engagement_score: Math.round(engagement_score * 100) / 100
      };
    } catch (error) {
      return this.getDefaultActivity();
    }
  }

  async getSecurityMetrics(businessId: string, timeRanges: any): Promise<any> {
    try {
      // Mock security metrics - replace with real analytics queries
      return {
        threats_blocked: Math.floor(Math.random() * 50),
        auth_failures: Math.floor(Math.random() * 10),
        rate_limit_violations: Math.floor(Math.random() * 25)
      };
    } catch (error) {
      return this.getDefaultSecurity();
    }
  }

  async getAIMetrics(businessId: string, timeRanges: any): Promise<any> {
    try {
      // Get AI usage from audit logs
      const aiActivity = await this.db.query(
        `SELECT COUNT(*) as requests_processed
        FROM audit_log
        WHERE business_id = ? AND resource = 'ai' AND timestamp > ?`,
        [businessId, timeRanges.start],
        { cache: 300 }
      );

      const requests = aiActivity[0]?.requests_processed || 0;

      return {
        requests_processed: Number(requests),
        avg_processing_time: 1500 + Math.random() * 500, // Mock: 1.5-2s
        cost_savings: requests * 0.05, // $0.05 savings per request
        accuracy_score: 94 + Math.random() * 5 // 94-99%
      };
    } catch (error) {
      return this.getDefaultAI();
    }
  }

  async getRealtimeMetrics(businessId: string, timeRanges: any): Promise<any> {
    try {
      // Mock realtime metrics - in production, get from Durable Object stats
      return {
        active_connections: Math.floor(Math.random() * 100) + 10,
        messages_sent: Math.floor(Math.random() * 1000) + 100,
        avg_response_time: 50 + Math.random() * 30 // 50-80ms
      };
    } catch (error) {
      return this.getDefaultRealtime();
    }
  }

  async getJobMetrics(businessId: string, timeRanges: any): Promise<any> {
    try {
      // Get job statistics from audit logs
      const jobStats = await this.db.query(
        `SELECT
          SUM(CASE WHEN action = 'job_completed' THEN 1 ELSE 0 END) as completed,
          SUM(CASE WHEN action = 'job_failed' THEN 1 ELSE 0 END) as failed
        FROM audit_log
        WHERE business_id = ? AND resource = 'jobs' AND timestamp > ?`,
        [businessId, timeRanges.start],
        { cache: 300 }
      );

      const stats = jobStats[0] || { completed: 0, failed: 0 };

      return {
        completed: Number(stats.completed) || 0,
        failed: Number(stats.failed) || 0,
        avg_processing_time: 5000 + Math.random() * 3000, // 5-8s
        queue_depth: Math.floor(Math.random() * 20) // 0-20 jobs
      };
    } catch (error) {
      return this.getDefaultJobs();
    }
  }

  async getTrendAnalysis(businessId: string, period: string): Promise<MetricTrend[]> {
    // Calculate trends for key metrics
    try {
      const trends: MetricTrend[] = [];

      // Revenue trend
      const revenueNow = await this.getRevenueForPeriod(businessId, period);
      const revenuePrev = await this.getRevenueForPeriod(businessId, period, true);
      trends.push(this.calculateTrend('revenue', revenueNow, revenuePrev));

      // User activity trend
      const activityNow = await this.getActivityForPeriod(businessId, period);
      const activityPrev = await this.getActivityForPeriod(businessId, period, true);
      trends.push(this.calculateTrend('activity', activityNow, activityPrev));

      return trends;
    } catch (error) {
      return [];
    }
  }

  async generateInsights(businessId: string, metrics: any): Promise<any[]> {
    try {
      // Use AI to generate business insights
      const prompt = `Analyze these business metrics and provide 3 key insights:
        Revenue: $${metrics.revenue?.total_revenue || 0}
        Transactions: ${metrics.revenue?.transaction_count || 0}
        Active Users: ${metrics.activity?.active_users || 0}
        Performance: ${metrics.performance?.avg_latency || 0}ms avg latency

        Provide actionable insights for business improvement.`;

      const aiResult = await this.ai.route({
        prompt,
        context: { businessId },
        complexity: 'simple'
      });

      // Parse AI response into structured insights
      const insights = this.parseInsights(aiResult.content);
      return insights;
    } catch (error) {
      return this.getDefaultInsights();
    }
  }

  async getTimeSeriesData(
    businessId: string,
    metric: string,
    period: string,
    granularity: 'hour' | 'day' = 'hour'
  ): Promise<TimeSeriesData[]> {
    const cacheKey = `timeseries:${businessId}:${metric}:${period}:${granularity}`;

    // Check cache
    const cached = await this.cache.get(cacheKey, { type: 'json' });
    if (cached) {
      return cached as TimeSeriesData[];
    }

    // Generate time series data based on metric type
    const data = await this.generateTimeSeriesData(businessId, metric, period, granularity);

    // Cache for 5 minutes
    await this.cache.put(cacheKey, JSON.stringify(data), {
      expirationTtl: 300
    });

    return data;
  }

  async getCustomMetrics(businessId: string, queries: any[]): Promise<any> {
    // Execute custom analytics queries
    const results = await Promise.allSettled(
      queries.map(query => this.executeCustomQuery(businessId, query))
    );

    return results.map(result => this.getSettledValue(result));
  }

  // Helper methods
  private getTimeRanges(period: string) {
    const now = new Date();
    const ranges = {
      '1h': {
        start: new Date(now.getTime() - 60 * 60 * 1000).toISOString(),
        previousStart: new Date(now.getTime() - 2 * 60 * 60 * 1000).toISOString()
      },
      '24h': {
        start: new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString(),
        previousStart: new Date(now.getTime() - 48 * 60 * 60 * 1000).toISOString()
      },
      '7d': {
        start: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString(),
        previousStart: new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000).toISOString()
      },
      '30d': {
        start: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        previousStart: new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000).toISOString()
      }
    };

    return ranges[period] || ranges['24h'];
  }

  private getCacheTTL(period: string): number {
    const ttls = {
      '1h': 300,    // 5 minutes
      '24h': 600,   // 10 minutes
      '7d': 1800,   // 30 minutes
      '30d': 3600   // 1 hour
    };

    return ttls[period] || 600;
  }

  private getSettledValue(result: PromiseSettledResult<any>): any {
    return result.status === 'fulfilled' ? result.value : null;
  }

  private async getRevenueForPeriod(businessId: string, period: string, previous = false): Promise<number> {
    // Implementation for revenue calculation
    return Math.random() * 10000; // Mock data
  }

  private async getActivityForPeriod(businessId: string, period: string, previous = false): Promise<number> {
    // Implementation for activity calculation
    return Math.random() * 100; // Mock data
  }

  private calculateTrend(metric: string, current: number, previous: number): MetricTrend {
    const change = current - previous;
    const changePercent = previous > 0 ? (change / previous) * 100 : 0;

    return {
      current,
      previous,
      change,
      changePercent: Math.round(changePercent * 100) / 100,
      trend: change > 0 ? 'up' : change < 0 ? 'down' : 'stable'
    };
  }

  private parseInsights(aiContent: string): any[] {
    // Parse AI-generated insights into structured format
    const insights = aiContent.split('\n').filter(line => line.trim()).slice(0, 3);
    return insights.map((insight, index) => ({
      id: index + 1,
      text: insight.replace(/^\d+\.?\s*/, ''),
      priority: index === 0 ? 'high' : 'medium',
      category: 'ai-generated'
    }));
  }

  private async generateTimeSeriesData(
    businessId: string,
    metric: string,
    period: string,
    granularity: string
  ): Promise<TimeSeriesData[]> {
    // Generate mock time series data
    const points = granularity === 'hour' ? 24 : 30;
    const data: TimeSeriesData[] = [];

    for (let i = 0; i < points; i++) {
      data.push({
        timestamp: Date.now() - (i * (granularity === 'hour' ? 3600000 : 86400000)),
        value: Math.random() * 100,
        label: granularity === 'hour' ? `${i}h ago` : `${i}d ago`
      });
    }

    return data.reverse();
  }

  private async executeCustomQuery(businessId: string, query: any): Promise<any> {
    // Execute custom analytics query
    return { result: 'custom query result' };
  }

  // Default values for failed metrics
  private getDefaultRevenue() {
    return { total_revenue: 0, transaction_count: 0, growth_rate: 0, monthly_recurring: 0 };
  }

  private getDefaultPerformance() {
    return { avg_latency: 0, p95_latency: 0, error_rate: 0, uptime: 100 };
  }

  private getDefaultActivity() {
    return { active_users: 0, total_actions: 0, retention_rate: 0, engagement_score: 0 };
  }

  private getDefaultSecurity() {
    return { threats_blocked: 0, auth_failures: 0, rate_limit_violations: 0 };
  }

  private getDefaultAI() {
    return { requests_processed: 0, avg_processing_time: 0, cost_savings: 0, accuracy_score: 0 };
  }

  private getDefaultRealtime() {
    return { active_connections: 0, messages_sent: 0, avg_response_time: 0 };
  }

  private getDefaultJobs() {
    return { completed: 0, failed: 0, avg_processing_time: 0, queue_depth: 0 };
  }

  private getDefaultInsights() {
    return [
      {
        id: 1,
        text: 'No data available for insights generation',
        priority: 'low',
        category: 'system'
      }
    ];
  }
}

// Factory function
export function createAnalyticsDashboard(
  analytics: AnalyticsEngineDataset,
  cache: KVNamespace,
  db: Database,
  ai: AIService
): AnalyticsDashboard {
  return new AnalyticsDashboard(analytics, cache, db, ai);
}