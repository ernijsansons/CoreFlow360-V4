import type { Env } from '../types/env';
import type {
  Dashboard,
  Widget,
  UserRole,
  MetricTrend,
  PipelineStage,
  LeaderboardEntry,
  AIInsight,
  MetricUpdate,
  SalesMetrics,
  TimeFrame
} from '../types/analytics';

export class CRMAnalytics {
  private env: Env;
  private eventEmitter: EventTarget;
  private metricsCache = new Map<string, { value: any; timestamp: number }>();
  private cacheTimeout = 60000; // 1 minute
  private businessId: string;

  constructor(env: Env, businessId: string) {
    this.env = env;
    this.businessId = businessId;
    this.eventEmitter = new EventTarget();
  }

  async generateDashboard(role: UserRole, userId?: string): Promise<Dashboard> {

    switch (role) {
      case 'sales_rep':
        return await this.generateRepDashboard(userId);
      case 'sales_manager':
        return await this.generateManagerDashboard(userId);
      case 'executive':
        return await this.generateExecutiveDashboard();
      case 'ops':
        return await this.generateOpsDashboard();
      case 'customer_success':
        return await this.generateCSDashboard();
      case 'marketing':
        return await this.generateMarketingDashboard();
      default:
        return await this.generateDefaultDashboard();
    }
  }

  private async generateRepDashboard(userId?: string): Promise<Dashboard> {
    const dashboardId = `dashboard_rep_${userId || 'default'}`;

    const [
      callsToday,
      personalPipeline,
      aiRecommendations,
      leaderboard,
      activityFeed,
      forecast
    ] = await Promise.all([
      this.getCallsToday(userId),
      this.getPersonalPipeline(userId),
      this.getAIRecommendations(userId),
      this.getLeaderboard('sales'),
      this.getActivityFeed(userId),
      this.getPersonalForecast(userId)
    ]);

    return {
      id: dashboardId,
      name: 'Sales Rep Dashboard',
      role: 'sales_rep',
      widgets: [
        {
          id: 'calls_today',
          type: 'metric',
          title: 'Calls Made Today',
          config: {
            value: callsToday.count,
            target: 50,
            trend: callsToday.trend,
            trendValue: callsToday.trendValue,
            format: 'number',
            color: callsToday.count >= 50 ? 'green' : 'orange',
            icon: 'phone'
          }
        },
        {
          id: 'emails_sent',
          type: 'metric',
          title: 'Emails Sent',
          config: {
            value: await this.getEmailsSent(userId),
            target: 100,
            format: 'number',
            icon: 'email'
          }
        },
        {
          id: 'meetings_scheduled',
          type: 'metric',
          title: 'Meetings Scheduled',
          config: {
            value: await this.getMeetingsScheduled(userId),
            target: 5,
            format: 'number',
            icon: 'calendar'
          }
        },
        {
          id: 'quota_attainment',
          type: 'metric',
          title: 'Quota Attainment',
          config: {
            value: await this.getQuotaAttainment(userId),
            target: 100,
            format: 'percentage',
            icon: 'target'
          }
        },
        {
          id: 'personal_pipeline',
          type: 'pipeline',
          title: 'Your Pipeline',
          config: {
            stages: personalPipeline.stages,
            totalValue: personalPipeline.totalValue,
            conversion: personalPipeline.conversion,
            velocity: personalPipeline.velocity
          }
        },
        {
          id: 'ai_insights',
          type: 'ai_insights',
          title: 'AI Recommendations',
          subtitle: 'Personalized actions to close more deals',
          config: {
            insights: aiRecommendations,
            priority: 'high'
          }
        },
        {
          id: 'team_leaderboard',
          type: 'leaderboard',
          title: 'Team Rankings',
          config: {
            entries: leaderboard,
            metric: 'revenue',
            showChange: true,
            limit: 10
          }
        },
        {
          id: 'activity_feed',
          type: 'activity_feed',
          title: 'Recent Activity',
          data: activityFeed
        },
        {
          id: 'personal_forecast',
          type: 'forecast',
          title: 'Your Forecast',
          config: {
            forecastPeriod: 'quarter',
            confidence: forecast.confidence,
            scenarios: forecast.scenarios
          }
        }
      ],
      layout: {
        columns: 4,
        rows: 3,
        widgetPositions: [
          { widgetId: 'calls_today', x: 0, y: 0, width: 1, height: 1 },
          { widgetId: 'emails_sent', x: 1, y: 0, width: 1, height: 1 },
          { widgetId: 'meetings_scheduled', x: 2, y: 0, width: 1, height: 1 },
          { widgetId: 'quota_attainment', x: 3, y: 0, width: 1, height: 1 },
          { widgetId: 'personal_pipeline', x: 0, y: 1, width: 2, height: 1 },
          { widgetId: 'ai_insights', x: 2, y: 1, width: 2, height: 1 },
          { widgetId: 'team_leaderboard', x: 0, y: 2, width: 1, height: 1 },
          { widgetId: 'activity_feed', x: 1, y: 2, width: 2, height: 1 },
          { widgetId: 'personal_forecast', x: 3, y: 2, width: 1, height: 1 }
        ]
      },
      refreshInterval: 60,
      lastUpdated: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };
  }

  private async generateManagerDashboard(userId?: string): Promise<Dashboard> {
    const dashboardId = `dashboard_manager_${userId || 'default'}`;

    const [
      teamPerformance,
      pipelineHealth,
      forecastAccuracy,
      dealVelocity,
      repPerformance,
      atRiskDeals
    ] = await Promise.all([
      this.getTeamPerformance(),
      this.getPipelineHealth(),
      this.getForecastAccuracy(),
      this.getDealVelocity(),
      this.getRepPerformance(),
      this.getAtRiskDeals()
    ]);

    return {
      id: dashboardId,
      name: 'Sales Manager Dashboard',
      role: 'sales_manager',
      widgets: [
        {
          id: 'team_revenue',
          type: 'metric',
          title: 'Team Revenue (MTD)',
          config: {
            value: teamPerformance.revenue,
            target: teamPerformance.target,
            trend: teamPerformance.trend,
            format: 'currency',
            prefix: '$',
            icon: 'dollar'
          }
        },
        {
          id: 'win_rate',
          type: 'metric',
          title: 'Win Rate',
          config: {
            value: teamPerformance.winRate,
            previousValue: teamPerformance.previousWinRate,
            format: 'percentage',
            icon: 'trophy'
          }
        },
        {
          id: 'avg_deal_size',
          type: 'metric',
          title: 'Avg Deal Size',
          config: {
            value: teamPerformance.avgDealSize,
            trend: teamPerformance.dealSizeTrend,
            format: 'currency',
            prefix: '$',
            icon: 'chart'
          }
        },
        {
          id: 'sales_cycle',
          type: 'metric',
          title: 'Sales Cycle (Days)',
          config: {
            value: teamPerformance.salesCycle,
            target: 30,
            format: 'number',
            suffix: ' days',
            icon: 'clock'
          }
        },
        {
          id: 'pipeline_health',
          type: 'chart',
          title: 'Pipeline Health',
          config: {
            chartType: 'waterfall',
            series: pipelineHealth.series,
            colors: ['#10b981', '#f59e0b', '#ef4444']
          }
        },
        {
          id: 'forecast_accuracy',
          type: 'chart',
          title: 'Forecast vs Actual',
          config: {
            chartType: 'line',
            series: forecastAccuracy.series,
            xAxis: { type: 'time' },
            yAxis: { label: 'Revenue', format: 'currency' }
          }
        },
        {
          id: 'deal_velocity',
          type: 'heatmap',
          title: 'Deal Velocity by Stage',
          data: dealVelocity
        },
        {
          id: 'rep_performance',
          type: 'table',
          title: 'Rep Performance',
          config: {
            columns: [
              { key: 'name', label: 'Rep', type: 'text' },
              { key: 'revenue', label: 'Revenue', type: 'number', format: 'currency' },
              { key: 'deals', label: 'Deals', type: 'number' },
              { key: 'winRate', label: 'Win Rate', type: 'number', format: 'percentage' },
              { key: 'quota', label: 'Quota %', type: 'number', format: 'percentage' },
              { key: 'activity', label: 'Activity Score', type: 'badge' }
            ],
            rows: repPerformance,
            sortable: true
          }
        },
        {
          id: 'at_risk_deals',
          type: 'table',
          title: 'At-Risk Deals',
          subtitle: 'Deals requiring immediate attention',
          config: {
            columns: [
              { key: 'name', label: 'Deal', type: 'link' },
              { key: 'value', label: 'Value', type: 'number', format: 'currency' },
              { key: 'stage', label: 'Stage', type: 'badge' },
              { key: 'riskLevel', label: 'Risk', type: 'badge' },
              { key: 'reason', label: 'Reason', type: 'text' },
              { key: 'action', label: 'Action', type: 'text' }
            ],
            rows: atRiskDeals,
            filterable: true
          }
        }
      ],
      refreshInterval: 300, // 5 minutes
      lastUpdated: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };
  }

  private async generateExecutiveDashboard(): Promise<Dashboard> {
    const dashboardId = 'dashboard_executive';

    const [
      companyMetrics,
      revenueCharts,
      customerMetrics,
      marketShare,
      competitiveAnalysis,
      strategicInsights
    ] = await Promise.all([
      this.getCompanyMetrics(),
      this.getRevenueCharts(),
      this.getCustomerMetrics(),
      this.getMarketShare(),
      this.getCompetitiveAnalysis(),
      this.getStrategicInsights()
    ]);

    return {
      id: dashboardId,
      name: 'Executive Dashboard',
      role: 'executive',
      widgets: [
        {
          id: 'arr',
          type: 'metric',
          title: 'ARR',
          config: {
            value: companyMetrics.arr,
            previousValue: companyMetrics.previousARR,
            trend: companyMetrics.arrTrend,
            format: 'currency',
            prefix: '$',
            suffix: 'M'
          }
        },
        {
          id: 'growth_rate',
          type: 'metric',
          title: 'Growth Rate (YoY)',
          config: {
            value: companyMetrics.growthRate,
            format: 'percentage',
            icon: 'trending-up'
          }
        },
        {
          id: 'gross_margin',
          type: 'metric',
          title: 'Gross Margin',
          config: {
            value: companyMetrics.grossMargin,
            target: 70,
            format: 'percentage'
          }
        },
        {
          id: 'ltv_cac',
          type: 'metric',
          title: 'LTV/CAC Ratio',
          config: {
            value: companyMetrics.ltvCacRatio,
            target: 3,
            format: 'number',
            suffix: 'x'
          }
        },
        {
          id: 'revenue_trend',
          type: 'chart',
          title: 'Revenue Trend',
          config: {
            chartType: 'area',
            series: revenueCharts.trend,
            xAxis: { type: 'time' },
            yAxis: { label: 'Revenue', format: 'currency' }
          }
        },
        {
          id: 'revenue_breakdown',
          type: 'chart',
          title: 'Revenue by Segment',
          config: {
            chartType: 'pie',
            series: revenueCharts.breakdown
          }
        },
        {
          id: 'customer_metrics',
          type: 'chart',
          title: 'Customer Metrics',
          config: {
            chartType: 'line',
            series: customerMetrics.series,
            legend: true
          }
        },
        {
          id: 'market_share',
          type: 'chart',
          title: 'Market Share',
          config: {
            chartType: 'doughnut',
            series: marketShare.series
          }
        },
        {
          id: 'competitive_analysis',
          type: 'table',
          title: 'Competitive Analysis',
          config: {
            columns: [
              { key: 'competitor', label: 'Competitor' },
              { key: 'winRate', label: 'Win Rate', format: 'percentage' },
              { key: 'lossReason', label: 'Primary Loss Reason' },
              { key: 'strategy', label: 'Counter Strategy' }
            ],
            rows: competitiveAnalysis
          }
        },
        {
          id: 'strategic_insights',
          type: 'ai_insights',
          title: 'Strategic Insights',
          config: {
            insights: strategicInsights,
            priority: 'high',
            category: ['opportunity', 'risk']
          }
        }
      ],
      refreshInterval: 3600, // 1 hour
      lastUpdated: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };
  }

  private async generateOpsDashboard(): Promise<Dashboard> {
    const dashboardId = 'dashboard_ops';

    return {
      id: dashboardId,
      name: 'Operations Dashboard',
      role: 'ops',
      widgets: [
        {
          id: 'system_health',
          type: 'metric',
          title: 'System Health',
          config: {
            value: await this.getSystemHealth(),
            format: 'percentage',
            color: 'green',
            icon: 'heart'
          }
        },
        {
          id: 'api_performance',
          type: 'chart',
          title: 'API Performance',
          config: {
            chartType: 'line',
            series: await this.getAPIPerformance()
          }
        },
        {
          id: 'data_quality',
          type: 'metric',
          title: 'Data Quality Score',
          config: {
            value: await this.getDataQuality(),
            target: 95,
            format: 'percentage'
          }
        },
        {
          id: 'integration_status',
          type: 'table',
          title: 'Integration Status',
          config: {
            columns: [
              { key: 'name', label: 'Integration' },
              { key: 'status', label: 'Status', type: 'badge' },
              { key: 'lastSync', label: 'Last Sync' },
              { key: 'recordsSynced', label: 'Records' }
            ],
            rows: await this.getIntegrationStatus()
          }
        }
      ],
      refreshInterval: 60,
      lastUpdated: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };
  }

  private async generateCSDashboard(): Promise<Dashboard> {
    const dashboardId = 'dashboard_cs';

    return {
      id: dashboardId,
      name: 'Customer Success Dashboard',
      role: 'customer_success',
      widgets: [
        {
          id: 'nps_score',
          type: 'metric',
          title: 'NPS Score',
          config: {
            value: await this.getNPSScore(),
            target: 50,
            format: 'number',
            color: await this.getNPSScore() > 50 ? 'green' : 'orange'
          }
        },
        {
          id: 'churn_rate',
          type: 'metric',
          title: 'Churn Rate',
          config: {
            value: await this.getChurnRate(),
            target: 5,
            format: 'percentage',
            color: await this.getChurnRate() < 5 ? 'green' : 'red'
          }
        },
        {
          id: 'customer_health',
          type: 'table',
          title: 'Customer Health',
          config: {
            columns: [
              { key: 'customer', label: 'Customer' },
              { key: 'health', label: 'Health', type: 'badge' },
              { key: 'arr', label: 'ARR', format: 'currency' },
              { key: 'lastContact', label: 'Last Contact' },
              { key: 'risk', label: 'Risk Level' }
            ],
            rows: await this.getCustomerHealth()
          }
        }
      ],
      refreshInterval: 300,
      lastUpdated: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };
  }

  private async generateMarketingDashboard(): Promise<Dashboard> {
    const dashboardId = 'dashboard_marketing';

    return {
      id: dashboardId,
      name: 'Marketing Dashboard',
      role: 'marketing',
      widgets: [
        {
          id: 'leads_generated',
          type: 'metric',
          title: 'Leads Generated',
          config: {
            value: await this.getLeadsGenerated(),
            target: 1000,
            format: 'number'
          }
        },
        {
          id: 'conversion_funnel',
          type: 'funnel',
          title: 'Conversion Funnel',
          data: await this.getConversionFunnel()
        },
        {
          id: 'campaign_roi',
          type: 'chart',
          title: 'Campaign ROI',
          config: {
            chartType: 'bar',
            series: await this.getCampaignROI()
          }
        }
      ],
      refreshInterval: 300,
      lastUpdated: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };
  }

  private async generateDefaultDashboard(): Promise<Dashboard> {
    return {
      id: 'dashboard_default',
      name: 'Dashboard',
      role: 'sales_rep',
      widgets: [],
      lastUpdated: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };
  }

  // Real-time streaming metrics
  async streamMetrics(userId?: string): Promise<ReadableStream<MetricUpdate>> {
    const encoder = new TextEncoder();

    return new ReadableStream({
      start: (controller) => {
        // Subscribe to events
        this.eventEmitter.addEventListener('lead_created', (event: any) => {
          const update: MetricUpdate = {
            type: 'metric_update',
            metric: 'total_leads',
            value: event.detail.count,
            change: 1,
            timestamp: new Date().toISOString()
          };
          controller.enqueue(encoder.encode(JSON.stringify(update) + '\n'));
        });

        this.eventEmitter.addEventListener('deal_won', (event: any) => {
          const update: MetricUpdate = {
            type: 'celebration',
            message: `🎉 ${event.detail.rep} just closed $${event.detail.value.toLocaleString()}!`,
            severity: 'success',
            timestamp: new Date().toISOString()
          };
          controller.enqueue(encoder.encode(JSON.stringify(update) + '\n'));
        });

        this.eventEmitter.addEventListener('deal_lost', (event: any) => {
          const update: MetricUpdate = {
            type: 'alert',
            message: `Deal lost: ${event.detail.name} ($${event.detail.value.toLocaleString()})`,
            severity: 'warning',
            timestamp: new Date().toISOString()
          };
          controller.enqueue(encoder.encode(JSON.stringify(update) + '\n'));
        });

        this.eventEmitter.addEventListener('quota_achieved', (event: any) => {
          const update: MetricUpdate = {
            type: 'celebration',
            message: `🏆 ${event.detail.rep} hit ${event.detail.percentage}% of quota!`,
            severity: 'success',
            timestamp: new Date().toISOString()
          };
          controller.enqueue(encoder.encode(JSON.stringify(update) + '\n'));
        });

        // Send heartbeat every 30 seconds
        const heartbeat = setInterval(() => {
          const update: MetricUpdate = {
            type: 'notification',
            message: 'heartbeat',
            severity: 'info',
            timestamp: new Date().toISOString()
          };
          controller.enqueue(encoder.encode(JSON.stringify(update) + '\n'));
        }, 30000);

        // Cleanup on close
        this.eventEmitter.addEventListener('close', () => {
          clearInterval(heartbeat);
          controller.close();
        });
      }
    });
  }

  // Data fetching methods

  private async getCallsToday(userId?: string): Promise<any> {
    const cacheKey = `calls_today_${userId || 'all'}`;
    const cached = this.getCachedValue(cacheKey);
    if (cached) return cached;

    const db = this.env.DB_CRM;
    const today = new Date().toISOString().split('T')[0];

    const query = userId
      ? `SELECT COUNT(*) as count FROM calls WHERE business_id = ? AND user_id = ? AND date(created_at) = ?`
      : `SELECT COUNT(*) as count FROM calls WHERE business_id = ? AND date(created_at) = ?`;

    const params = userId ? [this.businessId, userId, today] : [this.businessId, today];
    const result = await db.prepare(query).bind(...params).first();

    const count = result?.count || 0;

    // Get trend
    const yesterdayQuery = userId
      ? `SELECT COUNT(*) as count FROM calls
  WHERE business_id = ? AND user_id = ? AND date(created_at) = date('now', '-1 day')`
      : `SELECT COUNT(*) as count FROM calls WHERE business_id = ? AND date(created_at) = date('now', '-1 day')`;

    const yesterdayParams = userId ? [this.businessId, userId] : [this.businessId];
    const yesterdayResult = await db.prepare(yesterdayQuery).bind(...yesterdayParams).first();
    const yesterdayCount = yesterdayResult?.count || 0;

    const value = {
      count,
      trend: count > yesterdayCount ? 'up' : count < yesterdayCount ? 'down' : 'stable',
      trendValue: yesterdayCount > 0 ? ((count - yesterdayCount) / yesterdayCount) * 100 : 0
    };

    this.setCachedValue(cacheKey, value);
    return value;
  }

  private async getEmailsSent(userId?: string): Promise<number> {
    const db = this.env.DB_CRM;
    const today = new Date().toISOString().split('T')[0];

    const query = userId
      ? `SELECT COUNT(*) as count FROM emails WHERE business_id = ? AND sender_id = ? AND date(sent_at) = ?`
      : `SELECT COUNT(*) as count FROM emails WHERE business_id = ? AND date(sent_at) = ?`;

    const params = userId ? [this.businessId, userId, today] : [this.businessId, today];
    const result = await db.prepare(query).bind(...params).first();

    return result?.count || 0;
  }

  private async getMeetingsScheduled(userId?: string): Promise<number> {
    const db = this.env.DB_CRM;
    const today = new Date().toISOString().split('T')[0];

    const query = userId
      ? `SELECT COUNT(*) as count FROM meetings WHERE business_id = ? AND user_id = ? AND date(scheduled_at) = ?`
      : `SELECT COUNT(*) as count FROM meetings WHERE business_id = ? AND date(scheduled_at) = ?`;

    const params = userId ? [this.businessId, userId, today] : [this.businessId, today];
    const result = await db.prepare(query).bind(...params).first();

    return result?.count || 0;
  }

  private async getQuotaAttainment(userId?: string): Promise<number> {
    const db = this.env.DB_CRM;

    const query = userId
      ? `SELECT SUM(value) as revenue FROM opportunities WHERE business_id =
  ? AND owner_id = ? AND status = 'closed_won' AND date(close_date) >= date('now', 'start of month')`
      : `SELECT SUM(value) as revenue FROM opportunities WHERE
  business_id = ? AND status = 'closed_won' AND date(close_date) >= date('now', 'start of month')`;

    const params = userId ? [this.businessId, userId] : [this.businessId];
    const result = await db.prepare(query).bind(...params).first();
    const revenue = result?.revenue || 0;

    // Get quota
    const quotaQuery = userId
      ? `SELECT quota FROM users WHERE business_id = ? AND id = ?`
      : `SELECT SUM(quota) as quota FROM users WHERE business_id = ?`;

    const quotaParams = userId ? [this.businessId, userId] : [this.businessId];
    const quotaResult = await db.prepare(quotaQuery).bind(...quotaParams).first();
    const quota = quotaResult?.quota || 100000;

    return (revenue / quota) * 100;
  }

  private async getPersonalPipeline(userId?: string): Promise<any> {
    const db = this.env.DB_CRM;

    const stages = ['prospecting', 'qualification', 'proposal', 'negotiation', 'closing'];
    const pipelineStages: PipelineStage[] = [];

    for (const stage of stages) {
      const query = userId
        ? `SELECT COUNT(*) as count, SUM(value) as value FROM
  opportunities WHERE business_id = ? AND owner_id = ? AND stage = ? AND status = 'open'`
        : `SELECT COUNT(*) as count, SUM(value) as
  value FROM opportunities WHERE business_id = ? AND stage = ? AND status = 'open'`;

      const params = userId ? [this.businessId, userId, stage] : [this.businessId, stage];
      const result = await db.prepare(query).bind(...params).first();

      pipelineStages.push({
        name: stage.charAt(0).toUpperCase() + stage.slice(1),
        value: result?.value || 0,
        count: result?.count || 0
      });
    }

    const totalValue = pipelineStages.reduce((sum, stage) => sum + stage.value, 0);

    return {
      stages: pipelineStages,
      totalValue,
      conversion: 0.25, // Mock conversion rate
      velocity: 30 // Days
    };
  }

  private async getAIRecommendations(userId?: string): Promise<AIInsight[]> {
    // In production, this would call the AI service
    return [
      {
        id: 'insight_1',
        type: 'opportunity',
        priority: 'high',
        title: 'Follow up with Acme Corp',
        description: 'Acme Corp viewed your proposal 3 times yesterday. High engagement indicates buying intent.',
        action: 'Call John at Acme Corp today',
        owner: userId,
        deadline: new Date().toISOString(),
        confidence: 0.85,
        createdAt: new Date().toISOString()
      },
      {
        id: 'insight_2',
        type: 'risk',
        priority: 'medium',
        title: 'TechCorp deal at risk',
        description: 'No activity in 7 days. Deal typically stall at this stage.',
        action: 'Send value-add content to re-engage',
        owner: userId,
        confidence: 0.72,
        createdAt: new Date().toISOString()
      },
      {
        id: 'insight_3',
        type: 'recommendation',
        priority: 'low',
        title: 'Best time to call',
        description: 'Your prospects respond best between 2-4 PM on Tuesdays',
        action: 'Schedule calls for Tuesday afternoon',
        owner: userId,
        confidence: 0.91,
        createdAt: new Date().toISOString()
      }
    ];
  }

  private async getLeaderboard(metric: string = 'revenue'): Promise<LeaderboardEntry[]> {
    const db = this.env.DB_CRM;

    const query = `
      SELECT
        u.name,
        u.avatar,
        SUM(o.value) as revenue,
        COUNT(o.id) as deals,
        AVG(CASE WHEN o.status = 'closed_won' THEN 1.0 ELSE 0.0 END) as win_rate
      FROM users u
      LEFT JOIN opportunities o ON u.id = o.owner_id AND o.business_id = u.business_id
      WHERE u.business_id = ? AND o.close_date >= date('now', 'start of month')
      GROUP BY u.id
      ORDER BY revenue DESC
      LIMIT 10
    `;

    const result = await db.prepare(query).bind(this.businessId).all();

    return result.results.map((row, index) => ({
      rank: index + 1,
      previousRank: index + 1, // Would track historical ranks
      name: row.name as string,
      avatar: row.avatar as string,
      value: row.revenue as number,
      change: 0, // Would calculate change
      percentOfTarget: 85 + Math.random() * 30 // Mock
    }));
  }

  private async getActivityFeed(userId?: string): Promise<any[]> {
    const db = this.env.DB_CRM;

    const query = userId
      ? `SELECT * FROM activity_log WHERE business_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 20`
      : `SELECT * FROM activity_log WHERE business_id = ? ORDER BY created_at DESC LIMIT 20`;

    const params = userId ? [this.businessId, userId] : [this.businessId];
    const result = await db.prepare(query).bind(...params).all();

    return result.results;
  }

  private async getPersonalForecast(userId?: string): Promise<any> {
    // Mock forecast data
    return {
      confidence: 0.78,
      scenarios: [
        {
          name: 'Best Case',
          probability: 0.25,
          value: 500000,
          assumptions: ['All deals close', 'No pushouts'],
          color: 'green'
        },
        {
          name: 'Most Likely',
          probability: 0.60,
          value: 350000,
          assumptions: ['70% close rate', 'Some pushouts'],
          color: 'blue'
        },
        {
          name: 'Worst Case',
          probability: 0.15,
          value: 200000,
          assumptions: ['50% close rate', 'Major delays'],
          color: 'red'
        }
      ]
    };
  }

  // Manager dashboard data methods

  private async getTeamPerformance(): Promise<any> {
    const db = this.env.DB_CRM;

    const currentMonth = await db.prepare(`
      SELECT
        SUM(value) as revenue,
        COUNT(*) as deals,
        AVG(CASE WHEN status = 'closed_won' THEN 1.0 ELSE 0.0 END) as win_rate,
        AVG(value) as avg_deal_size,
        AVG(julianday(close_date) - julianday(created_at)) as sales_cycle
      FROM opportunities
      WHERE business_id = ? AND close_date >= date('now', 'start of month')
    `).bind(this.businessId).first();

    const previousMonth = await db.prepare(`
      SELECT
        AVG(CASE WHEN status = 'closed_won' THEN 1.0 ELSE 0.0 END) as win_rate,
        AVG(value) as avg_deal_size
      FROM opportunities
      WHERE business_id = ? AND close_date >= date('now', '-1 month', 'start of month')
        AND close_date < date('now', 'start of month')
    `).bind(this.businessId).first();

    return {
      revenue: currentMonth?.revenue || 0,
      target: 1000000, // Mock target
      trend: 'up' as MetricTrend,
      winRate: (currentMonth?.win_rate || 0) * 100,
      previousWinRate: (previousMonth?.win_rate || 0) * 100,
      avgDealSize: currentMonth?.avg_deal_size || 0,
      dealSizeTrend: currentMonth?.avg_deal_size > previousMonth?.avg_deal_size ? 'up' : 'down',
      salesCycle: Math.round(currentMonth?.sales_cycle || 30)
    };
  }

  private async getPipelineHealth(): Promise<any> {
    // Mock pipeline health data
    return {
      series: [{
        name: 'Pipeline Health',
        data: [
          { x: 'New', y: 50 },
          { x: 'Qualified', y: 35 },
          { x: 'Proposal', y: 25 },
          { x: 'Negotiation', y: 15 },
          { x: 'Closing', y: 10 }
        ]
      }]
    };
  }

  private async getForecastAccuracy(): Promise<any> {
    // Mock forecast accuracy data
    return {
      series: [
        {
          name: 'Forecast',
          data: Array.from({ length: 12 }, (_, i) => ({
            x: new Date(2024, i, 1),
            y: 800000 + Math.random() * 400000
          }))
        },
        {
          name: 'Actual',
          data: Array.from({ length: 12 }, (_, i) => ({
            x: new Date(2024, i, 1),
            y: 750000 + Math.random() * 500000
          }))
        }
      ]
    };
  }

  private async getDealVelocity(): Promise<any> {
    // Mock deal velocity data
    return Array.from({ length: 5 }, (_, stageIndex) =>
      Array.from({ length: 7 }, (_, dayIndex) => ({
        stage: stageIndex,
        day: dayIndex,
        value: Math.random() * 10
      }))
    ).flat();
  }

  private async getRepPerformance(): Promise<any[]> {
    const db = this.env.DB_CRM;

    const result = await db.prepare(`
      SELECT
        u.name,
        SUM(o.value) as revenue,
        COUNT(o.id) as deals,
        AVG(CASE WHEN o.status = 'closed_won' THEN 1.0 ELSE 0.0 END) as winRate,
        (SUM(o.value) / u.quota) as quota
      FROM users u
      LEFT JOIN opportunities o ON u.id = o.owner_id AND o.business_id = u.business_id
      WHERE u.business_id = ? AND o.close_date >= date('now', 'start of month')
      GROUP BY u.id
      ORDER BY revenue DESC
    `).bind(this.businessId).all();

    return result.results.map((row: any) => ({
      name: row.name,
      revenue: row.revenue || 0,
      deals: row.deals || 0,
      winRate: (row.winRate || 0) * 100,
      quota: (row.quota || 0) * 100,
      activity: row.quota > 0.8 ? 'high' : row.quota > 0.5 ? 'medium' : 'low'
    }));
  }

  private async getAtRiskDeals(): Promise<any[]> {
    const db = this.env.DB_CRM;

    const result = await db.prepare(`
      SELECT
        o.name,
        o.value,
        o.stage,
        julianday('now') - julianday(o.last_activity) as days_inactive
      FROM opportunities o
      WHERE o.business_id = ? AND o.status = 'open'
        AND (
          julianday('now') - julianday(o.last_activity) > 7
          OR o.close_date < date('now', '+7 days')
        )
      ORDER BY o.value DESC
      LIMIT 10
    `).bind(this.businessId).all();

    return result.results.map((row: any) => ({
      name: row.name,
      value: row.value,
      stage: row.stage,
      riskLevel: row.days_inactive > 14 ? 'high' : row.days_inactive > 7 ? 'medium' : 'low',
      reason: row.days_inactive > 7 ? `No activity for ${row.days_inactive} days` : 'Close date approaching',
      action: 'Schedule urgent follow-up'
    }));
  }

  // Executive dashboard data methods

  private async getCompanyMetrics(): Promise<any> {
    // Mock company-wide metrics
    return {
      arr: 12500000,
      previousARR: 10000000,
      arrTrend: 'up' as MetricTrend,
      growthRate: 25,
      grossMargin: 72,
      ltvCacRatio: 3.2
    };
  }

  private async getRevenueCharts(): Promise<any> {
    // Mock revenue data
    return {
      trend: [{
        name: 'Revenue',
        data: Array.from({ length: 12 }, (_, i) => ({
          x: new Date(2024, i, 1),
          y: 900000 + Math.random() * 300000
        }))
      }],
      breakdown: [{
        name: 'Revenue by Segment',
        data: [
          { x: 'Enterprise', y: 45 },
          { x: 'Mid-Market', y: 35 },
          { x: 'SMB', y: 20 }
        ]
      }]
    };
  }

  private async getCustomerMetrics(): Promise<any> {
    // Mock customer metrics
    return {
      series: [
        {
          name: 'Total Customers',
          data: Array.from({ length: 12 }, (_, i) => ({
            x: new Date(2024, i, 1),
            y: 1000 + i * 50 + Math.random() * 20
          }))
        },
        {
          name: 'NPS Score',
          data: Array.from({ length: 12 }, (_, i) => ({
            x: new Date(2024, i, 1),
            y: 45 + Math.random() * 20
          }))
        }
      ]
    };
  }

  private async getMarketShare(): Promise<any> {
    // Mock market share data
    return {
      series: [{
        name: 'Market Share',
        data: [
          { x: 'Our Company', y: 35 },
          { x: 'Competitor A', y: 25 },
          { x: 'Competitor B', y: 20 },
          { x: 'Others', y: 20 }
        ]
      }]
    };
  }

  private async getCompetitiveAnalysis(): Promise<any[]> {
    // Mock competitive analysis
    return [
      {
        competitor: 'Competitor A',
        winRate: 65,
        lossReason: 'Price',
        strategy: 'Emphasize ROI and total value'
      },
      {
        competitor: 'Competitor B',
        winRate: 72,
        lossReason: 'Features',
        strategy: 'Highlight unique capabilities'
      },
      {
        competitor: 'Competitor C',
        winRate: 80,
        lossReason: 'Brand recognition',
        strategy: 'Leverage customer success stories'
      }
    ];
  }

  private async getStrategicInsights(): Promise<AIInsight[]> {
    // Mock strategic insights
    return [
      {
        id: 'strategic_1',
        type: 'opportunity',
        priority: 'high',
        title: 'Expansion Opportunity in Healthcare',
        description: 'Healthcare vertical showing 150% YoY growth with 45% win rate',
        impact: '$5M additional ARR potential',
        action: 'Increase investment in healthcare sales team',
        confidence: 0.88,
        createdAt: new Date().toISOString()
      },
      {
        id: 'strategic_2',
        type: 'risk',
        priority: 'high',
        title: 'Churn Risk in SMB Segment',
        description: 'SMB churn rate increased to 12% from 8% last quarter',
        impact: '$2M ARR at risk',
        action: 'Launch customer success initiative for SMB',
        confidence: 0.92,
        createdAt: new Date().toISOString()
      }
    ];
  }

  // Other dashboard methods

  private async getSystemHealth(): Promise<number> {
    // Check various system metrics
    return 98.5;
  }

  private async getAPIPerformance(): Promise<any> {
    // Mock API performance data
    return [{
      name: 'Response Time',
      data: Array.from({ length: 24 }, (_, i) => ({
        x: new Date().setHours(i),
        y: 50 + Math.random() * 100
      }))
    }];
  }

  private async getDataQuality(): Promise<number> {
    const db = this.env.DB_CRM;

    const result = await db.prepare(`
      SELECT
        COUNT(*) as total,
        COUNT(CASE WHEN email IS NOT NULL AND phone IS NOT NULL THEN 1 END) as complete
      FROM leads
      WHERE business_id = ?
    `).bind(this.businessId).first();

    const total = result?.total || 1;
    const complete = result?.complete || 0;

    return (complete / total) * 100;
  }

  private async getIntegrationStatus(): Promise<any[]> {
    const db = this.env.DB_MAIN;

    const result = await db.prepare(`
      SELECT
        name,
        status,
        last_sync,
        (SELECT SUM(records_synced) FROM sync_logs WHERE integration_id = integrations.id) as records_synced
      FROM integrations
      WHERE business_id = ? AND status != 'archived'
    `).bind(this.businessId).all();

    return result.results.map((row: any) => ({
      name: row.name,
      status: row.status,
      lastSync: row.last_sync,
      recordsSynced: row.records_synced || 0
    }));
  }

  private async getNPSScore(): Promise<number> {
    // Mock NPS score
    return 52;
  }

  private async getChurnRate(): Promise<number> {
    // Mock churn rate
    return 4.5;
  }

  private async getCustomerHealth(): Promise<any[]> {
    // Mock customer health data
    return [
      {
        customer: 'Acme Corp',
        health: 'healthy',
        arr: 250000,
        lastContact: '2 days ago',
        risk: 'low'
      },
      {
        customer: 'TechCorp',
        health: 'at-risk',
        arr: 180000,
        lastContact: '2 weeks ago',
        risk: 'medium'
      }
    ];
  }

  private async getLeadsGenerated(): Promise<number> {
    const db = this.env.DB_CRM;

    const result = await db.prepare(`
      SELECT COUNT(*) as count
      FROM leads
      WHERE business_id = ? AND created_at >= date('now', 'start of month')
    `).bind(this.businessId).first();

    return result?.count || 0;
  }

  private async getConversionFunnel(): Promise<any> {
    // Mock funnel data
    return [
      { stage: 'Visitors', value: 10000 },
      { stage: 'Leads', value: 1000 },
      { stage: 'MQLs', value: 300 },
      { stage: 'SQLs', value: 100 },
      { stage: 'Opportunities', value: 50 },
      { stage: 'Customers', value: 10 }
    ];
  }

  private async getCampaignROI(): Promise<any> {
    // Mock campaign ROI data
    return [{
      name: 'Campaign ROI',
      data: [
        { x: 'Google Ads', y: 3.5 },
        { x: 'Facebook', y: 2.8 },
        { x: 'LinkedIn', y: 4.2 },
        { x: 'Email', y: 5.1 },
        { x: 'Content', y: 3.9 }
      ]
    }];
  }

  // Cache management

  private getCachedValue(key: string): any {
    const cached = this.metricsCache.get(key);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.value;
    }
    return null;
  }

  private setCachedValue(key: string, value: any): void {
    this.metricsCache.set(key, {
      value,
      timestamp: Date.now()
    });
  }

  // Event emission

  public emitEvent(eventName: string, detail: any): void {
    this.eventEmitter.dispatchEvent(new CustomEvent(eventName, { detail }));
  }
}