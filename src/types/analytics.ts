// Analytics and Reporting Types

export type UserRole = 'sales_rep' | 'sales_manager' | 'executive' | 'ops' | 'customer_success' | 'marketing' | 'admin';

export type WidgetType =
  | 'metric'
  | 'chart'
  | 'pipeline'
  | 'leaderboard'
  | 'activity_feed'
  | 'ai_insights'
  | 'forecast'
  | 'map'
  | 'table'
  | 'timeline'
  | 'heatmap'
  | 'funnel';

export type ChartType =
  | 'line'
  | 'bar'
  | 'pie'
  | 'doughnut'
  | 'area'
  | 'scatter'
  | 'bubble'
  | 'radar'
  | 'stacked_bar'
  | 'waterfall';

export type MetricTrend = 'up' | 'down' | 'stable';
export type TimeFrame = 'today' | 'yesterday' | 'this_week' | 'last_week'
  | 'this_month' | 'last_month' | 'this_quarter' | 'last_quarter' | 'this_year' | 'custom';

export interface Dashboard {
  id: string;
  name: string;
  role: UserRole;
  widgets: Widget[];
  layout?: DashboardLayout;
  filters?: DashboardFilter[];
  refreshInterval?: number; // seconds
  lastUpdated: string;
  createdAt: string;
}

export interface DashboardLayout {
  columns: number;
  rows: number;
  widgetPositions: Array<{
    widgetId: string;
    x: number;
    y: number;
    width: number;
    height: number;
  }>;
}

export interface DashboardFilter {
  field: string;
  label: string;
  type: 'date_range' | 'dropdown' | 'search' | 'toggle';
  value?: any;
  options?: any[];
  default?: any;
}

export interface Widget {
  id: string;
  type: WidgetType;
  title: string;
  subtitle?: string;
  data?: any;
  config?: WidgetConfig;
  refreshInterval?: number;
  lastUpdated?: string;
}

export interface WidgetConfig {
  // Metric widget
  value?: number | string;
  previousValue?: number;
  target?: number;
  trend?: MetricTrend;
  trendValue?: number;
  format?: 'number' | 'currency' | 'percentage' | 'duration';
  prefix?: string;
  suffix?: string;
  color?: string;
  icon?: string;

  // Chart widget
  chartType?: ChartType;
  xAxis?: AxisConfig;
  yAxis?: AxisConfig;
  series?: ChartSeries[];
  legend?: boolean;
  tooltip?: boolean;
  colors?: string[];

  // Pipeline widget
  stages?: PipelineStage[];
  totalValue?: number;
  conversion?: number;
  velocity?: number;

  // Leaderboard widget
  entries?: LeaderboardEntry[];
  metric?: string;
  showChange?: boolean;
  limit?: number;

  // AI Insights widget
  insights?: AIInsight[];
  priority?: 'all' | 'high' | 'medium' | 'low';
  category?: string[];

  // Table widget
  columns?: TableColumn[];
  rows?: any[];
  sortable?: boolean;
  filterable?: boolean;
  paginated?: boolean;
  pageSize?: number;

  // Forecast widget
  forecastPeriod?: string;
  confidence?: number;
  scenarios?: ForecastScenario[];
}

export interface AxisConfig {
  label?: string;
  type?: 'category' | 'value' | 'time';
  min?: number;
  max?: number;
  format?: string;
  gridLines?: boolean;
}

export interface ChartSeries {
  name: string;
  data: Array<{
    x: any;
    y: any;
    label?: string;
    meta?: any;
  }>;
  type?: ChartType;
  color?: string;
  stack?: string;
  yAxisIndex?: number;
}

export interface PipelineStage {
  name: string;
  value: number;
  count: number;
  conversion?: number;
  averageTime?: number;
  deals?: Array<{
    id: string;
    name: string;
    value: number;
    daysInStage: number;
  }>;
}

export interface LeaderboardEntry {
  rank: number;
  previousRank?: number;
  name: string;
  avatar?: string;
  value: number;
  change?: number;
  percentOfTarget?: number;
  metadata?: Record<string, any>;
}

export interface AIInsight {
  id: string;
  type: 'opportunity' | 'risk' | 'recommendation' | 'anomaly' | 'trend';
  priority: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  impact?: string;
  action?: string;
  owner?: string;
  deadline?: string;
  confidence: number;
  data?: any;
  createdAt: string;
}

export interface TableColumn {
  key: string;
  label: string;
  type?: 'text' | 'number' | 'date' | 'boolean' | 'link' | 'badge' | 'avatar';
  sortable?: boolean;
  filterable?: boolean;
  width?: number;
  format?: string;
  align?: 'left' | 'center' | 'right';
}

export interface ForecastScenario {
  name: string;
  probability: number;
  value: number;
  assumptions: string[];
  color?: string;
}

// Streaming Metrics
export interface MetricUpdate {
  type: 'metric_update' | 'celebration' | 'alert' | 'notification';
  metric?: string;
  value?: any;
  change?: number;
  message?: string;
  severity?: 'info' | 'success' | 'warning' | 'error';
  timestamp: string;
}

// Insights
export interface Insights {
  daily: DailyInsights;
  alerts: Alert[];
  recommendations: Recommendation[];
  anomalies: Anomaly[];
}

export interface DailyInsights {
  date: string;
  summary: string;
  keyMetrics: Array<{
    name: string;
    value: number;
    change: number;
    trend: MetricTrend;
  }>;
  topPerformers: Array<{
    name: string;
    metric: string;
    value: number;
  }>;
  attentionRequired: Array<{
    issue: string;
    impact: string;
    action: string;
    owner: string;
    deadline: string;
  }>;
  opportunities: AIInsight[];
  risks: AIInsight[];
}

export interface Alert {
  id: string;
  type: 'churn_risk' | 'deal_risk' | 'sla_breach' | 'quota_risk' | 'anomaly' | 'system';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  message: string;
  probability?: number;
  impact?: string;
  action?: string;
  owner?: string;
  deadline?: string;
  data?: any;
  createdAt: string;
  acknowledged?: boolean;
  resolvedAt?: string;
}

export interface Recommendation {
  id: string;
  category: string;
  title: string;
  description: string;
  expectedImpact: string;
  effort: 'low' | 'medium' | 'high';
  priority: 'high' | 'medium' | 'low';
  action: string;
  data?: any;
  confidence: number;
  createdAt: string;
}

export interface Anomaly {
  id: string;
  metric: string;
  type: 'spike' | 'drop' | 'pattern_break' | 'outlier';
  severity: 'high' | 'medium' | 'low';
  description: string;
  value: number;
  expectedValue: number;
  deviation: number;
  timestamp: string;
  possibleCauses?: string[];
  recommendedAction?: string;
}

// Reports
export interface Report {
  id: string;
  name: string;
  description?: string;
  type: 'standard' | 'custom' | 'scheduled';
  format: 'pdf' | 'excel' | 'csv' | 'html' | 'json';
  schedule?: ReportSchedule;
  filters?: ReportFilter[];
  sections: ReportSection[];
  metadata?: Record<string, any>;
  createdBy: string;
  createdAt: string;
  lastGenerated?: string;
}

export interface ReportSchedule {
  frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly';
  dayOfWeek?: number; // 0-6
  dayOfMonth?: number; // 1-31
  time?: string; // HH:MM
  timezone?: string;
  recipients: string[];
  enabled: boolean;
}

export interface ReportFilter {
  field: string;
  operator: string;
  value: any;
  label?: string;
}

export interface ReportSection {
  id: string;
  title: string;
  type: 'summary' | 'table' | 'chart' | 'text' | 'metrics';
  data?: any;
  config?: any;
  order: number;
}

export interface ReportQuery {
  dataSource: string;
  query?: string;
  filters?: ReportFilter[];
  groupBy?: string[];
  orderBy?: Array<{
    field: string;
    direction: 'asc' | 'desc';
  }>;
  limit?: number;
  aggregations?: Array<{
    field: string;
    function: 'sum' | 'avg' | 'count' | 'min' | 'max';
    alias?: string;
  }>;
}

// Analytics Metrics
export interface AnalyticsMetrics {
  sales: SalesMetrics;
  marketing: MarketingMetrics;
  customer: CustomerMetrics;
  operational: OperationalMetrics;
  financial: FinancialMetrics;
}

export interface SalesMetrics {
  revenue: number;
  revenueTarget: number;
  newDeals: number;
  closedDeals: number;
  lostDeals: number;
  winRate: number;
  averageDealSize: number;
  salesCycle: number;
  pipelineValue: number;
  forecastValue: number;
  quotaAttainment: number;
  activityMetrics: {
    calls: number;
    emails: number;
    meetings: number;
    demos: number;
  };
}

export interface MarketingMetrics {
  leads: number;
  mqls: number;
  sqls: number;
  conversionRate: number;
  costPerLead: number;
  campaignROI: number;
  websiteTraffic: number;
  emailEngagement: {
    sent: number;
    opened: number;
    clicked: number;
    converted: number;
  };
  socialEngagement: {
    followers: number;
    engagement: number;
    reach: number;
  };
}

export interface CustomerMetrics {
  totalCustomers: number;
  newCustomers: number;
  churnRate: number;
  nps: number;
  csat: number;
  lifetimeValue: number;
  retentionRate: number;
  upsellRate: number;
  supportTickets: number;
  averageResponseTime: number;
}

export interface OperationalMetrics {
  efficiency: number;
  productivity: number;
  utilization: number;
  slaCompliance: number;
  dataQuality: number;
  systemUptime: number;
  apiCalls: number;
  storageUsed: number;
  activeUsers: number;
  concurrentSessions: number;
}

export interface FinancialMetrics {
  arr: number; // Annual Recurring Revenue
  mrr: number; // Monthly Recurring Revenue
  grossMargin: number;
  burnRate: number;
  runway: number; // months
  cashFlow: number;
  dso: number; // Days Sales Outstanding
  cac: number; // Customer Acquisition Cost
  ltv: number; // Lifetime Value
  ltvCacRatio: number;
}