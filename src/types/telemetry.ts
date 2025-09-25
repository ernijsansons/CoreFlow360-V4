export interface LogEntry {
  // Core Fields
  timestamp: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  businessId: string;
  userId: string;
  sessionId: string;

  // Request Context
  requestId: string;
  method: string;
  path: string;
  statusCode: number;
  latencyMs: number;

  // AI Context
  aiModel?: string;
  promptTokens?: number;
  completionTokens?: number;
  aiCostCents?: number;
  aiProvider?: string;

  // Business Context
  module: string;
  capability: string;
  workflowId?: string;
  documentId?: string;

  // Performance Metrics
  cpuMs?: number;
  memoryMB?: number;
  ioOps?: number;
  cacheHit?: boolean;

  // Error Context
  error?: {
    type: string;
    message: string;
    stack?: string;
    userMessage: string;
  };

  // Custom Fields
  metadata: Record<string, any>;
}

export interface Span {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  operationName: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  tags: Record<string, any>;
  logs: Array<{
    timestamp: number;
    fields: Record<string, any>;
  }>;
  status: 'ok' | 'error' | 'timeout';
}

export interface Metric {
  name: string;
  value: number;
  timestamp: number;
  tags: Record<string, string>;
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
}

export interface Alert {
  id: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'firing' | 'resolved' | 'acknowledged';
  message: string;
  timestamp: number;
  resolvedAt?: number;
  acknowledgedAt?: number;
  acknowledgedBy?: string;
  source: string;
  metadata: Record<string, any>;
  channels: string[];
  escalationLevel: number;
  correlatedAlerts: string[];
}

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  condition: string;
  threshold: number;
  operator: 'gt' | 'lt' | 'eq' | 'ne' | 'gte' | 'lte';
  duration: number;
  severity: Alert['severity'];
  channels: string[];
  enabled: boolean;
  tags: Record<string, string>;
  metadata: Record<string, any>;
}

export interface BusinessMetric {
  revenue: number;
  activeUsers: number;
  featureUsage: Record<string, number>;
  conversionRate: number;
  churnRate: number;
  customerSatisfaction: number;
}

export interface AIMetric {
  totalTokens: number;
  promptTokens: number;
  completionTokens: number;
  costCents: number;
  requestCount: number;
  averageLatency: number;
  errorRate: number;
  model: string;
  provider: string;
}

export interface InfrastructureMetric {
  cpuUsagePercent: number;
  memoryUsagePercent: number;
  diskUsagePercent: number;
  networkInBytes: number;
  networkOutBytes: number;
  activeConnections: number;
  requestsPerSecond: number;
}

export interface GoldenSignals {
  latency: {
    p50: number;
    p95: number;
    p99: number;
    p999: number;
  };
  traffic: {
    requestsPerSecond: number;
    bytesPerSecond: number;
  };
  errors: {
    errorRate: number;
    errorCount: number;
  };
  saturation: {
    cpuUsage: number;
    memoryUsage: number;
    diskUsage: number;
  };
}

export interface AnalyticsData {
  timestamp: number;
  businessId: string;
  metrics: {
    golden: GoldenSignals;
    business: BusinessMetric;
    ai: AIMetric;
    infrastructure: InfrastructureMetric;
  };
  dimensions: Record<string, string>;
}

export interface ClickhouseEvent {
  event_time: string;
  business_id: string;
  user_id: string;
  session_id: string;
  trace_id: string;
  span_id: string;
  event_type: string;
  event_name: string;
  properties: string; // JSON string
  metrics: string; // JSON string
}

export interface DashboardConfig {
  id: string;
  name: string;
  description: string;
  layout: Array<{
    i: string;
    x: number;
    y: number;
    w: number;
    h: number;
    widget: WidgetConfig;
  }>;
  filters: Record<string, any>;
  timeRange: {
    start: string;
    end: string;
    relative?: string;
  };
  refreshInterval: number;
}

export interface WidgetConfig {
  type: 'chart' | 'table' | 'stat' | 'heatmap' | 'topology' | 'alert-list';
  title: string;
  query: string;
  visualization: {
    chartType?: 'line' | 'bar' | 'pie' | 'scatter' | 'area';
    aggregation?: 'sum' | 'avg' | 'max' | 'min' | 'count';
    groupBy?: string[];
  };
  thresholds?: Array<{
    value: number;
    color: string;
    condition: 'gt' | 'lt';
  }>;
}

export interface ExportConfig {
  format: 'csv' | 'json' | 'pdf' | 'prometheus' | 'opentelemetry';
  destination: 'download' | 's3' | 'email' | 'webhook';
  schedule?: {
    cron: string;
    timezone: string;
  };
  filters: Record<string, any>;
  fields: string[];
}

export interface ComplianceReport {
  id: string;
  type: 'sla' | 'audit' | 'security' | 'cost' | 'performance';
  period: {
    start: string;
    end: string;
  };
  metrics: Record<string, any>;
  violations: Array<{
    rule: string;
    severity: string;
    count: number;
    examples: any[];
  }>;
  summary: {
    compliance_score: number;
    total_incidents: number;
    resolved_incidents: number;
    average_resolution_time: number;
  };
}

export interface SelfHealingAction {
  id: string;
  type: 'scale_up' | 'scale_down' | 'restart' | 'rollback' | 'throttle' | 'circuit_breaker';
  target: string;
  parameters: Record<string, any>;
  condition: string;
  cooldown: number;
  enabled: boolean;
  autoApprove: boolean;
}

export interface TraceContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  baggage?: Record<string, string>;
}

export interface SearchQuery {
  query: string;
  filters: Record<string, any>;
  timeRange: {
    start: string;
    end: string;
  };
  limit: number;
  offset: number;
  orderBy: string;
  orderDirection: 'asc' | 'desc';
}