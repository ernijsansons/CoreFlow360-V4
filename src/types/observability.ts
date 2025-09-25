// CoreFlow360 V4 - Observability Platform Types

export interface LogEntry {
  // Core Fields
  timestamp: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  businessId: string;
  userId?: string;
  sessionId?: string;

  // Request Context
  requestId: string;
  method?: string;
  path?: string;
  statusCode?: number;
  latencyMs?: number;

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

  // Log Level
  level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';

  // Custom Fields
  metadata: Record<string, any>;
}

export interface MetricPoint {
  timestamp: string;
  businessId: string;
  metricName: string;
  metricType: 'counter' | 'gauge' | 'histogram' | 'summary';
  value: number;
  count?: number;
  labels?: Record<string, string>;
}

export interface TraceContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  flags: number;
  baggage?: Record<string, string>;
}

export interface Span {
  spanId: string;
  traceId: string;
  parentSpanId?: string;
  serviceName: string;
  operationName: string;
  startTime: Date;
  endTime?: Date;
  durationMs?: number;
  status: 'ok' | 'error' | 'timeout';
  statusMessage?: string;
  spanKind?: 'client' | 'server' | 'internal' | 'producer' | 'consumer';
  tags: Record<string, any>;
  logs: LogEvent[];
}

export interface LogEvent {
  timestamp: Date;
  fields: Record<string, any>;
}

export interface Trace {
  traceId: string;
  businessId: string;
  userId?: string;
  serviceName: string;
  operationName: string;
  startTime: Date;
  endTime?: Date;
  durationMs?: number;
  status: 'ok' | 'error' | 'timeout';
  statusMessage?: string;
  tags: Record<string, any>;
  spans: Span[];
}

export interface AlertRule {
  id: string;
  businessId: string;
  name: string;
  description?: string;
  query: string;
  condition: AlertCondition;
  thresholdValue?: number;
  thresholdOperator: 'gt' | 'lt' | 'eq' | 'ne' | 'gte' | 'lte';
  evaluationWindow: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  notificationChannels: string[];
  escalationRules?: EscalationRule[];
  useMlAnomalyDetection: boolean;
  mlSensitivity: number;
  mlModelType?: 'isolation-forest' | 'prophet' | 'arima';
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface AlertCondition {
  metric: string;
  aggregation: 'avg' | 'sum' | 'count' | 'min' | 'max' | 'p50' | 'p95' | 'p99';
  groupBy?: string[];
  filters?: Record<string, string>;
  timeWindow: string;
}

export interface EscalationRule {
  level: number;
  delay: string; // ISO 8601 duration
  channels: string[];
  recipients?: string[];
}

export interface Alert {
  id: string;
  ruleId: string;
  businessId: string;
  title: string;
  description?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'firing' | 'resolved' | 'silenced';
  triggeredAt: Date;
  resolvedAt?: Date;
  metricValue?: number;
  thresholdValue?: number;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  resolvedBy?: string;
  resolutionNote?: string;
  fingerprint: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface NotificationChannel {
  id: string;
  businessId: string;
  name: string;
  type: 'email' | 'sms' | 'slack' | 'webhook' | 'pagerduty' | 'teams' | 'discord';
  enabled: boolean;
  config: NotificationChannelConfig;
  rateLimitEnabled: boolean;
  rateLimitCount: number;
  rateLimitWindow: number;
  lastTestAt?: Date;
  lastTestStatus?: 'success' | 'failed';
  lastTestError?: string;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface NotificationChannelConfig {
  // Email
  smtpHost?: string;
  smtpPort?: number;
  smtpUser?: string;
  smtpPassword?: string;
  fromEmail?: string;
  toEmails?: string[];

  // SMS
  twilioAccountSid?: string;
  twilioAuthToken?: string;
  fromPhone?: string;
  toPhones?: string[];

  // Slack
  slackWebhookUrl?: string;
  slackChannel?: string;
  slackToken?: string;

  // Webhook
  webhookUrl?: string;
  webhookHeaders?: Record<string, string>;
  webhookTimeout?: number;

  // PagerDuty
  pagerdutyIntegrationKey?: string;

  // Teams
  teamsWebhookUrl?: string;

  // Discord
  discordWebhookUrl?: string;
}

export interface Anomaly {
  id: string;
  modelId: string;
  businessId: string;
  timestamp: Date;
  metricName: string;
  actualValue: number;
  predictedValue?: number;
  anomalyScore: number;
  severity?: 'low' | 'medium' | 'high';
  confidence: number;
  labels: Record<string, string>;
  explanation?: string;
  reviewed: boolean;
  reviewedBy?: string;
  reviewNote?: string;
  createdAt: Date;
}

export interface MLModel {
  id: string;
  businessId: string;
  name: string;
  type: 'isolation-forest' | 'prophet' | 'lstm' | 'arima';
  targetMetric: string;
  hyperparameters: Record<string, any>;
  trainingDataQuery: string;
  trainingPeriod: string;
  status: 'training' | 'ready' | 'error';
  accuracyScore?: number;
  lastTrainedAt?: Date;
  modelArtifactUrl?: string;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface Dashboard {
  id: string;
  businessId: string;
  name: string;
  description?: string;
  layout: DashboardLayout;
  visibility: 'private' | 'team' | 'public';
  sharedWith: string[];
  refreshInterval: number;
  timeRange: string;
  variables: DashboardVariable[];
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface DashboardLayout {
  panels: DashboardPanel[];
  grid: {
    columns: number;
    rowHeight: number;
  };
}

export interface DashboardPanel {
  id: string;
  title: string;
  type: 'chart' | 'table' | 'stat' | 'logs' | 'heatmap' | 'gauge';
  position: {
    x: number;
    y: number;
    w: number;
    h: number;
  };
  query: string;
  dataSource: string;
  visualizationConfig: any;
  displayOptions: any;
}

export interface DashboardVariable {
  name: string;
  type: 'query' | 'custom' | 'constant';
  query?: string;
  options?: string[];
  defaultValue?: string;
  multiSelect: boolean;
}

export interface CostTrackingEntry {
  id: string;
  timestamp: Date;
  businessId: string;
  userId?: string;
  workflowId?: string;
  documentId?: string;
  module?: string;
  capability?: string;
  aiProvider?: string;
  aiModel?: string;
  promptTokens?: number;
  completionTokens?: number;
  costCents: number;
  requestId?: string;
  traceId?: string;
  metadata?: Record<string, any>;
}

export interface ServicePerformance {
  id: string;
  timestamp: Date;
  businessId: string;
  serviceName: string;
  endpoint?: string;
  method?: string;
  requestCount: number;
  errorCount: number;
  avgLatencyMs: number;
  p50LatencyMs?: number;
  p95LatencyMs?: number;
  p99LatencyMs?: number;
  avgCpuPercent?: number;
  avgMemoryMB?: number;
  maxMemoryMB?: number;
  windowStart: Date;
  windowEnd: Date;
}

export interface AnalyticsEnginePoint {
  blobs: string[];
  doubles: number[];
  indexes: string[];
}

export interface AlertNotification {
  id: string;
  alertId: string;
  channelType: string;
  channelConfig: any;
  recipient: string;
  status: 'pending' | 'sent' | 'failed' | 'delivered';
  sentAt?: Date;
  deliveredAt?: Date;
  responseCode?: number;
  responseMessage?: string;
  errorMessage?: string;
  retryCount: number;
  nextRetryAt?: Date;
  createdAt: Date;
}

export interface MetricAggregation {
  id: string;
  timestamp: Date;
  businessId: string;
  metricName: string;
  aggregationPeriod: '1m' | '5m' | '15m' | '1h' | '6h' | '1d';
  count: number;
  sum: number;
  min: number;
  max: number;
  avg: number;
  p50?: number;
  p95?: number;
  p99?: number;
  labelsHash: string;
  labels: Record<string, string>;
  createdAt: Date;
}

export interface SelfHealingAction {
  type: 'SCALE_UP' | 'SCALE_DOWN' | 'RESTART' |
  'ROLLBACK' | 'THROTTLE' | 'CIRCUIT_BREAK' | 'CLEAR_CACHE' | 'ADJUST_LIMITS';
  service?: string;
  instances?: number;
  version?: string;
  endpoint?: string;
  metadata?: Record<string, any>;
}

export interface ExportRequest {
  id: string;
  businessId: string;
  format: 'prometheus' | 'opentelemetry' | 'datadog' | 'json' | 'csv';
  query: string;
  timeRange: {
    start: Date;
    end: Date;
  };
  filters?: Record<string, any>;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  downloadUrl?: string;
  errorMessage?: string;
  requestedBy: string;
  createdAt: Date;
  completedAt?: Date;
}

export interface StreamMetrics {
  type: 'metrics' | 'logs' | 'traces' | 'alerts';
  data: any;
  timestamp: Date;
  metadata?: Record<string, any>;
}