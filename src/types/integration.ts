// Integration and Automation Types

export type IntegrationType =
  | 'marketing'
  | 'sales'
  | 'communication'
  | 'enrichment'
  | 'analytics'
  | 'accounting'
  | 'calendar'
  | 'document'
  | 'payment';

export type IntegrationStatus = 'connected' | 'disconnected' | 'error' | 'syncing';

export interface Integration {
  id: string;
  name: string;
  type: IntegrationType;
  provider: string;
  status: IntegrationStatus;
  credentials?: Record<string, any>;
  config: IntegrationConfig;
  lastSync?: string;
  nextSync?: string;
  metadata?: Record<string, any>;
  createdAt: string;
  updatedAt: string;
}

export interface IntegrationConfig {
  apiKey?: string;
  apiSecret?: string;
  accessToken?: string;
  refreshToken?: string;
  webhookUrl?: string;
  syncInterval?: number; // minutes
  syncDirection: 'inbound' | 'outbound' | 'bidirectional';
  fieldMappings?: FieldMapping[];
  filters?: Record<string, any>;
  options?: Record<string, any>;
}

export interface FieldMapping {
  sourceField: string;
  targetField: string;
  transform?: string; // JS expression or function name
  defaultValue?: any;
}

export interface SyncResult {
  integrationId: string;
  status: 'success' | 'partial' | 'failed';
  recordsSynced: number;
  recordsFailed: number;
  errors?: SyncError[];
  startTime: string;
  endTime: string;
  duration: number; // milliseconds
}

export interface SyncError {
  recordId?: string;
  field?: string;
  error: string;
  timestamp: string;
}

// Workflow Types
export type TriggerType =
  | 'webhook'
  | 'schedule'
  | 'event'
  | 'manual'
  | 'condition';

export type ActionType =
  | 'send_email'
  | 'send_sms'
  | 'make_call'
  | 'create_task'
  | 'update_field'
  | 'assign_lead'
  | 'score_lead'
  | 'enrich_data'
  | 'create_invoice'
  | 'send_notification'
  | 'http_request'
  | 'custom_code'
  | 'ai_action';

export interface Trigger {
  id: string;
  type: TriggerType;
  name: string;
  description: string;
  config: TriggerConfig;
  conditions?: Condition[];
  enabled: boolean;
}

export interface TriggerConfig {
  // For webhook
  webhookUrl?: string;

  // For schedule
  cron?: string;
  timezone?: string;

  // For event
  eventName?: string;
  eventSource?: string;

  // For condition
  checkInterval?: number;
  conditionExpression?: string;
}

export interface Action {
  id: string;
  type: ActionType;
  name: string;
  description: string;
  config: ActionConfig;
  retryPolicy?: RetryPolicy;
  errorHandler?: ErrorHandler;
  timeout?: number;
}

export interface ActionConfig {
  // Email action
  to?: string | string[];
  subject?: string;
  body?: string;
  templateId?: string;

  // SMS action
  phoneNumber?: string;
  message?: string;

  // Call action
  callTo?: string;
  callScript?: string;

  // Field update
  field?: string;
  value?: any;
  operation?: 'set' | 'append' | 'increment' | 'decrement';

  // HTTP request
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  payload?: any;

  // Custom code
  code?: string;
  runtime?: 'javascript' | 'python';

  // AI action
  prompt?: string;
  model?: string;
  temperature?: number;

  // Common
  integrationId?: string;
  parameters?: Record<string, any>;
}

export interface Condition {
  field: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'starts_with' | 'ends_with' |
           'greater_than' | 'less_than' | 'in' | 'not_in' | 'is_empty' | 'is_not_empty';
  value: any;
  logicalOperator?: 'AND' | 'OR';
}

export interface RetryPolicy {
  maxRetries: number;
  retryDelay: number; // milliseconds
  backoffMultiplier?: number;
  maxDelay?: number;
}

export interface ErrorHandler {
  type: 'ignore' | 'stop' | 'alternative_action' | 'notification';
  alternativeActionId?: string;
  notificationChannels?: string[];
  customHandler?: string; // Function name or code
}

export interface Workflow {
  id: string;
  name: string;
  description: string;
  trigger: Trigger;
  actions: WorkflowAction[];
  status: 'active' | 'inactive' | 'draft' | 'archived';
  version: number;
  tags?: string[];
  metrics?: WorkflowMetrics;
  createdBy?: string;
  createdAt: string;
  updatedAt: string;
}

export interface WorkflowAction extends Action {
  order: number;
  conditions?: Condition[];
  parallel?: boolean;
  dependsOn?: string[]; // Action IDs
}

export interface WorkflowMetrics {
  totalRuns: number;
  successfulRuns: number;
  failedRuns: number;
  averageDuration: number;
  lastRun?: string;
  nextScheduledRun?: string;
}

export interface WorkflowExecution {
  id: string;
  workflowId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  triggeredBy: string;
  triggeredAt: string;
  completedAt?: string;
  duration?: number;
  steps: WorkflowStep[];
  context: Record<string, any>;
  error?: string;
}

export interface WorkflowStep {
  actionId: string;
  actionName: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  startTime?: string;
  endTime?: string;
  duration?: number;
  input?: any;
  output?: any;
  error?: string;
  retryCount?: number;
}

// Automation Builder Types
export interface AutomationTemplate {
  id: string;
  name: string;
  category: string;
  description: string;
  trigger: Trigger;
  actions: Action[];
  variables?: Variable[];
  tags: string[];
  popularity: number;
  successRate?: number;
}

export interface Variable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'date';
  defaultValue?: any;
  required: boolean;
  description?: string;
  validation?: string; // Regex or JS expression
}

export interface AutomationRequest {
  description: string;
  context?: Record<string, any>;
  preferences?: {
    complexity?: 'simple' | 'moderate' | 'complex';
    errorHandling?: 'strict' | 'lenient';
    performance?: 'optimize_speed' | 'optimize_reliability';
  };
}

export interface AutomationSuggestion {
  workflow: Workflow;
  confidence: number;
  explanation: string;
  alternatives?: Workflow[];
  estimatedTime?: number;
  requiredIntegrations?: string[];
}