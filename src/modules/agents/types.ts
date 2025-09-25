/**
 * Agent System Types and Interfaces
 * Modular design to support hundreds of specialized agents
 */

import { z } from 'zod';

/**
 * Core agent types
 */
export type AgentType = 'native' | 'external' | 'specialized' | 'custom';
export type AgentStatus = 'online' | 'offline' | 'degraded' | 'maintenance' | 'error';
export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'timeout';
export type TaskPriority = 'low' | 'normal' | 'high' | 'urgent';

/**
 * Business context for all agent interactions
 */
export interface BusinessContext {
  // User and business identity
  userId: string;
  businessId: string;
  tenantId?: string;
  sessionId?: string;
  correlationId: string;

  // Business data context
  businessData: {
    companyName: string;
    industry: string;
    size: 'startup' | 'small' | 'medium' | 'large' | 'enterprise';
    timezone: string;
    locale: string;
    currency: string;
    fiscalYearStart: string; // MM-DD format
  };

  // User context
  userContext: {
    name: string;
    email: string;
    role: string;
    department: string;
    permissions: string[];
    preferences: Record<string, unknown>;
  };

  // Current business state
  businessState?: {
    currentFiscalPeriod: string;
    activeProjects: string[];
    recentTransactions: Array<{
      id: string;
      date: string;
      amount: number;
      description: string;
      type: 'credit' | 'debit';
    }>;
    keyMetrics: Record<string, number>;
    alerts: Array<{
      id: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      message: string;
      timestamp: string;
    }>;
  };

  // Request context
  requestContext: {
    timestamp: number;
    ipAddress: string;
    userAgent: string;
    platform: string;
    requestId: string;
  };
}

/**
 * Agent task definition
 */
export interface AgentTask {
  // Task identity
  id: string;
  capability: string;
  type: 'query' | 'action' | 'analysis' | 'generation' | 'automation';
  priority: TaskPriority;

  // Task input
  input: {
    prompt?: string;
    data?: unknown;
    parameters?: Record<string, unknown>;
    files?: Array<{
      name: string;
      type: string;
      size: number;
      url: string;
    }>;
  };

  // Business context
  context: BusinessContext;

  // Task constraints
  constraints?: {
    maxCost?: number;
    maxLatency?: number;
    requiredAccuracy?: number;
    allowedModels?: string[];
    fallbackEnabled?: boolean;
    streamingEnabled?: boolean;
  };

  // Metadata
  metadata?: {
    department?: string;
    project?: string;
    tags?: string[];
    customFields?: Record<string, unknown>;
  };

  // Tracking
  createdAt: number;
  scheduledAt?: number;
  startedAt?: number;
  completedAt?: number;
  retryCount: number;
  parentTaskId?: string;
  childTaskIds?: string[];
}

/**
 * Agent result
 */
export interface AgentResult {
  // Result identity
  taskId: string;
  agentId: string;
  status: TaskStatus;

  // Result data
  result?: {
    data: unknown;
    confidence?: number;
    reasoning?: string;
    sources?: string[];
    artifacts?: Array<{
      type: string;
      name: string;
      url: string;
      metadata?: Record<string, unknown>;
    }>;
  };

  // Error information
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    retryable: boolean;
    category: 'validation' | 'permission' | 'cost' | 'rate_limit' | 'api' | 'system';
  };

  // Execution metrics
  metrics: {
    executionTime: number;
    tokensUsed?: number;
    costUSD: number;
    modelUsed?: string;
    retryCount: number;
    cacheHit?: boolean;
  };

  // Timestamps
  startedAt: number;
  completedAt: number;

  // Metadata
  metadata?: Record<string, unknown>;
}

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  errors?: Array<{
    field: string;
    code: string;
    message: string;
  }>;
  warnings?: Array<{
    field: string;
    message: string;
  }>;
  sanitizedInput?: unknown;
}

/**
 * Health status
 */
export interface HealthStatus {
  status: AgentStatus;
  latency?: number;
  errorRate?: number;
  lastCheck: number;
  details?: {
    apiConnectivity?: boolean;
    rateLimitStatus?: {
      remaining: number;
      resetAt: number;
    };
    memoryUsage?: number;
    activeConnections?: number;
    recentErrors?: string[];
  };
}

/**
 * Core agent interface - ALL agents must implement this
 */
export interface IAgent {
  // Agent identity
  readonly id: string;
  readonly name: string;
  readonly type: AgentType;
  readonly version: string;

  // Agent capabilities
  readonly capabilities: string[];
  readonly departments?: string[];
  readonly tags?: string[];

  // Agent characteristics
  readonly costPerCall: number;
  readonly maxConcurrency: number;
  readonly averageLatency: number;
  readonly supportedLanguages?: string[];
  readonly supportedFormats?: string[];

  // Core methods every agent MUST implement
  execute(task: AgentTask, context: BusinessContext): Promise<AgentResult>;
  validateInput(input: unknown, capability: string): Promise<ValidationResult>;
  estimateCost(task: AgentTask): Promise<number>;
  healthCheck(): Promise<HealthStatus>;

  // Optional methods for advanced agents
  initialize?(config: Record<string, unknown>): Promise<void>;
  cleanup?(): Promise<void>;
  updateConfig?(config: Record<string, unknown>): Promise<void>;
  getCapabilityDetails?(capability: string): CapabilityDetails | undefined;
}

/**
 * Capability details
 */
export interface CapabilityDetails {
  id: string;
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  examples: Array<{
    input: unknown;
    output: unknown;
    description: string;
  }>;
  constraints: {
    maxInputSize?: number;
    maxOutputSize?: number;
    timeoutMs?: number;
    costLimit?: number;
  };
  requiredPermissions: string[];
  department?: string;
}

/**
 * Agent configuration
 */
export interface AgentConfig {
  // Basic configuration
  id: string;
  name: string;
  type: AgentType;
  enabled: boolean;

  // Connection details
  apiEndpoint?: string;
  apiKey?: string;
  timeout?: number;
  retries?: number;

  // Model configuration
  model?: string;
  fallbackModels?: string[];
  temperature?: number;
  maxTokens?: number;

  // Behavior configuration
  systemPrompt?: string;
  departmentPrompts?: Record<string, string>;
  capabilities: string[];
  departments?: string[];

  // Resource limits
  maxConcurrency: number;
  costPerCall: number;
  rateLimitPerMinute?: number;
  memoryLimitMB?: number;

  // Feature flags
  streamingEnabled?: boolean;
  fallbackEnabled?: boolean;
  cachingEnabled?: boolean;
  loggingEnabled?: boolean;

  // Custom configuration
  customConfig?: Record<string, unknown>;

  // Metadata
  owner: string;
  description?: string;
  tags?: string[];
  createdAt: number;
  updatedAt: number;
}

/**
 * Agent registry entry
 */
export interface AgentRegistryEntry {
  config: AgentConfig;
  instance?: IAgent;
  metrics: {
    totalTasks: number;
    successfulTasks: number;
    failedTasks: number;
    averageLatency: number;
    totalCost: number;
    lastUsed?: number;
  };
  health: HealthStatus;
  loadBalancing: {
    weight: number;
    activeConnections: number;
    queueSize: number;
  };
}

/**
 * Task routing request
 */
export interface TaskRoutingRequest {
  task: AgentTask;
  preferences?: {
    preferredAgents?: string[];
    excludedAgents?: string[];
    costOptimized?: boolean;
    latencyOptimized?: boolean;
    accuracyOptimized?: boolean;
  };
  fallbackEnabled?: boolean;
}

/**
 * Task routing result
 */
export interface TaskRoutingResult {
  selectedAgent: string;
  reasoning: string;
  alternatives: Array<{
    agentId: string;
    score: number;
    reason: string;
  }>;
  estimatedCost: number;
  estimatedLatency: number;
}

/**
 * Memory record for agent context
 */
export interface MemoryRecord {
  id: string;
  type: 'conversation' | 'fact' | 'preference' | 'workflow' | 'decision';
  userId: string;
  businessId: string;
  agentId?: string;

  content: {
    summary: string;
    details: unknown;
    context: Record<string, unknown>;
  };

  relevance: {
    department?: string;
    capability?: string;
    keywords: string[];
    importance: number; // 0-1 scale
  };

  lifecycle: {
    createdAt: number;
    updatedAt: number;
    accessedAt: number;
    expiresAt?: number;
    version: number;
  };

  metadata?: Record<string, unknown>;
}

/**
 * Streaming response chunk
 */
export interface StreamingChunk {
  id: string;
  taskId: string;
  type: 'text' | 'function_call' | 'function_result' | 'metadata' | 'error' | 'complete';
  data: {
    content?: string;
    delta?: string;
    function?: {
      name: string;
      arguments: Record<string, unknown>;
    };
    metadata?: Record<string, unknown>;
    error?: {
      code: string;
      message: string;
    };
  };
  timestamp: number;
  sequence: number;
}

/**
 * Cost tracking record
 */
export interface CostRecord {
  id: string;
  taskId: string;
  agentId: string;
  userId: string;
  businessId: string;

  costs: {
    inputTokens: number;
    outputTokens: number;
    totalTokens: number;
    modelCost: number;
    processingCost: number;
    storageCost: number;
    totalCostUSD: number;
  };

  billing: {
    model: string;
    provider: string;
    region?: string;
    tier?: string;
    discountApplied?: number;
  };

  timestamp: number;
  metadata?: Record<string, unknown>;
}

/**
 * Retry configuration
 */
export interface RetryConfig {
  maxRetries: number;
  baseDelayMs: number;
  exponentialBackoff: boolean;
  jitterMs: number;
  retryableErrors: string[];
  nonRetryableErrors: string[];
  timeoutMs: number;
}

/**
 * Fallback configuration
 */
export interface FallbackConfig {
  enabled: boolean;
  triggers: Array<{
    condition: 'error' | 'timeout' | 'cost_limit' | 'rate_limit' | 'low_confidence';
    threshold?: number;
  }>;
  strategy: 'cheaper_model' | 'different_agent' | 'cached_response' | 'default_response';
  fallbackAgents?: string[];
  maxFallbacks: number;
}

/**
 * Department-specific prompt configuration
 */
export interface DepartmentPromptConfig {
  department: string;
  systemPrompt: string;
  contextInjection: {
    businessMetrics?: string[];
    recentData?: {
      type: string;
      daysBack: number;
      limit: number;
    }[];
    permissions?: string[];
  };
  responseFormat?: {
    style: 'professional' | 'casual' | 'technical' | 'executive';
    includeReferences: boolean;
    includeConfidence: boolean;
  };
  constraints?: {
    maxResponseLength?: number;
    requiredSections?: string[];
    prohibitedTopics?: string[];
  };
}

/**
 * Agent orchestrator configuration
 */
export interface OrchestratorConfig {
  // Routing configuration
  routing: {
    strategy: 'round_robin' | 'least_connections' | 'cost_optimized' | 'latency_optimized' | 'capability_based';
    fallbackEnabled: boolean;
    loadBalancingEnabled: boolean;
  };

  // Memory configuration
  memory: {
    shortTermEnabled: boolean;
    longTermEnabled: boolean;
    contextWindowSize: number;
    retentionPolicy: {
      conversationDays: number;
      factsDays: number;
      preferencesDays: number;
    };
  };

  // Cost management
  costManagement: {
    enabled: boolean;
    dailyLimitUSD?: number;
    monthlyLimitUSD?: number;
    alertThresholds: number[];
    costOptimizationEnabled: boolean;
  };

  // Performance settings
  performance: {
    caching: {
      enabled: boolean;
      ttlSeconds: number;
      maxCacheSize: number;
    };
    concurrent: {
      maxPerUser: number;
      maxGlobal: number;
      queueSize: number;
    };
    timeouts: {
      defaultTaskTimeout: number;
      healthCheckTimeout: number;
      streamingTimeout: number;
    };
  };

  // Monitoring
  monitoring: {
    metricsEnabled: boolean;
    healthCheckInterval: number;
    alertingEnabled: boolean;
    logLevel: 'error' | 'warn' | 'info' | 'debug';
  };
}

/**
 * Validation schemas
 */
export const BusinessContextSchema = z.object({
  userId: z.string().min(1),
  businessId: z.string().min(1),
  tenantId: z.string().optional(),
  sessionId: z.string().optional(),
  correlationId: z.string().min(1),
  businessData: z.object({
    companyName: z.string().min(1),
    industry: z.string().min(1),
    size: z.enum(['startup', 'small', 'medium', 'large', 'enterprise']),
    timezone: z.string(),
    locale: z.string(),
    currency: z.string().length(3),
    fiscalYearStart: z.string().regex(/^[0-9]{2}-[0-9]{2}$/),
  }),
  userContext: z.object({
    name: z.string().min(1),
    email: z.string().email(),
    role: z.string().min(1),
    department: z.string().min(1),
    permissions: z.array(z.string()),
    preferences: z.record(z.unknown()),
  }),
  businessState: z.object({
    currentFiscalPeriod: z.string(),
    activeProjects: z.array(z.string()),
    recentTransactions: z.array(z.unknown()),
    keyMetrics: z.record(z.number()),
    alerts: z.array(z.unknown()),
  }).optional(),
  requestContext: z.object({
    timestamp: z.number(),
    ipAddress: z.string(),
    userAgent: z.string(),
    platform: z.string(),
    requestId: z.string(),
  }),
});

export const AgentTaskSchema = z.object({
  id: z.string().min(1),
  capability: z.string().min(1),
  type: z.enum(['query', 'action', 'analysis', 'generation', 'automation']),
  priority: z.enum(['low', 'normal', 'high', 'urgent']),
  input: z.object({
    prompt: z.string().optional(),
    data: z.unknown().optional(),
    parameters: z.record(z.unknown()).optional(),
    files: z.array(z.object({
      name: z.string(),
      type: z.string(),
      size: z.number(),
      url: z.string().url(),
    })).optional(),
  }),
  context: BusinessContextSchema,
  constraints: z.object({
    maxCost: z.number().min(0).optional(),
    maxLatency: z.number().min(0).optional(),
    requiredAccuracy: z.number().min(0).max(1).optional(),
    allowedModels: z.array(z.string()).optional(),
    fallbackEnabled: z.boolean().optional(),
    streamingEnabled: z.boolean().optional(),
  }).optional(),
  metadata: z.object({
    department: z.string().optional(),
    project: z.string().optional(),
    tags: z.array(z.string()).optional(),
    customFields: z.record(z.unknown()).optional(),
  }).optional(),
  createdAt: z.number(),
  scheduledAt: z.number().optional(),
  startedAt: z.number().optional(),
  completedAt: z.number().optional(),
  retryCount: z.number().min(0),
  parentTaskId: z.string().optional(),
  childTaskIds: z.array(z.string()).optional(),
});

export const AgentConfigSchema = z.object({
  id: z.string().min(1).max(64),
  name: z.string().min(1).max(256),
  type: z.enum(['native', 'external', 'specialized', 'custom']),
  enabled: z.boolean(),
  apiEndpoint: z.string().url().optional(),
  apiKey: z.string().optional(),
  timeout: z.number().min(1000).max(300000).optional(),
  retries: z.number().min(0).max(10).optional(),
  model: z.string().optional(),
  fallbackModels: z.array(z.string()).optional(),
  temperature: z.number().min(0).max(2).optional(),
  maxTokens: z.number().min(1).max(200000).optional(),
  systemPrompt: z.string().optional(),
  departmentPrompts: z.record(z.string()).optional(),
  capabilities: z.array(z.string()).min(1),
  departments: z.array(z.string()).optional(),
  maxConcurrency: z.number().min(1).max(100),
  costPerCall: z.number().min(0),
  rateLimitPerMinute: z.number().min(1).optional(),
  memoryLimitMB: z.number().min(1).optional(),
  streamingEnabled: z.boolean().optional(),
  fallbackEnabled: z.boolean().optional(),
  cachingEnabled: z.boolean().optional(),
  loggingEnabled: z.boolean().optional(),
  customConfig: z.record(z.unknown()).optional(),
  owner: z.string().min(1),
  description: z.string().max(2000).optional(),
  tags: z.array(z.string()).optional(),
  createdAt: z.number(),
  updatedAt: z.number(),
});

/**
 * Error types
 */
export class AgentError extends Error {
  constructor(
    message: string,
    public code: string,
    public category: string = 'system',
    public retryable: boolean = false,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AgentError';
  }
}

export class AgentNotFoundError extends AgentError {
  constructor(agentId: string) {
    super(`Agent '${agentId}' not found`, 'AGENT_NOT_FOUND', 'validation', false, { agentId });
  }
}

export class CapabilityNotSupportedError extends AgentError {
  constructor(capability: string, agentId: string) {
    super(`Capability '${capability}' not supported by
  agent '${agentId}'`, 'CAPABILITY_NOT_SUPPORTED', 'validation', false, { capability, agentId });
  }
}

export class CostLimitExceededError extends AgentError {
  constructor(estimatedCost: number, limit: number) {
    super(`Estimated cost $${estimatedCost} exceeds
  limit $${limit}`, 'COST_LIMIT_EXCEEDED', 'cost', false, { estimatedCost, limit });
  }
}

export class RateLimitExceededError extends AgentError {
  constructor(agentId: string, resetAt?: number) {
    super(`Rate limit exceeded for
  agent '${agentId}'`, 'RATE_LIMIT_EXCEEDED', 'rate_limit', true, { agentId, resetAt });
  }
}

export class AgentUnavailableError extends AgentError {
  constructor(agentId: string, reason: string) {
    super(`Agent '${agentId}' is unavailable: ${reason}`, 'AGENT_UNAVAILABLE', 'system', true, { agentId, reason });
  }
}

/**
 * Constants
 */
export const AGENT_LIMITS = {
  MAX_TASK_SIZE_MB: 10,
  MAX_RESPONSE_SIZE_MB: 50,
  MAX_CONCURRENT_TASKS: 1000,
  MAX_MEMORY_RECORDS: 10000,
  MAX_RETRY_ATTEMPTS: 5,
  DEFAULT_TIMEOUT_MS: 60000,
  MAX_STREAMING_DURATION_MS: 300000,
} as const;

export const COST_LIMITS = {
  DEFAULT_DAILY_LIMIT_USD: 100,
  DEFAULT_MONTHLY_LIMIT_USD: 1000,
  DEFAULT_TASK_LIMIT_USD: 1,
  ALERT_THRESHOLDS: [0.5, 0.8, 0.95],
} as const;

export const DEPARTMENT_CAPABILITIES = {
  finance: [
    'financial_analysis',
    'budget_planning',
    'invoice_processing',
    'expense_analysis',
    'cash_flow_analysis',
    'compliance_reporting',
  ],
  hr: [
    'resume_analysis',
    'employee_onboarding',
    'performance_analysis',
    'policy_generation',
    'benefits_assistance',
    'training_recommendations',
  ],
  sales: [
    'lead_qualification',
    'proposal_generation',
    'market_analysis',
    'customer_insights',
    'pipeline_analysis',
    'contract_review',
  ],
  marketing: [
    'content_generation',
    'campaign_analysis',
    'audience_segmentation',
    'social_media_optimization',
    'seo_analysis',
    'brand_monitoring',
  ],
  operations: [
    'process_optimization',
    'inventory_analysis',
    'supplier_evaluation',
    'quality_control',
    'logistics_planning',
    'risk_assessment',
  ],
} as const;