/**
 * Core Agent System Types
 * Defines interfaces and types for the modular agent integration system
 */

import { z } from 'zod';

// ============================================================================
// CORE AGENT INTERFACES
// ============================================================================

/**
 * Universal agent interface that all agents must implement
 */
export interface IAgent {
  readonly id: string;
  readonly name: string;
  readonly type: AgentType;
  readonly capabilities: string[];
  readonly department?: string[];
  readonly costPerCall: number;
  readonly maxConcurrency: number;

  // Core methods every agent must implement
  execute(task: AgentTask, context: BusinessContext): Promise<AgentResult>;
  validateInput(input: unknown): ValidationResult;
  estimateCost(task: AgentTask): number;
  healthCheck(): Promise<HealthStatus>;
}

/**
 * Agent types for classification and routing
 */
export type AgentType = 'native' | 'external' | 'specialized' | 'custom';

/**
 * Task structure for agent execution
 */
export interface AgentTask {
  id: string;
  capability: string;
  input: unknown;
  context: BusinessContext;
  constraints?: TaskConstraints;
  metadata?: Record<string, unknown>;
  priority?: 'low' | 'normal' | 'high' | 'critical';
}

/**
 * Task constraints for execution control
 */
export interface TaskConstraints {
  maxCost?: number;
  maxLatency?: number;
  requiredAccuracy?: number;
  timeout?: number;
  retryLimit?: number;
}

/**
 * Business context for agent execution
 */
export interface BusinessContext {
  businessId: string;
  userId: string;
  sessionId?: string;
  department?: string;
  timezone: string;
  currency: string;
  locale: string;
  permissions: string[];
  memory?: MemoryContext;
  realTimeData?: Record<string, unknown>;
}

/**
 * Memory context for agents
 */
export interface MemoryContext {
  shortTerm: Memory;
  longTerm: Knowledge[];
  conversationHistory: ConversationEntry[];
}

/**
 * Agent execution result
 */
export interface AgentResult {
  taskId: string;
  agentId: string;
  success: boolean;
  data?: unknown;
  error?: string;
  confidence?: number;
  metrics: ExecutionMetrics;
  suggestions?: string[];
  nextActions?: NextAction[];
  retry?: boolean;
  debugInfo?: Record<string, unknown>;
}

/**
 * Execution metrics for monitoring
 */
export interface ExecutionMetrics {
  startTime: number;
  endTime: number;
  latency: number;
  cost: number;
  tokensUsed?: number;
  modelUsed?: string;
  retryCount: number;
  memoryHits: number;
}

/**
 * Agent health status
 */
export interface HealthStatus {
  healthy: boolean;
  status: 'online' | 'degraded' | 'offline';
  latency: number;
  lastCheck: number;
  errors?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Input validation result
 */
export interface ValidationResult {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
  sanitizedInput?: unknown;
}

// ============================================================================
// AGENT REGISTRY TYPES
// ============================================================================

/**
 * Agent registry entry with metadata
 */
export interface AgentRegistryEntry {
  agent: IAgent;
  config: AgentConfig;
  status: AgentStatus;
  health: HealthStatus;
  metrics: AgentMetrics;
  loadBalancing: LoadBalancingData;
  registeredAt: number;
  lastHealthCheck: number;
}

/**
 * Agent configuration
 */
export interface AgentConfig {
  id: string;
  name: string;
  type: AgentType;
  version: string;
  description: string;
  capabilities: string[];
  department?: string[];
  costPerCall: number;
  maxConcurrency: number;
  enabled: boolean;

  // Model configuration for AI agents
  model?: string;
  fallbackModels?: string[];
  maxTokens?: number;
  temperature?: number;

  // External agent configuration
  apiEndpoint?: string;
  webhookUrl?: string;
  apiKey?: string;
  headers?: Record<string, string>;

  // Feature flags
  streamingEnabled: boolean;
  cachingEnabled: boolean;
  retryEnabled: boolean;
  fallbackEnabled: boolean;

  // Metadata
  owner: string;
  tags: string[];
  documentation?: string;
  createdAt: number;
  updatedAt: number;
}

/**
 * Agent status tracking
 */
export type AgentStatus = 'active' | 'inactive' | 'degraded' | 'maintenance' | 'error';

/**
 * Agent performance metrics
 */
export interface AgentMetrics {
  totalTasks: number;
  successfulTasks: number;
  failedTasks: number;
  averageLatency: number;
  averageCost: number;
  totalCost: number;
  successRate: number;
  lastTaskAt?: number;
  errorRate: number;
  throughput: number; // tasks per minute
}

/**
 * Load balancing data
 */
export interface LoadBalancingData {
  activeConnections: number;
  queuedTasks: number;
  capacity: number;
  utilization: number;
  lastRequestAt?: number;
  priority: number;
}

// ============================================================================
// ORCHESTRATOR TYPES
// ============================================================================

/**
 * Orchestrator execution result
 */
export interface OrchestratorResult {
  taskId: string;
  success: boolean;
  result?: AgentResult;
  error?: OrchestratorError;
  selectedAgent?: string;
  alternatives?: string[];
  executionPath: ExecutionStep[];
  totalCost: number;
  totalLatency: number;
}

/**
 * Execution step tracking
 */
export interface ExecutionStep {
  step: string;
  agentId?: string;
  startTime: number;
  endTime?: number;
  success?: boolean;
  error?: string;
  cost?: number;
}

/**
 * Orchestrator error
 */
export interface OrchestratorError {
  code: string;
  message: string;
  retryable: boolean;
  suggestedActions?: string[];
}

/**
 * Workflow definition for multi-step tasks
 */
export interface Workflow {
  id: string;
  name: string;
  description: string;
  steps: WorkflowStep[];
  metadata?: Record<string, unknown>;
}

/**
 * Workflow step definition
 */
export interface WorkflowStep {
  id: string;
  capability: string;
  input: unknown;
  required: boolean;
  retryable: boolean;
  condition?: string;
  dependencies?: string[];
}

/**
 * Workflow execution result
 */
export interface WorkflowResult {
  workflowId: string;
  success: boolean;
  steps: WorkflowStepResult[];
  totalCost: number;
  totalLatency: number;
  error?: string;
}

/**
 * Workflow step result
 */
export interface WorkflowStepResult {
  stepId: string;
  agentId: string;
  success: boolean;
  result?: unknown;
  error?: string;
  cost: number;
  latency: number;
}

// ============================================================================
// MEMORY SYSTEM TYPES
// ============================================================================

/**
 * Short-term memory structure
 */
export interface Memory {
  sessionId: string;
  businessId: string;
  userId: string;
  messages: MemoryMessage[];
  context: Record<string, unknown>;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
}

/**
 * Memory message entry
 */
export interface MemoryMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
  agentId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Long-term knowledge entry
 */
export interface Knowledge {
  id: string;
  businessId: string;
  topic: string;
  content: string;
  summary: string;
  embedding?: number[];
  relevance: number;
  confidence: number;
  source: string;
  createdAt: number;
  updatedAt: number;
  accessCount: number;
  lastAccessed: number;
}

/**
 * Conversation history entry
 */
export interface ConversationEntry {
  id: string;
  taskId: string;
  agentId: string;
  input: unknown;
  output: unknown;
  timestamp: number;
  success: boolean;
  cost: number;
}

// ============================================================================
// CAPABILITY SYSTEM TYPES
// ============================================================================

/**
 * Capability contract definition
 */
export interface CapabilityContract {
  name: string;
  description: string;
  version: string;
  category: string;
  inputSchema: JSONSchema;
  outputSchema: JSONSchema;
  requiredPermissions: string[];
  supportedAgents: string[];
  estimatedLatency: number;
  estimatedCost: number;
  examples: CapabilityExample[];
  documentation: string;
  deprecated?: boolean;
  replacedBy?: string;
}

/**
 * JSON Schema type
 */
export interface JSONSchema {
  type: string;
  properties?: Record<string, JSONSchema>;
  required?: string[];
  items?: JSONSchema;
  enum?: unknown[];
  format?: string;
  pattern?: string;
  minimum?: number;
  maximum?: number;
}

/**
 * Capability example
 */
export interface CapabilityExample {
  name: string;
  description: string;
  input: unknown;
  expectedOutput: unknown;
  constraints?: TaskConstraints;
}

// ============================================================================
// COST TRACKING TYPES
// ============================================================================

/**
 * Cost tracking metrics
 */
export interface CostMetrics {
  businessId: string;
  agentId: string;
  taskId: string;
  cost: number;
  latency: number;
  timestamp: number;
  success: boolean;
  capability: string;
  department?: string;
  userId: string;
}

/**
 * Cost breakdown
 */
export interface CostBreakdown {
  inputTokens: number;
  outputTokens: number;
  modelCost: number;
  processingCost: number;
  storageCost: number;
  total: number;
}

/**
 * Cost limits configuration
 */
export interface CostLimits {
  daily: number;
  monthly: number;
  perTask: number;
  perAgent: number;
  currency: string;
}

// ============================================================================
// STREAMING TYPES
// ============================================================================

/**
 * Streaming response chunk
 */
export interface StreamingChunk {
  type: 'start' | 'data' | 'tool' | 'error' | 'end';
  agentId: string;
  taskId: string;
  data?: unknown;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

/**
 * Streaming configuration
 */
export interface StreamingConfig {
  enabled: boolean;
  bufferSize: number;
  flushInterval: number;
  compression: boolean;
  heartbeat: boolean;
  heartbeatInterval: number;
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/**
 * Base agent error
 */
export class AgentError extends Error {
  constructor(
    message: string,
    public code: string,
    public agentId?: string,
    public retryable: boolean = false
  ) {
    super(message);
    this.name = 'AgentError';
  }
}

/**
 * Agent not found error
 */
export class AgentNotFoundError extends AgentError {
  constructor(agentId: string) {
    super(`Agent '${agentId}' not found`, 'AGENT_NOT_FOUND', agentId, false);
  }
}

/**
 * Agent unavailable error
 */
export class AgentUnavailableError extends AgentError {
  constructor(agentId: string, reason: string) {
    super(`Agent '${agentId}' unavailable: ${reason}`, 'AGENT_UNAVAILABLE', agentId, true);
  }
}

/**
 * Capability not supported error
 */
export class CapabilityNotSupportedError extends AgentError {
  constructor(capability: string, agentId: string) {
    super(`Capability '${capability}' not supported by agent '${agentId}'`, 'CAPABILITY_NOT_SUPPORTED', agentId, false);
  }
}

/**
 * Cost limit exceeded error
 */
export class CostLimitExceededError extends AgentError {
  constructor(current: number, limit: number) {
    super(`Cost limit exceeded: ${current} > ${limit}`, 'COST_LIMIT_EXCEEDED', undefined, false);
  }
}

/**
 * Validation error
 */
export class ValidationError extends AgentError {
  constructor(message: string, agentId?: string) {
    super(message, 'VALIDATION_ERROR', agentId, false);
  }
}

// ============================================================================
// NEXT ACTION TYPES
// ============================================================================

/**
 * Suggested next action
 */
export interface NextAction {
  type: 'task' | 'workflow' | 'approval' | 'manual';
  capability?: string;
  description: string;
  priority: 'low' | 'normal' | 'high';
  estimatedCost?: number;
  estimatedTime?: number;
  requiredPermissions?: string[];
}

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

export const AgentTaskSchema = z.object({
  id: z.string().min(1),
  capability: z.string().min(1),
  input: z.unknown(),
  context: z.object({
    businessId: z.string().min(1),
    userId: z.string().min(1),
    sessionId: z.string().optional(),
    department: z.string().optional(),
    timezone: z.string(),
    currency: z.string(),
    locale: z.string(),
    permissions: z.array(z.string()),
  }),
  constraints: z.object({
    maxCost: z.number().positive().optional(),
    maxLatency: z.number().positive().optional(),
    requiredAccuracy: z.number().min(0).max(1).optional(),
    timeout: z.number().positive().optional(),
    retryLimit: z.number().int().min(0).optional(),
  }).optional(),
  metadata: z.record(z.unknown()).optional(),
  priority: z.enum(['low', 'normal', 'high', 'critical']).optional(),
});

export const AgentConfigSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  type: z.enum(['native', 'external', 'specialized', 'custom']),
  version: z.string().min(1),
  description: z.string(),
  capabilities: z.array(z.string()).min(1),
  department: z.array(z.string()).optional(),
  costPerCall: z.number().min(0),
  maxConcurrency: z.number().int().min(1),
  enabled: z.boolean(),
  model: z.string().optional(),
  fallbackModels: z.array(z.string()).optional(),
  maxTokens: z.number().int().positive().optional(),
  temperature: z.number().min(0).max(2).optional(),
  apiEndpoint: z.string().url().optional(),
  webhookUrl: z.string().url().optional(),
  streamingEnabled: z.boolean(),
  cachingEnabled: z.boolean(),
  retryEnabled: z.boolean(),
  fallbackEnabled: z.boolean(),
  owner: z.string().min(1),
  tags: z.array(z.string()),
  documentation: z.string().optional(),
  createdAt: z.number(),
  updatedAt: z.number(),
});

export const CapabilityContractSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  version: z.string().min(1),
  category: z.string().min(1),
  inputSchema: z.record(z.unknown()),
  outputSchema: z.record(z.unknown()),
  requiredPermissions: z.array(z.string()),
  supportedAgents: z.array(z.string()),
  estimatedLatency: z.number().min(0),
  estimatedCost: z.number().min(0),
  examples: z.array(z.object({
    name: z.string(),
    description: z.string(),
    input: z.unknown(),
    expectedOutput: z.unknown(),
  })),
  documentation: z.string(),
  deprecated: z.boolean().optional(),
  replacedBy: z.string().optional(),
});

// ============================================================================
// CONSTANTS
// ============================================================================

export const AGENT_CONSTANTS = {
  MAX_CONCURRENCY: 1000,
  DEFAULT_TIMEOUT: 30000, // 30 seconds
  MAX_RETRIES: 3,
  HEALTH_CHECK_INTERVAL: 30000, // 30 seconds
  METRICS_UPDATE_INTERVAL: 60000, // 1 minute
  MEMORY_TTL: 3600, // 1 hour
  KNOWLEDGE_TTL: 86400 * 30, // 30 days
  MAX_WORKFLOW_STEPS: 50,
  MAX_MEMORY_SIZE: 10000, // characters
  MAX_KNOWLEDGE_SIZE: 50000, // characters
} as const;

export const DEPARTMENT_CAPABILITIES = {
  finance: [
    'financial.analysis',
    'budget.planning',
    'cost.analysis',
    'revenue.analysis',
    'cash_flow.management',
    'financial.reporting',
    'tax.planning',
    'audit.support',
    'investment.analysis',
    'risk.assessment',
    'compliance.monitoring',
    'invoice.processing'
  ],
  hr: [
    'resume.analysis',
    'employee.onboarding',
    'performance.management',
    'compensation.analysis',
    'benefits.administration',
    'policy.development',
    'compliance.monitoring',
    'training.coordination',
    'employee.relations',
    'recruitment.support',
    'organizational.development'
  ],
  sales: [
    'lead.qualification',
    'customer.analysis',
    'sales.forecasting',
    'proposal.generation',
    'crm.management',
    'pipeline.analysis',
    'competitor.analysis',
    'pricing.strategy',
    'contract.review',
    'revenue.tracking',
    'customer.segmentation'
  ],
  marketing: [
    'market.analysis',
    'campaign.planning',
    'content.strategy',
    'brand.management',
    'customer.segmentation',
    'competitive.analysis',
    'roi.analysis',
    'lead.generation',
    'social_media.strategy',
    'event.planning',
    'public.relations'
  ],
  operations: [
    'process.optimization',
    'quality.management',
    'supply_chain.analysis',
    'inventory.management',
    'vendor.management',
    'cost.optimization',
    'efficiency.analysis',
    'project.management',
    'risk.management',
    'compliance.monitoring',
    'performance.metrics'
  ],
  it: [
    'system.analysis',
    'security.assessment',
    'infrastructure.planning',
    'software.evaluation',
    'data.management',
    'cybersecurity',
    'backup.recovery',
    'user.support',
    'project.management',
    'vendor.management',
    'compliance.monitoring'
  ],
  legal: [
    'contract.review',
    'compliance.monitoring',
    'legal.research',
    'risk.assessment',
    'policy.development',
    'litigation.support',
    'regulatory.analysis',
    'intellectual_property',
    'employment.law',
    'corporate.governance',
    'dispute.resolution'
  ]
} as const;