/**
 * Workflow Orchestrator Types for Durable Objects
 * Comprehensive type definitions for workflow management
 */

import { z } from 'zod';

/**
 * Workflow step status
 */
export type StepStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'skipped'
  | 'waiting_approval'
  | 'timeout'
  | 'cancelled'
  | 'rolled_back';

/**
 * Workflow execution status
 */
export type WorkflowStatus =
  | 'created'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'rolling_back'
  | 'rolled_back';

/**
 * Step execution mode
 */
export type StepExecutionMode = 'sequential' | 'parallel' | 'conditional';

/**
 * Cost tracking for workflow steps
 */
export interface StepCost {
  computeUnits: number;
  storageBytes: number;
  networkCalls: number;
  aiTokens: number;
  customCosts: Record<string, number>;
  totalUSD: number;
}

/**
 * Individual workflow step definition
 */
export interface WorkflowStep {
  id: string;
  name: string;
  description?: string;
  type: 'action' | 'approval' | 'condition' | 'parallel_group' | 'sub_workflow';

  // Execution configuration
  executionMode: StepExecutionMode;
  dependsOn: string[]; // Step IDs this step depends on
  parallelGroup?: string; // Group ID for parallel execution
  retryPolicy?: {
    maxRetries: number;
    backoffMs: number;
    exponentialBackoff: boolean;
  };

  // Timeout configuration
  timeoutMs?: number;
  approvalTimeoutMs?: number; // For approval steps

  // Step implementation
  handler: string; // Handler function name or reference
  parameters: Record<string, unknown>;

  // Conditions for conditional execution
  condition?: {
    expression: string; // JavaScript expression
    variables: Record<string, unknown>;
  };

  // Rollback configuration
  rollbackHandler?: string;
  rollbackParameters?: Record<string, unknown>;
  canRollback: boolean;

  // Approval configuration (for approval type steps)
  approvalConfig?: {
    requiredApprovers: string[]; // User IDs
    requiredCount: number; // Minimum approvals needed
    allowSelfApproval: boolean;
    escalationChain?: string[]; // User IDs for escalation
    escalationDelayMs?: number;
  };

  // Cost estimation
  estimatedCost?: StepCost;
}

/**
 * Step execution result
 */
export interface StepExecutionResult {
  stepId: string;
  status: StepStatus;
  startTime: number;
  endTime?: number;
  duration?: number;

  // Execution details
  output?: unknown;
  error?: {
    message: string;
    code?: string;
    stack?: string;
    retryable: boolean;
  };

  // Cost tracking
  actualCost: StepCost;

  // Approval tracking (for approval steps)
  approvals?: {
    userId: string;
    decision: 'approve' | 'reject';
    timestamp: number;
    comment?: string;
  }[];

  // Retry tracking
  retryCount: number;
  retryHistory: {
    attempt: number;
    timestamp: number;
    error?: string;
  }[];

  // Metadata
  executionId: string;
  correlationId: string;
  metadata?: Record<string, unknown>;
}

/**
 * Workflow definition
 */
export interface WorkflowDefinition {
  id: string;
  name: string;
  description?: string;
  version: string;

  // Workflow configuration
  steps: WorkflowStep[];
  globalTimeout?: number;

  // Rollback configuration
  autoRollbackOnFailure: boolean;
  rollbackTimeout?: number;

  // SSE configuration
  enableProgressUpdates: boolean;
  progressUpdateInterval?: number;

  // Cost limits
  maxCostUSD?: number;
  costAlertThresholds?: number[]; // Alert at these percentages

  // Metadata
  createdBy: string;
  createdAt: number;
  tags?: string[];
}

/**
 * Workflow execution instance
 */
export interface WorkflowExecution {
  id: string;
  workflowId: string;
  workflowVersion: string;
  status: WorkflowStatus;

  // Context
  businessId: string;
  userId: string;
  correlationId: string;

  // Execution tracking
  startTime: number;
  endTime?: number;
  duration?: number;

  // Step tracking
  steps: Map<string, StepExecutionResult>;
  currentSteps: string[]; // Currently executing step IDs
  completedSteps: string[];
  failedSteps: string[];

  // Parallel execution tracking
  parallelGroups: Map<string, {
    groupId: string;
    stepIds: string[];
    status: 'running' | 'completed' | 'failed';
    startTime: number;
    endTime?: number;
  }>;

  // Variables and context
  variables: Record<string, unknown>;
  output?: unknown;

  // Cost tracking
  totalCost: StepCost;
  costHistory: {
    stepId: string;
    cost: StepCost;
    timestamp: number;
  }[];

  // Error tracking
  error?: {
    message: string;
    code?: string;
    failedStepId?: string;
    timestamp: number;
  };

  // Rollback tracking
  rollbackSteps: string[]; // Steps that have been rolled back
  rollbackInProgress: boolean;

  // Approval tracking
  pendingApprovals: {
    stepId: string;
    requiredApprovers: string[];
    currentApprovals: string[];
    deadline: number;
  }[];

  // Metadata
  metadata?: Record<string, unknown>;
  lastUpdateTime: number;
}

/**
 * Alarm configuration for timeout management
 */
export interface WorkflowAlarm {
  id: string;
  workflowExecutionId: string;
  type: 'step_timeout' | 'approval_timeout' | 'workflow_timeout' | 'cost_limit';
  stepId?: string; // For step-specific alarms
  scheduledTime: number;
  data: Record<string, unknown>;
  active: boolean;
}

/**
 * SSE event for workflow progress
 */
export interface WorkflowProgressEvent {
  workflowExecutionId: string;
  type: 'step_started' | 'step_completed' | 'step_failed' | 'approval_requested' | 'cost_updated' | 'workflow_completed' | 'workflow_failed';
  stepId?: string;
  timestamp: number;
  data: {
    status?: WorkflowStatus | StepStatus;
    progress?: {
      completed: number;
      total: number;
      percentage: number;
    };
    cost?: StepCost;
    totalCost?: StepCost;
    error?: string;
    approvalRequired?: {
      stepId: string;
      requiredApprovers: string[];
      deadline: number;
    };
    metadata?: Record<string, unknown>;
  };
}

/**
 * Workflow orchestrator configuration
 */
export interface WorkflowOrchestratorConfig {
  maxConcurrentWorkflows: number;
  maxStepsPerWorkflow: number;
  defaultStepTimeoutMs: number;
  defaultApprovalTimeoutMs: number;
  progressUpdateIntervalMs: number;
  alarmCheckIntervalMs: number;
  enableSSEUpdates: boolean;
  enableMetrics: boolean;
  costTrackingEnabled: boolean;
}

/**
 * Step handler interface
 */
export interface StepHandler {
  execute(
    step: WorkflowStep,
    context: {
      variables: Record<string, unknown>;
      workflowId: string;
      executionId: string;
      stepId: string;
      correlationId: string;
      businessId: string;
      userId: string;
    }
  ): Promise<{
    success: boolean;
    output?: unknown;
    cost?: Partial<StepCost>;
    error?: string;
    metadata?: Record<string, unknown>;
  }>;

  rollback?(
    step: WorkflowStep,
    context: {
      variables: Record<string, unknown>;
      workflowId: string;
      executionId: string;
      stepId: string;
      correlationId: string;
      businessId: string;
      userId: string;
      originalOutput?: unknown;
    }
  ): Promise<{
    success: boolean;
    error?: string;
    metadata?: Record<string, unknown>;
  }>;
}

/**
 * Workflow orchestrator state for Durable Object persistence
 */
export interface WorkflowOrchestratorState {
  executions: Map<string, WorkflowExecution>;
  alarms: Map<string, WorkflowAlarm>;
  config: WorkflowOrchestratorConfig;
  metrics: {
    totalExecutions: number;
    completedExecutions: number;
    failedExecutions: number;
    totalStepsExecuted: number;
    totalCostUSD: number;
    averageExecutionTime: number;
  };
  lastCleanup: number;
}

/**
 * Default configuration
 */
export const DEFAULT_WORKFLOW_CONFIG: WorkflowOrchestratorConfig = {
  maxConcurrentWorkflows: 100,
  maxStepsPerWorkflow: 1000,
  defaultStepTimeoutMs: 300000, // 5 minutes
  defaultApprovalTimeoutMs: 86400000, // 24 hours
  progressUpdateIntervalMs: 5000, // 5 seconds
  alarmCheckIntervalMs: 30000, // 30 seconds
  enableSSEUpdates: true,
  enableMetrics: true,
  costTrackingEnabled: true,
};

/**
 * Validation schemas
 */
export const StepCostSchema = z.object({
  computeUnits: z.number().min(0),
  storageBytes: z.number().min(0),
  networkCalls: z.number().min(0),
  aiTokens: z.number().min(0),
  customCosts: z.record(z.number()),
  totalUSD: z.number().min(0),
});

export const WorkflowStepSchema = z.object({
  id: z.string().min(1).max(128),
  name: z.string().min(1).max(256),
  description: z.string().max(1000).optional(),
  type: z.enum(['action', 'approval', 'condition', 'parallel_group', 'sub_workflow']),
  executionMode: z.enum(['sequential', 'parallel', 'conditional']),
  dependsOn: z.array(z.string()),
  parallelGroup: z.string().optional(),
  retryPolicy: z.object({
    maxRetries: z.number().min(0).max(10),
    backoffMs: z.number().min(100).max(60000),
    exponentialBackoff: z.boolean(),
  }).optional(),
  timeoutMs: z.number().min(1000).max(3600000).optional(), // 1s to 1h
  approvalTimeoutMs: z.number().min(60000).max(86400000).optional(), // 1m to 24h
  handler: z.string().min(1),
  parameters: z.record(z.unknown()),
  condition: z.object({
    expression: z.string(),
    variables: z.record(z.unknown()),
  }).optional(),
  rollbackHandler: z.string().optional(),
  rollbackParameters: z.record(z.unknown()).optional(),
  canRollback: z.boolean(),
  approvalConfig: z.object({
    requiredApprovers: z.array(z.string()),
    requiredCount: z.number().min(1),
    allowSelfApproval: z.boolean(),
    escalationChain: z.array(z.string()).optional(),
    escalationDelayMs: z.number().optional(),
  }).optional(),
  estimatedCost: StepCostSchema.optional(),
});

export const WorkflowDefinitionSchema = z.object({
  id: z.string().min(1).max(128),
  name: z.string().min(1).max(256),
  description: z.string().max(1000).optional(),
  version: z.string().min(1).max(32),
  steps: z.array(WorkflowStepSchema).min(1).max(1000),
  globalTimeout: z.number().min(60000).max(86400000).optional(), // 1m to 24h
  autoRollbackOnFailure: z.boolean(),
  rollbackTimeout: z.number().min(30000).max(3600000).optional(), // 30s to 1h
  enableProgressUpdates: z.boolean(),
  progressUpdateInterval: z.number().min(1000).max(60000).optional(),
  maxCostUSD: z.number().min(0).optional(),
  costAlertThresholds: z.array(z.number().min(0).max(100)).optional(),
  createdBy: z.string().min(1),
  createdAt: z.number(),
  tags: z.array(z.string()).optional(),
});

/**
 * Error types
 */
export class WorkflowError extends Error {
  constructor(
    message: string,
    public code: string,
    public workflowId?: string,
    public stepId?: string,
    public retryable = false
  ) {
    super(message);
    this.name = 'WorkflowError';
  }
}

export class StepTimeoutError extends WorkflowError {
  constructor(stepId: string, timeoutMs: number) {
    super(`Step ${stepId} timed out after ${timeoutMs}ms`, 'STEP_TIMEOUT', undefined, stepId, true);
  }
}

export class ApprovalTimeoutError extends WorkflowError {
  constructor(stepId: string, timeoutMs: number) {
    super(`Approval for step ${stepId} timed out after ${timeoutMs}ms`, 'APPROVAL_TIMEOUT', undefined, stepId, false);
  }
}

export class CostLimitExceededError extends WorkflowError {
  constructor(currentCost: number, limit: number) {
    super(`Workflow cost ${currentCost} exceeds limit ${limit}`, 'COST_LIMIT_EXCEEDED', undefined, undefined, false);
  }
}

export class WorkflowValidationError extends WorkflowError {
  constructor(message: string, field?: string) {
    super(`Workflow validation failed: ${message}`, 'VALIDATION_ERROR', undefined, undefined, false);
  }
}