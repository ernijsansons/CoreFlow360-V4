/**
 * Agent Orchestrator with Future-Proof Router
 * Manages task execution across single or multiple agents
 */

import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import {
  AgentTask,
  BusinessContext,
  OrchestratorResult,
  OrchestratorError,
  Workflow,
  WorkflowResult,
  WorkflowStep,
  WorkflowStepResult,
  ExecutionStep,
  IAgent,
  AgentResult,
  TaskConstraints,
  AGENT_CONSTANTS
} from './types';
import { AgentRegistry } from './registry';
import { AgentMemory } from './memory';
import { CostTracker } from './cost-tracker';
import { CostReservationManager } from './cost-reservation-manager';
import { RetryHandler } from './retry-handler';
import { Logger } from '../../shared/logger';
import { CorrelationId } from '../../shared/security-utils';
import { AuditLogger, AuditEventType } from './audit-logger';
import { IdempotencyManager } from './idempotency-manager';

export class AgentOrchestrator {
  private logger: Logger;
  private registry: AgentRegistry;
  private memory: AgentMemory;
  private costTracker: CostTracker;
  private costReservationManager: CostReservationManager;
  private retryHandler: RetryHandler;
  private auditLogger: AuditLogger;
  private idempotencyManager: IdempotencyManager;
  private activeExecutions = new Map<string, ExecutionContext>();

  constructor(
    registry: AgentRegistry,
    memory: AgentMemory,
    costTracker: CostTracker,
    retryHandler: RetryHandler,
    kv: KVNamespace,
    db: D1Database
  ) {
    this.logger = new Logger();
    this.registry = registry;
    this.memory = memory;
    this.costTracker = costTracker;
    this.costReservationManager = new CostReservationManager(kv, db);
    this.retryHandler = retryHandler;
    this.auditLogger = AuditLogger.getInstance(db);
    this.idempotencyManager = new IdempotencyManager(kv, {
      ttlSeconds: 300,
      maxRetries: 3,
      enableCaching: true,
      cacheOnlySuccess: true
    });
  }

  /**
   * Execute a single task with intelligent agent selection
   */
  async executeTask(task: AgentTask): Promise<OrchestratorResult> {
    // Check for idempotent cached result
    const existingResult = await this.idempotencyManager.checkExisting(task);
    if (existingResult.exists && existingResult.result) {
      this.logger.info('Returning cached idempotent result', {
        taskId: task.id,
        originalTaskId: existingResult.record?.taskId,
        cacheAge: Date.now() - (existingResult.record?.createdAt || 0)
      });
      return existingResult.result;
    }

    // Create execution promise for idempotency tracking
    const executionPromise = this.executeTaskInternal(task);

    // Register execution for duplicate prevention
    await this.idempotencyManager.registerExecution(task, executionPromise);

    try {
      const result = await executionPromise;

      // Store successful result for future idempotency
      if (result.success) {
        await this.idempotencyManager.storeResult(task, result);
      }

      return result;
    } catch (error: any) {
      // Invalidate cache on error
      await this.idempotencyManager.invalidate(task);
      throw error;
    }
  }

  /**
   * Internal task execution logic
   */
  private async executeTaskInternal(task: AgentTask): Promise<OrchestratorResult> {
    const executionId = CorrelationId.generate();
    const startTime = Date.now();
    const executionPath: ExecutionStep[] = [];

    try {
      this.logger.info('Starting task execution', {
        taskId: task.id,
        executionId,
        capability: task.capability,
        department: task.context.department,
        priority: task.priority,
      });

      // Step 1: Select best agent
      executionPath.push({
        step: 'agent_selection',
        startTime: Date.now(),
      });

      const agent = this.registry.selectAgent(task);
      const selectedAgentId = agent.id;

      executionPath[executionPath.length - 1].endTime = Date.now();
      executionPath[executionPath.length - 1].success = true;
      executionPath[executionPath.length - 1].agentId = selectedAgentId;

      this.logger.debug('Agent selected for task', {
        taskId: task.id,
        selectedAgent: selectedAgentId,
        capability: task.capability,
      });

      // Step 2: Validate constraints and reserve cost
      executionPath.push({
        step: 'constraint_validation_and_cost_reservation',
        startTime: Date.now(),
        agentId: selectedAgentId,
      });

      // Estimate cost for reservation
      const estimatedCost = agent.estimateCost(task);

      // Create cost reservation
      const reservation = await this.costReservationManager.reserve(
        task.context.businessId,
        task.context.userId,
        task.id,
        selectedAgentId,
        estimatedCost,
        { capability: task.capability, department: task.context.department }
      );

      if (!reservation.success) {
        executionPath[executionPath.length - 1].endTime = Date.now();
        executionPath[executionPath.length - 1].success = false;
        executionPath[executionPath.length - 1].error = reservation.reason;

        await this.auditLogger.log(
          AuditEventType.TASK_FAILED,
          'high',
          task.context.businessId,
          task.context.userId,
          { reason: 'Cost reservation failed', details: reservation.reason },
          { taskId: task.id, agentId: selectedAgentId }
        );

        return this.createErrorResult(
          task.id,
          executionId,
          reservation.reason || 'Cost reservation failed',
          executionPath,
          startTime
        );
      }

      const reservationId = reservation.reservationId!;

      // Validate other constraints
      const constraintValidation = await this.validateConstraints(task, agent);
      if (!constraintValidation.valid) {
        // Release reservation if constraints fail
        await this.costReservationManager.release(reservationId, 'Constraint validation failed');

        executionPath[executionPath.length - 1].endTime = Date.now();
        executionPath[executionPath.length - 1].success = false;
        executionPath[executionPath.length - 1].error = constraintValidation.reason;

        return this.createErrorResult(
          task.id,
          executionId,
          constraintValidation.reason,
          executionPath,
          startTime
        );
      }

      executionPath[executionPath.length - 1].endTime = Date.now();
      executionPath[executionPath.length - 1].success = true;
      executionPath[executionPath.length - 1].cost = estimatedCost;

      // Step 3: Load relevant memory
      executionPath.push({
        step: 'memory_loading',
        startTime: Date.now(),
        agentId: selectedAgentId,
      });

      task.context.memory = await this.memory.load(
        task.context.businessId,
        task.context.sessionId || task.id
      );

      executionPath[executionPath.length - 1].endTime = Date.now();
      executionPath[executionPath.length - 1].success = true;

      // Step 4: Track execution start
      const executionContext: ExecutionContext = {
        taskId: task.id,
        executionId,
        agentId: selectedAgentId,
        startTime: Date.now(),
        status: 'running',
      };
      this.activeExecutions.set(executionId, executionContext);

      // Step 5: Execute with telemetry and retry logic
      executionPath.push({
        step: 'task_execution',
        startTime: Date.now(),
        agentId: selectedAgentId,
      });

      let result: AgentResult;
      try {
        result = await this.retryHandler.executeWithRetry(
          agent,
          task,
          task.context,
          3 // max attempts
        );

        // Commit the reservation with actual cost
        await this.costReservationManager.commit(reservationId, result.metrics.cost);

        executionPath[executionPath.length - 1].endTime = Date.now();
        executionPath[executionPath.length - 1].success = result.success;
        executionPath[executionPath.length - 1].cost = result.metrics.cost;

        if (!result.success) {
          executionPath[executionPath.length - 1].error = result.error;
        }

        // Log task completion
        await this.auditLogger.log(
          result.success ? AuditEventType.TASK_COMPLETED : AuditEventType.TASK_FAILED,
          result.success ? 'low' : 'medium',
          task.context.businessId,
          task.context.userId,
          {
            taskId: task.id,
            success: result.success,
            actualCost: result.metrics.cost,
            estimatedCost,
            latency: result.metrics.latency
          },
          { taskId: task.id, agentId: selectedAgentId }
        );

      } catch (error: any) {
        // Release reservation on execution failure
        await this.costReservationManager.release(reservationId, 'Task execution failed');

        executionPath[executionPath.length - 1].endTime = Date.now();
        executionPath[executionPath.length - 1].success = false;
        executionPath[executionPath.length - 1].error = error instanceof Error ? error.message : 'Unknown error';

        throw error;
      }

      // Step 6: Update metrics and costs
      executionPath.push({
        step: 'metrics_tracking',
        startTime: Date.now(),
        agentId: selectedAgentId,
      });

      await this.updateMetricsAndCosts(result, task, selectedAgentId);

      executionPath[executionPath.length - 1].endTime = Date.now();
      executionPath[executionPath.length - 1].success = true;

      // Step 7: Save to memory
      if (result.success) {
        executionPath.push({
          step: 'memory_saving',
          startTime: Date.now(),
          agentId: selectedAgentId,
        });

        await this.memory.save(
          task.context.businessId,
          task.context.sessionId || task.id,
          result
        );

        executionPath[executionPath.length - 1].endTime = Date.now();
        executionPath[executionPath.length - 1].success = true;
      }

      // Clean up execution tracking
      this.activeExecutions.delete(executionId);

      const totalLatency = Date.now() - startTime;

      this.logger.info('Task execution completed', {
        taskId: task.id,
        executionId,
        success: result.success,
        selectedAgent: selectedAgentId,
        totalLatency,
        totalCost: result.metrics.cost,
      });

      return {
        taskId: task.id,
        success: result.success,
        result,
        selectedAgent: selectedAgentId,
        alternatives: this.getAlternativeAgents(task, selectedAgentId),
        executionPath,
        totalCost: result.metrics.cost,
        totalLatency,
      };

    } catch (error: any) {
      this.activeExecutions.delete(executionId);

      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      this.logger.error('Task execution failed', error, {
        taskId: task.id,
        executionId,
        capability: task.capability,
      });

      return this.createErrorResult(
        task.id,
        executionId,
        errorMessage,
        executionPath,
        startTime
      );
    }
  }

  /**
   * Execute a workflow with multiple steps (ready for multi-agent coordination)
   */
  async executeWorkflow(workflow: Workflow): Promise<WorkflowResult> {
    const startTime = Date.now();
    const results: WorkflowStepResult[] = [];
    let totalCost = 0;

    this.logger.info('Starting workflow execution', {
      workflowId: workflow.id,
      stepCount: workflow.steps.length,
    });

    try {
      // For now: sequential execution
      // Future: parallel, conditional, loops
      for (let i = 0; i < workflow.steps.length; i++) {
        const step = workflow.steps[i];

        this.logger.debug('Executing workflow step', {
          workflowId: workflow.id,
          stepId: step.id,
          stepIndex: i,
          capability: step.capability,
        });

        // Check dependencies
        if (step.dependencies && step.dependencies.length > 0) {
          const dependenciesMet = step.dependencies.every(depId =>
            results.some(r => r.stepId === depId && r.success)
          );

          if (!dependenciesMet) {
            const missingDeps = step.dependencies.filter((depId: any) =>
              !results.some(r => r.stepId === depId && r.success)
            );

            this.logger.warn('Workflow step dependencies not met', {
              workflowId: workflow.id,
              stepId: step.id,
              missingDependencies: missingDeps,
            });

            if (step.required) {
              return {
                workflowId: workflow.id,
                success: false,
                steps: results,
                totalCost,
                totalLatency: Date.now() - startTime,
                error: `Dependencies not met for required step ${step.id}: ${missingDeps.join(', ')}`,
              };
            } else {
              // Skip optional step
              results.push({
                stepId: step.id,
                agentId: 'skipped',
                success: false,
                error: 'Dependencies not met',
                cost: 0,
                latency: 0,
              });
              continue;
            }
          }
        }

        // Convert workflow step to agent task
        const task = this.workflowStepToTask(step, workflow);

        // Execute the task
        const stepStartTime = Date.now();
        try {
          const orchestratorResult = await this.executeTask(task);
          const stepLatency = Date.now() - stepStartTime;
          const stepCost = orchestratorResult.result?.metrics.cost || 0;

          totalCost += stepCost;

          const stepResult: WorkflowStepResult = {
            stepId: step.id,
            agentId: orchestratorResult.selectedAgent || 'unknown',
            success: orchestratorResult.success,
            result: orchestratorResult.result?.data,
            error: orchestratorResult.result?.error,
            cost: stepCost,
            latency: stepLatency,
          };

          results.push(stepResult);

          if (!orchestratorResult.success && step.required) {
            this.logger.error('Required workflow step failed', {
              workflowId: workflow.id,
              stepId: step.id,
              error: orchestratorResult.result?.error,
            });

            return {
              workflowId: workflow.id,
              success: false,
              steps: results,
              totalCost,
              totalLatency: Date.now() - startTime,
              error: `Required step ${step.id} failed: ${orchestratorResult.result?.error}`,
            };
          }

        } catch (error: any) {
          const stepError = error instanceof Error ? error.message : 'Unknown error';

          results.push({
            stepId: step.id,
            agentId: 'error',
            success: false,
            error: stepError,
            cost: 0,
            latency: Date.now() - stepStartTime,
          });

          if (step.required) {
            return {
              workflowId: workflow.id,
              success: false,
              steps: results,
              totalCost,
              totalLatency: Date.now() - startTime,
              error: `Required step ${step.id} failed: ${stepError}`,
            };
          }
        }
      }

      const totalLatency = Date.now() - startTime;
      const success = results.every(r => r.success || !workflow.steps.find(s => s.id === r.stepId)?.required);

      this.logger.info('Workflow execution completed', {
        workflowId: workflow.id,
        success,
        totalSteps: workflow.steps.length,
        successfulSteps: results.filter((r: any) => r.success).length,
        totalCost,
        totalLatency,
      });

      return {
        workflowId: workflow.id,
        success,
        steps: results,
        totalCost,
        totalLatency,
      };

    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      this.logger.error('Workflow execution failed', error, {
        workflowId: workflow.id,
      });

      return {
        workflowId: workflow.id,
        success: false,
        steps: results,
        totalCost,
        totalLatency: Date.now() - startTime,
        error: errorMessage,
      };
    }
  }

  /**
   * Get active executions for monitoring
   */
  getActiveExecutions(): ExecutionContext[] {
    return Array.from(this.activeExecutions.values());
  }

  /**
   * Cancel an active execution
   */
  async cancelExecution(executionId: string, reason: string = 'User cancelled'): Promise<boolean> {
    const execution = this.activeExecutions.get(executionId);
    if (!execution) {
      return false;
    }

    execution.status = 'cancelled';
    execution.cancelReason = reason;
    execution.endTime = Date.now();

    this.logger.info('Execution cancelled', {
      executionId,
      taskId: execution.taskId,
      reason,
      duration: execution.endTime - execution.startTime,
    });

    return true;
  }

  /**
   * Get orchestrator statistics
   */
  getStatistics(): {
    activeExecutions: number;
    totalExecutions: number;
    averageLatency: number;
    successRate: number;
    totalCost: number;
    registryStats: any;
  } {
    const registryStats = this.registry.getStatistics();
    const costStats = this.costTracker.getStatistics();

    return {
      activeExecutions: this.activeExecutions.size,
      totalExecutions: registryStats.totalTasks,
      averageLatency: registryStats.averageLatency,
      successRate: registryStats.averageSuccessRate,
      totalCost: registryStats.totalCost,
      registryStats,
    };
  }

  /**
   * Private helper methods
   */

  private async validateConstraints(task: AgentTask, agent: IAgent): Promise<{
    valid: boolean;
    reason?: string;
  }> {
    const constraints = task.constraints;
    if (!constraints) {
      return { valid: true };
    }

    // Check cost constraints (but actual reservation is handled separately)
    if (constraints.maxCost !== undefined) {
      const estimatedCost = agent.estimateCost(task);
      if (estimatedCost > constraints.maxCost) {
        return {
          valid: false,
        
   reason: `Estimated cost ($${estimatedCost.toFixed(2)}) exceeds maximum allowed ($${constraints.maxCost.toFixed(2)})`,
        };
      }
    }

    // Check agent capacity
    const agentEntry = this.registry.getAgentEntry(agent.id);
    if (agentEntry && agentEntry.loadBalancing.utilization >= 1.0) {
      return {
        valid: false,
        reason: `Agent ${agent.id} is at capacity`,
      };
    }

    return { valid: true };
  }

  private async updateMetricsAndCosts(
    result: AgentResult,
    task: AgentTask,
    agentId: string
  ): Promise<void> {
    try {
      // Update agent metrics
      this.registry.updateAgentMetrics(agentId, {
        taskCompleted: true,
        success: result.success,
        latency: result.metrics.latency,
        cost: result.metrics.cost,
      });

      // Track costs
      await this.costTracker.track({
        businessId: task.context.businessId,
        agentId,
        taskId: task.id,
        cost: result.metrics.cost,
        latency: result.metrics.latency,
        timestamp: Date.now(),
        success: result.success,
        capability: task.capability,
        department: task.context.department,
        userId: task.context.userId,
      });

    } catch (error: any) {
      this.logger.error('Failed to update metrics and costs', error, {
        taskId: task.id,
        agentId,
      });
    }
  }

  private getAlternativeAgents(task: AgentTask, excludeAgentId: string): string[] {
    const allAgents = this.registry.getAgentsForCapability(task.capability);
    return allAgents
      .filter((agent: any) => agent.id !== excludeAgentId)
      .slice(0, 3) // Return top 3 alternatives
      .map((agent: any) => agent.id);
  }

  private workflowStepToTask(step: WorkflowStep, workflow: Workflow): AgentTask {
    // Create a business context for the workflow step
    const context: BusinessContext = {
      businessId: workflow.metadata?.businessId as string || 'unknown',
      userId: workflow.metadata?.userId as string || 'system',
      sessionId: workflow.id,
      timezone: workflow.metadata?.timezone as string || 'UTC',
      currency: workflow.metadata?.currency as string || 'USD',
      locale: workflow.metadata?.locale as string || 'en-US',
      permissions: workflow.metadata?.permissions as string[] || [],
    };

    return {
      id: `${workflow.id}_${step.id}`,
      capability: step.capability,
      input: step.input,
      context,
      constraints: {
        timeout: AGENT_CONSTANTS.DEFAULT_TIMEOUT,
        retryLimit: step.retryable ? 3 : 0,
      },
      metadata: {
        workflowId: workflow.id,
        stepId: step.id,
        required: step.required,
      },
    };
  }

  private createErrorResult(
    taskId: string,
    executionId: string,
    errorMessage: string,
    executionPath: ExecutionStep[],
    startTime: number
  ): OrchestratorResult {
    const error: OrchestratorError = {
      code: 'EXECUTION_FAILED',
      message: errorMessage,
      retryable: this.isRetryableError(errorMessage),
      suggestedActions: [
        'Check agent availability',
        'Verify task constraints',
        'Review input parameters',
      ],
    };

    return {
      taskId,
      success: false,
      error,
      executionPath,
      totalCost: 0,
      totalLatency: Date.now() - startTime,
    };
  }

  private isRetryableError(errorMessage: string): boolean {
    const retryablePatterns = [
      'timeout',
      'rate limit',
      'server error',
      'network error',
      'capacity',
      'temporary',
    ];

    const errorLower = errorMessage.toLowerCase();
    return retryablePatterns.some(pattern => errorLower.includes(pattern));
  }
}

/**
 * Execution context for tracking active tasks
 */
interface ExecutionContext {
  taskId: string;
  executionId: string;
  agentId: string;
  startTime: number;
  endTime?: number;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  cancelReason?: string;
}