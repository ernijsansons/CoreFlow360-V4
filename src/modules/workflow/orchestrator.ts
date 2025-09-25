/**
 * WorkflowOrchestrator Durable Object
 * Manages workflow execution with state persistence, parallel processing, and rollback
 */

import type { DurableObjectState, DurableObjectStorage } from '@cloudflare/workers-types';
import {
  WorkflowDefinition,
  WorkflowExecution,
  WorkflowStep,
  StepExecutionResult,
  WorkflowAlarm,
  WorkflowProgressEvent,
  WorkflowOrchestratorState,
  WorkflowOrchestratorConfig,
  StepHandler,
  StepStatus,
  WorkflowStatus,
  StepCost,
  WorkflowError,
  StepTimeoutError,
  ApprovalTimeoutError,
  CostLimitExceededError,
  DEFAULT_WORKFLOW_CONFIG,
  WorkflowDefinitionSchema
} from './types';
import { Logger } from '../../shared/logger';
import { SecurityError, InputValidator, CorrelationId } from '../../shared/security-utils';

export class WorkflowOrchestrator implements DurableObject {
  private state: DurableObjectState;
  private storage: DurableObjectStorage;
  private logger: Logger;
  private orchestratorState!: WorkflowOrchestratorState;
  private stepHandlers: Map<string, StepHandler> = new Map();
  private alarmTimer?: number;
  private progressTimer?: number;
  private sseConnections: Map<string, {
    writer: WritableStreamDefaultWriter<Uint8Array>;
    workflowIds: Set<string>;
  }> = new Map();

  constructor(state: DurableObjectState) {
    this.state = state;
    this.storage = state.storage;
    this.logger = new Logger();
    this.initializeState();
  }

  /**
   * Initialize orchestrator state from storage
   */
  private async initializeState(): Promise<void> {
    try {
      const storedState = await this.storage.get<WorkflowOrchestratorState>('orchestrator_state');

      if (storedState) {
        this.orchestratorState = {
          ...storedState,
          executions: new Map(Object.entries(storedState.executions || {})),
          alarms: new Map(Object.entries(storedState.alarms || {})),
        };
      } else {
        this.orchestratorState = {
          executions: new Map(),
          alarms: new Map(),
          config: { ...DEFAULT_WORKFLOW_CONFIG },
          metrics: {
            totalExecutions: 0,
            completedExecutions: 0,
            failedExecutions: 0,
            totalStepsExecuted: 0,
            totalCostUSD: 0,
            averageExecutionTime: 0,
          },
          lastCleanup: Date.now(),
        };
      }

      this.startPeriodicTasks();
    } catch (error) {
      this.logger.error('Failed to initialize workflow orchestrator state', error);
      throw new WorkflowError('Initialization failed', 'INIT_ERROR');
    }
  }

  /**
   * Start workflow execution
   */
  async startWorkflow(request: Request): Promise<Response> {
    try {
      const body = await request.json();
      const { workflowDefinition, businessId, userId, correlationId, variables = {} } = body;

      // Validate inputs
      const validatedWorkflow = WorkflowDefinitionSchema.parse(workflowDefinition);
      const validatedBusinessId = InputValidator.validateResourceId(businessId, 'businessId');
      const validatedUserId = InputValidator.validateResourceId(userId, 'userId');
      const validatedCorrelationId = correlationId || CorrelationId.generate();

      // Check concurrent workflow limits
      const userWorkflows = Array.from(this.orchestratorState.executions.values())
        .filter(exec => exec.userId === validatedUserId && exec.status === 'running');

      if (userWorkflows.length >= this.orchestratorState.config.maxConcurrentWorkflows) {
        throw new WorkflowError(
        
   `User has reached maximum concurrent workflows limit (${this.orchestratorState.config.maxConcurrentWorkflows})`,
          'CONCURRENT_LIMIT_EXCEEDED'
        );
      }

      // Create workflow execution
      const executionId = this.generateExecutionId();
      const execution: WorkflowExecution = {
        id: executionId,
        workflowId: validatedWorkflow.id,
        workflowVersion: validatedWorkflow.version,
        status: 'created',
        businessId: validatedBusinessId,
        userId: validatedUserId,
        correlationId: validatedCorrelationId,
        startTime: Date.now(),
        steps: new Map(),
        currentSteps: [],
        completedSteps: [],
        failedSteps: [],
        parallelGroups: new Map(),
        variables,
        totalCost: this.createEmptyCost(),
        costHistory: [],
        rollbackSteps: [],
        rollbackInProgress: false,
        pendingApprovals: [],
        lastUpdateTime: Date.now(),
      };

      // Store execution
      this.orchestratorState.executions.set(executionId, execution);
      await this.persistState();

      // Start execution
      await this.executeWorkflow(validatedWorkflow, execution);

      // Update metrics
      this.orchestratorState.metrics.totalExecutions++;
      await this.persistState();

      this.logger.info('Workflow started', {
        workflowId: validatedWorkflow.id,
        executionId,
        businessId: validatedBusinessId,
        userId: validatedUserId,
        correlationId: validatedCorrelationId,
      });

      return new Response(JSON.stringify({
        success: true,
        executionId,
        status: execution.status,
        workflowId: validatedWorkflow.id,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Failed to start workflow', error);
      return new Response(JSON.stringify({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: error instanceof WorkflowError ? error.code : 'WORKFLOW_START_ERROR',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  /**
   * Get workflow execution status
   */
  async getWorkflowStatus(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const executionId = url.searchParams.get('executionId');

      if (!executionId) {
        throw new WorkflowError('Missing executionId parameter', 'MISSING_PARAMETER');
      }

      const execution = this.orchestratorState.executions.get(executionId);
      if (!execution) {
        throw new WorkflowError('Workflow execution not found', 'EXECUTION_NOT_FOUND');
      }

      // Convert Map to object for JSON serialization
      const response = {
        ...execution,
        steps: Object.fromEntries(execution.steps),
        parallelGroups: Object.fromEntries(execution.parallelGroups),
      };

      return new Response(JSON.stringify(response), {
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Failed to get workflow status', error);
      return new Response(JSON.stringify({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: error instanceof WorkflowError ? error.code : 'STATUS_ERROR',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  /**
   * Approve workflow step
   */
  async approveStep(request: Request): Promise<Response> {
    try {
      const body = await request.json();
      const { executionId, stepId, userId, decision, comment } = body;

      const execution = this.orchestratorState.executions.get(executionId);
      if (!execution) {
        throw new WorkflowError('Workflow execution not found', 'EXECUTION_NOT_FOUND');
      }

      const stepResult = execution.steps.get(stepId);
      if (!stepResult || stepResult.status !== 'waiting_approval') {
        throw new WorkflowError('Step not waiting for approval', 'INVALID_APPROVAL_STATE');
      }

      // Record approval
      if (!stepResult.approvals) {
        stepResult.approvals = [];
      }

      stepResult.approvals.push({
        userId,
        decision,
        timestamp: Date.now(),
        comment,
      });

      // Check if we have enough approvals
      const pendingApproval = execution.pendingApprovals.find(pa => pa.stepId === stepId);
      if (pendingApproval) {
        const approvalCount = stepResult.approvals.filter(a => a.decision === 'approve').length;
        const rejectionCount = stepResult.approvals.filter(a => a.decision === 'reject').length;

        if (rejectionCount > 0) {
          // Rejection - fail the step
          stepResult.status = 'failed';
          stepResult.error = {
            message: 'Step rejected during approval process',
            code: 'APPROVAL_REJECTED',
            retryable: false,
          };
          await this.handleStepFailure(execution, stepId);
        } else if (approvalCount >= pendingApproval.requiredApprovers.length) {
          // Approved - continue execution
          stepResult.status = 'completed';
          execution.pendingApprovals = execution.pendingApprovals.filter(pa => pa.stepId !== stepId);
          await this.continueWorkflowExecution(execution);
        }
      }

      await this.persistState();
      await this.emitProgressEvent(execution, 'step_completed', stepId);

      return new Response(JSON.stringify({
        success: true,
        stepId,
        status: stepResult.status,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Failed to approve step', error);
      return new Response(JSON.stringify({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: error instanceof WorkflowError ? error.code : 'APPROVAL_ERROR',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  /**
   * Cancel workflow execution
   */
  async cancelWorkflow(request: Request): Promise<Response> {
    try {
      const body = await request.json();
      const { executionId, reason = 'User cancelled' } = body;

      const execution = this.orchestratorState.executions.get(executionId);
      if (!execution) {
        throw new WorkflowError('Workflow execution not found', 'EXECUTION_NOT_FOUND');
      }

      if (execution.status === 'completed' || execution.status === 'cancelled') {
        throw new WorkflowError('Workflow cannot be cancelled in current state', 'INVALID_CANCEL_STATE');
      }

      // Cancel execution
      execution.status = 'cancelled';
      execution.endTime = Date.now();
      execution.duration = execution.endTime - execution.startTime;

      // Cancel any running steps
      for (const stepId of execution.currentSteps) {
        const stepResult = execution.steps.get(stepId);
        if (stepResult && stepResult.status === 'running') {
          stepResult.status = 'cancelled';
          stepResult.endTime = Date.now();
          stepResult.duration = stepResult.endTime - stepResult.startTime;
        }
      }

      execution.currentSteps = [];

      // Clear alarms
      await this.clearWorkflowAlarms(executionId);

      await this.persistState();
      await this.emitProgressEvent(execution, 'workflow_failed');

      this.logger.info('Workflow cancelled', {
        executionId,
        reason,
        duration: execution.duration,
      });

      return new Response(JSON.stringify({
        success: true,
        executionId,
        status: execution.status,
        reason,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Failed to cancel workflow', error);
      return new Response(JSON.stringify({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: error instanceof WorkflowError ? error.code : 'CANCEL_ERROR',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  /**
   * Subscribe to workflow progress via SSE
   */
  async subscribeToProgress(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const workflowIds = url.searchParams.get('workflowIds')?.split(',') || [];
      const connectionId = CorrelationId.generate();

      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();

      this.sseConnections.set(connectionId, {
        writer,
        workflowIds: new Set(workflowIds),
      });

      // Send initial connection event
      const initialEvent = this.formatSSEEvent({
        type: 'connection_established',
        workflowExecutionId: 'system',
        timestamp: Date.now(),
        data: {
          connectionId,
          subscribedWorkflows: workflowIds,
        },
      });

      await writer.write(new TextEncoder().encode(initialEvent));

      // Cleanup on connection close
      request.signal?.addEventListener('abort', () => {
        this.sseConnections.delete(connectionId);
        writer.close();
      });

      return new Response(readable, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'Access-Control-Allow-Origin': '*',
        },
      });

    } catch (error) {
      this.logger.error('Failed to subscribe to progress', error);
      return new Response('Failed to establish SSE connection', { status: 500 });
    }
  }

  /**
   * Handle alarm events for timeout management
   */
  async alarm(): Promise<void> {
    try {
      const now = Date.now();
      const activeAlarms = Array.from(this.orchestratorState.alarms.values())
        .filter(alarm => alarm.active && alarm.scheduledTime <= now);

      for (const alarm of activeAlarms) {
        await this.handleAlarmEvent(alarm);
        alarm.active = false;
      }

      // Clean up processed alarms
      for (const [id, alarm] of this.orchestratorState.alarms.entries()) {
        if (!alarm.active) {
          this.orchestratorState.alarms.delete(id);
        }
      }

      await this.persistState();

      // Schedule next alarm check
      const nextAlarm = Array.from(this.orchestratorState.alarms.values())
        .filter(alarm => alarm.active)
        .sort((a, b) => a.scheduledTime - b.scheduledTime)[0];

      if (nextAlarm) {
        this.state.storage.setAlarm(nextAlarm.scheduledTime);
      }

    } catch (error) {
      this.logger.error('Failed to handle alarm', error);
    }
  }

  /**
   * Register step handler
   */
  registerStepHandler(handlerName: string, handler: StepHandler): void {
    this.stepHandlers.set(handlerName, handler);
  }

  /**
   * Private methods for workflow execution
   */

  private async executeWorkflow(definition: WorkflowDefinition, execution: WorkflowExecution): Promise<void> {
    try {
      execution.status = 'running';
      execution.lastUpdateTime = Date.now();

      // Set global timeout alarm
      if (definition.globalTimeout) {
        await this.scheduleAlarm({
          id: `workflow_timeout_${execution.id}`,
          workflowExecutionId: execution.id,
          type: 'workflow_timeout',
          scheduledTime: Date.now() + definition.globalTimeout,
          data: { timeoutMs: definition.globalTimeout },
          active: true,
        });
      }

      // Find initial steps (no dependencies)
      const initialSteps = definition.steps.filter(step => step.dependsOn.length === 0);

      if (initialSteps.length === 0) {
        throw new WorkflowError('No initial steps found', 'NO_INITIAL_STEPS');
      }

      // Start initial steps
      await this.executeSteps(definition, execution, initialSteps.map(s => s.id));
      await this.emitProgressEvent(execution, 'step_started');

    } catch (error) {
      execution.status = 'failed';
      execution.error = {
        message: error instanceof Error ? error.message : 'Unknown error',
        code: error instanceof WorkflowError ? error.code : 'EXECUTION_ERROR',
        timestamp: Date.now(),
      };
      await this.emitProgressEvent(execution, 'workflow_failed');
      throw error;
    }
  }

  private async executeSteps(definition: WorkflowDefinition,
  execution: WorkflowExecution, stepIds: string[]): Promise<void> {
    const steps = stepIds.map(id => definition.steps.find(s => s.id === id)).filter(Boolean) as WorkflowStep[];

    // Group steps by parallel groups
    const parallelGroups = new Map<string, WorkflowStep[]>();
    const sequentialSteps: WorkflowStep[] = [];

    for (const step of steps) {
      if (step.parallelGroup) {
        if (!parallelGroups.has(step.parallelGroup)) {
          parallelGroups.set(step.parallelGroup, []);
        }
        parallelGroups.get(step.parallelGroup)!.push(step);
      } else {
        sequentialSteps.push(step);
      }
    }

    // Execute parallel groups
    const parallelPromises: Promise<void>[] = [];
    for (const [groupId, groupSteps] of parallelGroups) {
      parallelPromises.push(this.executeParallelGroup(definition, execution, groupId, groupSteps));
    }

    // Execute sequential steps
    for (const step of sequentialSteps) {
      parallelPromises.push(this.executeStep(definition, execution, step));
    }

    // Wait for all to complete
    await Promise.allSettled(parallelPromises);
  }

  private async executeParallelGroup(definition: WorkflowDefinition, execution:
  WorkflowExecution, groupId: string, steps: WorkflowStep[]): Promise<void> {
    const groupState = {
      groupId,
      stepIds: steps.map(s => s.id),
      status: 'running' as const,
      startTime: Date.now(),
    };

    execution.parallelGroups.set(groupId, groupState);

    try {
      // Execute all steps in parallel
      const stepPromises = steps.map(step => this.executeStep(definition, execution, step));
      await Promise.all(stepPromises);

      groupState.status = 'completed';
      groupState.endTime = Date.now();

    } catch (error) {
      groupState.status = 'failed';
      groupState.endTime = Date.now();
      throw error;
    }
  }

  private async executeStep(definition: WorkflowDefinition,
  execution: WorkflowExecution, step: WorkflowStep): Promise<void> {
    const stepResult: StepExecutionResult = {
      stepId: step.id,
      status: 'running',
      startTime: Date.now(),
      actualCost: this.createEmptyCost(),
      retryCount: 0,
      retryHistory: [],
      executionId: execution.id,
      correlationId: execution.correlationId,
    };

    execution.steps.set(step.id, stepResult);
    execution.currentSteps.push(step.id);

    try {
      // Check if step should be executed based on conditions
      if (step.condition && !this.evaluateCondition(step.condition, execution.variables)) {
        stepResult.status = 'skipped';
        stepResult.endTime = Date.now();
        stepResult.duration = stepResult.endTime - stepResult.startTime;
        execution.completedSteps.push(step.id);
        execution.currentSteps = execution.currentSteps.filter(id => id !== step.id);
        await this.continueWorkflowExecution(execution);
        return;
      }

      // Set step timeout alarm
      if (step.timeoutMs) {
        await this.scheduleAlarm({
          id: `step_timeout_${execution.id}_${step.id}`,
          workflowExecutionId: execution.id,
          type: 'step_timeout',
          stepId: step.id,
          scheduledTime: Date.now() + step.timeoutMs,
          data: { timeoutMs: step.timeoutMs },
          active: true,
        });
      }

      // Handle approval steps
      if (step.type === 'approval') {
        await this.handleApprovalStep(execution, step, stepResult);
        return;
      }

      // Execute step with retry logic
      await this.executeStepWithRetry(execution, step, stepResult);

    } catch (error) {
      await this.handleStepFailure(execution, step.id, error);
    }
  }

  private async executeStepWithRetry(execution: WorkflowExecution,
  step: WorkflowStep, stepResult: StepExecutionResult): Promise<void> {
    const maxRetries = step.retryPolicy?.maxRetries || 0;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        stepResult.retryCount = attempt;

        // Get step handler
        const handler = this.stepHandlers.get(step.handler);
        if (!handler) {
          throw new WorkflowError(`Step handler '${step.handler}' not found`, 'HANDLER_NOT_FOUND');
        }

        // Execute step
        const result = await handler.execute(step, {
          variables: execution.variables,
          workflowId: execution.workflowId,
          executionId: execution.id,
          stepId: step.id,
          correlationId: execution.correlationId,
          businessId: execution.businessId,
          userId: execution.userId,
        });

        if (result.success) {
          stepResult.status = 'completed';
          stepResult.output = result.output;
          stepResult.endTime = Date.now();
          stepResult.duration = stepResult.endTime - stepResult.startTime;

          // Update cost
          if (result.cost) {
            this.updateStepCost(stepResult.actualCost, result.cost);
            this.addCostToExecution(execution, step.id, stepResult.actualCost);
          }

          // Update variables with step output
          if (result.output && typeof result.output === 'object') {
            execution.variables = { ...execution.variables, ...result.output };
          }

          execution.completedSteps.push(step.id);
          execution.currentSteps = execution.currentSteps.filter(id => id !== step.id);

          await this.emitProgressEvent(execution, 'step_completed', step.id);
          await this.continueWorkflowExecution(execution);
          return;

        } else {
          throw new Error(result.error || 'Step execution failed');
        }

      } catch (error) {
        stepResult.retryHistory.push({
          attempt,
          timestamp: Date.now(),
          error: error instanceof Error ? error.message : String(error),
        });

        if (attempt < maxRetries) {
          // Wait before retry
          const backoffMs = step.retryPolicy?.exponentialBackoff
            ? (step.retryPolicy.backoffMs || 1000) * Math.pow(2, attempt)
            : (step.retryPolicy?.backoffMs || 1000);

          await new Promise(resolve => setTimeout(resolve, backoffMs));
        } else {
          // Final failure
          stepResult.status = 'failed';
          stepResult.error = {
            message: error instanceof Error ? error.message : String(error),
            code: error instanceof WorkflowError ? error.code : 'STEP_EXECUTION_ERROR',
            retryable: attempt < maxRetries,
          };
          stepResult.endTime = Date.now();
          stepResult.duration = stepResult.endTime - stepResult.startTime;

          execution.failedSteps.push(step.id);
          execution.currentSteps = execution.currentSteps.filter(id => id !== step.id);

          throw error;
        }
      }
    }
  }

  private async handleApprovalStep(execution: WorkflowExecution,
  step: WorkflowStep, stepResult: StepExecutionResult): Promise<void> {
    if (!step.approvalConfig) {
      throw new WorkflowError('Approval step missing approval configuration', 'MISSING_APPROVAL_CONFIG');
    }

    stepResult.status = 'waiting_approval';
    stepResult.approvals = [];

    const deadline = Date.now() + (step.approvalTimeoutMs || this.orchestratorState.config.defaultApprovalTimeoutMs);

    execution.pendingApprovals.push({
      stepId: step.id,
      requiredApprovers: step.approvalConfig.requiredApprovers,
      currentApprovals: [],
      deadline,
    });

    // Set approval timeout alarm
    await this.scheduleAlarm({
      id: `approval_timeout_${execution.id}_${step.id}`,
      workflowExecutionId: execution.id,
      type: 'approval_timeout',
      stepId: step.id,
      scheduledTime: deadline,
      data: { approvalConfig: step.approvalConfig },
      active: true,
    });

    await this.emitProgressEvent(execution, 'approval_requested', step.id);
  }

  private async handleStepFailure(execution: WorkflowExecution, stepId: string, error?: unknown): Promise<void> {
    execution.currentSteps = execution.currentSteps.filter(id => id !== stepId);

    // Check if workflow should be rolled back
    const workflowDefinition = await this.getWorkflowDefinition(execution.workflowId);

    if (workflowDefinition?.autoRollbackOnFailure) {
      await this.rollbackWorkflow(execution);
    } else {
      execution.status = 'failed';
      execution.endTime = Date.now();
      execution.duration = execution.endTime - execution.startTime;
      execution.error = {
        message: error instanceof Error ? error.message : 'Step execution failed',
        code: error instanceof WorkflowError ? error.code : 'STEP_FAILURE',
        failedStepId: stepId,
        timestamp: Date.now(),
      };

      this.orchestratorState.metrics.failedExecutions++;
      await this.emitProgressEvent(execution, 'workflow_failed');
    }

    await this.persistState();
  }

  private async continueWorkflowExecution(execution: WorkflowExecution): Promise<void> {
    if (execution.status !== 'running') return;

    const workflowDefinition = await this.getWorkflowDefinition(execution.workflowId);
    if (!workflowDefinition) {
      throw new WorkflowError('Workflow definition not found', 'DEFINITION_NOT_FOUND');
    }

    // Find next steps to execute
    const nextSteps = workflowDefinition.steps.filter(step => {
      // Skip if already completed or failed
      if (execution.completedSteps.includes(step.id) || execution.failedSteps.includes(step.id)) {
        return false;
      }

      // Skip if currently running
      if (execution.currentSteps.includes(step.id)) {
        return false;
      }

      // Check if all dependencies are completed
      return step.dependsOn.every(depId => execution.completedSteps.includes(depId));
    });

    if (nextSteps.length > 0) {
      await this.executeSteps(workflowDefinition, execution, nextSteps.map(s => s.id));
    } else if (execution.currentSteps.length === 0) {
      // Workflow completed
      execution.status = 'completed';
      execution.endTime = Date.now();
      execution.duration = execution.endTime - execution.startTime;

      this.orchestratorState.metrics.completedExecutions++;
      this.updateAverageExecutionTime(execution.duration);

      await this.clearWorkflowAlarms(execution.id);
      await this.emitProgressEvent(execution, 'workflow_completed');
    }

    await this.persistState();
  }

  private async rollbackWorkflow(execution: WorkflowExecution): Promise<void> {
    execution.status = 'rolling_back';
    execution.rollbackInProgress = true;

    try {
      const workflowDefinition = await this.getWorkflowDefinition(execution.workflowId);
      if (!workflowDefinition) {
        throw new WorkflowError('Cannot rollback: workflow definition not found', 'DEFINITION_NOT_FOUND');
      }

      // Rollback completed steps in reverse order
      const stepsToRollback = execution.completedSteps
        .map(stepId => workflowDefinition.steps.find(s => s.id === stepId))
        .filter(step => step?.canRollback)
        .reverse();

      for (const step of stepsToRollback) {
        if (!step) continue;

        try {
          await this.rollbackStep(execution, step);
          execution.rollbackSteps.push(step.id);
        } catch (error) {
          this.logger.error('Failed to rollback step', error, { stepId: step.id });
          // Continue with other rollbacks even if one fails
        }
      }

      execution.status = 'rolled_back';
      execution.rollbackInProgress = false;

    } catch (error) {
      execution.status = 'failed';
      execution.rollbackInProgress = false;
      execution.error = {
        message: error instanceof Error ? error.message : 'Rollback failed',
        code: 'ROLLBACK_ERROR',
        timestamp: Date.now(),
      };
    }

    execution.endTime = Date.now();
    execution.duration = execution.endTime - execution.startTime;

    await this.persistState();
  }

  private async rollbackStep(execution: WorkflowExecution, step: WorkflowStep): Promise<void> {
    if (!step.rollbackHandler) {
      this.logger.warn('Step has no rollback handler', { stepId: step.id });
      return;
    }

    const handler = this.stepHandlers.get(step.rollbackHandler);
    if (!handler?.rollback) {
      throw new WorkflowError(`Rollback handler '${step.rollbackHandler}' not found`, 'ROLLBACK_HANDLER_NOT_FOUND');
    }

    const stepResult = execution.steps.get(step.id);
    const result = await handler.rollback(step, {
      variables: execution.variables,
      workflowId: execution.workflowId,
      executionId: execution.id,
      stepId: step.id,
      correlationId: execution.correlationId,
      businessId: execution.businessId,
      userId: execution.userId,
      originalOutput: stepResult?.output,
    });

    if (!result.success) {
      throw new Error(result.error || 'Rollback failed');
    }

    // Update step status
    if (stepResult) {
      stepResult.status = 'rolled_back';
    }
  }

  private async handleAlarmEvent(alarm: WorkflowAlarm): Promise<void> {
    const execution = this.orchestratorState.executions.get(alarm.workflowExecutionId);
    if (!execution) return;

    switch (alarm.type) {
      case 'step_timeout':
        if (alarm.stepId) {
          await this.handleStepTimeout(execution, alarm.stepId);
        }
        break;

      case 'approval_timeout':
        if (alarm.stepId) {
          await this.handleApprovalTimeout(execution, alarm.stepId);
        }
        break;

      case 'workflow_timeout':
        await this.handleWorkflowTimeout(execution);
        break;

      case 'cost_limit':
        await this.handleCostLimitExceeded(execution);
        break;
    }
  }

  private async handleStepTimeout(execution: WorkflowExecution, stepId: string): Promise<void> {
    const stepResult = execution.steps.get(stepId);
    if (!stepResult || stepResult.status !== 'running') return;

    stepResult.status = 'timeout';
    stepResult.endTime = Date.now();
    stepResult.duration = stepResult.endTime - stepResult.startTime;
    stepResult.error = {
      message: `Step timed out after ${stepResult.duration}ms`,
      code: 'STEP_TIMEOUT',
      retryable: false,
    };

    await this.handleStepFailure(execution, stepId, new StepTimeoutError(stepId, stepResult.duration));
  }

  private async handleApprovalTimeout(execution: WorkflowExecution, stepId: string): Promise<void> {
    const stepResult = execution.steps.get(stepId);
    if (!stepResult || stepResult.status !== 'waiting_approval') return;

    stepResult.status = 'timeout';
    stepResult.endTime = Date.now();
    stepResult.duration = stepResult.endTime - stepResult.startTime;
    stepResult.error = {
      message: 'Approval timeout exceeded',
      code: 'APPROVAL_TIMEOUT',
      retryable: false,
    };

    execution.pendingApprovals = execution.pendingApprovals.filter(pa => pa.stepId !== stepId);

    await this.handleStepFailure(execution, stepId, new ApprovalTimeoutError(stepId, stepResult.duration));
  }

  private async handleWorkflowTimeout(execution: WorkflowExecution): Promise<void> {
    execution.status = 'failed';
    execution.endTime = Date.now();
    execution.duration = execution.endTime - execution.startTime;
    execution.error = {
      message: `Workflow timed out after ${execution.duration}ms`,
      code: 'WORKFLOW_TIMEOUT',
      timestamp: Date.now(),
    };

    // Cancel all running steps
    for (const stepId of execution.currentSteps) {
      const stepResult = execution.steps.get(stepId);
      if (stepResult && stepResult.status === 'running') {
        stepResult.status = 'cancelled';
        stepResult.endTime = Date.now();
        stepResult.duration = stepResult.endTime - stepResult.startTime;
      }
    }

    execution.currentSteps = [];
    await this.emitProgressEvent(execution, 'workflow_failed');
  }

  private async handleCostLimitExceeded(execution: WorkflowExecution): Promise<void> {
    execution.status = 'failed';
    execution.endTime = Date.now();
    execution.duration = execution.endTime - execution.startTime;
    execution.error = {
      message: `Workflow cost limit exceeded: $${execution.totalCost.totalUSD}`,
      code: 'COST_LIMIT_EXCEEDED',
      timestamp: Date.now(),
    };

    await this.emitProgressEvent(execution, 'workflow_failed');
  }

  /**
   * Utility methods
   */

  private async scheduleAlarm(alarm: WorkflowAlarm): Promise<void> {
    this.orchestratorState.alarms.set(alarm.id, alarm);
    this.state.storage.setAlarm(alarm.scheduledTime);
  }

  private async clearWorkflowAlarms(workflowExecutionId: string): Promise<void> {
    for (const [id, alarm] of this.orchestratorState.alarms.entries()) {
      if (alarm.workflowExecutionId === workflowExecutionId) {
        alarm.active = false;
      }
    }
  }

  private async emitProgressEvent(execution: WorkflowExecution,
  type: WorkflowProgressEvent['type'], stepId?: string): Promise<void> {
    if (!this.orchestratorState.config.enableSSEUpdates) return;

    const event: WorkflowProgressEvent = {
      workflowExecutionId: execution.id,
      type,
      stepId,
      timestamp: Date.now(),
      data: {
        status: execution.status,
        progress: {
          completed: execution.completedSteps.length,
          total: execution.completedSteps.length + execution.currentSteps.length + execution.failedSteps.length,
         
  percentage: Math.round((execution.completedSteps.length / Math.max(1, execution.completedSteps.length + execution.currentSteps.length + execution.failedSteps.length)) * 100),
        },
        totalCost: execution.totalCost,
      },
    };

    const sseEvent = this.formatSSEEvent(event);
    const data = new TextEncoder().encode(sseEvent);

    // Send to all subscribed connections
    for (const [connectionId, connection] of this.sseConnections.entries()) {
      if (connection.workflowIds.has(execution.workflowId) || connection.workflowIds.size === 0) {
        try {
          await connection.writer.write(data);
        } catch (error) {
          // Connection closed, clean up
          this.sseConnections.delete(connectionId);
        }
      }
    }
  }

  private formatSSEEvent(event: WorkflowProgressEvent): string {
    return `id: ${event.workflowExecutionId}-${event.timestamp}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
  }

  private evaluateCondition(condition: { expression: string; variables:
  Record<string, unknown> }, workflowVariables: Record<string, unknown>): boolean {
    try {
      // Simple expression evaluation (in production, use a proper expression engine)
      const allVariables = { ...condition.variables, ...workflowVariables };
      const func = new Function(...Object.keys(allVariables), `return ${condition.expression}`);
      return Boolean(func(...Object.values(allVariables)));
    } catch (error) {
      this.logger.warn('Failed to evaluate condition', error, { expression: condition.expression });
      return false;
    }
  }

  private createEmptyCost(): StepCost {
    return {
      computeUnits: 0,
      storageBytes: 0,
      networkCalls: 0,
      aiTokens: 0,
      customCosts: {},
      totalUSD: 0,
    };
  }

  private updateStepCost(target: StepCost, partial: Partial<StepCost>): void {
    target.computeUnits += partial.computeUnits || 0;
    target.storageBytes += partial.storageBytes || 0;
    target.networkCalls += partial.networkCalls || 0;
    target.aiTokens += partial.aiTokens || 0;
    target.totalUSD += partial.totalUSD || 0;

    if (partial.customCosts) {
      for (const [key, value] of Object.entries(partial.customCosts)) {
        target.customCosts[key] = (target.customCosts[key] || 0) + value;
      }
    }
  }

  private addCostToExecution(execution: WorkflowExecution, stepId: string, cost: StepCost): void {
    this.updateStepCost(execution.totalCost, cost);

    execution.costHistory.push({
      stepId,
      cost: { ...cost },
      timestamp: Date.now(),
    });

    this.orchestratorState.metrics.totalCostUSD += cost.totalUSD;
  }

  private updateAverageExecutionTime(duration: number): void {
    const metrics = this.orchestratorState.metrics;
    const totalExecutions = metrics.completedExecutions;

    if (totalExecutions === 1) {
      metrics.averageExecutionTime = duration;
    } else {
      metrics.averageExecutionTime =
  (metrics.averageExecutionTime * (totalExecutions - 1) + duration) / totalExecutions;
    }
  }

  private generateExecutionId(): string {
    return `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private async getWorkflowDefinition(workflowId: string): Promise<WorkflowDefinition | null> {
    // In a real implementation, this would fetch from a workflow registry
    // For now, return null (workflow definitions would be stored separately)
    return null;
  }

  private async persistState(): Promise<void> {
    try {
      // Convert Maps to objects for storage
      const stateToStore = {
        ...this.orchestratorState,
        executions: Object.fromEntries(this.orchestratorState.executions),
        alarms: Object.fromEntries(this.orchestratorState.alarms),
      };

      await this.storage.put('orchestrator_state', stateToStore);
    } catch (error) {
      this.logger.error('Failed to persist orchestrator state', error);
    }
  }

  private startPeriodicTasks(): void {
    // Start alarm checker
    this.alarmTimer = setInterval(() => {
      this.checkAlarms().catch(error => {
        this.logger.error('Alarm check failed', error);
      });
    }, this.orchestratorState.config.alarmCheckIntervalMs) as any;

    // Start progress updater
    if (this.orchestratorState.config.enableSSEUpdates) {
      this.progressTimer = setInterval(() => {
        this.sendPeriodicProgressUpdates().catch(error => {
          this.logger.error('Progress update failed', error);
        });
      }, this.orchestratorState.config.progressUpdateIntervalMs) as any;
    }
  }

  private async checkAlarms(): Promise<void> {
    const now = Date.now();
    const dueAlarms = Array.from(this.orchestratorState.alarms.values())
      .filter(alarm => alarm.active && alarm.scheduledTime <= now);

    if (dueAlarms.length > 0) {
      // Trigger alarm handler
      this.state.storage.setAlarm(now);
    }
  }

  private async sendPeriodicProgressUpdates(): Promise<void> {
    for (const execution of this.orchestratorState.executions.values()) {
      if (execution.status === 'running') {
        await this.emitProgressEvent(execution, 'step_started');
      }
    }
  }

  fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;

    // Route requests to appropriate handlers
    switch (true) {
      case method === 'POST' && url.pathname.endsWith('/start'):
        return this.startWorkflow(request);

      case method === 'GET' && url.pathname.endsWith('/status'):
        return this.getWorkflowStatus(request);

      case method === 'POST' && url.pathname.endsWith('/approve'):
        return this.approveStep(request);

      case method === 'POST' && url.pathname.endsWith('/cancel'):
        return this.cancelWorkflow(request);

      case method === 'GET' && url.pathname.endsWith('/progress'):
        return this.subscribeToProgress(request);

      default:
        return new Response('Not Found', { status: 404 });
    }
  }
}