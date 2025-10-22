import type { Env } from '../types/env';
import type { Workflow,
  WorkflowStep,
  Action,
  Condition,
  RetryPolicy } from '../types/integration';import { Logger } from "../shared/logger";
const logger = new Logger({ component: "services-workflow-automation" });



// Grug make extended workflow type for internal use - simple!
interface WorkflowInternal extends Workflow {
  businessId: string;
  metadata?: Record<string, any>;
  steps?: WorkflowStepInternal[];
}

interface WorkflowStepInternal {
  id: string;
  name: string;
  type: 'action' | 'condition' | 'delay' | 'webhook';
  action?: Action;
  condition?: Condition;
  delayMs?: number;
  webhook?: { url: string; method: string };
  input?: any;
  retryPolicy?: RetryPolicy;
}

// Grug make own execution type - simple!
interface WorkflowExecutionInternal {
  id: string;
  workflowId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  triggeredBy: string;
  triggeredAt: string;
  startedAt: Date | string;
  completedAt?: Date | string;
  duration?: number;
  steps: WorkflowStep[];
  context: Record<string, any>;
  error?: string;
  triggerData?: any;
  logs?: any[];
  metadata?: Record<string, any>;
}

export class WorkflowAutomation {
  private env: Env;
  private workflows = new Map<string, WorkflowInternal>();
  private executions = new Map<string, WorkflowExecutionInternal>();
  private scheduledWorkflows = new Map<string, NodeJS.Timeout>();
  private webhookHandlers = new Map<string, string>(); // webhook URL -> workflow ID

  constructor(env: Env) {
    this.env = env;
  }

  async initialize(): Promise<void> {
    // Load active workflows
    await this.loadWorkflows();
    
    // Start scheduled workflows
    await this.startScheduledWorkflows();
    
    // Register webhook handlers
    await this.registerWebhookHandlers();
  }

  private async loadWorkflows(): Promise<void> {
    const db = this.env.DB_MAIN;
    const result = await db.prepare(`
      SELECT * FROM workflows
      WHERE status IN ('active', 'inactive')
      ORDER BY created_at DESC
    `).all();

    for (const row of result.results) {
      const workflow: WorkflowInternal = {
        id: (row as any).id as string,
        name: (row as any).name as string,
        description: (row as any).description as string,
        trigger: JSON.parse((row as any).trigger_config as string),
        actions: [], // Grug add empty actions - required by Workflow type
        steps: JSON.parse((row as any).steps_config as string),
        status: (row as any).status as 'active' | 'inactive' | 'draft',
        createdAt: (row as any).created_at as string, // Grug keep as string!
        updatedAt: (row as any).updated_at as string, // Grug keep as string!
        createdBy: (row as any).created_by as string,
        businessId: (row as any).business_id as string,
        version: (row as any).version as number,
        tags: JSON.parse((row as any).tags as string || '[]'),
        metadata: JSON.parse((row as any).metadata as string || '{}')
      };

      this.workflows.set(workflow.id, workflow);
    }
  }

  private async startScheduledWorkflows(): Promise<void> {
    for (const [id, workflow] of this.workflows) {
    void id;
      if (workflow.status === 'active' && workflow.trigger.type === 'schedule') {
        await this.scheduleWorkflow(workflow);
      }
    }
  }

  private async registerWebhookHandlers(): Promise<void> {
    for (const [id, workflow] of this.workflows) {
      if (workflow.status === 'active' && workflow.trigger.type === 'webhook') {
        const webhookUrl = `/webhook/workflow/${id}`;
        this.webhookHandlers.set(webhookUrl, id);
      }
    }
  }

  async createWorkflow(workflowData: Omit<WorkflowInternal, 'id' | 'createdAt' | 'updatedAt' | 'version'>): Promise<WorkflowInternal> {
    const db = this.env.DB_MAIN;
    const id = `workflow_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const now = new Date().toISOString(); // Grug make string date!
    const workflow: WorkflowInternal = {
      ...workflowData,
      id,
      createdAt: now,
      updatedAt: now,
      version: 1
    };

    await db.prepare(`
      INSERT INTO workflows (
        id, name, description, trigger_config, steps_config, status,
        created_at, updated_at, created_by, business_id, version, tags, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      workflow.id,
      workflow.name,
      workflow.description,
      JSON.stringify(workflow.trigger),
      JSON.stringify(workflow.steps || []),
      workflow.status,
      workflow.createdAt,
      workflow.updatedAt,
      workflow.createdBy || '',
      workflow.businessId,
      workflow.version,
      JSON.stringify(workflow.tags || []),
      JSON.stringify(workflow.metadata || {})
    ).run();

    this.workflows.set(workflow.id, workflow);

    if (workflow.status === 'active') {
      if (workflow.trigger.type === 'schedule') {
        await this.scheduleWorkflow(workflow);
      } else if (workflow.trigger.type === 'webhook') {
        const webhookUrl = `/webhook/workflow/${workflow.id}`;
        this.webhookHandlers.set(webhookUrl, workflow.id);
      }
    }

    return workflow;
  }

  async updateWorkflow(id: string, updates: Partial<WorkflowInternal>): Promise<WorkflowInternal | null> {
    const existing = this.workflows.get(id);
    if (!existing) return null;

    const updated: WorkflowInternal = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString(), // Grug make string!
      version: existing.version + 1
    };

    const db = this.env.DB_MAIN;
    await db.prepare(`
      UPDATE workflows SET
        name = ?, description = ?, trigger_config = ?, steps_config = ?,
        status = ?, updated_at = ?, version = ?, tags = ?, metadata = ?
      WHERE id = ?
    `).bind(
      updated.name,
      updated.description,
      JSON.stringify(updated.trigger),
      JSON.stringify(updated.steps || []),
      updated.status,
      updated.updatedAt,
      updated.version,
      JSON.stringify(updated.tags || []),
      JSON.stringify(updated.metadata || {}),
      id
    ).run();

    this.workflows.set(id, updated);
    return updated;
  }

  async deleteWorkflow(id: string): Promise<boolean> {
    const workflow = this.workflows.get(id);
    if (!workflow) return false;

    // Stop scheduled workflow if running
    if (workflow.trigger.type === 'schedule') {
      const timeoutId = this.scheduledWorkflows.get(id);
      if (timeoutId) {
        clearTimeout(timeoutId);
        this.scheduledWorkflows.delete(id);
      }
    }

    // Remove webhook handler
    if (workflow.trigger.type === 'webhook') {
      const webhookUrl = `/webhook/workflow/${id}`;
      this.webhookHandlers.delete(webhookUrl);
    }

    const db = this.env.DB_MAIN;
    await db.prepare('DELETE FROM workflows WHERE id = ?').bind(id).run();
    
    this.workflows.delete(id);
    return true;
  }

  async executeWorkflow(id: string, triggerData?: any): Promise<WorkflowExecutionInternal> {
    const workflow = this.workflows.get(id);
    if (!workflow) {
      throw new Error(`Workflow ${id} not found`);
    }

    if (workflow.status !== 'active') {
      throw new Error(`Workflow ${id} is not active`);
    }

    const executionId = `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const execution: WorkflowExecutionInternal = {
      id: executionId,
      workflowId: id,
      status: 'running',
      triggeredBy: 'system', // Grug add required field!
      triggeredAt: new Date().toISOString(), // Grug make string!
      startedAt: new Date(), // Grug keep internal Date
      triggerData: triggerData || {},
      steps: [],
      context: {},
      logs: [],
      metadata: {}
    };

    this.executions.set(executionId, execution);

    try {
      await this.runWorkflowSteps(workflow, execution);
      execution.status = 'completed';
      execution.completedAt = new Date().toISOString(); // Grug make string!
    } catch (error: any) {
      execution.status = 'failed';
      execution.completedAt = new Date().toISOString(); // Grug make string!
      execution.error = error instanceof Error ? error.message : 'Unknown error';
    }

    // Store execution in database
    await this.storeExecution(execution);

    return execution;
  }

  private async runWorkflowSteps(workflow: WorkflowInternal, execution: WorkflowExecutionInternal): Promise<void> {
    const steps = workflow.steps || []; // Grug protect against undefined!
    for (const step of steps) {
      // Grug make proper WorkflowStep type
      const stepExecution: WorkflowStep = {
        actionId: step.id,
        actionName: step.name,
        status: 'running',
        startTime: new Date().toISOString(),
        input: step.input || {},
        output: {},
        retryCount: 0
      };

      execution.steps.push(stepExecution);

      try {
        await this.executeStep(step, stepExecution, execution);
        stepExecution.status = 'completed';
        stepExecution.endTime = new Date().toISOString();
      } catch (error: any) {
        stepExecution.status = 'failed';
        stepExecution.endTime = new Date().toISOString();
        stepExecution.error = error instanceof Error ? error.message : 'Unknown error';

        // Handle retry logic
        if (step.retryPolicy && (stepExecution.retryCount || 0) < step.retryPolicy.maxRetries) {
          stepExecution.retryCount = (stepExecution.retryCount || 0) + 1;
          stepExecution.status = 'running';
          stepExecution.startTime = new Date().toISOString();

          // Wait before retry
          await new Promise(resolve =>
            setTimeout(resolve, step.retryPolicy!.retryDelay || 1000)
          );

          try {
            await this.executeStep(step, stepExecution, execution);
            stepExecution.status = 'completed';
            stepExecution.endTime = new Date().toISOString();
          } catch (retryError) {
            stepExecution.status = 'failed';
            stepExecution.endTime = new Date().toISOString();
            stepExecution.error = retryError instanceof Error ? retryError.message : 'Unknown error';
          }
        }

        if (stepExecution.status === 'failed') {
          throw new Error(`Step ${step.id} failed: ${stepExecution.error}`);
        }
      }
    }
  }

  private async executeStep(step: WorkflowStepInternal, stepExecution: WorkflowStep, execution: WorkflowExecutionInternal): Promise<void> {
    // Grug no need for logs - remove complexity

    switch (step.type) {
      case 'action':
        await this.executeAction(step, stepExecution, execution);
        break;
      case 'condition':
        await this.executeCondition(step, stepExecution, execution);
        break;
      case 'delay':
        await this.executeDelay(step, stepExecution, execution);
        break;
      case 'webhook':
        await this.executeWebhook(step, stepExecution, execution);
        break;
      default:
        throw new Error(`Unknown step type: ${step.type}`);
    }
  }

  private async executeAction(step: WorkflowStepInternal, stepExecution: WorkflowStep, _execution: WorkflowExecutionInternal): Promise<void> {
    const action = step.action;
    if (!action) throw new Error('Action not defined for step');

    // Mock action execution - would implement real actions in production
    switch (action.type) {
      case 'send_email':
        stepExecution.output = { messageId: `email_${Date.now()}` };
        break;
      case 'create_task':
        stepExecution.output = { taskId: `task_${Date.now()}` };
        break;
      case 'update_field':
        stepExecution.output = { recordId: `record_${Date.now()}` };
        break;
      default:
        stepExecution.output = { success: true };
    }
  }

  private async executeCondition(step: WorkflowStepInternal, stepExecution: WorkflowStep, execution: WorkflowExecutionInternal): Promise<void> {
    const condition = step.condition;
    if (!condition) throw new Error('Condition not defined for step');

    // Mock condition evaluation - would implement real condition logic in production
    const result = this.evaluateCondition(condition, execution.context);
    stepExecution.output = { result };
  }

  private async executeDelay(step: WorkflowStepInternal, stepExecution: WorkflowStep, _execution: WorkflowExecutionInternal): Promise<void> {
    const delayMs = step.delayMs || 1000;
    await new Promise(resolve => setTimeout(resolve, delayMs));
    stepExecution.output = { delayed: delayMs };
  }

  private async executeWebhook(step: WorkflowStepInternal, stepExecution: WorkflowStep, _execution: WorkflowExecutionInternal): Promise<void> {
    const webhook = step.webhook;
    if (!webhook) throw new Error('Webhook not defined for step');

    // Mock webhook execution - would implement real webhook calls in production
    stepExecution.output = {
      url: webhook.url,
      method: webhook.method,
      statusCode: 200,
      response: { success: true }
    };
  }

  private evaluateCondition(_condition: Condition, _context: any): boolean {
    // Mock condition evaluation - would implement real condition logic in production
    return Math.random() > 0.5;
  }

  private async scheduleWorkflow(workflow: WorkflowInternal): Promise<void> {
    if (workflow.trigger.type !== 'schedule') return;

    const schedule = workflow.trigger.config.cron; // Grug use config.cron instead!
    if (!schedule) return;

    const intervalMs = this.parseScheduleInterval(schedule);
    const timeoutId = setTimeout(async () => {
      try {
        await this.executeWorkflow(workflow.id);
        // Reschedule if workflow is still active
        if (this.workflows.get(workflow.id)?.status === 'active') {
          await this.scheduleWorkflow(workflow as WorkflowInternal);
        }
      } catch (error: any) {
        logger.error(`Scheduled workflow ${workflow.id} failed:`, error);
      }
    }, intervalMs);

    this.scheduledWorkflows.set(workflow.id, timeoutId);
  }

  private parseScheduleInterval(interval: string): number {
    // Parse interval strings like "5m", "1h", "1d"
    const match = interval.match(/^(\d+)([smhd])$/);
    if (!match) return 60000; // Default to 1 minute

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: return 60000;
    }
  }

  private async storeExecution(execution: WorkflowExecutionInternal): Promise<void> {
    const db = this.env.DB_MAIN;

    // Grug convert dates to strings for DB
    const startedAt = execution.startedAt instanceof Date
      ? execution.startedAt.toISOString()
      : execution.startedAt;
    const completedAt = execution.completedAt instanceof Date
      ? execution.completedAt.toISOString()
      : execution.completedAt;

    await db.prepare(`
      INSERT INTO workflow_executions (
        id, workflow_id, status, started_at, completed_at, trigger_data,
        steps, context, logs, metadata, error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      execution.id,
      execution.workflowId,
      execution.status,
      startedAt,
      completedAt || null,
      JSON.stringify(execution.triggerData || {}),
      JSON.stringify(execution.steps),
      JSON.stringify(execution.context),
      JSON.stringify(execution.logs || []),
      JSON.stringify(execution.metadata || {}),
      execution.error || null
    ).run();
  }

  async getWorkflow(id: string): Promise<WorkflowInternal | null> {
    return this.workflows.get(id) || null;
  }

  async getWorkflows(businessId: string): Promise<WorkflowInternal[]> {
    return Array.from(this.workflows.values())
      .filter((w) => w.businessId === businessId);
  }

  async getExecution(id: string): Promise<WorkflowExecutionInternal | null> {
    return this.executions.get(id) || null;
  }

  async getExecutions(workflowId: string): Promise<WorkflowExecutionInternal[]> {
    return Array.from(this.executions.values())
      .filter((e) => e.workflowId === workflowId);
  }

  async handleWebhook(url: string, data: any): Promise<WorkflowExecutionInternal | null> {
    const workflowId = this.webhookHandlers.get(url);
    if (!workflowId) return null;

    return await this.executeWorkflow(workflowId, data);
  }

  async pauseWorkflow(id: string): Promise<boolean> {
    const workflow = this.workflows.get(id);
    if (!workflow) return false;

    if (workflow.trigger.type === 'schedule') {
      const timeoutId = this.scheduledWorkflows.get(id);
      if (timeoutId) {
        clearTimeout(timeoutId);
        this.scheduledWorkflows.delete(id);
      }
    }

    workflow.status = 'inactive';
    await this.updateWorkflow(id, { status: 'inactive' });
    return true;
  }

  async resumeWorkflow(id: string): Promise<boolean> {
    const workflow = this.workflows.get(id);
    if (!workflow) return false;

    workflow.status = 'active';
    await this.updateWorkflow(id, { status: 'active' });

    if (workflow.trigger.type === 'schedule') {
      await this.scheduleWorkflow(workflow);
    }

    return true;
  }

  async getWorkflowStats(businessId: string): Promise<{
    totalWorkflows: number;
    activeWorkflows: number;
    totalExecutions: number;
    successfulExecutions: number;
    failedExecutions: number;
    averageExecutionTime: number;
  }> {
    const workflows = await this.getWorkflows(businessId);
    const executions = Array.from(this.executions.values())
      .filter((e) => workflows.some(w => w.id === e.workflowId));

    const totalExecutions = executions.length;
    const successfulExecutions = executions.filter((e) => e.status === 'completed').length;
    const failedExecutions = executions.filter((e) => e.status === 'failed').length;

    const completedExecutions = executions.filter((e) => e.status === 'completed' && e.completedAt);
    const averageExecutionTime = completedExecutions.length > 0
      ? completedExecutions.reduce((sum, e) => {
          // Grug handle both Date and string!
          const completedTime = e.completedAt instanceof Date
            ? e.completedAt.getTime()
            : new Date(e.completedAt!).getTime();
          const startedTime = e.startedAt instanceof Date
            ? e.startedAt.getTime()
            : new Date(e.startedAt).getTime();
          const duration = completedTime - startedTime;
          return sum + duration;
        }, 0) / completedExecutions.length
      : 0;

    return {
      totalWorkflows: workflows.length,
      activeWorkflows: workflows.filter((w) => w.status === 'active').length,
      totalExecutions,
      successfulExecutions,
      failedExecutions,
      averageExecutionTime
    };
  }

  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      return {
        status: 'healthy',
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      };
    }
  }
}

