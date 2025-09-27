import type { Env } from '../types/env';
import type {
  Workflow,
  WorkflowAction,
  WorkflowExecution,
  WorkflowStep,
  Trigger,
  Action,
  Condition,
  ActionConfig,
  RetryPolicy
} from '../types/integration';

export class WorkflowAutomation {
  private env: Env;
  private workflows = new Map<string, Workflow>();
  private executions = new Map<string, WorkflowExecution>();
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
      const workflow: Workflow = {
        id: row.id as string,
        name: row.name as string,
        description: row.description as string,
        trigger: JSON.parse(row.trigger_config as string),
        steps: JSON.parse(row.steps_config as string),
        status: row.status as 'active' | 'inactive' | 'draft',
        createdAt: new Date(row.created_at as string),
        updatedAt: new Date(row.updated_at as string),
        createdBy: row.created_by as string,
        businessId: row.business_id as string,
        version: row.version as number,
        tags: JSON.parse(row.tags as string || '[]'),
        metadata: JSON.parse(row.metadata as string || '{}')
      };
      
      this.workflows.set(workflow.id, workflow);
    }
  }

  private async startScheduledWorkflows(): Promise<void> {
    for (const [id, workflow] of this.workflows) {
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

  async createWorkflow(workflowData: Omit<Workflow, 'id' | 'createdAt' | 'updatedAt' | 'version'>): Promise<Workflow> {
    const db = this.env.DB_MAIN;
    const id = `workflow_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const workflow: Workflow = {
      ...workflowData,
      id,
      createdAt: new Date(),
      updatedAt: new Date(),
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
      JSON.stringify(workflow.steps),
      workflow.status,
      workflow.createdAt.toISOString(),
      workflow.updatedAt.toISOString(),
      workflow.createdBy,
      workflow.businessId,
      workflow.version,
      JSON.stringify(workflow.tags),
      JSON.stringify(workflow.metadata)
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

  async updateWorkflow(id: string, updates: Partial<Workflow>): Promise<Workflow | null> {
    const existing = this.workflows.get(id);
    if (!existing) return null;

    const updated: Workflow = {
      ...existing,
      ...updates,
      updatedAt: new Date(),
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
      JSON.stringify(updated.steps),
      updated.status,
      updated.updatedAt.toISOString(),
      updated.version,
      JSON.stringify(updated.tags),
      JSON.stringify(updated.metadata),
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

  async executeWorkflow(id: string, triggerData?: any): Promise<WorkflowExecution> {
    const workflow = this.workflows.get(id);
    if (!workflow) {
      throw new Error(`Workflow ${id} not found`);
    }

    if (workflow.status !== 'active') {
      throw new Error(`Workflow ${id} is not active`);
    }

    const executionId = `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const execution: WorkflowExecution = {
      id: executionId,
      workflowId: id,
      status: 'running',
      startedAt: new Date(),
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
      execution.completedAt = new Date();
    } catch (error: any) {
      execution.status = 'failed';
      execution.completedAt = new Date();
      execution.error = error instanceof Error ? error.message : 'Unknown error';
    }

    // Store execution in database
    await this.storeExecution(execution);
    
    return execution;
  }

  private async runWorkflowSteps(workflow: Workflow, execution: WorkflowExecution): Promise<void> {
    for (const step of workflow.steps) {
      const stepExecution = {
        id: `step_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        stepId: step.id,
        status: 'running' as const,
        startedAt: new Date(),
        input: step.input || {},
        output: {},
        logs: [],
        retryCount: 0
      };

      execution.steps.push(stepExecution);

      try {
        await this.executeStep(step, stepExecution, execution);
        stepExecution.status = 'completed';
        stepExecution.completedAt = new Date();
      } catch (error: any) {
        stepExecution.status = 'failed';
        stepExecution.completedAt = new Date();
        stepExecution.error = error instanceof Error ? error.message : 'Unknown error';
        
        // Handle retry logic
        if (step.retryPolicy && stepExecution.retryCount < step.retryPolicy.maxRetries) {
          stepExecution.retryCount++;
          stepExecution.status = 'running';
          stepExecution.startedAt = new Date();
          
          // Wait before retry
          await new Promise(resolve => 
            setTimeout(resolve, step.retryPolicy.delayMs || 1000)
          );
          
          try {
            await this.executeStep(step, stepExecution, execution);
            stepExecution.status = 'completed';
            stepExecution.completedAt = new Date();
          } catch (retryError) {
            stepExecution.status = 'failed';
            stepExecution.completedAt = new Date();
            stepExecution.error = retryError instanceof Error ? retryError.message : 'Unknown error';
          }
        }
        
        if (stepExecution.status === 'failed') {
          throw new Error(`Step ${step.id} failed: ${stepExecution.error}`);
        }
      }
    }
  }

  private async executeStep(step: WorkflowStep, stepExecution: any, execution: WorkflowExecution): Promise<void> {
    const log = (message: string, level: 'info' | 'warn' | 'error' = 'info') => {
      stepExecution.logs.push({
        timestamp: new Date().toISOString(),
        level,
        message
      });
    };

    log(`Executing step: ${step.name}`);

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

    log(`Step completed: ${step.name}`);
  }

  private async executeAction(step: WorkflowStep, stepExecution: any, execution: WorkflowExecution): Promise<void> {
    const action = step.action;
    if (!action) throw new Error('Action not defined for step');

    // Mock action execution - would implement real actions in production
    switch (action.type) {
      case 'send_email':
        stepExecution.output = { messageId: `email_${Date.now()}` };
        break;
      case 'create_lead':
        stepExecution.output = { leadId: `lead_${Date.now()}` };
        break;
      case 'update_crm':
        stepExecution.output = { recordId: `record_${Date.now()}` };
        break;
      default:
        throw new Error(`Unknown action type: ${action.type}`);
    }
  }

  private async executeCondition(step: WorkflowStep, stepExecution: any, execution: WorkflowExecution): Promise<void> {
    const condition = step.condition;
    if (!condition) throw new Error('Condition not defined for step');

    // Mock condition evaluation - would implement real condition logic in production
    const result = this.evaluateCondition(condition, execution.context);
    stepExecution.output = { result };
  }

  private async executeDelay(step: WorkflowStep, stepExecution: any, execution: WorkflowExecution): Promise<void> {
    const delayMs = step.delayMs || 1000;
    await new Promise(resolve => setTimeout(resolve, delayMs));
    stepExecution.output = { delayed: delayMs };
  }

  private async executeWebhook(step: WorkflowStep, stepExecution: any, execution: WorkflowExecution): Promise<void> {
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

  private evaluateCondition(condition: Condition, context: any): boolean {
    // Mock condition evaluation - would implement real condition logic in production
    return Math.random() > 0.5;
  }

  private async scheduleWorkflow(workflow: Workflow): Promise<void> {
    if (workflow.trigger.type !== 'schedule') return;

    const schedule = workflow.trigger.schedule;
    if (!schedule) return;

    const intervalMs = this.parseScheduleInterval(schedule.interval);
    const timeoutId = setTimeout(async () => {
      try {
        await this.executeWorkflow(workflow.id);
        // Reschedule if workflow is still active
        if (this.workflows.get(workflow.id)?.status === 'active') {
          await this.scheduleWorkflow(workflow);
        }
      } catch (error: any) {
        console.error(`Scheduled workflow ${workflow.id} failed:`, error);
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

  private async storeExecution(execution: WorkflowExecution): Promise<void> {
    const db = this.env.DB_MAIN;
    await db.prepare(`
      INSERT INTO workflow_executions (
        id, workflow_id, status, started_at, completed_at, trigger_data,
        steps, context, logs, metadata, error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      execution.id,
      execution.workflowId,
      execution.status,
      execution.startedAt.toISOString(),
      execution.completedAt?.toISOString(),
      JSON.stringify(execution.triggerData),
      JSON.stringify(execution.steps),
      JSON.stringify(execution.context),
      JSON.stringify(execution.logs),
      JSON.stringify(execution.metadata),
      execution.error
    ).run();
  }

  async getWorkflow(id: string): Promise<Workflow | null> {
    return this.workflows.get(id) || null;
  }

  async getWorkflows(businessId: string): Promise<Workflow[]> {
    return Array.from(this.workflows.values())
      .filter((w: any) => w.businessId === businessId);
  }

  async getExecution(id: string): Promise<WorkflowExecution | null> {
    return this.executions.get(id) || null;
  }

  async getExecutions(workflowId: string): Promise<WorkflowExecution[]> {
    return Array.from(this.executions.values())
      .filter((e: any) => e.workflowId === workflowId);
  }

  async handleWebhook(url: string, data: any): Promise<WorkflowExecution | null> {
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
      .filter((e: any) => workflows.some(w => w.id === e.workflowId));

    const totalExecutions = executions.length;
    const successfulExecutions = executions.filter((e: any) => e.status === 'completed').length;
    const failedExecutions = executions.filter((e: any) => e.status === 'failed').length;
    
    const completedExecutions = executions.filter((e: any) => e.status === 'completed' && e.completedAt);
    const averageExecutionTime = completedExecutions.length > 0
      ? completedExecutions.reduce((sum, e) => {
          const duration = e.completedAt!.getTime() - e.startedAt.getTime();
          return sum + duration;
        }, 0) / completedExecutions.length
      : 0;

    return {
      totalWorkflows: workflows.length,
      activeWorkflows: workflows.filter((w: any) => w.status === 'active').length,
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

