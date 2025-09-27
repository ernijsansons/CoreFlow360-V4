import { EventEmitter } from 'events';
import { CoreFlow360AgentBridge } from './agent-bridge';
import { AgentServiceConnector } from './agent-connector';

export interface WorkflowStep {
  id: string;
  type: string;
  name: string;
  context: any;
  requiredAgent?: string;
  conditions?: WorkflowCondition[];
  actions?: WorkflowAction[];
  nextSteps?: string[];
  timeout?: number;
}

export interface WorkflowCondition {
  field: string;
  operator: 'equals' | 'gt' | 'lt' | 'contains' | 'in';
  value: any;
}

export interface WorkflowAction {
  type: string;
  target: string;
  params: any;
}

export interface AgentMapping {
  stepType: string;
  agentId: string;
  priority: number;
  fallbackAgent?: string;
}

export interface AutomatedWorkflow {
  id: string;
  name: string;
  type: string;
  triggers: WorkflowTrigger[];
  steps: WorkflowStep[];
  agentMappings: AgentMapping[];
  status: 'active' | 'paused' | 'completed' | 'failed';
  currentStep?: string;
  context: any;
  createdAt: Date;
  startedAt?: Date;
  completedAt?: Date;
}

export interface WorkflowTrigger {
  type: 'event' | 'schedule' | 'condition' | 'manual';
  config: any;
}

export interface WorkflowExecutionResult {
  workflowId: string;
  success: boolean;
  steps: StepResult[];
  finalOutput?: any;
  errors?: string[];
  duration: number;
}

export interface StepResult {
  stepId: string;
  success: boolean;
  agentUsed?: string;
  decision?: any;
  output?: any;
  error?: string;
  duration: number;
}

export class WorkflowAgentIntegration extends EventEmitter {
  private bridge: CoreFlow360AgentBridge;
  private connector: AgentServiceConnector;
  private activeWorkflows: Map<string, AutomatedWorkflow> = new Map();
  private agentMappings: Map<string, AgentMapping> = new Map();
  private executionHistory: Map<string, WorkflowExecutionResult[]> = new Map();
  private env: any;

  constructor(bridge: CoreFlow360AgentBridge, connector: AgentServiceConnector, env?: any) {
    super();
    this.bridge = bridge;
    this.connector = connector;
    this.env = env;
    this.initializeDefaultMappings();
  }

  private initializeDefaultMappings(): void {
    const defaultMappings: AgentMapping[] = [
      // Executive approvals
      { stepType: 'executive_approval', agentId: 'ceo', priority: 1 },
      { stepType: 'financial_approval', agentId: 'cfo', priority: 1 },
      { stepType: 'technical_approval', agentId: 'cto', priority: 1 },

      // Department reviews
      { stepType: 'hr_review', agentId: 'hr_manager', priority: 2 },
      { stepType: 'sales_review', agentId: 'sales_manager', priority: 2 },
      { stepType: 'legal_review', agentId: 'legal_advisor', priority: 2, fallbackAgent: 'ceo' },

      // Operational tasks
      { stepType: 'resource_allocation', agentId: 'operations', priority: 3 },
      { stepType: 'process_optimization', agentId: 'operations', priority: 3 },
      { stepType: 'workflow_routing', agentId: 'operations', priority: 3 },

      // Analysis and assessment
      { stepType: 'risk_assessment', agentId: 'risk_analyst', priority: 2 },
      { stepType: 'market_analysis', agentId: 'market_analyst', priority: 2 },
      { stepType: 'financial_analysis', agentId: 'cfo', priority: 2 },

      // Automated actions
      { stepType: 'data_validation', agentId: 'operations', priority: 4 },
      { stepType: 'notification_dispatch', agentId: 'operations', priority: 4 },
      { stepType: 'report_generation', agentId: 'operations', priority: 4 }
    ];

    defaultMappings.forEach((mapping: any) => {
      this.agentMappings.set(mapping.stepType, mapping);
    });
  }

  // === Workflow Automation ===

  async automateWorkflow(workflow: AutomatedWorkflow): Promise<WorkflowExecutionResult> {
    const startTime = Date.now();
    const results: StepResult[] = [];
    const errors: string[] = [];

    try {
      // Store active workflow
      this.activeWorkflows.set(workflow.id, workflow);
      workflow.status = 'active';
      workflow.startedAt = new Date();

      this.emit('workflowStarted', { workflowId: workflow.id, timestamp: new Date() });

      // Execute steps in sequence
      for (const step of workflow.steps) {
        workflow.currentStep = step.id;

        // Check conditions
        if (step.conditions && !this.evaluateConditions(step.conditions, workflow.context)) {
          results.push({
            stepId: step.id,
            success: true,
            output: 'Skipped - conditions not met',
            duration: 0
          });
          continue;
        }

        // Execute step with agent
        const stepResult = await this.executeWorkflowStep(step, workflow);
        results.push(stepResult);

        if (!stepResult.success) {
          errors.push(`Step ${step.id} failed: ${stepResult.error}`);

          // Check if we should continue on error
          if (!this.shouldContinueOnError(step)) {
            workflow.status = 'failed';
            break;
          }
        }

        // Update workflow context with step output
        if (stepResult.output) {
          workflow.context = {
            ...workflow.context,
            [`${step.id}_output`]: stepResult.output
          };
        }

        // Execute post-step actions
        if (step.actions) {
          await this.executeActions(step.actions, workflow.context);
        }

        this.emit('stepCompleted', {
          workflowId: workflow.id,
          stepId: step.id,
          result: stepResult
        });
      }

      // Mark workflow as completed
      if (workflow.status !== 'failed') {
        workflow.status = 'completed';
      }
      workflow.completedAt = new Date();

      const executionResult: WorkflowExecutionResult = {
        workflowId: workflow.id,
        success: workflow.status === 'completed',
        steps: results,
        finalOutput: this.aggregateOutputs(results),
        errors: errors.length > 0 ? errors : undefined,
        duration: Date.now() - startTime
      };

      // Store execution history
      if (!this.executionHistory.has(workflow.id)) {
        this.executionHistory.set(workflow.id, []);
      }
      this.executionHistory.get(workflow.id)!.push(executionResult);

      this.emit('workflowCompleted', executionResult);

      return executionResult;
    } catch (error: any) {
      workflow.status = 'failed';
      workflow.completedAt = new Date();

      const executionResult: WorkflowExecutionResult = {
        workflowId: workflow.id,
        success: false,
        steps: results,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        duration: Date.now() - startTime
      };

      this.emit('workflowFailed', { workflowId: workflow.id, error });

      return executionResult;
    } finally {
      this.activeWorkflows.delete(workflow.id);
    }
  }

  private async executeWorkflowStep(step: WorkflowStep, workflow: AutomatedWorkflow): Promise<StepResult> {
    const startTime = Date.now();

    try {
      // Get agent mapping for step
      const mapping = this.getAgentMapping(step);
      if (!mapping) {
        throw new Error(`No agent mapping found for step type: ${step.type}`);
      }

      // Prepare context for agent
      const agentContext = {
        workflowId: workflow.id,
        stepId: step.id,
        stepType: step.type,
        workflowContext: workflow.context,
        stepContext: step.context,
        metadata: {
          workflowName: workflow.name,
          stepName: step.name
        }
      };

      // Request decision from agent
      let agentUsed = mapping.agentId;
      let decision;

      try {
        decision = await this.requestAgentDecision(mapping.agentId, agentContext, step.timeout);
      } catch (error: any) {
        // Try fallback agent if available
        if (mapping.fallbackAgent) {
          agentUsed = mapping.fallbackAgent;
          decision = await this.requestAgentDecision(mapping.fallbackAgent, agentContext, step.timeout);
        } else {
          throw error;
        }
      }

      // Process agent decision
      const output = await this.processAgentDecision(decision, step);

      return {
        stepId: step.id,
        success: true,
        agentUsed,
        decision,
        output,
        duration: Date.now() - startTime
      };
    } catch (error: any) {
      return {
        stepId: step.id,
        success: false,
        error: error instanceof Error ? error.message : 'Step execution failed',
        duration: Date.now() - startTime
      };
    }
  }

  private async requestAgentDecision(agentId: string, context: any, timeout?: number): Promise<any> {
    const response = await this.connector.requestAgentAction({
      agentType: agentId,
      action: 'workflow_decision',
      context,
      timeout: timeout || 30000
    });

    if (!response.success) {
      throw new Error(`Agent ${agentId} failed: ${response.error}`);
    }

    return response.result;
  }

  private async processAgentDecision(decision: any, step: WorkflowStep): Promise<any> {
    // Process decision based on step type
    switch (step.type) {
      case 'approval':
      case 'executive_approval':
      case 'financial_approval':
      case 'technical_approval':
        return {
          approved: decision.approved || false,
          reason: decision.reasoning,
          conditions: decision.conditions,
          suggestions: decision.suggestions
        };

      case 'analysis':
      case 'risk_assessment':
      case 'market_analysis':
        return {
          findings: decision.findings,
          insights: decision.insights,
          recommendations: decision.recommendations,
          score: decision.score
        };

      case 'routing':
      case 'assignment':
        return {
          route: decision.route,
          assignTo: decision.assignTo,
          priority: decision.priority,
          reason: decision.reasoning
        };

      case 'optimization':
      case 'resource_allocation':
        return {
          optimizedValues: decision.optimizedValues,
          allocations: decision.allocations,
          improvements: decision.improvements
        };

      default:
        return decision;
    }
  }

  private getAgentMapping(step: WorkflowStep): AgentMapping | undefined {
    // Check for specific agent requirement
    if (step.requiredAgent) {
      return {
        stepType: step.type,
        agentId: step.requiredAgent,
        priority: 0
      };
    }

    // Get mapping by step type
    return this.agentMappings.get(step.type);
  }

  private evaluateConditions(conditions: WorkflowCondition[], context: any): boolean {
    return conditions.every(condition => {
      const value = this.getNestedValue(context, condition.field);

      switch (condition.operator) {
        case 'equals':
          return value === condition.value;
        case 'gt':
          return value > condition.value;
        case 'lt':
          return value < condition.value;
        case 'contains':
          return String(value).includes(condition.value);
        case 'in':
          return Array.isArray(condition.value) && condition.value.includes(value);
        default:
          return false;
      }
    });
  }

  private async executeActions(actions: WorkflowAction[], context: any): Promise<void> {
    for (const action of actions) {
      try {
        switch (action.type) {
          case 'update_field':
            this.setNestedValue(context, action.target, action.params.value);
            break;

          case 'send_notification':
            await this.sendNotification(action.params);
            break;

          case 'trigger_workflow':
            await this.triggerWorkflow(action.params.workflowId, context);
            break;

          case 'api_call':
            await this.makeApiCall(action.params);
            break;

          default:
        }
      } catch (error: any) {
        // Continue with other actions
      }
    }
  }

  private shouldContinueOnError(step: WorkflowStep): boolean {
    // Check if step is marked as optional or has error handling
    return step.context?.optional === true || step.context?.continueOnError === true;
  }

  private aggregateOutputs(results: StepResult[]): any {
    const outputs: any = {};

    results.forEach((result: any) => {
      if (result.output) {
        outputs[result.stepId] = result.output;
      }
    });

    return outputs;
  }

  // === Workflow Management ===

  async createAutomatedWorkflow(config: {
    name: string;
    type: string;
    triggers?: WorkflowTrigger[];
    steps: WorkflowStep[];
    context?: any;
  }): Promise<AutomatedWorkflow> {
    const workflow: AutomatedWorkflow = {
      id: crypto.randomUUID(),
      name: config.name,
      type: config.type,
      triggers: config.triggers || [],
      steps: config.steps,
      agentMappings: Array.from(this.agentMappings.values()),
      status: 'active',
      context: config.context || {},
      createdAt: new Date()
    };

    // Store workflow configuration
    if (this.env?.WORKFLOW_KV) {
      await this.env.WORKFLOW_KV.put(
        `workflow:${workflow.id}`,
        JSON.stringify(workflow)
      );
    }

    return workflow;
  }

  async getWorkflow(workflowId: string): Promise<AutomatedWorkflow | null> {
    // Check active workflows
    const active = this.activeWorkflows.get(workflowId);
    if (active) return active;

    // Load from storage
    if (this.env?.WORKFLOW_KV) {
      const data = await this.env.WORKFLOW_KV.get(`workflow:${workflowId}`);
      if (data) {
        return JSON.parse(data);
      }
    }

    return null;
  }

  async updateAgentMapping(stepType: string, agentId: string, options?: Partial<AgentMapping>): Promise<void> {
    const mapping: AgentMapping = {
      stepType,
      agentId,
      priority: options?.priority || 3,
      fallbackAgent: options?.fallbackAgent
    };

    this.agentMappings.set(stepType, mapping);

    // Persist mapping
    if (this.env?.WORKFLOW_KV) {
      await this.env.WORKFLOW_KV.put(
        `mapping:${stepType}`,
        JSON.stringify(mapping)
      );
    }
  }

  getActiveWorkflows(): AutomatedWorkflow[] {
    return Array.from(this.activeWorkflows.values());
  }

  getExecutionHistory(workflowId: string): WorkflowExecutionResult[] {
    return this.executionHistory.get(workflowId) || [];
  }

  // === Workflow Triggers ===

  async setupWorkflowTriggers(workflow: AutomatedWorkflow): Promise<void> {
    for (const trigger of workflow.triggers) {
      switch (trigger.type) {
        case 'event':
          this.setupEventTrigger(workflow, trigger.config);
          break;

        case 'schedule':
          this.setupScheduleTrigger(workflow, trigger.config);
          break;

        case 'condition':
          this.setupConditionTrigger(workflow, trigger.config);
          break;

        case 'manual':
          // No setup needed for manual triggers
          break;
      }
    }
  }

  private setupEventTrigger(workflow: AutomatedWorkflow, config: any): void {
    // Subscribe to events
    const eventHandler = async (data: any) => {
      const context = {
        ...workflow.context,
        triggerData: data
      };

      const workflowInstance = {
        ...workflow,
        id: `${workflow.id}-${Date.now()}`,
        context
      };

      await this.automateWorkflow(workflowInstance);
    };

    // Register event handler (implementation depends on event system)
    this.on(config.eventName, eventHandler);
  }

  private setupScheduleTrigger(workflow: AutomatedWorkflow, config: any): void {
    // Set up scheduled execution
    const schedule = config.schedule; // e.g., "0 9 * * *" for 9 AM daily

    // Implementation would depend on the scheduling system
    // For example, using node-cron or CloudFlare scheduled workers
  }

  private setupConditionTrigger(workflow: AutomatedWorkflow, config: any): void {
    // Monitor conditions and trigger when met
    const checkConditions = async () => {
      const context = await this.evaluateContext(config.contextSource);

      if (this.evaluateConditions(config.conditions, context)) {
        const workflowInstance = {
          ...workflow,
          id: `${workflow.id}-${Date.now()}`,
          context
        };

        await this.automateWorkflow(workflowInstance);
      }
    };

    // Check conditions periodically
    setInterval(checkConditions, config.checkInterval || 60000);
  }

  // === Helper Methods ===

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  private setNestedValue(obj: any, path: string, value: any): void {
    const keys = path.split('.');
    const lastKey = keys.pop()!;

    const target = keys.reduce((current, key) => {
      if (!current[key]) current[key] = {};
      return current[key];
    }, obj);

    target[lastKey] = value;
  }

  private async sendNotification(params: any): Promise<void> {
    // Implement notification sending
  }

  private async triggerWorkflow(workflowId: string, context: any): Promise<void> {
    const workflow = await this.getWorkflow(workflowId);
    if (workflow) {
      const instance = {
        ...workflow,
        id: `${workflow.id}-${Date.now()}`,
        context: { ...workflow.context, ...context }
      };
      await this.automateWorkflow(instance);
    }
  }

  private async makeApiCall(params: any): Promise<any> {
    const response = await fetch(params.url, {
      method: params.method || 'POST',
      headers: params.headers || { 'Content-Type': 'application/json' },
      body: params.body ? JSON.stringify(params.body) : undefined
    });

    if (!response.ok) {
      throw new Error(`API call failed: ${response.statusText}`);
    }

    return await response.json();
  }

  private async evaluateContext(contextSource: string): Promise<any> {
    // Fetch context from specified source
    // Implementation depends on the source type
    return {};
  }
}