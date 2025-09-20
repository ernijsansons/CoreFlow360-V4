/**
 * Workflow Module Exports
 * Central entry point for workflow orchestration functionality
 */

// Core workflow orchestrator
export { WorkflowOrchestrator } from './orchestrator';

// Step handlers
export {
  HttpRequestStepHandler,
  DatabaseStepHandler,
  EmailStepHandler,
  FileProcessingStepHandler,
  DelayStepHandler,
  StepHandlerRegistry
} from './step-handlers';

// Type definitions
export type {
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
  StepExecutionMode,
  StepCost
} from './types';

// Error types
export {
  WorkflowError,
  StepTimeoutError,
  ApprovalTimeoutError,
  CostLimitExceededError,
  WorkflowValidationError
} from './types';

// Default configuration and schemas
export {
  DEFAULT_WORKFLOW_CONFIG,
  StepCostSchema,
  WorkflowStepSchema,
  WorkflowDefinitionSchema
} from './types';

/**
 * Workflow Module factory for easy initialization
 */
export class WorkflowModule {
  private handlerRegistry: StepHandlerRegistry;

  constructor() {
    this.handlerRegistry = new StepHandlerRegistry();
  }

  /**
   * Create workflow module with custom handlers
   */
  static create(customHandlers?: Record<string, StepHandler>): WorkflowModule {
    const module = new WorkflowModule();

    if (customHandlers) {
      for (const [name, handler] of Object.entries(customHandlers)) {
        module.registerHandler(name, handler);
      }
    }

    return module;
  }

  /**
   * Register a custom step handler
   */
  registerHandler(name: string, handler: StepHandler): void {
    this.handlerRegistry.register(name, handler);
  }

  /**
   * Get the handler registry
   */
  getHandlerRegistry(): StepHandlerRegistry {
    return this.handlerRegistry;
  }

  /**
   * Get all registered handler names
   */
  getRegisteredHandlers(): string[] {
    return this.handlerRegistry.getRegisteredHandlers();
  }

  /**
   * Create a workflow orchestrator Durable Object
   * This would typically be called in the Cloudflare Worker binding
   */
  createOrchestrator(state: any): WorkflowOrchestrator {
    const orchestrator = new WorkflowOrchestrator(state);

    // Register all handlers with the orchestrator
    for (const [name, handler] of this.handlerRegistry['handlers'].entries()) {
      orchestrator.registerStepHandler(name, handler);
    }

    return orchestrator;
  }

  /**
   * Helper method to create a basic workflow definition
   */
  createWorkflowDefinition(config: {
    id: string;
    name: string;
    description?: string;
    version?: string;
    steps: Array<{
      id: string;
      name: string;
      type: 'action' | 'approval' | 'condition' | 'parallel_group' | 'sub_workflow';
      handler: string;
      parameters: Record<string, unknown>;
      dependsOn?: string[];
      parallelGroup?: string;
      timeoutMs?: number;
      approvalTimeoutMs?: number;
      canRollback?: boolean;
      rollbackHandler?: string;
      condition?: {
        expression: string;
        variables: Record<string, unknown>;
      };
      approvalConfig?: {
        requiredApprovers: string[];
        requiredCount: number;
        allowSelfApproval: boolean;
      };
    }>;
    autoRollbackOnFailure?: boolean;
    maxCostUSD?: number;
    globalTimeout?: number;
    createdBy: string;
  }): WorkflowDefinition {
    const definition: WorkflowDefinition = {
      id: config.id,
      name: config.name,
      description: config.description,
      version: config.version || '1.0.0',
      steps: config.steps.map(step => ({
        ...step,
        executionMode: step.parallelGroup ? 'parallel' : 'sequential',
        dependsOn: step.dependsOn || [],
        canRollback: step.canRollback ?? true,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 1000,
          exponentialBackoff: true,
        },
      })),
      globalTimeout: config.globalTimeout,
      autoRollbackOnFailure: config.autoRollbackOnFailure ?? true,
      enableProgressUpdates: true,
      maxCostUSD: config.maxCostUSD,
      createdBy: config.createdBy,
      createdAt: Date.now(),
    };

    // Validate the definition
    try {
      WorkflowDefinitionSchema.parse(definition);
    } catch (error) {
      throw new WorkflowValidationError(`Invalid workflow definition: ${error}`);
    }

    return definition;
  }

  /**
   * Helper to create common workflow patterns
   */
  createSequentialWorkflow(config: {
    id: string;
    name: string;
    steps: Array<{
      id: string;
      name: string;
      handler: string;
      parameters: Record<string, unknown>;
    }>;
    createdBy: string;
  }): WorkflowDefinition {
    const steps = config.steps.map((step, index) => ({
      ...step,
      type: 'action' as const,
      dependsOn: index > 0 ? [config.steps[index - 1].id] : [],
    }));

    return this.createWorkflowDefinition({
      ...config,
      steps,
    });
  }

  /**
   * Helper to create parallel workflow
   */
  createParallelWorkflow(config: {
    id: string;
    name: string;
    parallelSteps: Array<{
      id: string;
      name: string;
      handler: string;
      parameters: Record<string, unknown>;
    }>;
    createdBy: string;
  }): WorkflowDefinition {
    const parallelGroupId = 'parallel_group_1';

    const steps = config.parallelSteps.map(step => ({
      ...step,
      type: 'action' as const,
      dependsOn: [],
      parallelGroup: parallelGroupId,
    }));

    return this.createWorkflowDefinition({
      ...config,
      steps,
    });
  }

  /**
   * Helper to create approval workflow
   */
  createApprovalWorkflow(config: {
    id: string;
    name: string;
    actionStep: {
      id: string;
      name: string;
      handler: string;
      parameters: Record<string, unknown>;
    };
    approvalStep: {
      id: string;
      name: string;
      requiredApprovers: string[];
      requiredCount?: number;
      timeoutMs?: number;
    };
    createdBy: string;
  }): WorkflowDefinition {
    const steps = [
      {
        ...config.actionStep,
        type: 'action' as const,
        dependsOn: [config.approvalStep.id],
      },
      {
        ...config.approvalStep,
        type: 'approval' as const,
        handler: 'approval',
        parameters: {},
        dependsOn: [],
        approvalTimeoutMs: config.approvalStep.timeoutMs,
        approvalConfig: {
          requiredApprovers: config.approvalStep.requiredApprovers,
          requiredCount: config.approvalStep.requiredCount || config.approvalStep.requiredApprovers.length,
          allowSelfApproval: false,
        },
      },
    ];

    return this.createWorkflowDefinition({
      ...config,
      steps,
    });
  }
}

/**
 * Example workflow definitions for common patterns
 */
export const ExampleWorkflows = {
  /**
   * Simple HTTP request workflow
   */
  httpRequest: (url: string, method = 'GET'): WorkflowDefinition => {
    const module = new WorkflowModule();
    return module.createSequentialWorkflow({
      id: 'http_request_workflow',
      name: 'HTTP Request Workflow',
      steps: [
        {
          id: 'make_request',
          name: 'Make HTTP Request',
          handler: 'http_request',
          parameters: { url, method },
        },
      ],
      createdBy: 'system',
    });
  },

  /**
   * Data processing pipeline
   */
  dataProcessingPipeline: (inputFile: string, outputFile: string): WorkflowDefinition => {
    const module = new WorkflowModule();
    return module.createSequentialWorkflow({
      id: 'data_processing_pipeline',
      name: 'Data Processing Pipeline',
      steps: [
        {
          id: 'validate_input',
          name: 'Validate Input File',
          handler: 'file_processing',
          parameters: {
            operation: 'validate',
            inputPath: inputFile,
          },
        },
        {
          id: 'process_data',
          name: 'Process Data',
          handler: 'file_processing',
          parameters: {
            operation: 'convert',
            inputPath: inputFile,
            outputPath: outputFile,
            options: { format: 'json' },
          },
        },
        {
          id: 'notify_completion',
          name: 'Send Completion Notification',
          handler: 'email',
          parameters: {
            to: 'admin@example.com',
            subject: 'Data Processing Completed',
            template: 'processing_complete',
            templateData: { inputFile, outputFile },
          },
        },
      ],
      createdBy: 'system',
    });
  },

  /**
   * Multi-step approval workflow
   */
  approvalWorkflow: (requestData: any, approvers: string[]): WorkflowDefinition => {
    const module = new WorkflowModule();
    return module.createApprovalWorkflow({
      id: 'approval_workflow',
      name: 'Multi-Step Approval Workflow',
      actionStep: {
        id: 'execute_action',
        name: 'Execute Approved Action',
        handler: 'database',
        parameters: {
          operation: 'insert',
          table: 'approved_requests',
          data: requestData,
        },
      },
      approvalStep: {
        id: 'approval_gate',
        name: 'Approval Gate',
        requiredApprovers: approvers,
        requiredCount: Math.ceil(approvers.length / 2), // Majority approval
        timeoutMs: 24 * 60 * 60 * 1000, // 24 hours
      },
      createdBy: 'system',
    });
  },
};