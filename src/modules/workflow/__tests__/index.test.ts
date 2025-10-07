/**
 * Workflow Module Tests
 * Tests for WorkflowModule factory and helper functions
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  WorkflowModule,
  ExampleWorkflows,
  StepHandlerRegistry,
  WorkflowDefinition,
} from '../index';

describe('WorkflowModule', () => {
  let module: WorkflowModule;

  beforeEach(() => {
    module = new WorkflowModule();
  });

  describe('initialization', () => {
    it('should create module with default handler registry', () => {
      expect(module).toBeInstanceOf(WorkflowModule);
      expect(module.getHandlerRegistry()).toBeInstanceOf(StepHandlerRegistry);
    });

    it('should create module with custom handlers', () => {
      const customHandlers = {
        custom_handler: {
          execute: async () => ({ success: true }),
        },
      };

      const customModule = WorkflowModule.create(customHandlers);

      expect(customModule.getRegisteredHandlers()).toContain('custom_handler');
    });
  });

  describe('handler management', () => {
    it('should register custom handler', () => {
      const handler = {
        execute: async () => ({ success: true }),
      };

      module.registerHandler('test_handler', handler);

      expect(module.getRegisteredHandlers()).toContain('test_handler');
    });

    it('should get handler registry', () => {
      const registry = module.getHandlerRegistry();

      expect(registry).toBeInstanceOf(StepHandlerRegistry);
      expect(registry.has('http_request')).toBe(true);
    });

    it('should list all registered handlers', () => {
      const handlers = module.getRegisteredHandlers();

      expect(Array.isArray(handlers)).toBe(true);
      expect(handlers.length).toBeGreaterThan(0);
    });
  });

  describe('createWorkflowDefinition', () => {
    it('should create valid workflow definition', () => {
      const definition = module.createWorkflowDefinition({
        id: 'test_workflow',
        name: 'Test Workflow',
        description: 'A test workflow',
        version: '1.0.0',
        steps: [
          {
            id: 'step_1',
            name: 'First Step',
            type: 'action',
            handler: 'http_request',
            parameters: {
              url: 'https://api.example.com',
              method: 'GET',
            },
          },
        ],
        createdBy: 'test_user',
      });

      expect(definition.id).toBe('test_workflow');
      expect(definition.name).toBe('Test Workflow');
      expect(definition.version).toBe('1.0.0');
      expect(definition.steps.length).toBe(1);
      expect(definition.autoRollbackOnFailure).toBe(true);
      expect(definition.enableProgressUpdates).toBe(true);
    });

    it('should set default version if not provided', () => {
      const definition = module.createWorkflowDefinition({
        id: 'test_workflow',
        name: 'Test Workflow',
        steps: [
          {
            id: 'step_1',
            name: 'Step',
            type: 'action',
            handler: 'delay',
            parameters: { delayMs: 1000 },
          },
        ],
        createdBy: 'test_user',
      });

      expect(definition.version).toBe('1.0.0');
    });

    it('should apply retry policy to steps', () => {
      const definition = module.createWorkflowDefinition({
        id: 'test_workflow',
        name: 'Test Workflow',
        steps: [
          {
            id: 'step_1',
            name: 'Step',
            type: 'action',
            handler: 'http_request',
            parameters: { url: 'https://api.example.com' },
          },
        ],
        createdBy: 'test_user',
      });

      expect(definition.steps[0].retryPolicy).toBeDefined();
      expect(definition.steps[0].retryPolicy?.maxRetries).toBe(3);
      expect(definition.steps[0].retryPolicy?.exponentialBackoff).toBe(true);
    });

    it('should set execution mode based on parallel group', () => {
      const definition = module.createWorkflowDefinition({
        id: 'test_workflow',
        name: 'Test Workflow',
        steps: [
          {
            id: 'step_1',
            name: 'Sequential Step',
            type: 'action',
            handler: 'delay',
            parameters: { delayMs: 100 },
          },
          {
            id: 'step_2',
            name: 'Parallel Step',
            type: 'action',
            handler: 'delay',
            parameters: { delayMs: 100 },
            parallelGroup: 'group_1',
          },
        ],
        createdBy: 'test_user',
      });

      expect(definition.steps[0].executionMode).toBe('sequential');
      expect(definition.steps[1].executionMode).toBe('parallel');
    });

    it('should throw on invalid workflow definition', () => {
      expect(() => {
        module.createWorkflowDefinition({
          id: '', // Invalid: empty ID
          name: 'Test',
          steps: [],
          createdBy: 'user',
        });
      }).toThrow();
    });
  });

  describe('createSequentialWorkflow', () => {
    it('should create workflow with sequential dependencies', () => {
      const definition = module.createSequentialWorkflow({
        id: 'sequential_workflow',
        name: 'Sequential Workflow',
        steps: [
          {
            id: 'step_1',
            name: 'First',
            handler: 'delay',
            parameters: { delayMs: 100 },
          },
          {
            id: 'step_2',
            name: 'Second',
            handler: 'delay',
            parameters: { delayMs: 100 },
          },
          {
            id: 'step_3',
            name: 'Third',
            handler: 'delay',
            parameters: { delayMs: 100 },
          },
        ],
        createdBy: 'test_user',
      });

      expect(definition.steps[0].dependsOn).toEqual([]);
      expect(definition.steps[1].dependsOn).toEqual(['step_1']);
      expect(definition.steps[2].dependsOn).toEqual(['step_2']);
    });
  });

  describe('createParallelWorkflow', () => {
    it('should create workflow with parallel execution', () => {
      const definition = module.createParallelWorkflow({
        id: 'parallel_workflow',
        name: 'Parallel Workflow',
        parallelSteps: [
          {
            id: 'step_1',
            name: 'Parallel 1',
            handler: 'delay',
            parameters: { delayMs: 100 },
          },
          {
            id: 'step_2',
            name: 'Parallel 2',
            handler: 'delay',
            parameters: { delayMs: 100 },
          },
        ],
        createdBy: 'test_user',
      });

      expect(definition.steps[0].parallelGroup).toBe('parallel_group_1');
      expect(definition.steps[1].parallelGroup).toBe('parallel_group_1');
      expect(definition.steps[0].dependsOn).toEqual([]);
      expect(definition.steps[1].dependsOn).toEqual([]);
    });
  });

  describe('createApprovalWorkflow', () => {
    it('should create workflow with approval step', () => {
      const definition = module.createApprovalWorkflow({
        id: 'approval_workflow',
        name: 'Approval Workflow',
        actionStep: {
          id: 'execute_action',
          name: 'Execute Action',
          handler: 'database',
          parameters: {
            operation: 'insert',
            table: 'requests',
            data: { status: 'approved' },
          },
        },
        approvalStep: {
          id: 'approval_gate',
          name: 'Approval Gate',
          requiredApprovers: ['user_1', 'user_2'],
          requiredCount: 2,
          timeoutMs: 3600000, // 1 hour (max allowed)
        },
        createdBy: 'test_user',
      });

      expect(definition.steps.length).toBe(2);

      const approvalStep = definition.steps.find(s => s.type === 'approval');
      expect(approvalStep).toBeDefined();
      expect(approvalStep?.approvalConfig).toBeDefined();
      expect(approvalStep?.approvalConfig?.requiredApprovers).toEqual(['user_1', 'user_2']);
      expect(approvalStep?.approvalConfig?.requiredCount).toBe(2);

      const actionStep = definition.steps.find(s => s.id === 'execute_action');
      expect(actionStep?.dependsOn).toContain('approval_gate');
    });
  });
});

describe('ExampleWorkflows', () => {
  describe('httpRequest', () => {
    it('should create HTTP request workflow', () => {
      const workflow = ExampleWorkflows.httpRequest('https://api.example.com', 'POST');

      expect(workflow.id).toBe('http_request_workflow');
      expect(workflow.steps.length).toBe(1);
      expect(workflow.steps[0].handler).toBe('http_request');
      expect(workflow.steps[0].parameters.url).toBe('https://api.example.com');
      expect(workflow.steps[0].parameters.method).toBe('POST');
    });

    it('should default to GET method', () => {
      const workflow = ExampleWorkflows.httpRequest('https://api.example.com');

      expect(workflow.steps[0].parameters.method).toBe('GET');
    });
  });

  describe('dataProcessingPipeline', () => {
    it('should create data processing workflow', () => {
      const workflow = ExampleWorkflows.dataProcessingPipeline(
        '/input/data.csv',
        '/output/data.json'
      );

      expect(workflow.id).toBe('data_processing_pipeline');
      expect(workflow.steps.length).toBe(3);
      expect(workflow.steps[0].name).toContain('Validate');
      expect(workflow.steps[1].name).toContain('Process');
      expect(workflow.steps[2].name).toContain('Completion');
    });

    it('should have sequential dependencies', () => {
      const workflow = ExampleWorkflows.dataProcessingPipeline(
        '/input/data.csv',
        '/output/data.json'
      );

      expect(workflow.steps[0].dependsOn).toEqual([]);
      expect(workflow.steps[1].dependsOn.length).toBeGreaterThan(0);
      expect(workflow.steps[2].dependsOn.length).toBeGreaterThan(0);
    });
  });

  describe('approvalWorkflow', () => {
    it('should create approval workflow', () => {
      const requestData = { amount: 1000, description: 'Budget Request' };
      const approvers = ['manager_1', 'finance_1'];

      const workflow = ExampleWorkflows.approvalWorkflow(requestData, approvers);

      expect(workflow.id).toBe('approval_workflow');
      expect(workflow.steps.length).toBe(2);

      const approvalStep = workflow.steps.find(s => s.type === 'approval');
      expect(approvalStep).toBeDefined();
      expect(approvalStep?.approvalConfig?.requiredApprovers).toEqual(approvers);
      expect(approvalStep?.approvalConfig?.requiredCount).toBe(1); // Majority of 2
    });

    it('should calculate majority approval count', () => {
      const approvers = ['user_1', 'user_2', 'user_3'];
      const workflow = ExampleWorkflows.approvalWorkflow({}, approvers);

      const approvalStep = workflow.steps.find(s => s.type === 'approval');
      expect(approvalStep?.approvalConfig?.requiredCount).toBe(2); // Majority of 3
    });
  });
});

describe('Workflow Type Safety', () => {
  it('should enforce WorkflowDefinition type constraints', () => {
    const module = new WorkflowModule();

    const definition: WorkflowDefinition = module.createWorkflowDefinition({
      id: 'typed_workflow',
      name: 'Typed Workflow',
      steps: [
        {
          id: 'step_1',
          name: 'Test Step',
          type: 'action',
          handler: 'delay',
          parameters: { delayMs: 1000 },
        },
      ],
      createdBy: 'test_user',
    });

    // TypeScript should enforce these types
    expect(typeof definition.id).toBe('string');
    expect(typeof definition.name).toBe('string');
    expect(Array.isArray(definition.steps)).toBe(true);
    expect(typeof definition.autoRollbackOnFailure).toBe('boolean');
  });
});
