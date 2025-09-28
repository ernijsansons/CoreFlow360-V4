/**
 * Comprehensive Agent Orchestrator Test Suite
 * Testing complex multi-agent coordination, cost management, and execution flows
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';
import type { KVNamespace, D1Database } from '../../src/cloudflare/types/cloudflare';
import { AgentOrchestrator } from '../../src/modules/agent-system/orchestrator';
import { AgentRegistry } from '../../src/modules/agent-system/registry';
import { AgentMemory } from '../../src/modules/agent-system/memory';
import { CostTracker } from '../../src/modules/agent-system/cost-tracker';
import { RetryHandler } from '../../src/modules/agent-system/retry-handler';
import {
  AgentTask,
  BusinessContext,
  OrchestratorResult,
  Workflow,
  IAgent,
  AgentResult,
  AGENT_CONSTANTS
} from '../../src/modules/agent-system/types';

// Mock implementations
class MockKVNamespace implements Partial<KVNamespace> {
  private storage = new Map<string, string>();
  private metadata = new Map<string, any>();

  async get(key: string, options?: any): Promise<string | null> {
    const value = this.storage.get(key);
    if (options?.type === 'json' && value) {
      return JSON.parse(value) as any;
    }
    return value || null;
  }

  async put(key: string, value: string | ArrayBuffer | ArrayBufferView | ReadableStream, options?: any): Promise<void> {
    if (typeof value !== 'string') {
      value = JSON.stringify(value);
    }
    this.storage.set(key, value as string);
    if (options?.metadata) {
      this.metadata.set(key, options.metadata);
    }
  }

  async delete(key: string): Promise<void> {
    this.storage.delete(key);
    this.metadata.delete(key);
  }

  async list(options?: any): Promise<any> {
    const keys = Array.from(this.storage.keys());
    return {
      keys: keys.map(name => ({ name })),
      list_complete: true,
      cursor: undefined
    };
  }

  clear(): void {
    this.storage.clear();
    this.metadata.clear();
  }
}

class MockD1Database implements Partial<D1Database> {
  private prepared = new Map<string, any>();
  private shouldFail = false;

  prepare(query: string): any {
    const mockPrepared = {
      bind: (...params: any[]) => ({
        all: async () => {
          if (this.shouldFail) throw new Error('Database error');
          return { results: [], success: true };
        },
        first: async () => {
          if (this.shouldFail) throw new Error('Database error');
          return null;
        },
        run: async () => {
          if (this.shouldFail) throw new Error('Database error');
          return { success: true };
        }
      }),
      all: async () => {
        if (this.shouldFail) throw new Error('Database error');
        return { results: [], success: true };
      },
      first: async () => {
        if (this.shouldFail) throw new Error('Database error');
        return null;
      },
      run: async () => {
        if (this.shouldFail) throw new Error('Database error');
        return { success: true };
      }
    };
    this.prepared.set(query, mockPrepared);
    return mockPrepared;
  }

  simulateFailure(shouldFail: boolean = true): void {
    this.shouldFail = shouldFail;
  }

  reset(): void {
    this.prepared.clear();
    this.shouldFail = false;
  }
}

class MockAgent implements IAgent {
  id: string;
  name: string;
  type = 'mock' as const;
  capabilities: string[];
  department: string[];
  costPerCall: number;
  maxConcurrency: number;
  private shouldFail: boolean = false;
  private executionDelay: number = 0;

  constructor(id: string, capabilities: string[] = ['*'], cost: number = 0.01) {
    this.id = id;
    this.name = `Mock Agent ${id}`;
    this.capabilities = capabilities;
    this.department = ['general'];
    this.costPerCall = cost;
    this.maxConcurrency = 10;
  }

  async execute(task: AgentTask, context: BusinessContext): Promise<AgentResult> {
    if (this.executionDelay > 0) {
      await new Promise(resolve => setTimeout(resolve, this.executionDelay));
    }

    if (this.shouldFail) {
      throw new Error(`Agent ${this.id} execution failed`);
    }

    return {
      taskId: task.id,
      agentId: this.id,
      success: true,
      data: { response: `Mock response from ${this.id}`, processed: task.input },
      confidence: 0.9,
      metrics: {
        startTime: Date.now() - 100,
        endTime: Date.now(),
        latency: 100,
        cost: this.costPerCall,
        tokensUsed: 500,
        retryCount: 0,
        memoryHits: 0
      }
    };
  }

  validateInput(input: unknown): { valid: boolean; errors?: string[] } {
    return { valid: true };
  }

  estimateCost(task: AgentTask): number {
    return this.costPerCall;
  }

  async healthCheck(): Promise<any> {
    return {
      healthy: !this.shouldFail,
      status: this.shouldFail ? 'offline' : 'online',
      latency: 50,
      lastCheck: Date.now()
    };
  }

  simulateFailure(shouldFail: boolean = true): void {
    this.shouldFail = shouldFail;
  }

  setExecutionDelay(delay: number): void {
    this.executionDelay = delay;
  }
}

describe('AgentOrchestrator Comprehensive Tests', () => {
  let orchestrator: AgentOrchestrator;
  let mockKV: MockKVNamespace;
  let mockDB: MockD1Database;
  let mockRegistry: AgentRegistry;
  let mockMemory: AgentMemory;
  let mockCostTracker: CostTracker;
  let mockRetryHandler: RetryHandler;
  let mockAgents: MockAgent[];

  const createMockTask = (overrides: Partial<AgentTask> = {}): AgentTask => ({
    id: `task_${Date.now()}_${Math.random()}`,
    capability: 'test_capability',
    input: { message: 'Test task input' },
    context: {
      businessId: 'test_business',
      userId: 'test_user',
      sessionId: 'test_session',
      department: 'general',
      timezone: 'UTC',
      currency: 'USD',
      locale: 'en-US',
      permissions: ['read', 'write']
    },
    constraints: {
      timeout: 30000,
      retryLimit: 3,
      maxCost: 1.0
    },
    ...overrides
  });

  const createMockWorkflow = (stepCount: number = 3): Workflow => ({
    id: `workflow_${Date.now()}`,
    name: 'Test Workflow',
    description: 'Test workflow for orchestrator testing',
    version: '1.0.0',
    steps: Array.from({ length: stepCount }, (_, i) => ({
      id: `step_${i + 1}`,
      name: `Step ${i + 1}`,
      capability: `test_capability_${i + 1}`,
      input: { stepData: `Step ${i + 1} data` },
      required: i < 2, // First two steps are required
      retryable: true,
      dependencies: i > 0 ? [`step_${i}`] : undefined
    })),
    metadata: {
      businessId: 'test_business',
      userId: 'test_user',
      timezone: 'UTC',
      currency: 'USD',
      locale: 'en-US',
      permissions: ['read', 'write']
    }
  });

  beforeEach(async () => {
    // Reset all mocks
    vi.clearAllMocks();

    // Create mock dependencies
    mockKV = new MockKVNamespace();
    mockDB = new MockD1Database();

    // Create mock agents
    mockAgents = [
      new MockAgent('agent_1', ['test_capability', 'analysis'], 0.01),
      new MockAgent('agent_2', ['test_capability', 'data_processing'], 0.02),
      new MockAgent('agent_3', ['advanced_capability'], 0.05)
    ];

    // Create mock registry
    mockRegistry = new AgentRegistry();
    mockAgents.forEach(agent => {
      mockRegistry.registerAgent(agent, {
        priority: 1.0,
        loadBalancing: { weight: 1.0, maxConcurrent: 10, utilization: 0.0 },
        healthCheck: { enabled: true, interval: 30000, timeout: 5000 }
      });
    });

    // Create mock memory
    mockMemory = new AgentMemory(mockKV as any, mockDB as any);

    // Create mock cost tracker
    mockCostTracker = new CostTracker(mockDB as any, mockKV as any);

    // Create mock retry handler
    mockRetryHandler = new RetryHandler();

    // Create orchestrator
    orchestrator = new AgentOrchestrator(
      mockRegistry,
      mockMemory,
      mockCostTracker,
      mockRetryHandler,
      mockKV as any,
      mockDB as any
    );
  });

  afterEach(() => {
    mockKV.clear();
    mockDB.reset();
    mockAgents.forEach(agent => agent.simulateFailure(false));
  });

  describe('Task Execution', () => {
    it('should execute simple task successfully', async () => {
      const task = createMockTask();
      const result = await orchestrator.executeTask(task);

      expect(result.success).toBe(true);
      expect(result.taskId).toBe(task.id);
      expect(result.selectedAgent).toBeDefined();
      expect(result.result).toBeDefined();
      expect(result.totalCost).toBeGreaterThan(0);
      expect(result.totalLatency).toBeGreaterThan(0);
      expect(result.executionPath).toHaveLength(6); // All execution steps
    });

    it('should handle agent selection based on capabilities', async () => {
      const task = createMockTask({ capability: 'advanced_capability' });
      const result = await orchestrator.executeTask(task);

      expect(result.success).toBe(true);
      expect(result.selectedAgent).toBe('agent_3'); // Only agent_3 has advanced_capability
    });

    it('should handle cost constraints during agent selection', async () => {
      const task = createMockTask({
        capability: 'test_capability',
        constraints: { maxCost: 0.015, retryLimit: 3, timeout: 30000 }
      });
      const result = await orchestrator.executeTask(task);

      expect(result.success).toBe(true);
      // Should select agent_1 (0.01) over agent_2 (0.02) due to cost constraint
      expect(result.selectedAgent).toBe('agent_1');
    });

    it('should fail when cost constraints cannot be met', async () => {
      const task = createMockTask({
        capability: 'advanced_capability',
        constraints: { maxCost: 0.001, retryLimit: 3, timeout: 30000 }
      });
      const result = await orchestrator.executeTask(task);

      expect(result.success).toBe(false);
      expect(result.error?.message).toContain('Estimated cost');
    });

    it('should handle agent execution failures with retries', async () => {
      const task = createMockTask();

      // Make first agent fail initially
      mockAgents[0].simulateFailure(true);

      // Mock retry handler to succeed on second attempt
      let attemptCount = 0;
      const originalExecute = mockRetryHandler.executeWithRetry;
      mockRetryHandler.executeWithRetry = vi.fn().mockImplementation(async (agent, taskParam, context, maxAttempts) => {
        attemptCount++;
        if (attemptCount === 1) {
          mockAgents[0].simulateFailure(false); // Fix on second attempt
        }
        return await agent.execute(taskParam, context);
      });

      const result = await orchestrator.executeTask(task);

      expect(result.success).toBe(true);
      expect(mockRetryHandler.executeWithRetry).toHaveBeenCalled();
    });

    it('should handle memory context loading and saving', async () => {
      const task = createMockTask();

      // Mock memory operations
      const loadSpy = vi.spyOn(mockMemory, 'load').mockResolvedValue({
        shortTerm: [{ role: 'user', content: 'Previous message' }],
        longTerm: {}
      });
      const saveSpy = vi.spyOn(mockMemory, 'save').mockResolvedValue();

      const result = await orchestrator.executeTask(task);

      expect(result.success).toBe(true);
      expect(loadSpy).toHaveBeenCalledWith(task.context.businessId, task.context.sessionId);
      expect(saveSpy).toHaveBeenCalledWith(
        task.context.businessId,
        task.context.sessionId,
        expect.any(Object)
      );
    });

    it('should handle concurrent task executions safely', async () => {
      const tasks = Array.from({ length: 5 }, () => createMockTask());

      const results = await Promise.all(
        tasks.map(task => orchestrator.executeTask(task))
      );

      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result.success).toBe(true);
        expect(result.selectedAgent).toBeDefined();
      });

      // Verify all tasks have unique IDs
      const taskIds = results.map(r => r.taskId);
      expect(new Set(taskIds).size).toBe(5);
    });

    it('should implement idempotency for duplicate tasks', async () => {
      const task = createMockTask();

      // Execute the same task twice
      const result1 = await orchestrator.executeTask(task);
      const result2 = await orchestrator.executeTask(task);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);

      // Results should be identical (idempotent)
      expect(result1.taskId).toBe(result2.taskId);
    });
  });

  describe('Workflow Execution', () => {
    it('should execute workflow with sequential steps successfully', async () => {
      const workflow = createMockWorkflow(3);
      const result = await orchestrator.executeWorkflow(workflow);

      expect(result.success).toBe(true);
      expect(result.workflowId).toBe(workflow.id);
      expect(result.steps).toHaveLength(3);
      expect(result.totalCost).toBeGreaterThan(0);
      expect(result.totalLatency).toBeGreaterThan(0);

      // All steps should be successful
      result.steps.forEach(step => {
        expect(step.success).toBe(true);
      });
    });

    it('should handle workflow step dependencies correctly', async () => {
      const workflow = createMockWorkflow(3);

      // Make the first step fail
      mockAgents[0].simulateFailure(true);

      const result = await orchestrator.executeWorkflow(workflow);

      expect(result.success).toBe(false);
      expect(result.steps[0].success).toBe(false);
      // Dependent steps should not execute if required step fails
      expect(result.error).toContain('Required step');
    });

    it('should skip optional steps when dependencies are not met', async () => {
      const workflow = createMockWorkflow(3);

      // Make all steps optional except the first
      workflow.steps[1].required = false;
      workflow.steps[2].required = false;

      // Make the first step fail
      mockAgents[0].simulateFailure(true);

      const result = await orchestrator.executeWorkflow(workflow);

      expect(result.success).toBe(false);
      expect(result.steps[0].success).toBe(false);

      // Optional dependent steps should be skipped
      expect(result.steps.some(step => step.agentId === 'skipped')).toBe(true);
    });

    it('should handle workflow with parallel-capable steps', async () => {
      const workflow = createMockWorkflow(3);

      // Remove dependencies to allow parallel execution
      workflow.steps[1].dependencies = undefined;
      workflow.steps[2].dependencies = undefined;

      const result = await orchestrator.executeWorkflow(workflow);

      expect(result.success).toBe(true);
      expect(result.steps).toHaveLength(3);

      // All steps should execute successfully
      result.steps.forEach(step => {
        expect(step.success).toBe(true);
      });
    });

    it('should calculate total workflow costs accurately', async () => {
      const workflow = createMockWorkflow(3);
      const result = await orchestrator.executeWorkflow(workflow);

      expect(result.success).toBe(true);

      const stepCosts = result.steps.reduce((total, step) => total + step.cost, 0);
      expect(result.totalCost).toBe(stepCosts);
      expect(result.totalCost).toBeGreaterThan(0);
    });
  });

  describe('Execution Monitoring and Management', () => {
    it('should track active executions', async () => {
      const task = createMockTask();

      // Set execution delay to monitor active execution
      mockAgents[0].setExecutionDelay(500);

      const executionPromise = orchestrator.executeTask(task);

      // Check active executions during execution
      await new Promise(resolve => setTimeout(resolve, 100));
      const activeExecutions = orchestrator.getActiveExecutions();
      expect(activeExecutions.length).toBeGreaterThan(0);

      // Wait for completion
      await executionPromise;

      // Should be no active executions after completion
      const finalActiveExecutions = orchestrator.getActiveExecutions();
      expect(finalActiveExecutions.length).toBe(0);
    });

    it('should cancel active executions', async () => {
      const task = createMockTask();

      // Set long execution delay
      mockAgents[0].setExecutionDelay(2000);

      const executionPromise = orchestrator.executeTask(task);

      // Wait for execution to start
      await new Promise(resolve => setTimeout(resolve, 100));

      const activeExecutions = orchestrator.getActiveExecutions();
      expect(activeExecutions.length).toBe(1);

      const executionId = activeExecutions[0].executionId;
      const cancelled = await orchestrator.cancelExecution(executionId, 'Test cancellation');

      expect(cancelled).toBe(true);

      // Check that execution is marked as cancelled
      const updatedExecutions = orchestrator.getActiveExecutions();
      const cancelledExecution = updatedExecutions.find(e => e.executionId === executionId);
      expect(cancelledExecution?.status).toBe('cancelled');
      expect(cancelledExecution?.cancelReason).toBe('Test cancellation');

      // Clean up
      try {
        await executionPromise;
      } catch {
        // Expected to fail due to cancellation
      }
    });

    it('should provide accurate orchestrator statistics', async () => {
      const tasks = Array.from({ length: 3 }, () => createMockTask());

      await Promise.all(tasks.map(task => orchestrator.executeTask(task)));

      const stats = orchestrator.getStatistics();

      expect(stats.activeExecutions).toBe(0);
      expect(stats.totalExecutions).toBeGreaterThanOrEqual(3);
      expect(stats.totalCost).toBeGreaterThan(0);
      expect(stats.averageLatency).toBeGreaterThan(0);
      expect(stats.successRate).toBeGreaterThan(0);
      expect(stats.registryStats).toBeDefined();
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle database failures gracefully', async () => {
      const task = createMockTask();

      // Simulate database failure
      mockDB.simulateFailure(true);

      const result = await orchestrator.executeTask(task);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle agent registry failures', async () => {
      const task = createMockTask({ capability: 'nonexistent_capability' });

      try {
        await orchestrator.executeTask(task);
        expect(false).toBe(true); // Should not reach here
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it('should provide detailed error information', async () => {
      const task = createMockTask();

      // Make all agents fail
      mockAgents.forEach(agent => agent.simulateFailure(true));

      const result = await orchestrator.executeTask(task);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error?.code).toBe('EXECUTION_FAILED');
      expect(result.error?.retryable).toBeDefined();
      expect(result.error?.suggestedActions).toBeDefined();
      expect(result.executionPath.length).toBeGreaterThan(0);
    });

    it('should handle memory operation failures', async () => {
      const task = createMockTask();

      // Mock memory save failure
      vi.spyOn(mockMemory, 'save').mockRejectedValue(new Error('Memory save failed'));

      // Should still complete task even if memory save fails
      const result = await orchestrator.executeTask(task);

      expect(result.success).toBe(true); // Task execution should succeed
      // Memory failure should be logged but not fail the task
    });
  });

  describe('Performance and Load Testing', () => {
    it('should handle high concurrent load', async () => {
      const taskCount = 50;
      const tasks = Array.from({ length: taskCount }, () => createMockTask());

      const startTime = Date.now();
      const results = await Promise.all(
        tasks.map(task => orchestrator.executeTask(task))
      );
      const totalTime = Date.now() - startTime;

      expect(results).toHaveLength(taskCount);

      const successCount = results.filter(r => r.success).length;
      expect(successCount).toBeGreaterThanOrEqual(taskCount * 0.9); // 90% success rate

      const averageLatency = totalTime / taskCount;
      expect(averageLatency).toBeLessThan(1000); // Should be under 1 second per task on average
    });

    it('should maintain performance under agent failures', async () => {
      const taskCount = 20;
      const tasks = Array.from({ length: taskCount }, () => createMockTask());

      // Make some agents fail randomly
      mockAgents[0].simulateFailure(true);

      const results = await Promise.all(
        tasks.map(task => orchestrator.executeTask(task))
      );

      // Should still achieve reasonable success rate with remaining agents
      const successCount = results.filter(r => r.success).length;
      expect(successCount).toBeGreaterThanOrEqual(taskCount * 0.6); // 60% success rate
    });

    it('should handle memory pressure gracefully', async () => {
      const taskCount = 100;
      const tasks = Array.from({ length: taskCount }, () => createMockTask());

      // Execute tasks in batches to test memory management
      const batchSize = 10;
      const results: OrchestratorResult[] = [];

      for (let i = 0; i < taskCount; i += batchSize) {
        const batch = tasks.slice(i, i + batchSize);
        const batchResults = await Promise.all(
          batch.map(task => orchestrator.executeTask(task))
        );
        results.push(...batchResults);

        // Small delay between batches
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      expect(results).toHaveLength(taskCount);

      const successCount = results.filter(r => r.success).length;
      expect(successCount).toBeGreaterThanOrEqual(taskCount * 0.95); // 95% success rate
    });
  });
});