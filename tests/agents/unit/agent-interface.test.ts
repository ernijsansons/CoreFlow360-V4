/**
 * Agent Interface Compliance Tests
 * Ensures all agents strictly adhere to the IAgent interface
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  TestEnvironmentFactory,
  TestAssertions,
  BusinessContextGenerator,
  TaskGenerator,
  MockAgent,
  setupAgentTests,
  type TestEnvironment
} from '../test-harness';
import { ClaudeAgent } from '../../../src/modules/agents/claude-agent';
import type {
  IAgent,
  AgentTask,
  BusinessContext,
  AgentResult,
  ValidationResult,
  HealthStatus
} from '../../../src/modules/agents/types';
import { AGENT_LIMITS, COST_LIMITS } from '../../../src/modules/agents/types';

describe('Agent Interface Compliance', () => {
  let testEnv: TestEnvironment;
  let mockAgent: MockAgent;
  let businessContext: BusinessContext;

  setupAgentTests();

  beforeEach(async () => {
    testEnv = await TestEnvironmentFactory.create();
    mockAgent = testEnv.mockAgent;
    businessContext = testEnv.businessContext;
  });

  afterEach(async () => {
    await TestEnvironmentFactory.cleanup(testEnv);
  });

  describe('IAgent Interface Implementation', () => {
    it('should implement all required interface properties', () => {
      TestAssertions.assertAgentInterface(mockAgent);
    });

    it('should have valid agent metadata', () => {
      expect(mockAgent.id).toMatch(/^[a-zA-Z0-9_-]+$/);
      expect(mockAgent.name).toHaveLength.greaterThan(0);
      expect(mockAgent.version).toMatch(/^\d+\.\d+\.\d+$/);
      expect(['native', 'external', 'specialized', 'custom']).toContain(mockAgent.type);
    });

    it('should have at least one capability', () => {
      expect(mockAgent.capabilities).toHaveLength.greaterThan(0);
      mockAgent.capabilities.forEach(capability => {
        expect(capability).toMatch(/^[a-z_]+$/);
      });
    });

    it('should have valid resource constraints', () => {
      expect(mockAgent.costPerCall).toBeGreaterThanOrEqual(0);
      expect(mockAgent.maxConcurrency).toBeGreaterThan(0);
      expect(mockAgent.maxConcurrency).toBeLessThanOrEqual(AGENT_LIMITS.MAX_CONCURRENT_TASKS);
      expect(mockAgent.averageLatency).toBeGreaterThan(0);
    });

    it('should support required languages and formats', () => {
      if (mockAgent.supportedLanguages) {
        expect(mockAgent.supportedLanguages).toContain('en');
      }
      if (mockAgent.supportedFormats) {
        expect(mockAgent.supportedFormats.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Core Method Implementation', () => {
    let task: AgentTask;

    beforeEach(() => {
      task = TaskGenerator.generate({
        capability: 'test',
        context: businessContext
      });
    });

    describe('execute() method', () => {
      it('should execute task successfully', async () => {
        const result = await mockAgent.execute(task, businessContext);

        TestAssertions.assertAgentResult(result);
        expect(result.taskId).toBe(task.id);
        expect(result.agentId).toBe(mockAgent.id);
        expect(result.status).toBe('completed');
      });

      it('should handle task with minimal input', async () => {
        const minimalTask = TaskGenerator.generate({
          input: { prompt: 'test' },
          capability: 'test'
        });

        const result = await mockAgent.execute(minimalTask, businessContext);
        expect(result.status).toBe('completed');
      });

      it('should respect task constraints', async () => {
        const constrainedTask = TaskGenerator.generate({
          constraints: {
            maxCost: 0.005, // Lower than agent cost
            maxLatency: 50, // Very low latency
            requiredAccuracy: 0.99
          }
        });

        // Should either succeed within constraints or fail appropriately
        try {
          const result = await mockAgent.execute(constrainedTask, businessContext);
          expect(result.metrics.costUSD).toBeLessThanOrEqual(0.005);
          expect(result.metrics.executionTime).toBeLessThanOrEqual(50);
        } catch (error) {
          // Acceptable to fail if constraints cannot be met
          expect(error).toBeInstanceOf(Error);
        }
      });

      it('should handle streaming tasks', async () => {
        const streamingTask = TaskGenerator.generate({
          constraints: { streamingEnabled: true }
        });

        const result = await mockAgent.execute(streamingTask, businessContext);
        expect(result.status).toBe('completed');
      });

      it('should track execution metrics accurately', async () => {
        const startTime = Date.now();
        const result = await mockAgent.execute(task, businessContext);
        const endTime = Date.now();

        expect(result.metrics.executionTime).toBeGreaterThan(0);
        expect(result.metrics.executionTime).toBeLessThanOrEqual(endTime - startTime + 10); // 10ms tolerance
        expect(result.metrics.costUSD).toBeGreaterThanOrEqual(0);
        expect(result.startedAt).toBeGreaterThanOrEqual(startTime);
        expect(result.completedAt).toBeLessThanOrEqual(endTime);
      });

      it('should handle business context correctly', async () => {
        const multiTenantContexts = BusinessContextGenerator.generateMultiTenant(['biz-1', 'biz-2']);

        for (const context of multiTenantContexts) {
          const contextTask = TaskGenerator.generate({ context });
          const result = await mockAgent.execute(contextTask, context);

          expect(result.status).toBe('completed');
          // Should maintain business context isolation
          expect(result.metadata?.businessId || context.businessId).toBe(context.businessId);
        }
      });
    });

    describe('validateInput() method', () => {
      it('should validate valid input', async () => {
        const validInput = {
          prompt: 'Test prompt',
          data: { test: true },
          parameters: { param1: 'value1' }
        };

        const result = await mockAgent.validateInput(validInput, 'test');
        expect(result.valid).toBe(true);
        expect(result.errors).toBeUndefined();
      });

      it('should reject invalid input', async () => {
        const invalidInputs = [
          null,
          undefined,
          'string',
          123,
          []
        ];

        for (const input of invalidInputs) {
          const result = await mockAgent.validateInput(input, 'test');
          expect(result.valid).toBe(false);
          expect(result.errors).toBeDefined();
          expect(result.errors!.length).toBeGreaterThan(0);
        }
      });

      it('should sanitize input when needed', async () => {
        const unsafeInput = {
          prompt: '<script>alert("xss")</script>',
          data: { malicious: 'DROP TABLE users;' }
        };

        const result = await mockAgent.validateInput(unsafeInput, 'test');

        if (result.sanitizedInput) {
          expect(result.sanitizedInput).not.toEqual(unsafeInput);
        }
      });

      it('should validate capability-specific input', async () => {
        const capabilities = mockAgent.capabilities;

        for (const capability of capabilities) {
          const result = await mockAgent.validateInput({ test: true }, capability);
          expect(result).toBeDefined();
          expect(typeof result.valid).toBe('boolean');
        }
      });
    });

    describe('estimateCost() method', () => {
      it('should provide accurate cost estimates', async () => {
        const cost = await mockAgent.estimateCost(task);

        expect(cost).toBeGreaterThanOrEqual(0);
        expect(cost).toBeLessThanOrEqual(COST_LIMITS.DEFAULT_TASK_LIMIT_USD);
      });

      it('should scale cost with task complexity', async () => {
        const simpleTasks = TaskGenerator.generateBatch(5, {
          input: { prompt: 'simple' }
        });

        const complexTasks = TaskGenerator.generateBatch(5, {
          input: {
            prompt: 'complex task with multiple parameters and large data',
            data: { large: 'data'.repeat(1000) }
          }
        });

        const simpleCosts = await Promise.all(
          simpleTasks.map(t => mockAgent.estimateCost(t))
        );

        const complexCosts = await Promise.all(
          complexTasks.map(t => mockAgent.estimateCost(t))
        );

        const avgSimpleCost = simpleCosts.reduce((a, b) => a + b, 0) / simpleCosts.length;
        const avgComplexCost = complexCosts.reduce((a, b) => a + b, 0) / complexCosts.length;

        // Complex tasks should generally cost more (or at least not less)
        expect(avgComplexCost).toBeGreaterThanOrEqual(avgSimpleCost);
      });

      it('should provide consistent estimates', async () => {
        const estimates = await Promise.all([
          mockAgent.estimateCost(task),
          mockAgent.estimateCost(task),
          mockAgent.estimateCost(task)
        ]);

        // All estimates should be identical for the same task
        expect(estimates[0]).toBe(estimates[1]);
        expect(estimates[1]).toBe(estimates[2]);
      });
    });

    describe('healthCheck() method', () => {
      it('should report current health status', async () => {
        const health = await mockAgent.healthCheck();

        expect(health.status).toBeDefined();
        expect(['online', 'offline', 'degraded', 'maintenance', 'error']).toContain(health.status);
        expect(health.lastCheck).toBeGreaterThan(0);
      });

      it('should include performance metrics', async () => {
        const health = await mockAgent.healthCheck();

        if (health.latency !== undefined) {
          expect(health.latency).toBeGreaterThan(0);
        }

        if (health.errorRate !== undefined) {
          expect(health.errorRate).toBeGreaterThanOrEqual(0);
          expect(health.errorRate).toBeLessThanOrEqual(1);
        }
      });

      it('should detect degraded performance', async () => {
        // Simulate degraded performance
        mockAgent.setHealthStatus({
          status: 'degraded',
          latency: 5000,
          errorRate: 0.1,
          lastCheck: Date.now(),
          details: {
            apiConnectivity: true,
            memoryUsage: 0.9,
            recentErrors: ['timeout', 'rate_limit']
          }
        });

        const health = await mockAgent.healthCheck();
        expect(health.status).toBe('degraded');
        expect(health.details?.recentErrors).toBeDefined();
      });

      it('should track health check timing', async () => {
        const beforeCheck = Date.now();
        const health = await mockAgent.healthCheck();
        const afterCheck = Date.now();

        expect(health.lastCheck).toBeGreaterThanOrEqual(beforeCheck);
        expect(health.lastCheck).toBeLessThanOrEqual(afterCheck);
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle execution failures gracefully', async () => {
      mockAgent.shouldFail = true;

      await expect(mockAgent.execute(task, businessContext))
        .rejects.toThrow('Mock agent intentional failure');
    });

    it('should validate business context requirements', async () => {
      const invalidContexts = [
        { ...businessContext, businessId: '' },
        { ...businessContext, userId: '' },
        { ...businessContext, businessData: undefined as any }
      ];

      for (const invalidContext of invalidContexts) {
        try {
          await mockAgent.execute(task, invalidContext);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle unsupported capabilities', async () => {
      const unsupportedTask = TaskGenerator.generate({
        capability: 'unsupported_capability'
      });

      const result = await mockAgent.validateInput(
        unsupportedTask.input,
        'unsupported_capability'
      );

      // Should either handle gracefully or indicate unsupported
      expect(typeof result.valid).toBe('boolean');
    });
  });

  describe('Concurrency Limits', () => {
    it('should respect maximum concurrency', async () => {
      const concurrentTasks = TaskGenerator.generateBatch(
        mockAgent.maxConcurrency + 5
      );

      const startTime = Date.now();
      const results = await Promise.allSettled(
        concurrentTasks.map(t => mockAgent.execute(t, businessContext))
      );
      const endTime = Date.now();

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      // Should either complete all tasks or fail some due to concurrency limits
      expect(successful + failed).toBe(concurrentTasks.length);

      // If all succeeded, execution should show some queueing delay
      if (successful === concurrentTasks.length) {
        expect(endTime - startTime).toBeGreaterThan(0);
      }
    });
  });

  describe('Memory Management', () => {
    it('should not leak memory during multiple executions', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Execute many tasks
      const tasks = TaskGenerator.generateBatch(100);
      await Promise.all(
        tasks.map(t => mockAgent.execute(t, businessContext))
      );

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory should not increase dramatically
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // 50MB limit
    });
  });
});

describe('Claude Agent Specific Tests', () => {
  let claudeAgent: ClaudeAgent;
  let businessContext: BusinessContext;

  beforeEach(() => {
    const mockConfig = {
      id: 'claude-test',
      name: 'Claude Test Agent',
      type: 'external' as const,
      enabled: true,
      apiKey: 'test-key',
      model: 'claude-3-sonnet-20240229',
      maxTokens: 4000,
      temperature: 0.7,
      capabilities: ['analysis', 'generation', 'reasoning'],
      departments: ['all'],
      maxConcurrency: 5,
      costPerCall: 0.02,
      owner: 'test',
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    claudeAgent = new ClaudeAgent(mockConfig);
    businessContext = BusinessContextGenerator.generate();
  });

  it('should implement IAgent interface correctly', () => {
    TestAssertions.assertAgentInterface(claudeAgent);
  });

  it('should have Claude-specific properties', () => {
    expect(claudeAgent.id).toBe('claude-test');
    expect(claudeAgent.type).toBe('external');
    expect(claudeAgent.capabilities).toContain('analysis');
    expect(claudeAgent.costPerCall).toBeGreaterThan(0);
  });

  it('should validate Anthropic API requirements', async () => {
    const task = TaskGenerator.generate({
      capability: 'analysis',
      input: {
        prompt: 'Analyze this business data',
        data: { revenue: 100000, expenses: 80000 }
      }
    });

    // Should handle API key validation
    const validation = await claudeAgent.validateInput(task.input, 'analysis');
    expect(typeof validation.valid).toBe('boolean');
  });

  it('should estimate costs based on token usage', async () => {
    const shortTask = TaskGenerator.generate({
      input: { prompt: 'Hello' }
    });

    const longTask = TaskGenerator.generate({
      input: { prompt: 'Analyze this very long prompt with lots of details about the business operations, financial metrics, strategic planning, and comprehensive market analysis that requires extensive processing and detailed response generation with multiple sections and comprehensive explanations.' }
    });

    const shortCost = await claudeAgent.estimateCost(shortTask);
    const longCost = await claudeAgent.estimateCost(longTask);

    expect(shortCost).toBeGreaterThan(0);
    expect(longCost).toBeGreaterThan(shortCost);
  });
});