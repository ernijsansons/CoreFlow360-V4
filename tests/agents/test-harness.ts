/**
 * Elite Agent Test Harness
 * Comprehensive testing framework for CoreFlow360 agents
 */

import { vi, beforeEach, afterEach } from 'vitest';
import type { MockedFunction } from 'vitest';
import {
  IAgent,
  AgentTask,
  BusinessContext,
  AgentResult,
  AgentConfig,
  HealthStatus,
  ValidationResult,
  TaskPriority,
  StreamingChunk
} from '../../src/modules/agents/types';
import { AgentOrchestrator } from '../../src/modules/agents/orchestrator';
import { AgentRegistry } from '../../src/modules/agents/registry';
import { ClaudeAgent } from '../../src/modules/agents/claude-agent';
import { Logger } from '../../src/shared/logger';

// Test Environment Setup
export interface TestEnvironment {
  orchestrator: AgentOrchestrator;
  registry: AgentRegistry;
  logger: Logger;
  mockAgent: MockAgent;
  businessContext: BusinessContext;
  mockEnv: any;
}

export interface PerformanceMetrics {
  executionTime: number;
  memoryUsage: number;
  cpuUsage: number;
  taskThroughput: number;
  errorRate: number;
  responseTime: number;
}

export interface TestScenario {
  name: string;
  description: string;
  category: 'unit' | 'integration' | 'performance' | 'security' | 'e2e';
  priority: 'critical' | 'high' | 'medium' | 'low';
  expectedDuration: number;
  setup?: () => Promise<void>;
  teardown?: () => Promise<void>;
}

/**
 * Mock Agent for Testing
 */
export class MockAgent implements IAgent {
  readonly id: string = 'test-agent';
  readonly name: string = 'Test Agent';
  readonly type = 'native' as const;
  readonly version: string = '1.0.0';
  readonly capabilities: string[] = ['test', 'mock', 'validation'];
  readonly departments: string[] = ['engineering', 'qa'];
  readonly tags: string[] = ['test', 'mock'];
  readonly costPerCall: number = 0.01;
  readonly maxConcurrency: number = 10;
  readonly averageLatency: number = 100;
  readonly supportedLanguages: string[] = ['en'];
  readonly supportedFormats: string[] = ['json', 'text'];

  private executionResults: Map<string, AgentResult> = new Map();
  private validationResults: Map<string, ValidationResult> = new Map();
  private healthStatus: HealthStatus = {
    status: 'online',
    latency: 100,
    errorRate: 0,
    lastCheck: Date.now()
  };

  // Mock execution control
  public shouldFail: boolean = false;
  public executionDelay: number = 0;
  public costMultiplier: number = 1;
  public customResponse: any = null;

  async execute(task: AgentTask, context: BusinessContext): Promise<AgentResult> {
    const startTime = Date.now();

    if (this.executionDelay > 0) {
      await new Promise(resolve => setTimeout(resolve, this.executionDelay));
    }

    if (this.shouldFail) {
      throw new Error('Mock agent intentional failure');
    }

    const result: AgentResult = {
      taskId: task.id,
      agentId: this.id,
      status: 'completed',
      result: {
        data: this.customResponse || { message: 'Mock response', taskId: task.id },
        confidence: 0.95,
        reasoning: 'Mock agent execution',
        sources: ['test-data']
      },
      metrics: {
        executionTime: Date.now() - startTime,
        tokensUsed: 100,
        costUSD: this.costPerCall * this.costMultiplier,
        modelUsed: 'mock-model',
        retryCount: 0,
        cacheHit: false
      },
      startedAt: startTime,
      completedAt: Date.now()
    };

    this.executionResults.set(task.id, result);
    return result;
  }

  async validateInput(input: unknown, capability: string): Promise<ValidationResult> {
    const result: ValidationResult = {
      valid: true,
      sanitizedInput: input
    };

    if (typeof input !== 'object' || input === null) {
      result.valid = false;
      result.errors = [{
        field: 'input',
        code: 'INVALID_TYPE',
        message: 'Input must be an object'
      }];
    }

    this.validationResults.set(capability, result);
    return result;
  }

  async estimateCost(task: AgentTask): Promise<number> {
    return this.costPerCall * this.costMultiplier;
  }

  async healthCheck(): Promise<HealthStatus> {
    this.healthStatus.lastCheck = Date.now();
    return this.healthStatus;
  }

  // Test utilities
  setHealthStatus(status: HealthStatus): void {
    this.healthStatus = status;
  }

  getExecutionResult(taskId: string): AgentResult | undefined {
    return this.executionResults.get(taskId);
  }

  getValidationResult(capability: string): ValidationResult | undefined {
    return this.validationResults.get(capability);
  }

  reset(): void {
    this.executionResults.clear();
    this.validationResults.clear();
    this.shouldFail = false;
    this.executionDelay = 0;
    this.costMultiplier = 1;
    this.customResponse = null;
    this.healthStatus = {
      status: 'online',
      latency: 100,
      errorRate: 0,
      lastCheck: Date.now()
    };
  }
}

/**
 * Business Context Generator
 */
export class BusinessContextGenerator {
  static generate(overrides: Partial<BusinessContext> = {}): BusinessContext {
    const defaultContext: BusinessContext = {
      userId: 'test-user-123',
      businessId: 'test-business-123',
      tenantId: 'test-tenant-123',
      sessionId: 'test-session-123',
      correlationId: 'test-correlation-123',
      businessData: {
        companyName: 'Test Company Inc.',
        industry: 'Technology',
        size: 'medium',
        timezone: 'America/New_York',
        locale: 'en-US',
        currency: 'USD',
        fiscalYearStart: '01-01'
      },
      userContext: {
        name: 'Test User',
        email: 'test@example.com',
        role: 'admin',
        department: 'engineering',
        permissions: ['read', 'write', 'admin'],
        preferences: { theme: 'dark', notifications: true }
      },
      businessState: {
        currentFiscalPeriod: '2024-Q1',
        activeProjects: ['project-1', 'project-2'],
        recentTransactions: [
          {
            id: 'txn-1',
            date: '2024-01-15',
            amount: 1000,
            description: 'Software License',
            type: 'debit'
          }
        ],
        keyMetrics: {
          revenue: 100000,
          expenses: 80000,
          profit: 20000,
          employees: 50
        },
        alerts: []
      },
      requestContext: {
        timestamp: Date.now(),
        ipAddress: '192.168.1.1',
        userAgent: 'Test Agent 1.0',
        platform: 'test',
        requestId: 'test-request-123'
      }
    };

    return { ...defaultContext, ...overrides };
  }

  static generateMultiTenant(businessIds: string[]): BusinessContext[] {
    return businessIds.map(businessId =>
      this.generate({ businessId, userId: `user-${businessId}` })
    );
  }
}

/**
 * Task Generator
 */
export class TaskGenerator {
  static generate(overrides: Partial<AgentTask> = {}): AgentTask {
    const defaultTask: AgentTask = {
      id: `task-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      capability: 'test',
      type: 'query',
      priority: 'normal',
      input: {
        prompt: 'Test prompt',
        data: { test: true },
        parameters: {}
      },
      context: BusinessContextGenerator.generate(),
      constraints: {
        maxCost: 1.0,
        maxLatency: 5000,
        requiredAccuracy: 0.8,
        fallbackEnabled: true,
        streamingEnabled: false
      },
      metadata: {
        department: 'engineering',
        project: 'test-project',
        tags: ['test'],
        customFields: {}
      },
      createdAt: Date.now(),
      retryCount: 0
    };

    return { ...defaultTask, ...overrides };
  }

  static generateBatch(count: number, template: Partial<AgentTask> = {}): AgentTask[] {
    return Array.from({ length: count }, () => this.generate(template));
  }

  static generateHighLoad(count: number = 1000): AgentTask[] {
    const priorities: TaskPriority[] = ['low', 'normal', 'high', 'urgent'];
    const capabilities = ['analysis', 'generation', 'automation', 'query'];

    return Array.from({ length: count }, (_, i) =>
      this.generate({
        priority: priorities[i % priorities.length],
        capability: capabilities[i % capabilities.length],
        metadata: {
          department: ['engineering', 'sales', 'marketing', 'finance'][i % 4],
          tags: [`load-test-${i}`]
        }
      })
    );
  }
}

/**
 * Performance Monitor
 */
export class PerformanceMonitor {
  private startTime: number = 0;
  private endTime: number = 0;
  private metrics: Map<string, number> = new Map();

  start(): void {
    this.startTime = performance.now();
    this.metrics.clear();
  }

  end(): void {
    this.endTime = performance.now();
  }

  recordMetric(name: string, value: number): void {
    this.metrics.set(name, value);
  }

  getExecutionTime(): number {
    return this.endTime - this.startTime;
  }

  getMetric(name: string): number | undefined {
    return this.metrics.get(name);
  }

  getPerformanceReport(): PerformanceMetrics {
    return {
      executionTime: this.getExecutionTime(),
      memoryUsage: this.getMetric('memoryUsage') || 0,
      cpuUsage: this.getMetric('cpuUsage') || 0,
      taskThroughput: this.getMetric('taskThroughput') || 0,
      errorRate: this.getMetric('errorRate') || 0,
      responseTime: this.getMetric('responseTime') || 0
    };
  }

  async measureMemoryUsage(): Promise<number> {
    if (typeof global !== 'undefined' && global.gc) {
      global.gc();
    }

    const memoryUsage = process.memoryUsage();
    const totalMemory = memoryUsage.heapUsed + memoryUsage.external;
    this.recordMetric('memoryUsage', totalMemory);
    return totalMemory;
  }

  async measureTaskThroughput(taskCount: number, duration: number): Promise<number> {
    const throughput = taskCount / (duration / 1000); // tasks per second
    this.recordMetric('taskThroughput', throughput);
    return throughput;
  }
}

/**
 * Test Environment Factory
 */
export class TestEnvironmentFactory {
  static async create(): Promise<TestEnvironment> {
    const mockEnv = {
      DB: createMockDatabase(),
      DB_ANALYTICS: createMockDatabase(),
      KV_CACHE: createMockKV(),
      KV_SESSION: createMockKV(),
      KV_CONFIG: createMockKV(),
      WORKFLOW_STORAGE: createMockKV(),
      R2_DOCUMENTS: createMockR2(),
      ANTHROPIC_API_KEY: 'test-api-key',
      AGENT_SYSTEM_URL: 'http://localhost:3000'
    };

    const logger = new Logger({ component: 'test-harness' });
    const registry = new AgentRegistry(mockEnv);
    const orchestrator = new AgentOrchestrator(registry, {
      routing: {
        strategy: 'capability_based',
        fallbackEnabled: true,
        loadBalancingEnabled: true
      },
      memory: {
        shortTermEnabled: true,
        longTermEnabled: true,
        contextWindowSize: 1000,
        retentionPolicy: {
          conversationDays: 30,
          factsDays: 90,
          preferencesDays: 365
        }
      },
      costManagement: {
        enabled: true,
        dailyLimitUSD: 100,
        monthlyLimitUSD: 1000,
        alertThresholds: [0.5, 0.8, 0.95],
        costOptimizationEnabled: true
      },
      performance: {
        caching: {
          enabled: true,
          ttlSeconds: 300,
          maxCacheSize: 1000
        },
        concurrent: {
          maxPerUser: 10,
          maxGlobal: 100,
          queueSize: 1000
        },
        timeouts: {
          defaultTaskTimeout: 30000,
          healthCheckTimeout: 5000,
          streamingTimeout: 300000
        }
      },
      monitoring: {
        metricsEnabled: true,
        healthCheckInterval: 30000,
        alertingEnabled: true,
        logLevel: 'info'
      }
    }, mockEnv);

    const mockAgent = new MockAgent();
    const businessContext = BusinessContextGenerator.generate();

    await registry.registerAgent(mockAgent);

    return {
      orchestrator,
      registry,
      logger,
      mockAgent,
      businessContext,
      mockEnv
    };
  }

  static async cleanup(env: TestEnvironment): Promise<void> {
    await env.orchestrator.shutdown();
    env.mockAgent.reset();
  }
}

/**
 * Mock Factory Functions
 */
function createMockDatabase(): any {
  const data = new Map<string, any[]>();

  return {
    prepare: vi.fn().mockImplementation((query: string) => ({
      bind: vi.fn().mockReturnThis(),
      first: vi.fn().mockResolvedValue(null),
      all: vi.fn().mockResolvedValue({ results: [] }),
      run: vi.fn().mockResolvedValue({ success: true, changes: 1 })
    })),
    batch: vi.fn().mockResolvedValue([]),
    exec: vi.fn().mockResolvedValue(undefined)
  };
}

function createMockKV(): any {
  const storage = new Map<string, string>();

  return {
    get: vi.fn().mockImplementation((key: string) =>
      Promise.resolve(storage.get(key) || null)
    ),
    put: vi.fn().mockImplementation((key: string, value: string) => {
      storage.set(key, value);
      return Promise.resolve();
    }),
    delete: vi.fn().mockImplementation((key: string) => {
      storage.delete(key);
      return Promise.resolve();
    }),
    list: vi.fn().mockResolvedValue({ keys: [] })
  };
}

function createMockR2(): any {
  return {
    get: vi.fn().mockResolvedValue(null),
    put: vi.fn().mockResolvedValue(undefined),
    delete: vi.fn().mockResolvedValue(undefined),
    head: vi.fn().mockResolvedValue(null),
    list: vi.fn().mockResolvedValue({ objects: [] })
  };
}

/**
 * Test Assertions and Utilities
 */
export class TestAssertions {
  static assertAgentInterface(agent: IAgent): void {
    expect(agent.id).toBeDefined();
    expect(agent.name).toBeDefined();
    expect(agent.type).toBeDefined();
    expect(agent.version).toBeDefined();
    expect(agent.capabilities).toBeInstanceOf(Array);
    expect(agent.costPerCall).toBeGreaterThanOrEqual(0);
    expect(agent.maxConcurrency).toBeGreaterThan(0);
    expect(agent.averageLatency).toBeGreaterThan(0);
    expect(typeof agent.execute).toBe('function');
    expect(typeof agent.validateInput).toBe('function');
    expect(typeof agent.estimateCost).toBe('function');
    expect(typeof agent.healthCheck).toBe('function');
  }

  static assertAgentResult(result: AgentResult): void {
    expect(result.taskId).toBeDefined();
    expect(result.agentId).toBeDefined();
    expect(result.status).toBeDefined();
    expect(result.metrics).toBeDefined();
    expect(result.startedAt).toBeGreaterThan(0);
    expect(result.completedAt).toBeGreaterThan(0);
    expect(result.completedAt).toBeGreaterThanOrEqual(result.startedAt);
  }

  static assertPerformanceMetrics(metrics: PerformanceMetrics, thresholds: Partial<PerformanceMetrics>): void {
    if (thresholds.executionTime) {
      expect(metrics.executionTime).toBeLessThanOrEqual(thresholds.executionTime);
    }
    if (thresholds.memoryUsage) {
      expect(metrics.memoryUsage).toBeLessThanOrEqual(thresholds.memoryUsage);
    }
    if (thresholds.errorRate) {
      expect(metrics.errorRate).toBeLessThanOrEqual(thresholds.errorRate);
    }
    if (thresholds.responseTime) {
      expect(metrics.responseTime).toBeLessThanOrEqual(thresholds.responseTime);
    }
  }

  static assertBusinessIsolation(results: AgentResult[], expectedBusinessIds: string[]): void {
    results.forEach(result => {
      expect(expectedBusinessIds).toContain(result.metadata?.businessId);
    });
  }
}

/**
 * Global Test Setup
 */
export function setupAgentTests(): void {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });
}

// Re-export all test utilities (already exported as classes above)