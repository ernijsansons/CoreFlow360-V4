/**
 * Test Utilities for E2E Agent Tests
 * Provides mock environments and test helpers
 */

export class MockOrchestrator {
  public shouldFail: boolean = false;

  async executeTask(task: any, context: any): Promise<any> {
    // Check if we should simulate a failure
    if (this.shouldFail) {
      throw new Error('Simulated task failure');
    }

    // Mock task execution - always succeeds for test purposes
    return {
      status: 'completed',
      result: {
        success: true,
        data: {
          ...task.input?.data,
          processedAt: new Date(),
          leadScore: 85,
          qualified: true,
          assignedTo: 'sales-team-01'
        }
      },
      taskId: task.id || `task-${Date.now()}`,
      duration: Math.floor(Math.random() * 1000),
      metadata: task.metadata || {}
    };
  }

  async cancelTask(taskId: string): Promise<void> {
    // Mock task cancellation
    return Promise.resolve();
  }

  async getTaskStatus(taskId: string): Promise<string> {
    // Mock status check
    return 'completed';
  }
}

export interface MockTestEnvironment {
  id: string;
  name: string;
  config: Record<string, any>;
  businessContext: any;
  orchestrator: MockOrchestrator;
  cleanup: () => Promise<void>;
}

export class SimpleTestEnvironmentFactory {
  static async create(name: string = 'default'): Promise<MockTestEnvironment> {
    return {
      id: `env-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name,
      config: {
        database: 'memory',
        cache: 'local',
        auth: 'mock',
        logging: 'test'
      },
      businessContext: {
        businessId: 'test-business',
        name: 'Test Business',
        tier: 'enterprise',
        features: ['ai', 'automation', 'advanced_analytics'],
        limits: {
          users: 100,
          storage: '1TB',
          apiCalls: 100000
        }
      },
      orchestrator: new MockOrchestrator(),
      cleanup: async () => {
        // Cleanup resources
      }
    };
  }

  static async cleanup(env: MockTestEnvironment): Promise<void> {
    if (env && env.cleanup) {
      await env.cleanup();
    }
  }

  static async createEnvironment(name: string): Promise<MockTestEnvironment> {
    return this.create(name);
  }
}

export class SimpleTaskGenerator {
  static generate(options: any) {
    const { capability, context, input, metadata } = options;
    return {
      id: `task-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      capability: capability || 'default',
      context: context || {},
      input: input || {},
      metadata: metadata || {},
      createdAt: new Date(),
      status: 'pending',
      priority: options.priority || 'medium'
    };
  }

  static generateTask(type: string, priority: 'low' | 'medium' | 'high' = 'medium') {
    return this.generate({
      capability: type,
      priority: priority
    });
  }
}

export class SimplePerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();
  private startTime: number = 0;

  start(): void {
    this.startTime = Date.now();
  }

  end(): number {
    return Date.now() - this.startTime;
  }

  getExecutionTime(): number {
    return Date.now() - this.startTime;
  }

  startTimer(name: string): () => number {
    const start = Date.now();
    return () => {
      const duration = Date.now() - start;
      if (!this.metrics.has(name)) {
        this.metrics.set(name, []);
      }
      this.metrics.get(name)!.push(duration);
      return duration;
    };
  }

  getAverageTime(name: string): number {
    const times = this.metrics.get(name) || [];
    return times.length > 0 ? times.reduce((a, b) => a + b, 0) / times.length : 0;
  }

  reset(): void {
    this.metrics.clear();
  }
}