/**
 * Test Utilities for E2E Agent Tests
 * Provides mock environments and test helpers
 */

export interface MockTestEnvironment {
  id: string;
  name: string;
  config: Record<string, any>;
  cleanup: () => Promise<void>;
}

export class SimpleTestEnvironmentFactory {
  static async createEnvironment(name: string): Promise<MockTestEnvironment> {
    return {
      id: `env-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name,
      config: {
        database: 'memory',
        cache: 'local',
        auth: 'mock',
        logging: 'test'
      },
      cleanup: async () => {
        // Cleanup resources
      }
    };
  }
}

export class SimpleTaskGenerator {
  static generateTask(type: string, priority: 'low' | 'medium' | 'high' = 'medium') {
    return {
      id: `task-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      priority,
      payload: {},
      createdAt: new Date(),
      status: 'pending'
    };
  }
}

export class SimplePerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();

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