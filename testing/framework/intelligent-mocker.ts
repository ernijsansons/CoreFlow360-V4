/**
 * Intelligent Mocking System
 * Creates realistic mocks based on production behavior analysis
 */

import { z } from 'zod';
import { Logger } from '../../src/shared/logger';
import { CorrelationId } from '../../src/shared/correlation-id';

export interface Dependency {
  name: string;
  type: 'api' | 'database' | 'service' | 'external';
  schema?: z.ZodSchema;
  endpoints?: string[];
  methods?: string[];
}

export interface MockBehavior {
  responses: ResponsePattern[];
  errors: ErrorPattern[];
  latencies: LatencyPattern[];
  rateLimit?: RateLimitConfig;
}

export interface ResponsePattern {
  pattern: string;
  probability: number;
  data: any;
  conditions?: Record<string, any>;
}

export interface ErrorPattern {
  code: number | string;
  message: string;
  probability: number;
  retryable: boolean;
}

export interface LatencyPattern {
  min: number;
  max: number;
  p50: number;
  p95: number;
  p99: number;
}

export interface RateLimitConfig {
  requestsPerSecond: number;
  burstSize: number;
}

export class MockSet {
  constructor(private mocks: Map<string, MockImplementation>) {}

  get(name: string): MockImplementation | undefined {
    return this.mocks.get(name);
  }

  getAll(): MockImplementation[] {
    return Array.from(this.mocks.values());
  }

  apply(): void {
    for (const mock of this.mocks.values()) {
      mock.activate();
    }
  }

  reset(): void {
    for (const mock of this.mocks.values()) {
      mock.reset();
    }
  }
}

export class MockImplementation {
  private callCount = 0;
  private callHistory: any[] = [];
  private active = false;

  constructor(
    public name: string,
    private implementation: Function,
    private scenarios: MockScenario[],
    private errorCases: ErrorCase[]
  ) {}

  activate(): void {
    this.active = true;
  }

  reset(): void {
    this.callCount = 0;
    this.callHistory = [];
  }

  async execute(...args: any[]): Promise<any> {
    if (!this.active) {
      throw new Error(`Mock ${this.name} is not active`);
    }

    this.callCount++;
    this.callHistory.push({ args, timestamp: Date.now() });

    // Check for error scenarios
    const error = this.checkErrorScenarios(args);
    if (error) {
      throw error;
    }

    // Find matching scenario
    const scenario = this.findMatchingScenario(args);
    if (scenario) {
      return this.executeScenario(scenario, args);
    }

    // Default implementation
    return this.implementation(...args);
  }

  private checkErrorScenarios(args: any[]): Error | null {
    for (const errorCase of this.errorCases) {
      if (Math.random() < errorCase.probability) {
        return new Error(errorCase.message);
      }
    }
    return null;
  }

  private findMatchingScenario(args: any[]): MockScenario | null {
    for (const scenario of this.scenarios) {
      if (scenario.matches(args)) {
        return scenario;
      }
    }
    return null;
  }

  private async executeScenario(scenario: MockScenario, args: any[]): Promise<any> {
    // Simulate latency
    if (scenario.latency) {
      await this.simulateLatency(scenario.latency);
    }

    // Return response
    return scenario.response(args);
  }

  private simulateLatency(latency: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, latency));
  }

  getCallCount(): number {
    return this.callCount;
  }

  getCallHistory(): any[] {
    return this.callHistory;
  }

  wasCalledWith(...args: any[]): boolean {
    return this.callHistory.some(call =>
      JSON.stringify(call.args) === JSON.stringify(args)
    );
  }
}

export class IntelligentMocker {
  private logger = new Logger();
  private correlationId = CorrelationId.generate();

  /**
   * Create intelligent mocks based on production behavior
   */
  async createMocks(dependencies: Dependency[], options?: {
    source?: 'production-logs' | 'synthetic' | 'hybrid';
    duration?: string;
    includeErrors?: boolean;
  }): Promise<MockSet> {
    const mocks = new Map<string, MockImplementation>();

    for (const dep of dependencies) {
      const behavior = await this.analyzeBehavior(dep, options);
      const implementation = this.generateMockImplementation(dep, behavior);
      const scenarios = this.generateScenarios(dep, behavior);
      const errorCases = this.generateErrorCases(dep, behavior);

      mocks.set(dep.name, new MockImplementation(
        dep.name,
        implementation,
        scenarios,
        errorCases
      ));
    }

    return new MockSet(mocks);
  }

  /**
   * Analyze dependency behavior from production data
   */
  private async analyzeBehavior(
    dependency: Dependency,
    options?: {
      source?: string;
      duration?: string;
      includeErrors?: boolean;
    }
  ): Promise<MockBehavior> {
    // In a real implementation, this would fetch data from monitoring systems
    // For now, we'll generate synthetic behavior patterns

    return {
      responses: this.generateResponsePatterns(dependency),
      errors: options?.includeErrors ? this.generateErrorPatterns(dependency) : [],
      latencies: this.generateLatencyPatterns(dependency),
      rateLimit: this.generateRateLimitConfig(dependency)
    };
  }

  /**
   * Generate mock implementation
   */
  private generateMockImplementation(
    dependency: Dependency,
    behavior: MockBehavior
  ): Function {
    switch (dependency.type) {
      case 'api':
        return this.generateAPIMock(dependency, behavior);
      case 'database':
        return this.generateDatabaseMock(dependency, behavior);
      case 'service':
        return this.generateServiceMock(dependency, behavior);
      case 'external':
        return this.generateExternalMock(dependency, behavior);
      default:
        return this.generateDefaultMock(dependency, behavior);
    }
  }

  /**
   * Generate API mock
   */
  private generateAPIMock(dependency: Dependency, behavior: MockBehavior): Function {
    return async (endpoint: string, options?: any) => {
      // Find matching response pattern
      const pattern = behavior.responses.find(p =>
        new RegExp(p.pattern).test(endpoint)
      );

      if (pattern) {
        // Simulate latency
        const latency = this.sampleLatency(behavior.latencies);
        await new Promise(resolve => setTimeout(resolve, latency));

        // Check for errors
        if (Math.random() < 0.05) { // 5% error rate
          const error = behavior.errors[Math.floor(Math.random() * behavior.errors.length)];
          throw new Error(error.message);
        }

        // Return mocked response
        return this.generateResponse(pattern.data, options);
      }

      throw new Error(`No mock found for endpoint: ${endpoint}`);
    };
  }

  /**
   * Generate database mock
   */
  private generateDatabaseMock(dependency: Dependency, behavior: MockBehavior): Function {
    const mockData = new Map<string, any[]>();

    return {
      prepare: (sql: string) => ({
        bind: (...params: any[]) => ({
          first: async () => {
            const latency = this.sampleLatency(behavior.latencies);
            await new Promise(resolve => setTimeout(resolve, latency));

            // Parse SQL to determine operation
            if (sql.toLowerCase().includes('select')) {
              const tableName = this.extractTableName(sql);
              const data = mockData.get(tableName) || [];
              return data[0] || null;
            }

            return { success: true };
          },

          all: async () => {
            const latency = this.sampleLatency(behavior.latencies);
            await new Promise(resolve => setTimeout(resolve, latency));

            if (sql.toLowerCase().includes('select')) {
              const tableName = this.extractTableName(sql);
              const data = mockData.get(tableName) || [];
              return { results: data, success: true };
            }

            return { results: [], success: true };
          },

          run: async () => {
            const latency = this.sampleLatency(behavior.latencies);
            await new Promise(resolve => setTimeout(resolve, latency));

            if (sql.toLowerCase().includes('insert')) {
              const tableName = this.extractTableName(sql);
              const existing = mockData.get(tableName) || [];
              existing.push({ id: Math.random().toString(), ...params });
              mockData.set(tableName, existing);
            }

            return { success: true, meta: { changes: 1 } };
          }
        })
      }),

      batch: async (statements: any[]) => {
        const latency = this.sampleLatency(behavior.latencies);
        await new Promise(resolve => setTimeout(resolve, latency));

        return statements.map(() => ({ success: true }));
      }
    };
  }

  /**
   * Generate service mock
   */
  private generateServiceMock(dependency: Dependency, behavior: MockBehavior): Function {
    const mockMethods: Record<string, Function> = {};

    for (const method of dependency.methods || []) {
      mockMethods[method] = async (...args: any[]) => {
        const latency = this.sampleLatency(behavior.latencies);
        await new Promise(resolve => setTimeout(resolve, latency));

        // Find response pattern for method
        const pattern = behavior.responses.find(p => p.pattern === method);
        if (pattern) {
          return this.generateResponse(pattern.data, args);
        }

        return { success: true, data: null };
      };
    }

    return mockMethods as any;
  }

  /**
   * Generate external service mock
   */
  private generateExternalMock(dependency: Dependency, behavior: MockBehavior): Function {
    return async (request: any) => {
      // Rate limiting
      if (behavior.rateLimit) {
        // Simple rate limit check
        if (Math.random() > behavior.rateLimit.requestsPerSecond / 100) {
          throw new Error('Rate limit exceeded');
        }
      }

      const latency = this.sampleLatency(behavior.latencies);
      await new Promise(resolve => setTimeout(resolve, latency));

      // Random error injection
      for (const error of behavior.errors) {
        if (Math.random() < error.probability) {
          throw new Error(error.message);
        }
      }

      // Return successful response
      return {
        status: 200,
        data: this.generateResponse({}, request)
      };
    };
  }

  /**
   * Generate default mock
   */
  private generateDefaultMock(dependency: Dependency, behavior: MockBehavior): Function {
    return async (...args: any[]) => {
      const latency = this.sampleLatency(behavior.latencies);
      await new Promise(resolve => setTimeout(resolve, latency));

      return { success: true, data: args };
    };
  }

  /**
   * Generate mock scenarios
   */
  private generateScenarios(dependency: Dependency, behavior: MockBehavior): MockScenario[] {
    const scenarios: MockScenario[] = [];

    // Happy path scenario
    scenarios.push(new MockScenario(
      'happy-path',
      (args: any[]) => true, // Matches all
      (args: any[]) => ({ success: true, data: 'mock-data' }),
      behavior.latencies.p50
    ));

    // Slow response scenario
    scenarios.push(new MockScenario(
      'slow-response',
      (args: any[]) => Math.random() < 0.1, // 10% chance
      (args: any[]) => ({ success: true, data: 'slow-mock-data' }),
      behavior.latencies.p99
    ));

    // Empty response scenario
    scenarios.push(new MockScenario(
      'empty-response',
      (args: any[]) => args[0] === 'empty',
      (args: any[]) => ({ success: true, data: [] }),
      behavior.latencies.p50
    ));

    return scenarios;
  }

  /**
   * Generate error cases
   */
  private generateErrorCases(dependency: Dependency, behavior: MockBehavior): ErrorCase[] {
    return behavior.errors.map(error => new ErrorCase(
      error.code.toString(),
      error.message,
      error.probability,
      error.retryable
    ));
  }

  /**
   * Generate response patterns
   */
  private generateResponsePatterns(dependency: Dependency): ResponsePattern[] {
    const patterns: ResponsePattern[] = [];

    switch (dependency.type) {
      case 'api':
        patterns.push({
          pattern: '.*',
          probability: 1.0,
          data: { id: 'mock-id', status: 'success' }
        });
        break;

      case 'database':
        patterns.push({
          pattern: 'SELECT',
          probability: 1.0,
          data: [{ id: 1, name: 'mock-record' }]
        });
        break;

      default:
        patterns.push({
          pattern: '.*',
          probability: 1.0,
          data: { mock: true }
        });
    }

    return patterns;
  }

  /**
   * Generate error patterns
   */
  private generateErrorPatterns(dependency: Dependency): ErrorPattern[] {
    return [
      {
        code: 500,
        message: 'Internal Server Error',
        probability: 0.01,
        retryable: true
      },
      {
        code: 503,
        message: 'Service Unavailable',
        probability: 0.005,
        retryable: true
      },
      {
        code: 429,
        message: 'Too Many Requests',
        probability: 0.02,
        retryable: true
      },
      {
        code: 400,
        message: 'Bad Request',
        probability: 0.03,
        retryable: false
      }
    ];
  }

  /**
   * Generate latency patterns
   */
  private generateLatencyPatterns(dependency: Dependency): LatencyPattern {
    switch (dependency.type) {
      case 'database':
        return { min: 1, max: 100, p50: 5, p95: 20, p99: 50 };
      case 'api':
        return { min: 10, max: 1000, p50: 50, p95: 200, p99: 500 };
      case 'external':
        return { min: 50, max: 5000, p50: 200, p95: 1000, p99: 3000 };
      default:
        return { min: 1, max: 100, p50: 10, p95: 50, p99: 90 };
    }
  }

  /**
   * Generate rate limit configuration
   */
  private generateRateLimitConfig(dependency: Dependency): RateLimitConfig | undefined {
    if (dependency.type === 'external') {
      return {
        requestsPerSecond: 100,
        burstSize: 150
      };
    }
    return undefined;
  }

  /**
   * Sample latency from distribution
   */
  private sampleLatency(pattern: LatencyPattern): number {
    const random = Math.random();

    if (random < 0.5) {
      return pattern.p50;
    } else if (random < 0.95) {
      return pattern.p95;
    } else if (random < 0.99) {
      return pattern.p99;
    } else {
      return pattern.max;
    }
  }

  /**
   * Extract table name from SQL
   */
  private extractTableName(sql: string): string {
    const match = sql.match(/FROM\s+(\w+)/i);
    return match ? match[1] : 'unknown';
  }

  /**
   * Generate response data
   */
  private generateResponse(template: any, context?: any): any {
    if (typeof template === 'function') {
      return template(context);
    }

    if (typeof template === 'object' && template !== null) {
      const result: any = Array.isArray(template) ? [] : {};

      for (const key in template) {
        result[key] = this.generateResponse(template[key], context);
      }

      return result;
    }

    // Replace placeholders
    if (typeof template === 'string' && template.includes('{{')) {
      return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
        return context?.[key] || key;
      });
    }

    return template;
  }
}

class MockScenario {
  constructor(
    public name: string,
    public matches: (args: any[]) => boolean,
    public response: (args: any[]) => any,
    public latency?: number
  ) {}
}

class ErrorCase {
  constructor(
    public code: string,
    public message: string,
    public probability: number,
    public retryable: boolean
  ) {}
}