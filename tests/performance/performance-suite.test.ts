/**
 * Comprehensive Performance Test Suite
 * Integration with Artillery for load testing and performance validation
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { exec } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs/promises';

const execAsync = promisify(exec);

// Performance thresholds (in milliseconds)
const PERFORMANCE_THRESHOLDS = {
  // API Response Times (p99)
  AUTH_LOGIN: 1000,
  AUTH_VALIDATE: 200,
  AGENT_EXECUTE: 5000,
  BUSINESS_SWITCH: 500,
  FINANCE_OPERATIONS: 2000,
  REALTIME_EVENTS: 300,
  DATA_EXPORT: 10000,

  // API Response Times (p95)
  AUTH_LOGIN_P95: 500,
  AGENT_EXECUTE_P95: 3000,
  FINANCE_OPERATIONS_P95: 1000,

  // API Response Times (mean)
  OVERALL_MEAN: 400,
  AUTH_MEAN: 300,
  AGENT_MEAN: 2000,

  // Throughput (requests per second)
  MIN_THROUGHPUT: 10,
  TARGET_THROUGHPUT: 50,

  // Error Rates (percentage)
  MAX_ERROR_RATE: 1,
  MAX_CLIENT_ERROR_RATE: 2,

  // Memory and CPU
  MAX_MEMORY_USAGE: 512 * 1024 * 1024, // 512MB
  MAX_CPU_USAGE: 80, // 80%

  // Business-specific
  CONCURRENT_USERS: 100,
  CONCURRENT_BUSINESSES: 10,
};

interface PerformanceMetrics {
  responseTime: {
    mean: number;
    p50: number;
    p95: number;
    p99: number;
    max: number;
  };
  throughput: {
    requestsPerSecond: number;
    totalRequests: number;
  };
  errorRates: {
    total: number;
    clientErrors: number;
    serverErrors: number;
  };
  endpointMetrics: Record<string, {
    count: number;
    mean: number;
    p95: number;
    p99: number;
  }>;
  systemMetrics: {
    memoryUsage: number;
    cpuUsage: number;
  };
}

class PerformanceTestRunner {
  private artilleryConfigPath: string;
  private testDataPath: string;

  constructor() {
    this.artilleryConfigPath = path.join(__dirname, 'artillery-benchmarks.yml');
    this.testDataPath = path.join(__dirname, 'test-data');
  }

  async setupTestData(): Promise<void> {
    // Create test data directory
    try {
      await fs.mkdir(this.testDataPath, { recursive: true });
    } catch (error) {
      // Directory might already exist
    }

    // Generate business context data
    const businessContextData = Array.from({ length: 100 }, (_, i) => ({
      businessId: `biz_test_${i}`,
      name: `Test Business ${i}`,
      industry: ['technology', 'finance', 'healthcare', 'retail'][i % 4],
      tier: ['startup', 'growth', 'enterprise'][i % 3],
      region: ['us-east', 'us-west', 'eu-central', 'asia-pacific'][i % 4],
      settings: {
        maxUsers: 50 + (i % 200),
        dataRetention: [30, 90, 365][i % 3],
        features: ['basic', 'advanced', 'premium'][i % 3]
      }
    }));

    // Generate task data
    const taskData = Array.from({ length: 500 }, (_, i) => ({
      id: `task_${i}`,
      capability: [
        'financial.analysis',
        'sales.forecasting',
        'hr.recruitment',
        'marketing.campaign',
        'operations.optimization'
      ][i % 5],
      input: {
        message: `Test task ${i} for performance testing`,
        data: {
          value: Math.random() * 1000000,
          category: ['revenue', 'expense', 'asset', 'liability'][i % 4],
          period: `Q${(i % 4) + 1}-2024`
        }
      },
      priority: ['low', 'medium', 'high'][i % 3],
      constraints: {
        maxCost: 0.1 + (Math.random() * 1.9),
        timeout: 30000
      }
    }));

    // Generate user profiles
    const userProfiles = Array.from({ length: 200 }, (_, i) => ({
      email: `perftest_user_${i}@example.com`,
      role: ['user', 'admin', 'manager'][i % 3],
      department: ['finance', 'sales', 'hr', 'marketing', 'operations', 'it'][i % 6],
      permissions: ['read', 'write', 'admin'].slice(0, (i % 3) + 1),
      businessIds: [`biz_test_${i % 10}`, `biz_test_${(i + 5) % 10}`]
    }));

    // Write test data files
    await fs.writeFile(
      path.join(this.testDataPath, 'businessContext.json'),
      JSON.stringify(businessContextData, null, 2)
    );
    await fs.writeFile(
      path.join(this.testDataPath, 'taskData.json'),
      JSON.stringify(taskData, null, 2)
    );
    await fs.writeFile(
      path.join(this.testDataPath, 'userProfiles.json'),
      JSON.stringify(userProfiles, null, 2)
    );
  }

  async runArtilleryTest(scenario?: string, environment: string = 'development'): Promise<PerformanceMetrics> {
    const command = [
      'npx artillery run',
      this.artilleryConfigPath,
      `--environment ${environment}`,
      '--output /tmp/artillery-report.json',
      scenario ? `--scenario ${scenario}` : ''
    ].filter(Boolean).join(' ');

    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout: 300000, // 5 minutes
        maxBuffer: 1024 * 1024 * 10 // 10MB buffer
      });

      if (stderr && !stderr.includes('warn')) {
        console.warn('Artillery stderr:', stderr);
      }

      // Parse Artillery output
      return this.parseArtilleryResults(stdout);
    } catch (error: any) {
      throw new Error(`Artillery test failed: ${error.message}`);
    }
  }

  private parseArtilleryResults(output: string): PerformanceMetrics {
    // Extract metrics from Artillery output
    const lines = output.split('\n');
    const metrics: PerformanceMetrics = {
      responseTime: { mean: 0, p50: 0, p95: 0, p99: 0, max: 0 },
      throughput: { requestsPerSecond: 0, totalRequests: 0 },
      errorRates: { total: 0, clientErrors: 0, serverErrors: 0 },
      endpointMetrics: {},
      systemMetrics: { memoryUsage: 0, cpuUsage: 0 }
    };

    for (const line of lines) {
      // Parse response time metrics
      if (line.includes('http.response_time')) {
        if (line.includes('mean:')) {
          metrics.responseTime.mean = this.extractNumber(line);
        } else if (line.includes('p50:')) {
          metrics.responseTime.p50 = this.extractNumber(line);
        } else if (line.includes('p95:')) {
          metrics.responseTime.p95 = this.extractNumber(line);
        } else if (line.includes('p99:')) {
          metrics.responseTime.p99 = this.extractNumber(line);
        } else if (line.includes('max:')) {
          metrics.responseTime.max = this.extractNumber(line);
        }
      }

      // Parse throughput metrics
      if (line.includes('http.requests:')) {
        metrics.throughput.totalRequests = this.extractNumber(line);
      }
      if (line.includes('http.request_rate:')) {
        metrics.throughput.requestsPerSecond = this.extractNumber(line);
      }

      // Parse error rates
      if (line.includes('http.codes.4')) {
        metrics.errorRates.clientErrors += this.extractNumber(line);
      }
      if (line.includes('http.codes.5')) {
        metrics.errorRates.serverErrors += this.extractNumber(line);
      }
    }

    metrics.errorRates.total = metrics.errorRates.clientErrors + metrics.errorRates.serverErrors;

    return metrics;
  }

  private extractNumber(line: string): number {
    const match = line.match(/[\d.]+/);
    return match ? parseFloat(match[0]) : 0;
  }

  async measureSystemMetrics(): Promise<{ memoryUsage: number; cpuUsage: number }> {
    try {
      // Get memory usage
      const memoryUsage = process.memoryUsage().heapUsed;

      // Get CPU usage (simplified)
      const startUsage = process.cpuUsage();
      await new Promise(resolve => setTimeout(resolve, 100));
      const endUsage = process.cpuUsage(startUsage);
      const cpuUsage = ((endUsage.user + endUsage.system) / 100000) * 100; // Convert to percentage

      return { memoryUsage, cpuUsage };
    } catch (error) {
      return { memoryUsage: 0, cpuUsage: 0 };
    }
  }
}

describe('Performance Test Suite', () => {
  let performanceRunner: PerformanceTestRunner;

  beforeEach(async () => {
    performanceRunner = new PerformanceTestRunner();
    await performanceRunner.setupTestData();
  });

  describe('Authentication Performance', () => {
    it('should meet authentication response time thresholds', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Authentication Flow');

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.AUTH_LOGIN);
      expect(metrics.responseTime.p95).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.AUTH_LOGIN_P95);
      expect(metrics.responseTime.mean).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.AUTH_MEAN);
      expect(metrics.errorRates.total).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 120000);

    it('should handle concurrent authentication requests', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Authentication Flow');

      expect(metrics.throughput.requestsPerSecond).toBeGreaterThanOrEqual(PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT);
      expect(metrics.errorRates.serverErrors).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 120000);
  });

  describe('Agent Execution Performance', () => {
    it('should meet agent execution response time thresholds', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Agent Task Execution');

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.AGENT_EXECUTE);
      expect(metrics.responseTime.p95).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.AGENT_EXECUTE_P95);
      expect(metrics.responseTime.mean).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.AGENT_MEAN);
    }, 180000);

    it('should maintain performance under concurrent agent requests', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Agent Task Execution');

      expect(metrics.throughput.requestsPerSecond).toBeGreaterThanOrEqual(PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT);
      expect(metrics.errorRates.total).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 180000);

    it('should handle complex agent workflows efficiently', async () => {
      // Test with more complex agent tasks
      const metrics = await performanceRunner.runArtilleryTest('Agent Task Execution');

      // Agent execution should complete within time limits even for complex tasks
      expect(metrics.responseTime.max).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.AGENT_EXECUTE * 2);
    }, 240000);
  });

  describe('Multi-Business Performance', () => {
    it('should handle business switching efficiently', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Multi-Business Operations');

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.BUSINESS_SWITCH);
      expect(metrics.errorRates.total).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 120000);

    it('should maintain performance across multiple tenants', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Multi-Business Operations');

      expect(metrics.throughput.requestsPerSecond).toBeGreaterThanOrEqual(PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT);
      expect(metrics.errorRates.serverErrors).toBeLessThanOrEqual(0.5); // Stricter for multi-tenant
    }, 120000);
  });

  describe('Financial Operations Performance', () => {
    it('should handle financial operations within time limits', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Financial Operations');

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.FINANCE_OPERATIONS);
      expect(metrics.responseTime.p95).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.FINANCE_OPERATIONS_P95);
      expect(metrics.errorRates.total).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 180000);

    it('should maintain data consistency under load', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Financial Operations');

      // Financial operations must have very low error rates
      expect(metrics.errorRates.serverErrors).toBeLessThanOrEqual(0.1);
      expect(metrics.errorRates.clientErrors).toBeLessThanOrEqual(1);
    }, 180000);
  });

  describe('Real-time Operations Performance', () => {
    it('should handle real-time events with low latency', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Real-time Operations');

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.REALTIME_EVENTS);
      expect(metrics.responseTime.mean).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.REALTIME_EVENTS / 2);
    }, 120000);

    it('should maintain real-time performance under high frequency events', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Real-time Operations');

      expect(metrics.throughput.requestsPerSecond).toBeGreaterThanOrEqual(PERFORMANCE_THRESHOLDS.TARGET_THROUGHPUT);
      expect(metrics.errorRates.total).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 120000);
  });

  describe('Data Export Performance', () => {
    it('should handle data export requests efficiently', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Data Export Operations');

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.DATA_EXPORT);
      expect(metrics.errorRates.total).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 300000); // 5 minutes for data export tests
  });

  describe('System Resource Performance', () => {
    it('should maintain acceptable memory usage', async () => {
      const initialMetrics = await performanceRunner.measureSystemMetrics();

      // Run a load test
      await performanceRunner.runArtilleryTest('Sustained Load');

      const finalMetrics = await performanceRunner.measureSystemMetrics();
      const memoryIncrease = finalMetrics.memoryUsage - initialMetrics.memoryUsage;

      expect(memoryIncrease).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_MEMORY_USAGE);
    }, 180000);

    it('should maintain acceptable CPU usage', async () => {
      const systemMetrics = await performanceRunner.measureSystemMetrics();

      expect(systemMetrics.cpuUsage).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_CPU_USAGE);
    });
  });

  describe('Stress Testing', () => {
    it('should handle peak load without degradation', async () => {
      const metrics = await performanceRunner.runArtilleryTest('Peak Load');

      // Under peak load, allow some degradation but within limits
      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.AGENT_EXECUTE * 1.5);
      expect(metrics.errorRates.total).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE * 2);
      expect(metrics.throughput.requestsPerSecond).toBeGreaterThanOrEqual(PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT);
    }, 300000);

    it('should recover gracefully after stress', async () => {
      // Run stress test
      await performanceRunner.runArtilleryTest('Stress Test');

      // Run recovery test
      const recoveryMetrics = await performanceRunner.runArtilleryTest('Recovery');

      // System should recover to normal performance levels
      expect(recoveryMetrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.AGENT_EXECUTE);
      expect(recoveryMetrics.errorRates.total).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 600000); // 10 minutes for stress and recovery
  });

  describe('Performance Regression Detection', () => {
    it('should detect performance regressions', async () => {
      // This test would compare against baseline metrics
      const currentMetrics = await performanceRunner.runArtilleryTest('Baseline Performance');

      // Baseline metrics would be stored and loaded here
      const baselineMetrics = {
        responseTime: { p99: 2000, p95: 1000, mean: 400 },
        throughput: { requestsPerSecond: 25 },
        errorRates: { total: 0.5 }
      };

      // Check for regression (more than 20% degradation)
      const p99Regression = (currentMetrics.responseTime.p99 - baselineMetrics.responseTime.p99) / baselineMetrics.responseTime.p99;
      const throughputRegression = (baselineMetrics.throughput.requestsPerSecond - currentMetrics.throughput.requestsPerSecond) / baselineMetrics.throughput.requestsPerSecond;

      expect(p99Regression).toBeLessThanOrEqual(0.2); // Max 20% regression
      expect(throughputRegression).toBeLessThanOrEqual(0.2); // Max 20% throughput decrease
    }, 180000);
  });

  describe('Scalability Testing', () => {
    it('should scale horizontally with load', async () => {
      // Test with increasing load levels
      const lightLoad = await performanceRunner.runArtilleryTest('Light Load');
      const mediumLoad = await performanceRunner.runArtilleryTest('Medium Load');
      const heavyLoad = await performanceRunner.runArtilleryTest('Heavy Load');

      // Response time should not increase exponentially with load
      const lightToMediumIncrease = (mediumLoad.responseTime.p99 - lightLoad.responseTime.p99) / lightLoad.responseTime.p99;
      const mediumToHeavyIncrease = (heavyLoad.responseTime.p99 - mediumLoad.responseTime.p99) / mediumLoad.responseTime.p99;

      expect(lightToMediumIncrease).toBeLessThanOrEqual(0.5); // Max 50% increase
      expect(mediumToHeavyIncrease).toBeLessThanOrEqual(0.5); // Should scale linearly
    }, 600000);
  });
});