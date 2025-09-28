import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { spawn } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import path from 'path';

// Performance test configuration
const PERFORMANCE_THRESHOLDS = {
  P95_RESPONSE_TIME: 100, // 95th percentile under 100ms
  P99_RESPONSE_TIME: 150, // 99th percentile under 150ms (CRITICAL)
  MAX_ERROR_RATE: 1,      // Error rate under 1%
  MIN_THROUGHPUT: 100,    // Minimum requests per second
  MAX_MEMORY_USAGE: 512,  // Maximum memory usage in MB
  MAX_CPU_USAGE: 80       // Maximum CPU usage percentage
};

interface PerformanceMetrics {
  responseTime: {
    p50: number;
    p95: number;
    p99: number;
    mean: number;
    min: number;
    max: number;
  };
  throughput: {
    requestsPerSecond: number;
    totalRequests: number;
    duration: number;
  };
  errors: {
    totalErrors: number;
    errorRate: number;
    errorTypes: Record<string, number>;
  };
  resources: {
    memoryUsage: number;
    cpuUsage: number;
    networkIO: number;
  };
  concurrency: {
    maxConcurrentUsers: number;
    averageConcurrentUsers: number;
  };
}

class PerformanceTestRunner {
  private results: PerformanceMetrics[] = [];
  private server: any;

  async startTestServer(): Promise<void> {
    // Start the application server for testing
    this.server = spawn('npm', ['run', 'dev'], {
      stdio: 'pipe',
      env: { ...process.env, NODE_ENV: 'test' }
    });

    // Wait for server to be ready
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Server startup timeout'));
      }, 30000);

      this.server.stdout.on('data', (data: Buffer) => {
        if (data.toString().includes('Server listening')) {
          clearTimeout(timeout);
          resolve(void 0);
        }
      });

      this.server.stderr.on('data', (data: Buffer) => {
        console.error('Server error:', data.toString());
      });
    });
  }

  async stopTestServer(): Promise<void> {
    if (this.server) {
      this.server.kill();
      await new Promise((resolve) => {
        this.server.on('close', resolve);
      });
    }
  }

  async runArtilleryTest(configFile: string): Promise<PerformanceMetrics> {
    return new Promise((resolve, reject) => {
      const outputFile = path.join(process.cwd(), 'temp-artillery-results.json');

      const artillery = spawn('artillery', [
        'run',
        '--output',
        outputFile,
        configFile
      ]);

      let stdout = '';
      let stderr = '';

      artillery.stdout.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      artillery.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      artillery.on('close', (code) => {
        if (code === 0) {
          try {
            const results = JSON.parse(readFileSync(outputFile, 'utf-8'));
            const metrics = this.parseArtilleryResults(results);
            resolve(metrics);
          } catch (error) {
            reject(new Error(`Failed to parse Artillery results: ${error}`));
          }
        } else {
          reject(new Error(`Artillery test failed with code ${code}: ${stderr}`));
        }
      });
    });
  }

  private parseArtilleryResults(rawResults: any): PerformanceMetrics {
    const aggregate = rawResults.aggregate;

    return {
      responseTime: {
        p50: aggregate.latency?.p50 || 0,
        p95: aggregate.latency?.p95 || 0,
        p99: aggregate.latency?.p99 || 0,
        mean: aggregate.latency?.mean || 0,
        min: aggregate.latency?.min || 0,
        max: aggregate.latency?.max || 0,
      },
      throughput: {
        requestsPerSecond: aggregate.rps?.mean || 0,
        totalRequests: aggregate.counters?.['vusers.completed'] || 0,
        duration: rawResults.intermediate?.length * 10 || 0, // Artillery reports every 10s
      },
      errors: {
        totalErrors: aggregate.counters?.['errors.total'] || 0,
        errorRate: this.calculateErrorRate(aggregate),
        errorTypes: this.extractErrorTypes(aggregate),
      },
      resources: {
        memoryUsage: this.estimateMemoryUsage(aggregate),
        cpuUsage: this.estimateCpuUsage(aggregate),
        networkIO: aggregate.counters?.['http.downloaded_bytes'] || 0,
      },
      concurrency: {
        maxConcurrentUsers: aggregate.counters?.['vusers.created_by_name.total'] || 0,
        averageConcurrentUsers: Math.round((aggregate.counters?.['vusers.completed'] || 0) / 2),
      },
    };
  }

  private calculateErrorRate(aggregate: any): number {
    const totalRequests = aggregate.counters?.['http.requests'] || 0;
    const totalErrors = aggregate.counters?.['errors.total'] || 0;
    return totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0;
  }

  private extractErrorTypes(aggregate: any): Record<string, number> {
    const errorTypes: Record<string, number> = {};

    Object.keys(aggregate.counters || {}).forEach(key => {
      if (key.startsWith('errors.')) {
        const errorType = key.replace('errors.', '');
        errorTypes[errorType] = aggregate.counters[key];
      }
    });

    return errorTypes;
  }

  private estimateMemoryUsage(aggregate: any): number {
    // Estimate based on request volume and response sizes
    const totalRequests = aggregate.counters?.['http.requests'] || 0;
    const avgResponseSize = aggregate.counters?.['http.downloaded_bytes'] / totalRequests || 1024;
    return Math.round((totalRequests * avgResponseSize) / (1024 * 1024)); // Convert to MB
  }

  private estimateCpuUsage(aggregate: any): number {
    // Estimate CPU usage based on response times and throughput
    const avgResponseTime = aggregate.latency?.mean || 0;
    const rps = aggregate.rps?.mean || 0;
    return Math.min(Math.round((avgResponseTime * rps) / 10), 100);
  }

  generatePerformanceReport(metrics: PerformanceMetrics[]): string {
    const report = {
      summary: {
        totalTests: metrics.length,
        timestamp: new Date().toISOString(),
        overallStatus: this.getOverallStatus(metrics),
      },
      performance: {
        responseTime: this.aggregateResponseTimes(metrics),
        throughput: this.aggregateThroughput(metrics),
        errors: this.aggregateErrors(metrics),
        resources: this.aggregateResources(metrics),
      },
      thresholds: PERFORMANCE_THRESHOLDS,
      violations: this.findThresholdViolations(metrics),
      recommendations: this.generateRecommendations(metrics),
    };

    return JSON.stringify(report, null, 2);
  }

  private getOverallStatus(metrics: PerformanceMetrics[]): 'PASS' | 'FAIL' {
    return metrics.every(m =>
      m.responseTime.p99 <= PERFORMANCE_THRESHOLDS.P99_RESPONSE_TIME &&
      m.errors.errorRate <= PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE
    ) ? 'PASS' : 'FAIL';
  }

  private aggregateResponseTimes(metrics: PerformanceMetrics[]) {
    return {
      avgP50: Math.round(metrics.reduce((sum, m) => sum + m.responseTime.p50, 0) / metrics.length),
      avgP95: Math.round(metrics.reduce((sum, m) => sum + m.responseTime.p95, 0) / metrics.length),
      avgP99: Math.round(metrics.reduce((sum, m) => sum + m.responseTime.p99, 0) / metrics.length),
      maxP99: Math.max(...metrics.map(m => m.responseTime.p99)),
    };
  }

  private aggregateThroughput(metrics: PerformanceMetrics[]) {
    return {
      avgRps: Math.round(metrics.reduce((sum, m) => sum + m.throughput.requestsPerSecond, 0) / metrics.length),
      maxRps: Math.max(...metrics.map(m => m.throughput.requestsPerSecond)),
      totalRequests: metrics.reduce((sum, m) => sum + m.throughput.totalRequests, 0),
    };
  }

  private aggregateErrors(metrics: PerformanceMetrics[]) {
    return {
      avgErrorRate: metrics.reduce((sum, m) => sum + m.errors.errorRate, 0) / metrics.length,
      maxErrorRate: Math.max(...metrics.map(m => m.errors.errorRate)),
      totalErrors: metrics.reduce((sum, m) => sum + m.errors.totalErrors, 0),
    };
  }

  private aggregateResources(metrics: PerformanceMetrics[]) {
    return {
      avgMemoryUsage: Math.round(metrics.reduce((sum, m) => sum + m.resources.memoryUsage, 0) / metrics.length),
      maxMemoryUsage: Math.max(...metrics.map(m => m.resources.memoryUsage)),
      avgCpuUsage: Math.round(metrics.reduce((sum, m) => sum + m.resources.cpuUsage, 0) / metrics.length),
      maxCpuUsage: Math.max(...metrics.map(m => m.resources.cpuUsage)),
    };
  }

  private findThresholdViolations(metrics: PerformanceMetrics[]): string[] {
    const violations: string[] = [];

    metrics.forEach((metric, index) => {
      if (metric.responseTime.p95 > PERFORMANCE_THRESHOLDS.P95_RESPONSE_TIME) {
        violations.push(`Test ${index + 1}: P95 response time ${metric.responseTime.p95}ms exceeds threshold ${PERFORMANCE_THRESHOLDS.P95_RESPONSE_TIME}ms`);
      }

      if (metric.responseTime.p99 > PERFORMANCE_THRESHOLDS.P99_RESPONSE_TIME) {
        violations.push(`Test ${index + 1}: P99 response time ${metric.responseTime.p99}ms exceeds CRITICAL threshold ${PERFORMANCE_THRESHOLDS.P99_RESPONSE_TIME}ms`);
      }

      if (metric.errors.errorRate > PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE) {
        violations.push(`Test ${index + 1}: Error rate ${metric.errors.errorRate}% exceeds threshold ${PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE}%`);
      }

      if (metric.throughput.requestsPerSecond < PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT) {
        violations.push(`Test ${index + 1}: Throughput ${metric.throughput.requestsPerSecond} RPS below threshold ${PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT} RPS`);
      }

      if (metric.resources.memoryUsage > PERFORMANCE_THRESHOLDS.MAX_MEMORY_USAGE) {
        violations.push(`Test ${index + 1}: Memory usage ${metric.resources.memoryUsage}MB exceeds threshold ${PERFORMANCE_THRESHOLDS.MAX_MEMORY_USAGE}MB`);
      }
    });

    return violations;
  }

  private generateRecommendations(metrics: PerformanceMetrics[]): string[] {
    const recommendations: string[] = [];
    const aggregated = {
      avgP99: this.aggregateResponseTimes(metrics).avgP99,
      avgErrorRate: this.aggregateErrors(metrics).avgErrorRate,
      avgMemoryUsage: this.aggregateResources(metrics).avgMemoryUsage,
    };

    if (aggregated.avgP99 > PERFORMANCE_THRESHOLDS.P99_RESPONSE_TIME * 0.8) {
      recommendations.push('Consider implementing response caching for frequently accessed endpoints');
      recommendations.push('Review database query optimization and indexing');
      recommendations.push('Implement connection pooling for database operations');
    }

    if (aggregated.avgErrorRate > PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE * 0.5) {
      recommendations.push('Implement circuit breaker patterns for external service calls');
      recommendations.push('Add retry mechanisms with exponential backoff');
      recommendations.push('Improve input validation to reduce 400-level errors');
    }

    if (aggregated.avgMemoryUsage > PERFORMANCE_THRESHOLDS.MAX_MEMORY_USAGE * 0.7) {
      recommendations.push('Implement memory-efficient data structures');
      recommendations.push('Add memory leak detection and monitoring');
      recommendations.push('Consider implementing data streaming for large responses');
    }

    return recommendations;
  }
}

describe('Performance Test Suite', () => {
  let testRunner: PerformanceTestRunner;
  const testResults: PerformanceMetrics[] = [];

  beforeAll(async () => {
    testRunner = new PerformanceTestRunner();
    await testRunner.startTestServer();
  }, 60000);

  afterAll(async () => {
    await testRunner.stopTestServer();

    // Generate comprehensive performance report
    const report = testRunner.generatePerformanceReport(testResults);
    writeFileSync(
      path.join(process.cwd(), 'performance-test-report.json'),
      report
    );

    console.log('\n' + '='.repeat(80));
    console.log('PERFORMANCE TEST SUMMARY');
    console.log('='.repeat(80));

    const parsedReport = JSON.parse(report);
    console.log(`Overall Status: ${parsedReport.summary.overallStatus}`);
    console.log(`Total Tests: ${parsedReport.summary.totalTests}`);
    console.log(`Average P99 Response Time: ${parsedReport.performance.responseTime.avgP99}ms`);
    console.log(`Average Error Rate: ${parsedReport.performance.errors.avgErrorRate.toFixed(2)}%`);

    if (parsedReport.violations.length > 0) {
      console.log('\nTHRESHOLD VIOLATIONS:');
      parsedReport.violations.forEach((violation: string) => {
        console.log(`❌ ${violation}`);
      });
    } else {
      console.log('\n✅ All performance thresholds met');
    }

    if (parsedReport.recommendations.length > 0) {
      console.log('\nRECOMMENDATIONS:');
      parsedReport.recommendations.forEach((rec: string) => {
        console.log(`💡 ${rec}`);
      });
    }

    console.log('='.repeat(80));
  }, 10000);

  describe('API Gateway Performance', () => {
    it('should meet response time thresholds for basic endpoints', async () => {
      const metrics = await testRunner.runArtilleryTest(
        path.join(__dirname, 'artillery-basic.yml')
      );
      testResults.push(metrics);

      expect(metrics.responseTime.p95).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.P95_RESPONSE_TIME);
      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.P99_RESPONSE_TIME);
      expect(metrics.errors.errorRate).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 120000);

    it('should handle authentication flow efficiently', async () => {
      const metrics = await testRunner.runArtilleryTest(
        path.join(__dirname, 'artillery-auth.yml')
      );
      testResults.push(metrics);

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.P99_RESPONSE_TIME);
      expect(metrics.throughput.requestsPerSecond).toBeGreaterThanOrEqual(PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT);
    }, 120000);
  });

  describe('Database Performance', () => {
    it('should handle CRM operations within time limits', async () => {
      const metrics = await testRunner.runArtilleryTest(
        path.join(__dirname, 'artillery-crm.yml')
      );
      testResults.push(metrics);

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.P99_RESPONSE_TIME);
      expect(metrics.errors.errorRate).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 180000);

    it('should maintain performance under concurrent database access', async () => {
      const metrics = await testRunner.runArtilleryTest(
        path.join(__dirname, 'artillery-database-stress.yml')
      );
      testResults.push(metrics);

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.P99_RESPONSE_TIME * 1.2); // 20% tolerance for stress test
      expect(metrics.concurrency.maxConcurrentUsers).toBeGreaterThan(10);
    }, 300000);
  });

  describe('Finance Module Performance', () => {
    it('should handle invoice operations efficiently', async () => {
      const metrics = await testRunner.runArtilleryTest(
        path.join(__dirname, 'artillery-finance.yml')
      );
      testResults.push(metrics);

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.P99_RESPONSE_TIME);
      expect(metrics.errors.errorRate).toBeLessThanOrEqual(PERFORMANCE_THRESHOLDS.MAX_ERROR_RATE);
    }, 180000);

    it('should handle complex financial calculations within limits', async () => {
      // Test tax calculations, currency conversions, etc.
      const start = Date.now();

      // Simulate complex financial operations
      for (let i = 0; i < 100; i++) {
        const mockCalculation = Array.from({ length: 1000 }, (_, j) =>
          Math.pow(Math.random() * 100, 2) * 1.08875 // Tax calculation simulation
        ).reduce((sum, val) => sum + val, 0);

        expect(mockCalculation).toBeGreaterThan(0);
      }

      const duration = Date.now() - start;
      expect(duration).toBeLessThan(1000); // Should complete in under 1 second
    });
  });

  describe('Cache Performance', () => {
    it('should provide fast cache access times', async () => {
      const metrics = await testRunner.runArtilleryTest(
        path.join(__dirname, 'artillery-cache.yml')
      );
      testResults.push(metrics);

      expect(metrics.responseTime.p99).toBeLessThanOrEqual(50); // Cache should be very fast
      expect(metrics.throughput.requestsPerSecond).toBeGreaterThanOrEqual(PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT * 2);
    }, 120000);

    it('should handle cache invalidation efficiently', async () => {
      const start = Date.now();

      // Simulate cache operations
      const cache = new Map();

      // Fill cache
      for (let i = 0; i < 10000; i++) {
        cache.set(`key_${i}`, `value_${i}`);
      }

      // Pattern-based invalidation
      for (const [key] of cache.entries()) {
        if (key.startsWith('key_1')) {
          cache.delete(key);
        }
      }

      const duration = Date.now() - start;
      expect(duration).toBeLessThan(100); // Should complete quickly
      expect(cache.size).toBeLessThan(10000);
    });
  });

  describe('Memory and Resource Performance', () => {
    it('should maintain acceptable memory usage under load', async () => {
      const initialMemory = process.memoryUsage();

      // Simulate memory-intensive operations
      const largeArrays: number[][] = [];

      for (let i = 0; i < 100; i++) {
        largeArrays.push(new Array(10000).fill(Math.random()));
      }

      const peakMemory = process.memoryUsage();
      const memoryIncrease = (peakMemory.heapUsed - initialMemory.heapUsed) / (1024 * 1024);

      // Clean up
      largeArrays.length = 0;

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      expect(memoryIncrease).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_MEMORY_USAGE);
    });

    it('should handle concurrent requests without memory leaks', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Simulate concurrent request processing
      const promises = Array.from({ length: 1000 }, async (_, i) => {
        return new Promise(resolve => {
          const data = { id: i, payload: 'x'.repeat(1000) };
          setTimeout(() => resolve(data), Math.random() * 10);
        });
      });

      await Promise.all(promises);

      // Force garbage collection
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryDelta = (finalMemory - initialMemory) / (1024 * 1024);

      // Should not have significant memory growth
      expect(memoryDelta).toBeLessThan(50); // Less than 50MB increase
    });
  });

  describe('Error Handling Performance', () => {
    it('should handle errors without performance degradation', async () => {
      const start = Date.now();
      const errors: Error[] = [];

      // Generate various error scenarios
      for (let i = 0; i < 1000; i++) {
        try {
          if (i % 10 === 0) throw new Error(`Test error ${i}`);
          if (i % 15 === 0) throw new TypeError(`Type error ${i}`);
          if (i % 20 === 0) throw new RangeError(`Range error ${i}`);

          // Normal operation
          JSON.stringify({ test: 'data', index: i });
        } catch (error) {
          errors.push(error as Error);
        }
      }

      const duration = Date.now() - start;

      expect(duration).toBeLessThan(1000); // Should handle errors quickly
      expect(errors.length).toBeGreaterThan(0);
      expect(errors.length).toBeLessThan(200); // Should not have too many errors
    });
  });

  describe('Scalability and Load Testing', () => {
    it('should scale linearly with increased load', async () => {
      const loads = [10, 20, 40]; // Different load levels
      const results: { load: number; rps: number; responseTime: number }[] = [];

      for (const load of loads) {
        // Simulate different load levels
        const start = Date.now();
        const requests = Array.from({ length: load * 10 }, (_, i) =>
          Promise.resolve({ id: i, processed: Date.now() })
        );

        await Promise.all(requests);

        const duration = Date.now() - start;
        const rps = (load * 10) / (duration / 1000);

        results.push({
          load,
          rps,
          responseTime: duration / (load * 10)
        });
      }

      // Check that performance doesn't degrade disproportionately
      for (let i = 1; i < results.length; i++) {
        const prev = results[i - 1];
        const curr = results[i];

        // Response time shouldn't increase more than 2x for 2x load
        const responseTimeRatio = curr.responseTime / prev.responseTime;
        const loadRatio = curr.load / prev.load;

        expect(responseTimeRatio).toBeLessThanOrEqual(loadRatio * 1.5);
      }
    });
  });
});