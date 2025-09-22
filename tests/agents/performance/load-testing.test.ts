/**
 * Elite Agent Load Testing Suite
 * Tests agent performance under high load and concurrent execution scenarios
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  TestEnvironmentFactory,
  BusinessContextGenerator,
  TaskGenerator,
  PerformanceMonitor,
  TestAssertions,
  setupAgentTests,
  type TestEnvironment,
  type PerformanceMetrics
} from '../test-harness';
import type { AgentTask, AgentResult } from '../../../src/modules/agents/types';

describe('Elite Agent Load Testing', () => {
  let testEnv: TestEnvironment;
  let performanceMonitor: PerformanceMonitor;

  setupAgentTests();

  beforeEach(async () => {
    testEnv = await TestEnvironmentFactory.create();
    performanceMonitor = new PerformanceMonitor();
  });

  afterEach(async () => {
    await TestEnvironmentFactory.cleanup(testEnv);
  });

  describe('Concurrent Task Execution', () => {
    it('should handle 100 concurrent tasks efficiently', async () => {
      const taskCount = 100;
      const tasks = TaskGenerator.generateBatch(taskCount);

      performanceMonitor.start();
      await performanceMonitor.measureMemoryUsage();

      const startTime = Date.now();
      const results = await Promise.allSettled(
        tasks.map(task => testEnv.mockAgent.execute(task, testEnv.businessContext))
      );
      const endTime = Date.now();

      performanceMonitor.end();
      await performanceMonitor.measureMemoryUsage();

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;
      const totalTime = endTime - startTime;

      await performanceMonitor.measureTaskThroughput(successful, totalTime);

      // Performance assertions
      expect(successful).toBeGreaterThan(taskCount * 0.95); // 95% success rate
      expect(totalTime).toBeLessThan(10000); // Under 10 seconds
      expect(performanceMonitor.getMetric('taskThroughput')).toBeGreaterThan(10); // 10+ tasks/second

      console.log(`✅ Concurrent Tasks: ${successful}/${taskCount} succeeded in ${totalTime}ms`);
      console.log(`📊 Throughput: ${performanceMonitor.getMetric('taskThroughput')?.toFixed(2)} tasks/sec`);
    });

    it('should handle 500 concurrent tasks with graceful degradation', async () => {
      const taskCount = 500;
      const tasks = TaskGenerator.generateBatch(taskCount);

      performanceMonitor.start();

      const startTime = Date.now();
      const results = await Promise.allSettled(
        tasks.map(task => testEnv.mockAgent.execute(task, testEnv.businessContext))
      );
      const endTime = Date.now();

      performanceMonitor.end();

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const totalTime = endTime - startTime;

      // Under extreme load, should maintain reasonable performance
      expect(successful).toBeGreaterThan(taskCount * 0.8); // 80% minimum success rate
      expect(totalTime).toBeLessThan(30000); // Under 30 seconds

      console.log(`⚡ High Load: ${successful}/${taskCount} succeeded in ${totalTime}ms`);
    });

    it('should handle 1000 concurrent tasks (stress test)', async () => {
      const taskCount = 1000;
      const tasks = TaskGenerator.generateHighLoad(taskCount);

      performanceMonitor.start();
      const initialMemory = await performanceMonitor.measureMemoryUsage();

      const startTime = Date.now();
      const results = await Promise.allSettled(
        tasks.map(task => testEnv.mockAgent.execute(task, testEnv.businessContext))
      );
      const endTime = Date.now();

      const finalMemory = await performanceMonitor.measureMemoryUsage();
      performanceMonitor.end();

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;
      const totalTime = endTime - startTime;
      const memoryIncrease = finalMemory - initialMemory;

      // Stress test thresholds
      expect(successful).toBeGreaterThan(taskCount * 0.7); // 70% minimum under stress
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Max 100MB memory increase

      console.log(`🔥 Stress Test: ${successful}/${taskCount} succeeded, ${failed} failed`);
      console.log(`💾 Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
    });
  });

  describe('Response Time Performance', () => {
    it('should maintain sub-2-second response times under normal load', async () => {
      const taskCount = 50;
      const tasks = TaskGenerator.generateBatch(taskCount);
      const responseTimes: number[] = [];

      for (const task of tasks) {
        const startTime = Date.now();
        await testEnv.mockAgent.execute(task, testEnv.businessContext);
        const responseTime = Date.now() - startTime;
        responseTimes.push(responseTime);
      }

      // Calculate percentiles
      responseTimes.sort((a, b) => a - b);
      const p50 = responseTimes[Math.floor(responseTimes.length * 0.5)];
      const p95 = responseTimes[Math.floor(responseTimes.length * 0.95)];
      const p99 = responseTimes[Math.floor(responseTimes.length * 0.99)];

      expect(p50).toBeLessThan(500); // 50th percentile under 500ms
      expect(p95).toBeLessThan(2000); // 95th percentile under 2s
      expect(p99).toBeLessThan(5000); // 99th percentile under 5s

      console.log(`⏱️  Response Times - P50: ${p50}ms, P95: ${p95}ms, P99: ${p99}ms`);
    });

    it('should handle burst traffic efficiently', async () => {
      const burstSizes = [10, 50, 100, 200];
      const burstResults: { size: number; avgTime: number; maxTime: number }[] = [];

      for (const burstSize of burstSizes) {
        const tasks = TaskGenerator.generateBatch(burstSize);

        const startTime = Date.now();
        const results = await Promise.all(
          tasks.map(task => testEnv.mockAgent.execute(task, testEnv.businessContext))
        );
        const totalTime = Date.now() - startTime;

        const avgTime = totalTime / burstSize;
        const maxTime = totalTime;

        burstResults.push({ size: burstSize, avgTime, maxTime });

        expect(results).toHaveLength(burstSize);
        expect(avgTime).toBeLessThan(1000); // Average under 1s per task
      }

      // Performance should not degrade significantly with burst size
      const firstBurst = burstResults[0];
      const lastBurst = burstResults[burstResults.length - 1];
      const degradationRatio = lastBurst.avgTime / firstBurst.avgTime;

      expect(degradationRatio).toBeLessThan(5); // Max 5x degradation

      console.log(`💥 Burst Traffic Results:`, burstResults);
    });
  });

  describe('Resource Utilization', () => {
    it('should maintain stable memory usage during sustained load', async () => {
      const duration = 10000; // 10 seconds
      const interval = 100; // 100ms between tasks
      const taskCount = duration / interval;

      const memoryReadings: number[] = [];
      const startTime = Date.now();

      // Sustained load test
      while (Date.now() - startTime < duration) {
        const task = TaskGenerator.generate();
        const beforeMemory = await performanceMonitor.measureMemoryUsage();

        await testEnv.mockAgent.execute(task, testEnv.businessContext);

        const afterMemory = await performanceMonitor.measureMemoryUsage();
        memoryReadings.push(afterMemory);

        await new Promise(resolve => setTimeout(resolve, interval));
      }

      // Analyze memory stability
      const maxMemory = Math.max(...memoryReadings);
      const minMemory = Math.min(...memoryReadings);
      const avgMemory = memoryReadings.reduce((a, b) => a + b, 0) / memoryReadings.length;
      const memoryVariance = maxMemory - minMemory;

      expect(memoryVariance).toBeLessThan(50 * 1024 * 1024); // Max 50MB variance
      expect(maxMemory).toBeLessThan(512 * 1024 * 1024); // Max 512MB total

      console.log(`📈 Memory Stats - Avg: ${(avgMemory / 1024 / 1024).toFixed(2)}MB, Variance: ${(memoryVariance / 1024 / 1024).toFixed(2)}MB`);
    });

    it('should handle memory pressure gracefully', async () => {
      // Create memory pressure with large tasks
      const largeTasks = Array.from({ length: 20 }, () =>
        TaskGenerator.generate({
          input: {
            prompt: 'Process large dataset',
            data: {
              largeArray: Array.from({ length: 10000 }, (_, i) => ({
                id: i,
                data: `large-data-${i}`.repeat(100)
              }))
            }
          }
        })
      );

      const initialMemory = await performanceMonitor.measureMemoryUsage();

      const results = await Promise.allSettled(
        largeTasks.map(task => testEnv.mockAgent.execute(task, testEnv.businessContext))
      );

      // Force garbage collection
      if (global.gc) {
        global.gc();
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      const finalMemory = await performanceMonitor.measureMemoryUsage();
      const memoryIncrease = finalMemory - initialMemory;

      const successful = results.filter(r => r.status === 'fulfilled').length;

      expect(successful).toBeGreaterThan(largeTasks.length * 0.8); // 80% success under pressure
      expect(memoryIncrease).toBeLessThan(200 * 1024 * 1024); // Max 200MB increase

      console.log(`🧠 Memory Pressure: ${successful}/${largeTasks.length} succeeded, ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB increase`);
    });
  });

  describe('Throughput Optimization', () => {
    it('should achieve target throughput of 100+ tasks/second', async () => {
      const testDuration = 5000; // 5 seconds
      const tasks: AgentTask[] = [];
      const results: AgentResult[] = [];

      performanceMonitor.start();

      const startTime = Date.now();
      let taskCount = 0;

      // Generate and execute tasks continuously
      const interval = setInterval(async () => {
        const batchSize = 10;
        const batch = TaskGenerator.generateBatch(batchSize);
        tasks.push(...batch);

        const batchResults = await Promise.allSettled(
          batch.map(task => testEnv.mockAgent.execute(task, testEnv.businessContext))
        );

        batchResults.forEach(result => {
          if (result.status === 'fulfilled') {
            results.push(result.value);
          }
        });

        taskCount += batchSize;
      }, 50); // Every 50ms

      await new Promise(resolve => setTimeout(resolve, testDuration));
      clearInterval(interval);

      const endTime = Date.now();
      const actualDuration = endTime - startTime;
      const throughput = (results.length / actualDuration) * 1000; // tasks per second

      performanceMonitor.recordMetric('actualThroughput', throughput);
      performanceMonitor.end();

      expect(throughput).toBeGreaterThan(50); // Minimum 50 tasks/second
      expect(results.length).toBeGreaterThan(taskCount * 0.9); // 90% completion rate

      console.log(`🚀 Throughput: ${throughput.toFixed(2)} tasks/second (${results.length}/${taskCount} completed)`);
    });

    it('should optimize batch processing', async () => {
      const batchSizes = [1, 5, 10, 25, 50, 100];
      const batchResults: { size: number; throughput: number; latency: number }[] = [];

      for (const batchSize of batchSizes) {
        const batches = Array.from({ length: 5 }, () =>
          TaskGenerator.generateBatch(batchSize)
        );

        const startTime = Date.now();

        const allResults = await Promise.all(
          batches.map(batch =>
            Promise.all(
              batch.map(task => testEnv.mockAgent.execute(task, testEnv.businessContext))
            )
          )
        );

        const endTime = Date.now();
        const totalTime = endTime - startTime;
        const totalTasks = batchSizes.reduce((sum, size) => sum + size, 0) * 5;
        const throughput = (totalTasks / totalTime) * 1000;
        const avgLatency = totalTime / totalTasks;

        batchResults.push({ size: batchSize, throughput, latency: avgLatency });

        expect(allResults.flat()).toHaveLength(totalTasks);
      }

      // Find optimal batch size (highest throughput)
      const optimalBatch = batchResults.reduce((best, current) =>
        current.throughput > best.throughput ? current : best
      );

      expect(optimalBatch.throughput).toBeGreaterThan(10); // Minimum viable throughput

      console.log(`📊 Batch Optimization:`, batchResults);
      console.log(`🎯 Optimal batch size: ${optimalBatch.size} (${optimalBatch.throughput.toFixed(2)} tasks/sec)`);
    });
  });

  describe('Error Rate Under Load', () => {
    it('should maintain low error rate under sustained load', async () => {
      const taskCount = 200;
      const tasks = TaskGenerator.generateBatch(taskCount);

      // Introduce some variability to simulate real conditions
      testEnv.mockAgent.shouldFail = false;
      const originalDelay = testEnv.mockAgent.executionDelay;

      const results = await Promise.allSettled(
        tasks.map(async (task, index) => {
          // Add random delay to some tasks
          if (index % 10 === 0) {
            testEnv.mockAgent.executionDelay = Math.random() * 100;
          }

          return testEnv.mockAgent.execute(task, testEnv.businessContext);
        })
      );

      testEnv.mockAgent.executionDelay = originalDelay;

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;
      const errorRate = failed / taskCount;

      expect(errorRate).toBeLessThan(0.05); // Less than 5% error rate
      expect(successful).toBeGreaterThan(taskCount * 0.95);

      console.log(`❌ Error Rate: ${(errorRate * 100).toFixed(2)}% (${failed}/${taskCount} failed)`);
    });

    it('should recover from temporary failures', async () => {
      const taskCount = 100;
      const tasks = TaskGenerator.generateBatch(taskCount);

      let failureCount = 0;
      const maxFailures = 10;

      const results = await Promise.allSettled(
        tasks.map(async (task, index) => {
          // Introduce periodic failures
          if (index % 20 === 0 && failureCount < maxFailures) {
            testEnv.mockAgent.shouldFail = true;
            failureCount++;
          } else {
            testEnv.mockAgent.shouldFail = false;
          }

          try {
            return await testEnv.mockAgent.execute(task, testEnv.businessContext);
          } finally {
            testEnv.mockAgent.shouldFail = false;
          }
        })
      );

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      // Should recover and maintain high success rate despite intermittent failures
      expect(successful).toBeGreaterThan(taskCount - maxFailures);
      expect(failed).toBeLessThanOrEqual(maxFailures);

      console.log(`🔄 Recovery Test: ${successful}/${taskCount} succeeded after ${failed} failures`);
    });
  });

  describe('Performance Benchmarks', () => {
    it('should meet all elite performance benchmarks', async () => {
      const benchmarkTasks = TaskGenerator.generateBatch(50);
      const metrics: PerformanceMetrics[] = [];

      for (const task of benchmarkTasks) {
        const monitor = new PerformanceMonitor();
        monitor.start();

        const beforeMemory = await monitor.measureMemoryUsage();
        const startTime = Date.now();

        const result = await testEnv.mockAgent.execute(task, testEnv.businessContext);

        const endTime = Date.now();
        const afterMemory = await monitor.measureMemoryUsage();

        monitor.end();

        const performanceMetric: PerformanceMetrics = {
          executionTime: endTime - startTime,
          memoryUsage: afterMemory - beforeMemory,
          cpuUsage: 0, // Mock implementation
          taskThroughput: 1000 / (endTime - startTime), // tasks per second for this task
          errorRate: 0,
          responseTime: endTime - startTime
        };

        metrics.push(performanceMetric);
      }

      // Calculate aggregate metrics
      const avgMetrics: PerformanceMetrics = {
        executionTime: metrics.reduce((sum, m) => sum + m.executionTime, 0) / metrics.length,
        memoryUsage: metrics.reduce((sum, m) => sum + m.memoryUsage, 0) / metrics.length,
        cpuUsage: 0,
        taskThroughput: metrics.reduce((sum, m) => sum + m.taskThroughput, 0) / metrics.length,
        errorRate: 0,
        responseTime: metrics.reduce((sum, m) => sum + m.responseTime, 0) / metrics.length
      };

      // Elite performance thresholds
      const eliteThresholds: PerformanceMetrics = {
        executionTime: 2000, // 2 seconds max
        memoryUsage: 10 * 1024 * 1024, // 10MB max per task
        cpuUsage: 0.8, // 80% max
        taskThroughput: 0.5, // 0.5 tasks/second min
        errorRate: 0.01, // 1% max
        responseTime: 2000 // 2 seconds max
      };

      TestAssertions.assertPerformanceMetrics(avgMetrics, eliteThresholds);

      console.log(`🏆 Elite Benchmarks Met:`);
      console.log(`   Avg Execution: ${avgMetrics.executionTime.toFixed(2)}ms`);
      console.log(`   Avg Memory: ${(avgMetrics.memoryUsage / 1024 / 1024).toFixed(2)}MB`);
      console.log(`   Avg Throughput: ${avgMetrics.taskThroughput.toFixed(2)} tasks/sec`);
    });
  });
});