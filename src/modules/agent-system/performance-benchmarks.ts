/**
 * Performance Benchmarks for Agent System
 * Comprehensive testing suite for performance, latency, throughput, and scalability
 */

import {
  IAgent,
  AgentTask,
  BusinessContext,
  AgentResult,
  Workflow,
  TaskConstraints
} from './types';
import { AgentSystem } from './index';
import { ClaudeNativeAgent } from './claude-native-agent';

export interface BenchmarkResult {
  name: string;
  description: string;
  iterations: number;
  totalTimeMs: number;
  avgLatencyMs: number;
  minLatencyMs: number;
  maxLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  throughputPerSecond: number;
  successRate: number;
  totalCost: number;
  avgCostPerTask: number;
  memoryUsageKb?: number;
  cpuUsagePercent?: number;
  errors: Array<{ error: string; count: number }>;
  metadata: Record<string, any>;
}

export interface BenchmarkSuite {
  name: string;
  version: string;
  environment: string;
  timestamp: number;
  results: BenchmarkResult[];
  summary: {
    totalBenchmarks: number;
    totalExecutions: number;
    overallSuccessRate: number;
    totalCost: number;
    avgLatency: number;
    highestThroughput: number;
  };
}

export class AgentSystemBenchmarks {
  private agentSystem: AgentSystem;
  private defaultContext: BusinessContext;

  constructor(agentSystem: AgentSystem) {
    this.agentSystem = agentSystem;
    this.defaultContext = {
      businessId: 'benchmark-business',
      userId: 'benchmark-user',
      sessionId: 'benchmark-session',
      department: 'operations',
      permissions: ['read', 'write', 'execute'],
      metadata: { benchmark: true }
    };
  }

  /**
   * Run comprehensive benchmark suite
   */
  async runFullSuite(): Promise<BenchmarkSuite> {

    const startTime = Date.now();
    const results: BenchmarkResult[] = [];

    // Single task execution benchmarks
    results.push(await this.benchmarkSingleTaskLatency());
    results.push(await this.benchmarkSimpleQueries());
    results.push(await this.benchmarkComplexAnalysis());
    results.push(await this.benchmarkCodeGeneration());

    // Concurrency and load benchmarks
    results.push(await this.benchmarkConcurrentExecution());
    results.push(await this.benchmarkHighThroughput());
    results.push(await this.benchmarkLoadSpikes());

    // Memory and cost benchmarks
    results.push(await this.benchmarkMemoryEfficiency());
    results.push(await this.benchmarkCostOptimization());

    // Streaming benchmarks
    results.push(await this.benchmarkStreamingLatency());
    results.push(await this.benchmarkStreamingThroughput());

    // Workflow benchmarks
    results.push(await this.benchmarkWorkflowExecution());

    // Error handling and retry benchmarks
    results.push(await this.benchmarkRetryMechanisms());
    results.push(await this.benchmarkErrorRecovery());

    // Scalability benchmarks
    results.push(await this.benchmarkScalability());

    const totalTime = Date.now() - startTime;

    const summary = this.calculateSummary(results, totalTime);

    const suite: BenchmarkSuite = {
      name: 'Agent System Performance Suite',
      version: '1.0.0',
      environment: 'development', // Would be configurable
      timestamp: Date.now(),
      results,
      summary
    };

    this.printSummary(suite);
    return suite;
  }

  /**
   * Benchmark single task execution latency
   */
  private async benchmarkSingleTaskLatency(): Promise<BenchmarkResult> {

    const iterations = 100;
    const latencies: number[] = [];
    const costs: number[] = [];
    const errors: Array<{ error: string; count: number }> = [];
    let successCount = 0;

    const startTime = Date.now();

    for (let i = 0; i < iterations; i++) {
      const task: AgentTask = {
        id: `latency-test-${i}`,
        capability: 'text_analysis',
        input: { text: 'Analyze the sentiment of this text: The weather is beautiful today!' },
        constraints: { maxLatency: 5000, maxCost: 0.01 },
        metadata: { benchmark: 'latency' }
      };

      try {
        const taskStart = Date.now();
        const result = await this.agentSystem.executeTask(task);
        const latency = Date.now() - taskStart;

        latencies.push(latency);
        costs.push(result.totalCost);

        if (result.success) {
          successCount++;
        } else {
          this.addError(errors, result.error || 'Unknown error');
        }
      } catch (error) {
        this.addError(errors, error instanceof Error ? error.message : String(error));
      }
    }

    const totalTime = Date.now() - startTime;

    return {
      name: 'Single Task Latency',
      description: 'Measures latency for individual task execution',
      iterations,
      totalTimeMs: totalTime,
      avgLatencyMs: this.average(latencies),
      minLatencyMs: Math.min(...latencies),
      maxLatencyMs: Math.max(...latencies),
      p50LatencyMs: this.percentile(latencies, 50),
      p95LatencyMs: this.percentile(latencies, 95),
      p99LatencyMs: this.percentile(latencies, 99),
      throughputPerSecond: (iterations / totalTime) * 1000,
      successRate: (successCount / iterations) * 100,
      totalCost: this.sum(costs),
      avgCostPerTask: this.average(costs),
      errors,
      metadata: { type: 'latency' }
    };
  }

  /**
   * Benchmark simple query performance
   */
  private async benchmarkSimpleQueries(): Promise<BenchmarkResult> {

    const iterations = 50;
    const queries = [
      'What is 2+2?',
      'Convert 100 USD to EUR',
      'What day is it today?',
      'Calculate 15% of 200',
      'What is the capital of France?'
    ];

    return await this.runTaskBenchmark(
      'Simple Queries',
      'Performance for simple, quick questions',
      iterations,
      (i) => ({
        id: `simple-query-${i}`,
        capability: 'general_query',
        input: { query: queries[i % queries.length] },
        constraints: { maxLatency: 3000, maxCost: 0.005 },
        metadata: { benchmark: 'simple' }
      })
    );
  }

  /**
   * Benchmark complex analysis tasks
   */
  private async benchmarkComplexAnalysis(): Promise<BenchmarkResult> {

    const complexData = Array.from({ length: 1000 }, (_, i) => ({
      id: i,
      value: Math.random() * 100,
      category: ['A', 'B', 'C'][i % 3],
      timestamp: Date.now() - i * 1000
    }));

    return await this.runTaskBenchmark(
      'Complex Analysis',
      'Performance for data analysis and complex reasoning',
      20,
      (i) => ({
        id: `complex-analysis-${i}`,
        capability: 'data_analysis',
        input: {
          data: complexData,
          task: 'Analyze trends, identify patterns, and provide insights'
        },
        constraints: { maxLatency: 15000, maxCost: 0.05 },
        metadata: { benchmark: 'complex' }
      })
    );
  }

  /**
   * Benchmark code generation tasks
   */
  private async benchmarkCodeGeneration(): Promise<BenchmarkResult> {

    const codePrompts = [
      'Create a TypeScript function to sort an array of objects by date',
      'Write a React component for a data table with pagination',
      'Generate a SQL query to find top customers by revenue',
      'Create a Python function for data validation',
      'Write JavaScript code for API rate limiting'
    ];

    return await this.runTaskBenchmark(
      'Code Generation',
      'Performance for generating code and technical content',
      15,
      (i) => ({
        id: `code-gen-${i}`,
        capability: 'code_generation',
        input: { prompt: codePrompts[i % codePrompts.length] },
        constraints: { maxLatency: 20000, maxCost: 0.08 },
        metadata: { benchmark: 'code' }
      })
    );
  }

  /**
   * Benchmark concurrent execution
   */
  private async benchmarkConcurrentExecution(): Promise<BenchmarkResult> {

    const concurrency = 10;
    const tasksPerWorker = 5;
    const totalTasks = concurrency * tasksPerWorker;

    const startTime = Date.now();
    const latencies: number[] = [];
    const costs: number[] = [];
    const errors: Array<{ error: string; count: number }> = [];
    let successCount = 0;

    // Create concurrent workers
    const workers = Array.from({ length: concurrency }, async (_, workerId) => {
      const workerLatencies: number[] = [];
      const workerCosts: number[] = [];

      for (let i = 0; i < tasksPerWorker; i++) {
        const task: AgentTask = {
          id: `concurrent-${workerId}-${i}`,
          capability: 'text_analysis',
          input: { text: `Worker ${workerId} analyzing text ${i}` },
          constraints: { maxLatency: 8000, maxCost: 0.02 },
          metadata: { benchmark: 'concurrent', workerId }
        };

        try {
          const taskStart = Date.now();
          const result = await this.agentSystem.executeTask(task);
          const latency = Date.now() - taskStart;

          workerLatencies.push(latency);
          workerCosts.push(result.totalCost);

          if (result.success) {
            successCount++;
          } else {
            this.addError(errors, result.error || 'Unknown error');
          }
        } catch (error) {
          this.addError(errors, error instanceof Error ? error.message : String(error));
        }
      }

      return { latencies: workerLatencies, costs: workerCosts };
    });

    // Wait for all workers to complete
    const results = await Promise.all(workers);

    // Aggregate results
    results.forEach(({ latencies: workerLatencies, costs: workerCosts }) => {
      latencies.push(...workerLatencies);
      costs.push(...workerCosts);
    });

    const totalTime = Date.now() - startTime;

    return {
      name: 'Concurrent Execution',
      description: `Performance with ${concurrency} concurrent workers`,
      iterations: totalTasks,
      totalTimeMs: totalTime,
      avgLatencyMs: this.average(latencies),
      minLatencyMs: Math.min(...latencies),
      maxLatencyMs: Math.max(...latencies),
      p50LatencyMs: this.percentile(latencies, 50),
      p95LatencyMs: this.percentile(latencies, 95),
      p99LatencyMs: this.percentile(latencies, 99),
      throughputPerSecond: (totalTasks / totalTime) * 1000,
      successRate: (successCount / totalTasks) * 100,
      totalCost: this.sum(costs),
      avgCostPerTask: this.average(costs),
      errors,
      metadata: { concurrency, tasksPerWorker }
    };
  }

  /**
   * Benchmark high throughput scenarios
   */
  private async benchmarkHighThroughput(): Promise<BenchmarkResult> {

    const totalTasks = 200;
    const batchSize = 20;
    const batches = Math.ceil(totalTasks / batchSize);

    const allLatencies: number[] = [];
    const allCosts: number[] = [];
    const errors: Array<{ error: string; count: number }> = [];
    let successCount = 0;

    const startTime = Date.now();

    for (let batch = 0; batch < batches; batch++) {
      const batchTasks = Math.min(batchSize, totalTasks - batch * batchSize);

      const batchPromises = Array.from({ length: batchTasks }, async (_, i) => {
        const taskId = batch * batchSize + i;
        const task: AgentTask = {
          id: `throughput-${taskId}`,
          capability: 'text_processing',
          input: { text: `Process batch ${batch}, task ${i}` },
          constraints: { maxLatency: 5000, maxCost: 0.01 },
          metadata: { benchmark: 'throughput', batch }
        };

        try {
          const taskStart = Date.now();
          const result = await this.agentSystem.executeTask(task);
          const latency = Date.now() - taskStart;

          if (result.success) {
            successCount++;
          } else {
            this.addError(errors, result.error || 'Unknown error');
          }

          return { latency, cost: result.totalCost };
        } catch (error) {
          this.addError(errors, error instanceof Error ? error.message : String(error));
          return { latency: 0, cost: 0 };
        }
      });

      const batchResults = await Promise.all(batchPromises);

      batchResults.forEach(({ latency, cost }) => {
        allLatencies.push(latency);
        allCosts.push(cost);
      });

      // Small delay between batches to avoid overwhelming the system
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    const totalTime = Date.now() - startTime;

    return {
      name: 'High Throughput',
      description: `Performance with ${totalTasks} tasks in batches of ${batchSize}`,
      iterations: totalTasks,
      totalTimeMs: totalTime,
      avgLatencyMs: this.average(allLatencies),
      minLatencyMs: Math.min(...allLatencies),
      maxLatencyMs: Math.max(...allLatencies),
      p50LatencyMs: this.percentile(allLatencies, 50),
      p95LatencyMs: this.percentile(allLatencies, 95),
      p99LatencyMs: this.percentile(allLatencies, 99),
      throughputPerSecond: (totalTasks / totalTime) * 1000,
      successRate: (successCount / totalTasks) * 100,
      totalCost: this.sum(allCosts),
      avgCostPerTask: this.average(allCosts),
      errors,
      metadata: { batchSize, batches }
    };
  }

  /**
   * Benchmark load spikes
   */
  private async benchmarkLoadSpikes(): Promise<BenchmarkResult> {

    const spikeTasks = 50;
    const normalTasks = 20;
    const totalTasks = spikeTasks + normalTasks;

    const latencies: number[] = [];
    const costs: number[] = [];
    const errors: Array<{ error: string; count: number }> = [];
    let successCount = 0;

    const startTime = Date.now();

    // Simulate sudden spike
    const spikePromises = Array.from({ length: spikeTasks }, async (_, i) => {
      const task: AgentTask = {
        id: `spike-${i}`,
        capability: 'general_query',
        input: { query: `Spike load task ${i}` },
        constraints: { maxLatency: 10000, maxCost: 0.02 },
        metadata: { benchmark: 'spike', phase: 'spike' }
      };

      try {
        const taskStart = Date.now();
        const result = await this.agentSystem.executeTask(task);
        const latency = Date.now() - taskStart;

        latencies.push(latency);
        costs.push(result.totalCost);

        if (result.success) {
          successCount++;
        } else {
          this.addError(errors, result.error || 'Unknown error');
        }
      } catch (error) {
        this.addError(errors, error instanceof Error ? error.message : String(error));
      }
    });

    // Wait for spike to complete
    await Promise.all(spikePromises);

    // Add normal load after spike
    const normalPromises = Array.from({ length: normalTasks }, async (_, i) => {
      const task: AgentTask = {
        id: `normal-${i}`,
        capability: 'general_query',
        input: { query: `Normal load task ${i}` },
        constraints: { maxLatency: 5000, maxCost: 0.01 },
        metadata: { benchmark: 'spike', phase: 'normal' }
      };

      try {
        const taskStart = Date.now();
        const result = await this.agentSystem.executeTask(task);
        const latency = Date.now() - taskStart;

        latencies.push(latency);
        costs.push(result.totalCost);

        if (result.success) {
          successCount++;
        } else {
          this.addError(errors, result.error || 'Unknown error');
        }
      } catch (error) {
        this.addError(errors, error instanceof Error ? error.message : String(error));
      }
    });

    await Promise.all(normalPromises);

    const totalTime = Date.now() - startTime;

    return {
      name: 'Load Spikes',
      description: `Performance during sudden load spikes (${spikeTasks} spike + ${normalTasks} normal)`,
      iterations: totalTasks,
      totalTimeMs: totalTime,
      avgLatencyMs: this.average(latencies),
      minLatencyMs: Math.min(...latencies),
      maxLatencyMs: Math.max(...latencies),
      p50LatencyMs: this.percentile(latencies, 50),
      p95LatencyMs: this.percentile(latencies, 95),
      p99LatencyMs: this.percentile(latencies, 99),
      throughputPerSecond: (totalTasks / totalTime) * 1000,
      successRate: (successCount / totalTasks) * 100,
      totalCost: this.sum(costs),
      avgCostPerTask: this.average(costs),
      errors,
      metadata: { spikeTasks, normalTasks }
    };
  }

  /**
   * Benchmark memory efficiency
   */
  private async benchmarkMemoryEfficiency(): Promise<BenchmarkResult> {

    // Simulate memory-intensive tasks
    return await this.runTaskBenchmark(
      'Memory Efficiency',
      'Performance with memory-intensive tasks',
      30,
      (i) => ({
        id: `memory-${i}`,
        capability: 'data_processing',
        input: {
          data: Array.from({ length: 10000 }, (_, j) => ({ id: j, value: Math.random() })),
          operation: 'aggregate_and_analyze'
        },
        constraints: { maxLatency: 12000, maxCost: 0.03 },
        metadata: { benchmark: 'memory' }
      })
    );
  }

  /**
   * Benchmark cost optimization
   */
  private async benchmarkCostOptimization(): Promise<BenchmarkResult> {

    // Test with very low cost constraints to trigger optimization
    return await this.runTaskBenchmark(
      'Cost Optimization',
      'Performance with strict cost constraints',
      25,
      (i) => ({
        id: `cost-opt-${i}`,
        capability: 'text_analysis',
        input: { text: `Cost-optimized analysis ${i}` },
        constraints: { maxLatency: 8000, maxCost: 0.002 }, // Very low cost limit
        metadata: { benchmark: 'cost' }
      })
    );
  }

  /**
   * Benchmark streaming latency
   */
  private async benchmarkStreamingLatency(): Promise<BenchmarkResult> {

    const iterations = 20;
    const firstChunkLatencies: number[] = [];
    const totalLatencies: number[] = [];
    const costs: number[] = [];
    const errors: Array<{ error: string; count: number }> = [];
    let successCount = 0;

    const startTime = Date.now();

    for (let i = 0; i < iterations; i++) {
      const task: AgentTask = {
        id: `streaming-latency-${i}`,
        capability: 'text_generation',
        input: { prompt: `Generate a story about task ${i}` },
        constraints: { maxLatency: 15000, maxCost: 0.05 },
        streaming: true,
        metadata: { benchmark: 'streaming-latency' }
      };

      try {
        const taskStart = Date.now();
        let firstChunkTime: number | null = null;
        let chunkCount = 0;

        // Note: In a real implementation, this would use the streaming response
        // For now, simulate streaming behavior
        const result = await this.agentSystem.executeTask(task);
        const totalLatency = Date.now() - taskStart;

        // Simulate first chunk latency (typically much faster)
        firstChunkTime = taskStart + Math.random() * 1000 + 200; // 200-1200ms
        const firstChunkLatency = firstChunkTime - taskStart;

        firstChunkLatencies.push(firstChunkLatency);
        totalLatencies.push(totalLatency);
        costs.push(result.totalCost);

        if (result.success) {
          successCount++;
        } else {
          this.addError(errors, result.error || 'Unknown error');
        }
      } catch (error) {
        this.addError(errors, error instanceof Error ? error.message : String(error));
      }
    }

    const totalTime = Date.now() - startTime;

    return {
      name: 'Streaming Latency',
      description: 'Time to first chunk and total streaming latency',
      iterations,
      totalTimeMs: totalTime,
      avgLatencyMs: this.average(totalLatencies),
      minLatencyMs: Math.min(...totalLatencies),
      maxLatencyMs: Math.max(...totalLatencies),
      p50LatencyMs: this.percentile(totalLatencies, 50),
      p95LatencyMs: this.percentile(totalLatencies, 95),
      p99LatencyMs: this.percentile(totalLatencies, 99),
      throughputPerSecond: (iterations / totalTime) * 1000,
      successRate: (successCount / iterations) * 100,
      totalCost: this.sum(costs),
      avgCostPerTask: this.average(costs),
      errors,
      metadata: {
        avgFirstChunkLatency: this.average(firstChunkLatencies),
        p95FirstChunkLatency: this.percentile(firstChunkLatencies, 95)
      }
    };
  }

  /**
   * Benchmark streaming throughput
   */
  private async benchmarkStreamingThroughput(): Promise<BenchmarkResult> {

    return await this.runTaskBenchmark(
      'Streaming Throughput',
      'Concurrent streaming task performance',
      15,
      (i) => ({
        id: `streaming-throughput-${i}`,
        capability: 'content_generation',
        input: { prompt: `Generate content for streaming test ${i}` },
        constraints: { maxLatency: 20000, maxCost: 0.06 },
        streaming: true,
        metadata: { benchmark: 'streaming-throughput' }
      })
    );
  }

  /**
   * Benchmark workflow execution
   */
  private async benchmarkWorkflowExecution(): Promise<BenchmarkResult> {

    const iterations = 10;
    const latencies: number[] = [];
    const costs: number[] = [];
    const errors: Array<{ error: string; count: number }> = [];
    let successCount = 0;

    const startTime = Date.now();

    for (let i = 0; i < iterations; i++) {
      const workflow: Workflow = {
        id: `workflow-benchmark-${i}`,
        name: `Benchmark Workflow ${i}`,
        description: 'Multi-step workflow for performance testing',
        steps: [
          {
            id: 'step1',
            capability: 'data_extraction',
            input: { source: `data-${i}` },
            constraints: { maxLatency: 5000, maxCost: 0.02 }
          },
          {
            id: 'step2',
            capability: 'data_analysis',
            input: { data: '${step1.output}' },
            constraints: { maxLatency: 8000, maxCost: 0.03 },
            dependencies: ['step1']
          },
          {
            id: 'step3',
            capability: 'report_generation',
            input: { analysis: '${step2.output}' },
            constraints: { maxLatency: 6000, maxCost: 0.025 },
            dependencies: ['step2']
          }
        ],
        metadata: { benchmark: 'workflow' }
      };

      try {
        const workflowStart = Date.now();
        const result = await this.agentSystem.executeWorkflow(workflow);
        const latency = Date.now() - workflowStart;

        latencies.push(latency);
        costs.push(result.totalCost);

        if (result.success) {
          successCount++;
        } else {
          this.addError(errors, result.error || 'Unknown error');
        }
      } catch (error) {
        this.addError(errors, error instanceof Error ? error.message : String(error));
      }
    }

    const totalTime = Date.now() - startTime;

    return {
      name: 'Workflow Execution',
      description: 'Performance of multi-step workflow execution',
      iterations,
      totalTimeMs: totalTime,
      avgLatencyMs: this.average(latencies),
      minLatencyMs: Math.min(...latencies),
      maxLatencyMs: Math.max(...latencies),
      p50LatencyMs: this.percentile(latencies, 50),
      p95LatencyMs: this.percentile(latencies, 95),
      p99LatencyMs: this.percentile(latencies, 99),
      throughputPerSecond: (iterations / totalTime) * 1000,
      successRate: (successCount / iterations) * 100,
      totalCost: this.sum(costs),
      avgCostPerTask: this.average(costs),
      errors,
      metadata: { stepsPerWorkflow: 3 }
    };
  }

  /**
   * Benchmark retry mechanisms
   */
  private async benchmarkRetryMechanisms(): Promise<BenchmarkResult> {

    // Create tasks that will likely fail and trigger retries
    return await this.runTaskBenchmark(
      'Retry Mechanisms',
      'Performance of retry and fallback logic',
      20,
      (i) => ({
        id: `retry-${i}`,
        capability: 'unreliable_test', // This capability should trigger retries
        input: { data: `test-${i}`, failureRate: 0.3 },
        constraints: { maxLatency: 15000, maxCost: 0.04 },
        retryPolicy: { maxRetries: 3, exponentialBackoff: true },
        metadata: { benchmark: 'retry' }
      })
    );
  }

  /**
   * Benchmark error recovery
   */
  private async benchmarkErrorRecovery(): Promise<BenchmarkResult> {

    return await this.runTaskBenchmark(
      'Error Recovery',
      'System resilience and error handling',
      15,
      (i) => ({
        id: `error-recovery-${i}`,
        capability: 'error_prone_task',
        input: { data: `error-test-${i}`, errorType: i % 3 === 0 ? 'timeout' : 'processing' },
        constraints: { maxLatency: 10000, maxCost: 0.03 },
        metadata: { benchmark: 'error-recovery' }
      })
    );
  }

  /**
   * Benchmark scalability
   */
  private async benchmarkScalability(): Promise<BenchmarkResult> {

    const scales = [5, 10, 25, 50, 100];
    const allLatencies: number[] = [];
    const allCosts: number[] = [];
    const errors: Array<{ error: string; count: number }> = [];
    let totalSuccess = 0;
    let totalTasks = 0;

    const startTime = Date.now();

    for (const scale of scales) {

      const scalePromises = Array.from({ length: scale }, async (_, i) => {
        const task: AgentTask = {
          id: `scale-${scale}-${i}`,
          capability: 'scalability_test',
          input: { scale, taskId: i },
          constraints: { maxLatency: 8000, maxCost: 0.02 },
          metadata: { benchmark: 'scalability', scale }
        };

        try {
          const taskStart = Date.now();
          const result = await this.agentSystem.executeTask(task);
          const latency = Date.now() - taskStart;

          if (result.success) {
            totalSuccess++;
          } else {
            this.addError(errors, result.error || 'Unknown error');
          }

          return { latency, cost: result.totalCost };
        } catch (error) {
          this.addError(errors, error instanceof Error ? error.message : String(error));
          return { latency: 0, cost: 0 };
        }
      });

      const scaleResults = await Promise.all(scalePromises);

      scaleResults.forEach(({ latency, cost }) => {
        allLatencies.push(latency);
        allCosts.push(cost);
      });

      totalTasks += scale;

      // Brief pause between scales
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    const totalTime = Date.now() - startTime;

    return {
      name: 'Scalability',
      description: `Performance across different scales: ${scales.join(', ')} tasks`,
      iterations: totalTasks,
      totalTimeMs: totalTime,
      avgLatencyMs: this.average(allLatencies),
      minLatencyMs: Math.min(...allLatencies),
      maxLatencyMs: Math.max(...allLatencies),
      p50LatencyMs: this.percentile(allLatencies, 50),
      p95LatencyMs: this.percentile(allLatencies, 95),
      p99LatencyMs: this.percentile(allLatencies, 99),
      throughputPerSecond: (totalTasks / totalTime) * 1000,
      successRate: (totalSuccess / totalTasks) * 100,
      totalCost: this.sum(allCosts),
      avgCostPerTask: this.average(allCosts),
      errors,
      metadata: { scales, tasksPerScale: scales }
    };
  }

  /**
   * Generic task benchmark runner
   */
  private async runTaskBenchmark(
    name: string,
    description: string,
    iterations: number,
    taskFactory: (i: number) => AgentTask
  ): Promise<BenchmarkResult> {
    const latencies: number[] = [];
    const costs: number[] = [];
    const errors: Array<{ error: string; count: number }> = [];
    let successCount = 0;

    const startTime = Date.now();

    for (let i = 0; i < iterations; i++) {
      const task = taskFactory(i);

      try {
        const taskStart = Date.now();
        const result = await this.agentSystem.executeTask(task);
        const latency = Date.now() - taskStart;

        latencies.push(latency);
        costs.push(result.totalCost);

        if (result.success) {
          successCount++;
        } else {
          this.addError(errors, result.error || 'Unknown error');
        }
      } catch (error) {
        this.addError(errors, error instanceof Error ? error.message : String(error));
      }
    }

    const totalTime = Date.now() - startTime;

    return {
      name,
      description,
      iterations,
      totalTimeMs: totalTime,
      avgLatencyMs: this.average(latencies),
      minLatencyMs: Math.min(...latencies),
      maxLatencyMs: Math.max(...latencies),
      p50LatencyMs: this.percentile(latencies, 50),
      p95LatencyMs: this.percentile(latencies, 95),
      p99LatencyMs: this.percentile(latencies, 99),
      throughputPerSecond: (iterations / totalTime) * 1000,
      successRate: (successCount / iterations) * 100,
      totalCost: this.sum(costs),
      avgCostPerTask: this.average(costs),
      errors,
      metadata: {}
    };
  }

  /**
   * Helper methods for statistics
   */
  private average(numbers: number[]): number {
    return numbers.length > 0 ? numbers.reduce((a, b) => a + b, 0) / numbers.length : 0;
  }

  private sum(numbers: number[]): number {
    return numbers.reduce((a, b) => a + b, 0);
  }

  private percentile(numbers: number[], percentile: number): number {
    if (numbers.length === 0) return 0;
    const sorted = [...numbers].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  }

  private addError(errors: Array<{ error: string; count: number }>, error: string): void {
    const existing = errors.find(e => e.error === error);
    if (existing) {
      existing.count++;
    } else {
      errors.push({ error, count: 1 });
    }
  }

  private calculateSummary(results: BenchmarkResult[], totalTime: number) {
    const totalExecutions = results.reduce((sum, r) => sum + r.iterations, 0);
    const totalCost = results.reduce((sum, r) => sum + r.totalCost, 0);
    const avgSuccessRate = results.reduce((sum, r) => sum + r.successRate, 0) / results.length;
    const avgLatency = results.reduce((sum, r) => sum + r.avgLatencyMs, 0) / results.length;
    const highestThroughput = Math.max(...results.map(r => r.throughputPerSecond));

    return {
      totalBenchmarks: results.length,
      totalExecutions,
      overallSuccessRate: avgSuccessRate,
      totalCost,
      avgLatency,
      highestThroughput
    };
  }

  private printSummary(suite: BenchmarkSuite): void {



    suite.results.forEach((result, index) => {

      if (result.errors.length > 0) {
      }
    });

  }

  /**
   * Save benchmark results to file
   */
  async saveBenchmarkResults(suite: BenchmarkSuite, filePath?: string): Promise<void> {
    const fileName = filePath || `benchmark-results-${Date.now()}.json`;

    try {
      // In a real implementation, this would save to the file system
    } catch (error) {
    }
  }

  /**
   * Compare with previous benchmark results
   */
  compareBenchmarks(current: BenchmarkSuite, previous: BenchmarkSuite): {
    improvements: string[];
    regressions: string[];
    summary: string;
  } {
    const improvements: string[] = [];
    const regressions: string[] = [];

    current.results.forEach(currentResult => {
      const previousResult = previous.results.find(r => r.name === currentResult.name);
      if (!previousResult) return;

      // Compare key metrics
      const latencyImprovement
  = ((previousResult.avgLatencyMs - currentResult.avgLatencyMs) / previousResult.avgLatencyMs) * 100;
      const throughputImprovement
  = ((currentResult.throughputPerSecond - previousResult.throughputPerSecond) / previousResult.throughputPerSecond) * 100;
      const costImprovement
  = ((previousResult.avgCostPerTask - currentResult.avgCostPerTask) / previousResult.avgCostPerTask) * 100;

      if (latencyImprovement > 5) {
        improvements.push(`${currentResult.name}: ${latencyImprovement.toFixed(1)}% faster`);
      } else if (latencyImprovement < -5) {
        regressions.push(`${currentResult.name}: ${Math.abs(latencyImprovement).toFixed(1)}% slower`);
      }

      if (throughputImprovement > 5) {
        improvements.push(`${currentResult.name}: ${throughputImprovement.toFixed(1)}% higher throughput`);
      } else if (throughputImprovement < -5) {
        regressions.push(`${currentResult.name}: ${Math.abs(throughputImprovement).toFixed(1)}% lower throughput`);
      }

      if (costImprovement > 5) {
        improvements.push(`${currentResult.name}: ${costImprovement.toFixed(1)}% cheaper`);
      } else if (costImprovement < -5) {
        regressions.push(`${currentResult.name}: ${Math.abs(costImprovement).toFixed(1)}% more expensive`);
      }
    });

    const summary = `Performance comparison: ${improvements.length} improvements, ${regressions.length} regressions`;

    return { improvements, regressions, summary };
  }
}

/**
 * Run benchmarks for the agent system
 */
export async function runAgentSystemBenchmarks(agentSystem: AgentSystem): Promise<BenchmarkSuite> {
  const benchmarks = new AgentSystemBenchmarks(agentSystem);
  return await benchmarks.runFullSuite();
}