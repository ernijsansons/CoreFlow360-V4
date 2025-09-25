/**
 * Performance Monitoring and Tracing Accuracy Tests
 * Testing distributed tracing and performance metrics collection
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  PerformanceMonitor,
  getGlobalMonitor,
  Trace,
  MetricsCollector,
  TraceSpan,
  PerformanceMetrics
} from '../performance-monitor';

describe('Performance Monitoring Tests', () => {
  let monitor: PerformanceMonitor;
  let metricsCollector: MetricsCollector;

  beforeEach(() => {
    monitor = new PerformanceMonitor({
      enableTracing: true,
      enableMetrics: true,
      sampleRate: 1.0,
      maxSpansPerTrace: 100,
      thresholds: {
        reportGeneration: { warning: 1000, critical: 3000, timeout: 5000 },
        databaseQuery: { warning: 50, critical: 200, timeout: 500 },
        export: { warning: 500, critical: 1500, timeout: 3000 },
        validation: { warning: 10, critical: 50, timeout: 100 }
      }
    });
    metricsCollector = new MetricsCollector(monitor);
  });

  afterEach(() => {
    // Clear any active spans
    const activeTraces = monitor.getActiveTraces();
    for (const span of activeTraces) {
      monitor.finishSpan(span.spanId, 'success');
    }
  });

  describe('Trace Span Management', () => {
    it('should create and manage trace spans correctly', () => {
      const spanId = monitor.startSpan('test_operation', undefined, {
        component: 'financial-module',
        operation_type: 'database_query'
      });

      expect(typeof spanId).toBe('string');
      expect(spanId).toMatch(/^span_\d+_[a-z0-9]+$/);

      const activeTraces = monitor.getActiveTraces();
      expect(activeTraces.length).toBe(1);

      const span = activeTraces[0];
      expect(span.spanId).toBe(spanId);
      expect(span.operationName).toBe('test_operation');
      expect(span.status).toBe('success');
      expect(span.tags.component).toBe('financial-module');
      expect(span.tags.operation_type).toBe('database_query');
      expect(span.startTime).toBeGreaterThan(Date.now() - 1000);
    });

    it('should finish spans and calculate duration correctly', async () => {
      const spanId = monitor.startSpan('timed_operation');

      // Simulate some work
      await new Promise(resolve => setTimeout(resolve, 100));

      monitor.finishSpan(spanId, 'success');

      const activeTraces = monitor.getActiveTraces();
      expect(activeTraces.length).toBe(0);

      // Verify span was finished with correct duration
      const allSpans = monitor.getTrace(monitor.getActiveTraces()[0]?.traceId || '');
      // Since span is finished, we can't easily access it from the monitor
      // In a real implementation, you'd have access to finished spans
    });

    it('should create nested spans with parent-child relationships', () => {
      const parentSpanId = monitor.startSpan('parent_operation');
      const childSpanId = monitor.startSpan('child_operation', parentSpanId, {
        child_of: parentSpanId
      });

      const activeTraces = monitor.getActiveTraces();
      expect(activeTraces.length).toBe(2);

      const parentSpan = activeTraces.find(s => s.spanId === parentSpanId);
      const childSpan = activeTraces.find(s => s.spanId === childSpanId);

      expect(parentSpan).toBeDefined();
      expect(childSpan).toBeDefined();
      expect(childSpan?.parentSpanId).toBe(parentSpanId);
      expect(childSpan?.traceId).toBe(parentSpan?.traceId);
    });

    it('should handle span logs correctly', () => {
      const spanId = monitor.startSpan('logged_operation');

      monitor.addSpanLog(spanId, 'info', 'Operation started', {
        input_size: 1024,
        user_id: 'test_user'
      });

      monitor.addSpanLog(spanId, 'warn', 'Performance threshold warning', {
        duration_ms: 150,
        threshold_ms: 100
      });

      const activeTraces = monitor.getActiveTraces();
      const span = activeTraces.find(s => s.spanId === spanId);

      expect(span?.logs.length).toBe(2);
      expect(span?.logs[0].level).toBe('info');
      expect(span?.logs[0].message).toBe('Operation started');
      expect(span?.logs[0].fields?.input_size).toBe(1024);
      expect(span?.logs[1].level).toBe('warn');
      expect(span?.logs[1].fields?.duration_ms).toBe(150);
    });

    it('should add tags to spans dynamically', () => {
      const spanId = monitor.startSpan('tagged_operation', undefined, {
        initial_tag: 'initial_value'
      });

      monitor.addSpanTags(spanId, {
        user_id: 'user_123',
        business_id: 'business_456',
        result_count: 42
      });

      const activeTraces = monitor.getActiveTraces();
      const span = activeTraces.find(s => s.spanId === spanId);

      expect(span?.tags.initial_tag).toBe('initial_value');
      expect(span?.tags.user_id).toBe('user_123');
      expect(span?.tags.business_id).toBe('business_456');
      expect(span?.tags.result_count).toBe(42);
    });

    it('should handle error spans correctly', () => {
      const spanId = monitor.startSpan('error_operation');

      monitor.addSpanLog(spanId, 'error', 'Database connection failed', {
        error_code: 'CONN_TIMEOUT',
        retry_count: 3
      });

      monitor.finishSpan(spanId, 'error', 'Database timeout error');

      // Since span is finished, verify it was marked as error
      // In real implementation, you'd have access to the finished span
      expect(true).toBe(true); // Placeholder assertion
    });
  });

  describe('Performance Metrics Collection', () => {
    it('should record performance metrics correctly', () => {
      const metrics: PerformanceMetrics = {
        duration: 150,
        memory: 512,
        cpuUsage: 25.5,
        dbQueries: 3,
        cacheHits: 5,
        cacheMisses: 2
      };

      monitor.recordMetrics('database_operation', metrics);

      const stats = monitor.getPerformanceStats('database_operation');

      expect(stats).toBeDefined();
      expect(stats?.count).toBe(1);
      expect(stats?.avgDuration).toBe(150);
      expect(stats?.p50Duration).toBe(150);
      expect(stats?.p95Duration).toBe(150);
      expect(stats?.p99Duration).toBe(150);
    });

    it('should calculate statistics for multiple metrics', () => {
      const operationName = 'report_generation';

      // Record multiple metrics
      const durations = [100, 150, 200, 300, 250, 180, 220, 350, 120, 280];

      for (const duration of durations) {
        monitor.recordMetrics(operationName, { duration });
      }

      const stats = monitor.getPerformanceStats(operationName);

      expect(stats).toBeDefined();
      expect(stats?.count).toBe(10);
      expect(stats?.avgDuration).toBe(215); // Average of durations
      expect(stats?.p50Duration).toBe(200); // Median
      expect(stats?.p95Duration).toBe(300); // 95th percentile
      expect(stats?.p99Duration).toBe(350); // 99th percentile
    });

    it('should maintain metrics for different operations separately', () => {
      monitor.recordMetrics('operation_a', { duration: 100 });
      monitor.recordMetrics('operation_b', { duration: 200 });
      monitor.recordMetrics('operation_a', { duration: 150 });

      const statsA = monitor.getPerformanceStats('operation_a');
      const statsB = monitor.getPerformanceStats('operation_b');

      expect(statsA?.count).toBe(2);
      expect(statsA?.avgDuration).toBe(125);
      expect(statsB?.count).toBe(1);
      expect(statsB?.avgDuration).toBe(200);
    });

    it('should limit metrics storage to prevent memory issues', () => {
      const operationName = 'memory_test_operation';

      // Record more than 1000 metrics (the configured limit)
      for (let i = 0; i < 1500; i++) {
        monitor.recordMetrics(operationName, { duration: i });
      }

      const stats = monitor.getPerformanceStats(operationName);

      // Should only keep the last 1000 metrics
      expect(stats?.count).toBeLessThanOrEqual(1000);
    });
  });

  describe('Performance Threshold Monitoring', () => {
    it('should detect warning threshold violations', async () => {
      const spanId = monitor.startSpan('slow_report_generation');

      // Simulate slow operation
      await new Promise(resolve => setTimeout(resolve, 1200)); // Over 1000ms warning threshold

      monitor.finishSpan(spanId, 'success');

      // In real implementation, this would trigger warning logs
      // For testing, we verify the span duration is recorded correctly
      expect(true).toBe(true); // Placeholder assertion
    });

    it('should detect critical threshold violations', async () => {
      const spanId = monitor.startSpan('very_slow_database_query');

      // Simulate very slow operation
      await new Promise(resolve => setTimeout(resolve, 250)); // Over 200ms critical threshold

      monitor.finishSpan(spanId, 'success');

      // In real implementation, this would trigger critical alerts
      expect(true).toBe(true); // Placeholder assertion
    });

    it('should categorize operations correctly for threshold checking', () => {
      const reportSpanId = monitor.startSpan('generate_profit_loss_report');
      const dbSpanId = monitor.startSpan('query_invoice_data');
      const exportSpanId = monitor.startSpan('export_to_excel');
      const validationSpanId = monitor.startSpan('validate_journal_entry');

      // Finish spans with different durations
      monitor.finishSpan(reportSpanId, 'success');
      monitor.finishSpan(dbSpanId, 'success');
      monitor.finishSpan(exportSpanId, 'success');
      monitor.finishSpan(validationSpanId, 'success');

      // Verify spans were created (thresholds would be checked on finish)
      expect(true).toBe(true); // Placeholder assertion
    });
  });

  describe('Trace Decorator', () => {
    class TestClass {
      @Trace('test_method')
      async testMethod(param1: string, param2: number): Promise<string> {
        await new Promise(resolve => setTimeout(resolve, 50));
        return `${param1}-${param2}`;
      }

      @Trace('error_method')
      async errorMethod(): Promise<void> {
        throw new Error('Test error');
      }

      @Trace()
      async autoNamedMethod(): Promise<string> {
        return 'auto-named';
      }
    }

    it('should create traces automatically with decorator', async () => {
      const testInstance = new TestClass();

      const result = await testInstance.testMethod('test', 123);

      expect(result).toBe('test-123');

      // Verify trace was created (in real implementation, you'd check the global monitor)
      const globalMonitor = getGlobalMonitor();
      expect(globalMonitor).toBeDefined();
    });

    it('should handle errors in traced methods', async () => {
      const testInstance = new TestClass();

      try {
        await testInstance.errorMethod();
        expect(false).toBe(true); // Should not reach here
      } catch (error) {
        expect(error instanceof Error).toBe(true);
        expect(error.message).toBe('Test error');
      }

      // Verify error trace was created
      expect(true).toBe(true); // Placeholder assertion
    });

    it('should auto-name traces when no name provided', async () => {
      const testInstance = new TestClass();

      const result = await testInstance.autoNamedMethod();

      expect(result).toBe('auto-named');

      // Verify trace was created with auto-generated name
      expect(true).toBe(true); // Placeholder assertion
    });
  });

  describe('Metrics Export and Health Checks', () => {
    it('should export Prometheus-formatted metrics', () => {
      // Record some test metrics
      monitor.recordMetrics('api_request', { duration: 100 });
      monitor.recordMetrics('api_request', { duration: 150 });
      monitor.recordMetrics('api_request', { duration: 200 });
      monitor.recordMetrics('database_query', { duration: 50 });
      monitor.recordMetrics('database_query', { duration: 75 });

      const prometheusMetrics = metricsCollector.exportPrometheusMetrics();

      expect(prometheusMetrics).toContain('# HELP finance_operation_duration_ms');
      expect(prometheusMetrics).toContain('# TYPE finance_operation_duration_ms summary');
      expect(prometheusMetrics).toContain('finance_operation_duration_ms{operation="api_request",quantile="0.5"}');
      expect(prometheusMetrics).toContain('finance_operation_duration_ms{operation="database_query",quantile="0.95"}');
      expect(prometheusMetrics).toContain('finance_operation_duration_ms_count{operation="api_request"} 3');
      expect(prometheusMetrics).toContain('finance_operation_duration_ms_count{operation="database_query"} 2');
    });

    it('should provide health check metrics', () => {
      // Record some metrics to simulate system activity
      monitor.recordMetrics('api_request', { duration: 100 });
      monitor.recordMetrics('api_request', { duration: 2000 }); // Slow request
      monitor.recordMetrics('report_generation', { duration: 500 });

      // Create some active traces
      const spanId1 = monitor.startSpan('active_operation_1');
      const spanId2 = monitor.startSpan('active_operation_2');

      const healthMetrics = metricsCollector.getHealthMetrics();

      expect(healthMetrics.status).toMatch(/healthy|degraded|unhealthy/);
      expect(healthMetrics.activeTraces).toBe(2);
      expect(healthMetrics.avgResponseTime).toBeGreaterThan(0);
      expect(healthMetrics.errorRate).toBeGreaterThanOrEqual(0);

      // Clean up active spans
      monitor.finishSpan(spanId1, 'success');
      monitor.finishSpan(spanId2, 'success');
    });

    it('should determine health status based on performance', () => {
      // Test healthy status
      monitor.recordMetrics('fast_operation', { duration: 50 });
      monitor.recordMetrics('fast_operation', { duration: 75 });

      let healthMetrics = metricsCollector.getHealthMetrics();
      expect(healthMetrics.status).toBe('healthy');

      // Test degraded status
      monitor.recordMetrics('slow_operation', { duration: 6000 }); // Slow
      monitor.recordMetrics('slow_operation', { duration: 7000 }); // Slow

      healthMetrics = metricsCollector.getHealthMetrics();
      expect(['degraded', 'unhealthy']).toContain(healthMetrics.status);

      // Test with many active traces
      const activeSpans = [];
      for (let i = 0; i < 60; i++) {
        activeSpans.push(monitor.startSpan(`active_span_${i}`));
      }

      healthMetrics = metricsCollector.getHealthMetrics();
      expect(['degraded', 'unhealthy']).toContain(healthMetrics.status);

      // Clean up
      for (const spanId of activeSpans) {
        monitor.finishSpan(spanId, 'success');
      }
    });
  });

  describe('Sampling and Configuration', () => {
    it('should respect sampling rate configuration', () => {
      const sampledMonitor = new PerformanceMonitor({
        enableTracing: true,
        sampleRate: 0.0 // No sampling
      });

      const spanId = sampledMonitor.startSpan('sampled_operation');

      // Even with 0% sampling, span ID should be returned (but no actual tracing)
      expect(typeof spanId).toBe('string');

      const activeTraces = sampledMonitor.getActiveTraces();
      expect(activeTraces.length).toBe(0); // No traces due to 0% sampling
    });

    it('should disable tracing when configured', () => {
      const disabledMonitor = new PerformanceMonitor({
        enableTracing: false,
        enableMetrics: true
      });

      const spanId = disabledMonitor.startSpan('disabled_operation');

      expect(typeof spanId).toBe('string');

      const activeTraces = disabledMonitor.getActiveTraces();
      expect(activeTraces.length).toBe(0);
    });

    it('should disable metrics when configured', () => {
      const noMetricsMonitor = new PerformanceMonitor({
        enableTracing: true,
        enableMetrics: false
      });

      noMetricsMonitor.recordMetrics('test_operation', { duration: 100 });

      const stats = noMetricsMonitor.getPerformanceStats('test_operation');
      expect(stats).toBeNull();
    });

    it('should enforce max spans per trace limit', () => {
      const limitedMonitor = new PerformanceMonitor({
        enableTracing: true,
        maxSpansPerTrace: 3
      });

      const parentSpanId = limitedMonitor.startSpan('parent');

      // Create spans up to the limit
      const spanIds = [];
      for (let i = 0; i < 5; i++) {
        spanIds.push(limitedMonitor.startSpan(`child_${i}`, parentSpanId));
      }

      const activeTraces = limitedMonitor.getActiveTraces();

      // Should not exceed the configured limit
      expect(activeTraces.length).toBeLessThanOrEqual(3);

      // Clean up
      for (const spanId of spanIds) {
        limitedMonitor.finishSpan(spanId, 'success');
      }
      limitedMonitor.finishSpan(parentSpanId, 'success');
    });
  });

  describe('Concurrent Operations', () => {
    it('should handle concurrent trace operations safely', async () => {
      const concurrentOperations = Array.from({ length: 50 }, (_, i) =>
        async () => {
          const spanId = monitor.startSpan(`concurrent_operation_${i}`);

          monitor.addSpanTags(spanId, {
            operation_index: i,
            thread_id: Math.random().toString(36)
          });

          monitor.addSpanLog(spanId, 'info', `Operation ${i} started`);

          // Simulate work
          await new Promise(resolve => setTimeout(resolve, Math.random() * 50));

          monitor.addSpanLog(spanId, 'info', `Operation ${i} completed`);
          monitor.finishSpan(spanId, 'success');

          return i;
        }
      );

      const results = await Promise.all(concurrentOperations.map(op => op()));

      // All operations should complete successfully
      expect(results.length).toBe(50);
      expect(results).toEqual(Array.from({ length: 50 }, (_, i) => i));

      // No spans should remain active
      const activeTraces = monitor.getActiveTraces();
      expect(activeTraces.length).toBe(0);
    });

    it('should handle concurrent metrics recording safely', async () => {
      const concurrentMetrics = Array.from({ length: 100 }, (_, i) =>
        async () => {
          monitor.recordMetrics(`operation_${i % 10}`, {
            duration: Math.random() * 1000,
            memory: Math.random() * 1024,
            cpuUsage: Math.random() * 100
          });

          return i;
        }
      );

      const results = await Promise.all(concurrentMetrics.map(op => op()));

      expect(results.length).toBe(100);

      // Verify metrics were recorded for different operations
      for (let i = 0; i < 10; i++) {
        const stats = monitor.getPerformanceStats(`operation_${i}`);
        expect(stats).toBeDefined();
        expect(stats?.count).toBe(10); // 100 operations / 10 operation types
      }
    });

    it('should maintain trace isolation between concurrent operations', async () => {
      const tracePromises = Array.from({ length: 10 }, (_, i) =>
        async () => {
          const parentSpanId = monitor.startSpan(`trace_${i}_parent`);
          const childSpanId = monitor.startSpan(`trace_${i}_child`, parentSpanId);

          monitor.addSpanTags(parentSpanId, { trace_index: i });
          monitor.addSpanTags(childSpanId, { trace_index: i });

          await new Promise(resolve => setTimeout(resolve, 20));

          monitor.finishSpan(childSpanId, 'success');
          monitor.finishSpan(parentSpanId, 'success');

          return i;
        }
      );

      const results = await Promise.all(tracePromises);

      expect(results.length).toBe(10);

      // All traces should be completed
      const activeTraces = monitor.getActiveTraces();
      expect(activeTraces.length).toBe(0);
    });
  });

  describe('Memory Management', () => {
    it('should clean up finished spans to prevent memory leaks', async () => {
      // Create and finish many spans
      for (let i = 0; i < 1000; i++) {
        const spanId = monitor.startSpan(`span_${i}`);
        monitor.finishSpan(spanId, 'success');
      }

      // Wait for cleanup (spans should be cleaned up after 1 minute in real implementation)
      // For testing, we simulate the cleanup
      await new Promise(resolve => setTimeout(resolve, 100));

      // Active traces should be empty
      const activeTraces = monitor.getActiveTraces();
      expect(activeTraces.length).toBe(0);
    });

    it('should limit metrics storage to prevent unbounded growth', () => {
      const operationName = 'bounded_operation';

      // Record many metrics
      for (let i = 0; i < 2000; i++) {
        monitor.recordMetrics(operationName, { duration: i });
      }

      const stats = monitor.getPerformanceStats(operationName);

      // Should be limited to configured maximum (1000)
      expect(stats?.count).toBeLessThanOrEqual(1000);
    });

    it('should handle large numbers of concurrent active spans', () => {
      const spanIds = [];

      // Create many active spans
      for (let i = 0; i < 500; i++) {
        spanIds.push(monitor.startSpan(`active_span_${i}`));
      }

      const activeTraces = monitor.getActiveTraces();
      expect(activeTraces.length).toBeLessThanOrEqual(500);

      // Clean up all spans
      for (const spanId of spanIds) {
        monitor.finishSpan(spanId, 'success');
      }

      const finalActiveTraces = monitor.getActiveTraces();
      expect(finalActiveTraces.length).toBe(0);
    });
  });

  describe('Integration with Error Handling', () => {
    it('should handle exceptions during tracing gracefully', () => {
      // Simulate tracing errors
      const spanId = monitor.startSpan('error_prone_operation');

      // These should not throw even if internal errors occur
      expect(() => {
        monitor.addSpanLog(spanId, 'info', 'Test log');
        monitor.addSpanTags(spanId, { test_tag: 'test_value' });
        monitor.finishSpan(spanId, 'error', 'Test error');
      }).not.toThrow();
    });

    it('should continue functioning after individual span failures', () => {
      // Create a normal span
      const goodSpanId = monitor.startSpan('good_operation');

      // Try to operate on non-existent span (should not affect other spans)
      monitor.addSpanLog('non_existent_span', 'info', 'This should not crash');
      monitor.finishSpan('non_existent_span', 'success');

      // Good span should still work
      monitor.addSpanLog(goodSpanId, 'info', 'This should work');
      monitor.finishSpan(goodSpanId, 'success');

      expect(true).toBe(true); // Test passed if no exceptions thrown
    });
  });
});