import { Metric, GoldenSignals, BusinessMetric, AIMetric, InfrastructureMetric } from '../../types/telemetry';
import { TelemetryCollector } from './collector';

interface MetricOptions {
  tags?: Record<string, string>;
  timestamp?: number;
}

interface HistogramBucket {
  le: number;
  count: number;
}

interface Histogram {
  buckets: HistogramBucket[];
  count: number;
  sum: number;
}

interface Summary {
  count: number;
  sum: number;
  quantiles: Record<string, number>;
}

export class MetricsCollector {
  private collector: TelemetryCollector;
  private counters: Map<string, number> = new Map();
  private gauges: Map<string, number> = new Map();
  private histograms: Map<string, Histogram> = new Map();
  private summaries: Map<string, Summary> = new Map();
  private defaultTags: Record<string, string> = {};

  constructor(collector: TelemetryCollector, defaultTags: Record<string, string> = {}) {
    this.collector = collector;
    this.defaultTags = defaultTags;
  }

  counter(name: string, value: number = 1, options: MetricOptions = {}): void {
    const key = this.getMetricKey(name, options.tags);
    const currentValue = this.counters.get(key) || 0;
    this.counters.set(key, currentValue + value);

    this.recordMetric({
      name,
      value: currentValue + value,
      timestamp: options.timestamp || Date.now(),
      tags: { ...this.defaultTags, ...options.tags },
      type: 'counter'
    });
  }

  gauge(name: string, value: number, options: MetricOptions = {}): void {
    const key = this.getMetricKey(name, options.tags);
    this.gauges.set(key, value);

    this.recordMetric({
      name,
      value,
      timestamp: options.timestamp || Date.now(),
      tags: { ...this.defaultTags, ...options.tags },
      type: 'gauge'
    });
  }

  histogram(name: string, value: number, options: MetricOptions = {}): void {
    const key = this.getMetricKey(name, options.tags);
    let hist = this.histograms.get(key);

    if (!hist) {
      hist = {
        buckets: [
          { le: 0.001, count: 0 }, // 1ms
          { le: 0.005, count: 0 }, // 5ms
          { le: 0.01, count: 0 },  // 10ms
          { le: 0.025, count: 0 }, // 25ms
          { le: 0.05, count: 0 },  // 50ms
          { le: 0.1, count: 0 },   // 100ms
          { le: 0.25, count: 0 },  // 250ms
          { le: 0.5, count: 0 },   // 500ms
          { le: 1.0, count: 0 },   // 1s
          { le: 2.5, count: 0 },   // 2.5s
          { le: 5.0, count: 0 },   // 5s
          { le: 10.0, count: 0 },  // 10s
          { le: Infinity, count: 0 }
        ],
        count: 0,
        sum: 0
      };
      this.histograms.set(key, hist);
    }

    hist.count++;
    hist.sum += value;

    for (const bucket of hist.buckets) {
      if (value <= bucket.le) {
        bucket.count++;
      }
    }

    this.recordMetric({
      name,
      value,
      timestamp: options.timestamp || Date.now(),
      tags: { ...this.defaultTags, ...options.tags },
      type: 'histogram'
    });
  }

  summary(name: string, value: number, options: MetricOptions = {}): void {
    const key = this.getMetricKey(name, options.tags);
    let summary = this.summaries.get(key);

    if (!summary) {
      summary = {
        count: 0,
        sum: 0,
        quantiles: {}
      };
      this.summaries.set(key, summary);
    }

    summary.count++;
    summary.sum += value;

    this.recordMetric({
      name,
      value,
      timestamp: options.timestamp || Date.now(),
      tags: { ...this.defaultTags, ...options.tags },
      type: 'summary'
    });
  }

  timing(name: string, duration: number, options: MetricOptions = {}): void {
    this.histogram(`${name}_duration_seconds`, duration / 1000, options);
    this.counter(`${name}_total`, 1, options);
  }

  increment(name: string, options: MetricOptions = {}): void {
    this.counter(name, 1, options);
  }

  decrement(name: string, options: MetricOptions = {}): void {
    this.counter(name, -1, options);
  }

  set(name: string, value: number, options: MetricOptions = {}): void {
    this.gauge(name, value, options);
  }

  private recordMetric(metric: Metric): void {
    this.collector.collectMetric(metric);
  }

  private getMetricKey(name: string, tags?: Record<string, string>): string {
    const allTags = { ...this.defaultTags, ...tags };
    const tagString = Object.entries(allTags)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join(',');
    return `${name}{${tagString}}`;
  }

  // Golden Signals Implementation
  recordRequest(latencyMs: number, statusCode: number, tags: Record<string, string> = {}): void {
    this.timing('http_request', latencyMs, tags);
    this.counter('http_requests_total', 1, { ...tags, status: statusCode.toString() });

    if (statusCode >= 400) {
      this.counter('http_errors_total', 1, tags);
    }
  }

  recordTraffic(requestsPerSecond: number, bytesPerSecond: number, tags: Record<string, string> = {}): void {
    this.gauge('http_requests_per_second', requestsPerSecond, tags);
    this.gauge('http_bytes_per_second', bytesPerSecond, tags);
  }

  recordSaturation(cpuPercent: number, memoryPercent: number, diskPercent:
  number, tags: Record<string, string> = {}): void {
    this.gauge('system_cpu_usage_percent', cpuPercent, tags);
    this.gauge('system_memory_usage_percent', memoryPercent, tags);
    this.gauge('system_disk_usage_percent', diskPercent, tags);
  }

  // Business Metrics
  recordRevenue(amount: number, currency: string = 'USD', tags: Record<string, string> = {}): void {
    this.counter('business_revenue_total', amount, { ...tags, currency });
  }

  recordActiveUsers(count: number, tags: Record<string, string> = {}): void {
    this.gauge('business_active_users', count, tags);
  }

  recordFeatureUsage(feature: string, usage: number, tags: Record<string, string> = {}): void {
    this.counter('business_feature_usage_total', usage, { ...tags, feature });
  }

  recordConversion(action: string, tags: Record<string, string> = {}): void {
    this.counter('business_conversions_total', 1, { ...tags, action });
  }

  recordChurn(tags: Record<string, string> = {}): void {
    this.counter('business_churn_total', 1, tags);
  }

  recordSatisfaction(score: number, tags: Record<string, string> = {}): void {
    this.gauge('business_satisfaction_score', score, tags);
  }

  // AI Metrics
  recordAIRequest(
    tokens: { prompt: number; completion: number },
    costCents: number,
    latencyMs: number,
    model: string,
    provider: string,
    tags: Record<string, string> = {}
  ): void {
    const aiTags = { ...tags, model, provider };

    this.counter('ai_tokens_total', tokens.prompt + tokens.completion, aiTags);
    this.counter('ai_prompt_tokens_total', tokens.prompt, aiTags);
    this.counter('ai_completion_tokens_total', tokens.completion, aiTags);
    this.counter('ai_cost_cents_total', costCents, aiTags);
    this.timing('ai_request', latencyMs, aiTags);
    this.counter('ai_requests_total', 1, aiTags);
  }

  recordAIError(error: string, model: string, provider: string, tags: Record<string, string> = {}): void {
    this.counter('ai_errors_total', 1, { ...tags, error, model, provider });
  }

  // Infrastructure Metrics
  recordInfrastructure(metrics: InfrastructureMetric, tags: Record<string, string> = {}): void {
    this.gauge('infra_cpu_usage_percent', metrics.cpuUsagePercent, tags);
    this.gauge('infra_memory_usage_percent', metrics.memoryUsagePercent, tags);
    this.gauge('infra_disk_usage_percent', metrics.diskUsagePercent, tags);
    this.gauge('infra_network_in_bytes', metrics.networkInBytes, tags);
    this.gauge('infra_network_out_bytes', metrics.networkOutBytes, tags);
    this.gauge('infra_active_connections', metrics.activeConnections, tags);
    this.gauge('infra_requests_per_second', metrics.requestsPerSecond, tags);
  }

  // Aggregated Metrics Calculation
  calculateGoldenSignals(timeRangeMs: number): GoldenSignals {
    const now = Date.now();
    const startTime = now - timeRangeMs;

    // This would typically query the time-series database
    // For now, returning estimated values based on current counters

    const totalRequests = Array.from(this.counters.entries())
      .filter(([key]) => key.includes('http_requests_total'))
      .reduce((sum, [, value]) => sum + value, 0);

    const totalErrors = Array.from(this.counters.entries())
      .filter(([key]) => key.includes('http_errors_total'))
      .reduce((sum, [, value]) => sum + value, 0);

    const latencyHistogram = this.histograms.get('http_request_duration_seconds{}');

    return {
      latency: {
        p50: this.calculatePercentile(latencyHistogram, 0.5) * 1000,
        p95: this.calculatePercentile(latencyHistogram, 0.95) * 1000,
        p99: this.calculatePercentile(latencyHistogram, 0.99) * 1000,
        p999: this.calculatePercentile(latencyHistogram, 0.999) * 1000
      },
      traffic: {
        requestsPerSecond: totalRequests / (timeRangeMs / 1000),
        bytesPerSecond: 0 // Would need to track bytes
      },
      errors: {
        errorRate: totalRequests > 0 ? totalErrors / totalRequests : 0,
        errorCount: totalErrors
      },
      saturation: {
        cpuUsage: this.gauges.get('system_cpu_usage_percent{}') || 0,
        memoryUsage: this.gauges.get('system_memory_usage_percent{}') || 0,
        diskUsage: this.gauges.get('system_disk_usage_percent{}') || 0
      }
    };
  }

  private calculatePercentile(histogram: Histogram | undefined, percentile: number): number {
    if (!histogram || histogram.count === 0) return 0;

    const targetCount = histogram.count * percentile;
    let currentCount = 0;

    for (const bucket of histogram.buckets) {
      currentCount += bucket.count;
      if (currentCount >= targetCount) {
        return bucket.le === Infinity ? bucket.le : bucket.le;
      }
    }

    return 0;
  }

  // Export metrics in Prometheus format
  exportPrometheus(): string {
    const lines: string[] = [];

    // Counters
    for (const [key, value] of this.counters) {
      const { name, tags } = this.parseMetricKey(key);
      const tagString = Object.entries(tags)
        .map(([k, v]) => `${k}="${v}"`)
        .join(',');
      lines.push(`# TYPE ${name} counter`);
      lines.push(`${name}{${tagString}} ${value}`);
    }

    // Gauges
    for (const [key, value] of this.gauges) {
      const { name, tags } = this.parseMetricKey(key);
      const tagString = Object.entries(tags)
        .map(([k, v]) => `${k}="${v}"`)
        .join(',');
      lines.push(`# TYPE ${name} gauge`);
      lines.push(`${name}{${tagString}} ${value}`);
    }

    // Histograms
    for (const [key, histogram] of this.histograms) {
      const { name, tags } = this.parseMetricKey(key);
      const tagString = Object.entries(tags)
        .map(([k, v]) => `${k}="${v}"`)
        .join(',');

      lines.push(`# TYPE ${name} histogram`);

      for (const bucket of histogram.buckets) {
        const bucketTags = { ...tags, le: bucket.le.toString() };
        const bucketTagString = Object.entries(bucketTags)
          .map(([k, v]) => `${k}="${v}"`)
          .join(',');
        lines.push(`${name}_bucket{${bucketTagString}} ${bucket.count}`);
      }

      lines.push(`${name}_count{${tagString}} ${histogram.count}`);
      lines.push(`${name}_sum{${tagString}} ${histogram.sum}`);
    }

    return lines.join('\n');
  }

  private parseMetricKey(key: string): { name: string; tags: Record<string, string> } {
    const bracketIndex = key.indexOf('{');
    if (bracketIndex === -1) {
      return { name: key, tags: {} };
    }

    const name = key.substring(0, bracketIndex);
    const tagString = key.substring(bracketIndex + 1, key.length - 1);

    const tags: Record<string, string> = {};
    if (tagString) {
      tagString.split(',').forEach(pair => {
        const [key, value] = pair.split('=');
        if (key && value) {
          tags[key] = value;
        }
      });
    }

    return { name, tags };
  }

  // Reset all metrics (useful for testing)
  reset(): void {
    this.counters.clear();
    this.gauges.clear();
    this.histograms.clear();
    this.summaries.clear();
  }

  // Get current metric values
  getMetrics(): any {
    return {
      counters: Object.fromEntries(this.counters),
      gauges: Object.fromEntries(this.gauges),
      histograms: Object.fromEntries(
        Array.from(this.histograms.entries()).map(([k, v]) => [k, {
          count: v.count,
          sum: v.sum,
          buckets: v.buckets.map(b => ({ le: b.le, count: b.count }))
        }])
      ),
      summaries: Object.fromEntries(this.summaries)
    };
  }
}

// Middleware for automatic HTTP metrics collection
export function metricsMiddleware(metrics: MetricsCollector) {
  return async (request: Request, env: any, ctx: any, next: () => Promise<Response>): Promise<Response> => {
    const startTime = Date.now();
    const path = new URL(request.url).pathname;

    try {
      const response = await next();
      const latency = Date.now() - startTime;

      metrics.recordRequest(latency, response.status, {
        method: request.method,
        path,
        status: response.status.toString()
      });

      return response;
    } catch (error) {
      const latency = Date.now() - startTime;
      metrics.recordRequest(latency, 500, {
        method: request.method,
        path,
        status: '500'
      });
      throw error;
    }
  };
}

// Decorator for function timing
export function timed(name: string, metrics: MetricsCollector) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const startTime = Date.now();
      try {
        const result = await originalMethod.apply(this, args);
        const duration = Date.now() - startTime;
        metrics.timing(name, duration, { method: propertyKey });
        return result;
      } catch (error) {
        const duration = Date.now() - startTime;
        metrics.timing(name, duration, { method: propertyKey, error: 'true' });
        throw error;
      }
    };

    return descriptor;
  };
}