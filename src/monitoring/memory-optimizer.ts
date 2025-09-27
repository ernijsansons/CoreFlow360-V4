export interface MemoryMetrics {
  heapUsed: number;
  heapTotal: number;
  external: number;
  arrayBuffers: number;
  timestamp: number;
}

export class MemoryOptimizer {
  private metricsHistory: MemoryMetrics[] = [];
  private readonly maxHistorySize = 100;
  private gcThreshold: number = 0.85; // Trigger GC at 85% memory usage

  constructor(private readonly env: any) {}

  public recordMetrics(metrics: MemoryMetrics): void {
    this.metricsHistory.push(metrics);
    if (this.metricsHistory.length > this.maxHistorySize) {
      this.metricsHistory.shift();
    }
  }

  public getMemoryUsage(): MemoryMetrics {
    // In Cloudflare Workers environment, we have limited memory access
    // This is a placeholder implementation
    return {
      heapUsed: 0,
      heapTotal: 128 * 1024 * 1024, // 128MB Workers limit
      external: 0,
      arrayBuffers: 0,
      timestamp: Date.now(),
    };
  }

  public async optimize(): Promise<void> {
    const metrics = this.getMemoryUsage();
    this.recordMetrics(metrics);

    const usageRatio = metrics.heapUsed / metrics.heapTotal;
    if (usageRatio > this.gcThreshold) {
      // In Workers environment, we can't force GC
      // Instead, we can clear caches or reduce memory usage
      await this.clearCaches();
    }
  }

  private async clearCaches(): Promise<void> {
    // Clear any in-memory caches
    // This is environment-specific
    console.log('Memory optimization: Clearing caches');
  }

  public getMetricsHistory(): MemoryMetrics[] {
    return [...this.metricsHistory];
  }

  public getAverageMemoryUsage(): number {
    if (this.metricsHistory.length === 0) return 0;

    const total = this.metricsHistory.reduce(
      (sum, m) => sum + (m.heapUsed / m.heapTotal),
      0
    );
    return total / this.metricsHistory.length;
  }

  public registerCleanupCallback(callback: () => Promise<void>): void {
    // Store cleanup callbacks for later execution
    if (!this.cleanupCallbacks) {
      this.cleanupCallbacks = [];
    }
    this.cleanupCallbacks.push(callback);
  }

  private cleanupCallbacks?: (() => Promise<void>)[];
}