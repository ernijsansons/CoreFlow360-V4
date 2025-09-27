import { Env } from '../types/env';

export interface RateLimitMetrics {
  identifier: string;
  requestCount: number;
  blockedCount: number;
  allowedCount: number;
  timestamp: number;
  window: number;
}

export interface RateLimitAlert {
  type: 'threshold' | 'spike' | 'anomaly';
  identifier: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: number;
  metrics: RateLimitMetrics;
}

export class RateLimitMonitor {
  private readonly kvNamespace: KVNamespace;
  private readonly metricsPrefix = 'metrics:ratelimit:';
  private readonly alertsPrefix = 'alerts:ratelimit:';
  private alerts: RateLimitAlert[] = [];

  constructor(private readonly env: Env) {
    this.kvNamespace = env.KV_RATE_LIMIT_METRICS || env.KV_AUTH;
  }

  async recordRequest(
    identifier: string,
    allowed: boolean,
    window: number = 60000
  ): Promise<void> {
    const key = `${this.metricsPrefix}${identifier}`;
    const metrics = await this.getMetrics(key) || this.createEmptyMetrics(identifier, window);

    metrics.requestCount++;
    if (allowed) {
      metrics.allowedCount++;
    } else {
      metrics.blockedCount++;
    }

    await this.saveMetrics(key, metrics);
    await this.checkThresholds(metrics);
  }

  private async getMetrics(key: string): Promise<RateLimitMetrics | null> {
    const data = await this.kvNamespace.get(key);
    if (!data) return null;

    const metrics = JSON.parse(data) as RateLimitMetrics;
    const now = Date.now();

    // Check if metrics are from current window
    if (now - metrics.timestamp > metrics.window) {
      return null;
    }

    return metrics;
  }

  private createEmptyMetrics(identifier: string, window: number): RateLimitMetrics {
    return {
      identifier,
      requestCount: 0,
      blockedCount: 0,
      allowedCount: 0,
      timestamp: Date.now(),
      window,
    };
  }

  private async saveMetrics(key: string, metrics: RateLimitMetrics): Promise<void> {
    await this.kvNamespace.put(key, JSON.stringify(metrics), {
      expirationTtl: Math.ceil(metrics.window / 1000) + 3600, // Keep for 1 hour after window
    });
  }

  private async checkThresholds(metrics: RateLimitMetrics): Promise<void> {
    const blockRate = metrics.requestCount > 0 ? metrics.blockedCount / metrics.requestCount : 0;

    // Check for high block rate
    if (blockRate > 0.5 && metrics.requestCount > 10) {
      await this.createAlert({
        type: 'threshold',
        identifier: metrics.identifier,
        message: `High block rate detected: ${(blockRate * 100).toFixed(1)}%`,
        severity: blockRate > 0.8 ? 'critical' : 'high',
        timestamp: Date.now(),
        metrics,
      });
    }

    // Check for traffic spike
    const previousMetrics = await this.getPreviousWindowMetrics(metrics.identifier);
    if (previousMetrics) {
      const increase = metrics.requestCount / previousMetrics.requestCount;
      if (increase > 5) {
        await this.createAlert({
          type: 'spike',
          identifier: metrics.identifier,
          message: `Traffic spike detected: ${increase.toFixed(1)}x increase`,
          severity: increase > 10 ? 'high' : 'medium',
          timestamp: Date.now(),
          metrics,
        });
      }
    }
  }

  private async getPreviousWindowMetrics(identifier: string): Promise<RateLimitMetrics | null> {
    // This would need to store historical data
    // For now, return null
    return null;
  }

  private async createAlert(alert: RateLimitAlert): Promise<void> {
    this.alerts.push(alert);

    // Store alert
    const key = `${this.alertsPrefix}${alert.identifier}:${alert.timestamp}`;
    await this.kvNamespace.put(key, JSON.stringify(alert), {
      expirationTtl: 86400, // Keep for 24 hours
    });

    // Trigger notification if needed
    if (alert.severity === 'critical' || alert.severity === 'high') {
      await this.sendNotification(alert);
    }
  }

  private async sendNotification(alert: RateLimitAlert): Promise<void> {
    // Implement notification logic (email, webhook, etc.)
    console.error('Rate limit alert:', alert);
  }

  async getRecentAlerts(hours: number = 1): Promise<RateLimitAlert[]> {
    const cutoff = Date.now() - hours * 60 * 60 * 1000;
    return this.alerts.filter((alert: any) => alert.timestamp > cutoff);
  }

  async getMetricsSummary(identifier: string): Promise<{
    current: RateLimitMetrics | null;
    alerts: RateLimitAlert[];
    trend: 'increasing' | 'stable' | 'decreasing';
  }> {
    const key = `${this.metricsPrefix}${identifier}`;
    const current = await this.getMetrics(key);
    const alerts = this.alerts.filter((a: any) => a.identifier === identifier);

    // Simple trend analysis
    let trend: 'increasing' | 'stable' | 'decreasing' = 'stable';
    if (alerts.some(a => a.type === 'spike')) {
      trend = 'increasing';
    }

    return {
      current,
      alerts,
      trend,
    };
  }

  async cleanup(): Promise<void> {
    // Clean up old metrics and alerts
    const list = await this.kvNamespace.list({ prefix: this.metricsPrefix });
    for (const key of list.keys) {
      const data = await this.kvNamespace.get(key.name);
      if (data) {
        const metrics = JSON.parse(data) as RateLimitMetrics;
        if (Date.now() - metrics.timestamp > metrics.window + 3600000) {
          await this.kvNamespace.delete(key.name);
        }
      }
    }
  }
}