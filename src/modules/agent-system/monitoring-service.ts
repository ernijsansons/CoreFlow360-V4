/**
 * Monitoring Service with Alerts
 * Real-time metrics collection and alerting system
 */

import { Logger } from '../../shared/logger';
import type { KVNamespace, D1Database } from '@cloudflare/workers-types';

export interface Metric {
  name: string;
  value: number;
  timestamp: number;
  tags: Record<string, string>;
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
}

export interface Alert {
  id: string;
  name: string;
  condition: AlertCondition;
  severity: 'info' | 'warning' | 'error' | 'critical';
  status: 'active' | 'resolved' | 'silenced';
  triggeredAt?: number;
  resolvedAt?: number;
  lastNotification?: number;
  notifications: number;
  metadata?: Record<string, any>;
}

export interface AlertCondition {
  metric: string;
  operator: '>' | '<' | '>=' | '<=' | '=' | '!=';
  threshold: number;
  duration?: number; // seconds
  evaluations?: number; // consecutive evaluations needed
}

export interface AlertChannel {
  type: 'email' | 'webhook' | 'slack' | 'pagerduty';
  config: Record<string, any>;
  filter?: (alert: Alert) => boolean;
}

export interface HealthCheck {
  name: string;
  endpoint?: string;
  check: () => Promise<boolean>;
  interval: number;
  timeout: number;
  lastCheck?: number;
  status: 'healthy' | 'unhealthy' | 'unknown';
  consecutiveFailures: number;
}

export interface MonitoringConfig {
  metricsInterval: number;
  alertEvaluationInterval: number;
  metricsRetention: number;
  enableAlerts: boolean;
  enableHealthChecks: boolean;
}

export // TODO: Consider splitting MonitoringService into smaller, focused classes
class MonitoringService {
  private logger: Logger;
  private kv: KVNamespace;
  private db?: D1Database;
  private config: MonitoringConfig;

  private metrics = new Map<string, Metric[]>();
  private alerts = new Map<string, Alert>();
  private channels: AlertChannel[] = [];
  private healthChecks = new Map<string, HealthCheck>();

  private metricsInterval?: NodeJS.Timeout;
  private alertInterval?: NodeJS.Timeout;
  private healthCheckIntervals = new Map<string, NodeJS.Timeout>();

  private aggregatedMetrics = new Map<string, AggregatedMetric>();

  constructor(kv: KVNamespace, db?: D1Database, config?: Partial<MonitoringConfig>) {
    this.logger = new Logger();
    this.kv = kv;
    this.db = db;
    this.config = {
      metricsInterval: 60000, // 1 minute
      alertEvaluationInterval: 30000, // 30 seconds
      metricsRetention: 86400000, // 24 hours
      enableAlerts: true,
      enableHealthChecks: true,
      ...config
    };

    this.startMonitoring();
  }

  /**
   * Record a metric
   */
  recordMetric(
    name: string,
    value: number,
    type: Metric['type'] = 'gauge',
    tags: Record<string, string> = {}
  ): void {
    const metric: Metric = {
      name,
      value,
      timestamp: Date.now(),
      tags,
      type
    };

    // Store in memory
    const metrics = this.metrics.get(name) || [];
    metrics.push(metric);

    // Limit retention in memory
    const cutoff = Date.now() - this.config.metricsRetention;
    const retained = metrics.filter((m: any) => m.timestamp > cutoff);
    this.metrics.set(name, retained);

    // Update aggregated metrics
    this.updateAggregatedMetric(name, value, type);

    this.logger.debug('Metric recorded', { name, value, type });
  }

  /**
   * Increment counter
   */
  increment(name: string, value: number = 1, tags?: Record<string, string>): void {
    this.recordMetric(name, value, 'counter', tags);
  }

  /**
   * Set gauge
   */
  gauge(name: string, value: number, tags?: Record<string, string>): void {
    this.recordMetric(name, value, 'gauge', tags);
  }

  /**
   * Record histogram
   */
  histogram(name: string, value: number, tags?: Record<string, string>): void {
    this.recordMetric(name, value, 'histogram', tags);
  }

  /**
   * Create alert
   */
  createAlert(
    name: string,
    condition: AlertCondition,
    severity: Alert['severity'] = 'warning'
  ): string {
    const alertId = `alert_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

    const alert: Alert = {
      id: alertId,
      name,
      condition,
      severity,
      status: 'active',
      notifications: 0
    };

    this.alerts.set(alertId, alert);

    this.logger.info('Alert created', {
      alertId,
      name,
      condition,
      severity
    });

    return alertId;
  }

  /**
   * Register alert channel
   */
  registerChannel(channel: AlertChannel): void {
    this.channels.push(channel);
    this.logger.info('Alert channel registered', { type: channel.type });
  }

  /**
   * Register health check
   */
  registerHealthCheck(healthCheck: Omit<HealthCheck, 'status' | 'consecutiveFailures'>): void {
    const check: HealthCheck = {
      ...healthCheck,
      status: 'unknown',
      consecutiveFailures: 0
    };

    this.healthChecks.set(check.name, check);

    if (this.config.enableHealthChecks) {
      this.startHealthCheck(check);
    }

    this.logger.info('Health check registered', { name: check.name });
  }

  /**
   * Evaluate alerts
   */
  private async evaluateAlerts(): Promise<void> {
    for (const [alertId, alert] of this.alerts) {
      if (alert.status === 'silenced') continue;

      try {
        const shouldTrigger = this.evaluateAlertCondition(alert);

        if (shouldTrigger && alert.status !== 'active') {
          await this.triggerAlert(alert);
        } else if (!shouldTrigger && alert.status === 'active' && alert.triggeredAt) {
          await this.resolveAlert(alert);
        }

      } catch (error: any) {
        this.logger.error('Alert evaluation failed', error, { alertId });
      }
    }
  }

  /**
   * Evaluate alert condition
   */
  private evaluateAlertCondition(alert: Alert): boolean {
    const metrics = this.metrics.get(alert.condition.metric);
    if (!metrics || metrics.length === 0) return false;

    const duration = alert.condition.duration || 0;
    const cutoff = Date.now() - (duration * 1000);
    const relevantMetrics = metrics.filter((m: any) => m.timestamp >= cutoff);

    if (relevantMetrics.length === 0) return false;

    // Calculate average value
    const avgValue = relevantMetrics.reduce((sum, m) => sum + m.value, 0) / relevantMetrics.length;

    // Evaluate condition
    switch (alert.condition.operator) {
      case '>':
        return avgValue > alert.condition.threshold;
      case '<':
        return avgValue < alert.condition.threshold;
      case '>=':
        return avgValue >= alert.condition.threshold;
      case '<=':
        return avgValue <= alert.condition.threshold;
      case '=':
        return Math.abs(avgValue - alert.condition.threshold) < 0.001;
      case '!=':
        return Math.abs(avgValue - alert.condition.threshold) >= 0.001;
      default:
        return false;
    }
  }

  /**
   * Trigger alert
   */
  private async triggerAlert(alert: Alert): Promise<void> {
    alert.status = 'active';
    alert.triggeredAt = Date.now();
    alert.notifications++;

    this.logger.warn('Alert triggered', {
      alertId: alert.id,
      name: alert.name,
      severity: alert.severity
    });

    // Send notifications
    for (const channel of this.channels) {
      if (!channel.filter || channel.filter(alert)) {
        await this.sendNotification(channel, alert);
      }
    }

    // Persist to database
    if (this.db) {
      await this.db.prepare(`
        INSERT INTO alert_history (
          alert_id, name, severity, condition,
          triggered_at, status
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        alert.id,
        alert.name,
        alert.severity,
        JSON.stringify(alert.condition),
        alert.triggeredAt,
        'triggered'
      ).run();
    }
  }

  /**
   * Resolve alert
   */
  private async resolveAlert(alert: Alert): Promise<void> {
    alert.status = 'resolved';
    alert.resolvedAt = Date.now();

    this.logger.info('Alert resolved', {
      alertId: alert.id,
      name: alert.name,
      duration: alert.resolvedAt - (alert.triggeredAt || 0)
    });

    // Send resolution notification
    for (const channel of this.channels) {
      if (!channel.filter || channel.filter(alert)) {
        await this.sendNotification(channel, alert, true);
      }
    }

    // Update database
    if (this.db) {
      await this.db.prepare(`
        UPDATE alert_history
        SET status = 'resolved', resolved_at = ?
        WHERE alert_id = ? AND status = 'triggered'
      `).bind(alert.resolvedAt, alert.id).run();
    }
  }

  /**
   * Send notification
   */
  private async sendNotification(
    channel: AlertChannel,
    alert: Alert,
    resolved: boolean = false
  ): Promise<void> {
    try {
      const message = this.formatAlertMessage(alert, resolved);

      switch (channel.type) {
        case 'webhook':
          await this.sendWebhook(channel.config.url, {
            alert: alert.name,
            severity: alert.severity,
            status: alert.status,
            message,
            timestamp: Date.now()
          });
          break;

        case 'slack':
          await this.sendSlackMessage(channel.config, message, alert.severity);
          break;

        case 'email':
          // Email implementation would go here
          this.logger.info('Email notification queued', { to: channel.config.to });
          break;

        case 'pagerduty':
          // PagerDuty implementation would go here
          this.logger.info('PagerDuty alert created');
          break;
      }

      alert.lastNotification = Date.now();

    } catch (error: any) {
      this.logger.error('Failed to send notification', error, {
        channel: channel.type,
        alertId: alert.id
      });
    }
  }

  /**
   * Send webhook
   */
  private async sendWebhook(url: string, payload: any): Promise<void> {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Webhook failed: ${response.status}`);
    }
  }

  /**
   * Send Slack message
   */
  private async sendSlackMessage(
    config: Record<string, any>,
    message: string,
    severity: Alert['severity']
  ): Promise<void> {
    const color = {
      info: '#36a64f',
      warning: '#ff9900',
      error: '#ff0000',
      critical: '#990000'
    }[severity];

    await this.sendWebhook(config.webhookUrl, {
      attachments: [{
        color,
        text: message,
        footer: 'CoreFlow360 Monitoring',
        ts: Math.floor(Date.now() / 1000)
      }]
    });
  }

  /**
   * Format alert message
   */
  private formatAlertMessage(alert: Alert, resolved: boolean): string {
    const status = resolved ? '✅ RESOLVED' : '🚨 TRIGGERED';
    const condition = `${alert.condition.metric} ${alert.condition.operator} ${alert.condition.threshold}`;

    return `${status}: ${alert.name}\nSeverity: ${alert.severity}\nCondition: ${condition}`;
  }

  /**
   * Perform health check
   */
  private async performHealthCheck(check: HealthCheck): Promise<void> {
    try {
      const timeoutPromise = new Promise<boolean>((_, reject) => {
        setTimeout(() => reject(new Error('Health check timeout')), check.timeout);
      });

      const healthy = await Promise.race([check.check(), timeoutPromise]);

      if (healthy) {
        if (check.status === 'unhealthy') {
          this.logger.info('Health check recovered', { name: check.name });
        }
        check.status = 'healthy';
        check.consecutiveFailures = 0;
      } else {
        throw new Error('Health check failed');
      }

    } catch (error: any) {
      check.consecutiveFailures++;
      check.status = 'unhealthy';

      this.logger.warn('Health check failed', {
        name: check.name,
        failures: check.consecutiveFailures,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      // Create alert if multiple failures
      if (check.consecutiveFailures >= 3) {
        this.createAlert(
          `Health Check Failed: ${check.name}`,
          {
            metric: `health.${check.name}`,
            operator: '<',
            threshold: 1
          },
          'error'
        );
      }
    }

    check.lastCheck = Date.now();
  }

  /**
   * Start health check
   */
  private startHealthCheck(check: HealthCheck): void {
    const interval = setInterval(async () => {
      await this.performHealthCheck(check);
    }, check.interval) as any;

    this.healthCheckIntervals.set(check.name, interval);

    // Perform initial check
    this.performHealthCheck(check).catch((error: any) => {
      this.logger.error('Initial health check failed', error);
    });
  }

  /**
   * Update aggregated metrics
   */
  private updateAggregatedMetric(name: string, value: number, type: Metric['type']): void {
    let agg = this.aggregatedMetrics.get(name);

    if (!agg) {
      agg = {
        name,
        count: 0,
        sum: 0,
        min: value,
        max: value,
        last: value,
        mean: 0,
        p50: 0,
        p95: 0,
        p99: 0,
        values: []
      };
      this.aggregatedMetrics.set(name, agg);
    }

    agg.count++;
    agg.sum += value;
    agg.last = value;
    agg.min = Math.min(agg.min, value);
    agg.max = Math.max(agg.max, value);
    agg.mean = agg.sum / agg.count;

    // Keep last 1000 values for percentiles
    agg.values.push(value);
    if (agg.values.length > 1000) {
      agg.values.shift();
    }

    // Calculate percentiles
    if (agg.values.length > 10) {
      const sorted = [...agg.values].sort((a, b) => a - b);
      agg.p50 = sorted[Math.floor(sorted.length * 0.5)];
      agg.p95 = sorted[Math.floor(sorted.length * 0.95)];
      agg.p99 = sorted[Math.floor(sorted.length * 0.99)];
    }
  }

  /**
   * Get aggregated metrics
   */
  getAggregatedMetrics(): Map<string, AggregatedMetric> {
    return new Map(this.aggregatedMetrics);
  }

  /**
   * Get health status
   */
  getHealthStatus(): {
    healthy: boolean;
    checks: Array<{ name: string; status: string; lastCheck?: number }>;
  } {
    const checks = Array.from(this.healthChecks.values()).map((check: any) => ({
      name: check.name,
      status: check.status,
      lastCheck: check.lastCheck
    }));

    const healthy = checks.every(c => c.status === 'healthy');

    return { healthy, checks };
  }

  /**
   * Export metrics
   */
  private async exportMetrics(): Promise<void> {
    if (!this.db) return;

    const batch = this.db.batch([]);
    const now = Date.now();

    for (const [name, metrics] of this.metrics) {
      for (const metric of metrics) {
        // Only export recent metrics
        if (now - metric.timestamp < 300000) { // 5 minutes
          batch.push(
            this.db.prepare(`
              INSERT INTO metrics (
                name, value, type, tags, timestamp
              ) VALUES (?, ?, ?, ?, ?)
            `).bind(
              metric.name,
              metric.value,
              metric.type,
              JSON.stringify(metric.tags),
              metric.timestamp
            )
          );
        }
      }
    }

    if (batch.length > 0) {
      await this.db.batch(batch);
      this.logger.debug('Metrics exported', { count: batch.length });
    }
  }

  /**
   * Start monitoring
   */
  private startMonitoring(): void {
    // Start metrics export
    this.metricsInterval = setInterval(() => {
      this.exportMetrics().catch((error: any) => {
        this.logger.error('Metrics export failed', error);
      });
    }, this.config.metricsInterval) as any;

    // Start alert evaluation
    if (this.config.enableAlerts) {
      this.alertInterval = setInterval(() => {
        this.evaluateAlerts().catch((error: any) => {
          this.logger.error('Alert evaluation failed', error);
        });
      }, this.config.alertEvaluationInterval) as any;
    }
  }

  /**
   * Shutdown monitoring
   */
  async shutdown(): Promise<void> {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }
    if (this.alertInterval) {
      clearInterval(this.alertInterval);
    }

    for (const interval of this.healthCheckIntervals.values()) {
      clearInterval(interval);
    }

    await this.exportMetrics();

    this.logger.info('Monitoring service shutdown');
  }
}

interface AggregatedMetric {
  name: string;
  count: number;
  sum: number;
  min: number;
  max: number;
  last: number;
  mean: number;
  p50: number;
  p95: number;
  p99: number;
  values: number[];
}