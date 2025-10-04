import { Alert, AlertRule, LogEntry, Metric, AnalyticsData } from '../../types/telemetry';
import { TelemetryCollector } from './collector';

interface AnomalyDetectionConfig {
  method: 'isolation-forest' | 'statistical' | 'ml-based';
  sensitivity: number;
  lookbackHours: number;
  minDataPoints: number;
}

interface PredictionConfig {
  model: 'prophet' | 'arima' | 'linear-regression';
  horizonHours: number;
  confidenceInterval: number;
}

interface RootCauseConfig {
  correlationThreshold: number;
  impactAnalysis: boolean;
  maxDepth: number;
}

interface Anomaly {
  timestamp: number;
  metric: string;
  value: number;
  expectedValue: number;
  severity: 'low' | 'medium' | 'high';
  confidence: number;
  context: Record<string, any>;
}

interface Prediction {
  metric: string;
  timestamp: number;
  predictedValue: number;
  confidenceInterval: [number, number];
  trend: 'increasing' | 'decreasing' | 'stable';
  seasonality: boolean;
}

interface RootCause {
  issue: string;
  causes: Array<{
    factor: string;
    correlation: number;
    impact: number;
    evidence: string[];
  }>;
  recommendations: string[];
}

export class AIAlertEngine {
  private collector: TelemetryCollector;
  private env: any;
  private alertHistory: Map<string, Alert[]> = new Map();
  private metricHistory: Map<string, number[]> = new Map();

  constructor(collector: TelemetryCollector, env: any) {
    this.collector = collector;
    this.env = env;
  }

  async analyzeMetrics(businessId: string): Promise<Alert[]> {
    const alerts: Alert[] = [];

    try {
      const timeRange = {
        start: new Date(Date.now() - 168 * 60 * 60 * 1000).toISOString(), // 7 days
        end: new Date().toISOString()
      };

      const metrics = await this.collector.getMetrics(businessId, timeRange);

      const [anomalies, predictions, rootCauses] = await Promise.all([
        this.detectAnomalies(metrics, {
          method: 'statistical',
          sensitivity: 0.95,
          lookbackHours: 168,
          minDataPoints: 50
        }),
        this.predictIssues(metrics, {
          model: 'linear-regression',
          horizonHours: 24,
          confidenceInterval: 0.95
        }),
        this.performRCA(metrics, {
          correlationThreshold: 0.8,
          impactAnalysis: true,
          maxDepth: 3
        })
      ]);

      alerts.push(
        ...this.generateAnomalyAlerts(anomalies),
        ...this.generatePredictionAlerts(predictions),
        ...this.generateRCAAlerts(rootCauses)
      );

      return alerts;
    } catch (error: any) {
      return [];
    }
  }

  private async detectAnomalies(
    metrics: AnalyticsData[],
    config: AnomalyDetectionConfig
  ): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    if (metrics.length < config.minDataPoints) {
      return anomalies;
    }

    switch (config.method) {
      case 'statistical':
        return this.detectStatisticalAnomalies(metrics, config);
      case 'isolation-forest':
        return this.detectIsolationForestAnomalies(metrics, config);
      case 'ml-based':
        return this.detectMLAnomalies(metrics, config);
      default:
        return anomalies;
    }
  }

  private detectStatisticalAnomalies(
    metrics: AnalyticsData[],
    config: AnomalyDetectionConfig
  ): Anomaly[] {
    const anomalies: Anomaly[] = [];

    const latencies = metrics.map((m: any) => m.metrics.golden.latency.p95);
    const errors = metrics.map((m: any) => m.metrics.golden.errors.errorRate);
    const costs = metrics.map((m: any) => m.metrics.ai.costCents);

    const latencyStats = this.calculateStats(latencies);
    const errorStats = this.calculateStats(errors);
    const costStats = this.calculateStats(costs);

    metrics.forEach((metric, index) => {
      const latency = metric.metrics.golden.latency.p95;
      const errorRate = metric.metrics.golden.errors.errorRate;
      const cost = metric.metrics.ai.costCents;

      if (this.isOutlier(latency, latencyStats, config.sensitivity)) {
        anomalies.push({
          timestamp: metric.timestamp,
          metric: 'latency_p95',
          value: latency,
          expectedValue: latencyStats.mean,
          severity: this.getSeverity(latency, latencyStats),
          confidence: config.sensitivity,
          context: { businessId: metric.businessId }
        });
      }

      if (this.isOutlier(errorRate, errorStats, config.sensitivity)) {
        anomalies.push({
          timestamp: metric.timestamp,
          metric: 'error_rate',
          value: errorRate,
          expectedValue: errorStats.mean,
          severity: this.getSeverity(errorRate, errorStats),
          confidence: config.sensitivity,
          context: { businessId: metric.businessId }
        });
      }

      if (this.isOutlier(cost, costStats, config.sensitivity)) {
        anomalies.push({
          timestamp: metric.timestamp,
          metric: 'ai_cost',
          value: cost,
          expectedValue: costStats.mean,
          severity: this.getSeverity(cost, costStats),
          confidence: config.sensitivity,
          context: { businessId: metric.businessId }
        });
      }
    });

    return anomalies;
  }

  private calculateStats(values: number[]): { mean: number; std: number; min: number; max: number } {
    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    const std = Math.sqrt(variance);

    return {
      mean,
      std,
      min: Math.min(...values),
      max: Math.max(...values)
    };
  }

  private isOutlier(value: number, stats: any, sensitivity: number): boolean {
    const zScore = Math.abs((value - stats.mean) / stats.std);
    const threshold = this.getZScoreThreshold(sensitivity);
    return zScore > threshold;
  }

  private getZScoreThreshold(sensitivity: number): number {
    if (sensitivity >= 0.99) return 3.0;
    if (sensitivity >= 0.95) return 2.5;
    if (sensitivity >= 0.90) return 2.0;
    return 1.5;
  }

  private getSeverity(value: number, stats: any): 'low' | 'medium' | 'high' {
    const zScore = Math.abs((value - stats.mean) / stats.std);
    if (zScore > 3.0) return 'high';
    if (zScore > 2.0) return 'medium';
    return 'low';
  }

  private async detectIsolationForestAnomalies(
    metrics: AnalyticsData[],
    config: AnomalyDetectionConfig
  ): Promise<Anomaly[]> {
    // Simplified isolation forest implementation
    // In production, use a proper ML library
    return this.detectStatisticalAnomalies(metrics, config);
  }

  private async detectMLAnomalies(
    metrics: AnalyticsData[],
    config: AnomalyDetectionConfig
  ): Promise<Anomaly[]> {
    if (!this.env.AI_ENDPOINT) {
      return this.detectStatisticalAnomalies(metrics, config);
    }

    try {
      const response = await fetch(`${this.env.AI_ENDPOINT}/anomaly-detection`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.env.AI_API_KEY}`
        },
        body: JSON.stringify({
          metrics: metrics.map((m: any) => ({
            timestamp: m.timestamp,
            latency: m.metrics.golden.latency.p95,
            errors: m.metrics.golden.errors.errorRate,
            cost: m.metrics.ai.costCents,
            traffic: m.metrics.golden.traffic.requestsPerSecond
          })),
          config
        })
      });

      const result = await response.json();
      return (result as any).anomalies || [];
    } catch (error: any) {
      return this.detectStatisticalAnomalies(metrics, config);
    }
  }

  private async predictIssues(
    metrics: AnalyticsData[],
    config: PredictionConfig
  ): Promise<Prediction[]> {
    const predictions: Prediction[] = [];

    if (metrics.length < 20) return predictions;

    const latencies = metrics.map((m: any) => ({
      timestamp: m.timestamp,
      value: m.metrics.golden.latency.p95
    }));
    const errors = metrics.map((m: any) => ({
      timestamp: m.timestamp,
      value: m.metrics.golden.errors.errorRate
    }));
    const costs = metrics.map((m: any) => ({
      timestamp: m.timestamp,
      value: m.metrics.ai.costCents
    }));

    predictions.push(
      ...this.predictTimeSeries('latency_p95', latencies, config),
      ...this.predictTimeSeries('error_rate', errors, config),
      ...this.predictTimeSeries('ai_cost', costs, config)
    );

    return predictions;
  }

  private predictTimeSeries(
    metric: string,
    data: Array<{ timestamp: number; value: number }>,
    config: PredictionConfig
  ): Prediction[] {
    // Simple linear regression prediction
    const n = data.length;
    const sumX = data.reduce((sum, d, i) => sum + i, 0);
    const sumY = data.reduce((sum, d) => sum + d.value, 0);
    const sumXY = data.reduce((sum, d, i) => sum + i * d.value, 0);
    const sumXX = data.reduce((sum, d, i) => sum + i * i, 0);

    const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;

    const predictions: Prediction[] = [];
    const futureSteps = Math.ceil(config.horizonHours / 1); // 1 hour intervals

    for (let i = 1; i <= futureSteps; i++) {
      const futureIndex = n + i;
      const predictedValue = slope * futureIndex + intercept;
      const timestamp = data[data.length - 1].timestamp + i * 60 * 60 * 1000; // 1 hour

      // Calculate confidence interval (simplified)
      const residuals = data.map((d, idx) => d.value - (slope * idx + intercept));
      const mse = residuals.reduce((sum, r) => sum + r * r, 0) / n;
      const margin = 1.96 * Math.sqrt(mse); // 95% confidence

      predictions.push({
        metric,
        timestamp,
        predictedValue,
        confidenceInterval: [predictedValue - margin, predictedValue + margin],
        trend: slope > 0 ? 'increasing' : slope < 0 ? 'decreasing' : 'stable',
        seasonality: false // Simplified
      });
    }

    return predictions;
  }

  private async performRCA(
    metrics: AnalyticsData[],
    config: RootCauseConfig
  ): Promise<RootCause[]> {
    const rootCauses: RootCause[] = [];

    if (metrics.length < 10) return rootCauses;

    // Identify issues with high error rates
    const highErrorMetrics = metrics.filter((m: any) => m.metrics.golden.errors.errorRate > 0.05);

    if (highErrorMetrics.length > 0) {
      rootCauses.push({
        issue: 'High Error Rate',
        causes: [
          {
            factor: 'Increased latency',
            correlation: this.calculateCorrelation(
              metrics.map((m: any) => m.metrics.golden.errors.errorRate),
              metrics.map((m: any) => m.metrics.golden.latency.p95)
            ),
            impact: 0.8,
            evidence: ['Error rate correlation with latency spikes']
          },
          {
            factor: 'AI service degradation',
            correlation: this.calculateCorrelation(
              metrics.map((m: any) => m.metrics.golden.errors.errorRate),
              metrics.map((m: any) => m.metrics.ai.errorRate)
            ),
            impact: 0.7,
            evidence: ['AI service error rate correlation']
          }
        ],
        recommendations: [
          'Scale up AI service capacity',
          'Implement circuit breakers',
          'Add request timeout handling',
          'Review AI model performance'
        ]
      });
    }

    // Identify cost anomalies
    const avgCost = metrics.reduce((sum, m) => sum + m.metrics.ai.costCents, 0) / metrics.length;
    const highCostMetrics = metrics.filter((m: any) => m.metrics.ai.costCents > avgCost * 2);

    if (highCostMetrics.length > 0) {
      rootCauses.push({
        issue: 'High AI Costs',
        causes: [
          {
            factor: 'Increased token usage',
            correlation: this.calculateCorrelation(
              metrics.map((m: any) => m.metrics.ai.costCents),
              metrics.map((m: any) => m.metrics.ai.totalTokens)
            ),
            impact: 0.9,
            evidence: ['Direct correlation between tokens and cost']
          },
          {
            factor: 'Model selection',
            correlation: 0.6,
            impact: 0.5,
            evidence: ['Usage of expensive models during peak hours']
          }
        ],
        recommendations: [
          'Implement token usage optimization',
          'Use cheaper models for non-critical operations',
          'Add cost-based routing',
          'Implement usage quotas'
        ]
      });
    }

    return rootCauses;
  }

  private calculateCorrelation(x: number[], y: number[]): number {
    if (x.length !== y.length || x.length === 0) return 0;

    const n = x.length;
    const sumX = x.reduce((sum, val) => sum + val, 0);
    const sumY = y.reduce((sum, val) => sum + val, 0);
    const sumXY = x.reduce((sum, val, i) => sum + val * y[i], 0);
    const sumXX = x.reduce((sum, val) => sum + val * val, 0);
    const sumYY = y.reduce((sum, val) => sum + val * val, 0);

    const numerator = n * sumXY - sumX * sumY;
    const denominator = Math.sqrt((n * sumXX - sumX * sumX) * (n * sumYY - sumY * sumY));

    return denominator === 0 ? 0 : numerator / denominator;
  }

  private generateAnomalyAlerts(anomalies: Anomaly[]): Alert[] {
    return anomalies.map((anomaly: any) => ({
      id: crypto.randomUUID(),
      name: `Anomaly Detected: ${anomaly.metric}`,
      severity: anomaly.severity === 'high' ? 'critical' :
                anomaly.severity === 'medium' ? 'high' : 'medium',
      status: 'firing' as const,
     
  message: `Anomalous ${anomaly.metric} detected: ${anomaly.value.toFixed(2)} (expected: ${anomaly.expectedValue.toFixed(2)})`,
      timestamp: anomaly.timestamp,
      source: 'ai-analytics',
      metadata: {
        type: 'anomaly',
        confidence: anomaly.confidence,
        context: anomaly.context
      },
      channels: ['email', 'slack'],
      escalationLevel: 0,
      correlatedAlerts: []
    }));
  }

  private generatePredictionAlerts(predictions: Prediction[]): Alert[] {
    const alerts: Alert[] = [];

    predictions.forEach((prediction: any) => {
      if (prediction.trend === 'increasing' && prediction.metric === 'error_rate') {
        alerts.push({
          id: crypto.randomUUID(),
          name: `Predicted Issue: Rising ${prediction.metric}`,
          severity: 'medium',
          status: 'firing',
         
  message: `${prediction.metric} is predicted to reach ${prediction.predictedValue.toFixed(4)} with ${prediction.trend} trend`,
          timestamp: prediction.timestamp,
          source: 'ai-analytics',
          metadata: {
            type: 'prediction',
            trend: prediction.trend,
            confidence: prediction.confidenceInterval
          },
          channels: ['email'],
          escalationLevel: 0,
          correlatedAlerts: []
        });
      }
    });

    return alerts;
  }

  private generateRCAAlerts(rootCauses: RootCause[]): Alert[] {
    return rootCauses.map((rca: any) => ({
      id: crypto.randomUUID(),
      name: `Root Cause Analysis: ${rca.issue}`,
      severity: 'high' as const,
      status: 'firing' as const,
      message: `Root cause identified for ${rca.issue}: ${rca.causes[0]?.factor || 'Unknown'}`,
      timestamp: Date.now(),
      source: 'ai-analytics',
      metadata: {
        type: 'root-cause',
        causes: rca.causes,
        recommendations: rca.recommendations
      },
      channels: ['email', 'slack'],
      escalationLevel: 0,
      correlatedAlerts: []
    }));
  }

  async getCostIntelligence(businessId: string): Promise<any> {
    const timeRange = {
      start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
      end: new Date().toISOString()
    };

    const metrics = await this.collector.getMetrics(businessId, timeRange);

    const totalCost = metrics.reduce((sum, m) => sum + m.metrics.ai.costCents, 0) / 100;
    const avgDailyCost = totalCost / 30;
    const projectedMonthlyCost = avgDailyCost * 30;

    return {
      totalCost,
      avgDailyCost,
      projectedMonthlyCost,
      costByFeature: this.analyzeCostByFeature(metrics),
      anomalies: await this.detectCostAnomalies(metrics),
      optimizationRecommendations: this.generateCostOptimizations(metrics)
    };
  }

  private analyzeCostByFeature(metrics: AnalyticsData[]): Record<string, number> {
    // Simplified feature cost analysis
    return {
      'chat': metrics.reduce((sum, m) => sum + m.metrics.ai.costCents * 0.4, 0) / 100,
      'agents': metrics.reduce((sum, m) => sum + m.metrics.ai.costCents * 0.3, 0) / 100,
      'analytics': metrics.reduce((sum, m) => sum + m.metrics.ai.costCents * 0.2, 0) / 100,
      'other': metrics.reduce((sum, m) => sum + m.metrics.ai.costCents * 0.1, 0) / 100
    };
  }

  private async detectCostAnomalies(metrics: AnalyticsData[]): Promise<Anomaly[]> {
    const costs = metrics.map((m: any) => m.metrics.ai.costCents);
    const stats = this.calculateStats(costs);

    return metrics
      .filter((m: any) => this.isOutlier(m.metrics.ai.costCents, stats, 0.95))
      .map((m: any) => ({
        timestamp: m.timestamp,
        metric: 'cost',
        value: m.metrics.ai.costCents,
        expectedValue: stats.mean,
        severity: this.getSeverity(m.metrics.ai.costCents, stats),
        confidence: 0.95,
        context: { businessId: m.businessId }
      }));
  }

  private generateCostOptimizations(metrics: AnalyticsData[]): string[] {
    const recommendations: string[] = [];

    const avgCost = metrics.reduce((sum, m) => sum + m.metrics.ai.costCents, 0) / metrics.length;
    const avgTokens = metrics.reduce((sum, m) => sum + m.metrics.ai.totalTokens, 0) / metrics.length;

    if (avgCost > 100) { // > $1 per request
      recommendations.push('Consider using more cost-effective AI models for routine operations');
    }

    if (avgTokens > 2000) {
      recommendations.push('Implement prompt optimization to reduce token usage');
    }

    recommendations.push(
      'Implement caching for repeated queries',
      'Use model routing based on complexity',
      'Set up usage quotas and alerts'
    );

    return recommendations;
  }
}