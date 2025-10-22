// CoreFlow360 V4 - AI-Powered Analytics and Alerting Engine
import { Alert, Anomaly } from '../types/observability';
import { getAIClient, AIClient } from './ai-client';
import type { Env } from '../types/env';import { Logger } from "../shared/logger";
const logger = new Logger({ component: "services-ai-analytics-engine" });



export class AIAnalyticsEngine {
  private env: Env;
  private db: D1Database;
  private aiClient: AIClient;

  constructor(env: Env) {
    this.env = env;
    this.db = env.DB_ANALYTICS || env.DB;
    this.aiClient = getAIClient(env);
  }

  async analyzeMetrics(): Promise<Alert[]> {
    const alerts: Alert[] = [];

    // Get all businesses to analyze
    const businesses = await this.db.prepare('SELECT id FROM businesses').all();

    if (!businesses.results) {
      return alerts;
    }

    for (const business of businesses.results) {
      const businessRecord = business as Record<string, unknown>;
      if (businessRecord.id && typeof businessRecord.id === 'string') {
        const businessAlerts = await this.analyzeBusinessMetrics(businessRecord.id);
        alerts.push(...businessAlerts);
      }
    }

    return alerts;
  }

  private async analyzeBusinessMetrics(businessId: string): Promise<Alert[]> {
    const alerts: Alert[] = [];

    // 1. Detect anomalies using AI
    const anomalies = await this.detectAnomalies({
      businessId,
      method: 'isolation-forest',
      sensitivity: 0.95,
      lookbackHours: 168 // 7 days
    });

    // 2. Predict future issues
    const predictions = await this.predictIssues({
      businessId,
      model: 'prophet',
      horizonHours: 24
    });

    // 3. Perform root cause analysis
    const rootCauses = await this.performRCA({
      businessId,
      correlationThreshold: 0.8,
      impactAnalysis: true
    });

    // Generate alerts from analysis
    alerts.push(...await this.generateAlerts(anomalies, predictions, rootCauses));

    return alerts;
  }

  async detectAnomalies(options: {
    businessId: string;
    method: 'isolation-forest' | 'statistical' | 'lstm';
    sensitivity: number;
    lookbackHours: number;
  }): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];
    void anomalies;

    // Get recent metrics for analysis
    const since = new Date(Date.now() - options.lookbackHours * 60 * 60 * 1000);
    const metrics = await this.getMetricsForAnalysis(options.businessId, since);

    switch (options.method) {
      case 'isolation-forest':
        return await this.isolationForestDetection(metrics, options);
      case 'statistical':
        return await this.statisticalAnomalyDetection(metrics, options);
      case 'lstm':
        return await this.lstmAnomalyDetection(metrics, options);
      default:
        throw new Error(`Unsupported anomaly detection method: ${options.method}`);
    }
  }

  private async isolationForestDetection(
    metrics: Array<Record<string, unknown>>,
    options: { businessId: string; sensitivity: number }
  ): Promise<Anomaly[]> {
    // Use AI to perform isolation forest anomaly detection
    const prompt = `
    Analyze the following time-series metrics data for anomalies using isolation forest approach.

    Data: ${JSON.stringify(metrics.slice(0, 1000))} // Limit data size

    Sensitivity: ${options.sensitivity}

    Return a JSON array of anomalies with:
    - timestamp
    - metricName
    - actualValue
    - anomalyScore (0-1)
    - severity (low/medium/high)
    - explanation

    Focus on:
    1. Values that deviate significantly from normal patterns
    2. Sudden spikes or drops
    3. Pattern changes
    4. Temporal anomalies
    `;

    try {
      const response = await this.aiClient.generateText(prompt);
      const aiAnomalies = JSON.parse(response);

      const anomalies: Anomaly[] = [];
      if (!Array.isArray(aiAnomalies)) {
        return anomalies;
      }

      for (const aiAnomaly of aiAnomalies) {
        const anomalyData: Partial<Anomaly> = {
          modelId: crypto.randomUUID(),
          businessId: options.businessId,
          timestamp: new Date(aiAnomaly.timestamp || Date.now()),
          metricName: String(aiAnomaly.metricName || 'unknown'),
          actualValue: Number(aiAnomaly.actualValue || 0),
          anomalyScore: Number(aiAnomaly.anomalyScore || 0),
          severity: (aiAnomaly.severity as 'low' | 'medium' | 'high') || 'medium',
          confidence: options.sensitivity,
          labels: { method: 'isolation-forest' },
          explanation: String(aiAnomaly.explanation || ''),
          reviewed: false,
          createdAt: new Date()
        };

        // Persist anomaly
        const anomalyId = await this.persistAnomaly(anomalyData);
        anomalies.push({ id: anomalyId, ...anomalyData } as Anomaly);
      }

      return anomalies;

    } catch (error: unknown) {
      logger.error('Isolation forest detection failed:', error);
      return [];
    }
  }

  private async statisticalAnomalyDetection(
    metrics: Array<Record<string, unknown>>,
    options: { businessId: string; sensitivity: number }
  ): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    // Group metrics by name
    const metricGroups = new Map<string, Array<Record<string, unknown>>>();
    for (const metric of metrics) {
      const metricName = String(metric.metric_name || 'unknown');
      if (!metricGroups.has(metricName)) {
        metricGroups.set(metricName, []);
      }
      metricGroups.get(metricName)!.push(metric);
    }

    // Analyze each metric group
    for (const [metricName, metricData] of metricGroups) {
    void metricName;
      const values = metricData.map((m) => Number(m.value || 0));

      if (values.length === 0) {
        continue;
      }

      // Calculate statistics
      const mean = values.reduce((a, b) => a + b, 0) / values.length;
      const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
      const stdDev = Math.sqrt(variance);

      if (stdDev === 0) {
        continue;
      }

      // Z-score threshold based on sensitivity
      const threshold = this.getZScoreThreshold(options.sensitivity);

      // Find anomalies
      for (const metric of metricData) {
        const value = Number(metric.value || 0);
        const zScore = Math.abs((value - mean) / stdDev);

        if (zScore > threshold) {
          const anomalyData: Partial<Anomaly> = {
            modelId: crypto.randomUUID(),
            businessId: options.businessId,
            timestamp: new Date(String(metric.timestamp || Date.now())),
            metricName: String(metric.metric_name || 'unknown'),
            actualValue: value,
            predictedValue: mean,
            anomalyScore: Math.min(zScore / 5, 1), // Normalize to 0-1
            severity: zScore > threshold * 2 ? 'high' : zScore > threshold * 1.5 ? 'medium' : 'low',
            confidence: options.sensitivity,
            labels: { method: 'statistical', zScore: zScore.toString() },
            explanation: `Value ${value} deviates ${zScore.toFixed(2)} standard deviations from mean ${mean.toFixed(2)}`,
            reviewed: false,
            createdAt: new Date()
          };

          const anomalyId = await this.persistAnomaly(anomalyData);
          anomalies.push({ id: anomalyId, ...anomalyData } as Anomaly);
        }
      }
    }

    return anomalies;
  }

  private async lstmAnomalyDetection(
    metrics: Array<Record<string, unknown>>,
    options: { businessId: string; sensitivity: number }
  ): Promise<Anomaly[]> {
    // For LSTM, we would typically use a pre-trained model
    // This is a simplified implementation using AI for pattern analysis

    const prompt = `
    Analyze the following time-series data for anomalies using LSTM-style pattern analysis.
    Look for temporal patterns, sequences, and long-term dependencies.

    Data: ${JSON.stringify(metrics.slice(0, 500))}

    Return JSON array of anomalies focusing on:
    1. Sequence anomalies
    2. Pattern breaks
    3. Temporal dependencies
    4. Seasonal deviations
    `;

    try {
      const response = await this.aiClient.generateText(prompt);
      const aiAnomalies = JSON.parse(response);

      const anomalies: Anomaly[] = [];
      if (!Array.isArray(aiAnomalies)) {
        return anomalies;
      }

      for (const aiAnomaly of aiAnomalies) {
        const anomalyData: Partial<Anomaly> = {
          modelId: crypto.randomUUID(),
          businessId: options.businessId,
          timestamp: new Date(aiAnomaly.timestamp || Date.now()),
          metricName: String(aiAnomaly.metricName || 'unknown'),
          actualValue: Number(aiAnomaly.actualValue || 0),
          predictedValue: Number(aiAnomaly.predictedValue),
          anomalyScore: Number(aiAnomaly.anomalyScore || 0),
          severity: (aiAnomaly.severity as 'low' | 'medium' | 'high') || 'medium',
          confidence: options.sensitivity,
          labels: { method: 'lstm' },
          explanation: String(aiAnomaly.explanation || ''),
          reviewed: false,
          createdAt: new Date()
        };

        const anomalyId = await this.persistAnomaly(anomalyData);
        anomalies.push({ id: anomalyId, ...anomalyData } as Anomaly);
      }

      return anomalies;

    } catch (error: unknown) {
      logger.error('LSTM anomaly detection failed:', error);
      return [];
    }
  }

  async predictIssues(options: {
    businessId: string;
    model: 'prophet' | 'arima' | 'linear';
    horizonHours: number;
  }): Promise<Array<Record<string, unknown>>> {
    const predictions: Array<Record<string, unknown>> = [];

    // Get historical data for prediction
    const lookbackHours = options.horizonHours * 24; // Use 24x horizon for training
    const since = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);
    const metrics = await this.getMetricsForAnalysis(options.businessId, since);

    const prompt = `
    Based on the following historical metrics data, predict potential issues for the next ${options.horizonHours} hours.

    Historical Data: ${JSON.stringify(metrics.slice(0, 1000))}

    Model: ${options.model}
    Prediction Horizon: ${options.horizonHours} hours

    Return JSON array of predictions with:
    - timestamp (future)
    - metricName
    - predictedValue
    - confidence (0-1)
    - issueType (performance_degradation, resource_exhaustion, cost_spike, etc.)
    - severity (low/medium/high/critical)
    - description
    - recommendedActions

    Focus on:
    1. Trend analysis
    2. Seasonal patterns
    3. Capacity planning
    4. Performance degradation
    5. Cost optimization
    `;

    try {
      const response = await this.aiClient.generateText(prompt);
      const aiPredictions = JSON.parse(response);

      if (Array.isArray(aiPredictions)) {
        for (const prediction of aiPredictions) {
          predictions.push({
            businessId: options.businessId,
            ...prediction,
            model: options.model,
            generatedAt: new Date()
          });
        }
      }

    } catch (error: unknown) {
      logger.error('Issue prediction failed:', error);
    }

    return predictions;
  }

  async performRCA(options: {
    businessId: string;
    correlationThreshold: number;
    impactAnalysis: boolean;
  }): Promise<Array<Record<string, unknown>>> {
    const rootCauses: Array<Record<string, unknown>> = [];

    // Get recent incidents and errors
    const incidents = await this.getRecentIncidents(options.businessId);

    for (const incident of incidents) {
      const analysis = await this.analyzeIncident(incident, options);
      if (analysis) {
        rootCauses.push(analysis);
      }
    }

    return rootCauses;
  }

  private async analyzeIncident(
    incident: Record<string, unknown>,
    options: { businessId: string; correlationThreshold: number; impactAnalysis: boolean }
  ): Promise<Record<string, unknown> | null> {
    // Get contextual data around the incident
    const contextWindow = 30 * 60 * 1000; // 30 minutes
    const timestamp = incident.timestamp instanceof Date
      ? incident.timestamp
      : new Date(String(incident.timestamp || Date.now()));

    const startTime = new Date(timestamp.getTime() - contextWindow);
    const endTime = new Date(timestamp.getTime() + contextWindow);

    const contextData = await this.getContextualData(options.businessId, startTime, endTime);

    const prompt = `
    Perform root cause analysis for the following incident:

    Incident: ${JSON.stringify(incident)}

    Contextual Data: ${JSON.stringify(contextData)}

    Correlation Threshold: ${options.correlationThreshold}

    Analyze and return:
    - rootCause (most likely cause)
    - contributingFactors (array)
    - correlations (array of correlated metrics/events)
    - confidence (0-1)
    - timeline (sequence of events)
    - impactAssessment (if requested)
    - remediation (suggested actions)

    Look for:
    1. Timing correlations
    2. Causal relationships
    3. Cascade effects
    4. Resource constraints
    5. Configuration changes
    `;

    try {
      const response = await this.aiClient.generateText(prompt);
      return JSON.parse(response) as Record<string, unknown>;
    } catch (error: unknown) {
      logger.error('Incident analysis failed:', error);
      return null;
    }
  }

  private async generateAlerts(
    anomalies: Anomaly[],
    predictions: Array<Record<string, unknown>>,
    rootCauses: Array<Record<string, unknown>>
  ): Promise<Alert[]> {
    const alerts: Alert[] = [];

    // Generate alerts for anomalies
    for (const anomaly of anomalies) {
      if (anomaly.severity === 'high' || anomaly.anomalyScore > 0.8) {
        const alert = await this.createAnomalyAlert(anomaly);
        alerts.push(alert);
      }
    }

    // Generate alerts for predictions
    for (const prediction of predictions) {
      if (prediction.severity === 'high' || prediction.severity === 'critical') {
        const alert = await this.createPredictiveAlert(prediction);
        alerts.push(alert);
      }
    }

    // Generate alerts for root causes
    for (const rca of rootCauses) {
      const confidence = Number(rca.confidence || 0);
      if (confidence > 0.7) {
        const alert = await this.createRCAAlert(rca);
        alerts.push(alert);
      }
    }

    return alerts;
  }

  private async createAnomalyAlert(anomaly: Anomaly): Promise<Alert> {
    const alertId = crypto.randomUUID();
    const fingerprint = this.generateFingerprint('anomaly', anomaly.metricName, anomaly.businessId);

    const alert: Alert = {
      id: alertId,
      ruleId: anomaly.modelId,
      businessId: anomaly.businessId,
      title: `Anomaly Detected: ${anomaly.metricName}`,
      description: anomaly.explanation || 'Anomaly detected in metric',
      severity: anomaly.severity || 'medium',
      status: 'firing',
      triggeredAt: anomaly.timestamp,
      metricValue: anomaly.actualValue,
      labels: {
        type: 'anomaly',
        metricName: anomaly.metricName,
        anomalyScore: anomaly.anomalyScore.toString()
      },
      annotations: {
        anomalyId: anomaly.id,
        confidence: anomaly.confidence.toString(),
        method: anomaly.labels.method || 'unknown'
      },
      fingerprint,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await this.persistAlert(alert);
    return alert;
  }

  private async createPredictiveAlert(prediction: Record<string, unknown>): Promise<Alert> {
    const alertId = crypto.randomUUID();
    const fingerprint = this.generateFingerprint(
      'prediction',
      String(prediction.metricName || 'unknown'),
      String(prediction.businessId || '')
    );

    const alert: Alert = {
      id: alertId,
      ruleId: crypto.randomUUID(),
      businessId: String(prediction.businessId || ''),
      title: `Predicted Issue: ${prediction.issueType || 'unknown'}`,
      description: String(prediction.description || 'Predicted issue detected'),
      severity: (prediction.severity as 'low' | 'medium' | 'high' | 'critical') || 'medium',
      status: 'firing',
      triggeredAt: new Date(),
      labels: {
        type: 'prediction',
        issueType: String(prediction.issueType || 'unknown'),
        confidence: String(prediction.confidence || '0')
      },
      annotations: {
        futureTimestamp: String(prediction.timestamp || ''),
        model: String(prediction.model || ''),
        recommendedActions: JSON.stringify(prediction.recommendedActions || [])
      },
      fingerprint,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await this.persistAlert(alert);
    return alert;
  }

  private async createRCAAlert(rca: Record<string, unknown>): Promise<Alert> {
    const alertId = crypto.randomUUID();
    const fingerprint = this.generateFingerprint(
      'rca',
      String(rca.rootCause || 'unknown'),
      String(rca.businessId || '')
    );

    const alert: Alert = {
      id: alertId,
      ruleId: crypto.randomUUID(),
      businessId: String(rca.businessId || ''),
      title: `Root Cause Identified: ${rca.rootCause || 'unknown'}`,
      description: `Root cause analysis identified: ${rca.rootCause || 'unknown'}`,
      severity: 'medium',
      status: 'firing',
      triggeredAt: new Date(),
      labels: {
        type: 'rca',
        rootCause: String(rca.rootCause || 'unknown'),
        confidence: String(rca.confidence || '0')
      },
      annotations: {
        contributingFactors: JSON.stringify(rca.contributingFactors || []),
        remediation: JSON.stringify(rca.remediation || []),
        timeline: JSON.stringify(rca.timeline || [])
      },
      fingerprint,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await this.persistAlert(alert);
    return alert;
  }

  async analyzeCostIntelligence(businessId: string): Promise<Record<string, unknown> | null> {
    const costData = await this.getCostData(businessId);

    const prompt = `
    Analyze the following cost data for intelligence insights:

    ${JSON.stringify(costData)}

    Provide analysis for:
    1. Cost breakdown by service/feature/user
    2. Cost anomalies and spikes
    3. Budget forecasting for next 30 days
    4. Optimization opportunities
    5. What-if scenarios for cost reduction

    Return structured JSON with:
    - breakdown: per-service cost analysis
    - anomalies: unusual cost patterns
    - forecast: 30-day cost prediction
    - optimizations: cost saving recommendations
    - insights: key findings and trends
    `;

    try {
      const response = await this.aiClient.generateText(prompt);
      return JSON.parse(response) as Record<string, unknown>;
    } catch (error: unknown) {
      logger.error('Cost intelligence analysis failed:', error);
      return null;
    }
  }

  async analyzePerformanceIntelligence(businessId: string): Promise<Record<string, unknown> | null> {
    const perfData = await this.getPerformanceData(businessId);

    const prompt = `
    Analyze the following performance data for intelligence insights:

    ${JSON.stringify(perfData)}

    Provide analysis for:
    1. Bottleneck detection
    2. Query optimization suggestions
    3. Cache effectiveness
    4. Capacity planning predictions
    5. SLA violation analysis
    6. Auto-scaling recommendations

    Return structured JSON with actionable insights.
    `;

    try {
      const response = await this.aiClient.generateText(prompt);
      return JSON.parse(response) as Record<string, unknown>;
    } catch (error: unknown) {
      logger.error('Performance intelligence analysis failed:', error);
      return null;
    }
  }

  // Helper methods

  private async getMetricsForAnalysis(businessId: string, since: Date): Promise<Array<Record<string, unknown>>> {
    const result = await this.db.prepare(`
      SELECT metric_name, value, timestamp, labels
      FROM metrics
      WHERE business_id = ? AND timestamp >= ?
      ORDER BY timestamp DESC
      LIMIT 10000
    `).bind(businessId, since.toISOString()).all();

    return (result.results as Array<Record<string, unknown>>) || [];
  }

  private async getRecentIncidents(businessId: string): Promise<Array<Record<string, unknown>>> {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000); // Last 24 hours

    const result = await this.db.prepare(`
      SELECT * FROM log_entries
      WHERE business_id = ?
        AND timestamp >= ?
        AND (level = 'ERROR' OR level = 'CRITICAL' OR status_code >= 500)
      ORDER BY timestamp DESC
      LIMIT 100
    `).bind(businessId, since.toISOString()).all();

    return (result.results as Array<Record<string, unknown>>) || [];
  }

  private async getContextualData(
    businessId: string,
    startTime: Date,
    endTime: Date
  ): Promise<{
    logs: Array<Record<string, unknown>>;
    metrics: Array<Record<string, unknown>>;
    traces: Array<Record<string, unknown>>;
  }> {
    const [logs, metrics, traces] = await Promise.all([
      this.db.prepare(`
        SELECT * FROM log_entries
        WHERE business_id = ? AND timestamp BETWEEN ? AND ?
        ORDER BY timestamp
      `).bind(businessId, startTime.toISOString(), endTime.toISOString()).all(),

      this.db.prepare(`
        SELECT * FROM metrics
        WHERE business_id = ? AND timestamp BETWEEN ? AND ?
        ORDER BY timestamp
      `).bind(businessId, startTime.toISOString(), endTime.toISOString()).all(),

      this.db.prepare(`
        SELECT * FROM traces
        WHERE business_id = ? AND start_time BETWEEN ? AND ?
        ORDER BY start_time
      `).bind(businessId, startTime.toISOString(), endTime.toISOString()).all()
    ]);

    return {
      logs: (logs.results as Array<Record<string, unknown>>) || [],
      metrics: (metrics.results as Array<Record<string, unknown>>) || [],
      traces: (traces.results as Array<Record<string, unknown>>) || []
    };
  }

  private async getCostData(businessId: string): Promise<Array<Record<string, unknown>>> {
    const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // Last 30 days

    const result = await this.db.prepare(`
      SELECT * FROM cost_tracking
      WHERE business_id = ? AND timestamp >= ?
      ORDER BY timestamp DESC
    `).bind(businessId, since.toISOString()).all();

    return (result.results as Array<Record<string, unknown>>) || [];
  }

  private async getPerformanceData(businessId: string): Promise<Array<Record<string, unknown>>> {
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // Last 7 days

    const result = await this.db.prepare(`
      SELECT * FROM service_performance
      WHERE business_id = ? AND timestamp >= ?
      ORDER BY timestamp DESC
    `).bind(businessId, since.toISOString()).all();

    return (result.results as Array<Record<string, unknown>>) || [];
  }

  private getZScoreThreshold(sensitivity: number): number {
    // Convert sensitivity (0-1) to Z-score threshold
    // Higher sensitivity = lower threshold
    return 3 - (sensitivity * 1.5); // Range: 1.5 to 3
  }

  private async persistAnomaly(anomaly: Partial<Anomaly>): Promise<string> {
    const id = crypto.randomUUID();

    await this.db.prepare(`
      INSERT INTO anomalies (
        id, business_id, timestamp, metric_name, actual_value,
        predicted_value, anomaly_score, severity, confidence,
        labels, explanation, reviewed
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      anomaly.businessId,
      anomaly.timestamp?.toISOString(),
      anomaly.metricName,
      anomaly.actualValue,
      anomaly.predictedValue,
      anomaly.anomalyScore,
      anomaly.severity,
      anomaly.confidence,
      JSON.stringify(anomaly.labels),
      anomaly.explanation,
      anomaly.reviewed
    ).run();

    return id;
  }

  private async persistAlert(alert: Alert): Promise<void> {
    await this.db.prepare(`
      INSERT INTO alerts (
        id, rule_id, business_id, title, description, severity, status,
        triggered_at, metric_value, labels, annotations, fingerprint,
        created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      alert.id,
      alert.ruleId,
      alert.businessId,
      alert.title,
      alert.description,
      alert.severity,
      alert.status,
      alert.triggeredAt.toISOString(),
      alert.metricValue,
      JSON.stringify(alert.labels),
      JSON.stringify(alert.annotations),
      alert.fingerprint,
      alert.createdAt.toISOString(),
      alert.updatedAt.toISOString()
    ).run();
  }

  private generateFingerprint(type: string, identifier: string, businessId: string): string {
    const data = `${type}:${identifier}:${businessId}`;
    return btoa(data).replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
  }

  // Public API methods required by routes
  async getSummary(options: {
    businessId: string;
    startDate?: Date;
    endDate?: Date;
  }): Promise<Record<string, unknown>> {
    const startDate = options.startDate || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const endDate = options.endDate || new Date();

    const [anomalies, alerts, metrics] = await Promise.all([
      this.db.prepare(`
        SELECT COUNT(*) as count, severity
        FROM anomalies
        WHERE business_id = ? AND timestamp BETWEEN ? AND ?
        GROUP BY severity
      `).bind(options.businessId, startDate.toISOString(), endDate.toISOString()).all(),

      this.db.prepare(`
        SELECT COUNT(*) as count, status, severity
        FROM alerts
        WHERE business_id = ? AND triggered_at BETWEEN ? AND ?
        GROUP BY status, severity
      `).bind(options.businessId, startDate.toISOString(), endDate.toISOString()).all(),

      this.db.prepare(`
        SELECT COUNT(*) as count
        FROM metrics
        WHERE business_id = ? AND timestamp BETWEEN ? AND ?
      `).bind(options.businessId, startDate.toISOString(), endDate.toISOString()).all()
    ]);

    const anomalyTotal = anomalies.results?.reduce(
      (sum: number, row: any) => sum + (Number(row.count) || 0),
      0
    ) || 0;

    const alertTotal = alerts.results?.reduce(
      (sum: number, row: any) => sum + (Number(row.count) || 0),
      0
    ) || 0;

    return {
      period: {
        start: startDate.toISOString(),
        end: endDate.toISOString()
      },
      anomalies: {
        total: anomalyTotal,
        bySeverity: anomalies.results || []
      },
      alerts: {
        total: alertTotal,
        byStatus: alerts.results || []
      },
      metrics: {
        total: (metrics.results?.[0] as any)?.count || 0
      }
    };
  }

  async getMetrics(options: {
    businessId: string;
    startDate?: Date;
    endDate?: Date;
    metricNames?: string[];
  }): Promise<Array<Record<string, unknown>>> {
    const startDate = options.startDate || new Date(Date.now() - 24 * 60 * 60 * 1000);
    const endDate = options.endDate || new Date();

    let query = `
      SELECT metric_name, value, timestamp, labels
      FROM metrics
      WHERE business_id = ? AND timestamp BETWEEN ? AND ?
    `;

    const params = [options.businessId, startDate.toISOString(), endDate.toISOString()];

    if (options.metricNames && options.metricNames.length > 0) {
      query += ` AND metric_name IN (${options.metricNames.map(() => '?').join(',')})`;
      params.push(...options.metricNames);
    }

    query += ` ORDER BY timestamp DESC LIMIT 10000`;

    const result = await this.db.prepare(query).bind(...params).all();
    return (result.results as Array<Record<string, unknown>>) || [];
  }

  async getCostAnalysis(options: {
    businessId: string;
    startDate?: Date;
    endDate?: Date;
  }): Promise<Record<string, unknown>> {
    const startDate = options.startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const endDate = options.endDate || new Date();

    const costData = await this.db.prepare(`
      SELECT
        SUM(cost_cents) as total_cost,
        AVG(cost_cents) as avg_cost,
        COUNT(*) as transaction_count,
        ai_provider,
        ai_model
      FROM cost_tracking
      WHERE business_id = ? AND timestamp BETWEEN ? AND ?
      GROUP BY ai_provider, ai_model
    `).bind(options.businessId, startDate.toISOString(), endDate.toISOString()).all();

    const totalCostCents: number = (costData.results || []).reduce(
      (sum: number, row: any) => sum + (Number(row.total_cost) || 0),
      0
    );

    return {
      period: {
        start: startDate.toISOString(),
        end: endDate.toISOString()
      },
      totalCost: totalCostCents / 100, // Convert cents to dollars
      breakdown: costData.results || [],
      analysis: await this.analyzeCostIntelligence(options.businessId)
    };
  }

  async getHealth(): Promise<Record<string, unknown>> {
    try {
      // Simple health check - verify database connection
      await this.db.prepare('SELECT 1').all();

      return {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        checks: {
          database: 'ok',
          aiClient: 'ok'
        }
      };
    } catch (error: unknown) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
        checks: {
          database: 'error',
          aiClient: 'unknown'
        }
      };
    }
  }
}