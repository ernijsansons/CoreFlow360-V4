// CoreFlow360 V4 - Real-time Dashboard Streaming Durable Object
import { StreamMetrics } from '../types/observability';
import { StorageMonitor } from '../shared/storage-monitor';
import { BoundedMap, BoundedSet } from '../shared/bounded-collections';
import { Logger } from '../shared/logger';

export class DashboardStream {
  private state: DurableObjectState;
  private env: any;
  private subscribers: BoundedMap<string, WebSocket>;
  private subscriptions: BoundedMap<string, any>;
  private storageMonitor: StorageMonitor;
  private logger: Logger;
  private recentQueries: BoundedSet<string>;

  constructor(state: DurableObjectState, env: any) {
    this.state = state;
    this.env = env;
    this.logger = new Logger();

    // Initialize bounded collections to prevent unbounded growth
    this.subscribers = new BoundedMap<string, WebSocket>(500, (connectionId, webSocket) => {
      this.logger.warn('WebSocket connection evicted due to capacity limit', { connectionId });
      try {
        webSocket.close(1008, 'Connection limit reached');
      } catch (error: any) {
        this.logger.debug('Failed to close evicted WebSocket', { connectionId, error });
      }
    });

    this.subscriptions = new BoundedMap<string, any>(500, (connectionId) => {
      this.logger.warn('Subscription evicted due to capacity limit', { connectionId });
    });

    this.recentQueries = new BoundedSet<string>(1000, (query) => {
      this.logger.debug('Query evicted from recent queries cache', { queryHash: query.slice(0, 50) });
    });

    // Initialize storage monitoring
    this.storageMonitor = new StorageMonitor(this.state.storage);

    // Set up automatic storage monitoring every 5 minutes
    this.setupStorageMonitoring();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/websocket') {
      return this.handleWebSocketUpgrade(request);
    }

    if (url.pathname === '/metrics') {
      return this.handleMetricsRequest(request);
    }

    return new Response('Not found', { status: 404 });
  }

  private async handleWebSocketUpgrade(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    await this.handleWebSocketConnection(server, request);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  private async handleWebSocketConnection(webSocket: WebSocket, request: Request): Promise<void> {
    const url = new URL(request.url);
    const connectionId = crypto.randomUUID();

    // Extract subscription parameters
    const businessId = url.searchParams.get('businessId');
    const metrics = url.searchParams.get('metrics')?.split(',') || ['latency', 'errors', 'cost', 'traffic'];
    const granularity = url.searchParams.get('granularity') || '30s';

    if (!businessId) {
      webSocket.close(1008, 'Missing businessId parameter');
      return;
    }

    // Store connection
    this.subscribers.set(connectionId, webSocket);

    // Set up subscription
    const subscription = {
      connectionId,
      businessId,
      metrics,
      granularity,
      aggregations: ['p50', 'p95', 'p99', 'sum', 'count'],
      lastUpdate: new Date()
    };

    this.subscriptions.set(connectionId, subscription);

    // Send initial data
    await this.sendInitialData(connectionId);

    // Start streaming
    await this.startStreaming(connectionId);

    webSocket.addEventListener('message', async (event: any) => {
      await this.handleWebSocketMessage(connectionId, event.data);
    });

    webSocket.addEventListener('close', () => {
      this.subscribers.delete(connectionId);
      this.subscriptions.delete(connectionId);
    });

    webSocket.addEventListener('error', () => {
      this.subscribers.delete(connectionId);
      this.subscriptions.delete(connectionId);
    });

    webSocket.accept();
  }

  private async sendInitialData(connectionId: string): Promise<void> {
    const subscription = this.subscriptions.get(connectionId);
    if (!subscription) return;

    const webSocket = this.subscribers.get(connectionId);
    if (!webSocket) return;

    try {
      // Get recent metrics for initial load
      const initialData = await this.getInitialMetrics(subscription.businessId, subscription.metrics);

      const message = {
        type: 'initial',
        timestamp: new Date().toISOString(),
        data: initialData
      };

      webSocket.send(JSON.stringify(message));

    } catch (error: any) {
      this.logger.error('Failed to send initial data', error, { connectionId });
    }
  }

  private async startStreaming(connectionId: string): Promise<void> {
    const subscription = this.subscriptions.get(connectionId);
    if (!subscription) return;

    try {
      // Set up interval for streaming updates
      const interval = this.getIntervalMs(subscription.granularity);

      const streamConfig = {
        interval,
        nextUpdate: Date.now() + interval,
        connectionId,
        businessId: subscription.businessId,
        startedAt: Date.now()
      };

      // Use compressed storage for efficiency
      const { compressed } = await this.storageMonitor.compressStorageValue(
        `stream:${connectionId}`,
        streamConfig
      );

      // Check storage limits before writing
      const metrics = await this.storageMonitor.getStorageMetrics();
      if (metrics.utilizationPercentage > 90) {
        this.logger.warn('Storage near capacity, cleaning up old streams');
        await this.storageMonitor.performCleanup({
          keyPatterns: ['stream:'],
          maxAge: 30 * 60 * 1000, // 30 minutes
          maxItems: 50
        });
      }

      await this.state.storage.put(`stream:${connectionId}`, JSON.parse(compressed));
      await this.state.storage.setAlarm(Date.now() + interval);

      this.logger.debug('Stream configuration stored', {
        connectionId,
        interval,
        storageUtilization: metrics.utilizationPercentage
      });

    } catch (error: any) {
      this.logger.error('Failed to start streaming', { connectionId, error });
      throw error;
    }
  }

  async alarm(): Promise<void> {
    // Handle streaming alarms
    const activeStreams = await this.state.storage.list({ prefix: 'stream:' });

    for (const [key, streamConfig] of activeStreams) {
      const connectionId = key.split(':')[1];
      const subscription = this.subscriptions.get(connectionId);

      if (!subscription) {
        await this.state.storage.delete(key);
        continue;
      }

      await this.sendStreamUpdate(connectionId);

      // Schedule next update
      const nextUpdate = Date.now() + (streamConfig as any).interval;
      await this.state.storage.put(key, {
        ...(streamConfig as any),
        nextUpdate
      });
    }

    // Set next alarm
    const nextAlarmTime = Math.min(
      ...Array.from(activeStreams.values()).map((config: any) => config.nextUpdate)
    );

    if (nextAlarmTime < Infinity) {
      await this.state.storage.setAlarm(nextAlarmTime);
    }
  }

  private async sendStreamUpdate(connectionId: string): Promise<void> {
    const subscription = this.subscriptions.get(connectionId);
    const webSocket = this.subscribers.get(connectionId);

    if (!subscription || !webSocket) return;

    try {
      // Get latest metrics
      const metrics = await this.getLatestMetrics(
        subscription.businessId,
        subscription.metrics,
        subscription.lastUpdate
      );

      if (metrics.length > 0) {
        // Enrich with ML insights
        const enrichedMetrics = await this.enrichWithML(metrics);

        const message: StreamMetrics = {
          type: 'metrics',
          data: enrichedMetrics,
          timestamp: new Date(),
          metadata: {
            granularity: subscription.granularity,
            metricsCount: metrics.length
          }
        };

        webSocket.send(JSON.stringify(message));
        subscription.lastUpdate = new Date();
      }

    } catch (error: any) {
      this.logger.error('Failed to send stream update', error, { connectionId });
    }
  }

  private async handleWebSocketMessage(connectionId: string, message: string): Promise<void> {
    try {
      const data = JSON.parse(message);
      const subscription = this.subscriptions.get(connectionId);

      if (!subscription) return;

      switch (data.type) {
        case 'subscribe':
          // Update subscription
          subscription.metrics = data.metrics || subscription.metrics;
          subscription.granularity = data.granularity || subscription.granularity;
          break;

        case 'unsubscribe':
          this.subscribers.delete(connectionId);
          this.subscriptions.delete(connectionId);
          break;

        case 'query':
          // Handle ad-hoc queries
          await this.handleAdHocQuery(connectionId, data.query);
          break;

        case 'alert_ack':
          // Handle alert acknowledgment
          await this.handleAlertAcknowledgment(connectionId, data.alertId);
          break;
      }

    } catch (error: any) {
      this.logger.error('Failed to handle WebSocket message', error, { connectionId });
    }
  }

  private async handleAdHocQuery(connectionId: string, query: any): Promise<void> {
    const webSocket = this.subscribers.get(connectionId);
    if (!webSocket) return;

    try {
      const result = await this.executeQuery(query);

      const response = {
        type: 'query_result',
        queryId: query.id,
        data: result,
        timestamp: new Date().toISOString()
      };

      webSocket.send(JSON.stringify(response));

    } catch (error: any) {
      const response = {
        type: 'query_error',
        queryId: query.id,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      };

      webSocket.send(JSON.stringify(response));
    }
  }

  private async handleAlertAcknowledgment(connectionId: string, alertId: string): Promise<void> {
    // Update alert status
    await this.env.DB.prepare(`
      UPDATE alerts
      SET status = 'acknowledged'
      WHERE id = ?
    `).bind(alertId).run();

    // Broadcast to all subscribers
    const response = {
      type: 'alert_acknowledged',
      alertId,
      timestamp: new Date().toISOString()
    };

    this.broadcastToAll(JSON.stringify(response));
  }

  private async handleMetricsRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const businessId = url.searchParams.get('businessId');

    if (!businessId) {
      return new Response('Missing businessId', { status: 400 });
    }

    try {
      const metrics = await this.getLatestMetrics(businessId, ['latency', 'errors', 'cost', 'traffic']);

      return new Response(JSON.stringify({
        success: true,
        data: metrics,
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json' }
      });

    } catch (error: any) {
      return new Response(JSON.stringify({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  private async getInitialMetrics(businessId: string, metrics: string[]): Promise<any> {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000); // Last 24 hours

    const results = await Promise.all([
      this.getMetricHistory(businessId, metrics, since),
      this.getActiveAlerts(businessId),
      this.getServiceHealth(businessId),
      this.getCostSummary(businessId)
    ]);

    return {
      metrics: results[0],
      alerts: results[1],
      serviceHealth: results[2],
      costSummary: results[3],
      timestamp: new Date().toISOString()
    };
  }

  private async getLatestMetrics(businessId: string, metrics: string[], since?: Date): Promise<any[]> {
    const sinceDate = since || new Date(Date.now() - 5 * 60 * 1000); // Last 5 minutes

    const result = await this.env.DB.prepare(`
      SELECT
        metric_name,
        value,
        timestamp,
        labels
      FROM metrics
      WHERE business_id = ?
        AND metric_name IN (${metrics.map(() => '?').join(',')})
        AND timestamp >= ?
      ORDER BY timestamp DESC
      LIMIT 1000
    `).bind(businessId, ...metrics, sinceDate.toISOString()).all();

    return result.results;
  }

  private async getMetricHistory(businessId: string, metrics: string[], since: Date): Promise<any[]> {
    const result = await this.env.DB.prepare(`
      SELECT
        ma.metric_name,
        ma.timestamp,
        ma.aggregation_period,
        ma.count,
        ma.sum,
        ma.avg,
        ma.p50,
        ma.p95,
        ma.p99,
        ma.labels
      FROM metric_aggregations ma
      WHERE ma.business_id = ?
        AND ma.metric_name IN (${metrics.map(() => '?').join(',')})
        AND ma.timestamp >= ?
        AND ma.aggregation_period = '5m'
      ORDER BY ma.timestamp DESC
      LIMIT 1000
    `).bind(businessId, ...metrics, since.toISOString()).all();

    return result.results;
  }

  private async getActiveAlerts(businessId: string): Promise<any[]> {
    const result = await this.env.DB.prepare(`
      SELECT * FROM active_alerts
      WHERE business_id = ?
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
        END,
        triggered_at DESC
      LIMIT 100
    `).bind(businessId).all();

    return result.results;
  }

  private async getServiceHealth(businessId: string): Promise<any[]> {
    const since = new Date(Date.now() - 60 * 60 * 1000); // Last hour

    const result = await this.env.DB.prepare(`
      SELECT
        service_name,
        AVG(avg_latency_ms) as avg_latency,
        SUM(request_count) as total_requests,
        SUM(error_count) as total_errors,
        ROUND((SUM(error_count) * 100.0) / SUM(request_count), 2) as error_rate
      FROM service_performance
      WHERE business_id = ? AND timestamp >= ?
      GROUP BY service_name
    `).bind(businessId, since.toISOString()).all();

    return result.results;
  }

  private async getCostSummary(businessId: string): Promise<any> {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000); // Last 24 hours

    const result = await this.env.DB.prepare(`
      SELECT
        SUM(cost_cents) / 100.0 as total_cost_dollars,
        COUNT(*) as request_count,
        AVG(cost_cents) / 100.0 as avg_cost_per_request,
        ai_provider,
        ai_model
      FROM cost_tracking
      WHERE business_id = ? AND timestamp >= ?
      GROUP BY ai_provider, ai_model
      ORDER BY total_cost_dollars DESC
    `).bind(businessId, since.toISOString()).all();

    return {
      providers: result.results,
      totalCost: result.results.reduce((sum: number, item: any) => sum + item.total_cost_dollars, 0)
    };
  }

  private async enrichWithML(metrics: any[]): Promise<any[]> {
    // Add ML-powered insights to metrics
    try {
      for (const metric of metrics) {
        // Add trend analysis
        metric.trend = await this.calculateTrend(metric);

        // Add anomaly score
        metric.anomalyScore = await this.getAnomalyScore(metric);

        // Add predictions
        metric.predictions = await this.getPredictions(metric);
      }

      return metrics;

    } catch (error: any) {
      this.logger.error('Failed to enrich metrics with ML', error);
      return metrics;
    }
  }

  private async calculateTrend(metric: any): Promise<string> {
    // Simple trend calculation - in production this would use more sophisticated algorithms
    const recent = await this.env.DB.prepare(`
      SELECT value FROM metrics
      WHERE metric_name = ? AND timestamp >= ?
      ORDER BY timestamp DESC
      LIMIT 10
    `).bind(metric.metric_name, new Date(Date.now() - 30 * 60 * 1000).toISOString()).all();

    if (recent.results.length < 3) return 'stable';

    const values = recent.results.map((r: any) => r.value);
    const firstHalf = values.slice(0, Math.floor(values.length / 2));
    const secondHalf = values.slice(Math.floor(values.length / 2));

    const firstAvg = firstHalf.reduce((a: number, b: number) => a + b, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((a: number, b: number) => a + b, 0) / secondHalf.length;

    const change = (secondAvg - firstAvg) / firstAvg;

    if (change > 0.1) return 'increasing';
    if (change < -0.1) return 'decreasing';
    return 'stable';
  }

  private async getAnomalyScore(metric: any): Promise<number> {
    // Check if there's a recent anomaly for this metric
    const anomaly = await this.env.DB.prepare(`
      SELECT anomaly_score FROM anomalies
      WHERE metric_name = ? AND timestamp >= ?
      ORDER BY timestamp DESC
      LIMIT 1
    `).bind(metric.metric_name, new Date(Date.now() - 5 * 60 * 1000).toISOString()).first();

    return anomaly?.anomaly_score || 0;
  }

  private async getPredictions(metric: any): Promise<any> {
    // Simplified prediction - in production this would use trained models
    return {
      next5min: metric.value * (1 + (Math.random() - 0.5) * 0.1),
      confidence: 0.7
    };
  }

  private async executeQuery(query: any): Promise<any> {
    const { sql, params, businessId } = query;

    // Security: Only allow SELECT queries
    if (!sql.trim().toUpperCase().startsWith('SELECT')) {
      throw new Error('Only SELECT queries are allowed');
    }

    // Create query hash for tracking
    const queryHash = await this.hashQuery(sql, params);

    // Check for query flooding (same query executed too frequently)
    if (this.recentQueries.has(queryHash)) {
      this.logger.warn('Duplicate query detected within recent timeframe', {
        queryHash: queryHash.slice(0, 16),
        businessId
      });
      throw new Error('Query rate limit exceeded - duplicate query detected');
    }

    // Track this query
    this.recentQueries.add(queryHash);

    // Add business_id filter if not present for security
    let finalSql = sql;
    let finalParams = params || [];

    if (!sql.includes('business_id')) {
      finalSql += ' WHERE business_id = ?';
      finalParams.push(businessId);
    }

    // Execute with timeout
    try {
      const result = await Promise.race([
        this.env.DB.prepare(finalSql).bind(...finalParams).all(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Query timeout (10s)')), 10000)
        )
      ]) as any;

      this.logger.debug('Query executed successfully', {
        queryHash: queryHash.slice(0, 16),
        resultCount: result.results?.length || 0,
        businessId
      });

      return result.results;

    } catch (error: any) {
      this.logger.error('Query execution failed', {
        queryHash: queryHash.slice(0, 16),
        error: error instanceof Error ? error.message : String(error),
        businessId
      });
      throw error;
    }
  }

  private async hashQuery(sql: string, params: any[]): Promise<string> {
    const queryString = sql + JSON.stringify(params || []);
    const encoder = new TextEncoder();
    const data = encoder.encode(queryString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b: any) => b.toString(16).padStart(2, '0')).join('');
  }

  private broadcastToAll(message: string): void {
    for (const webSocket of this.subscribers.values()) {
      try {
        webSocket.send(message);
      } catch (error: any) {
        this.logger.error('Failed to broadcast message', error);
      }
    }
  }

  private getIntervalMs(granularity: string): number {
    const intervals: Record<string, number> = {
      '1s': 1000,
      '5s': 5000,
      '10s': 10000,
      '30s': 30000,
      '1m': 60000,
      '5m': 5 * 60000,
      '15m': 15 * 60000
    };

    return intervals[granularity] || 30000; // Default to 30s
  }

  private async setupStorageMonitoring(): Promise<void> {
    try {
      // Check storage health on startup
      const summary = await this.storageMonitor.getStorageSummary();

      if (summary.status === 'critical') {
        this.logger.error('CRITICAL: Dashboard stream storage at capacity', {
          utilization: summary.metrics.utilizationPercentage,
          keyCount: summary.metrics.keyCount,
          alerts: summary.alerts.length
        });

        // Perform emergency cleanup
        await this.performEmergencyCleanup();
      } else if (summary.status === 'warning') {
        this.logger.warn('Dashboard stream storage approaching limits', {
          utilization: summary.metrics.utilizationPercentage,
          recommendations: summary.recommendations
        });
      }

      // Set up periodic storage monitoring (every 5 minutes)
      this.storageMonitor.setupAutomaticMonitoring(5 * 60 * 1000);

    } catch (error: any) {
      this.logger.error('Failed to setup storage monitoring', error);
    }
  }

  private async performEmergencyCleanup(): Promise<void> {
    try {
      this.logger.info('Performing emergency storage cleanup');

      // Clean up expired stream configurations (older than 1 hour)
      const result = await this.storageMonitor.performCleanup({
        maxAge: 60 * 60 * 1000, // 1 hour
        keyPatterns: ['stream:', 'temp:', 'cache:'],
        maxItems: 200
      });

      this.logger.info('Emergency cleanup completed', {
        itemsRemoved: result.itemsRemoved,
        bytesFreed: result.bytesFreed,
        success: result.success
      });

      // Clear in-memory caches
      if (this.subscribers.size > 100) {
        this.logger.warn('Clearing excess WebSocket connections');
        const connectionsToClose = Array.from(this.subscribers.keys()).slice(100);
        for (const connectionId of connectionsToClose) {
          const ws = this.subscribers.get(connectionId);
          if (ws) {
            ws.close(1008, 'Storage capacity management');
          }
          this.subscribers.delete(connectionId);
          this.subscriptions.delete(connectionId);
        }
      }

    } catch (error: any) {
      this.logger.error('Emergency cleanup failed', error);
    }
  }
}