import { AnalyticsData, DashboardConfig, WidgetConfig } from '../../types/telemetry';
import { TelemetryCollector } from './collector';
import { MetricsCollector } from './metrics';
import { AIAlertEngine } from './ai-analytics';

interface DashboardSubscription {
  id: string;
  businessId: string;
  websocket: WebSocket;
  config: DashboardConfig;
  lastUpdate: number;
  filters: Record<string, any>;
}

interface MetricUpdate {
  type: 'metrics' | 'alert' | 'trace' | 'log';
  timestamp: number;
  data: any;
  subscription: string;
}

interface AlertUpdate {
  type: 'alert';
  alert: any;
  severity: string;
  timestamp: number;
}

export class DashboardStream {
  private collector: TelemetryCollector;
  private metrics: MetricsCollector;
  private aiEngine: AIAlertEngine;
  private subscriptions: Map<string, DashboardSubscription> = new Map();
  private updateInterval: number = 1000; // 1 second
  private batchSize: number = 100;

  constructor(
    collector: TelemetryCollector,
    metrics: MetricsCollector,
    aiEngine: AIAlertEngine
  ) {
    this.collector = collector;
    this.metrics = metrics;
    this.aiEngine = aiEngine;
    this.startStreamingLoop();
  }

  async subscribe(
    websocket: WebSocket,
    businessId: string,
    config: DashboardConfig
  ): Promise<string> {
    const subscriptionId = crypto.randomUUID();

    const subscription: DashboardSubscription = {
      id: subscriptionId,
      businessId,
      websocket,
      config,
      lastUpdate: Date.now(),
      filters: config.filters || {}
    };

    this.subscriptions.set(subscriptionId, subscription);

    // Send initial data
    await this.sendInitialData(subscription);

    // Handle WebSocket close
    websocket.addEventListener('close', () => {
      this.subscriptions.delete(subscriptionId);
    });

    websocket.addEventListener('message', (event) => {
      this.handleWebSocketMessage(subscriptionId, JSON.parse(event.data));
    });

    return subscriptionId;
  }

  private async sendInitialData(subscription: DashboardSubscription): Promise<void> {
    const { config, businessId } = subscription;

    // Send dashboard layout
    this.sendMessage(subscription, {
      type: 'dashboard_config',
      data: config
    });

    // Send initial metrics for each widget
    for (const widget of config.layout) {
      const data = await this.getWidgetData(widget.widget, businessId, config.timeRange);
      this.sendMessage(subscription, {
        type: 'widget_data',
        widgetId: widget.i,
        data
      });
    }

    // Send current alerts
    const alerts = await this.aiEngine.analyzeMetrics(businessId);
    this.sendMessage(subscription, {
      type: 'alerts',
      data: alerts
    });
  }

  private async handleWebSocketMessage(subscriptionId: string, message: any): Promise<void> {
    const subscription = this.subscriptions.get(subscriptionId);
    if (!subscription) return;

    switch (message.type) {
      case 'update_filters':
        subscription.filters = { ...subscription.filters, ...message.filters };
        await this.sendInitialData(subscription);
        break;

      case 'update_time_range':
        subscription.config.timeRange = message.timeRange;
        await this.sendInitialData(subscription);
        break;

      case 'query':
        const result = await this.executeQuery(message.query, subscription.businessId);
        this.sendMessage(subscription, {
          type: 'query_result',
          queryId: message.queryId,
          data: result
        });
        break;

      case 'export':
        await this.handleExportRequest(subscription, message);
        break;
    }
  }

  private async getWidgetData(widget: WidgetConfig, businessId: string, timeRange: any): Promise<any> {
    switch (widget.type) {
      case 'chart':
        return this.getChartData(widget, businessId, timeRange);
      case 'table':
        return this.getTableData(widget, businessId, timeRange);
      case 'stat':
        return this.getStatData(widget, businessId, timeRange);
      case 'heatmap':
        return this.getHeatmapData(widget, businessId, timeRange);
      case 'topology':
        return this.getTopologyData(widget, businessId, timeRange);
      case 'alert-list':
        return this.getAlertListData(widget, businessId, timeRange);
      default:
        return {};
    }
  }

  private async getChartData(widget: WidgetConfig, businessId: string, timeRange: any): Promise<any> {
    const metrics = await this.collector.getMetrics(businessId, timeRange);

    const series = metrics.map(m => ({
      timestamp: m.timestamp,
      value: this.extractValue(m, widget.query),
      dimensions: m.dimensions
    }));

    return {
      type: 'time-series',
      series: [{
        name: widget.title,
        data: series.map(s => [s.timestamp, s.value])
      }],
      aggregation: widget.visualization?.aggregation || 'avg'
    };
  }

  private async getTableData(widget: WidgetConfig, businessId: string, timeRange: any): Promise<any> {
    const results = await this.collector.query(widget.query);

    return {
      type: 'table',
      columns: Object.keys(results[0] || {}),
      rows: results.slice(0, 1000) // Limit to 1000 rows
    };
  }

  private async getStatData(widget: WidgetConfig, businessId: string, timeRange: any): Promise<any> {
    const metrics = await this.collector.getMetrics(businessId, timeRange);

    if (metrics.length === 0) {
      return { type: 'stat', value: 0, unit: '', trend: 'neutral' };
    }

    const values = metrics.map(m => this.extractValue(m, widget.query));
    const currentValue = values[values.length - 1];
    const previousValue = values[Math.floor(values.length * 0.8)] || currentValue;

    const trend = currentValue > previousValue ? 'up' :
                 currentValue < previousValue ? 'down' : 'neutral';

    return {
      type: 'stat',
      value: currentValue,
      unit: this.getUnit(widget.query),
      trend,
      change: previousValue ? ((currentValue - previousValue) / previousValue * 100) : 0
    };
  }

  private async getHeatmapData(widget: WidgetConfig, businessId: string, timeRange: any): Promise<any> {
    // Validate inputs to prevent injection
    if (!this.isValidBusinessId(businessId)) {
      throw new Error('Invalid business ID format');
    }
    if (!this.isValidTimeRange(timeRange)) {
      throw new Error('Invalid time range format');
    }

    const sql = `
      SELECT
        toStartOfHour(event_time) as hour,
        JSONExtract(properties, 'path', 'String') as path,
        AVG(JSONExtract(metrics, 'latencyMs', 'Float64')) as avg_latency
      FROM telemetry_events
      WHERE business_id = ?
        AND event_time BETWEEN ? AND ?
      GROUP BY hour, path
      ORDER BY hour, path
    `;

    const results = await this.collector.queryWithParams(sql, [businessId, timeRange.start, timeRange.end]);

    const hours = [...new Set(results.map(r => r.hour))].sort();
    const paths = [...new Set(results.map(r => r.path))].sort();

    const data = hours.map(hour =>
      paths.map(path => {
        const result = results.find(r => r.hour === hour && r.path === path);
        return result ? result.avg_latency : 0;
      })
    );

    return {
      type: 'heatmap',
      data,
      xLabels: paths,
      yLabels: hours
    };
  }

  private async getTopologyData(widget: WidgetConfig, businessId: string, timeRange: any): Promise<any> {
    const sql = `
      SELECT
        JSONExtract(properties, 'module', 'String') as source,
        JSONExtract(properties, 'capability', 'String') as target,
        COUNT(*) as requests,
        AVG(JSONExtract(metrics, 'latencyMs', 'Float64')) as avg_latency
      FROM telemetry_events
      WHERE business_id = '${businessId}'
        AND event_time BETWEEN '${timeRange.start}' AND '${timeRange.end}'
      GROUP BY source, target
    `;

    const results = await this.collector.query(sql);

    const nodes = new Set<string>();
    results.forEach(r => {
      nodes.add(r.source);
      nodes.add(r.target);
    });

    return {
      type: 'topology',
      nodes: Array.from(nodes).map(id => ({ id, label: id })),
      edges: results.map(r => ({
        source: r.source,
        target: r.target,
        weight: r.requests,
        latency: r.avg_latency
      }))
    };
  }

  private async getAlertListData(widget: WidgetConfig, businessId: string, timeRange: any): Promise<any> {
    const alerts = await this.aiEngine.analyzeMetrics(businessId);

    return {
      type: 'alert-list',
      alerts: alerts.map(alert => ({
        id: alert.id,
        name: alert.name,
        severity: alert.severity,
        status: alert.status,
        timestamp: alert.timestamp,
        message: alert.message
      }))
    };
  }

  private extractValue(metric: AnalyticsData, query: string): number {
    // Simple query parser - in production, use a proper query engine
    if (query.includes('latency.p95')) {
      return metric.metrics.golden.latency.p95;
    } else if (query.includes('error_rate')) {
      return metric.metrics.golden.errors.errorRate;
    } else if (query.includes('ai_cost')) {
      return metric.metrics.ai.costCents;
    } else if (query.includes('requests_per_second')) {
      return metric.metrics.golden.traffic.requestsPerSecond;
    }
    return 0;
  }

  private getUnit(query: string): string {
    if (query.includes('latency')) return 'ms';
    if (query.includes('cost')) return 'cents';
    if (query.includes('rate') || query.includes('percent')) return '%';
    if (query.includes('requests')) return 'req/s';
    return '';
  }

  private async executeQuery(query: string, businessId: string): Promise<any> {
    try {
      // Validate businessId format to prevent injection
      if (!this.isValidBusinessId(businessId)) {
        throw new Error('Invalid business ID format');
      }

      // Use parameterized query instead of string concatenation
      const modifiedQuery = query.includes('WHERE')
        ? query.replace('WHERE', 'WHERE business_id = ? AND')
        : query + ' WHERE business_id = ?';

      return await this.collector.queryWithParams(modifiedQuery, [businessId]);
    } catch (error) {
      return { error: (error as Error).message };
    }
  }

  private isValidBusinessId(businessId: string): boolean {
    // Business ID should be a UUID or specific format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const customFormat = /^bus_[a-zA-Z0-9]{12,}$/;
    return uuidRegex.test(businessId) || customFormat.test(businessId);
  }

  private isValidTimeRange(timeRange: any): boolean {
    if (!timeRange || typeof timeRange !== 'object') return false;

    // Validate ISO date format
    const isoDateRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?$/;

    return (
      typeof timeRange.start === 'string' &&
      typeof timeRange.end === 'string' &&
      isoDateRegex.test(timeRange.start) &&
      isoDateRegex.test(timeRange.end) &&
      new Date(timeRange.start) < new Date(timeRange.end)
    );
  }

  private async handleExportRequest(subscription: DashboardSubscription, message: any): Promise<void> {
    const { format, widgets } = message;

    const exportData = await Promise.all(
      widgets.map(async (widgetId: string) => {
        const widget = subscription.config.layout.find(w => w.i === widgetId)?.widget;
        if (!widget) return null;

        const data = await this.getWidgetData(widget, subscription.businessId, subscription.config.timeRange);
        return { widgetId, widget: widget.title, data };
      })
    );

    let exportContent: string;

    switch (format) {
      case 'csv':
        exportContent = this.exportToCSV(exportData.filter(Boolean));
        break;
      case 'json':
        exportContent = JSON.stringify(exportData.filter(Boolean), null, 2);
        break;
      default:
        exportContent = JSON.stringify(exportData.filter(Boolean), null, 2);
    }

    this.sendMessage(subscription, {
      type: 'export_ready',
      format,
      content: exportContent,
      filename: `dashboard_export_${Date.now()}.${format}`
    });
  }

  private exportToCSV(data: any[]): string {
    const rows: string[] = [];

    data.forEach(item => {
      if (item.data.type === 'table') {
        rows.push(`\n# ${item.widget}`);
        rows.push(item.data.columns.join(','));
        item.data.rows.forEach((row: any) => {
          rows.push(Object.values(row).join(','));
        });
      } else if (item.data.type === 'time-series') {
        rows.push(`\n# ${item.widget}`);
        rows.push('timestamp,value');
        item.data.series[0].data.forEach(([timestamp, value]: [number, number]) => {
          rows.push(`${new Date(timestamp).toISOString()},${value}`);
        });
      }
    });

    return rows.join('\n');
  }

  private sendMessage(subscription: DashboardSubscription, message: any): void {
    if (subscription.websocket.readyState === WebSocket.OPEN) {
      subscription.websocket.send(JSON.stringify({
        ...message,
        timestamp: Date.now(),
        subscription: subscription.id
      }));
    }
  }

  private startStreamingLoop(): void {
    setInterval(async () => {
      await this.broadcastUpdates();
    }, this.updateInterval);
  }

  private async broadcastUpdates(): Promise<void> {
    for (const subscription of this.subscriptions.values()) {
      try {
        await this.sendRealtimeUpdates(subscription);
      } catch (error) {
      }
    }
  }

  private async sendRealtimeUpdates(subscription: DashboardSubscription): Promise<void> {
    const { config, businessId, lastUpdate } = subscription;

    // Get latest metrics
    const timeRange = {
      start: new Date(lastUpdate).toISOString(),
      end: new Date().toISOString()
    };

    const newMetrics = await this.collector.getMetrics(businessId, timeRange);

    if (newMetrics.length > 0) {
      // Send incremental updates for each widget
      for (const widget of config.layout) {
        const data = await this.getWidgetData(widget.widget, businessId, timeRange);

        this.sendMessage(subscription, {
          type: 'widget_update',
          widgetId: widget.i,
          data,
          incremental: true
        });
      }

      subscription.lastUpdate = Date.now();
    }

    // Check for new alerts
    const alerts = await this.aiEngine.analyzeMetrics(businessId);
    const newAlerts = alerts.filter(alert => alert.timestamp > lastUpdate);

    if (newAlerts.length > 0) {
      this.sendMessage(subscription, {
        type: 'new_alerts',
        data: newAlerts
      });
    }
  }

  // Natural language query processing
  async processNaturalLanguageQuery(query: string, businessId: string): Promise<any> {
    const lowercaseQuery = query.toLowerCase();

    let sql = '';
    let timeRange = 'AND event_time >= now() - INTERVAL 1 DAY';

    // Extract time range
    if (lowercaseQuery.includes('yesterday')) {
      timeRange = 'AND event_time >= yesterday() AND event_time < today()';
    } else if (lowercaseQuery.includes('last hour')) {
      timeRange = 'AND event_time >= now() - INTERVAL 1 HOUR';
    } else if (lowercaseQuery.includes('last week')) {
      timeRange = 'AND event_time >= now() - INTERVAL 7 DAY';
    }

    // Build SQL based on query intent
    if (lowercaseQuery.includes('slow') && lowercaseQuery.includes('api')) {
      sql = `
        SELECT
          JSONExtract(properties, 'path', 'String') as path,
          AVG(JSONExtract(metrics, 'latencyMs', 'Float64')) as avg_latency,
          COUNT(*) as request_count
        FROM telemetry_events
        WHERE business_id = '${businessId}' ${timeRange}
          AND JSONExtract(metrics, 'latencyMs', 'Float64') > 1000
        GROUP BY path
        ORDER BY avg_latency DESC
        LIMIT 10
      `;
    } else if (lowercaseQuery.includes('error') && lowercaseQuery.includes('rate')) {
      sql = `
        SELECT
          toStartOfHour(event_time) as hour,
          JSONExtract(properties, 'statusCode', 'UInt16') as status_code,
          COUNT(*) as count
        FROM telemetry_events
        WHERE business_id = '${businessId}' ${timeRange}
          AND JSONExtract(properties, 'statusCode', 'UInt16') >= 400
        GROUP BY hour, status_code
        ORDER BY hour DESC
      `;
    } else if (lowercaseQuery.includes('cost') || lowercaseQuery.includes('expensive')) {
      sql = `
        SELECT
          JSONExtract(properties, 'aiModel', 'String') as model,
          SUM(JSONExtract(metrics, 'aiCostCents', 'Float64')) as total_cost,
          COUNT(*) as request_count
        FROM telemetry_events
        WHERE business_id = '${businessId}' ${timeRange}
          AND JSONExtract(metrics, 'aiCostCents', 'Float64') > 0
        GROUP BY model
        ORDER BY total_cost DESC
      `;
    } else {
      // Default: show recent activity
      sql = `
        SELECT
          event_time,
          JSONExtract(properties, 'module', 'String') as module,
          JSONExtract(properties, 'capability', 'String') as capability,
          JSONExtract(metrics, 'latencyMs', 'Float64') as latency
        FROM telemetry_events
        WHERE business_id = '${businessId}' ${timeRange}
        ORDER BY event_time DESC
        LIMIT 100
      `;
    }

    return await this.collector.query(sql);
  }

  getActiveConnections(): number {
    return this.subscriptions.size;
  }

  disconnectAll(): void {
    for (const subscription of this.subscriptions.values()) {
      subscription.websocket.close();
    }
    this.subscriptions.clear();
  }
}

// WebSocket upgrade handler for Cloudflare Workers
export function handleWebSocketUpgrade(request: Request, dashboardStream: DashboardStream): Response {
  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader !== 'websocket') {
    return new Response('Expected Upgrade: websocket', { status: 426 });
  }

  const url = new URL(request.url);
  const businessId = url.searchParams.get('businessId');
  if (!businessId) {
    return new Response('businessId parameter required', { status: 400 });
  }

  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);

  server.accept();

  // Parse dashboard config from query params or use default
  const configParam = url.searchParams.get('config');
  const config: DashboardConfig = configParam ?
    JSON.parse(decodeURIComponent(configParam)) :
    getDefaultDashboardConfig();

  dashboardStream.subscribe(server, businessId, config);

  return new Response(null, {
    status: 101,
    webSocket: client
  });
}

function getDefaultDashboardConfig(): DashboardConfig {
  return {
    id: 'default',
    name: 'Default Dashboard',
    description: 'Default observability dashboard',
    layout: [
      {
        i: 'latency',
        x: 0, y: 0, w: 6, h: 4,
        widget: {
          type: 'chart',
          title: 'Response Time (P95)',
          query: 'latency.p95',
          visualization: { chartType: 'line', aggregation: 'avg' }
        }
      },
      {
        i: 'errors',
        x: 6, y: 0, w: 6, h: 4,
        widget: {
          type: 'chart',
          title: 'Error Rate',
          query: 'error_rate',
          visualization: { chartType: 'line', aggregation: 'avg' }
        }
      },
      {
        i: 'requests',
        x: 0, y: 4, w: 3, h: 3,
        widget: {
          type: 'stat',
          title: 'Requests/sec',
          query: 'requests_per_second',
          visualization: { aggregation: 'avg' }
        }
      },
      {
        i: 'cost',
        x: 3, y: 4, w: 3, h: 3,
        widget: {
          type: 'stat',
          title: 'AI Cost',
          query: 'ai_cost',
          visualization: { aggregation: 'sum' }
        }
      }
    ],
    filters: {},
    timeRange: {
      start: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      end: new Date().toISOString(),
      relative: '24h'
    },
    refreshInterval: 5000
  };
}