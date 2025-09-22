// CoreFlow360 V4 - Real-time Observability Dashboard
import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  ScatterChart, Scatter, Heatmap
} from 'recharts';
import * as d3 from 'd3';

interface DashboardProps {
  businessId: string;
  timeRange: string;
  refreshInterval: number;
}

interface MetricData {
  timestamp: string;
  metricName: string;
  value: number;
  trend?: 'increasing' | 'decreasing' | 'stable';
  anomalyScore?: number;
  predictions?: any;
}

interface Alert {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'firing' | 'resolved' | 'acknowledged';
  triggeredAt: string;
  metricValue?: number;
}

export const ObservabilityDashboard: React.FC<DashboardProps> = ({
  businessId,
  timeRange,
  refreshInterval
}) => {
  const [metrics, setMetrics] = useState<MetricData[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [serviceHealth, setServiceHealth] = useState<any[]>([]);
  const [costSummary, setCostSummary] = useState<any>(null);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTimeRange, setSelectedTimeRange] = useState(timeRange);
  const [selectedMetrics, setSelectedMetrics] = useState(['latency', 'errors', 'cost', 'traffic']);
  const [searchQuery, setSearchQuery] = useState('');
  const [customQuery, setCustomQuery] = useState('');
  const [queryResults, setQueryResults] = useState<any>(null);
  const [connectionAttempts, setConnectionAttempts] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);
  const chartContainerRef = useRef<HTMLDivElement>(null);

  // Establish WebSocket connection
  useEffect(() => {
    const connectWebSocket = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/api/v4/observability/stream?businessId=${businessId}&metrics=${selectedMetrics.join(',')}&granularity=30s`;

      wsRef.current = new WebSocket(wsUrl);

      wsRef.current.onopen = () => {
        setConnected(true);
        setLoading(false);
        setError(null);
        setConnectionAttempts(0);
        console.log('Connected to observability stream');
      };

      wsRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleStreamMessage(data);
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
          setError('Failed to parse real-time data');
        }
      };

      wsRef.current.onclose = (event) => {
        setConnected(false);
        console.log('Disconnected from observability stream');

        // Only attempt to reconnect if it's not a normal closure and we haven't exceeded max attempts
        if (event.code !== 1000 && connectionAttempts < 5) {
          setConnectionAttempts(prev => prev + 1);
          const delay = Math.min(1000 * Math.pow(2, connectionAttempts), 30000); // Exponential backoff, max 30s
          setTimeout(connectWebSocket, delay);
        } else if (connectionAttempts >= 5) {
          setError('Failed to connect to real-time stream after multiple attempts');
          setLoading(false);
        }
      };

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        setError('WebSocket connection error');
      };
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [businessId, selectedMetrics]);

  const handleStreamMessage = (data: any) => {
    switch (data.type) {
      case 'initial':
        setMetrics(data.data.metrics || []);
        setAlerts(data.data.alerts || []);
        setServiceHealth(data.data.serviceHealth || []);
        setCostSummary(data.data.costSummary || null);
        break;

      case 'metrics':
        setMetrics(prev => {
          const newMetrics = [...prev, ...data.data];
          // Keep only last 1000 points for performance
          return newMetrics.slice(-1000);
        });
        break;

      case 'alert_triggered':
        setAlerts(prev => [data.data, ...prev]);
        break;

      case 'alert_resolved':
        setAlerts(prev => prev.map(alert =>
          alert.id === data.data.alertId
            ? { ...alert, status: 'resolved' }
            : alert
        ));
        break;

      case 'query_result':
        setQueryResults(data.data);
        break;

      case 'query_error':
        console.error('Query error:', data.error);
        break;
    }
  };

  // Process metrics for charts
  const processedMetrics = useMemo(() => {
    const grouped = metrics.reduce((acc, metric) => {
      if (!acc[metric.metricName]) {
        acc[metric.metricName] = [];
      }
      acc[metric.metricName].push({
        timestamp: new Date(metric.timestamp).getTime(),
        value: metric.value,
        trend: metric.trend,
        anomalyScore: metric.anomalyScore || 0
      });
      return acc;
    }, {} as Record<string, any[]>);

    // Sort by timestamp and limit to time range
    const timeRangeMs = getTimeRangeMs(selectedTimeRange);
    const cutoff = Date.now() - timeRangeMs;

    Object.keys(grouped).forEach(key => {
      grouped[key] = grouped[key]
        .filter(point => point.timestamp > cutoff)
        .sort((a, b) => a.timestamp - b.timestamp);
    });

    return grouped;
  }, [metrics, selectedTimeRange]);

  const handleMetricSubscriptionChange = (newMetrics: string[]) => {
    setSelectedMetrics(newMetrics);

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'subscribe',
        metrics: newMetrics,
        granularity: '30s'
      }));
    }
  };

  const handleCustomQuery = () => {
    if (!customQuery.trim()) return;

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'query',
        query: {
          id: Date.now().toString(),
          sql: customQuery,
          businessId
        }
      }));
    }
  };

  const acknowledgeAlert = (alertId: string) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'alert_ack',
        alertId
      }));
    }
  };

  const filteredAlerts = alerts.filter(alert =>
    alert.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    alert.severity.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Loading state
  if (loading) {
    return (
      <div className="observability-dashboard p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className="text-gray-600">Connecting to observability stream...</p>
            {connectionAttempts > 0 && (
              <p className="text-sm text-gray-500 mt-2">
                Attempt {connectionAttempts + 1} of 5
              </p>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error && !connected) {
    return (
      <div className="observability-dashboard p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Connection Failed</h3>
            <p className="text-gray-600 mb-4">{error}</p>
            <button
              onClick={() => {
                setError(null);
                setLoading(true);
                setConnectionAttempts(0);
                window.location.reload();
              }}
              className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
            >
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="observability-dashboard p-6 bg-gray-50 min-h-screen">
      {/* Header */}
      <div className="dashboard-header bg-white rounded-lg shadow p-6 mb-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-3xl font-bold text-gray-900">Observability Dashboard</h1>
          <div className="flex items-center space-x-4">
            <div className={`connection-indicator flex items-center ${connected ? 'text-green-600' : 'text-red-600'}`}>
              <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}></div>
              <span className="ml-2 font-medium">{connected ? 'Connected' : 'Disconnected'}</span>
            </div>
            <select
              value={selectedTimeRange}
              onChange={(e) => setSelectedTimeRange(e.target.value)}
              className="px-3 py-1 border rounded"
            >
              <option value="1h">Last Hour</option>
              <option value="6h">Last 6 Hours</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>
        </div>

        {/* Metric Selection */}
        <div className="metric-selection mb-4">
          <h3 className="text-lg font-semibold mb-2">Metrics</h3>
          <div className="flex flex-wrap gap-2">
            {['latency', 'errors', 'cost', 'traffic', 'cpu', 'memory', 'disk'].map(metric => (
              <label key={metric} className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={selectedMetrics.includes(metric)}
                  onChange={(e) => {
                    if (e.target.checked) {
                      handleMetricSubscriptionChange([...selectedMetrics, metric]);
                    } else {
                      handleMetricSubscriptionChange(selectedMetrics.filter(m => m !== metric));
                    }
                  }}
                />
                <span className="capitalize">{metric}</span>
              </label>
            ))}
          </div>
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div className="dashboard-grid grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Golden Signals */}
        <div className="lg:col-span-2 space-y-6">
          {/* Metrics Overview Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <MetricCard title="Latency P95" value="125ms" trend="decreasing" />
            <MetricCard title="Error Rate" value="0.2%" trend="stable" />
            <MetricCard title="Requests/min" value="1.2k" trend="increasing" />
            <MetricCard title="Cost (24h)" value="$12.45" trend="increasing" />
          </div>
          {/* Latency Chart */}
          {processedMetrics.latency && (
            <ChartPanel
              title="Latency (P95)"
              data={processedMetrics.latency}
              color="#8884d8"
              unit="ms"
              type="line"
              showAnomalies={true}
            />
          )}

          {/* Error Rate Chart */}
          {processedMetrics.errors && (
            <ChartPanel
              title="Error Rate"
              data={processedMetrics.errors}
              color="#ff7c7c"
              unit="%"
              type="area"
              showAnomalies={true}
            />
          )}

          {/* Traffic Chart */}
          {processedMetrics.traffic && (
            <ChartPanel
              title="Request Traffic"
              data={processedMetrics.traffic}
              color="#82ca9d"
              unit="req/s"
              type="bar"
            />
          )}

          {/* Cost Chart */}
          {processedMetrics.cost && (
            <ChartPanel
              title="AI Cost"
              data={processedMetrics.cost}
              color="#ffc658"
              unit="$"
              type="line"
            />
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Alerts Panel */}
          <div className="alerts-panel bg-white p-4 rounded-lg shadow">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Active Alerts</h3>
              <span className="bg-red-100 text-red-800 px-2 py-1 rounded-full text-sm">
                {filteredAlerts.filter(a => a.status === 'firing').length}
              </span>
            </div>

            <input
              type="text"
              placeholder="Search alerts..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full mb-4 px-3 py-2 border rounded"
            />

            <div className="space-y-2 max-h-96 overflow-y-auto">
              {filteredAlerts.map(alert => (
                <AlertCard
                  key={alert.id}
                  alert={alert}
                  onAcknowledge={acknowledgeAlert}
                />
              ))}
            </div>
          </div>

          {/* Service Health */}
          <div className="service-health bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-4">Service Health</h3>
            <div className="space-y-3">
              {serviceHealth.map((service, index) => (
                <ServiceHealthCard key={index} service={service} />
              ))}
            </div>
          </div>

          {/* Cost Summary */}
          {costSummary && (
            <div className="cost-summary bg-white p-4 rounded-lg shadow">
              <h3 className="text-lg font-semibold mb-4">Cost Summary (24h)</h3>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Total Cost:</span>
                  <span className="font-bold">${costSummary.totalCost?.toFixed(2)}</span>
                </div>
                {costSummary.providers?.map((provider: any, index: number) => (
                  <div key={index} className="flex justify-between text-sm">
                    <span>{provider.ai_provider}:</span>
                    <span>${provider.total_cost_dollars?.toFixed(2)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Custom Query Panel */}
      <div className="custom-query-panel mt-8 bg-white p-6 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">Custom Query</h3>
        <div className="flex space-x-4 mb-4">
          <textarea
            value={customQuery}
            onChange={(e) => setCustomQuery(e.target.value)}
            placeholder="SELECT * FROM metrics WHERE business_id = ? AND timestamp >= ?"
            className="flex-1 px-3 py-2 border rounded font-mono text-sm"
            rows={3}
          />
          <button
            onClick={handleCustomQuery}
            className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          >
            Execute
          </button>
        </div>

        {queryResults && (
          <div className="query-results">
            <h4 className="font-semibold mb-2">Results:</h4>
            <div className="overflow-auto max-h-64 border rounded">
              <table className="min-w-full">
                <thead className="bg-gray-50">
                  <tr>
                    {Object.keys(queryResults[0] || {}).map(key => (
                      <th key={key} className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                        {key}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {queryResults.slice(0, 100).map((row: any, index: number) => (
                    <tr key={index} className="border-t">
                      {Object.values(row).map((value: any, cellIndex: number) => (
                        <td key={cellIndex} className="px-3 py-2 text-sm">
                          {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// Chart Panel Component
interface ChartPanelProps {
  title: string;
  data: any[];
  color: string;
  unit: string;
  type: 'line' | 'area' | 'bar';
  showAnomalies?: boolean;
}

const ChartPanel: React.FC<ChartPanelProps> = ({
  title,
  data,
  color,
  unit,
  type,
  showAnomalies
}) => {
  const formatXAxis = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const formatTooltip = (value: any, name: string) => {
    return [`${value}${unit}`, name];
  };

  const renderChart = () => {
    const chartProps = {
      data,
      margin: { top: 5, right: 30, left: 20, bottom: 5 }
    };

    switch (type) {
      case 'area':
        return (
          <AreaChart {...chartProps}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="timestamp" tickFormatter={formatXAxis} />
            <YAxis />
            <Tooltip labelFormatter={(timestamp) => new Date(timestamp).toLocaleString()} />
            <Area type="monotone" dataKey="value" stroke={color} fill={color} fillOpacity={0.3} />
          </AreaChart>
        );

      case 'bar':
        return (
          <BarChart {...chartProps}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="timestamp" tickFormatter={formatXAxis} />
            <YAxis />
            <Tooltip labelFormatter={(timestamp) => new Date(timestamp).toLocaleString()} />
            <Bar dataKey="value" fill={color} />
          </BarChart>
        );

      default:
        return (
          <LineChart {...chartProps}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="timestamp" tickFormatter={formatXAxis} />
            <YAxis />
            <Tooltip labelFormatter={(timestamp) => new Date(timestamp).toLocaleString()} />
            <Legend />
            <Line
              type="monotone"
              dataKey="value"
              stroke={color}
              strokeWidth={2}
              dot={showAnomalies ? {
                fill: (entry: any) => entry.anomalyScore > 0.5 ? '#ff0000' : color,
                strokeWidth: (entry: any) => entry.anomalyScore > 0.5 ? 3 : 1
              } : false}
            />
          </LineChart>
        );
    }
  };

  return (
    <div className="chart-panel bg-white p-6 rounded-lg shadow">
      <h3 className="text-lg font-semibold mb-4">{title}</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          {renderChart()}
        </ResponsiveContainer>
      </div>
    </div>
  );
};

// Alert Card Component
interface AlertCardProps {
  alert: Alert;
  onAcknowledge: (alertId: string) => void;
}

const AlertCard: React.FC<AlertCardProps> = ({ alert, onAcknowledge }) => {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className={`alert-card p-3 rounded border ${getSeverityColor(alert.severity)}`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <h4 className="font-medium text-sm">{alert.title}</h4>
          <p className="text-xs mt-1 opacity-75">
            {new Date(alert.triggeredAt).toLocaleString()}
          </p>
          {alert.metricValue && (
            <p className="text-xs mt-1">Value: {alert.metricValue}</p>
          )}
        </div>
        {alert.status === 'firing' && (
          <button
            onClick={() => onAcknowledge(alert.id)}
            className="ml-2 px-2 py-1 text-xs bg-white bg-opacity-50 rounded hover:bg-opacity-75"
          >
            ACK
          </button>
        )}
      </div>
    </div>
  );
};

// Service Health Card Component
interface ServiceHealthCardProps {
  service: any;
}

const ServiceHealthCard: React.FC<ServiceHealthCardProps> = ({ service }) => {
  const getHealthStatus = (errorRate: number) => {
    if (errorRate > 5) return { status: 'unhealthy', color: 'text-red-600' };
    if (errorRate > 1) return { status: 'degraded', color: 'text-yellow-600' };
    return { status: 'healthy', color: 'text-green-600' };
  };

  const health = getHealthStatus(service.error_rate || 0);

  return (
    <div className="service-health-card p-3 border rounded">
      <div className="flex items-center justify-between mb-2">
        <h4 className="font-medium text-sm">{service.service_name}</h4>
        <span className={`text-xs font-medium ${health.color}`}>
          {health.status}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <span className="text-gray-500">Latency:</span>
          <span className="ml-1">{service.avg_latency?.toFixed(0)}ms</span>
        </div>
        <div>
          <span className="text-gray-500">Error Rate:</span>
          <span className="ml-1">{service.error_rate?.toFixed(1)}%</span>
        </div>
        <div>
          <span className="text-gray-500">Requests:</span>
          <span className="ml-1">{service.total_requests}</span>
        </div>
        <div>
          <span className="text-gray-500">Errors:</span>
          <span className="ml-1">{service.total_errors}</span>
        </div>
      </div>
    </div>
  );
};

// Helper function
function getTimeRangeMs(timeRange: string): number {
  const ranges: Record<string, number> = {
    '1h': 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000
  };
  return ranges[timeRange] || ranges['24h'];
}

// Metric Card Component
interface MetricCardProps {
  title: string;
  value: string;
  trend: 'increasing' | 'decreasing' | 'stable';
  description?: string;
}

const MetricCard: React.FC<MetricCardProps> = ({ title, value, trend, description }) => {
  const getTrendIcon = () => {
    switch (trend) {
      case 'increasing':
        return (
          <svg className="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
          </svg>
        );
      case 'decreasing':
        return (
          <svg className="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 17h8m0 0V9m0 8l-8-8-4 4-6-6" />
          </svg>
        );
      default:
        return (
          <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14" />
          </svg>
        );
    }
  };

  const getTrendColor = () => {
    switch (trend) {
      case 'increasing':
        return 'text-green-600';
      case 'decreasing':
        return 'text-red-600';
      default:
        return 'text-gray-600';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium text-gray-600">{title}</h3>
        <div className="flex items-center">
          {getTrendIcon()}
        </div>
      </div>
      <div className="flex items-baseline justify-between">
        <span className="text-2xl font-bold text-gray-900">{value}</span>
        <span className={`text-xs font-medium ${getTrendColor()}`}>
          {trend}
        </span>
      </div>
      {description && (
        <p className="text-xs text-gray-500 mt-1">{description}</p>
      )}
    </div>
  );
};

export default ObservabilityDashboard;