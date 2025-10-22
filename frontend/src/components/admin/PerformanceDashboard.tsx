import React, { useEffect, useState } from 'react';
import { Activity, TrendingUp, TrendingDown, Clock, Zap, Database, Server } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card-refactored';

interface PerformanceMetrics {
  coreWebVitals: {
    lcp: number; // Largest Contentful Paint
    fid: number; // First Input Delay
    cls: number; // Cumulative Layout Shift
    fcp: number; // First Contentful Paint
    ttfb: number; // Time to First Byte
    inp: number; // Interaction to Next Paint
  };
  api: {
    responseTime: {
      p50: number;
      p95: number;
      p99: number;
    };
    throughput: number; // requests per second
    errorRate: number; // percentage
  };
  cache: {
    hitRate: number; // percentage
    missRate: number; // percentage
    totalRequests: number;
  };
  system: {
    uptime: number; // percentage
    memoryUsage: number; // MB
    activeConnections: number;
  };
}

/**
 * Performance Monitoring Dashboard Component
 * Displays real-time performance metrics and Core Web Vitals
 */
export function PerformanceDashboard() {
  const [metrics, setMetrics] = useState<PerformanceMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadPerformanceMetrics();
    // Refresh every 30 seconds
    const interval = setInterval(loadPerformanceMetrics, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadPerformanceMetrics = async () => {
    try {
      // In production, fetch from your analytics API
      // const response = await fetch('/api/v1/analytics/performance');
      // const data = await response.json();

      // Mock data for now
      const mockData: PerformanceMetrics = {
        coreWebVitals: {
          lcp: 1850, // Good: < 2500ms
          fid: 45,   // Good: < 100ms
          cls: 0.05, // Good: < 0.1
          fcp: 1200, // Good: < 1800ms
          ttfb: 280, // Good: < 800ms
          inp: 85,   // Good: < 200ms
        },
        api: {
          responseTime: {
            p50: 65,
            p95: 185,
            p99: 420,
          },
          throughput: 127,
          errorRate: 0.3,
        },
        cache: {
          hitRate: 76.5,
          missRate: 23.5,
          totalRequests: 45230,
        },
        system: {
          uptime: 99.97,
          memoryUsage: 342,
          activeConnections: 1847,
        },
      };

      setMetrics(mockData);
      setLoading(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load metrics');
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-primary-600" />
      </div>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-6">
          <p className="text-red-600">Error loading metrics: {error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!metrics) {
    return null;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-slate-900 mb-2">Performance Monitoring</h2>
        <p className="text-slate-600">Real-time system performance and Core Web Vitals</p>
      </div>

      {/* Core Web Vitals */}
      <div className="grid gap-4 md:grid-cols-3">
        <MetricCard
          title="Largest Contentful Paint"
          value={`${metrics.coreWebVitals.lcp}ms`}
          description="Loading Performance"
          icon={Clock}
          status={getWebVitalStatus('lcp', metrics.coreWebVitals.lcp)}
          target="< 2500ms"
        />
        <MetricCard
          title="Cumulative Layout Shift"
          value={metrics.coreWebVitals.cls.toFixed(3)}
          description="Visual Stability"
          icon={Activity}
          status={getWebVitalStatus('cls', metrics.coreWebVitals.cls)}
          target="< 0.1"
        />
        <MetricCard
          title="Interaction to Next Paint"
          value={`${metrics.coreWebVitals.inp}ms`}
          description="Responsiveness"
          icon={Zap}
          status={getWebVitalStatus('inp', metrics.coreWebVitals.inp)}
          target="< 200ms"
        />
      </div>

      {/* Additional Web Vitals */}
      <Card>
        <CardHeader>
          <CardTitle>Additional Web Vitals</CardTitle>
          <CardDescription>Supporting performance metrics</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <div className="text-sm text-slate-600 mb-1">First Contentful Paint</div>
              <div className="text-2xl font-bold">{metrics.coreWebVitals.fcp}ms</div>
              <div className="text-xs text-slate-500">Target: &lt; 1800ms</div>
            </div>
            <div>
              <div className="text-sm text-slate-600 mb-1">Time to First Byte</div>
              <div className="text-2xl font-bold">{metrics.coreWebVitals.ttfb}ms</div>
              <div className="text-xs text-slate-500">Target: &lt; 800ms</div>
            </div>
            <div>
              <div className="text-sm text-slate-600 mb-1">First Input Delay</div>
              <div className="text-2xl font-bold">{metrics.coreWebVitals.fid}ms</div>
              <div className="text-xs text-slate-500">Target: &lt; 100ms</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* API Performance */}
      <Card>
        <CardHeader>
          <CardTitle>API Performance</CardTitle>
          <CardDescription>Backend response times and throughput</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div>
              <div className="text-sm text-slate-600 mb-1">P50 Response Time</div>
              <div className="text-2xl font-bold text-green-600">{metrics.api.responseTime.p50}ms</div>
            </div>
            <div>
              <div className="text-sm text-slate-600 mb-1">P95 Response Time</div>
              <div className="text-2xl font-bold text-yellow-600">{metrics.api.responseTime.p95}ms</div>
            </div>
            <div>
              <div className="text-sm text-slate-600 mb-1">Throughput</div>
              <div className="text-2xl font-bold">{metrics.api.throughput} req/s</div>
            </div>
            <div>
              <div className="text-sm text-slate-600 mb-1">Error Rate</div>
              <div className={`text-2xl font-bold ${metrics.api.errorRate < 1 ? 'text-green-600' : 'text-red-600'}`}>
                {metrics.api.errorRate}%
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Cache Performance */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5" />
              Cache Performance
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-sm text-slate-600">Hit Rate</span>
                  <span className="text-sm font-semibold text-green-600">{metrics.cache.hitRate}%</span>
                </div>
                <div className="w-full bg-slate-200 rounded-full h-2">
                  <div
                    className="bg-green-600 h-2 rounded-full"
                    style={{ width: `${metrics.cache.hitRate}%` }}
                  />
                </div>
              </div>
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-sm text-slate-600">Miss Rate</span>
                  <span className="text-sm font-semibold text-red-600">{metrics.cache.missRate}%</span>
                </div>
                <div className="w-full bg-slate-200 rounded-full h-2">
                  <div
                    className="bg-red-600 h-2 rounded-full"
                    style={{ width: `${metrics.cache.missRate}%` }}
                  />
                </div>
              </div>
              <div className="pt-2 border-t">
                <div className="text-sm text-slate-600">Total Requests</div>
                <div className="text-2xl font-bold">{metrics.cache.totalRequests.toLocaleString()}</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              System Health
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="text-sm text-slate-600 mb-1">Uptime</div>
                <div className="text-3xl font-bold text-green-600">{metrics.system.uptime}%</div>
              </div>
              <div>
                <div className="text-sm text-slate-600 mb-1">Memory Usage</div>
                <div className="text-2xl font-bold">{metrics.system.memoryUsage} MB</div>
              </div>
              <div>
                <div className="text-sm text-slate-600 mb-1">Active Connections</div>
                <div className="text-2xl font-bold">{metrics.system.activeConnections.toLocaleString()}</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

interface MetricCardProps {
  title: string;
  value: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  status: 'good' | 'needs-improvement' | 'poor';
  target: string;
}

function MetricCard({ title, value, description, icon: Icon, status, target }: MetricCardProps) {
  const statusConfig = {
    good: {
      color: 'text-green-600',
      bg: 'bg-green-50',
      icon: TrendingUp,
      label: 'Good',
    },
    'needs-improvement': {
      color: 'text-yellow-600',
      bg: 'bg-yellow-50',
      icon: Activity,
      label: 'Needs Improvement',
    },
    poor: {
      color: 'text-red-600',
      bg: 'bg-red-50',
      icon: TrendingDown,
      label: 'Poor',
    },
  };

  const config = statusConfig[status];
  const StatusIcon = config.icon;

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-start justify-between mb-4">
          <div className={`p-2 rounded-lg ${config.bg}`}>
            <Icon className={`h-6 w-6 ${config.color}`} />
          </div>
          <div className={`flex items-center gap-1 text-xs ${config.color}`}>
            <StatusIcon className="h-3 w-3" />
            <span>{config.label}</span>
          </div>
        </div>

        <div className="space-y-1">
          <h3 className="text-sm font-medium text-slate-600">{title}</h3>
          <p className="text-3xl font-bold text-slate-900">{value}</p>
          <p className="text-xs text-slate-500">{description}</p>
          <p className="text-xs text-slate-400">Target: {target}</p>
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Determine Core Web Vital status based on Google's thresholds
 */
function getWebVitalStatus(
  metric: 'lcp' | 'cls' | 'fid' | 'inp',
  value: number
): 'good' | 'needs-improvement' | 'poor' {
  const thresholds = {
    lcp: { good: 2500, poor: 4000 },
    cls: { good: 0.1, poor: 0.25 },
    fid: { good: 100, poor: 300 },
    inp: { good: 200, poor: 500 },
  };

  const threshold = thresholds[metric];
  if (value <= threshold.good) return 'good';
  if (value <= threshold.poor) return 'needs-improvement';
  return 'poor';
}

export default PerformanceDashboard;
