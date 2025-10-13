/**
 * AI Audit & Monitoring Dashboard
 * Comprehensive AI system monitoring, auditing, and performance tracking
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState, useEffect } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { aiMonitoringService, type MonitoringDashboard, type MonitoringAlert } from '@/lib/api/services/ai-monitoring.service';
import { aiAuditService, type AIAuditReport } from '@/lib/api/services/ai-audit.service';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  TrendingDown,
  Zap,
  Shield,
  Target,
  BarChart3,
  AlertCircle,
  RefreshCw,
  Play,
  Download,
  Settings,
  Eye,
  XCircle,
  Loader2,
  Brain,
  Sparkles,
  LineChart
} from 'lucide-react';

export const Route = createFileRoute('/ai-monitoring')({
  component: AIMonitoringPage,
});

function AIMonitoringPage() {
  const [dashboard, setDashboard] = useState<MonitoringDashboard | null>(null);
  const [alerts, setAlerts] = useState<MonitoringAlert[]>([]);
  const [auditReports, setAuditReports] = useState<AIAuditReport[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h');
  const [selectedTab, setSelectedTab] = useState<'overview' | 'models' | 'alerts' | 'audits'>('overview');
  const [isRunningAudit, setIsRunningAudit] = useState(false);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, [timeRange]);

  const loadData = async () => {
    try {
      const [dashboardRes, alertsRes, auditsRes] = await Promise.all([
        aiMonitoringService.getDashboard({ time_range: timeRange }),
        aiMonitoringService.listAlerts({ resolved: false, limit: 10 }),
        aiAuditService.listAuditReports({ limit: 5 }),
      ]);

      setDashboard(dashboardRes.data);
      setAlerts(alertsRes.data);
      setAuditReports(auditsRes.data);
    } catch (error) {
      console.error('Failed to load monitoring data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunAudit = async () => {
    setIsRunningAudit(true);
    try {
      await aiAuditService.runComprehensiveAudit({
        include_models: true,
        include_workflows: true,
        include_safety: true,
      });

      const event = new CustomEvent('show-toast', {
        detail: { message: 'Comprehensive audit started', type: 'success' }
      });
      window.dispatchEvent(event);

      loadData();
    } catch (error) {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Failed to start audit', type: 'error' }
      });
      window.dispatchEvent(event);
    } finally {
      setIsRunningAudit(false);
    }
  };

  const handleResolveAlert = async (alertId: string) => {
    try {
      await aiMonitoringService.resolveAlert(alertId);
      loadData();
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Alert resolved', type: 'success' }
      });
      window.dispatchEvent(event);
    } catch (error) {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Failed to resolve alert', type: 'error' }
      });
      window.dispatchEvent(event);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      case 'high':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'low':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-500';
      case 'degraded':
        return 'text-yellow-500';
      case 'down':
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  if (isLoading || !dashboard) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-[calc(100vh-4rem)]">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
              <Brain className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">AI Monitoring & Audit</h1>
              <p className="text-muted-foreground mt-1">
                Real-time monitoring, performance tracking, and safety auditing
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Time Range Selector */}
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value as any)}
              className="h-9 px-3 rounded-md border border-input bg-background"
            >
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>

            <Button variant="outline" size="sm" onClick={loadData}>
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>

            <Button size="sm" onClick={handleRunAudit} disabled={isRunningAudit}>
              {isRunningAudit ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Play className="w-4 h-4 mr-2" />
              )}
              Run Audit
            </Button>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b">
          <div className="flex gap-6">
            {[
              { id: 'overview', label: 'Overview', icon: Activity },
              { id: 'models', label: 'Model Health', icon: Target },
              { id: 'alerts', label: 'Alerts', icon: AlertTriangle, badge: alerts.length },
              { id: 'audits', label: 'Audit Reports', icon: Shield },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSelectedTab(tab.id as any)}
                className={`flex items-center gap-2 pb-3 border-b-2 transition-colors ${
                  selectedTab === tab.id
                    ? 'border-primary text-primary'
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span className="font-medium">{tab.label}</span>
                {tab.badge !== undefined && tab.badge > 0 && (
                  <span className="bg-red-500 text-white text-xs rounded-full px-2 py-0.5">
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Overview Tab */}
        {selectedTab === 'overview' && (
          <>
            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {/* Total Requests */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                    <Zap className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <TrendingUp className="w-4 h-4 text-green-500" />
                </div>
                <h3 className="text-2xl font-bold">{dashboard.overview.total_ai_requests_24h.toLocaleString()}</h3>
                <p className="text-sm text-muted-foreground">AI Requests ({timeRange})</p>
              </Card>

              {/* Avg Response Time */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                    <Clock className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                  </div>
                  {dashboard.overview.avg_response_time_ms < 500 ? (
                    <TrendingDown className="w-4 h-4 text-green-500" />
                  ) : (
                    <TrendingUp className="w-4 h-4 text-red-500" />
                  )}
                </div>
                <h3 className="text-2xl font-bold">{dashboard.overview.avg_response_time_ms}ms</h3>
                <p className="text-sm text-muted-foreground">Avg Response Time</p>
              </Card>

              {/* Error Rate */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2 bg-orange-100 dark:bg-orange-900/20 rounded-lg">
                    <AlertCircle className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                  </div>
                  {dashboard.overview.error_rate < 1 ? (
                    <TrendingDown className="w-4 h-4 text-green-500" />
                  ) : (
                    <TrendingUp className="w-4 h-4 text-red-500" />
                  )}
                </div>
                <h3 className="text-2xl font-bold">{dashboard.overview.error_rate.toFixed(2)}%</h3>
                <p className="text-sm text-muted-foreground">Error Rate</p>
              </Card>

              {/* Cost */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2 bg-green-100 dark:bg-green-900/20 rounded-lg">
                    <BarChart3 className="w-5 h-5 text-green-600 dark:text-green-400" />
                  </div>
                </div>
                <h3 className="text-2xl font-bold">${dashboard.overview.cost_24h.toFixed(2)}</h3>
                <p className="text-sm text-muted-foreground">AI Cost ({timeRange})</p>
              </Card>

              {/* Active Models */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2 bg-indigo-100 dark:bg-indigo-900/20 rounded-lg">
                    <Brain className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                  </div>
                </div>
                <h3 className="text-2xl font-bold">{dashboard.overview.active_models}</h3>
                <p className="text-sm text-muted-foreground">Active AI Models</p>
              </Card>

              {/* Active Workflows */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2 bg-teal-100 dark:bg-teal-900/20 rounded-lg">
                    <Sparkles className="w-5 h-5 text-teal-600 dark:text-teal-400" />
                  </div>
                </div>
                <h3 className="text-2xl font-bold">{dashboard.overview.active_workflows}</h3>
                <p className="text-sm text-muted-foreground">Active Workflows</p>
              </Card>
            </div>

            {/* Recent Alerts */}
            {dashboard.recent_alerts.length > 0 && (
              <Card className="p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-orange-500" />
                  Recent Alerts
                </h3>
                <div className="space-y-3">
                  {dashboard.recent_alerts.slice(0, 5).map((alert) => (
                    <div key={alert.alert_id} className="flex items-start justify-between p-3 border border-border rounded-lg">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                            {alert.severity.toUpperCase()}
                          </span>
                          <span className="text-sm font-medium">{alert.type}</span>
                        </div>
                        <p className="text-sm text-muted-foreground">{alert.message}</p>
                        <span className="text-xs text-muted-foreground mt-1 block">
                          {new Date(alert.triggered_at).toLocaleString()}
                        </span>
                      </div>
                      {!alert.resolved && (
                        <Button size="sm" variant="ghost" onClick={() => handleResolveAlert(alert.alert_id)}>
                          <CheckCircle className="w-4 h-4" />
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              </Card>
            )}
          </>
        )}

        {/* Model Health Tab */}
        {selectedTab === 'models' && (
          <div className="grid grid-cols-1 gap-4">
            {dashboard.model_health.map((model) => (
              <Card key={model.model_id} className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full ${
                      model.status === 'healthy' ? 'bg-green-500' :
                      model.status === 'degraded' ? 'bg-yellow-500' : 'bg-red-500'
                    }`} />
                    <div>
                      <h3 className="font-semibold text-lg">{model.model_name}</h3>
                      <p className="text-sm text-muted-foreground">Model ID: {model.model_id}</p>
                    </div>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium capitalize ${
                    model.status === 'healthy' ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400' :
                    model.status === 'degraded' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400' :
                    'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400'
                  }`}>
                    {model.status}
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-6">
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Uptime</p>
                    <p className="text-2xl font-bold">{model.uptime_percent.toFixed(1)}%</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Avg Latency</p>
                    <p className="text-2xl font-bold">{model.avg_latency_ms}ms</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Error Rate</p>
                    <p className="text-2xl font-bold">{model.error_rate.toFixed(2)}%</p>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}

        {/* Alerts Tab */}
        {selectedTab === 'alerts' && (
          <div className="space-y-4">
            {alerts.length > 0 ? (
              alerts.map((alert) => (
                <Card key={alert.id} className="p-6">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-3">
                        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(alert.severity)}`}>
                          {alert.severity.toUpperCase()}
                        </span>
                        <span className="font-semibold">{alert.title}</span>
                      </div>
                      <p className="text-muted-foreground mb-2">{alert.message}</p>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <span>Type: {alert.type.replace('_', ' ')}</span>
                        <span>•</span>
                        <span>Triggered: {new Date(alert.triggered_at).toLocaleString()}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-4">
                      <Button size="sm" onClick={() => handleResolveAlert(alert.id)}>
                        <CheckCircle className="w-4 h-4 mr-2" />
                        Resolve
                      </Button>
                    </div>
                  </div>
                </Card>
              ))
            ) : (
              <Card className="p-12">
                <div className="text-center">
                  <CheckCircle className="mx-auto h-12 w-12 text-green-500 mb-4" />
                  <h3 className="text-lg font-semibold mb-2">All Clear!</h3>
                  <p className="text-sm text-muted-foreground">
                    No active alerts at this time. Your AI systems are running smoothly.
                  </p>
                </div>
              </Card>
            )}
          </div>
        )}

        {/* Audits Tab */}
        {selectedTab === 'audits' && (
          <div className="space-y-4">
            {auditReports.length > 0 ? (
              auditReports.map((report) => (
                <Card key={report.audit_id} className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <Shield className="w-5 h-5 text-purple-500" />
                      <div>
                        <h3 className="font-semibold capitalize">
                          {report.audit_type.replace('_', ' ')} Audit
                        </h3>
                        <p className="text-sm text-muted-foreground">
                          Started: {new Date(report.started_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                      report.status === 'completed' ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400' :
                      report.status === 'running' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400' :
                      'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400'
                    }`}>
                      {report.status}
                    </span>
                  </div>

                  {report.results && (
                    <div className="space-y-4">
                      <div className="flex items-center gap-6">
                        <div>
                          <p className="text-sm text-muted-foreground">Overall Score</p>
                          <p className="text-3xl font-bold text-primary">
                            {report.results.overall_score}/100
                          </p>
                        </div>
                        <div className="flex-1">
                          <p className="text-sm text-muted-foreground mb-2">Findings by Severity</p>
                          <div className="flex gap-2">
                            {['critical', 'high', 'medium', 'low'].map((severity) => {
                              const count = report.results!.findings.filter(f => f.severity === severity).length;
                              if (count === 0) return null;
                              return (
                                <span key={severity} className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(severity)}`}>
                                  {count} {severity}
                                </span>
                              );
                            })}
                          </div>
                        </div>
                      </div>

                      {report.results.findings.length > 0 && (
                        <div className="space-y-2">
                          <h4 className="font-medium text-sm">Key Findings:</h4>
                          {report.results.findings.slice(0, 3).map((finding, idx) => (
                            <div key={idx} className="p-3 border border-border rounded-lg">
                              <div className="flex items-center gap-2 mb-1">
                                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                                  {finding.severity}
                                </span>
                                <span className="text-sm font-medium">{finding.category}</span>
                              </div>
                              <p className="text-sm text-muted-foreground">{finding.description}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  <div className="flex gap-2 mt-4 pt-4 border-t">
                    <Button size="sm" variant="outline">
                      <Eye className="w-4 h-4 mr-2" />
                      View Full Report
                    </Button>
                    <Button size="sm" variant="outline">
                      <Download className="w-4 h-4 mr-2" />
                      Export
                    </Button>
                  </div>
                </Card>
              ))
            ) : (
              <Card className="p-12">
                <div className="text-center">
                  <Shield className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-semibold mb-2">No audit reports yet</h3>
                  <p className="text-sm text-muted-foreground mb-6">
                    Run your first comprehensive audit to start monitoring AI safety and performance
                  </p>
                  <Button onClick={handleRunAudit} disabled={isRunningAudit}>
                    {isRunningAudit ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Play className="w-4 h-4 mr-2" />
                    )}
                    Run Audit
                  </Button>
                </div>
              </Card>
            )}
          </div>
        )}
      </div>
    </MainLayout>
  );
}
