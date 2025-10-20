/**
 * Admin Dashboard - Fortune 50 Level Analytics & Management
 * Main admin dashboard with real-time metrics, user management, and system analytics
 */

import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import UserManagement from '../../components/admin/UserManagement';
import SecurityMonitoring from '../../components/admin/SecurityMonitoring';
import BusinessAnalytics from '../../components/admin/BusinessAnalytics';

// API Configuration
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8790';

interface AdminKPIs {
  totalBusinesses: number;
  activeUsers: number;
  totalRevenue: number;
  monthlyRevenue: number;
  revenueGrowth: number;
  activeSessions: number;
  systemHealthScore: number;
}

interface RealtimeMetrics {
  activeUsers: number;
  requestsPerMinute: number;
  errorRate: number;
  recentPayments: number;
  avgResponseTime: number;
}

interface SystemMetrics {
  database: {
    tables: Array<{ table_name: string; index_count: number }>;
    recordCounts: {
      users: number;
      businesses: number;
      payments: number;
      auditLog: number;
      sessions: number;
    };
  };
  performance: {
    api: {
      avgResponseTime: number;
      p95ResponseTime: number;
      errorRate: number;
    };
  };
  cache: {
    hitRate: number;
    totalKeys: number;
  };
}

export default function AdminDashboard() {
  const [selectedTab, setSelectedTab] = useState<'analytics' | 'business' | 'users' | 'system' | 'security'>('analytics');

  // Get user from auth store (would use actual auth in production)
  const userId = localStorage.getItem('userId');
  const token = localStorage.getItem('token');

  // Fetch Executive KPIs
  const { data: kpisData, isLoading: kpisLoading } = useQuery({
    queryKey: ['admin', 'kpis'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE}/api/v1/admin/analytics/kpis`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-User-ID': userId || ''
        }
      });
      if (!response.ok) throw new Error('Failed to fetch KPIs');
      return response.json();
    },
    refetchInterval: 30000 // Refresh every 30 seconds
  });

  // Fetch Real-time Metrics
  const { data: realtimeData, isLoading: realtimeLoading } = useQuery({
    queryKey: ['admin', 'realtime'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE}/api/v1/admin/analytics/realtime`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-User-ID': userId || ''
        }
      });
      if (!response.ok) throw new Error('Failed to fetch realtime metrics');
      return response.json();
    },
    refetchInterval: 5000 // Refresh every 5 seconds
  });

  // Fetch System Analytics
  const { data: systemData, isLoading: systemLoading } = useQuery({
    queryKey: ['admin', 'system'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE}/api/v1/admin/analytics/system`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-User-ID': userId || ''
        }
      });
      if (!response.ok) throw new Error('Failed to fetch system metrics');
      return response.json();
    },
    refetchInterval: 60000 // Refresh every minute
  });

  const kpis: AdminKPIs | undefined = kpisData?.data?.kpis;
  const realtime: RealtimeMetrics | undefined = realtimeData?.data?.realtime;
  const system: SystemMetrics | undefined = systemData?.data;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                Admin Dashboard
              </h1>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Fortune 50 Level Analytics & System Management
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  System Health
                </div>
                <div className="text-2xl font-bold text-green-600">
                  {kpis?.systemHealthScore?.toFixed(1) || '--'}%
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav className="flex space-x-8" aria-label="Tabs">
            {['analytics', 'business', 'users', 'system', 'security'].map((tab) => (
              <button
                key={tab}
                onClick={() => setSelectedTab(tab as any)}
                className={`
                  py-4 px-1 border-b-2 font-medium text-sm capitalize
                  ${selectedTab === tab
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                  }
                `}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {selectedTab === 'analytics' && (
          <div className="space-y-6">
            {/* Executive KPIs */}
            <div>
              <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Executive KPIs
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <KPICard
                  title="Total Revenue"
                  value={`$${(kpis?.totalRevenue || 0).toLocaleString()}`}
                  change={`${kpis?.revenueGrowth > 0 ? '+' : ''}${kpis?.revenueGrowth?.toFixed(1) || 0}%`}
                  isPositive={(kpis?.revenueGrowth || 0) >= 0}
                  loading={kpisLoading}
                />
                <KPICard
                  title="Active Users"
                  value={(kpis?.activeUsers || 0).toLocaleString()}
                  subtitle="Currently logged in"
                  loading={kpisLoading}
                />
                <KPICard
                  title="Total Businesses"
                  value={(kpis?.totalBusinesses || 0).toLocaleString()}
                  subtitle="Active businesses"
                  loading={kpisLoading}
                />
                <KPICard
                  title="Monthly Revenue"
                  value={`$${(kpis?.monthlyRevenue || 0).toLocaleString()}`}
                  subtitle="Current month"
                  loading={kpisLoading}
                />
              </div>
            </div>

            {/* Real-time Metrics */}
            <div>
              <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Real-time Monitoring
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                <MetricCard
                  title="Active Users"
                  value={(realtime?.activeUsers || 0).toString()}
                  icon="👥"
                  loading={realtimeLoading}
                />
                <MetricCard
                  title="Requests/Min"
                  value={(realtime?.requestsPerMinute || 0).toString()}
                  icon="📊"
                  loading={realtimeLoading}
                />
                <MetricCard
                  title="Error Rate"
                  value={`${realtime?.errorRate?.toFixed(2) || 0}%`}
                  icon="⚠️"
                  alert={realtime && realtime.errorRate > 1}
                  loading={realtimeLoading}
                />
                <MetricCard
                  title="Avg Response"
                  value={`${realtime?.avgResponseTime || 0}ms`}
                  icon="⚡"
                  loading={realtimeLoading}
                />
                <MetricCard
                  title="Recent Payments"
                  value={(realtime?.recentPayments || 0).toString()}
                  icon="💰"
                  loading={realtimeLoading}
                />
              </div>
            </div>
          </div>
        )}

        {selectedTab === 'system' && (
          <div className="space-y-6">
            {/* System Analytics */}
            <div>
              <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                System Performance
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <SystemCard
                  title="API Performance"
                  metrics={[
                    { label: 'Avg Response', value: `${system?.performance?.api?.avgResponseTime || 0}ms` },
                    { label: 'P95 Response', value: `${system?.performance?.api?.p95ResponseTime || 0}ms` },
                    { label: 'Error Rate', value: `${system?.performance?.api?.errorRate || 0}%` }
                  ]}
                  loading={systemLoading}
                />
                <SystemCard
                  title="Cache Statistics"
                  metrics={[
                    { label: 'Hit Rate', value: `${system?.cache?.hitRate || 0}%` },
                    { label: 'Total Keys', value: (system?.cache?.totalKeys || 0).toLocaleString() }
                  ]}
                  loading={systemLoading}
                />
                <SystemCard
                  title="Database"
                  metrics={[
                    { label: 'Users', value: (system?.database?.recordCounts?.users || 0).toLocaleString() },
                    { label: 'Businesses', value: (system?.database?.recordCounts?.businesses || 0).toLocaleString() },
                    { label: 'Payments', value: (system?.database?.recordCounts?.payments || 0).toLocaleString() }
                  ]}
                  loading={systemLoading}
                />
              </div>
            </div>

            {/* Database Tables */}
            {system?.database?.tables && (
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                  Database Tables ({system.database.tables.length})
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {system.database.tables.slice(0, 20).map((table) => (
                    <div
                      key={table.table_name}
                      className="text-sm p-2 bg-gray-50 dark:bg-gray-700 rounded"
                    >
                      <div className="font-medium text-gray-900 dark:text-white truncate">
                        {table.table_name}
                      </div>
                      <div className="text-gray-500 dark:text-gray-400 text-xs">
                        {table.index_count} indexes
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {selectedTab === 'business' && (
          <BusinessAnalytics />
        )}

        {selectedTab === 'users' && (
          <UserManagement />
        )}

        {selectedTab === 'security' && (
          <SecurityMonitoring />
        )}
      </div>
    </div>
  );
}

// KPI Card Component
function KPICard({ title, value, change, isPositive, subtitle, loading }: {
  title: string;
  value: string;
  change?: string;
  isPositive?: boolean;
  subtitle?: string;
  loading?: boolean;
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <div className="text-sm font-medium text-gray-500 dark:text-gray-400">
        {title}
      </div>
      {loading ? (
        <div className="mt-2 h-8 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
      ) : (
        <>
          <div className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">
            {value}
          </div>
          {change && (
            <div className={`mt-1 text-sm ${isPositive ? 'text-green-600' : 'text-red-600'}`}>
              {change}
            </div>
          )}
          {subtitle && (
            <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              {subtitle}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// Metric Card Component
function MetricCard({ title, value, icon, alert, loading }: {
  title: string;
  value: string;
  icon: string;
  alert?: boolean;
  loading?: boolean;
}) {
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg shadow p-4 ${alert ? 'ring-2 ring-red-500' : ''}`}>
      <div className="flex items-center justify-between">
        <div className="text-2xl">{icon}</div>
        {alert && <div className="text-red-500 text-xs font-medium">ALERT</div>}
      </div>
      <div className="mt-2 text-xs font-medium text-gray-500 dark:text-gray-400">
        {title}
      </div>
      {loading ? (
        <div className="mt-1 h-6 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
      ) : (
        <div className="mt-1 text-xl font-bold text-gray-900 dark:text-white">
          {value}
        </div>
      )}
    </div>
  );
}

// System Card Component
function SystemCard({ title, metrics, loading }: {
  title: string;
  metrics: Array<{ label: string; value: string }>;
  loading?: boolean;
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
        {title}
      </h3>
      {loading ? (
        <div className="space-y-3">
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
        </div>
      ) : (
        <div className="space-y-3">
          {metrics.map((metric) => (
            <div key={metric.label} className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-300">
                {metric.label}
              </span>
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {metric.value}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
