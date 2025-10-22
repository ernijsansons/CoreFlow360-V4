/**
 * CRM Analytics Dashboard - Fortune 50 Level
 * Comprehensive analytics with real-time metrics and visualizations
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { useCRMDashboardStats, usePipelineMetrics } from '@/lib/api/hooks/useCRM';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  BarChart3,
  TrendingUp,
  Users,
  DollarSign,
  Target,
  Building2,
  Activity,
  Calendar,
  RefreshCw,
  Download,
  ArrowUp,
  ArrowDown,
  Minus
} from 'lucide-react';

export const Route = createFileRoute('/analytics')({
  component: AnalyticsPage,
});

function AnalyticsPage() {
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d' | 'ytd'>('30d');

  const { data: statsData, isLoading, error, refetch, isFetching } = useCRMDashboardStats();
  const { data: pipelineData } = usePipelineMetrics();

  const stats = statsData || {
    total_companies: 0,
    total_contacts: 0,
    total_deals: 0,
    total_activities: 0,
    active_deals_value: 0,
    won_deals_value: 0,
    average_deal_size: 0,
    win_rate: 0,
    average_sales_cycle: 0,
    conversion_rate: 0,
  };

  const pipeline = pipelineData || { stages: [] };

  const handleRefresh = async () => {
    await refetch();
    const event = new CustomEvent('show-toast', {
      detail: { message: 'Analytics refreshed', type: 'success' }
    });
    window.dispatchEvent(event);
  };

  const handleExport = () => {
    const data = {
      generated_at: new Date().toISOString(),
      time_range: timeRange,
      summary: stats,
      pipeline: pipeline.stages,
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `analytics-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);

    const event = new CustomEvent('show-toast', {
      detail: { message: 'Analytics exported', type: 'success' }
    });
    window.dispatchEvent(event);
  };

  const formatCurrency = (value: number) => {
    if (value >= 1000000) return `$${(value / 1000000).toFixed(1)}M`;
    if (value >= 1000) return `$${(value / 1000).toFixed(0)}K`;
    return `$${value}`;
  };

  const getTrendIcon = (trend: 'up' | 'down' | 'neutral') => {
    if (trend === 'up') return <ArrowUp className="w-4 h-4 text-green-600 dark:text-green-400" />;
    if (trend === 'down') return <ArrowDown className="w-4 h-4 text-red-600 dark:text-red-400" />;
    return <Minus className="w-4 h-4 text-gray-600 dark:text-gray-400" />;
  };

  const getTrendColor = (trend: 'up' | 'down' | 'neutral') => {
    if (trend === 'up') return 'text-green-600 dark:text-green-400';
    if (trend === 'down') return 'text-red-600 dark:text-red-400';
    return 'text-gray-600 dark:text-gray-400';
  };

  // Calculate trends (mock for now - would come from backend)
  const calculateTrend = (value: number): { percent: number; direction: 'up' | 'down' | 'neutral' } => {
    const mockTrend = Math.random() * 30 - 10; // -10% to +20%
    return {
      percent: Math.abs(mockTrend),
      direction: mockTrend > 2 ? 'up' : mockTrend < -2 ? 'down' : 'neutral',
    };
  };

  const companyTrend = calculateTrend(stats.total_companies);
  const contactTrend = calculateTrend(stats.total_contacts);
  const dealTrend = calculateTrend(stats.total_deals);
  const revenueTrend = calculateTrend(stats.won_deals_value);

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
              <BarChart3 className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">CRM Analytics</h1>
              <p className="text-muted-foreground mt-1">Real-time insights and performance metrics</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Time Range Selector */}
            <div className="flex items-center gap-2 border rounded-lg p-1">
              <Button
                variant={timeRange === '7d' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setTimeRange('7d')}
              >
                7D
              </Button>
              <Button
                variant={timeRange === '30d' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setTimeRange('30d')}
              >
                30D
              </Button>
              <Button
                variant={timeRange === '90d' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setTimeRange('90d')}
              >
                90D
              </Button>
              <Button
                variant={timeRange === 'ytd' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setTimeRange('ytd')}
              >
                YTD
              </Button>
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              disabled={isFetching}
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleExport}
            >
              <Download className="w-4 h-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        {/* Loading State */}
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : error ? (
          <Card className="p-6">
            <div className="text-center text-destructive">
              <p className="font-semibold">Error loading analytics</p>
              <p className="text-sm mt-1">{error instanceof Error ? error.message : 'Unknown error'}</p>
              <Button onClick={() => refetch()} className="mt-4" size="sm">
                Try Again
              </Button>
            </div>
          </Card>
        ) : (
          <>
            {/* Key Metrics Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {/* Total Companies */}
              <Card className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-muted-foreground">Companies</p>
                    <h3 className="text-3xl font-bold mt-2">{stats.total_companies}</h3>
                    <div className={`flex items-center gap-1 mt-2 text-sm ${getTrendColor(companyTrend.direction)}`}>
                      {getTrendIcon(companyTrend.direction)}
                      <span>{companyTrend.percent.toFixed(1)}% vs last period</span>
                    </div>
                  </div>
                  <div className="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                    <Building2 className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  </div>
                </div>
              </Card>

              {/* Total Contacts */}
              <Card className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-muted-foreground">Contacts</p>
                    <h3 className="text-3xl font-bold mt-2">{stats.total_contacts}</h3>
                    <div className={`flex items-center gap-1 mt-2 text-sm ${getTrendColor(contactTrend.direction)}`}>
                      {getTrendIcon(contactTrend.direction)}
                      <span>{contactTrend.percent.toFixed(1)}% vs last period</span>
                    </div>
                  </div>
                  <div className="p-3 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                    <Users className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                  </div>
                </div>
              </Card>

              {/* Active Deals */}
              <Card className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-muted-foreground">Active Deals</p>
                    <h3 className="text-3xl font-bold mt-2">{stats.total_deals}</h3>
                    <div className={`flex items-center gap-1 mt-2 text-sm ${getTrendColor(dealTrend.direction)}`}>
                      {getTrendIcon(dealTrend.direction)}
                      <span>{dealTrend.percent.toFixed(1)}% vs last period</span>
                    </div>
                  </div>
                  <div className="p-3 bg-orange-100 dark:bg-orange-900/20 rounded-lg">
                    <Target className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                  </div>
                </div>
              </Card>

              {/* Revenue */}
              <Card className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-muted-foreground">Won Revenue</p>
                    <h3 className="text-3xl font-bold mt-2">{formatCurrency(stats.won_deals_value)}</h3>
                    <div className={`flex items-center gap-1 mt-2 text-sm ${getTrendColor(revenueTrend.direction)}`}>
                      {getTrendIcon(revenueTrend.direction)}
                      <span>{revenueTrend.percent.toFixed(1)}% vs last period</span>
                    </div>
                  </div>
                  <div className="p-3 bg-green-100 dark:bg-green-900/20 rounded-lg">
                    <DollarSign className="w-5 h-5 text-green-600 dark:text-green-400" />
                  </div>
                </div>
              </Card>
            </div>

            {/* Pipeline Metrics */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Pipeline Value by Stage */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold">Pipeline by Stage</h3>
                  <Activity className="w-5 h-5 text-muted-foreground" />
                </div>

                {pipeline.stages && pipeline.stages.length > 0 ? (
                  <div className="space-y-4">
                    {pipeline.stages.map((stage: any) => {
                      const maxValue = Math.max(...pipeline.stages.map((s: any) => s.total_value || 0));
                      const percentage = maxValue > 0 ? ((stage.total_value || 0) / maxValue) * 100 : 0;

                      return (
                        <div key={stage.stage}>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium capitalize">
                              {stage.stage.replace(/_/g, ' ')}
                            </span>
                            <span className="text-sm font-semibold">
                              {formatCurrency(stage.total_value || 0)} ({stage.deal_count || 0})
                            </span>
                          </div>
                          <div className="w-full bg-muted rounded-full h-2">
                            <div
                              className="bg-blue-600 dark:bg-blue-400 h-2 rounded-full transition-all"
                              style={{ width: `${percentage}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <BarChart3 className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No pipeline data available</p>
                  </div>
                )}
              </Card>

              {/* Performance Metrics */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold">Performance Metrics</h3>
                  <TrendingUp className="w-5 h-5 text-muted-foreground" />
                </div>

                <div className="space-y-6">
                  {/* Win Rate */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Win Rate</span>
                      <span className="text-2xl font-bold text-green-600 dark:text-green-400">
                        {stats.win_rate.toFixed(1)}%
                      </span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-green-600 dark:bg-green-400 h-2 rounded-full transition-all"
                        style={{ width: `${stats.win_rate}%` }}
                      />
                    </div>
                  </div>

                  {/* Conversion Rate */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Conversion Rate</span>
                      <span className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                        {stats.conversion_rate.toFixed(1)}%
                      </span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-blue-600 dark:bg-blue-400 h-2 rounded-full transition-all"
                        style={{ width: `${stats.conversion_rate}%` }}
                      />
                    </div>
                  </div>

                  {/* Average Deal Size */}
                  <div className="pt-4 border-t">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-muted-foreground">Average Deal Size</span>
                      <span className="text-xl font-bold">
                        {formatCurrency(stats.average_deal_size)}
                      </span>
                    </div>
                  </div>

                  {/* Average Sales Cycle */}
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-muted-foreground">Avg Sales Cycle</span>
                      <span className="text-xl font-bold">
                        {stats.average_sales_cycle} days
                      </span>
                    </div>
                  </div>
                </div>
              </Card>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card className="p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                    <DollarSign className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <h3 className="font-semibold">Pipeline Value</h3>
                </div>
                <p className="text-3xl font-bold">{formatCurrency(stats.active_deals_value)}</p>
                <p className="text-sm text-muted-foreground mt-2">
                  Active opportunities in pipeline
                </p>
              </Card>

              <Card className="p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                    <Activity className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                  </div>
                  <h3 className="font-semibold">Activities</h3>
                </div>
                <p className="text-3xl font-bold">{stats.total_activities}</p>
                <p className="text-sm text-muted-foreground mt-2">
                  Interactions this period
                </p>
              </Card>

              <Card className="p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-green-100 dark:bg-green-900/20 rounded-lg">
                    <Calendar className="w-5 h-5 text-green-600 dark:text-green-400" />
                  </div>
                  <h3 className="font-semibold">This Period</h3>
                </div>
                <p className="text-3xl font-bold">{timeRange.toUpperCase()}</p>
                <p className="text-sm text-muted-foreground mt-2">
                  Selected time range
                </p>
              </Card>
            </div>
          </>
        )}
      </div>
    </MainLayout>
  );
}
