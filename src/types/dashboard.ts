/**
 * Dashboard Types
 * Type definitions for dashboard widgets, layouts, and configurations
 */

export type WidgetType =
  | 'revenue_kpi'
  | 'profit_margin_kpi'
  | 'customer_growth_kpi'
  | 'employee_count_kpi'
  | 'sales_kpi'
  | 'conversion_kpi'
  | 'expense_kpi'
  | 'cash_flow_kpi'
  | 'burn_rate_kpi'
  | 'pipeline_kpi'
  | 'quota_kpi'
  | 'personal_quota_kpi'
  | 'personal_sales_kpi'
  | 'personal_pipeline_kpi'
  | 'activities_kpi'
  | 'line_chart'
  | 'bar_chart'
  | 'pie_chart'
  | 'area_chart'
  | 'funnel_chart'
  | 'waterfall_chart'
  | 'gauge_chart'
  | 'heatmap_chart'
  | 'forecast_chart'
  | 'progress_chart'
  | 'table'
  | 'data_table'
  | 'list'
  | 'timeline'
  | 'calendar'
  | 'calendar_widget'
  | 'map'
  | 'map_chart'
  | 'activity_feed'
  | 'leaderboard'
  | 'custom';

export interface WidgetConfig {
  metric?: string;
  period?: string;
  groupBy?: string;
  showTrend?: boolean;
  showTarget?: boolean;
  target?: number;
  threshold?: {
    good: number;
    warning: number;
  };
  realTime?: boolean;
  showGrid?: boolean;
  showLegend?: boolean;
  filters?: Record<string, unknown>;
  refreshInterval?: number;
  [key: string]: unknown;
}

export interface Widget {
  id?: string;
  dashboardId?: string;
  type: WidgetType;
  title: string;
  description?: string;
  config: WidgetConfig;
  position?: {
    x: number;
    y: number;
    w: number;
    h: number;
  };
  visible?: boolean;
  permissions?: string[];
  createdAt?: number;
  updatedAt?: number;
}

export interface DashboardLayout {
  cols?: number;
  rows?: number;
  gap?: number;
  responsive?: boolean;
  breakpoints?: {
    mobile: number;
    tablet: number;
    desktop: number;
  };
  lg?: Array<{
    i: string;
    x: number;
    y: number;
    w: number;
    h: number;
  }>;
}

export interface Dashboard {
  id: string;
  name: string;
  description?: string;
  userId?: string;
  businessId?: string;
  widgets: Widget[];
  layout: DashboardLayout;
  isDefault?: boolean;
  isShared?: boolean;
  isPublic?: boolean;
  sharedWith?: string[];
  permissions?: {
    canEdit: boolean;
    canExport: boolean;
    canShare: boolean;
    dataAccess: string[];
  };
  tags?: string[];
  createdAt: number;
  updatedAt: number;
}

export interface MetricDefinition {
  id: string;
  name: string;
  description?: string;
  category: 'revenue' | 'sales' | 'marketing' | 'operations' | 'finance' | 'hr' | 'custom';
  dataSource: {
    type: 'database' | 'api' | 'computed';
    query?: string;
    endpoint?: string;
    computation?: string;
  };
  format: 'currency' | 'percentage' | 'number' | 'duration' | 'date';
  aggregation?: 'sum' | 'avg' | 'count' | 'min' | 'max' | 'median';
  refreshInterval?: number;
}

export interface DashboardPermissions {
  view: string[];
  edit: string[];
  share: string[];
  export: string[];
  delete: string[];
}

export interface RolePermissions {
  role: string;
  dashboards: {
    canCreate: boolean;
    canView: boolean;
    canEdit: boolean;
    canDelete: boolean;
    canShare: boolean;
    canExport: boolean;
  };
  widgets: {
    allowed: WidgetType[];
    canCustomize: boolean;
  };
  dataAccess: {
    level: 'all' | 'business' | 'team' | 'own';
    restrictedMetrics?: string[];
  };
}

export interface DashboardConfig {
  id: string;
  name: string;
  description: string;
  role?: string;
  widgets: Partial<Widget>[];
  layout: DashboardLayout;
  permissions: {
    canEdit: boolean;
    canExport: boolean;
    canShare: boolean;
    dataAccess: string[];
  };
}

export interface DashboardFilter {
  id: string;
  name: string;
  type: 'date' | 'select' | 'multiselect' | 'range' | 'search';
  options?: Array<{ label: string; value: string }>;
  default?: unknown;
  required?: boolean;
}

export interface DashboardTheme {
  primaryColor: string;
  secondaryColor: string;
  backgroundColor: string;
  textColor: string;
  chartColors: string[];
}

export interface DashboardExportOptions {
  format: 'pdf' | 'xlsx' | 'csv' | 'json';
  includeCharts: boolean;
  includeData: boolean;
  dateRange?: {
    start: string;
    end: string;
  };
}

export interface DashboardSnapshot {
  id: string;
  dashboardId: string;
  name: string;
  description?: string;
  data: Record<string, unknown>;
  createdAt: number;
  createdBy: string;
}
