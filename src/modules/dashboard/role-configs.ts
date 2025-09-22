/**
 * Role-Based Dashboard Configurations
 * Automatic dashboard setup for different user roles
 */

import { z } from 'zod'
import type { Env } from '@/types/env'
import type { Widget, Dashboard, DashboardLayout } from '@/types/dashboard'
import { AppError } from '@/shared/errors/app-error'

export type UserRole = 'ceo' | 'cfo' | 'sales_manager'
  | 'sales_rep' | 'marketing_manager' | 'operations_manager' | 'hr_manager' | 'admin'

interface RoleDashboardConfig {
  name: string
  description: string
  widgets: Partial<Widget>[]
  layout: DashboardLayout
  permissions: {
    canEdit: boolean
    canExport: boolean
    canShare: boolean
    dataAccess: string[]
  }
}

const CEO_DASHBOARD_CONFIG: RoleDashboardConfig = {
  name: 'Executive Overview',
  description: 'High-level KPIs and strategic metrics for executive decision making',
  widgets: [
    {
      type: 'revenue_kpi',
      title: 'Total Revenue',
      description: 'Company-wide revenue performance',
      config: {
        metric: 'total_revenue',
        period: '30d',
        showTrend: true,
        showTarget: true,
        target: 1000000
      }
    },
    {
      type: 'profit_margin_kpi',
      title: 'Profit Margin',
      description: 'Overall profitability percentage',
      config: {
        metric: 'profit_margin',
        period: '30d',
        showTrend: true,
        threshold: { good: 20, warning: 15 }
      }
    },
    {
      type: 'customer_growth_kpi',
      title: 'Customer Growth',
      description: 'Monthly customer acquisition rate',
      config: {
        metric: 'customer_growth',
        period: '30d',
        showTrend: true
      }
    },
    {
      type: 'employee_count_kpi',
      title: 'Team Size',
      description: 'Total active employees',
      config: {
        metric: 'employee_count',
        realTime: true
      }
    },
    {
      type: 'line_chart',
      title: 'Revenue Trend',
      description: '12-month revenue performance',
      config: {
        metric: 'monthly_revenue',
        period: '12m',
        groupBy: 'month',
        showGrid: true,
        showLegend: true
      }
    },
    {
      type: 'bar_chart',
      title: 'Department Performance',
      description: 'Revenue by department',
      config: {
        metric: 'department_revenue',
        period: '30d',
        groupBy: 'department'
      }
    },
    {
      type: 'pie_chart',
      title: 'Market Share',
      description: 'Revenue distribution by market segment',
      config: {
        metric: 'market_revenue',
        period: '30d',
        groupBy: 'segment'
      }
    },
    {
      type: 'data_table',
      title: 'Top Opportunities',
      description: 'Highest value sales opportunities',
      config: {
        metric: 'top_opportunities',
        limit: 10,
        sortBy: 'value',
        columns: ['name', 'value', 'stage', 'close_date', 'owner']
      }
    },
    {
      type: 'gauge_chart',
      title: 'Goal Progress',
      description: 'Annual revenue goal achievement',
      config: {
        metric: 'annual_goal_progress',
        target: 10000000,
        showPercentage: true
      }
    },
    {
      type: 'heatmap_chart',
      title: 'Performance Heatmap',
      description: 'Team performance across metrics',
      config: {
        metric: 'team_performance',
        xAxis: 'team_member',
        yAxis: 'metric',
        period: '30d'
      }
    }
  ],
  layout: {
    lg: [
      { i: '0', x: 0, y: 0, w: 6, h: 4 },   // Revenue KPI
      { i: '1', x: 6, y: 0, w: 6, h: 4 },   // Profit Margin KPI
      { i: '2', x: 12, y: 0, w: 6, h: 4 },  // Customer Growth KPI
      { i: '3', x: 18, y: 0, w: 6, h: 4 },  // Employee Count KPI
      { i: '4', x: 0, y: 4, w: 12, h: 8 },  // Revenue Trend Chart
      { i: '5', x: 12, y: 4, w: 12, h: 8 }, // Department Performance
      { i: '6', x: 0, y: 12, w: 8, h: 8 },  // Market Share
      { i: '7', x: 8, y: 12, w: 16, h: 8 }, // Top Opportunities
      { i: '8', x: 0, y: 20, w: 8, h: 6 },  // Goal Progress
      { i: '9', x: 8, y: 20, w: 16, h: 6 }  // Performance Heatmap
    ]
  },
  permissions: {
    canEdit: true,
    canExport: true,
    canShare: true,
    dataAccess: ['all']
  }
}

const CFO_DASHBOARD_CONFIG: RoleDashboardConfig = {
  name: 'Financial Dashboard',
  description: 'Financial metrics, cash flow, and budget analysis',
  widgets: [
    {
      type: 'revenue_kpi',
      title: 'Monthly Revenue',
      description: 'Current month revenue performance',
      config: {
        metric: 'monthly_revenue',
        period: '1m',
        showTrend: true,
        showTarget: true
      }
    },
    {
      type: 'expense_kpi',
      title: 'Monthly Expenses',
      description: 'Operating expenses this month',
      config: {
        metric: 'monthly_expenses',
        period: '1m',
        showTrend: true
      }
    },
    {
      type: 'cash_flow_kpi',
      title: 'Cash Flow',
      description: 'Net cash flow position',
      config: {
        metric: 'cash_flow',
        period: '1m',
        showTrend: true,
        threshold: { good: 100000, warning: 50000 }
      }
    },
    {
      type: 'burn_rate_kpi',
      title: 'Burn Rate',
      description: 'Monthly cash burn rate',
      config: {
        metric: 'burn_rate',
        period: '1m',
        showTrend: true
      }
    },
    {
      type: 'waterfall_chart',
      title: 'Cash Flow Breakdown',
      description: 'Monthly cash flow components',
      config: {
        metric: 'cash_flow_breakdown',
        period: '1m',
        categories: ['revenue', 'expenses', 'investments', 'financing']
      }
    },
    {
      type: 'line_chart',
      title: 'Budget vs Actual',
      description: 'Budget performance tracking',
      config: {
        metric: 'budget_vs_actual',
        period: '12m',
        groupBy: 'month',
        datasets: ['budget', 'actual']
      }
    },
    {
      type: 'bar_chart',
      title: 'Expense Categories',
      description: 'Spending by category',
      config: {
        metric: 'expense_categories',
        period: '1m',
        groupBy: 'category'
      }
    },
    {
      type: 'data_table',
      title: 'Outstanding Invoices',
      description: 'Unpaid invoices and aging',
      config: {
        metric: 'outstanding_invoices',
        sortBy: 'due_date',
        columns: ['invoice_number', 'customer', 'amount', 'due_date', 'days_overdue']
      }
    },
    {
      type: 'gauge_chart',
      title: 'Collection Rate',
      description: 'Invoice collection efficiency',
      config: {
        metric: 'collection_rate',
        period: '30d',
        target: 95,
        showPercentage: true
      }
    },
    {
      type: 'forecast_chart',
      title: 'Revenue Forecast',
      description: 'AI-powered revenue predictions',
      config: {
        metric: 'revenue_forecast',
        period: '6m',
        showConfidenceInterval: true
      }
    }
  ],
  layout: {
    lg: [
      { i: '0', x: 0, y: 0, w: 6, h: 4 },   // Monthly Revenue
      { i: '1', x: 6, y: 0, w: 6, h: 4 },   // Monthly Expenses
      { i: '2', x: 12, y: 0, w: 6, h: 4 },  // Cash Flow
      { i: '3', x: 18, y: 0, w: 6, h: 4 },  // Burn Rate
      { i: '4', x: 0, y: 4, w: 12, h: 8 },  // Cash Flow Breakdown
      { i: '5', x: 12, y: 4, w: 12, h: 8 }, // Budget vs Actual
      { i: '6', x: 0, y: 12, w: 8, h: 8 },  // Expense Categories
      { i: '7', x: 8, y: 12, w: 16, h: 8 }, // Outstanding Invoices
      { i: '8', x: 0, y: 20, w: 8, h: 6 },  // Collection Rate
      { i: '9', x: 8, y: 20, w: 16, h: 6 }  // Revenue Forecast
    ]
  },
  permissions: {
    canEdit: true,
    canExport: true,
    canShare: true,
    dataAccess: ['financial', 'accounting', 'budget']
  }
}

const SALES_MANAGER_DASHBOARD_CONFIG: RoleDashboardConfig = {
  name: 'Sales Management',
  description: 'Sales team performance, pipeline, and targets',
  widgets: [
    {
      type: 'sales_kpi',
      title: 'Monthly Sales',
      description: 'Current month sales performance',
      config: {
        metric: 'monthly_sales',
        period: '1m',
        showTrend: true,
        showTarget: true
      }
    },
    {
      type: 'pipeline_kpi',
      title: 'Pipeline Value',
      description: 'Total opportunity value in pipeline',
      config: {
        metric: 'pipeline_value',
        realTime: true,
        showTrend: true
      }
    },
    {
      type: 'conversion_kpi',
      title: 'Conversion Rate',
      description: 'Lead to customer conversion rate',
      config: {
        metric: 'conversion_rate',
        period: '30d',
        showTrend: true,
        threshold: { good: 25, warning: 15 }
      }
    },
    {
      type: 'quota_kpi',
      title: 'Quota Attainment',
      description: 'Team quota achievement',
      config: {
        metric: 'quota_attainment',
        period: '1m',
        showPercentage: true,
        target: 100
      }
    },
    {
      type: 'funnel_chart',
      title: 'Sales Funnel',
      description: 'Lead progression through stages',
      config: {
        metric: 'sales_funnel',
        period: '30d',
        stages: ['leads', 'qualified', 'proposal', 'negotiation', 'closed']
      }
    },
    {
      type: 'bar_chart',
      title: 'Team Performance',
      description: 'Sales by team member',
      config: {
        metric: 'sales_by_rep',
        period: '1m',
        groupBy: 'sales_rep'
      }
    },
    {
      type: 'line_chart',
      title: 'Sales Trend',
      description: 'Monthly sales progression',
      config: {
        metric: 'monthly_sales_trend',
        period: '12m',
        groupBy: 'month'
      }
    },
    {
      type: 'data_table',
      title: 'Top Deals',
      description: 'Highest value opportunities',
      config: {
        metric: 'top_deals',
        limit: 15,
        sortBy: 'value',
        columns: ['opportunity', 'customer', 'value', 'stage', 'close_date', 'probability']
      }
    },
    {
      type: 'map_chart',
      title: 'Sales by Territory',
      description: 'Geographic sales distribution',
      config: {
        metric: 'sales_by_territory',
        period: '1m',
        mapType: 'regions'
      }
    },
    {
      type: 'activity_feed',
      title: 'Recent Activities',
      description: 'Latest sales team activities',
      config: {
        metric: 'sales_activities',
        limit: 10,
        types: ['calls', 'meetings', 'proposals', 'closes']
      }
    }
  ],
  layout: {
    lg: [
      { i: '0', x: 0, y: 0, w: 6, h: 4 },   // Monthly Sales
      { i: '1', x: 6, y: 0, w: 6, h: 4 },   // Pipeline Value
      { i: '2', x: 12, y: 0, w: 6, h: 4 },  // Conversion Rate
      { i: '3', x: 18, y: 0, w: 6, h: 4 },  // Quota Attainment
      { i: '4', x: 0, y: 4, w: 8, h: 8 },   // Sales Funnel
      { i: '5', x: 8, y: 4, w: 8, h: 8 },   // Team Performance
      { i: '6', x: 16, y: 4, w: 8, h: 8 },  // Sales Trend
      { i: '7', x: 0, y: 12, w: 16, h: 8 }, // Top Deals
      { i: '8', x: 16, y: 12, w: 8, h: 8 }, // Sales by Territory
      { i: '9', x: 0, y: 20, w: 24, h: 6 }  // Recent Activities
    ]
  },
  permissions: {
    canEdit: true,
    canExport: true,
    canShare: true,
    dataAccess: ['sales', 'customers', 'opportunities']
  }
}

const SALES_REP_DASHBOARD_CONFIG: RoleDashboardConfig = {
  name: 'Sales Performance',
  description: 'Individual sales metrics and personal targets',
  widgets: [
    {
      type: 'personal_quota_kpi',
      title: 'My Quota',
      description: 'Personal quota achievement',
      config: {
        metric: 'personal_quota',
        period: '1m',
        showPercentage: true,
        showTarget: true
      }
    },
    {
      type: 'personal_sales_kpi',
      title: 'My Sales',
      description: 'Personal sales this month',
      config: {
        metric: 'personal_sales',
        period: '1m',
        showTrend: true
      }
    },
    {
      type: 'personal_pipeline_kpi',
      title: 'My Pipeline',
      description: 'Personal pipeline value',
      config: {
        metric: 'personal_pipeline',
        realTime: true,
        showTrend: true
      }
    },
    {
      type: 'activities_kpi',
      title: 'Activities Today',
      description: 'Completed activities today',
      config: {
        metric: 'daily_activities',
        period: '1d',
        target: 10
      }
    },
    {
      type: 'data_table',
      title: 'My Opportunities',
      description: 'Active sales opportunities',
      config: {
        metric: 'personal_opportunities',
        sortBy: 'close_date',
        columns: ['opportunity', 'customer', 'value', 'stage', 'close_date', 'next_action']
      }
    },
    {
      type: 'calendar_widget',
      title: 'My Schedule',
      description: 'Upcoming meetings and tasks',
      config: {
        metric: 'personal_calendar',
        period: '7d',
        showTasks: true
      }
    },
    {
      type: 'leaderboard',
      title: 'Team Ranking',
      description: 'Performance vs teammates',
      config: {
        metric: 'sales_leaderboard',
        period: '1m',
        showRank: true,
        limit: 10
      }
    },
    {
      type: 'progress_chart',
      title: 'Monthly Progress',
      description: 'Daily progress toward quota',
      config: {
        metric: 'daily_quota_progress',
        period: '1m',
        showTarget: true
      }
    }
  ],
  layout: {
    lg: [
      { i: '0', x: 0, y: 0, w: 6, h: 4 },   // Personal Quota
      { i: '1', x: 6, y: 0, w: 6, h: 4 },   // Personal Sales
      { i: '2', x: 12, y: 0, w: 6, h: 4 },  // Personal Pipeline
      { i: '3', x: 18, y: 0, w: 6, h: 4 },  // Activities Today
      { i: '4', x: 0, y: 4, w: 12, h: 10 }, // My Opportunities
      { i: '5', x: 12, y: 4, w: 12, h: 10 }, // My Schedule
      { i: '6', x: 0, y: 14, w: 8, h: 8 },  // Team Ranking
      { i: '7', x: 8, y: 14, w: 16, h: 8 }  // Monthly Progress
    ]
  },
  permissions: {
    canEdit: false,
    canExport: true,
    canShare: false,
    dataAccess: ['personal_sales', 'personal_customers']
  }
}

// Dashboard configurations by role
export const ROLE_DASHBOARD_CONFIGS: Record<UserRole, RoleDashboardConfig> = {
  ceo: CEO_DASHBOARD_CONFIG,
  cfo: CFO_DASHBOARD_CONFIG,
  sales_manager: SALES_MANAGER_DASHBOARD_CONFIG,
  sales_rep: SALES_REP_DASHBOARD_CONFIG,
  marketing_manager: {
    name: 'Marketing Analytics',
    description: 'Campaign performance and lead generation metrics',
    widgets: [], // Would be defined similar to above
    layout: { lg: [] },
    permissions: {
      canEdit: true,
      canExport: true,
      canShare: true,
      dataAccess: ['marketing', 'campaigns', 'leads']
    }
  },
  operations_manager: {
    name: 'Operations Dashboard',
    description: 'Operational efficiency and resource utilization',
    widgets: [], // Would be defined similar to above
    layout: { lg: [] },
    permissions: {
      canEdit: true,
      canExport: true,
      canShare: true,
      dataAccess: ['operations', 'inventory', 'logistics']
    }
  },
  hr_manager: {
    name: 'Human Resources',
    description: 'Employee metrics and HR analytics',
    widgets: [], // Would be defined similar to above
    layout: { lg: [] },
    permissions: {
      canEdit: true,
      canExport: true,
      canShare: true,
      dataAccess: ['hr', 'employees', 'payroll']
    }
  },
  admin: {
    name: 'System Administration',
    description: 'System health and usage analytics',
    widgets: [], // Would be defined similar to above
    layout: { lg: [] },
    permissions: {
      canEdit: true,
      canExport: true,
      canShare: true,
      dataAccess: ['all']
    }
  }
}

export // TODO: Consider splitting RoleBasedDashboardService into smaller, focused classes
class RoleBasedDashboardService {
  constructor(private env: Env) {}

  /**
   * Get dashboard configuration for user role
   */
  getRoleConfiguration(role: UserRole): RoleDashboardConfig {
    const config = ROLE_DASHBOARD_CONFIGS[role]
    if (!config) {
      throw new AppError(`No dashboard configuration found for role: ${role}`, 'INVALID_ROLE')
    }
    return config
  }

  /**
   * Create default dashboard for user based on role
   */
  async createRoleDashboard(
    userId: string,
    businessId: string,
    role: UserRole
  ): Promise<Dashboard> {
    const config = this.getRoleConfiguration(role)

    // Generate dashboard ID
    const dashboardId = crypto.randomUUID()

    // Create dashboard record
    const dashboard: Dashboard = {
      id: dashboardId,
      name: config.name,
      description: config.description,
      businessId,
      userId,
      isDefault: true,
      isPublic: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }

    // Save dashboard to database
    await this.env.DB.prepare(`
      INSERT INTO dashboards (
        id, name, description, business_id, user_id,
        is_default, is_public, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      dashboard.id,
      dashboard.name,
      dashboard.description,
      dashboard.businessId,
      dashboard.userId,
      dashboard.isDefault ? 1 : 0,
      dashboard.isPublic ? 1 : 0,
      dashboard.createdAt,
      dashboard.updatedAt
    ).run()

    // Create widgets
    for (let i = 0; i < config.widgets.length; i++) {
      const widgetConfig = config.widgets[i]
      const widgetId = crypto.randomUUID()

      const widget: Widget = {
        id: widgetId,
        dashboardId,
        type: widgetConfig.type!,
        title: widgetConfig.title!,
        description: widgetConfig.description,
        config: widgetConfig.config || {},
        position: config.layout.lg[i] || { i: String(i), x: 0, y: 0, w: 6, h: 4 },
        isVisible: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }

      await this.env.DB.prepare(`
        INSERT INTO dashboard_widgets (
          id, dashboard_id, type, title, description, config,
          position, is_visible, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        widget.id,
        widget.dashboardId,
        widget.type,
        widget.title,
        widget.description || '',
        JSON.stringify(widget.config),
        JSON.stringify(widget.position),
        widget.isVisible ? 1 : 0,
        widget.createdAt,
        widget.updatedAt
      ).run()
    }

    // Save layout
    await this.env.DB.prepare(`
      INSERT INTO dashboard_layouts (
        dashboard_id, layout_data, created_at, updated_at
      ) VALUES (?, ?, ?, ?)
    `).bind(
      dashboard.id,
      JSON.stringify(config.layout),
      new Date().toISOString(),
      new Date().toISOString()
    ).run()

    // Save permissions
    await this.env.DB.prepare(`
      INSERT INTO dashboard_permissions (
        dashboard_id, user_id, can_edit, can_export, can_share, data_access
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      dashboard.id,
      userId,
      config.permissions.canEdit ? 1 : 0,
      config.permissions.canExport ? 1 : 0,
      config.permissions.canShare ? 1 : 0,
      JSON.stringify(config.permissions.dataAccess)
    ).run()

    return dashboard
  }

  /**
   * Get recommended widgets for role
   */
  getRecommendedWidgets(role: UserRole): Partial<Widget>[] {
    const config = this.getRoleConfiguration(role)
    return config.widgets
  }

  /**
   * Check if user can access data type
   */
  canAccessData(role: UserRole, dataType: string): boolean {
    const config = this.getRoleConfiguration(role)
    return config.permissions.dataAccess.includes('all') ||
           config.permissions.dataAccess.includes(dataType)
  }

  /**
   * Get role permissions
   */
  getRolePermissions(role: UserRole) {
    const config = this.getRoleConfiguration(role)
    return config.permissions
  }

  /**
   * Update dashboard based on role requirements
   */
  async updateDashboardForRole(
    dashboardId: string,
    role: UserRole
  ): Promise<void> {
    const config = this.getRoleConfiguration(role)

    // Update dashboard metadata
    await this.env.DB.prepare(`
      UPDATE dashboards
      SET name = ?, description = ?, updated_at = ?
      WHERE id = ?
    `).bind(
      config.name,
      config.description,
      new Date().toISOString(),
      dashboardId
    ).run()

    // Update permissions
    await this.env.DB.prepare(`
      UPDATE dashboard_permissions
      SET can_edit = ?, can_export = ?, can_share = ?, data_access = ?
      WHERE dashboard_id = ?
    `).bind(
      config.permissions.canEdit ? 1 : 0,
      config.permissions.canExport ? 1 : 0,
      config.permissions.canShare ? 1 : 0,
      JSON.stringify(config.permissions.dataAccess),
      dashboardId
    ).run()
  }
}

export default RoleBasedDashboardService