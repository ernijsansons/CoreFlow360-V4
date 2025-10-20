/**
 * Dashboard Service - Provides aggregated business metrics and insights
 */

import type { Env } from '../types/env';

export interface DashboardStats {
  overview: {
    totalUsers: number;
    totalRevenue: number;
    churnRate: number;
    activeProjects: number;
    userGrowth: string;
    revenueGrowth: string;
    churnChange: string;
    projectGrowth: string;
  };
  revenueByMonth: {
    month: string;
    revenue: number;
  }[];
  topProducts: {
    name: string;
    revenue: number;
    units: number;
  }[];
  recentActivity: {
    id: string;
    type: string;
    description: string;
    timestamp: string;
    user?: string;
  }[];
  tasks: {
    total: number;
    completed: number;
    pending: number;
    overdue: number;
  };
}

export class DashboardService {
  constructor(
    private db: D1Database,
    private businessId: string
  ) {}

  /**
   * Get complete dashboard statistics
   */
  async getStats(dateRange: '7d' | '30d' | '90d' | '1y' = '30d'): Promise<DashboardStats> {
    const days = this.getDaysFromRange(dateRange);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    const startDateStr = startDate.toISOString();

    // Get overview stats
    const overview = await this.getOverviewStats(startDateStr);

    // Get revenue trend
    const revenueByMonth = await this.getRevenueTrend(days);

    // Get top products/services
    const topProducts = await this.getTopProducts(startDateStr);

    // Get recent activity
    const recentActivity = await this.getRecentActivity(20);

    // Get tasks summary
    const tasks = await this.getTasksSummary();

    return {
      overview,
      revenueByMonth,
      topProducts,
      recentActivity,
      tasks
    };
  }

  /**
   * Get overview KPI metrics
   */
  private async getOverviewStats(startDate: string) {
    // Count users created after start date
    const userStats = await this.db.prepare(`
      SELECT
        COUNT(*) as total_users,
        COUNT(CASE WHEN created_at >= ? THEN 1 END) as new_users
      FROM business_memberships
      WHERE business_id = ? AND status = 'active'
    `).bind(startDate, this.businessId).first<any>();

    // Calculate revenue from invoices
    const revenueStats = await this.db.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN status = 'paid' THEN total_amount ELSE 0 END), 0) as total_revenue,
        COALESCE(SUM(CASE WHEN status = 'paid' AND paid_at >= ? THEN total_amount ELSE 0 END), 0) as period_revenue
      FROM invoices
      WHERE business_id = ?
    `).bind(startDate, this.businessId).first<any>();

    // Count active projects/leads
    const projectStats = await this.db.prepare(`
      SELECT
        COUNT(*) as total_projects,
        COUNT(CASE WHEN created_at >= ? THEN 1 END) as new_projects
      FROM crm_leads
      WHERE business_id = ? AND deleted_at IS NULL
    `).bind(startDate, this.businessId).first<any>();

    // Calculate growth percentages (simplified - compare to previous period)
    const totalUsers = userStats?.total_users || 0;
    const newUsers = userStats?.new_users || 0;
    const userGrowth = totalUsers > 0 ? ((newUsers / totalUsers) * 100).toFixed(1) : '0.0';

    const totalRevenue = revenueStats?.total_revenue || 0;
    const periodRevenue = revenueStats?.period_revenue || 0;
    const revenueGrowth = totalRevenue > 0 ? ((periodRevenue / totalRevenue) * 100).toFixed(1) : '0.0';

    const totalProjects = projectStats?.total_projects || 0;
    const newProjects = projectStats?.new_projects || 0;
    const projectGrowth = totalProjects > 0 ? ((newProjects / totalProjects) * 100).toFixed(1) : '0.0';

    return {
      totalUsers: totalUsers,
      totalRevenue: totalRevenue,
      churnRate: 2.4, // TODO: Calculate real churn rate
      activeProjects: totalProjects,
      userGrowth: `+${userGrowth}%`,
      revenueGrowth: `+${revenueGrowth}%`,
      churnChange: '-0.8%', // TODO: Calculate real churn change
      projectGrowth: `+${projectGrowth}%`
    };
  }

  /**
   * Get revenue trend by month
   */
  private async getRevenueTrend(days: number) {
    const months = Math.ceil(days / 30);

    const results = await this.db.prepare(`
      SELECT
        strftime('%Y-%m', paid_at) as month,
        SUM(total_amount) as revenue
      FROM invoices
      WHERE business_id = ?
        AND status = 'paid'
        AND paid_at >= date('now', '-${months} months')
      GROUP BY strftime('%Y-%m', paid_at)
      ORDER BY month ASC
    `).bind(this.businessId).all<any>();

    return results.results?.map(row => ({
      month: row.month || '',
      revenue: parseFloat(row.revenue || 0)
    })) || [];
  }

  /**
   * Get top products/services by revenue
   */
  private async getTopProducts(startDate: string) {
    const results = await this.db.prepare(`
      SELECT
        li.description as name,
        SUM(li.line_total) as revenue,
        SUM(li.quantity) as units
      FROM invoice_items li
      JOIN invoices i ON li.invoice_id = i.id
      WHERE i.business_id = ?
        AND i.status = 'paid'
        AND i.paid_at >= ?
      GROUP BY li.description
      ORDER BY revenue DESC
      LIMIT 5
    `).bind(this.businessId, startDate).all<any>();

    return results.results?.map(row => ({
      name: row.name || 'Unknown',
      revenue: parseFloat(row.revenue || 0),
      units: parseInt(row.units || 0)
    })) || [];
  }

  /**
   * Get recent activity feed
   */
  private async getRecentActivity(limit: number = 20) {
    try {
      // Get recent activities from audit log
      const results = await this.db.prepare(`
        SELECT
          id,
          event as type,
          metadata,
          created_at as timestamp,
          user_id
        FROM audit_log
        WHERE business_id = ?
        ORDER BY created_at DESC
        LIMIT ?
      `).bind(this.businessId, limit).all<any>();

      return results.results?.map(row => {
        const metadata = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
        return {
          id: row.id,
          type: row.type,
          description: this.formatActivityDescription(row.type, metadata),
          timestamp: row.timestamp,
          user: row.user_id
        };
      }) || [];
    } catch (error) {
      // Audit log table might not exist
      return [];
    }
  }

  /**
   * Get tasks summary
   */
  private async getTasksSummary() {
    // Get task counts by status (if tasks table exists)
    try {
      const result = await this.db.prepare(`
        SELECT
          COUNT(*) as total,
          COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
          COUNT(CASE WHEN status = 'pending' OR status = 'in_progress' THEN 1 END) as pending,
          COUNT(CASE WHEN due_date < datetime('now') AND status != 'completed' THEN 1 END) as overdue
        FROM tasks
        WHERE business_id = ?
      `).bind(this.businessId).first<any>();

      return {
        total: result?.total || 0,
        completed: result?.completed || 0,
        pending: result?.pending || 0,
        overdue: result?.overdue || 0
      };
    } catch (error) {
      // Tasks table might not exist, return zeros
      return {
        total: 0,
        completed: 0,
        pending: 0,
        overdue: 0
      };
    }
  }

  /**
   * Format activity description based on event type
   */
  private formatActivityDescription(type: string, metadata: any): string {
    const formatters: Record<string, (m: any) => string> = {
      'login': () => 'User logged in',
      'invoice_created': (m) => `Invoice ${m.invoice_number || ''} created`,
      'invoice_paid': (m) => `Invoice ${m.invoice_number || ''} marked as paid`,
      'contact_created': (m) => `New contact ${m.name || ''} added`,
      'lead_created': (m) => `New lead ${m.company || ''} created`,
      'deal_won': (m) => `Deal won: ${m.deal_name || ''}`,
      'user_invited': (m) => `User ${m.email || ''} invited`,
    };

    const formatter = formatters[type];
    return formatter ? formatter(metadata) : `${type} event`;
  }

  /**
   * Convert date range to days
   */
  private getDaysFromRange(range: '7d' | '30d' | '90d' | '1y'): number {
    const map = { '7d': 7, '30d': 30, '90d': 90, '1y': 365 };
    return map[range];
  }
}
