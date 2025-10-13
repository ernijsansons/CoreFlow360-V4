import apiClient, { ApiResponse } from '../client'

export interface DashboardStats {
  overview: {
    totalUsers: number
    totalRevenue: number
    churnRate: number
    activeProjects: number
    userGrowth: string
    revenueGrowth: string
    churnChange: string
    projectGrowth: string
  }
  revenueByMonth: {
    month: string
    revenue: number
  }[]
  topProducts: {
    name: string
    revenue: number
    units: number
  }[]
  recentActivity: {
    id: string
    type: string
    description: string
    timestamp: string
    user?: string
  }[]
  tasks: {
    total: number
    completed: number
    pending: number
    overdue: number
  }
}

export interface Activity {
  id: string
  type: string
  description: string
  timestamp: string
  user?: string
  metadata?: Record<string, unknown>
}

export interface TasksSummary {
  total: number
  completed: number
  pending: number
  overdue: number
}

class DashboardService {
  /**
   * Get dashboard statistics
   */
  async getStats(dateRange: '7d' | '30d' | '90d' | '1y' = '30d'): Promise<ApiResponse<DashboardStats>> {
    return apiClient.get<DashboardStats>(`/api/dashboard/stats?dateRange=${dateRange}`)
  }

  /**
   * Get recent activity feed
   */
  async getActivity(limit: number = 20): Promise<ApiResponse<Activity[]>> {
    return apiClient.get<Activity[]>(`/api/dashboard/activity?limit=${limit}`)
  }

  /**
   * Get tasks summary
   */
  async getTasks(): Promise<ApiResponse<TasksSummary>> {
    return apiClient.get<TasksSummary>('/api/dashboard/tasks')
  }

  /**
   * Get chart data for specific metric
   */
  async getChartData(
    metric: 'revenue' | 'users' | 'deals',
    dateRange: '7d' | '30d' | '90d' | '1y' = '30d'
  ): Promise<ApiResponse<any[]>> {
    return apiClient.get<any[]>(`/api/dashboard/charts/${metric}?dateRange=${dateRange}`)
  }
}

export const dashboardService = new DashboardService()
export default dashboardService
