import { useQuery } from '@tanstack/react-query'
import { dashboardService } from '../services/dashboard.service'

/**
 * Hook to fetch dashboard statistics
 */
export function useDashboardStats(dateRange: '7d' | '30d' | '90d' | '1y' = '30d') {
  return useQuery({
    queryKey: ['dashboard', 'stats', dateRange],
    queryFn: async () => {
      const response = await dashboardService.getStats(dateRange)
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch dashboard stats')
      }
      return response.data
    },
    staleTime: 1000 * 60 * 5, // 5 minutes
    refetchOnWindowFocus: true,
  })
}

/**
 * Hook to fetch recent activity
 */
export function useDashboardActivity(limit: number = 20) {
  return useQuery({
    queryKey: ['dashboard', 'activity', limit],
    queryFn: async () => {
      const response = await dashboardService.getActivity(limit)
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch activity')
      }
      return response.data
    },
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

/**
 * Hook to fetch tasks summary
 */
export function useDashboardTasks() {
  return useQuery({
    queryKey: ['dashboard', 'tasks'],
    queryFn: async () => {
      const response = await dashboardService.getTasks()
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch tasks')
      }
      return response.data
    },
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

/**
 * Hook to fetch chart data
 */
export function useDashboardChart(
  metric: 'revenue' | 'users' | 'deals',
  dateRange: '7d' | '30d' | '90d' | '1y' = '30d'
) {
  return useQuery({
    queryKey: ['dashboard', 'chart', metric, dateRange],
    queryFn: async () => {
      const response = await dashboardService.getChartData(metric, dateRange)
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch chart data')
      }
      return response.data
    },
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}
