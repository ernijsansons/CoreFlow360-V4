import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { aiMonitoringService } from '@/lib/api/services'
import { toast } from '@/hooks/use-toast'

// Query Keys
export const aiMonitoringKeys = {
  all: ['ai-monitoring'] as const,
  dashboard: (timeRange?: string) => [...aiMonitoringKeys.all, 'dashboard', timeRange] as const,
  scheduledAudits: () => [...aiMonitoringKeys.all, 'scheduled-audits'] as const,
  executions: (filters?: unknown) => [...aiMonitoringKeys.all, 'executions', filters] as const,
  alerts: (filters?: unknown) => [...aiMonitoringKeys.all, 'alerts', filters] as const,
  metrics: () => [...aiMonitoringKeys.all, 'metrics'] as const,
}

// Queries
export function useAIMonitoringDashboard(timeRange?: '1h' | '24h' | '7d' | '30d') {
  return useQuery({
    queryKey: aiMonitoringKeys.dashboard(timeRange),
    queryFn: () => aiMonitoringService.getDashboard({ time_range: timeRange }),
    refetchInterval: 60000, // Refresh every minute
    staleTime: 30000, // 30 seconds
  })
}

export function useScheduledAudits() {
  return useQuery({
    queryKey: aiMonitoringKeys.scheduledAudits(),
    queryFn: () => aiMonitoringService.listScheduledAudits(),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useAuditExecutionHistory(params?: {
  audit_id?: string
  status?: string
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: aiMonitoringKeys.executions(params),
    queryFn: () => aiMonitoringService.getAuditExecutionHistory(params),
    staleTime: 1000 * 60, // 1 minute
  })
}

export function useMonitoringAlerts(params?: {
  severity?: 'low' | 'medium' | 'high' | 'critical'
  resolved?: boolean
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: aiMonitoringKeys.alerts(params),
    queryFn: () => aiMonitoringService.listAlerts(params),
    refetchInterval: 30000, // Refresh every 30 seconds
    staleTime: 15000, // 15 seconds
  })
}

export function useRealtimeMetrics() {
  return useQuery({
    queryKey: aiMonitoringKeys.metrics(),
    queryFn: () => aiMonitoringService.getRealtimeMetrics(),
    refetchInterval: 5000, // Refresh every 5 seconds
    staleTime: 0, // Always fetch fresh data
  })
}

// Mutations
export function useCreateScheduledAudit() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      audit_type: string
      schedule: 'daily' | 'weekly' | 'monthly'
      config?: Record<string, unknown>
    }) => aiMonitoringService.createScheduledAudit(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: aiMonitoringKeys.scheduledAudits() })
      toast({
        title: 'Audit scheduled',
        description: 'The AI audit has been scheduled successfully.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to schedule audit',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useUpdateScheduledAudit() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ auditId, data }: {
      auditId: string
      data: Partial<{
        schedule: 'daily' | 'weekly' | 'monthly'
        enabled: boolean
        config: Record<string, unknown>
      }>
    }) => aiMonitoringService.updateScheduledAudit(auditId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: aiMonitoringKeys.scheduledAudits() })
      toast({
        title: 'Audit updated',
        description: 'The scheduled audit has been updated.',
      })
    },
  })
}

export function useDeleteScheduledAudit() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (auditId: string) => aiMonitoringService.deleteScheduledAudit(auditId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: aiMonitoringKeys.scheduledAudits() })
      toast({
        title: 'Audit deleted',
        description: 'The scheduled audit has been removed.',
      })
    },
  })
}

export function useResolveAlert() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ alertId, notes }: { alertId: string; notes?: string }) =>
      aiMonitoringService.resolveAlert(alertId, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: aiMonitoringKeys.alerts() })
      toast({
        title: 'Alert resolved',
        description: 'The monitoring alert has been resolved.',
      })
    },
  })
}

export function useAcknowledgeAlert() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (alertId: string) => aiMonitoringService.acknowledgeAlert(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: aiMonitoringKeys.alerts() })
    },
  })
}
