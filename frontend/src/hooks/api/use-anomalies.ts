import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { anomaliesService } from '@/lib/api/services/anomalies.service'
import { toast } from '@/components/ui/toast'

// Query Keys
export const anomaliesKeys = {
  all: ['anomalies'] as const,
  list: (filters?: Record<string, unknown>) => [...anomaliesKeys.all, 'list', filters] as const,
  detail: (id: string) => [...anomaliesKeys.all, 'detail', id] as const,
}

// Hooks

export function useAnomalies(params?: {
  type?: 'revenue_spike' | 'revenue_drop' | 'unusual_expense' | 'duplicate_transaction' | 'missing_invoice'
  status?: 'pending' | 'investigating' | 'resolved' | 'false_positive'
  severity?: 'low' | 'medium' | 'high' | 'critical'
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: anomaliesKeys.list(params),
    queryFn: () => anomaliesService.listAnomalies(params),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

export function useAnomaly(id: string) {
  return useQuery({
    queryKey: anomaliesKeys.detail(id),
    queryFn: () => anomaliesService.getAnomaly(id),
    enabled: !!id,
    staleTime: 1000 * 60 * 5,
  })
}

export function useScanAnomalies() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params?: { start_date?: string; end_date?: string; types?: string[] }) =>
      anomaliesService.scanAnomalies(params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: anomaliesKeys.list() })
      toast({
        title: 'Scan complete',
        description: 'Anomaly scan completed successfully',
      })
    },
  })
}

export function useResolveAnomaly() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      anomaly_id: string
      resolution: 'resolved' | 'false_positive'
      notes?: string
      corrective_action?: Record<string, unknown>
    }) => anomaliesService.resolveAnomaly(params),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: anomaliesKeys.detail(variables.anomaly_id) })
      queryClient.invalidateQueries({ queryKey: anomaliesKeys.list() })
      toast({
        title: 'Anomaly resolved',
        description: 'The anomaly has been marked as resolved',
      })
    },
  })
}
