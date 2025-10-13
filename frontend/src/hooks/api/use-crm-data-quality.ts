import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { crmDataQualityService } from '@/lib/api/services/crm-data-quality.service'
import { toast } from '@/components/ui/toast'

// Query Keys
export const crmDataQualityKeys = {
  all: ['crm-data-quality'] as const,
  duplicates: (entityType: string, entityId?: string) =>
    [...crmDataQualityKeys.all, 'duplicates', entityType, entityId] as const,
  pendingMatches: () => [...crmDataQualityKeys.all, 'pending-matches'] as const,
  quality: (entityType: string, entityId: string) =>
    [...crmDataQualityKeys.all, 'quality', entityType, entityId] as const,
  report: () => [...crmDataQualityKeys.all, 'report'] as const,
  issues: (filters?: Record<string, unknown>) =>
    [...crmDataQualityKeys.all, 'issues', filters] as const,
  dashboard: () => [...crmDataQualityKeys.all, 'dashboard'] as const,
}

// Hooks

export function useFindDuplicates(params: {
  entity_type: 'contact' | 'company'
  entity_id?: string
  threshold?: number
}) {
  return useQuery({
    queryKey: crmDataQualityKeys.duplicates(params.entity_type, params.entity_id),
    queryFn: () => crmDataQualityService.findDuplicates(params),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useScanDuplicates() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: { entity_type: 'contact' | 'company'; batch_size?: number }) =>
      crmDataQualityService.scanAllDuplicates(params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmDataQualityKeys.pendingMatches() })
      toast({
        title: 'Scan complete',
        description: 'Duplicate scan completed successfully',
      })
    },
  })
}

export function usePendingMatches() {
  return useQuery({
    queryKey: crmDataQualityKeys.pendingMatches(),
    queryFn: () => crmDataQualityService.getPendingMatches(),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

export function useMergeDuplicates() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      entity_type: 'contact' | 'company'
      primary_id: string
      duplicate_ids: string[]
      merge_strategy?: 'primary' | 'newest' | 'most_complete'
    }) => crmDataQualityService.mergeDuplicates(params),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({
        queryKey: crmDataQualityKeys.duplicates(variables.entity_type),
      })
      queryClient.invalidateQueries({ queryKey: crmDataQualityKeys.pendingMatches() })
      queryClient.invalidateQueries({ queryKey: crmDataQualityKeys.dashboard() })
      toast({
        title: 'Merged successfully',
        description: 'Duplicate records have been merged',
      })
    },
  })
}

export function useDismissMatch() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (matchId: string) => crmDataQualityService.dismissMatch(matchId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmDataQualityKeys.pendingMatches() })
      toast({
        title: 'Match dismissed',
        description: 'Duplicate match has been dismissed',
      })
    },
  })
}

export function useValidateEntityQuality(entityType: 'contact' | 'company', entityId: string) {
  return useQuery({
    queryKey: crmDataQualityKeys.quality(entityType, entityId),
    queryFn: () => crmDataQualityService.validateEntityQuality(entityType, entityId),
    staleTime: 1000 * 60 * 5,
  })
}

export function useDataQualityReport() {
  return useQuery({
    queryKey: crmDataQualityKeys.report(),
    queryFn: () => crmDataQualityService.getDataQualityReport(),
    staleTime: 1000 * 60 * 10, // 10 minutes
  })
}

export function useDataQualityIssues(filters?: {
  entity_type?: 'contact' | 'company'
  severity?: 'low' | 'medium' | 'high' | 'critical'
  status?: 'pending' | 'fixed' | 'ignored'
  limit?: number
}) {
  return useQuery({
    queryKey: crmDataQualityKeys.issues(filters),
    queryFn: () => crmDataQualityService.getDataQualityIssues(filters),
    staleTime: 1000 * 60 * 2,
  })
}

export function useAutoFixIssues() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: { issue_ids: string[]; dry_run?: boolean }) =>
      crmDataQualityService.autoFixIssues(params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmDataQualityKeys.issues() })
      queryClient.invalidateQueries({ queryKey: crmDataQualityKeys.dashboard() })
      toast({
        title: 'Issues fixed',
        description: 'Data quality issues have been auto-fixed',
      })
    },
  })
}

export function useResolveIssue() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      issue_id: string
      resolution: 'fixed' | 'ignored'
      correction_data?: Record<string, unknown>
    }) => crmDataQualityService.resolveIssue(params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmDataQualityKeys.issues() })
      queryClient.invalidateQueries({ queryKey: crmDataQualityKeys.dashboard() })
      toast({
        title: 'Issue resolved',
        description: 'Data quality issue has been resolved',
      })
    },
  })
}

export function useDataQualityDashboard() {
  return useQuery({
    queryKey: crmDataQualityKeys.dashboard(),
    queryFn: () => crmDataQualityService.getDataQualityDashboard(),
    staleTime: 1000 * 60 * 5,
    refetchInterval: 1000 * 60 * 5, // Auto-refresh every 5 minutes
  })
}
