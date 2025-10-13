import { useMutation, useQueryClient } from '@tanstack/react-query'
import { enrichmentService } from '@/lib/api/services/enrichment.service'
import { toast } from '@/components/ui/toast'

// Hooks

export function useEnrichLead() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      lead_id: string
      sources?: Array<'clearbit' | 'hunter' | 'linkedin'>
      fields?: string[]
    }) => enrichmentService.enrichLead(params),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'lead', variables.lead_id] })
      toast({
        title: 'Lead enriched',
        description: 'Lead data has been successfully enriched',
      })
    },
  })
}

export function useBulkEnrichLeads() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      lead_ids: string[]
      sources?: Array<'clearbit' | 'hunter' | 'linkedin'>
      fields?: string[]
    }) => enrichmentService.bulkEnrichLeads(params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'leads'] })
      toast({
        title: 'Bulk enrichment started',
        description: 'Lead enrichment is processing in the background',
      })
    },
  })
}

export function useEstimateEnrichmentCost() {
  return useMutation({
    mutationFn: (params: {
      lead_count: number
      sources: Array<'clearbit' | 'hunter' | 'linkedin'>
      fields?: string[]
    }) => enrichmentService.estimateCost(params),
  })
}

export function useValidateEnrichmentSource() {
  return useMutation({
    mutationFn: (source: 'clearbit' | 'hunter' | 'linkedin') =>
      enrichmentService.validateSource(source),
    onSuccess: (data, source) => {
      if (data.data.valid) {
        toast({
          title: 'Source validated',
          description: `${source} integration is configured correctly`,
        })
      } else {
        toast({
          title: 'Invalid configuration',
          description: data.data.error || `${source} integration needs configuration`,
          variant: 'destructive',
        })
      }
    },
  })
}
