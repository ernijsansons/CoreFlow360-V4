import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { crmService } from '@/lib/api/services/crm.service'
import { toast } from '@/hooks/use-toast'

// Query Keys
export const crmKeys = {
  all: ['crm'] as const,
  leads: () => [...crmKeys.all, 'leads'] as const,
  lead: (id: string) => [...crmKeys.leads(), id] as const,
  contacts: () => [...crmKeys.all, 'contacts'] as const,
  contact: (id: string) => [...crmKeys.contacts(), id] as const,
  companies: () => [...crmKeys.all, 'companies'] as const,
  company: (id: string) => [...crmKeys.companies(), id] as const,
  deals: () => [...crmKeys.all, 'deals'] as const,
  deal: (id: string) => [...crmKeys.deals(), id] as const,
  pipeline: () => [...crmKeys.all, 'pipeline'] as const,
  activities: () => [...crmKeys.all, 'activities'] as const,
  metrics: () => [...crmKeys.all, 'metrics'] as const,
}

// Leads Hooks
export function useLeads(filters?: {
  status?: string
  owner?: string
  source?: string
  priority?: string
  search?: string
}) {
  return useQuery({
    queryKey: [...crmKeys.leads(), filters],
    queryFn: () => crmService.getLeads(filters),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

export function useLead(id: string) {
  return useQuery({
    queryKey: crmKeys.lead(id),
    queryFn: () => crmService.getLead(id),
    enabled: !!id,
  })
}

export function useCreateLead() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: crmService.createLead,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: crmKeys.leads() })
      toast({
        title: 'Lead created',
        description: `${data.name} has been added to your leads.`,
      })
    },
    onError: (error) => {
      toast({
        title: 'Error creating lead',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useUpdateLead() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) =>
      crmService.updateLead(id, data),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: crmKeys.lead(variables.id) })
      queryClient.invalidateQueries({ queryKey: crmKeys.leads() })
      toast({
        title: 'Lead updated',
        description: 'The lead has been successfully updated.',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error updating lead',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useDeleteLead() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: crmService.deleteLead,
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: crmKeys.leads() })
      queryClient.removeQueries({ queryKey: crmKeys.lead(id) })
      toast({
        title: 'Lead deleted',
        description: 'The lead has been removed.',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error deleting lead',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Pipeline/Deals Hooks
export function useDeals(filters?: {
  stage?: string
  owner?: string
  status?: string
}) {
  return useQuery({
    queryKey: [...crmKeys.deals(), filters],
    queryFn: () => crmService.getDeals(filters),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

export function useDeal(id: string) {
  return useQuery({
    queryKey: crmKeys.deal(id),
    queryFn: () => crmService.getDeal(id),
    enabled: !!id,
  })
}

export function useCreateDeal() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: crmService.createDeal,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: crmKeys.deals() })
      queryClient.invalidateQueries({ queryKey: crmKeys.pipeline() })
      toast({
        title: 'Deal created',
        description: `${data.title} has been added to the pipeline.`,
      })
    },
    onError: (error) => {
      toast({
        title: 'Error creating deal',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useUpdateDeal() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) =>
      crmService.updateDeal(id, data),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: crmKeys.deal(variables.id) })
      queryClient.invalidateQueries({ queryKey: crmKeys.deals() })
      queryClient.invalidateQueries({ queryKey: crmKeys.pipeline() })
      toast({
        title: 'Deal updated',
        description: 'The deal has been successfully updated.',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error updating deal',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useMoveDealStage() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, stage }: { id: string; stage: string }) =>
      crmService.moveDealStage(id, stage),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmKeys.deals() })
      queryClient.invalidateQueries({ queryKey: crmKeys.pipeline() })
      toast({
        title: 'Deal moved',
        description: 'The deal has been moved to the new stage.',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error moving deal',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Pipeline Hook
export function usePipeline() {
  return useQuery({
    queryKey: crmKeys.pipeline(),
    queryFn: crmService.getPipeline,
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

// CRM Metrics Hook
export function useCRMMetrics(dateRange?: { start: Date; end: Date }) {
  return useQuery({
    queryKey: [...crmKeys.metrics(), dateRange],
    queryFn: () => crmService.getMetrics(dateRange),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

// Contacts Hooks
export function useContacts(filters?: {
  search?: string
  company?: string
}) {
  return useQuery({
    queryKey: [...crmKeys.contacts(), filters],
    queryFn: () => crmService.getContacts(filters),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

export function useCreateContact() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: crmService.createContact,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: crmKeys.contacts() })
      toast({
        title: 'Contact created',
        description: `${data.name} has been added to your contacts.`,
      })
    },
    onError: (error) => {
      toast({
        title: 'Error creating contact',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Bulk Operations
export function useBulkUpdateLeads() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ ids, updates }: { ids: string[]; updates: any }) =>
      crmService.bulkUpdateLeads(ids, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmKeys.leads() })
      toast({
        title: 'Leads updated',
        description: 'Selected leads have been updated successfully.',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error updating leads',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useBulkDeleteLeads() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (ids: string[]) => crmService.bulkDeleteLeads(ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmKeys.leads() })
      toast({
        title: 'Leads deleted',
        description: 'Selected leads have been removed.',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error deleting leads',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}