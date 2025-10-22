import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { reconciliationService } from '@/lib/api/services/reconciliation.service'
import { toast } from '@/components/ui/toast'

// Query Keys
export const reconciliationKeys = {
  all: ['reconciliation'] as const,
  accounts: () => [...reconciliationKeys.all, 'accounts'] as const,
  reconciliations: (accountId?: string) =>
    [...reconciliationKeys.all, 'reconciliations', accountId] as const,
  detail: (id: string) => [...reconciliationKeys.all, 'detail', id] as const,
}

// Hooks

export function useReconciliationAccounts() {
  return useQuery({
    queryKey: reconciliationKeys.accounts(),
    queryFn: () => reconciliationService.listAccounts(),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useCreateReconciliation() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      account_id: string
      statement_date: string
      statement_balance: number
    }) => reconciliationService.createReconciliation(params),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({
        queryKey: reconciliationKeys.reconciliations(variables.account_id),
      })
      toast({
        title: 'Reconciliation created',
        description: 'New reconciliation has been started',
      })
    },
  })
}

export function useUploadStatement() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: { reconciliation_id: string; file: File }) =>
      reconciliationService.uploadStatement(params),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({
        queryKey: reconciliationKeys.detail(variables.reconciliation_id),
      })
      toast({
        title: 'Statement uploaded',
        description: 'Bank statement has been parsed successfully',
      })
    },
  })
}

export function useAutoMatch() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (reconciliationId: string) => reconciliationService.autoMatch(reconciliationId),
    onSuccess: (_, reconciliationId) => {
      queryClient.invalidateQueries({ queryKey: reconciliationKeys.detail(reconciliationId) })
      toast({
        title: 'Auto-match complete',
        description: 'Transactions have been automatically matched',
      })
    },
  })
}

export function useManualMatch() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      reconciliation_id: string
      statement_line_id: string
      ledger_transaction_ids: string[]
    }) => reconciliationService.manualMatch(params),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({
        queryKey: reconciliationKeys.detail(variables.reconciliation_id),
      })
      toast({
        title: 'Transaction matched',
        description: 'Transaction has been manually matched',
      })
    },
  })
}

export function useReconciliation(id: string) {
  return useQuery({
    queryKey: reconciliationKeys.detail(id),
    queryFn: () => reconciliationService.getReconciliation(id),
    enabled: !!id,
    staleTime: 1000 * 60 * 2,
  })
}

export function useCompleteReconciliation() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (reconciliationId: string) =>
      reconciliationService.completeReconciliation(reconciliationId),
    onSuccess: (_, reconciliationId) => {
      queryClient.invalidateQueries({ queryKey: reconciliationKeys.detail(reconciliationId) })
      queryClient.invalidateQueries({ queryKey: reconciliationKeys.reconciliations() })
      toast({
        title: 'Reconciliation complete',
        description: 'The reconciliation has been finalized',
      })
    },
  })
}
