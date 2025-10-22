import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { bankingService } from '@/lib/api/services'
import { toast } from '@/hooks/use-toast'

// Query Keys
export const bankingKeys = {
  all: ['banking'] as const,
  transactions: (filters?: unknown) => [...bankingKeys.all, 'transactions', filters] as const,
  transaction: (id: string) => [...bankingKeys.all, 'transaction', id] as const,
  connections: () => [...bankingKeys.all, 'connections'] as const,
  connection: (id: string) => [...bankingKeys.all, 'connection', id] as const,
  matches: (transactionId: string) => [...bankingKeys.all, 'matches', transactionId] as const,
}

// Transaction Queries
export function useBankTransactions(params?: {
  status?: 'pending' | 'matched' | 'ignored' | 'reviewed'
  limit?: number
  offset?: number
  from_date?: string
  to_date?: string
}) {
  return useQuery({
    queryKey: bankingKeys.transactions(params),
    queryFn: () => bankingService.listTransactions(params),
    staleTime: 1000 * 60, // 1 minute
  })
}

export function useBankTransaction(id: string) {
  return useQuery({
    queryKey: bankingKeys.transaction(id),
    queryFn: () => bankingService.getTransaction(id),
    enabled: !!id,
  })
}

export function useTransactionMatches(transactionId: string) {
  return useQuery({
    queryKey: bankingKeys.matches(transactionId),
    queryFn: () => bankingService.findMatches(transactionId),
    enabled: !!transactionId,
  })
}

// Bank Connection Queries
export function useBankConnections() {
  return useQuery({
    queryKey: bankingKeys.connections(),
    queryFn: () => bankingService.listConnections(),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useBankConnection(id: string) {
  return useQuery({
    queryKey: bankingKeys.connection(id),
    queryFn: () => bankingService.getConnection(id),
    enabled: !!id,
  })
}

// Transaction Mutations
export function useApplyMatch() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ transactionId, matchType, matchId }: {
      transactionId: string
      matchType: 'invoice' | 'expense' | 'journal_entry'
      matchId: string
    }) => bankingService.applyMatch(transactionId, matchType, matchId),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: bankingKeys.transaction(variables.transactionId) })
      queryClient.invalidateQueries({ queryKey: bankingKeys.transactions() })
      toast({
        title: 'Match applied',
        description: 'Transaction has been matched successfully.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to apply match',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useIgnoreTransaction() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (transactionId: string) => bankingService.ignoreTransaction(transactionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: bankingKeys.transactions() })
      toast({
        title: 'Transaction ignored',
        description: 'Transaction has been marked as ignored.',
      })
    },
  })
}

// Bank Connection Mutations
export function useCreateBankConnection() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      provider: string
      credentials: Record<string, unknown>
    }) => bankingService.createConnection(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: bankingKeys.connections() })
      toast({
        title: 'Bank connected',
        description: 'Your bank account has been connected successfully.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Connection failed',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useSyncBankConnection() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (connectionId: string) => bankingService.syncConnection(connectionId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: bankingKeys.transactions() })
      toast({
        title: 'Sync complete',
        description: `Synced ${data.data.new_transactions} new transactions.`,
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Sync failed',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useRemoveBankConnection() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (connectionId: string) => bankingService.removeConnection(connectionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: bankingKeys.connections() })
      toast({
        title: 'Connection removed',
        description: 'Bank connection has been disconnected.',
      })
    },
  })
}

export function useBulkMatchTransactions() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (matches: Array<{
      transaction_id: string
      match_type: 'invoice' | 'expense' | 'journal_entry'
      match_id: string
    }>) => bankingService.bulkMatch(matches),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: bankingKeys.transactions() })
      toast({
        title: 'Bulk matching complete',
        description: `Matched ${data.data.matched} transactions.`,
      })
    },
  })
}
