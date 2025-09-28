import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { financeService } from '@/lib/api/services/finance.service'
import { useToast } from '@/hooks/use-toast'

// Query Keys
export const financeKeys = {
  all: ['finance'] as const,
  invoices: () => [...financeKeys.all, 'invoices'] as const,
  invoice: (id: string) => [...financeKeys.invoices(), id] as const,
  payments: () => [...financeKeys.all, 'payments'] as const,
  payment: (id: string) => [...financeKeys.payments(), id] as const,
  accounts: () => [...financeKeys.all, 'accounts'] as const,
  account: (id: string) => [...financeKeys.accounts(), id] as const,
  journalEntries: () => [...financeKeys.all, 'journal-entries'] as const,
  journalEntry: (id: string) => [...financeKeys.journalEntries(), id] as const,
  reports: () => [...financeKeys.all, 'reports'] as const,
  metrics: () => [...financeKeys.all, 'metrics'] as const,
  transactions: () => [...financeKeys.all, 'transactions'] as const,
  budgets: () => [...financeKeys.all, 'budgets'] as const,
  subscriptions: () => [...financeKeys.all, 'subscriptions'] as const,
}

// Invoice Hooks
export function useInvoices(filters?: {
  status?: string
  customerId?: string
  startDate?: string
  endDate?: string
  search?: string
}) {
  return useQuery({
    queryKey: [...financeKeys.invoices(), filters],
    queryFn: () => financeService.getInvoices(filters),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

export function useInvoice(id: string) {
  return useQuery({
    queryKey: financeKeys.invoice(id),
    queryFn: () => financeService.getInvoice(id),
    enabled: !!id,
  })
}

export function useCreateInvoice() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: financeService.createInvoice,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() })
      queryClient.invalidateQueries({ queryKey: financeKeys.metrics() })
      toast({
        title: 'Invoice created',
        description: `Invoice #${data.number} has been created successfully.`,
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error creating invoice',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useUpdateInvoice() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) =>
      financeService.updateInvoice(id, data),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoice(variables.id) })
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() })
      toast({
        title: 'Invoice updated',
        description: 'The invoice has been successfully updated.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error updating invoice',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useSendInvoice() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: (id: string) => financeService.sendInvoice(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoice(id) })
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() })
      toast({
        title: 'Invoice sent',
        description: 'The invoice has been sent to the customer.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error sending invoice',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useVoidInvoice() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      financeService.voidInvoice(id, reason),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoice(variables.id) })
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() })
      toast({
        title: 'Invoice voided',
        description: 'The invoice has been voided successfully.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error voiding invoice',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Payment Hooks
export function usePayments(filters?: {
  invoiceId?: string
  customerId?: string
  startDate?: string
  endDate?: string
  method?: string
}) {
  return useQuery({
    queryKey: [...financeKeys.payments(), filters],
    queryFn: () => financeService.getPayments(filters),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

export function usePayment(id: string) {
  return useQuery({
    queryKey: financeKeys.payment(id),
    queryFn: () => financeService.getPayment(id),
    enabled: !!id,
  })
}

export function useRecordPayment() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: financeService.recordPayment,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.payments() })
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() })
      queryClient.invalidateQueries({ queryKey: financeKeys.metrics() })
      toast({
        title: 'Payment recorded',
        description: `Payment of ${data.amount} has been recorded successfully.`,
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error recording payment',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useRefundPayment() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: ({ id, amount, reason }: { id: string; amount: number; reason: string }) =>
      financeService.refundPayment(id, { amount, reason }),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.payment(variables.id) })
      queryClient.invalidateQueries({ queryKey: financeKeys.payments() })
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() })
      toast({
        title: 'Payment refunded',
        description: 'The payment has been refunded successfully.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error refunding payment',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Account Management Hooks
export function useAccounts(filters?: {
  type?: string
  search?: string
}) {
  return useQuery({
    queryKey: [...financeKeys.accounts(), filters],
    queryFn: () => financeService.getAccounts(filters),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useAccount(id: string) {
  return useQuery({
    queryKey: financeKeys.account(id),
    queryFn: () => financeService.getAccount(id),
    enabled: !!id,
  })
}

export function useCreateAccount() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: financeService.createAccount,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.accounts() })
      toast({
        title: 'Account created',
        description: `Account ${data.name} has been created successfully.`,
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error creating account',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Journal Entry Hooks
export function useJournalEntries(filters?: {
  startDate?: string
  endDate?: string
  accountId?: string
  search?: string
}) {
  return useQuery({
    queryKey: [...financeKeys.journalEntries(), filters],
    queryFn: () => financeService.getJournalEntries(filters),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

export function useJournalEntry(id: string) {
  return useQuery({
    queryKey: financeKeys.journalEntry(id),
    queryFn: () => financeService.getJournalEntry(id),
    enabled: !!id,
  })
}

export function useCreateJournalEntry() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: financeService.createJournalEntry,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.journalEntries() })
      queryClient.invalidateQueries({ queryKey: financeKeys.accounts() })
      toast({
        title: 'Journal entry created',
        description: 'The journal entry has been created successfully.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error creating journal entry',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Financial Reports Hooks
export function useFinancialReport(
  type: 'balance-sheet' | 'income-statement' | 'cash-flow' | 'trial-balance',
  params?: {
    startDate?: string
    endDate?: string
    comparePeriod?: boolean
  }
) {
  return useQuery({
    queryKey: [...financeKeys.reports(), type, params],
    queryFn: () => financeService.getFinancialReport(type, params),
    staleTime: 1000 * 60 * 5, // 5 minutes
    enabled: !!type,
  })
}

export function useCustomReport(reportId: string, params?: any) {
  return useQuery({
    queryKey: [...financeKeys.reports(), 'custom', reportId, params],
    queryFn: () => financeService.getCustomReport(reportId, params),
    enabled: !!reportId,
  })
}

// Financial Metrics Hook
export function useFinancialMetrics(dateRange?: { start: Date; end: Date }) {
  return useQuery({
    queryKey: [...financeKeys.metrics(), dateRange],
    queryFn: () => financeService.getMetrics(dateRange),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

// Transaction Hooks
export function useTransactions(filters?: {
  accountId?: string
  startDate?: string
  endDate?: string
  type?: string
  search?: string
}) {
  return useQuery({
    queryKey: [...financeKeys.transactions(), filters],
    queryFn: () => financeService.getTransactions(filters),
    staleTime: 1000 * 60 * 2, // 2 minutes
  })
}

// Budget Hooks
export function useBudgets(filters?: {
  period?: string
  departmentId?: string
}) {
  return useQuery({
    queryKey: [...financeKeys.budgets(), filters],
    queryFn: () => financeService.getBudgets(filters),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useCreateBudget() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: financeService.createBudget,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.budgets() })
      toast({
        title: 'Budget created',
        description: 'The budget has been created successfully.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error creating budget',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Subscription Management Hooks
export function useSubscriptions(filters?: {
  status?: 'active' | 'canceled' | 'past_due'
  customerId?: string
}) {
  return useQuery({
    queryKey: [...financeKeys.subscriptions(), filters],
    queryFn: () => financeService.getSubscriptions(filters),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useCreateSubscription() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: financeService.createSubscription,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.subscriptions() })
      toast({
        title: 'Subscription created',
        description: 'The subscription has been created successfully.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error creating subscription',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useCancelSubscription() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason?: string }) =>
      financeService.cancelSubscription(id, reason),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.subscriptions() })
      toast({
        title: 'Subscription canceled',
        description: 'The subscription has been canceled successfully.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error canceling subscription',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Stripe Payment Intent Hook
export function useCreatePaymentIntent() {
  const { toast } = useToast()

  return useMutation({
    mutationFn: ({ amount, currency, metadata }: {
      amount: number
      currency: string
      metadata?: any
    }) => financeService.createPaymentIntent({ amount, currency, metadata }),
    onError: (error) => {
      toast({
        title: 'Payment error',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

// Bulk Operations
export function useBulkSendInvoices() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  return useMutation({
    mutationFn: (invoiceIds: string[]) => financeService.bulkSendInvoices(invoiceIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() })
      toast({
        title: 'Invoices sent',
        description: 'Selected invoices have been sent successfully.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Error sending invoices',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useExportInvoices() {
  const { toast } = useToast()

  return useMutation({
    mutationFn: ({ format, filters }: {
      format: 'csv' | 'excel' | 'pdf'
      filters?: any
    }) => financeService.exportInvoices(format, filters),
    onSuccess: (blob, variables) => {
      // Create download link
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `invoices.${variables.format}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)

      toast({
        title: 'Export successful',
        description: 'Invoices have been exported successfully.',
        variant: 'success',
      })
    },
    onError: (error) => {
      toast({
        title: 'Export failed',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}