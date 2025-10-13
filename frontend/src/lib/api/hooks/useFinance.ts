/**
 * Finance React Query Hooks - Fortune 50 Level
 * Hooks for financial data management with intelligent caching
 */

import { useQuery, useMutation, useQueryClient, UseQueryResult, UseMutationResult } from '@tanstack/react-query';
import { financeService } from '../services/finance.service';
import type {
  Invoice,
  Payment,
  Account,
  JournalEntry,
  CreateInvoiceRequest,
  UpdateInvoiceRequest,
  RecordPaymentRequest,
  CreateAccountRequest,
  CreateJournalEntryRequest,
  FinancialReportParams
} from '../services/finance.service';
import type { ApiResponse } from '../client';

// ==================== QUERY KEYS ====================

export const financeKeys = {
  all: ['finance'] as const,
  invoices: () => [...financeKeys.all, 'invoices'] as const,
  invoicesList: (filters?: any) => [...financeKeys.invoices(), 'list', filters] as const,
  invoice: (id: string) => [...financeKeys.invoices(), 'detail', id] as const,
  payments: () => [...financeKeys.all, 'payments'] as const,
  paymentsList: (filters?: any) => [...financeKeys.payments(), 'list', filters] as const,
  payment: (id: string) => [...financeKeys.payments(), 'detail', id] as const,
  accounts: () => [...financeKeys.all, 'accounts'] as const,
  accountsList: (filters?: any) => [...financeKeys.accounts(), 'list', filters] as const,
  account: (id: string) => [...financeKeys.accounts(), 'detail', id] as const,
  journalEntries: () => [...financeKeys.all, 'journal-entries'] as const,
  journalEntriesList: (filters?: any) => [...financeKeys.journalEntries(), 'list', filters] as const,
  journalEntry: (id: string) => [...financeKeys.journalEntries(), 'detail', id] as const,
  reports: () => [...financeKeys.all, 'reports'] as const,
  trialBalance: (params: FinancialReportParams) => [...financeKeys.reports(), 'trial-balance', params] as const,
  incomeStatement: (params: FinancialReportParams) => [...financeKeys.reports(), 'income-statement', params] as const,
  balanceSheet: (params: FinancialReportParams) => [...financeKeys.reports(), 'balance-sheet', params] as const,
  cashFlow: (params: FinancialReportParams) => [...financeKeys.reports(), 'cash-flow', params] as const,
};

// ==================== INVOICES HOOKS ====================

export function useInvoices(filters?: {
  page?: number;
  limit?: number;
  status?: any;
  customerId?: string;
  startDate?: string;
  endDate?: string;
  search?: string;
  sort?: string;
}): UseQueryResult<Invoice[], Error> {
  return useQuery({
    queryKey: financeKeys.invoicesList(filters),
    queryFn: async () => {
      const response = await financeService.getInvoices(filters);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch invoices');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 2, // 2 minutes
  });
}

export function useInvoice(id: string): UseQueryResult<Invoice, Error> {
  return useQuery({
    queryKey: financeKeys.invoice(id),
    queryFn: async () => {
      const response = await financeService.getInvoice(id);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch invoice');
      }
      return response.data;
    },
    enabled: !!id,
  });
}

export function useCreateInvoice(): UseMutationResult<ApiResponse<Invoice>, Error, CreateInvoiceRequest> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateInvoiceRequest) => financeService.createInvoice(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() });
    },
  });
}

export function useUpdateInvoice(): UseMutationResult<ApiResponse<Invoice>, Error, { id: string; data: UpdateInvoiceRequest }> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateInvoiceRequest }) =>
      financeService.updateInvoice(id, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoice(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() });
    },
  });
}

export function useDeleteInvoice(): UseMutationResult<ApiResponse<void>, Error, string> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => financeService.deleteInvoice(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() });
    },
  });
}

export function useSendInvoice(): UseMutationResult<ApiResponse<void>, Error, { id: string; emails: string[] }> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, emails }: { id: string; emails: string[] }) =>
      financeService.sendInvoice(id, emails),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoice(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() });
    },
  });
}

export function useMarkInvoiceAsSent(): UseMutationResult<ApiResponse<Invoice>, Error, string> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => financeService.markInvoiceAsSent(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoice(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() });
    },
  });
}

export function useVoidInvoice(): UseMutationResult<ApiResponse<Invoice>, Error, { id: string; reason: string }> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      financeService.voidInvoice(id, reason),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.invoice(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() });
    },
  });
}

// ==================== PAYMENTS HOOKS ====================

export function usePayments(filters?: {
  page?: number;
  limit?: number;
  invoiceId?: string;
  customerId?: string;
  method?: any;
  startDate?: string;
  endDate?: string;
}): UseQueryResult<Payment[], Error> {
  return useQuery({
    queryKey: financeKeys.paymentsList(filters),
    queryFn: async () => {
      const response = await financeService.getPayments(filters);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch payments');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 2, // 2 minutes
  });
}

export function usePayment(id: string): UseQueryResult<Payment, Error> {
  return useQuery({
    queryKey: financeKeys.payment(id),
    queryFn: async () => {
      const response = await financeService.getPayment(id);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch payment');
      }
      return response.data;
    },
    enabled: !!id,
  });
}

export function useRecordPayment(): UseMutationResult<ApiResponse<Payment>, Error, RecordPaymentRequest> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: RecordPaymentRequest) => financeService.recordPayment(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: financeKeys.payments() });
      queryClient.invalidateQueries({ queryKey: financeKeys.invoices() });
    },
  });
}

export function useRefundPayment(): UseMutationResult<ApiResponse<Payment>, Error, { id: string; amount: number; reason: string }> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, amount, reason }: { id: string; amount: number; reason: string }) =>
      financeService.refundPayment(id, amount, reason),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.payment(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.payments() });
    },
  });
}

export function useCancelPayment(): UseMutationResult<ApiResponse<Payment>, Error, { id: string; reason: string }> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      financeService.cancelPayment(id, reason),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.payment(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.payments() });
    },
  });
}

// ==================== ACCOUNTS HOOKS ====================

export function useAccounts(filters?: {
  type?: string;
  parentId?: string;
  isActive?: boolean;
}): UseQueryResult<Account[], Error> {
  return useQuery({
    queryKey: financeKeys.accountsList(filters),
    queryFn: async () => {
      const response = await financeService.getAccounts(filters);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch accounts');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 10, // 10 minutes - accounts change infrequently
  });
}

export function useAccount(id: string): UseQueryResult<Account, Error> {
  return useQuery({
    queryKey: financeKeys.account(id),
    queryFn: async () => {
      const response = await financeService.getAccount(id);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch account');
      }
      return response.data;
    },
    enabled: !!id,
  });
}

export function useCreateAccount(): UseMutationResult<ApiResponse<Account>, Error, CreateAccountRequest> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateAccountRequest) => financeService.createAccount(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: financeKeys.accounts() });
    },
  });
}

export function useUpdateAccount(): UseMutationResult<ApiResponse<Account>, Error, { id: string; data: Partial<Account> }> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Account> }) =>
      financeService.updateAccount(id, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.account(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.accounts() });
    },
  });
}

export function useDeactivateAccount(): UseMutationResult<ApiResponse<Account>, Error, string> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => financeService.deactivateAccount(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.account(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.accounts() });
    },
  });
}

// ==================== JOURNAL ENTRIES HOOKS ====================

export function useJournalEntries(filters?: {
  page?: number;
  limit?: number;
  startDate?: string;
  endDate?: string;
  accountId?: string;
  status?: string;
}): UseQueryResult<JournalEntry[], Error> {
  return useQuery({
    queryKey: financeKeys.journalEntriesList(filters),
    queryFn: async () => {
      const response = await financeService.getJournalEntries(filters);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch journal entries');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 5, // 5 minutes
  });
}

export function useJournalEntry(id: string): UseQueryResult<JournalEntry, Error> {
  return useQuery({
    queryKey: financeKeys.journalEntry(id),
    queryFn: async () => {
      const response = await financeService.getJournalEntry(id);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch journal entry');
      }
      return response.data;
    },
    enabled: !!id,
  });
}

export function useCreateJournalEntry(): UseMutationResult<ApiResponse<JournalEntry>, Error, CreateJournalEntryRequest> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateJournalEntryRequest) => financeService.createJournalEntry(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: financeKeys.journalEntries() });
    },
  });
}

export function usePostJournalEntry(): UseMutationResult<ApiResponse<JournalEntry>, Error, string> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => financeService.postJournalEntry(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.journalEntry(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.journalEntries() });
      queryClient.invalidateQueries({ queryKey: financeKeys.accounts() });
    },
  });
}

export function useReverseJournalEntry(): UseMutationResult<ApiResponse<JournalEntry>, Error, { id: string; date: string; reason: string }> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, date, reason }: { id: string; date: string; reason: string }) =>
      financeService.reverseJournalEntry(id, date, reason),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: financeKeys.journalEntry(id) });
      queryClient.invalidateQueries({ queryKey: financeKeys.journalEntries() });
      queryClient.invalidateQueries({ queryKey: financeKeys.accounts() });
    },
  });
}

// ==================== FINANCIAL REPORTS HOOKS ====================

export function useTrialBalance(params: FinancialReportParams): UseQueryResult<Record<string, unknown>, Error> {
  return useQuery({
    queryKey: financeKeys.trialBalance(params),
    queryFn: async () => {
      const response = await financeService.getTrialBalance(params);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch trial balance');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 15, // 15 minutes
  });
}

export function useIncomeStatement(params: FinancialReportParams): UseQueryResult<Record<string, unknown>, Error> {
  return useQuery({
    queryKey: financeKeys.incomeStatement(params),
    queryFn: async () => {
      const response = await financeService.getIncomeStatement(params);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch income statement');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 15, // 15 minutes
  });
}

export function useBalanceSheet(params: FinancialReportParams): UseQueryResult<Record<string, unknown>, Error> {
  return useQuery({
    queryKey: financeKeys.balanceSheet(params),
    queryFn: async () => {
      const response = await financeService.getBalanceSheet(params);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch balance sheet');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 15, // 15 minutes
  });
}

export function useCashFlow(params: FinancialReportParams): UseQueryResult<Record<string, unknown>, Error> {
  return useQuery({
    queryKey: financeKeys.cashFlow(params),
    queryFn: async () => {
      const response = await financeService.getCashFlow(params);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch cash flow statement');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 15, // 15 minutes
  });
}
