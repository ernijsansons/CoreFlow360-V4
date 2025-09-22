import apiClient, { ApiResponse } from '../client'
import type {
  Invoice,
  InvoiceStatus,
  Payment,
  PaymentMethod,
  Account,
  JournalEntry,
  Report
} from '../types'

export interface CreateInvoiceRequest {
  customerId: string
  issueDate?: string
  dueDate: string
  items: {
    description: string
    quantity: number
    unitPrice: number
    tax?: number
    discount?: number
  }[]
  notes?: string
  terms?: string
  attachments?: string[]
}

export interface UpdateInvoiceRequest {
  status?: InvoiceStatus
  dueDate?: string
  notes?: string
  terms?: string
}

export interface RecordPaymentRequest {
  invoiceId: string
  amount: number
  method: PaymentMethod
  reference?: string
  notes?: string
  processedAt?: string
}

export interface CreateAccountRequest {
  code: string
  name: string
  type: 'asset' | 'liability' | 'equity' | 'revenue' | 'expense'
  subtype?: string
  parentId?: string
  currency: string
  description?: string
}

export interface CreateJournalEntryRequest {
  date: string
  description: string
  reference?: string
  lines: {
    accountId: string
    debit?: number
    credit?: number
    description?: string
    projectId?: string
    departmentId?: string
  }[]
  attachments?: string[]
}

export interface FinancialReportParams {
  startDate: string
  endDate: string
  format?: 'json' | 'pdf' | 'excel'
  comparePeriod?: boolean
  departments?: string[]
  projects?: string[]
}

class FinanceService {
  // Invoice Management
  async getInvoices(params?: {
    page?: number
    limit?: number
    status?: InvoiceStatus
    customerId?: string
    startDate?: string
    endDate?: string
    search?: string
    sort?: string
  }): Promise<ApiResponse<Invoice[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Invoice[]>(`/api/finance/invoices?${query}`)
  }

  async getInvoice(id: string): Promise<ApiResponse<Invoice>> {
    return apiClient.get<Invoice>(`/api/finance/invoices/${id}`)
  }

  async createInvoice(data: CreateInvoiceRequest): Promise<ApiResponse<Invoice>> {
    return apiClient.post<Invoice>('/api/finance/invoices', data)
  }

  async updateInvoice(
    id: string,
    data: UpdateInvoiceRequest
  ): Promise<ApiResponse<Invoice>> {
    return apiClient.patch<Invoice>(`/api/finance/invoices/${id}`, data)
  }

  async deleteInvoice(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/api/finance/invoices/${id}`)
  }

  async sendInvoice(id: string, emails: string[]): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/api/finance/invoices/${id}/send`, { emails })
  }

  async markInvoiceAsSent(id: string): Promise<ApiResponse<Invoice>> {
    return apiClient.post<Invoice>(`/api/finance/invoices/${id}/mark-sent`)
  }

  async voidInvoice(id: string, reason: string): Promise<ApiResponse<Invoice>> {
    return apiClient.post<Invoice>(`/api/finance/invoices/${id}/void`, { reason })
  }

  async generateInvoicePDF(id: string): Promise<Blob> {
    const response = await fetch(
      `${import.meta.env.VITE_API_URL}/api/finance/invoices/${id}/pdf`,
      {
        headers: {
          'Authorization': `Bearer ${useAuthStore.getState().token}`,
        },
      }
    )
    return response.blob()
  }

  // Payment Management
  async getPayments(params?: {
    page?: number
    limit?: number
    invoiceId?: string
    customerId?: string
    method?: PaymentMethod
    startDate?: string
    endDate?: string
  }): Promise<ApiResponse<Payment[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Payment[]>(`/api/finance/payments?${query}`)
  }

  async getPayment(id: string): Promise<ApiResponse<Payment>> {
    return apiClient.get<Payment>(`/api/finance/payments/${id}`)
  }

  async recordPayment(data: RecordPaymentRequest): Promise<ApiResponse<Payment>> {
    return apiClient.post<Payment>('/api/finance/payments', data)
  }

  async refundPayment(
    id: string,
    amount: number,
    reason: string
  ): Promise<ApiResponse<Payment>> {
    return apiClient.post<Payment>(`/api/finance/payments/${id}/refund`, {
      amount,
      reason,
    })
  }

  async cancelPayment(id: string, reason: string): Promise<ApiResponse<Payment>> {
    return apiClient.post<Payment>(`/api/finance/payments/${id}/cancel`, { reason })
  }

  // Chart of Accounts
  async getAccounts(params?: {
    type?: string
    parentId?: string
    isActive?: boolean
  }): Promise<ApiResponse<Account[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Account[]>(`/api/finance/accounts?${query}`)
  }

  async getAccount(id: string): Promise<ApiResponse<Account>> {
    return apiClient.get<Account>(`/api/finance/accounts/${id}`)
  }

  async createAccount(data: CreateAccountRequest): Promise<ApiResponse<Account>> {
    return apiClient.post<Account>('/api/finance/accounts', data)
  }

  async updateAccount(
    id: string,
    data: Partial<Account>
  ): Promise<ApiResponse<Account>> {
    return apiClient.patch<Account>(`/api/finance/accounts/${id}`, data)
  }

  async deactivateAccount(id: string): Promise<ApiResponse<Account>> {
    return apiClient.post<Account>(`/api/finance/accounts/${id}/deactivate`)
  }

  // Journal Entries
  async getJournalEntries(params?: {
    page?: number
    limit?: number
    startDate?: string
    endDate?: string
    accountId?: string
    status?: string
  }): Promise<ApiResponse<JournalEntry[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<JournalEntry[]>(`/api/finance/journal-entries?${query}`)
  }

  async getJournalEntry(id: string): Promise<ApiResponse<JournalEntry>> {
    return apiClient.get<JournalEntry>(`/api/finance/journal-entries/${id}`)
  }

  async createJournalEntry(
    data: CreateJournalEntryRequest
  ): Promise<ApiResponse<JournalEntry>> {
    return apiClient.post<JournalEntry>('/api/finance/journal-entries', data)
  }

  async postJournalEntry(id: string): Promise<ApiResponse<JournalEntry>> {
    return apiClient.post<JournalEntry>(`/api/finance/journal-entries/${id}/post`)
  }

  async reverseJournalEntry(
    id: string,
    date: string,
    reason: string
  ): Promise<ApiResponse<JournalEntry>> {
    return apiClient.post<JournalEntry>(`/api/finance/journal-entries/${id}/reverse`, {
      date,
      reason,
    })
  }

  // Financial Reports
  async getTrialBalance(params: FinancialReportParams): Promise<ApiResponse<any>> {
    const query = new URLSearchParams()
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        if (Array.isArray(value)) {
          query.append(key, value.join(','))
        } else {
          query.append(key, String(value))
        }
      }
    })
    return apiClient.get(`/api/finance/reports/trial-balance?${query}`)
  }

  async getIncomeStatement(params: FinancialReportParams): Promise<ApiResponse<any>> {
    const query = new URLSearchParams()
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        if (Array.isArray(value)) {
          query.append(key, value.join(','))
        } else {
          query.append(key, String(value))
        }
      }
    })
    return apiClient.get(`/api/finance/reports/income-statement?${query}`)
  }

  async getBalanceSheet(params: FinancialReportParams): Promise<ApiResponse<any>> {
    const query = new URLSearchParams()
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        if (Array.isArray(value)) {
          query.append(key, value.join(','))
        } else {
          query.append(key, String(value))
        }
      }
    })
    return apiClient.get(`/api/finance/reports/balance-sheet?${query}`)
  }

  async getCashFlow(params: FinancialReportParams): Promise<ApiResponse<any>> {
    const query = new URLSearchParams()
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        if (Array.isArray(value)) {
          query.append(key, value.join(','))
        } else {
          query.append(key, String(value))
        }
      }
    })
    return apiClient.get(`/api/finance/reports/cash-flow?${query}`)
  }

  async getAgingReport(params: {
    type: 'receivable' | 'payable'
    asOfDate?: string
    groupBy?: 'customer' | 'vendor'
  }): Promise<ApiResponse<any>> {
    const query = new URLSearchParams()
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) query.append(key, String(value))
    })
    return apiClient.get(`/api/finance/reports/aging?${query}`)
  }

  // Tax Management
  async getTaxRates(): Promise<ApiResponse<any[]>> {
    return apiClient.get('/api/finance/tax-rates')
  }

  async createTaxRate(data: {
    name: string
    rate: number
    description?: string
    isDefault?: boolean
  }): Promise<ApiResponse<any>> {
    return apiClient.post('/api/finance/tax-rates', data)
  }

  async updateTaxRate(id: string, data: any): Promise<ApiResponse<any>> {
    return apiClient.patch(`/api/finance/tax-rates/${id}`, data)
  }

  // Budget Management
  async getBudgets(params?: {
    year?: number
    departmentId?: string
    projectId?: string
  }): Promise<ApiResponse<any[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get(`/api/finance/budgets?${query}`)
  }

  async createBudget(data: {
    name: string
    year: number
    departmentId?: string
    projectId?: string
    items: {
      accountId: string
      amount: number
      period: 'monthly' | 'quarterly' | 'annual'
    }[]
  }): Promise<ApiResponse<any>> {
    return apiClient.post('/api/finance/budgets', data)
  }

  async updateBudget(id: string, data: any): Promise<ApiResponse<any>> {
    return apiClient.patch(`/api/finance/budgets/${id}`, data)
  }

  async getBudgetVariance(id: string): Promise<ApiResponse<any>> {
    return apiClient.get(`/api/finance/budgets/${id}/variance`)
  }

  // Reconciliation
  async getBankReconciliations(accountId: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/api/finance/reconciliations/bank/${accountId}`)
  }

  async startReconciliation(data: {
    accountId: string
    statementDate: string
    endingBalance: number
  }): Promise<ApiResponse<any>> {
    return apiClient.post('/api/finance/reconciliations/start', data)
  }

  async reconcileTransaction(
    reconciliationId: string,
    transactionId: string,
    match: boolean
  ): Promise<ApiResponse<any>> {
    return apiClient.post(
      `/api/finance/reconciliations/${reconciliationId}/transactions/${transactionId}`,
      { match }
    )
  }

  async completeReconciliation(id: string): Promise<ApiResponse<any>> {
    return apiClient.post(`/api/finance/reconciliations/${id}/complete`)
  }
}

export const financeService = new FinanceService()
export default financeService