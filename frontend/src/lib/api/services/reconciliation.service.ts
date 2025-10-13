import apiClient, { ApiResponse } from '../client'

export interface ReconciliationAccount {
  id: string
  account_id: string
  account_name: string
  account_number: string
  last_reconciliation_date?: string
  unreconciled_transactions: number
}

export interface Reconciliation {
  id: string
  account_id: string
  statement_date: string
  statement_ending_balance: number
  book_balance: number
  difference: number
  status: 'in_progress' | 'completed' | 'cancelled'
  matched_transactions: number
  unmatched_transactions: number
  created_at: string
  completed_at?: string
}

export interface ReconciliationTransaction {
  id: string
  transaction_id: string
  transaction_date: string
  description: string
  amount: number
  status: 'matched' | 'unmatched' | 'excluded'
  statement_match?: {
    statement_date: string
    statement_description: string
    confidence: number
  }
}

class ReconciliationService {
  async listAccountsForReconciliation(): Promise<ApiResponse<ReconciliationAccount[]>> {
    return apiClient.get<ReconciliationAccount[]>('/api/reconciliation/accounts')
  }

  async createReconciliation(data: {
    account_id: string
    statement_date: string
    statement_ending_balance: number
  }): Promise<ApiResponse<Reconciliation>> {
    return apiClient.post<Reconciliation>('/api/reconciliation', data)
  }

  async getReconciliation(id: string): Promise<ApiResponse<Reconciliation>> {
    return apiClient.get<Reconciliation>(`/api/reconciliation/${id}`)
  }

  async uploadBankStatement(
    reconciliationId: string,
    file: File
  ): Promise<ApiResponse<{
    parsed_transactions: number
    auto_matched: number
    requires_review: number
  }>> {
    const formData = new FormData()
    formData.append('file', file)
    return apiClient.post(`/api/reconciliation/${reconciliationId}/upload-statement`, formData)
  }

  async autoMatchTransactions(reconciliationId: string): Promise<ApiResponse<{
    matched: number
    unmatched: number
    confidence_threshold: number
  }>> {
    return apiClient.post(`/api/reconciliation/${reconciliationId}/auto-match`)
  }

  async getReconciliationTransactions(
    reconciliationId: string,
    params?: {
      status?: 'matched' | 'unmatched' | 'excluded'
    }
  ): Promise<ApiResponse<ReconciliationTransaction[]>> {
    const query = new URLSearchParams()
    if (params?.status) query.append('status', params.status)
    return apiClient.get<ReconciliationTransaction[]>(
      `/api/reconciliation/${reconciliationId}/transactions?${query}`
    )
  }

  async matchTransaction(
    reconciliationId: string,
    transactionId: string,
    statementLineId: string
  ): Promise<ApiResponse<void>> {
    return apiClient.post(
      `/api/reconciliation/${reconciliationId}/transactions/${transactionId}/match`,
      { statement_line_id: statementLineId }
    )
  }

  async unmatchTransaction(
    reconciliationId: string,
    transactionId: string
  ): Promise<ApiResponse<void>> {
    return apiClient.post(
      `/api/reconciliation/${reconciliationId}/transactions/${transactionId}/unmatch`
    )
  }

  async excludeTransaction(
    reconciliationId: string,
    transactionId: string,
    reason: string
  ): Promise<ApiResponse<void>> {
    return apiClient.post(
      `/api/reconciliation/${reconciliationId}/transactions/${transactionId}/exclude`,
      { reason }
    )
  }

  async completeReconciliation(id: string): Promise<ApiResponse<Reconciliation>> {
    return apiClient.post<Reconciliation>(`/api/reconciliation/${id}/complete`)
  }

  async cancelReconciliation(id: string): Promise<ApiResponse<void>> {
    return apiClient.post(`/api/reconciliation/${id}/cancel`)
  }

  async getReconciliationHistory(accountId: string): Promise<ApiResponse<Reconciliation[]>> {
    return apiClient.get<Reconciliation[]>(`/api/reconciliation/accounts/${accountId}/history`)
  }
}

export const reconciliationService = new ReconciliationService()
export default reconciliationService
