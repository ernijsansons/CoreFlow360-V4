import apiClient, { ApiResponse } from '../client'

export interface BankTransaction {
  id: string
  account_id: string
  amount: number
  currency: string
  transaction_date: string
  description: string
  merchant_name?: string
  category?: string
  status: 'pending' | 'matched' | 'ignored' | 'reviewed'
  matched_invoice_id?: string
  matched_expense_id?: string
  confidence_score?: number
}

export interface BankConnection {
  id: string
  provider: string
  account_name: string
  account_number_masked: string
  account_type: string
  balance: number
  currency: string
  status: 'active' | 'error' | 'disconnected'
  last_sync_at?: string
  created_at: string
}

export interface TransactionMatch {
  transaction_id: string
  match_type: 'invoice' | 'expense' | 'journal_entry'
  match_id: string
  confidence_score: number
  match_details: Record<string, unknown>
}

class BankingService {
  // Transactions
  async listTransactions(params?: {
    status?: 'pending' | 'matched' | 'ignored' | 'reviewed'
    limit?: number
    offset?: number
    from_date?: string
    to_date?: string
  }): Promise<ApiResponse<{
    transactions: BankTransaction[]
    total: number
    limit: number
    offset: number
  }>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get(`/api/banking/transactions?${query}`)
  }

  async getTransaction(id: string): Promise<ApiResponse<BankTransaction>> {
    return apiClient.get<BankTransaction>(`/api/banking/transactions/${id}`)
  }

  async findMatches(transactionId: string): Promise<ApiResponse<{
    matches: TransactionMatch[]
    best_match?: TransactionMatch
  }>> {
    return apiClient.post(`/api/banking/transactions/${transactionId}/find-matches`)
  }

  async applyMatch(
    transactionId: string,
    matchType: 'invoice' | 'expense' | 'journal_entry',
    matchId: string
  ): Promise<ApiResponse<BankTransaction>> {
    return apiClient.post(`/api/banking/transactions/${transactionId}/match`, {
      match_type: matchType,
      match_id: matchId
    })
  }

  async ignoreTransaction(transactionId: string): Promise<ApiResponse<BankTransaction>> {
    return apiClient.post(`/api/banking/transactions/${transactionId}/ignore`)
  }

  async unignoreTransaction(transactionId: string): Promise<ApiResponse<BankTransaction>> {
    return apiClient.post(`/api/banking/transactions/${transactionId}/unignore`)
  }

  // Bank Connections
  async listConnections(): Promise<ApiResponse<BankConnection[]>> {
    return apiClient.get<BankConnection[]>('/api/banking/connections')
  }

  async getConnection(id: string): Promise<ApiResponse<BankConnection>> {
    return apiClient.get<BankConnection>(`/api/banking/connections/${id}`)
  }

  async createConnection(data: {
    provider: string
    credentials: Record<string, unknown>
  }): Promise<ApiResponse<BankConnection>> {
    return apiClient.post<BankConnection>('/api/banking/connections', data)
  }

  async syncConnection(id: string): Promise<ApiResponse<{
    synced_transactions: number
    new_transactions: number
    status: string
  }>> {
    return apiClient.post(`/api/banking/connections/${id}/sync`)
  }

  async removeConnection(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/banking/connections/${id}`)
  }

  async testConnection(id: string): Promise<ApiResponse<{
    success: boolean
    error?: string
  }>> {
    return apiClient.post(`/api/banking/connections/${id}/test`)
  }

  // Bulk Operations
  async bulkMatch(matches: Array<{
    transaction_id: string
    match_type: 'invoice' | 'expense' | 'journal_entry'
    match_id: string
  }>): Promise<ApiResponse<{
    matched: number
    failed: number
    errors: string[]
  }>> {
    return apiClient.post('/api/banking/transactions/bulk-match', { matches })
  }

  async bulkIgnore(transactionIds: string[]): Promise<ApiResponse<{
    ignored: number
    failed: number
  }>> {
    return apiClient.post('/api/banking/transactions/bulk-ignore', { transaction_ids: transactionIds })
  }
}

export const bankingService = new BankingService()
export default bankingService
