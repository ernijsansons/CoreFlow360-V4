import { describe, it, expect, vi, beforeEach } from 'vitest'
import { bankingService } from '../banking.service'
import apiClient from '../../client'

vi.mock('../../client')

describe('Banking Service', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('listTransactions', () => {
    it('should list bank transactions with filters', async () => {
      const mockResponse = {
        data: {
          transactions: [
            {
              id: 'txn-1',
              amount: -150.50,
              description: 'Office Supplies',
              status: 'pending',
              transaction_date: '2025-10-10',
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
        },
        success: true,
      }

      vi.mocked(apiClient.get).mockResolvedValue(mockResponse)

      const result = await bankingService.listTransactions({
        status: 'pending',
        limit: 50,
      })

      expect(apiClient.get).toHaveBeenCalledWith(
        expect.stringContaining('/api/banking/transactions')
      )
      expect(result.data.transactions).toHaveLength(1)
      expect(result.data.transactions[0].status).toBe('pending')
    })
  })

  describe('findMatches', () => {
    it('should find matches for a transaction', async () => {
      const mockResponse = {
        data: {
          matches: [
            {
              transaction_id: 'txn-1',
              match_type: 'invoice',
              match_id: 'inv-123',
              confidence_score: 92,
              match_details: {
                amount: 150.50,
                description: 'Invoice #123',
              },
            },
          ],
          best_match: {
            transaction_id: 'txn-1',
            match_type: 'invoice',
            match_id: 'inv-123',
            confidence_score: 92,
          },
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await bankingService.findMatches('txn-1')

      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/banking/transactions/txn-1/find-matches'
      )
      expect(result.data.matches).toHaveLength(1)
      expect(result.data.best_match?.confidence_score).toBe(92)
    })
  })

  describe('applyMatch', () => {
    it('should apply a match to a transaction', async () => {
      const mockResponse = {
        data: {
          id: 'txn-1',
          status: 'matched',
          matched_invoice_id: 'inv-123',
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await bankingService.applyMatch('txn-1', 'invoice', 'inv-123')

      expect(apiClient.post).toHaveBeenCalledWith('/api/banking/transactions/txn-1/match', {
        match_type: 'invoice',
        match_id: 'inv-123',
      })
      expect(result.data.status).toBe('matched')
    })
  })

  describe('listConnections', () => {
    it('should list bank connections', async () => {
      const mockResponse = {
        data: [
          {
            id: 'conn-1',
            provider: 'plaid',
            account_name: 'Business Checking',
            status: 'active',
            balance: 25000,
            last_sync_at: '2025-10-12T10:00:00Z',
          },
        ],
        success: true,
      }

      vi.mocked(apiClient.get).mockResolvedValue(mockResponse)

      const result = await bankingService.listConnections()

      expect(apiClient.get).toHaveBeenCalledWith('/api/banking/connections')
      expect(result.data).toHaveLength(1)
      expect(result.data[0].status).toBe('active')
    })
  })

  describe('syncConnection', () => {
    it('should sync a bank connection', async () => {
      const mockResponse = {
        data: {
          synced_transactions: 25,
          new_transactions: 10,
          status: 'success',
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await bankingService.syncConnection('conn-1')

      expect(apiClient.post).toHaveBeenCalledWith('/api/banking/connections/conn-1/sync')
      expect(result.data.new_transactions).toBe(10)
    })
  })

  describe('bulkMatch', () => {
    it('should perform bulk matching', async () => {
      const mockResponse = {
        data: {
          matched: 8,
          failed: 2,
          errors: ['Transaction txn-9 not found'],
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const matches = [
        { transaction_id: 'txn-1', match_type: 'invoice' as const, match_id: 'inv-1' },
        { transaction_id: 'txn-2', match_type: 'expense' as const, match_id: 'exp-1' },
      ]

      const result = await bankingService.bulkMatch(matches)

      expect(apiClient.post).toHaveBeenCalledWith('/api/banking/transactions/bulk-match', {
        matches,
      })
      expect(result.data.matched).toBe(8)
      expect(result.data.failed).toBe(2)
    })
  })
})
