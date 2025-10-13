import { useState } from 'react'
import {
  useBankTransactions,
  useTransactionMatches,
  useApplyMatch,
  useIgnoreTransaction,
  useBankConnections,
  useSyncBankConnection
} from '@/hooks/api'
import type { BankTransaction, TransactionMatch } from '@/lib/api/services/banking.service'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import {
  Loader2,
  Link as LinkIcon,
  EyeOff,
  RefreshCw,
  TrendingDown,
  TrendingUp,
  AlertTriangle
} from 'lucide-react'

export function TransactionMatching() {
  const [selectedTransaction, setSelectedTransaction] = useState<string | null>(null)
  const [filter, setFilter] = useState<'pending' | 'matched' | 'ignored'>('pending')

  const { data: transactions, isLoading: transactionsLoading } = useBankTransactions({
    status: filter,
    limit: 50
  })
  const { data: matches, isLoading: matchesLoading } = useTransactionMatches(
    selectedTransaction || ''
  )
  const { data: connections } = useBankConnections()
  const applyMatch = useApplyMatch()
  const ignoreTransaction = useIgnoreTransaction()
  const syncConnection = useSyncBankConnection()

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'matched':
        return <Badge className="bg-green-500">Matched</Badge>
      case 'ignored':
        return <Badge variant="secondary">Ignored</Badge>
      case 'pending':
        return <Badge variant="outline">Pending</Badge>
      default:
        return <Badge>{status}</Badge>
    }
  }

  const formatCurrency = (amount: number, currency: string) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency || 'USD'
    }).format(amount)
  }

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return 'text-green-600'
    if (confidence >= 70) return 'text-yellow-600'
    return 'text-red-600'
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Transaction Matching
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Match bank transactions with invoices and expenses
          </p>
        </div>

        {connections?.data && connections.data.length > 0 && (
          <Button
            onClick={() => syncConnection.mutate(connections.data[0].id)}
            disabled={syncConnection.isPending}
          >
            {syncConnection.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4 mr-2" />
            )}
            Sync Transactions
          </Button>
        )}
      </div>

      {/* Filter Tabs */}
      <div className="flex space-x-2">
        {(['pending', 'matched', 'ignored'] as const).map((status) => (
          <Button
            key={status}
            variant={filter === status ? 'default' : 'outline'}
            onClick={() => setFilter(status)}
          >
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Transactions List */}
        <Card className="lg:col-span-2 p-6">
          <h2 className="text-xl font-bold mb-4">Transactions</h2>

          {transactionsLoading ? (
            <div className="flex items-center justify-center h-48">
              <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
            </div>
          ) : (
            <div className="space-y-3">
              {transactions?.data?.transactions && transactions.data.transactions.length > 0 ? (
                transactions.data.transactions.map((transaction: BankTransaction) => (
                  <div
                    key={transaction.id}
                    className={`p-4 border rounded-lg cursor-pointer transition-all ${
                      selectedTransaction === transaction.id
                        ? 'border-brand-primary bg-brand-primary/5'
                        : 'border-gray-200 dark:border-gray-700 hover:border-brand-primary/50'
                    }`}
                    onClick={() => setSelectedTransaction(transaction.id)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          {transaction.amount > 0 ? (
                            <TrendingUp className="h-5 w-5 text-green-500" />
                          ) : (
                            <TrendingDown className="h-5 w-5 text-red-500" />
                          )}
                          <span className="font-medium">{transaction.description}</span>
                        </div>
                        <div className="mt-1 space-y-1">
                          {transaction.merchant_name && (
                            <p className="text-sm text-gray-600 dark:text-gray-400">
                              {transaction.merchant_name}
                            </p>
                          )}
                          <p className="text-xs text-gray-500">
                            {new Date(transaction.transaction_date).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                      <div className="text-right space-y-2">
                        <p className={`text-lg font-semibold ${
                          transaction.amount > 0 ? 'text-green-600' : 'text-red-600'
                        }`}>
                          {formatCurrency(Math.abs(transaction.amount), transaction.currency)}
                        </p>
                        {getStatusBadge(transaction.status)}
                      </div>
                    </div>

                    {transaction.confidence_score && (
                      <div className="mt-2 flex items-center space-x-2">
                        <span className="text-xs text-gray-500">Match confidence:</span>
                        <span className={`text-xs font-medium ${getConfidenceColor(transaction.confidence_score)}`}>
                          {transaction.confidence_score}%
                        </span>
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-center py-12 text-gray-500">
                  No {filter} transactions found
                </div>
              )}
            </div>
          )}
        </Card>

        {/* Matches Panel */}
        <Card className="p-6">
          {selectedTransaction ? (
            <>
              <h2 className="text-xl font-bold mb-4">Suggested Matches</h2>

              {matchesLoading ? (
                <div className="flex items-center justify-center h-48">
                  <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
                </div>
              ) : matches?.data?.matches && matches.data.matches.length > 0 ? (
                <div className="space-y-3">
                  {matches.data.matches.map((match: TransactionMatch) => (
                    <div
                      key={`${match.match_type}-${match.match_id}`}
                      className="p-3 border border-gray-200 dark:border-gray-700 rounded-lg"
                    >
                      <div className="flex items-start justify-between mb-2">
                        <Badge variant="outline">{match.match_type}</Badge>
                        <span className={`text-sm font-medium ${getConfidenceColor(match.confidence_score)}`}>
                          {match.confidence_score}%
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                        {match.match_details.description || 'Match details'}
                      </p>
                      <Button
                        size="sm"
                        className="w-full"
                        onClick={() => {
                          applyMatch.mutate({
                            transactionId: selectedTransaction,
                            matchType: match.match_type,
                            matchId: match.match_id
                          })
                        }}
                        disabled={applyMatch.isPending}
                      >
                        {applyMatch.isPending ? (
                          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        ) : (
                          <LinkIcon className="h-4 w-4 mr-2" />
                        )}
                        Apply Match
                      </Button>
                    </div>
                  ))}

                  <div className="pt-3 border-t">
                    <Button
                      size="sm"
                      variant="outline"
                      className="w-full"
                      onClick={() => {
                        ignoreTransaction.mutate(selectedTransaction)
                        setSelectedTransaction(null)
                      }}
                    >
                      <EyeOff className="h-4 w-4 mr-2" />
                      Ignore Transaction
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-3" />
                  <p className="text-sm text-gray-500">No matches found</p>
                  <Button
                    size="sm"
                    variant="outline"
                    className="mt-4"
                    onClick={() => ignoreTransaction.mutate(selectedTransaction)}
                  >
                    <EyeOff className="h-4 w-4 mr-2" />
                    Ignore
                  </Button>
                </div>
              )}
            </>
          ) : (
            <div className="flex items-center justify-center h-48 text-gray-500">
              Select a transaction to view matches
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
