/**
 * Transaction Matcher Component
 * Match statement transactions with book transactions
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  CheckCircle2,
  Sparkles,
  TrendingUp,
  Search,
  Loader2,
  AlertCircle,
  Calendar,
  DollarSign,
  FileText
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface StatementTransaction {
  id: string;
  transaction_date: string;
  description: string;
  amount: number;
  matched: boolean;
  reference_number?: string;
  check_number?: string;
}

interface MatchSuggestion {
  statement_transaction_id: string;
  book_transaction_id: string;
  confidence: number;
  match_reasons: string[];
}

interface TransactionMatcherProps {
  reconciliationId: string;
}

export function TransactionMatcher({ reconciliationId }: TransactionMatcherProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTransaction, setSelectedTransaction] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: transactionsData, isLoading: isLoadingTransactions } = useQuery({
    queryKey: ['reconciliation-transactions', reconciliationId],
    queryFn: async () => {
      const response = await apiClient.get(`/api/v1/reconciliation/${reconciliationId}/transactions`);
      if (!response.ok) throw new Error('Failed to fetch transactions');
      return response.json();
    },
  });

  const { data: statsData } = useQuery({
    queryKey: ['reconciliation', reconciliationId],
    queryFn: async () => {
      const response = await apiClient.get(`/api/v1/reconciliation/${reconciliationId}`);
      if (!response.ok) throw new Error('Failed to fetch reconciliation');
      return response.json();
    },
  });

  const autoMatchMutation = useMutation({
    mutationFn: async () => {
      const response = await apiClient.post(`/api/v1/reconciliation/${reconciliationId}/auto-match`);
      if (!response.ok) throw new Error('Auto-match failed');
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['reconciliation-transactions', reconciliationId] });
      queryClient.invalidateQueries({ queryKey: ['reconciliation', reconciliationId] });

      const event = new CustomEvent('show-toast', {
        detail: {
          message: `✓ Auto-matched ${data.data.auto_matched} transactions`,
          type: 'success'
        }
      });
      window.dispatchEvent(event);
    },
  });

  const manualMatchMutation = useMutation({
    mutationFn: async ({
      statementTxnId,
      bookTxnId,
      confidence,
    }: {
      statementTxnId: string;
      bookTxnId: string;
      confidence: number;
    }) => {
      const response = await apiClient.post(`/api/v1/reconciliation/${reconciliationId}/match`, {
        json: {
          statement_transaction_id: statementTxnId,
          book_transaction_id: bookTxnId,
          confidence,
        },
      });
      if (!response.ok) throw new Error('Manual match failed');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reconciliation-transactions', reconciliationId] });
      queryClient.invalidateQueries({ queryKey: ['reconciliation', reconciliationId] });

      const event = new CustomEvent('show-toast', {
        detail: {
          message: '✓ Match applied successfully',
          type: 'success'
        }
      });
      window.dispatchEvent(event);
    },
  });

  const transactions = transactionsData?.data?.statement_transactions || [];
  const stats = statsData?.data?.stats || {
    total_statement_transactions: 0,
    matched_transactions: 0,
    unmatched_transactions: 0,
    match_percentage: 0,
  };

  const filteredTransactions = transactions.filter((t: StatementTransaction) =>
    t.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
    t.amount.toString().includes(searchTerm)
  );

  const unmatchedTransactions = filteredTransactions.filter((t: StatementTransaction) => !t.matched);

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(Math.abs(amount));
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Transaction Matching</h2>
          <p className="text-muted-foreground mt-1">
            {stats.unmatched_transactions} transactions need to be matched
          </p>
        </div>

        <Button
          onClick={() => autoMatchMutation.mutate()}
          disabled={autoMatchMutation.isPending || stats.unmatched_transactions === 0}
        >
          {autoMatchMutation.isPending ? (
            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
          ) : (
            <Sparkles className="w-4 h-4 mr-2" />
          )}
          Auto-Match Transactions
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Total Transactions</p>
              <p className="text-2xl font-bold">{stats.total_statement_transactions}</p>
            </div>
            <FileText className="w-8 h-8 text-gray-600 dark:text-gray-400" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Matched</p>
              <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                {stats.matched_transactions}
              </p>
            </div>
            <CheckCircle2 className="w-8 h-8 text-green-600 dark:text-green-400" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Unmatched</p>
              <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                {stats.unmatched_transactions}
              </p>
            </div>
            <AlertCircle className="w-8 h-8 text-orange-600 dark:text-orange-400" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Match Rate</p>
              <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                {stats.match_percentage}%
              </p>
            </div>
            <TrendingUp className="w-8 h-8 text-blue-600 dark:text-blue-400" />
          </div>
        </Card>
      </div>

      {/* Search */}
      <Card className="p-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Search transactions by description or amount..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
      </Card>

      {/* Transaction List */}
      {isLoadingTransactions ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : unmatchedTransactions.length === 0 ? (
        <Card className="p-12">
          <div className="text-center">
            <CheckCircle2 className="mx-auto h-12 w-12 text-green-600 dark:text-green-400 mb-4" />
            <h3 className="text-lg font-semibold mb-2">All Transactions Matched!</h3>
            <p className="text-sm text-muted-foreground">
              {searchTerm
                ? 'No unmatched transactions match your search'
                : 'Great job! All statement transactions have been matched.'}
            </p>
          </div>
        </Card>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between mb-3">
            <p className="text-sm text-muted-foreground">
              Showing {unmatchedTransactions.length} unmatched transaction{unmatchedTransactions.length !== 1 ? 's' : ''}
            </p>
          </div>

          {unmatchedTransactions.map((transaction: StatementTransaction) => (
            <Card
              key={transaction.id}
              className="p-5 hover:shadow-md transition-shadow cursor-pointer"
              onClick={() => setSelectedTransaction(transaction.id)}
            >
              <div className="flex items-center justify-between">
                {/* Left side */}
                <div className="flex-1">
                  <div className="flex items-center gap-4 mb-3">
                    <div className="p-2 bg-orange-100 dark:bg-orange-900/20 rounded-lg">
                      <AlertCircle className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                    </div>
                    <div className="flex-1">
                      <p className="font-semibold">{transaction.description}</p>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground mt-1">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {formatDate(transaction.transaction_date)}
                        </div>
                        {transaction.reference_number && (
                          <div className="flex items-center gap-1">
                            <FileText className="w-3 h-3" />
                            Ref: {transaction.reference_number}
                          </div>
                        )}
                        {transaction.check_number && (
                          <div className="flex items-center gap-1">
                            <FileText className="w-3 h-3" />
                            Check: {transaction.check_number}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Right side - Amount */}
                <div className="text-right">
                  <div className="flex items-center gap-2">
                    <DollarSign className="w-4 h-4 text-muted-foreground" />
                    <span
                      className={`text-xl font-bold ${
                        transaction.amount > 0
                          ? 'text-green-600 dark:text-green-400'
                          : 'text-red-600 dark:text-red-400'
                      }`}
                    >
                      {transaction.amount > 0 ? '+' : ''}
                      {formatCurrency(transaction.amount)}
                    </span>
                  </div>
                  <Button size="sm" variant="outline" className="mt-2">
                    Find Matches
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
