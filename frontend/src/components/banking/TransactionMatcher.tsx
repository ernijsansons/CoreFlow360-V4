/**
 * Transaction Matcher Component
 * AI-powered bank transaction matching with confidence scores
 */

import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  DollarSign,
  Calendar,
  FileText,
  Building2,
  TrendingUp,
  CheckCircle2,
  Loader2,
  AlertCircle,
  ArrowRight,
  X,
  Search,
  Sparkles
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface MatchSuggestion {
  match_type: 'invoice' | 'expense';
  match_id: string;
  match_name: string;
  match_amount: number;
  match_date: string;
  confidence: number;
  reasons: string[];
  details: {
    amount_match: boolean;
    amount_difference: number;
    date_proximity_days: number;
    description_similarity: number;
  };
}

interface BankTransaction {
  id: string;
  amount: number;
  transaction_date: string;
  description: string;
  status: 'unmatched' | 'matched' | 'ignored';
  matched_invoice_id?: string;
  matched_expense_id?: string;
  confidence_score?: number;
}

interface TransactionMatcherProps {
  transaction: BankTransaction;
  onMatchApplied?: () => void;
  onClose?: () => void;
}

export function TransactionMatcher({ transaction, onMatchApplied, onClose }: TransactionMatcherProps) {
  const [selectedMatch, setSelectedMatch] = useState<MatchSuggestion | null>(null);

  const { data: matchesData, isLoading, error, refetch } = useQuery({
    queryKey: ['transaction-matches', transaction.id],
    queryFn: async () => {
      const response = await apiClient.post(`/api/banking/transactions/${transaction.id}/find-matches`);
      if (!response.ok) throw new Error('Failed to find matches');
      return response.json();
    },
    enabled: transaction.status === 'unmatched',
  });

  const applyMatchMutation = useMutation({
    mutationFn: async ({ matchType, matchId }: { matchType: string; matchId: string }) => {
      const response = await apiClient.post(`/api/banking/transactions/${transaction.id}/apply-match`, {
        json: {
          match_type: matchType,
          match_id: matchId,
        },
      });
      if (!response.ok) throw new Error('Failed to apply match');
      return response.json();
    },
    onSuccess: () => {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Match applied successfully', type: 'success' }
      });
      window.dispatchEvent(event);
      if (onMatchApplied) onMatchApplied();
    },
  });

  const matches = matchesData?.data?.matches || [];

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return 'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/20';
    if (confidence >= 60) return 'text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/20';
    if (confidence >= 40) return 'text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900/20';
    return 'text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700';
  };

  const getConfidenceBadge = (confidence: number) => {
    if (confidence >= 80) return 'High Confidence';
    if (confidence >= 60) return 'Medium Confidence';
    if (confidence >= 40) return 'Low Confidence';
    return 'Very Low';
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(Math.abs(amount));
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  };

  const handleApplyMatch = (match: MatchSuggestion) => {
    setSelectedMatch(match);
    applyMatchMutation.mutate({
      matchType: match.match_type,
      matchId: match.match_id,
    });
  };

  return (
    <div className="space-y-6">
      {/* Transaction Details */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">Bank Transaction</h3>
          {onClose && (
            <Button variant="ghost" size="sm" onClick={onClose}>
              <X className="w-4 h-4" />
            </Button>
          )}
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Description</span>
            <span className="font-medium">{transaction.description}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Amount</span>
            <span className={`font-semibold ${transaction.amount > 0 ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
              {transaction.amount > 0 ? '+' : ''}{formatCurrency(transaction.amount)}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Date</span>
            <span className="font-medium">{formatDate(transaction.transaction_date)}</span>
          </div>
        </div>
      </Card>

      {/* Matching Status */}
      {isLoading ? (
        <Card className="p-8">
          <div className="flex flex-col items-center">
            <Loader2 className="w-12 h-12 text-brand-primary animate-spin mb-4" />
            <p className="text-lg font-semibold mb-2">Finding matches...</p>
            <p className="text-sm text-muted-foreground">Analyzing invoices and expenses</p>
          </div>
        </Card>
      ) : error ? (
        <Card className="p-6">
          <div className="flex items-center gap-3 text-destructive">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <div>
              <p className="font-semibold">Error finding matches</p>
              <p className="text-sm mt-1">Please try again</p>
            </div>
            <Button onClick={() => refetch()} size="sm" className="ml-auto">
              Retry
            </Button>
          </div>
        </Card>
      ) : matches.length === 0 ? (
        <Card className="p-12">
          <div className="text-center">
            <Search className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">No matches found</h3>
            <p className="text-sm text-muted-foreground mb-4">
              We couldn't find any invoices or expenses that match this transaction.
            </p>
            <p className="text-xs text-muted-foreground">
              This could be a unique transaction that needs manual categorization.
            </p>
          </div>
        </Card>
      ) : (
        <>
          {/* Match Suggestions Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-brand-primary" />
              <h3 className="text-lg font-semibold">AI Match Suggestions</h3>
            </div>
            <span className="text-sm text-muted-foreground">{matches.length} matches found</span>
          </div>

          {/* Match Suggestions List */}
          <div className="space-y-3">
            {matches.map((match: MatchSuggestion) => (
              <Card
                key={`${match.match_type}-${match.match_id}`}
                className={`p-5 transition-all ${
                  selectedMatch?.match_id === match.match_id
                    ? 'ring-2 ring-brand-primary'
                    : 'hover:shadow-md'
                }`}
              >
                {/* Match Header */}
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      {match.match_type === 'invoice' ? (
                        <FileText className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                      ) : (
                        <DollarSign className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                      )}
                      <span className="font-semibold">{match.match_name}</span>
                      <span className="text-xs text-muted-foreground capitalize px-2 py-0.5 rounded-full bg-muted">
                        {match.match_type}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span>{formatCurrency(match.match_amount)}</span>
                      <span>•</span>
                      <span>{formatDate(match.match_date)}</span>
                    </div>
                  </div>

                  {/* Confidence Badge */}
                  <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full ${getConfidenceColor(match.confidence)}`}>
                    <TrendingUp className="w-4 h-4" />
                    <span className="text-sm font-semibold">{match.confidence}%</span>
                  </div>
                </div>

                {/* Match Details Grid */}
                <div className="grid grid-cols-3 gap-4 mb-4 pt-4 border-t">
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Amount Match</p>
                    <div className="flex items-center gap-1">
                      {match.details.amount_match ? (
                        <CheckCircle2 className="w-4 h-4 text-green-600 dark:text-green-400" />
                      ) : (
                        <AlertCircle className="w-4 h-4 text-yellow-600 dark:text-yellow-400" />
                      )}
                      <span className="text-sm font-medium">
                        {match.details.amount_match ? 'Exact' : `±${formatCurrency(match.details.amount_difference)}`}
                      </span>
                    </div>
                  </div>

                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Date Proximity</p>
                    <p className="text-sm font-medium">
                      {match.details.date_proximity_days === 0
                        ? 'Same day'
                        : `${match.details.date_proximity_days} day${match.details.date_proximity_days > 1 ? 's' : ''}`}
                    </p>
                  </div>

                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Text Similarity</p>
                    <p className="text-sm font-medium">{match.details.description_similarity}%</p>
                  </div>
                </div>

                {/* Match Reasons */}
                <div className="mb-4">
                  <p className="text-xs text-muted-foreground mb-2">Match Reasons:</p>
                  <div className="space-y-1">
                    {match.reasons.map((reason, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-sm">
                        <div className="w-1.5 h-1.5 rounded-full bg-brand-primary" />
                        <span className="text-muted-foreground">{reason}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Action Button */}
                <Button
                  onClick={() => handleApplyMatch(match)}
                  disabled={applyMatchMutation.isPending}
                  className="w-full"
                  variant={match.confidence >= 80 ? 'default' : 'outline'}
                >
                  {applyMatchMutation.isPending && selectedMatch?.match_id === match.match_id ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Applying Match...
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-4 h-4 mr-2" />
                      Apply This Match
                      <ArrowRight className="w-4 h-4 ml-2" />
                    </>
                  )}
                </Button>
              </Card>
            ))}
          </div>

          {/* Confidence Guide */}
          <Card className="p-4 bg-muted/50">
            <p className="text-sm font-semibold mb-2">Confidence Guide:</p>
            <div className="space-y-1 text-xs text-muted-foreground">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-green-600 dark:bg-green-400" />
                <span><strong>80%+:</strong> High confidence - likely accurate match</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-600 dark:bg-blue-400" />
                <span><strong>60-79%:</strong> Medium confidence - review recommended</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-yellow-600 dark:bg-yellow-400" />
                <span><strong>40-59%:</strong> Low confidence - verify details carefully</span>
              </div>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
