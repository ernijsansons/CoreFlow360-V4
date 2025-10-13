/**
 * Reconciliation Detail Component
 * Complete reconciliation workflow with statement upload and transaction matching
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  CheckCircle2,
  AlertCircle,
  ArrowLeft,
  Loader2,
  FileText,
  TrendingUp
} from 'lucide-react';
import apiClient from '@/lib/api/client';
import { StatementUploader } from './StatementUploader';
import { TransactionMatcher } from './TransactionMatcher';

interface ReconciliationDetailProps {
  reconciliationId: string;
  onBack?: () => void;
}

export function ReconciliationDetail({ reconciliationId, onBack }: ReconciliationDetailProps) {
  const [activeTab, setActiveTab] = useState<'upload' | 'match' | 'review'>('upload');
  const queryClient = useQueryClient();

  const { data: reconciliationData, isLoading } = useQuery({
    queryKey: ['reconciliation', reconciliationId],
    queryFn: async () => {
      const response = await apiClient.get(`/api/v1/reconciliation/${reconciliationId}`);
      if (!response.ok) throw new Error('Failed to fetch reconciliation');
      return response.json();
    },
  });

  const detectDiscrepanciesMutation = useMutation({
    mutationFn: async () => {
      const response = await apiClient.post(
        `/api/v1/reconciliation/${reconciliationId}/detect-discrepancies`
      );
      if (!response.ok) throw new Error('Failed to detect discrepancies');
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['reconciliation', reconciliationId] });

      const event = new CustomEvent('show-toast', {
        detail: {
          message: `Found ${data.data.count} discrepanc${data.data.count !== 1 ? 'ies' : 'y'}`,
          type: data.data.count > 0 ? 'warning' : 'success'
        }
      });
      window.dispatchEvent(event);
    },
  });

  const completeReconciliationMutation = useMutation({
    mutationFn: async () => {
      const response = await apiClient.post(`/api/v1/reconciliation/${reconciliationId}/complete`);
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to complete reconciliation');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reconciliation', reconciliationId] });
      queryClient.invalidateQueries({ queryKey: ['reconciliations'] });

      const event = new CustomEvent('show-toast', {
        detail: {
          message: '✓ Reconciliation completed successfully',
          type: 'success'
        }
      });
      window.dispatchEvent(event);

      if (onBack) onBack();
    },
    onError: (error: Error) => {
      const event = new CustomEvent('show-toast', {
        detail: {
          message: `✗ ${error.message}`,
          type: 'error'
        }
      });
      window.dispatchEvent(event);
    },
  });

  const reconciliation = reconciliationData?.data?.reconciliation;
  const stats = reconciliationData?.data?.stats;

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  const getDifferenceColor = (difference: number) => {
    if (Math.abs(difference) < 0.01) {
      return 'text-green-600 dark:text-green-400';
    }
    return 'text-red-600 dark:text-red-400';
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!reconciliation) {
    return (
      <Card className="p-6">
        <p className="text-destructive">Reconciliation not found</p>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={onBack}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>
          <div className="h-8 w-px bg-border" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {reconciliation.account_name || 'Reconciliation'}
            </h1>
            <p className="text-muted-foreground mt-1">
              Statement Date: {formatDate(reconciliation.statement_date)}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {reconciliation.status === 'in_progress' && stats?.unmatched_transactions === 0 && (
            <Button
              onClick={() => completeReconciliationMutation.mutate()}
              disabled={completeReconciliationMutation.isPending}
            >
              {completeReconciliationMutation.isPending ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <CheckCircle2 className="w-4 h-4 mr-2" />
              )}
              Complete Reconciliation
            </Button>
          )}
        </div>
      </div>

      {/* Status Banner */}
      {reconciliation.status === 'completed' && (
        <Card className="p-4 bg-green-100 dark:bg-green-900/20 border-green-600">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400" />
            <div>
              <p className="font-semibold text-green-600 dark:text-green-400">
                Reconciliation Completed
              </p>
              <p className="text-sm text-green-600 dark:text-green-400">
                Completed on {formatDate(reconciliation.reconciled_at)}
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm text-muted-foreground">Statement Balance</p>
            <FileText className="w-5 h-5 text-muted-foreground" />
          </div>
          <p className="text-2xl font-bold">{formatCurrency(reconciliation.statement_balance)}</p>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm text-muted-foreground">Book Balance</p>
            <TrendingUp className="w-5 h-5 text-muted-foreground" />
          </div>
          <p className="text-2xl font-bold">{formatCurrency(reconciliation.book_balance)}</p>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm text-muted-foreground">Difference</p>
            {Math.abs(reconciliation.difference) < 0.01 ? (
              <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400" />
            ) : (
              <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
            )}
          </div>
          <p className={`text-2xl font-bold ${getDifferenceColor(reconciliation.difference)}`}>
            {formatCurrency(reconciliation.difference)}
          </p>
        </Card>
      </div>

      {/* Warning if difference exists */}
      {Math.abs(reconciliation.difference) >= 0.01 && reconciliation.status === 'in_progress' && (
        <Card className="p-4 bg-yellow-100 dark:bg-yellow-900/20 border-yellow-600">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm">
              <p className="font-semibold text-yellow-600 dark:text-yellow-400 mb-1">
                Balance Difference Detected
              </p>
              <p className="text-yellow-600 dark:text-yellow-400">
                There's a ${Math.abs(reconciliation.difference).toFixed(2)} difference between your statement and book balance.
                Please review all transactions and discrepancies before completing the reconciliation.
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Tabs for Workflow */}
      <Card className="p-6">
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="upload">1. Upload Statement</TabsTrigger>
            <TabsTrigger
              value="match"
              disabled={!stats || stats.total_statement_transactions === 0}
            >
              2. Match Transactions
            </TabsTrigger>
            <TabsTrigger
              value="review"
              disabled={!stats || stats.unmatched_transactions > 0}
            >
              3. Review & Complete
            </TabsTrigger>
          </TabsList>

          <TabsContent value="upload" className="mt-6">
            <StatementUploader
              reconciliationId={reconciliationId}
              onSuccess={() => {
                setActiveTab('match');
              }}
            />
          </TabsContent>

          <TabsContent value="match" className="mt-6">
            <TransactionMatcher reconciliationId={reconciliationId} />
          </TabsContent>

          <TabsContent value="review" className="mt-6">
            <div className="space-y-6">
              <div className="text-center py-8">
                <CheckCircle2 className="mx-auto h-16 w-16 text-green-600 dark:text-green-400 mb-4" />
                <h3 className="text-2xl font-bold mb-2">Ready to Complete</h3>
                <p className="text-muted-foreground mb-6">
                  All transactions have been matched. Review the summary and complete the reconciliation.
                </p>

                {stats && (
                  <div className="grid grid-cols-2 gap-4 max-w-md mx-auto mb-6">
                    <Card className="p-4">
                      <p className="text-sm text-muted-foreground">Total Transactions</p>
                      <p className="text-3xl font-bold">{stats.total_statement_transactions}</p>
                    </Card>
                    <Card className="p-4">
                      <p className="text-sm text-muted-foreground">Match Rate</p>
                      <p className="text-3xl font-bold text-green-600 dark:text-green-400">
                        {stats.match_percentage}%
                      </p>
                    </Card>
                  </div>
                )}

                <div className="flex items-center justify-center gap-3">
                  <Button
                    size="lg"
                    onClick={() => detectDiscrepanciesMutation.mutate()}
                    disabled={detectDiscrepanciesMutation.isPending}
                    variant="outline"
                  >
                    {detectDiscrepanciesMutation.isPending ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <AlertCircle className="w-4 h-4 mr-2" />
                    )}
                    Check for Discrepancies
                  </Button>

                  <Button
                    size="lg"
                    onClick={() => completeReconciliationMutation.mutate()}
                    disabled={completeReconciliationMutation.isPending}
                  >
                    {completeReconciliationMutation.isPending ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4 mr-2" />
                    )}
                    Complete Reconciliation
                  </Button>
                </div>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </Card>
    </div>
  );
}
