/**
 * Reconciliation Dashboard Component
 * Main dashboard for viewing and managing account reconciliations
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  CheckCircle2,
  AlertCircle,
  Clock,
  Plus,
  RefreshCw,
  FileText,
  TrendingUp
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface Reconciliation {
  id: string;
  account_name: string;
  account_type: string;
  statement_date: string;
  statement_balance: number;
  book_balance: number;
  difference: number;
  status: 'in_progress' | 'completed' | 'review_required';
  reconciled_at?: string;
  reconciled_by_email?: string;
}

interface ReconciliationDashboardProps {
  onCreateNew?: () => void;
  onSelectReconciliation?: (id: string) => void;
}

export function ReconciliationDashboard({
  onCreateNew,
  onSelectReconciliation,
}: ReconciliationDashboardProps) {
  const [statusFilter, setStatusFilter] = useState<string>('');

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['reconciliations', statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (statusFilter) params.append('status', statusFilter);
      params.append('limit', '50');

      const response = await apiClient.get(`/api/v1/reconciliation?${params.toString()}`);
      if (!response.ok) throw new Error('Failed to fetch reconciliations');
      return response.json();
    },
  });

  const reconciliations = data?.data?.reconciliations || [];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400" />;
      case 'in_progress':
        return <Clock className="w-5 h-5 text-blue-600 dark:text-blue-400" />;
      case 'review_required':
        return <AlertCircle className="w-5 h-5 text-orange-600 dark:text-orange-400" />;
      default:
        return <FileText className="w-5 h-5 text-gray-600 dark:text-gray-400" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const badges: Record<string, string> = {
      completed: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
      in_progress: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
      review_required: 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400',
    };
    return badges[status] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
  };

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

  // Calculate stats
  const stats = {
    total: reconciliations.length,
    completed: reconciliations.filter((r: Reconciliation) => r.status === 'completed').length,
    in_progress: reconciliations.filter((r: Reconciliation) => r.status === 'in_progress').length,
    review_required: reconciliations.filter((r: Reconciliation) => r.status === 'review_required')
      .length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
            <TrendingUp className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Account Reconciliation</h1>
            <p className="text-muted-foreground mt-1">{stats.in_progress} reconciliations in progress</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button onClick={onCreateNew}>
            <Plus className="w-4 h-4 mr-2" />
            New Reconciliation
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Total</p>
              <p className="text-2xl font-bold">{stats.total}</p>
            </div>
            <FileText className="w-8 h-8 text-gray-600 dark:text-gray-400" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Completed</p>
              <p className="text-2xl font-bold text-green-600 dark:text-green-400">{stats.completed}</p>
            </div>
            <CheckCircle2 className="w-8 h-8 text-green-600 dark:text-green-400" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">In Progress</p>
              <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">{stats.in_progress}</p>
            </div>
            <Clock className="w-8 h-8 text-blue-600 dark:text-blue-400" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Review Required</p>
              <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                {stats.review_required}
              </p>
            </div>
            <AlertCircle className="w-8 h-8 text-orange-600 dark:text-orange-400" />
          </div>
        </Card>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="flex items-center gap-4">
          <label className="text-sm font-medium">Status:</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 rounded-md border border-input bg-background"
          >
            <option value="">All Statuses</option>
            <option value="in_progress">In Progress</option>
            <option value="completed">Completed</option>
            <option value="review_required">Review Required</option>
          </select>
        </div>
      </Card>

      {/* Reconciliation List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : error ? (
        <Card className="p-6">
          <div className="text-center text-destructive">
            <p className="font-semibold">Error loading reconciliations</p>
            <p className="text-sm mt-1">{error instanceof Error ? error.message : 'Unknown error'}</p>
            <Button onClick={() => refetch()} className="mt-4" size="sm">
              Try Again
            </Button>
          </div>
        </Card>
      ) : reconciliations.length === 0 ? (
        <Card className="p-12">
          <div className="text-center">
            <FileText className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">No reconciliations found</h3>
            <p className="text-sm text-muted-foreground mb-4">
              {statusFilter
                ? 'Try adjusting your filters'
                : 'Get started by creating your first reconciliation'}
            </p>
            {!statusFilter && (
              <Button onClick={onCreateNew}>
                <Plus className="w-4 h-4 mr-2" />
                Create First Reconciliation
              </Button>
            )}
          </div>
        </Card>
      ) : (
        <div className="space-y-3">
          {reconciliations.map((reconciliation: Reconciliation) => (
            <Card
              key={reconciliation.id}
              className="p-5 hover:shadow-md transition-shadow cursor-pointer"
              onClick={() => onSelectReconciliation?.(reconciliation.id)}
            >
              <div className="flex items-start justify-between">
                {/* Left side */}
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    {getStatusIcon(reconciliation.status)}
                    <div>
                      <h3 className="font-semibold">{reconciliation.account_name}</h3>
                      <p className="text-sm text-muted-foreground capitalize">
                        {reconciliation.account_type.replace('_', ' ')}
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                    <div>
                      <p className="text-xs text-muted-foreground">Statement Date</p>
                      <p className="text-sm font-medium">{formatDate(reconciliation.statement_date)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Statement Balance</p>
                      <p className="text-sm font-medium">{formatCurrency(reconciliation.statement_balance)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Book Balance</p>
                      <p className="text-sm font-medium">{formatCurrency(reconciliation.book_balance)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Difference</p>
                      <p
                        className={`text-sm font-semibold ${
                          Math.abs(reconciliation.difference) < 0.01
                            ? 'text-green-600 dark:text-green-400'
                            : 'text-red-600 dark:text-red-400'
                        }`}
                      >
                        {formatCurrency(reconciliation.difference)}
                      </p>
                    </div>
                  </div>

                  {reconciliation.reconciled_at && (
                    <p className="text-xs text-muted-foreground mt-3">
                      Reconciled on {formatDate(reconciliation.reconciled_at)}
                      {reconciliation.reconciled_by_email && ` by ${reconciliation.reconciled_by_email}`}
                    </p>
                  )}
                </div>

                {/* Right side - Status badge */}
                <span
                  className={`px-3 py-1 rounded-full text-xs font-semibold uppercase ${getStatusBadge(
                    reconciliation.status
                  )}`}
                >
                  {reconciliation.status.replace('_', ' ')}
                </span>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
