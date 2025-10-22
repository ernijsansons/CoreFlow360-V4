/**
 * Real-time Sync Status Monitor
 * Live progress tracking for integration syncs with detailed status
 */

import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
  RefreshCw, CheckCircle, AlertTriangle, XCircle, Loader2,
  Mail, Phone, MessageSquare, Clock, TrendingUp, Activity
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface SyncStatus {
  integration_id: string;
  provider: string;
  status: 'idle' | 'syncing' | 'completed' | 'failed';
  started_at?: string;
  completed_at?: string;
  progress?: {
    current: number;
    total: number;
    percentage: number;
  };
  results?: {
    items_processed: number;
    items_captured: number;
    items_skipped: number;
    errors: string[];
  };
  last_error?: string;
}

const PROVIDER_ICONS: Record<string, typeof Mail> = {
  gmail: Mail,
  outlook: Mail,
  twilio: Phone,
  slack: MessageSquare,
  teams: MessageSquare
};

const STATUS_ICONS = {
  idle: Clock,
  syncing: Loader2,
  completed: CheckCircle,
  failed: XCircle
};

const STATUS_COLORS = {
  idle: 'text-gray-500',
  syncing: 'text-blue-600',
  completed: 'text-green-600',
  failed: 'text-red-600'
};

const STATUS_BG_COLORS = {
  idle: 'bg-gray-100 text-gray-800 border-gray-200',
  syncing: 'bg-blue-100 text-blue-800 border-blue-200',
  completed: 'bg-green-100 text-green-800 border-green-200',
  failed: 'bg-red-100 text-red-800 border-red-200'
};

export function SyncStatusMonitor() {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Fetch sync status for all integrations
  const { data: syncStatuses, isLoading } = useQuery({
    queryKey: ['crm', 'integrations', 'sync-status'],
    queryFn: async () => {
      const response = await apiClient.get('/api/v1/crm/integrations/sync-status');
      return response.data.data as SyncStatus[];
    },
    refetchInterval: (data) => {
      // Refetch every 2 seconds if any integration is syncing
      const hasActiveSyncs = data?.some(s => s.status === 'syncing');
      return hasActiveSyncs ? 2000 : 10000; // 2s when syncing, 10s otherwise
    }
  });

  const statuses = syncStatuses || [];
  const activeSyncs = statuses.filter(s => s.status === 'syncing').length;
  const completedToday = statuses.filter(s => {
    if (!s.completed_at) return false;
    const completed = new Date(s.completed_at);
    const today = new Date();
    return completed.toDateString() === today.toDateString();
  }).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
            Sync Status Monitor
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Real-time sync progress across all integrations
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge className="bg-blue-100 text-blue-800 border-blue-200">
            {activeSyncs} Active
          </Badge>
          <Badge variant="outline">
            {completedToday} Completed Today
          </Badge>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Active Syncs</p>
              <p className="text-2xl font-bold text-blue-600 mt-1">{activeSyncs}</p>
            </div>
            <Activity className="w-8 h-8 text-blue-500 opacity-50" />
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Completed Today</p>
              <p className="text-2xl font-bold text-green-600 mt-1">{completedToday}</p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-500 opacity-50" />
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Synced</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                {statuses.reduce((sum, s) => sum + (s.results?.items_captured || 0), 0)}
              </p>
            </div>
            <TrendingUp className="w-8 h-8 text-gray-500 opacity-50" />
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Failed</p>
              <p className="text-2xl font-bold text-red-600 mt-1">
                {statuses.filter(s => s.status === 'failed').length}
              </p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-500 opacity-50" />
          </div>
        </Card>
      </div>

      {/* Status List */}
      {isLoading ? (
        <Card className="p-8">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-primary"></div>
          </div>
        </Card>
      ) : statuses.length === 0 ? (
        <Card className="p-12 text-center">
          <Activity className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
            No Integrations
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            Add integrations to start syncing data
          </p>
        </Card>
      ) : (
        <div className="space-y-3">
          {statuses.map((status) => (
            <SyncStatusCard
              key={status.integration_id}
              status={status}
              isExpanded={expandedId === status.integration_id}
              onToggle={() => setExpandedId(expandedId === status.integration_id ? null : status.integration_id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function SyncStatusCard({
  status,
  isExpanded,
  onToggle
}: {
  status: SyncStatus;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const ProviderIcon = PROVIDER_ICONS[status.provider] || Activity;
  const StatusIcon = STATUS_ICONS[status.status];
  const statusColor = STATUS_COLORS[status.status];
  const statusBgColor = STATUS_BG_COLORS[status.status];

  const [elapsedTime, setElapsedTime] = useState<string>('');

  useEffect(() => {
    if (status.status === 'syncing' && status.started_at) {
      const interval = setInterval(() => {
        const started = new Date(status.started_at!);
        const now = new Date();
        const diff = Math.floor((now.getTime() - started.getTime()) / 1000);
        const minutes = Math.floor(diff / 60);
        const seconds = diff % 60;
        setElapsedTime(`${minutes}m ${seconds}s`);
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [status.status, status.started_at]);

  return (
    <Card className="overflow-hidden">
      <div className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3 flex-1">
            <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
              <ProviderIcon className="w-5 h-5 text-gray-600" />
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-2">
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  {status.provider.charAt(0).toUpperCase() + status.provider.slice(1)} Sync
                </h3>
                <Badge className={statusBgColor}>
                  <StatusIcon className={`w-3 h-3 mr-1 ${status.status === 'syncing' ? 'animate-spin' : ''}`} />
                  {status.status.charAt(0).toUpperCase() + status.status.slice(1)}
                </Badge>
              </div>

              {/* Progress Bar (for syncing status) */}
              {status.status === 'syncing' && status.progress && (
                <div className="mb-3">
                  <div className="flex items-center justify-between text-sm mb-2">
                    <span className="text-gray-600 dark:text-gray-400">
                      {status.progress.current} of {status.progress.total} items
                    </span>
                    <span className="text-gray-900 dark:text-white font-semibold">
                      {status.progress.percentage}%
                    </span>
                  </div>
                  <Progress value={status.progress.percentage} className="h-2" />
                </div>
              )}

              {/* Status Info */}
              <div className="flex items-center gap-4 text-sm text-gray-600 dark:text-gray-400">
                {status.status === 'syncing' && elapsedTime && (
                  <div className="flex items-center gap-1">
                    <Clock className="w-4 h-4" />
                    {elapsedTime}
                  </div>
                )}
                {status.started_at && (
                  <div>
                    Started: {new Date(status.started_at).toLocaleTimeString()}
                  </div>
                )}
                {status.completed_at && (
                  <div>
                    Completed: {new Date(status.completed_at).toLocaleTimeString()}
                  </div>
                )}
              </div>

              {/* Results Summary */}
              {status.results && (
                <div className="mt-3 flex items-center gap-4 text-sm">
                  <div>
                    <span className="text-gray-500">Processed:</span>
                    <span className="ml-1 font-semibold text-gray-900 dark:text-white">
                      {status.results.items_processed}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500">Captured:</span>
                    <span className="ml-1 font-semibold text-green-600">
                      {status.results.items_captured}
                    </span>
                  </div>
                  {status.results.items_skipped > 0 && (
                    <div>
                      <span className="text-gray-500">Skipped:</span>
                      <span className="ml-1 font-semibold text-yellow-600">
                        {status.results.items_skipped}
                      </span>
                    </div>
                  )}
                  {status.results.errors.length > 0 && (
                    <div>
                      <span className="text-gray-500">Errors:</span>
                      <span className="ml-1 font-semibold text-red-600">
                        {status.results.errors.length}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {/* Error Message */}
              {status.last_error && (
                <div className="mt-3 p-2 bg-red-50 dark:bg-red-900/20 rounded text-sm text-red-800 dark:text-red-200">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                    <span>{status.last_error}</span>
                  </div>
                </div>
              )}

              {/* Expanded Details */}
              {isExpanded && status.results?.errors && status.results.errors.length > 0 && (
                <div className="mt-3 p-3 bg-gray-50 dark:bg-gray-800 rounded">
                  <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                    Errors ({status.results.errors.length})
                  </h4>
                  <ul className="space-y-1 text-sm text-gray-700 dark:text-gray-300">
                    {status.results.errors.slice(0, 5).map((error, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <span className="text-red-500">•</span>
                        <span>{error}</span>
                      </li>
                    ))}
                    {status.results.errors.length > 5 && (
                      <li className="text-gray-500">
                        ... and {status.results.errors.length - 5} more
                      </li>
                    )}
                  </ul>
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 ml-4">
            {status.results?.errors && status.results.errors.length > 0 && (
              <Button variant="ghost" size="sm" onClick={onToggle}>
                {isExpanded ? 'Hide Details' : 'Show Details'}
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              disabled={status.status === 'syncing'}
            >
              <RefreshCw className={`w-4 h-4 ${status.status === 'syncing' ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </div>
      </div>
    </Card>
  );
}

export default SyncStatusMonitor;
