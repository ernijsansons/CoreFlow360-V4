/**
 * BankConnectionList Component
 * Displays connected banks with sync controls
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Building2,
  RefreshCw,
  Trash2,
  ChevronRight,
  CheckCircle,
  AlertCircle,
  Clock,
  Loader2,
} from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { formatDistanceToNow } from 'date-fns';

// ==================
// Types
// ==================

interface PlaidConnection {
  id: string;
  institution_id: string;
  institution_name: string;
  status: 'active' | 'error' | 'disconnected';
  error_code: string | null;
  error_message: string | null;
  created_at: string;
  last_sync_at: string | null;
  metadata: string | null;
}

interface BankConnectionListProps {
  onSelectConnection: (connectionId: string) => void;
}

// ==================
// BankConnectionList Component
// ==================

export function BankConnectionList({ onSelectConnection }: BankConnectionListProps) {
  const queryClient = useQueryClient();
  const [syncingConnectionId, setSyncingConnectionId] = useState<string | null>(null);

  // Fetch connections
  const { data, isLoading, error } = useQuery({
    queryKey: ['plaid-connections'],
    queryFn: async () => {
      const response = await apiClient.get('/api/v1/plaid/connections');
      const data = await response.json();
      return data.data.connections as PlaidConnection[];
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Sync connection mutation
  const syncMutation = useMutation({
    mutationFn: async (connectionId: string) => {
      setSyncingConnectionId(connectionId);
      const response = await apiClient.post(`/api/v1/plaid/connections/${connectionId}/sync`);
      return response.json();
    },
    onSuccess: (data, connectionId) => {
      queryClient.invalidateQueries({ queryKey: ['plaid-connections'] });
      queryClient.invalidateQueries({ queryKey: ['plaid-accounts', connectionId] });

      const result = data.data;
      const event = new CustomEvent('show-toast', {
        detail: {
          message: `✓ Synced: +${result.transactions_added} new, ~${result.transactions_modified} modified`,
          type: 'success',
        },
      });
      window.dispatchEvent(event);
      setSyncingConnectionId(null);
    },
    onError: (error: any) => {
      const event = new CustomEvent('show-toast', {
        detail: {
          message: `Sync failed: ${error.message}`,
          type: 'error',
        },
      });
      window.dispatchEvent(event);
      setSyncingConnectionId(null);
    },
  });

  // Disconnect mutation
  const disconnectMutation = useMutation({
    mutationFn: async (connectionId: string) => {
      const response = await apiClient.delete(`/api/v1/plaid/connections/${connectionId}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plaid-connections'] });
      const event = new CustomEvent('show-toast', {
        detail: {
          message: '✓ Bank disconnected successfully',
          type: 'success',
        },
      });
      window.dispatchEvent(event);
    },
    onError: (error: any) => {
      const event = new CustomEvent('show-toast', {
        detail: {
          message: `Failed to disconnect: ${error.message}`,
          type: 'error',
        },
      });
      window.dispatchEvent(event);
    },
  });

  const connections = data || [];

  // Parse metadata
  const parseMetadata = (metadataStr: string | null) => {
    if (!metadataStr) return null;
    try {
      return JSON.parse(metadataStr);
    } catch {
      return null;
    }
  };

  // Get status icon
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'error':
        return <AlertCircle className="w-5 h-5 text-red-600" />;
      case 'disconnected':
        return <AlertCircle className="w-5 h-5 text-gray-400" />;
      default:
        return <Clock className="w-5 h-5 text-gray-400" />;
    }
  };

  // Get status badge
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return (
          <Badge className="bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400">
            Active
          </Badge>
        );
      case 'error':
        return (
          <Badge className="bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400">
            Error
          </Badge>
        );
      case 'disconnected':
        return (
          <Badge className="bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400">
            Disconnected
          </Badge>
        );
      default:
        return null;
    }
  };

  if (isLoading) {
    return (
      <Card className="p-12">
        <div className="flex flex-col items-center justify-center space-y-4">
          <Loader2 className="w-8 h-8 text-brand-primary-600 animate-spin" />
          <p className="text-gray-600 dark:text-gray-400">Loading bank connections...</p>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="p-12">
        <div className="flex flex-col items-center justify-center space-y-4">
          <AlertCircle className="w-12 h-12 text-red-600" />
          <p className="text-red-600">Failed to load bank connections</p>
        </div>
      </Card>
    );
  }

  if (connections.length === 0) {
    return (
      <Card className="p-12">
        <div className="text-center space-y-4">
          <Building2 className="w-12 h-12 mx-auto text-gray-400" />
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              No Bank Connections
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              Connect your first bank account to start importing transactions automatically
            </p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {connections.map((connection) => {
        const metadata = parseMetadata(connection.metadata);
        const isSyncing = syncingConnectionId === connection.id;

        return (
          <Card
            key={connection.id}
            className="p-6 hover:shadow-lg transition-shadow cursor-pointer"
            onClick={() => onSelectConnection(connection.id)}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4 flex-1">
                {/* Institution Logo */}
                <div className="w-12 h-12 rounded-lg bg-gray-100 dark:bg-gray-800 flex items-center justify-center">
                  {metadata?.logo ? (
                    <img
                      src={metadata.logo}
                      alt={connection.institution_name}
                      className="w-8 h-8 object-contain"
                    />
                  ) : (
                    <Building2 className="w-6 h-6 text-gray-600 dark:text-gray-400" />
                  )}
                </div>

                {/* Connection Details */}
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                      {connection.institution_name}
                    </h3>
                    {getStatusBadge(connection.status)}
                  </div>

                  <div className="flex items-center gap-4 text-sm text-gray-600 dark:text-gray-400">
                    <div className="flex items-center gap-1">
                      {getStatusIcon(connection.status)}
                      <span>
                        {connection.status === 'active'
                          ? 'Connected'
                          : connection.status === 'error'
                            ? 'Connection Error'
                            : 'Disconnected'}
                      </span>
                    </div>

                    {connection.last_sync_at && (
                      <div className="flex items-center gap-1">
                        <Clock className="w-4 h-4" />
                        <span>
                          Last synced{' '}
                          {formatDistanceToNow(new Date(connection.last_sync_at), {
                            addSuffix: true,
                          })}
                        </span>
                      </div>
                    )}
                  </div>

                  {connection.error_message && (
                    <p className="text-sm text-red-600 dark:text-red-400 mt-1">
                      {connection.error_message}
                    </p>
                  )}
                </div>
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                {connection.status === 'active' && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => syncMutation.mutate(connection.id)}
                    disabled={isSyncing}
                  >
                    {isSyncing ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <RefreshCw className="w-4 h-4" />
                    )}
                    <span className="ml-2">{isSyncing ? 'Syncing...' : 'Sync'}</span>
                  </Button>
                )}

                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    if (confirm('Are you sure you want to disconnect this bank?')) {
                      disconnectMutation.mutate(connection.id);
                    }
                  }}
                  disabled={disconnectMutation.isPending}
                >
                  <Trash2 className="w-4 h-4 text-red-600" />
                </Button>

                <ChevronRight className="w-5 h-5 text-gray-400" />
              </div>
            </div>
          </Card>
        );
      })}
    </div>
  );
}
