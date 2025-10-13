/**
 * BankAccountSelector Component
 * Displays and manages bank accounts for a connection
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import {
  CreditCard,
  Wallet,
  TrendingUp,
  ArrowLeft,
  Loader2,
  AlertCircle,
  DollarSign,
} from 'lucide-react';
import { apiClient } from '@/lib/api/client';

// ==================
// Types
// ==================

interface PlaidAccount {
  id: string;
  plaid_connection_id: string;
  plaid_account_id: string;
  account_name: string;
  official_name: string | null;
  mask: string | null;
  type: string;
  subtype: string | null;
  balance_current: number | null;
  balance_available: number | null;
  balance_limit: number | null;
  currency_code: string;
  sync_enabled: boolean;
  created_at: string;
  last_synced_at: string | null;
}

interface BankAccountSelectorProps {
  connectionId: string;
  onBack: () => void;
}

// ==================
// BankAccountSelector Component
// ==================

export function BankAccountSelector({ connectionId, onBack }: BankAccountSelectorProps) {
  const queryClient = useQueryClient();

  // Fetch accounts
  const { data, isLoading, error } = useQuery({
    queryKey: ['plaid-accounts', connectionId],
    queryFn: async () => {
      const response = await apiClient.get(`/api/v1/plaid/connections/${connectionId}/accounts`);
      const data = await response.json();
      return data.data.accounts as PlaidAccount[];
    },
  });

  // Toggle sync mutation
  const toggleSyncMutation = useMutation({
    mutationFn: async ({ accountId, enabled }: { accountId: string; enabled: boolean }) => {
      const response = await apiClient.put(`/api/v1/plaid/accounts/${accountId}`, {
        body: JSON.stringify({ sync_enabled: enabled }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plaid-accounts', connectionId] });
      const event = new CustomEvent('show-toast', {
        detail: {
          message: '✓ Account settings updated',
          type: 'success',
        },
      });
      window.dispatchEvent(event);
    },
    onError: (error: any) => {
      const event = new CustomEvent('show-toast', {
        detail: {
          message: `Failed to update account: ${error.message}`,
          type: 'error',
        },
      });
      window.dispatchEvent(event);
    },
  });

  const accounts = data || [];

  // Get account type icon
  const getAccountIcon = (type: string, subtype: string | null) => {
    if (type === 'credit') {
      return <CreditCard className="w-6 h-6 text-brand-primary-600" />;
    } else if (subtype === 'savings') {
      return <TrendingUp className="w-6 h-6 text-green-600" />;
    } else {
      return <Wallet className="w-6 h-6 text-blue-600" />;
    }
  };

  // Format currency
  const formatCurrency = (amount: number | null, currencyCode: string) => {
    if (amount === null) return 'N/A';
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currencyCode || 'USD',
    }).format(amount);
  };

  // Get account type label
  const getAccountTypeLabel = (type: string, subtype: string | null) => {
    if (subtype) {
      return subtype.charAt(0).toUpperCase() + subtype.slice(1);
    }
    return type.charAt(0).toUpperCase() + type.slice(1);
  };

  if (isLoading) {
    return (
      <Card className="p-12">
        <div className="flex flex-col items-center justify-center space-y-4">
          <Loader2 className="w-8 h-8 text-brand-primary-600 animate-spin" />
          <p className="text-gray-600 dark:text-gray-400">Loading accounts...</p>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="p-12">
        <div className="flex flex-col items-center justify-center space-y-4">
          <AlertCircle className="w-12 h-12 text-red-600" />
          <p className="text-red-600">Failed to load accounts</p>
          <Button onClick={onBack} variant="outline">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Go Back
          </Button>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <Button onClick={onBack} variant="outline" size="sm">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Connections
        </Button>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-6">
          <p className="text-sm text-muted-foreground mb-2">Total Accounts</p>
          <p className="text-3xl font-bold text-gray-900 dark:text-white">{accounts.length}</p>
        </Card>

        <Card className="p-6">
          <p className="text-sm text-muted-foreground mb-2">Active Syncs</p>
          <p className="text-3xl font-bold text-green-600">
            {accounts.filter((a) => a.sync_enabled).length}
          </p>
        </Card>

        <Card className="p-6">
          <p className="text-sm text-muted-foreground mb-2">Total Balance</p>
          <p className="text-3xl font-bold text-brand-primary-600">
            {formatCurrency(
              accounts.reduce((sum, a) => sum + (a.balance_current || 0), 0),
              'USD'
            )}
          </p>
        </Card>
      </div>

      {/* Accounts List */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Bank Accounts</h3>

        {accounts.map((account) => (
          <Card key={account.id} className="p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4 flex-1">
                {/* Account Icon */}
                <div className="w-12 h-12 rounded-lg bg-gray-100 dark:bg-gray-800 flex items-center justify-center">
                  {getAccountIcon(account.type, account.subtype)}
                </div>

                {/* Account Details */}
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <h4 className="text-lg font-semibold text-gray-900 dark:text-white">
                      {account.account_name}
                    </h4>
                    {account.mask && (
                      <span className="text-sm text-gray-600 dark:text-gray-400">
                        ••••{account.mask}
                      </span>
                    )}
                    <Badge
                      className={
                        account.sync_enabled
                          ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400'
                          : 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400'
                      }
                    >
                      {account.sync_enabled ? 'Syncing' : 'Paused'}
                    </Badge>
                  </div>

                  <div className="flex items-center gap-4 text-sm text-gray-600 dark:text-gray-400">
                    <span>{getAccountTypeLabel(account.type, account.subtype)}</span>
                    {account.official_name && <span>• {account.official_name}</span>}
                  </div>
                </div>

                {/* Balance Information */}
                <div className="text-right space-y-1">
                  <div className="flex items-center justify-end gap-1">
                    <DollarSign className="w-4 h-4 text-gray-400" />
                    <span className="text-lg font-bold text-gray-900 dark:text-white">
                      {formatCurrency(account.balance_current, account.currency_code)}
                    </span>
                  </div>

                  {account.balance_available !== null &&
                    account.balance_available !== account.balance_current && (
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        Available: {formatCurrency(account.balance_available, account.currency_code)}
                      </div>
                    )}

                  {account.type === 'credit' && account.balance_limit !== null && (
                    <div className="text-xs text-gray-500 dark:text-gray-400">
                      Limit: {formatCurrency(account.balance_limit, account.currency_code)}
                    </div>
                  )}
                </div>

                {/* Sync Toggle */}
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Auto-sync</span>
                  <Switch
                    checked={account.sync_enabled}
                    onCheckedChange={(enabled) =>
                      toggleSyncMutation.mutate({ accountId: account.id, enabled })
                    }
                    disabled={toggleSyncMutation.isPending}
                  />
                </div>
              </div>
            </div>

            {/* Last Synced Info */}
            {account.last_synced_at && (
              <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Last synced: {new Date(account.last_synced_at).toLocaleString()}
                </p>
              </div>
            )}
          </Card>
        ))}
      </div>

      {accounts.length === 0 && (
        <Card className="p-12">
          <div className="text-center space-y-4">
            <Wallet className="w-12 h-12 mx-auto text-gray-400" />
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                No Accounts Found
              </h3>
              <p className="text-gray-600 dark:text-gray-400">
                No accounts were found for this connection
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
