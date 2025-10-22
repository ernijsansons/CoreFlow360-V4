/**
 * PlaidLink Component
 * Handles OAuth bank connection flow using Plaid Link
 */

import { useState, useCallback, useEffect } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Building2, AlertCircle, Loader2 } from 'lucide-react';
import { apiClient } from '@/lib/api/client';

// ==================
// Types
// ==================

interface PlaidLinkProps {
  onSuccess: (connectionId: string) => void;
  onExit?: () => void;
}

interface LinkTokenResponse {
  link_token: string;
  expiration: string;
}

// ==================
// PlaidLink Component
// ==================

export function PlaidLink({ onSuccess, onExit }: PlaidLinkProps) {
  const [linkToken, setLinkToken] = useState<string | null>(null);
  const [isPlaidReady, setIsPlaidReady] = useState(false);

  // Create link token
  const createLinkTokenMutation = useMutation({
    mutationFn: async () => {
      const response = await apiClient.post('/api/v1/plaid/link-token', {
        body: JSON.stringify({
          redirect_uri: window.location.origin + '/finance/bank-connections',
        }),
      });
      const data = await response.json();
      return data.data as LinkTokenResponse;
    },
    onSuccess: (data) => {
      setLinkToken(data.link_token);
    },
    onError: (error: any) => {
      const event = new CustomEvent('show-toast', {
        detail: {
          message: `Failed to initialize Plaid: ${error.message}`,
          type: 'error',
        },
      });
      window.dispatchEvent(event);
    },
  });

  // Exchange public token for connection
  const exchangeTokenMutation = useMutation({
    mutationFn: async (publicToken: string) => {
      const response = await apiClient.post('/api/v1/plaid/connections', {
        body: JSON.stringify({ public_token: publicToken }),
      });
      const data = await response.json();
      return data.data.connection_id as string;
    },
    onSuccess: (connectionId) => {
      const event = new CustomEvent('show-toast', {
        detail: {
          message: '✓ Bank connected successfully',
          type: 'success',
        },
      });
      window.dispatchEvent(event);
      onSuccess(connectionId);
    },
    onError: (error: any) => {
      const event = new CustomEvent('show-toast', {
        detail: {
          message: `Failed to connect bank: ${error.message}`,
          type: 'error',
        },
      });
      window.dispatchEvent(event);
    },
  });

  // Load Plaid Link script
  useEffect(() => {
    const script = document.createElement('script');
    script.src = 'https://cdn.plaid.com/link/v2/stable/link-initialize.js';
    script.async = true;
    script.onload = () => setIsPlaidReady(true);
    document.body.appendChild(script);

    return () => {
      document.body.removeChild(script);
    };
  }, []);

  // Initialize Plaid Link
  const openPlaidLink = useCallback(() => {
    if (!linkToken || !isPlaidReady || !(window as any).Plaid) {
      return;
    }

    const handler = (window as any).Plaid.create({
      token: linkToken,
      onSuccess: (publicToken: string, metadata: any) => {
        console.log('Plaid Link success:', metadata);
        exchangeTokenMutation.mutate(publicToken);
      },
      onExit: (err: any, metadata: any) => {
        console.log('Plaid Link exit:', err, metadata);
        if (onExit) onExit();
      },
      onEvent: (eventName: string, metadata: any) => {
        console.log('Plaid Link event:', eventName, metadata);
      },
    });

    handler.open();
  }, [linkToken, isPlaidReady, exchangeTokenMutation, onExit]);

  // Auto-open when link token is ready
  useEffect(() => {
    if (linkToken && isPlaidReady) {
      openPlaidLink();
    }
  }, [linkToken, isPlaidReady, openPlaidLink]);

  return (
    <Card className="p-8">
      <div className="text-center space-y-4">
        <div className="flex justify-center">
          {createLinkTokenMutation.isPending || exchangeTokenMutation.isPending ? (
            <Loader2 className="w-12 h-12 text-brand-primary-600 animate-spin" />
          ) : createLinkTokenMutation.isError ? (
            <AlertCircle className="w-12 h-12 text-red-600" />
          ) : (
            <Building2 className="w-12 h-12 text-brand-primary-600" />
          )}
        </div>

        <div>
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
            Connect Your Bank
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            Securely connect your bank account for automatic transaction imports
          </p>
        </div>

        {createLinkTokenMutation.isError && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
            <p className="text-sm text-red-800 dark:text-red-200">
              {createLinkTokenMutation.error?.message || 'Failed to initialize bank connection'}
            </p>
          </div>
        )}

        <div className="flex justify-center gap-3">
          {!linkToken && !createLinkTokenMutation.isPending && (
            <Button
              onClick={() => createLinkTokenMutation.mutate()}
              disabled={createLinkTokenMutation.isPending}
              size="lg"
            >
              {createLinkTokenMutation.isPending ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Initializing...
                </>
              ) : (
                'Connect Bank Account'
              )}
            </Button>
          )}

          {linkToken && (
            <Button onClick={openPlaidLink} size="lg" disabled={!isPlaidReady}>
              {isPlaidReady ? 'Open Bank Selection' : 'Loading...'}
            </Button>
          )}
        </div>

        <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
          <p className="text-xs text-gray-500 dark:text-gray-400">
            🔒 Your credentials are encrypted and never stored by CoreFlow360
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            Powered by Plaid - Bank-level security
          </p>
        </div>
      </div>
    </Card>
  );
}
