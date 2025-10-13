/**
 * Bank Connections Page
 * Manage Plaid bank connections and sync
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Plus, Info } from 'lucide-react';
import { PlaidLink } from '@/components/plaid/PlaidLink';
import { BankConnectionList } from '@/components/plaid/BankConnectionList';
import { BankAccountSelector } from '@/components/plaid/BankAccountSelector';

export const Route = createFileRoute('/finance/bank-connections')({
  component: BankConnectionsPage,
});

function BankConnectionsPage() {
  const [showPlaidLink, setShowPlaidLink] = useState(false);
  const [selectedConnectionId, setSelectedConnectionId] = useState<string | null>(null);

  // Handle successful connection
  const handleConnectionSuccess = (connectionId: string) => {
    setShowPlaidLink(false);
    setSelectedConnectionId(connectionId);
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white">
              Bank Connections
            </h1>
            <p className="text-muted-foreground mt-2">
              Connect your bank accounts for automatic transaction imports
            </p>
          </div>

          {!selectedConnectionId && (
            <Button onClick={() => setShowPlaidLink(true)} disabled={showPlaidLink}>
              <Plus className="h-4 w-4 mr-2" />
              Connect Bank
            </Button>
          )}
        </div>

        {/* Info Card */}
        <Card className="p-6 bg-brand-primary-50 dark:bg-brand-primary-900/10 border-brand-primary-200 dark:border-brand-primary-800">
          <div className="flex items-start gap-3">
            <Info className="w-5 h-5 text-brand-primary-600 dark:text-brand-primary-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-semibold text-brand-primary-900 dark:text-brand-primary-100 mb-1">
                Secure Bank Integration
              </h3>
              <p className="text-sm text-brand-primary-700 dark:text-brand-primary-300">
                Connect your bank accounts using Plaid, the industry-standard secure banking API.
                Your credentials are never stored by CoreFlow360 and all data is encrypted in
                transit and at rest. You can disconnect at any time.
              </p>
            </div>
          </div>
        </Card>

        {/* Plaid Link Modal */}
        {showPlaidLink && (
          <PlaidLink
            onSuccess={handleConnectionSuccess}
            onExit={() => setShowPlaidLink(false)}
          />
        )}

        {/* Account Details View */}
        {selectedConnectionId && (
          <BankAccountSelector
            connectionId={selectedConnectionId}
            onBack={() => setSelectedConnectionId(null)}
          />
        )}

        {/* Connection List View */}
        {!showPlaidLink && !selectedConnectionId && (
          <BankConnectionList onSelectConnection={(id) => setSelectedConnectionId(id)} />
        )}

        {/* Benefits Section */}
        {!showPlaidLink && !selectedConnectionId && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-6">
            <Card className="p-6">
              <div className="text-center space-y-2">
                <div className="w-12 h-12 rounded-full bg-green-100 dark:bg-green-900/20 mx-auto flex items-center justify-center">
                  <svg
                    className="w-6 h-6 text-green-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M5 13l4 4L19 7"
                    />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900 dark:text-white">Automatic Sync</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Transactions automatically imported daily - no more manual CSV uploads
                </p>
              </div>
            </Card>

            <Card className="p-6">
              <div className="text-center space-y-2">
                <div className="w-12 h-12 rounded-full bg-blue-100 dark:bg-blue-900/20 mx-auto flex items-center justify-center">
                  <svg
                    className="w-6 h-6 text-blue-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                    />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900 dark:text-white">Bank-Level Security</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  256-bit encryption and read-only access - your credentials are never stored
                </p>
              </div>
            </Card>

            <Card className="p-6">
              <div className="text-center space-y-2">
                <div className="w-12 h-12 rounded-full bg-brand-primary-100 dark:bg-brand-primary-900/20 mx-auto flex items-center justify-center">
                  <svg
                    className="w-6 h-6 text-brand-primary-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M13 10V3L4 14h7v7l9-11h-7z"
                    />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900 dark:text-white">Real-Time Updates</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Get notified instantly when new transactions are available
                </p>
              </div>
            </Card>
          </div>
        )}
      </div>
    </MainLayout>
  );
}
