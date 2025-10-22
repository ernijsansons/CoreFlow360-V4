/**
 * Bank Transaction Matching Page
 * AI-powered transaction reconciliation
 */

import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { TransactionMatching } from '@/pages/banking/TransactionMatching';
import { RouteErrorFallback } from '@/components/route-error-fallback';

export const Route = createFileRoute('/finance/banking')({
  component: BankingPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function BankingPage() {
  return (
    <MainLayout>
      <TransactionMatching />
    </MainLayout>
  );
}
