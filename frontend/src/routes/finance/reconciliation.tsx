/**
 * Account Reconciliation Page
 * Complete reconciliation workflow with statement upload and matching
 */

import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { RouteErrorFallback } from '@/components/route-error-fallback';
import { ReconciliationWorkflow } from '@/pages/finance/ReconciliationWorkflow';

export const Route = createFileRoute('/finance/reconciliation')({
  component: ReconciliationPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function ReconciliationPage() {
  return (
    <MainLayout>
      <ReconciliationWorkflow />
    </MainLayout>
  );
}
