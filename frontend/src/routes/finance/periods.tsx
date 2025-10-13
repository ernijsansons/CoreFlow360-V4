/**
 * Accounting Periods Management Page
 * Open, close, and lock accounting periods
 */

import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { RouteErrorFallback } from '@/components/route-error-fallback';
import { PeriodsManagement } from '@/pages/finance/PeriodsManagement';

export const Route = createFileRoute('/finance/periods')({
  component: PeriodsPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function PeriodsPage() {
  return (
    <MainLayout>
      <PeriodsManagement />
    </MainLayout>
  );
}
