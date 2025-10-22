/**
 * Financial Reports Dashboard
 * Trial Balance, Income Statement, Balance Sheet, Cash Flow
 */

import { createFileRoute } from '@tanstack/react-router';
import { lazy, Suspense } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { RouteErrorFallback } from '@/components/route-error-fallback';
import { RouteLoading } from '@/components/ui/route-loading';

// Lazy load the heavy FinancialReports component
const FinancialReports = lazy(() =>
  import('@/pages/finance/FinancialReports').then((module) => ({
    default: module.FinancialReports,
  }))
);

export const Route = createFileRoute('/finance/reports')({
  component: FinancialReportsPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function FinancialReportsPage() {
  return (
    <MainLayout>
      <Suspense fallback={<RouteLoading />}>
        <FinancialReports />
      </Suspense>
    </MainLayout>
  );
}
