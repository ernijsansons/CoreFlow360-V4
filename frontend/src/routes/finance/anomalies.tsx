/**
 * Anomaly Detection Page
 * Fraud detection and suspicious transaction monitoring
 */

import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { RouteErrorFallback } from '@/components/route-error-fallback';
import { AnomaliesMonitor } from '@/pages/finance/AnomaliesMonitor';

export const Route = createFileRoute('/finance/anomalies')({
  component: AnomaliesPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function AnomaliesPage() {
  return (
    <MainLayout>
      <AnomaliesMonitor />
    </MainLayout>
  );
}
