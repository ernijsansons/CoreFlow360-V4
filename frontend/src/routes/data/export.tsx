/**
 * Data Export Manager
 * Export business data to various formats
 */

import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { RouteErrorFallback } from '@/components/route-error-fallback';
import { ExportManager } from '@/pages/data/ExportManager';

export const Route = createFileRoute('/data/export')({
  component: ExportPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function ExportPage() {
  return (
    <MainLayout>
      <ExportManager />
    </MainLayout>
  );
}
