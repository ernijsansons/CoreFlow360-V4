/**
 * CRM Migration Wizard
 * Import data from external CRM systems
 */

import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { RouteErrorFallback } from '@/components/route-error-fallback';
import { MigrationWizard } from '@/pages/crm/MigrationWizard';

export const Route = createFileRoute('/crm/migration')({
  component: MigrationPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function MigrationPage() {
  return (
    <MainLayout>
      <MigrationWizard />
    </MainLayout>
  );
}
