/**
 * Document Processing Page
 * Upload and process documents with OCR
 */

import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { RouteErrorFallback } from '@/components/route-error-fallback';
import { DocumentUpload } from '@/pages/documents/DocumentUpload';

export const Route = createFileRoute('/finance/documents')({
  component: DocumentsPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function DocumentsPage() {
  return (
    <MainLayout>
      <DocumentUpload />
    </MainLayout>
  );
}
