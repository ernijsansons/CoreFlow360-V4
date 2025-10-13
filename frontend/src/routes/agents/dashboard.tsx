/**
 * AI Agents Dashboard
 * Monitor and manage autonomous AI agents
 */

import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { RouteErrorFallback } from '@/components/route-error-fallback';
import { AgentsDashboard } from '@/pages/agents/AgentsDashboard';

export const Route = createFileRoute('/agents/dashboard')({
  component: AgentsDashboardPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function AgentsDashboardPage() {
  return (
    <MainLayout>
      <AgentsDashboard />
    </MainLayout>
  );
}
