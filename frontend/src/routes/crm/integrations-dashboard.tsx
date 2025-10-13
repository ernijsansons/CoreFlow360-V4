import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/crm/integrations-dashboard')({
  component: RouteComponent,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
})

function RouteComponent() {
  return <div>Hello "/crm/integrations-dashboard"!</div>
}
