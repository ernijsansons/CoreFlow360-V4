import { createFileRoute } from '@tanstack/react-router'
import { CRMDashboard } from '@/modules/crm'
import { useUIStore } from '@/stores/ui-store'

export const Route = createFileRoute('/crm/')({
  component: CRMPage,
  beforeLoad: () => {
    // Set breadcrumbs
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard', href: '/' },
      { label: 'CRM' }
    ])
  },
  meta: () => [
    {
      title: 'CRM - CoreFlow360',
      description: 'Customer relationship management',
    },
  ],
})

function CRMPage() {
  return <CRMDashboard />
}