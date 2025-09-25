import { createFileRoute } from '@tanstack/react-router'
import { CRMDashboard } from '@/modules/crm'
import { useEntityPermissions } from '@/hooks'

export const Route = createFileRoute('/crm/')({
  component: CRMPage,
  beforeLoad: () => {
    const { hasPermission } = useEntityPermissions()

    if (!hasPermission('crm:view')) {
      throw new Error('Insufficient permissions')
    }

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