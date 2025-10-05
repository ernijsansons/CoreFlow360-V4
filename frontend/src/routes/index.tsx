import { createFileRoute } from '@tanstack/react-router'
import { Dashboard } from '@/modules/dashboard'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/')({
  component: Dashboard,
  beforeLoad: () => {
    // Set breadcrumbs
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard' }
    ])
  },
  meta: () => [
    {
      title: 'Dashboard - CoreFlow360',
      description: 'Your business command center',
    },
  ],
})