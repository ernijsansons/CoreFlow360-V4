import { createFileRoute, redirect } from '@tanstack/react-router'
import { Dashboard } from '@/modules/dashboard'
import { useUIStore, useAuthStore } from '@/stores'

export const Route = createFileRoute('/')({
  component: Dashboard,
  beforeLoad: () => {
    // Check authentication
    const { isAuthenticated } = useAuthStore.getState()

    if (!isAuthenticated) {
      throw redirect({
        to: '/login',
      })
    }

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