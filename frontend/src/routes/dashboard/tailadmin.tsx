import { createFileRoute, redirect } from '@tanstack/react-router';
import { useAuthStore } from '@/stores/authStore';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { Dashboard } from '@/pages/Dashboard';

/**
 * TailAdmin dashboard route
 * Protected route that renders the TailAdmin-styled dashboard
 */
export const Route = createFileRoute('/dashboard/tailadmin')({
  component: TailAdminDashboard,
  beforeLoad: ({ location }) => {
    const { isAuthenticated } = useAuthStore.getState();

    if (!isAuthenticated) {
      throw redirect({
        to: '/login',
        search: { redirect: location.href ?? '/dashboard/tailadmin' },
      });
    }
  },
  meta: () => [
    {
      title: 'TailAdmin Dashboard - CoreFlow360',
      description: 'TailAdmin-styled dashboard with CRM/ERP features',
    },
  ],
});

function TailAdminDashboard() {
  return (
    <DashboardLayout>
      <Dashboard />
    </DashboardLayout>
  );
}
