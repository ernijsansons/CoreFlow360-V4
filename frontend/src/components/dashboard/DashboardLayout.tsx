import React, { useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { useDashboardStore } from '@/stores/dashboardStore';
import { useIsDesktop } from '@/hooks/useMediaQuery';

interface DashboardLayoutProps {
  children?: React.ReactNode;
}

/**
 * Main dashboard layout wrapper with sidebar and header
 * Handles responsive sidebar behavior
 */
export const DashboardLayout: React.FC<DashboardLayoutProps> = ({
  children,
}) => {
  const { sidebarOpen, setSidebarOpen } = useDashboardStore();
  const isDesktop = useIsDesktop();

  // Auto-close sidebar on mobile
  useEffect(() => {
    if (!isDesktop && sidebarOpen) {
      setSidebarOpen(false);
    }
  }, [isDesktop, sidebarOpen, setSidebarOpen]);

  return (
    <div className="dark:bg-boxdark-2 dark:text-bodydark">
      {/* Toast notifications */}
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 3000,
          style: {
            background: '#363636',
            color: '#fff',
          },
          success: {
            style: {
              background: '#10B981',
            },
          },
          error: {
            style: {
              background: '#DC3545',
            },
          },
        }}
      />

      {/* Page Wrapper */}
      <div className="flex h-screen overflow-hidden">
        {/* Sidebar */}
        <Sidebar />

        {/* Content Area */}
        <div className="relative flex flex-1 flex-col overflow-y-auto overflow-x-hidden">
          {/* Header */}
          <Header />

          {/* Main Content */}
          <main>
            <div className="mx-auto max-w-screen-2xl p-4 md:p-6 2xl:p-10">
              {children || <Outlet />}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
};
