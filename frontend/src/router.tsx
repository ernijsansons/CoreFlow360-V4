/**
 * React Router v6 Configuration
 * Traditional BrowserRouter pattern for production compatibility
 */

import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Dashboard } from '@/modules/dashboard';
import { EntityProvider } from '@/hooks';
import { useAuthStore, useUIStore } from '@/stores';
import { MainLayout } from '@/layouts/main-layout';
import { Button } from '@/components/ui/button';

// Root layout component with theme management
function RootLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore();
  const { theme } = useUIStore();

  // Apply theme to document
  React.useEffect(() => {
    const root = window.document.documentElement;
    root.classList.remove('light', 'dark');

    if (theme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      root.classList.add(systemTheme);
    } else {
      root.classList.add(theme);
    }
  }, [theme]);

  if (!isAuthenticated) {
    return <main>{children}</main>;
  }

  return (
    <EntityProvider>
      <MainLayout>{children}</MainLayout>
    </EntityProvider>
  );
}

// Error boundary component
function ErrorBoundaryFallback() {
  return (
    <main className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center space-y-4">
        <h1 className="text-2xl font-bold text-destructive">Something went wrong</h1>
        <p className="text-muted-foreground">An error occurred while loading this page.</p>
        <div className="flex gap-2 justify-center">
          <Button
            onClick={() => window.location.reload()}
            size="lg"
            className="min-w-[88px] min-h-[44px]"
          >
            Try again
          </Button>
          <Button
            onClick={() => window.location.href = '/login'}
            variant="secondary"
            size="lg"
            className="min-w-[88px] min-h-[44px]"
          >
            Go to login
          </Button>
        </div>
      </div>
    </main>
  );
}

// Login page placeholder
function LoginPage() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <h1 className="text-2xl">Login Page (placeholder)</h1>
    </div>
  );
}

// Traditional component-based router - compatible with production builds
export function AppRouter() {
  return (
    <BrowserRouter>
      <RootLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </RootLayout>
    </BrowserRouter>
  );
}
