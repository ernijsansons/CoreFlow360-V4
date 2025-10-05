import * as React from 'react'
import { createRootRoute, Link, Outlet } from '@tanstack/react-router'
import { TanStackRouterDevtools } from '@tanstack/router-devtools'
import { EntityProvider } from '@/hooks'
import { useAuthStore, useUIStore } from '@/stores'
import { MainLayout } from '@/layouts/main-layout'

export const Route = createRootRoute({
  component: RootComponent,
  errorComponent: ({ error, reset }) => (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center space-y-4">
        <h1 className="text-2xl font-bold text-destructive">Something went wrong</h1>
        <p className="text-muted-foreground">{error.message}</p>
        <div className="space-x-2">
          <button
            onClick={reset}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            Try again
          </button>
          <Link
            to="/login"
            className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md hover:bg-secondary/80"
          >
            Go to login
          </Link>
        </div>
      </div>
    </div>
  ),
})

function RootComponent() {
  const { isAuthenticated } = useAuthStore()
  const { theme } = useUIStore()

  // Apply theme to document
  React.useEffect(() => {
    const root = window.document.documentElement
    root.classList.remove('light', 'dark')

    if (theme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
      root.classList.add(systemTheme)
    } else {
      root.classList.add(theme)
    }
  }, [theme])

  if (!isAuthenticated) {
    return (
      <>
        <Outlet />
        <TanStackRouterDevtools />
      </>
    )
  }

  return (
    <EntityProvider>
      <MainLayout>
        <Outlet />
      </MainLayout>
      <TanStackRouterDevtools />
    </EntityProvider>
  )
}