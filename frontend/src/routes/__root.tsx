import * as React from 'react'
import { createRootRoute, Link, Outlet } from 'react-router-dom'
import { TanStackRouterDevtools } from '@tanstack/router-devtools'
import { EntityProvider } from '@/hooks'
import { useAuthStore, useUIStore } from '@/stores'
import { MainLayout } from '@/layouts/main-layout'
import { Button } from '@/components/ui/button'

export const Route = createRootRoute({
  component: RootComponent,
  errorComponent: ({ error, reset }) => (
    <main className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center space-y-4">
        <h1 className="text-2xl font-bold text-destructive">Something went wrong</h1>
        <p className="text-muted-foreground">{error.message}</p>
        <div className="flex gap-2 justify-center">
          <Button onClick={reset} size="lg" className="min-w-[88px] min-h-[44px]">
            Try again
          </Button>
          <Button asChild variant="secondary" size="lg" className="min-w-[88px] min-h-[44px]">
            <Link to="/login">Go to login</Link>
          </Button>
        </div>
      </div>
    </main>
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
        <main>
          <Outlet />
        </main>
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