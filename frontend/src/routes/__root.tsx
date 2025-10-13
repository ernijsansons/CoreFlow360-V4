import * as React from 'react'
import { createRootRoute, Link, Outlet, useLocation } from '@tanstack/react-router'
import { EntityProvider } from '@/hooks'
import { useAuthStore, useUIStore } from '@/stores'
import { MainLayout } from '@/layouts/main-layout'
import { Analytics } from '@/lib/analytics'
import { SupportChat } from '@/components/support/SupportChat'
import { OnboardingTour } from '@/components/onboarding/OnboardingTour'

// Lazy load DevTools only in development
const TanStackRouterDevtools =
  process.env.NODE_ENV === 'production'
    ? () => null
    : React.lazy(() =>
        import('@tanstack/router-devtools').then((res) => ({
          default: res.TanStackRouterDevtools,
        }))
      )

export const Route = createRootRoute({
  component: RootComponent,
  errorComponent: ({ error, reset }) => {
    // Log detailed error for debugging
    console.error('[CoreFlow360] Router Error Boundary caught error:', error)
    console.error('[CoreFlow360] Error type:', typeof error)
    console.error('[CoreFlow360] Error constructor:', error?.constructor?.name)
    if (error instanceof Error) {
      console.error('[CoreFlow360] Error stack:', error.stack)
    }

    // Safely extract error message
    const errorMessage = error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : 'An unexpected error occurred'

    const errorDetails = error instanceof Error && error.stack
      ? error.stack
      : JSON.stringify(error, null, 2)

    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <div className="max-w-2xl w-full space-y-4">
          <div className="text-center space-y-4">
            <h1 className="text-2xl font-bold text-destructive">Something went wrong</h1>
            <p className="text-muted-foreground">{errorMessage}</p>
          </div>

          {/* Always show error details in production for debugging */}
          <details className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
            <summary className="cursor-pointer font-semibold text-sm mb-2">Error Details (Click to expand)</summary>
            <pre className="text-xs overflow-auto mt-2 whitespace-pre-wrap break-words">
              <code>{errorDetails}</code>
            </pre>
          </details>

          <div className="flex gap-2 justify-center">
            <button
              onClick={reset}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
            >
              Try again
            </button>
            <Link
              to="/landing"
              className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md hover:bg-secondary/80"
            >
              Go Home
            </Link>
          </div>
        </div>
      </div>
    )
  },
})

function RootComponent() {
  const location = useLocation()
  const { isAuthenticated, user } = useAuthStore()
  const { theme } = useUIStore()

  // Track page views
  React.useEffect(() => {
    Analytics.trackPageView(location.pathname)
  }, [location.pathname])

  // Set user ID when authenticated
  React.useEffect(() => {
    if (isAuthenticated && user) {
      Analytics.setUser(user.id, {
        email: user.email,
        created_at: user.createdAt,
      })
    }
  }, [isAuthenticated, user])

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
        <SupportChat />
        <TanStackRouterDevtools />
      </>
    )
  }

  return (
    <EntityProvider>
      <MainLayout>
        <Outlet />
      </MainLayout>
      <OnboardingTour />
      <SupportChat />
      <TanStackRouterDevtools />
    </EntityProvider>
  )
}