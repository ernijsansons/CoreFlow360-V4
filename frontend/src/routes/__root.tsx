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

// Enhanced error description that handles all thrown value types
const describeError = (value: unknown): string => {
  if (value instanceof Error) {
    return `${value.name}: ${value.message}\n${value.stack ?? ''}`
  }
  if (typeof value === 'string') {
    return value
  }
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

export const Route = createRootRoute({
  component: RootComponent,
  errorComponent: ({ error, reset }) => {
    // Log detailed error for debugging
    console.error('[CoreFlow360] Router Error Boundary caught error:', error)
    console.error('[CoreFlow360] Error type:', typeof error)
    console.error('[CoreFlow360] Error constructor:', error?.constructor?.name)
    if (error instanceof Error) {
      console.error('[CoreFlow360] Error stack:', error.stack)
      console.error('[CoreFlow360] Error cause:', (error as any).cause)
    }

    // Use enhanced error description
    const errorDetails = describeError(error)

    // Safely extract error message for display
    const errorMessage = error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : 'An unexpected error occurred'

    // Extract additional context if available
    const errorCause = (error as any)?.cause ? describeError((error as any).cause) : null
    const errorData = (error as any)?.data ? describeError((error as any).data) : null
    const errorResponse = (error as any)?.response ? describeError((error as any).response) : null

    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <div className="max-w-2xl w-full space-y-4">
          <div className="text-center space-y-4">
            <h1 className="text-2xl font-bold text-destructive">Something went wrong</h1>
            <p className="text-muted-foreground">{errorMessage}</p>
          </div>

          {/* Always show error details in production for debugging */}
          <details className="rounded-lg border border-destructive/50 bg-destructive/10 p-4" open>
            <summary className="cursor-pointer font-semibold text-sm mb-2">Error Details (Always Expanded for Debugging)</summary>
            <pre className="text-xs overflow-auto mt-2 whitespace-pre-wrap break-words">
              <code>{errorDetails}</code>
            </pre>

            {/* Show additional error context if available */}
            {errorCause && (
              <div className="mt-4 pt-4 border-t border-destructive/30">
                <div className="font-semibold text-sm mb-2">Error Cause:</div>
                <pre className="text-xs overflow-auto whitespace-pre-wrap break-words">
                  <code>{errorCause}</code>
                </pre>
              </div>
            )}

            {errorData && (
              <div className="mt-4 pt-4 border-t border-destructive/30">
                <div className="font-semibold text-sm mb-2">Error Data:</div>
                <pre className="text-xs overflow-auto whitespace-pre-wrap break-words">
                  <code>{errorData}</code>
                </pre>
              </div>
            )}

            {errorResponse && (
              <div className="mt-4 pt-4 border-t border-destructive/30">
                <div className="font-semibold text-sm mb-2">Error Response:</div>
                <pre className="text-xs overflow-auto whitespace-pre-wrap break-words">
                  <code>{errorResponse}</code>
                </pre>
              </div>
            )}
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
        {/* Temporarily disabled SupportChat to debug rendering error */}
        {/* <SupportChat /> */}
        {/* Temporarily disabled DevTools to debug rendering error */}
        {/* <TanStackRouterDevtools /> */}
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