import { useRouteError, useNavigate } from 'react-router-dom'
import { AlertTriangle, Home, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'

export function RouteErrorBoundary() {
  const error = useRouteError()
  const navigate = useNavigate()
  const isDevelopment = import.meta.env.DEV

  const handleReset = () => {
    window.location.reload()
  }

  const handleGoHome = () => {
    navigate({ to: '/' })
  }

  const getErrorMessage = () => {
    if (error instanceof Error) {
      return error.message
    }
    if (typeof error === 'string') {
      return error
    }
    return 'An unexpected error occurred'
  }

  const getErrorStatus = () => {
    if (error && typeof error === 'object' && 'status' in error) {
      return error.status
    }
    return null
  }

  const status = getErrorStatus()
  const is404 = status === 404

  if (is404) {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <div className="max-w-md w-full text-center space-y-4">
          <div className="text-6xl font-bold text-muted-foreground" aria-hidden="true">404</div>
          <h1 className="text-2xl font-semibold">Page Not Found</h1>
          <p className="text-muted-foreground">
            The page you're looking for doesn't exist or has been moved.
          </p>
          <Button onClick={handleGoHome} className="mt-8 min-h-11 min-w-[110px]">
            <Home className="mr-2 h-4 w-4" aria-hidden="true" />
            Go Home
          </Button>
        </div>
      </main>
    )
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <div className="max-w-2xl w-full space-y-4">
        <h1 className="text-2xl font-bold text-destructive mb-4">Something went wrong</h1>

        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
          <AlertTitle>Route Error</AlertTitle>
          <AlertDescription>{getErrorMessage()}</AlertDescription>
        </Alert>

        {isDevelopment && error instanceof Error && (
          <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
            <h2 className="font-semibold text-sm mb-2">Error Stack (Development Only)</h2>
            <pre className="text-xs overflow-auto">
              <code>{error.stack}</code>
            </pre>
          </div>
        )}

        <div className="flex gap-2">
          <Button onClick={handleReset} variant="default" className="min-h-11 min-w-[110px]">
            <RefreshCw className="mr-2 h-4 w-4" aria-hidden="true" />
            Try Again
          </Button>
          <Button onClick={handleGoHome} variant="outline" className="min-h-11 min-w-[110px]">
            <Home className="mr-2 h-4 w-4" aria-hidden="true" />
            Go Home
          </Button>
        </div>
      </div>
    </main>
  )
}