import { useRouteError, useNavigate } from '@tanstack/react-router'
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
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="max-w-md w-full text-center space-y-4">
          <div className="text-6xl font-bold text-muted-foreground">404</div>
          <h1 className="text-2xl font-semibold">Page Not Found</h1>
          <p className="text-muted-foreground">
            The page you're looking for doesn't exist or has been moved.
          </p>
          <Button onClick={handleGoHome} className="mt-8">
            <Home className="mr-2 h-4 w-4" />
            Go Home
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="max-w-2xl w-full space-y-4">
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Route Error</AlertTitle>
          <AlertDescription>{getErrorMessage()}</AlertDescription>
        </Alert>

        {isDevelopment && error instanceof Error && (
          <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
            <h3 className="font-semibold text-sm mb-2">Error Stack (Development Only)</h3>
            <pre className="text-xs overflow-auto">
              <code>{error.stack}</code>
            </pre>
          </div>
        )}

        <div className="flex gap-2">
          <Button onClick={handleReset} variant="default">
            <RefreshCw className="mr-2 h-4 w-4" />
            Try Again
          </Button>
          <Button onClick={handleGoHome} variant="outline">
            <Home className="mr-2 h-4 w-4" />
            Go Home
          </Button>
        </div>
      </div>
    </div>
  )
}