import { AlertTriangle, Home, RefreshCw } from 'lucide-react'
import { Link } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'

interface RouteErrorFallbackProps {
  error: Error | unknown
  reset?: () => void
}

export function RouteErrorFallback({ error, reset }: RouteErrorFallbackProps) {
  const errorMessage = error instanceof Error ? error.message : 'An unexpected error occurred'
  const isDevelopment = import.meta.env.DEV

  return (
    <div className="min-h-[400px] flex items-center justify-center p-6">
      <div className="max-w-md w-full space-y-4">
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Page Error</AlertTitle>
          <AlertDescription>
            This page encountered an error and cannot be displayed.
          </AlertDescription>
        </Alert>

        {isDevelopment && error && (
          <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
            <h3 className="font-semibold text-sm mb-2">Error Details (Development Only)</h3>
            <pre className="text-xs overflow-auto whitespace-pre-wrap">
              <code>{errorMessage}</code>
            </pre>
          </div>
        )}

        <div className="flex gap-2">
          {reset && (
            <Button onClick={reset} variant="default" className="flex-1">
              <RefreshCw className="mr-2 h-4 w-4" />
              Try Again
            </Button>
          )}
          <Link to="/dashboard" className="flex-1">
            <Button variant="outline" className="w-full">
              <Home className="mr-2 h-4 w-4" />
              Go Home
            </Button>
          </Link>
        </div>
      </div>
    </div>
  )
}
