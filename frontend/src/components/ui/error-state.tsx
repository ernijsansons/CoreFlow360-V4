import * as React from 'react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import {
  AlertCircle,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Home,
  ArrowLeft
} from 'lucide-react'

export interface ErrorStateProps {
  title?: string
  description?: string
  error?: Error | string
  variant?: 'error' | 'warning' | 'destructive'
  retry?: () => void
  reset?: () => void
  goBack?: () => void
  goHome?: () => void
  className?: string
  size?: 'sm' | 'md' | 'lg'
  showDetails?: boolean
}

export function ErrorState({
  title = "Something went wrong",
  description = "An unexpected error occurred. Please try again.",
  error,
  variant = 'error',
  retry,
  reset,
  goBack,
  goHome,
  className,
  size = 'md',
  showDetails = false
}: ErrorStateProps) {
  const [detailsOpen, setDetailsOpen] = React.useState(false)

  const icons = {
    error: XCircle,
    warning: AlertTriangle,
    destructive: AlertCircle
  }

  const iconColors = {
    error: 'text-red-500',
    warning: 'text-yellow-500',
    destructive: 'text-destructive'
  }

  const sizeClasses = {
    sm: {
      container: 'py-8',
      icon: 'h-12 w-12',
      title: 'text-lg',
      description: 'text-sm'
    },
    md: {
      container: 'py-12',
      icon: 'h-16 w-16',
      title: 'text-xl',
      description: 'text-base'
    },
    lg: {
      container: 'py-16',
      icon: 'h-20 w-20',
      title: 'text-2xl',
      description: 'text-lg'
    }
  }

  const Icon = icons[variant]
  const sizes = sizeClasses[size]
  const errorMessage = typeof error === 'string' ? error : error?.message

  return (
    <div className={cn(
      "flex flex-col items-center justify-center text-center",
      sizes.container,
      className
    )}>
      <div className={cn(
        "rounded-full bg-muted p-4 mb-4",
        size === 'lg' && "p-6"
      )}>
        <Icon className={cn(
          sizes.icon,
          iconColors[variant]
        )} />
      </div>

      <h3 className={cn("font-semibold mb-2", sizes.title)}>
        {title}
      </h3>

      <p className={cn(
        "text-muted-foreground max-w-sm mb-6",
        sizes.description
      )}>
        {description}
      </p>

      {errorMessage && showDetails && (
        <div className="mb-6 w-full max-w-md">
          <button
            onClick={() => setDetailsOpen(!detailsOpen)}
            className="text-sm text-muted-foreground hover:text-foreground underline"
          >
            {detailsOpen ? 'Hide' : 'Show'} error details
          </button>
          {detailsOpen && (
            <div className="mt-2 p-3 bg-muted rounded-md text-left">
              <code className="text-xs text-muted-foreground break-all">
                {errorMessage}
              </code>
            </div>
          )}
        </div>
      )}

      <div className="flex items-center gap-3">
        {retry && (
          <Button onClick={retry} variant="default">
            <RefreshCw className="h-4 w-4 mr-2" />
            Try Again
          </Button>
        )}
        {reset && (
          <Button onClick={reset} variant="outline">
            Reset
          </Button>
        )}
        {goBack && (
          <Button onClick={goBack} variant="outline">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Go Back
          </Button>
        )}
        {goHome && (
          <Button onClick={goHome} variant="outline">
            <Home className="h-4 w-4 mr-2" />
            Go Home
          </Button>
        )}
      </div>
    </div>
  )
}

// Preset error states
export function NotFoundError(props: Partial<ErrorStateProps>) {
  return (
    <ErrorState
      title="Page not found"
      description="The page you're looking for doesn't exist."
      variant="warning"
      {...props}
    />
  )
}

export function NetworkError(props: Partial<ErrorStateProps>) {
  return (
    <ErrorState
      title="Network error"
      description="Please check your internet connection and try again."
      variant="error"
      {...props}
    />
  )
}

export function PermissionError(props: Partial<ErrorStateProps>) {
  return (
    <ErrorState
      title="Permission denied"
      description="You don't have permission to access this resource."
      variant="destructive"
      {...props}
    />
  )
}

export function ServerError(props: Partial<ErrorStateProps>) {
  return (
    <ErrorState
      title="Server error"
      description="Something went wrong on our end. Please try again later."
      variant="error"
      {...props}
    />
  )
}