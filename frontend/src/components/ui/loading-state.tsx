import * as React from 'react'
import { cn } from '@/lib/utils'
import { Loader2 } from 'lucide-react'

export interface LoadingSpinnerProps {
  className?: string
  size?: 'sm' | 'md' | 'lg' | 'xl'
  color?: 'primary' | 'secondary' | 'muted'
  label?: string
}

export function LoadingSpinner({
  className,
  size = 'md',
  color = 'primary',
  label
}: LoadingSpinnerProps) {
  const sizeClasses = {
    sm: 'h-4 w-4',
    md: 'h-6 w-6',
    lg: 'h-8 w-8',
    xl: 'h-12 w-12'
  }

  const colorClasses = {
    primary: 'text-primary',
    secondary: 'text-secondary',
    muted: 'text-muted-foreground'
  }

  return (
    <div className={cn("flex flex-col items-center justify-center gap-2", className)}>
      <Loader2 className={cn(
        "animate-spin",
        sizeClasses[size],
        colorClasses[color]
      )} />
      {label && (
        <p className="text-sm text-muted-foreground">{label}</p>
      )}
    </div>
  )
}

export interface LoadingStateProps {
  className?: string
  title?: string
  description?: string
  size?: 'sm' | 'md' | 'lg'
}

export function LoadingState({
  className,
  title = "Loading...",
  description,
  size = 'md'
}: LoadingStateProps) {
  const sizeClasses = {
    sm: {
      container: 'py-8',
      title: 'text-lg',
      description: 'text-sm'
    },
    md: {
      container: 'py-12',
      title: 'text-xl',
      description: 'text-base'
    },
    lg: {
      container: 'py-16',
      title: 'text-2xl',
      description: 'text-lg'
    }
  }

  const sizes = sizeClasses[size]

  return (
    <div className={cn(
      "flex flex-col items-center justify-center text-center",
      sizes.container,
      className
    )}>
      <LoadingSpinner size={size === 'sm' ? 'md' : size === 'md' ? 'lg' : 'xl'} />
      <h3 className={cn("font-semibold mt-4", sizes.title)}>
        {title}
      </h3>
      {description && (
        <p className={cn(
          "text-muted-foreground mt-2 max-w-sm",
          sizes.description
        )}>
          {description}
        </p>
      )}
    </div>
  )
}

export interface LoadingOverlayProps {
  visible?: boolean
  className?: string
  label?: string
  fullScreen?: boolean
}

export function LoadingOverlay({
  visible = true,
  className,
  label,
  fullScreen = false
}: LoadingOverlayProps) {
  if (!visible) return null

  return (
    <div className={cn(
      "absolute inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm",
      fullScreen && "fixed",
      className
    )}>
      <LoadingSpinner size="lg" label={label} />
    </div>
  )
}

export interface SkeletonProps {
  className?: string
  variant?: 'text' | 'circular' | 'rectangular'
  width?: string | number
  height?: string | number
  animation?: 'pulse' | 'wave' | 'none'
}

export function Skeleton({
  className,
  variant = 'rectangular',
  width,
  height,
  animation = 'pulse'
}: SkeletonProps) {
  const animationClasses = {
    pulse: 'animate-pulse',
    wave: 'animate-shimmer',
    none: ''
  }

  const variantClasses = {
    text: 'rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-md'
  }

  return (
    <div
      className={cn(
        "bg-muted",
        animationClasses[animation],
        variantClasses[variant],
        className
      )}
      style={{
        width: width || '100%',
        height: height || (variant === 'text' ? '1em' : '100%')
      }}
    />
  )
}