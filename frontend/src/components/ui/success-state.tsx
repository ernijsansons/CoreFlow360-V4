import * as React from 'react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import {
  CheckCircle,
  CheckCircle2,
  PartyPopper,
  Trophy,
  ArrowRight,
  Home
} from 'lucide-react'

export interface SuccessStateProps {
  title: string
  description?: string
  variant?: 'success' | 'celebration' | 'achievement'
  action?: {
    label: string
    onClick: () => void
  }
  secondaryAction?: {
    label: string
    onClick: () => void
  }
  className?: string
  size?: 'sm' | 'md' | 'lg'
  autoHide?: boolean
  autoHideDelay?: number
  onHide?: () => void
}

export function SuccessState({
  title,
  description,
  variant = 'success',
  action,
  secondaryAction,
  className,
  size = 'md',
  autoHide = false,
  autoHideDelay = 3000,
  onHide
}: SuccessStateProps) {
  const icons = {
    success: CheckCircle,
    celebration: PartyPopper,
    achievement: Trophy
  }

  const iconColors = {
    success: 'text-green-500',
    celebration: 'text-yellow-500',
    achievement: 'text-purple-500'
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

  React.useEffect(() => {
    if (autoHide && onHide) {
      const timer = setTimeout(onHide, autoHideDelay)
      return () => clearTimeout(timer)
    }
  }, [autoHide, autoHideDelay, onHide])

  return (
    <div className={cn(
      "flex flex-col items-center justify-center text-center",
      sizes.container,
      className
    )}>
      <div className={cn(
        "rounded-full bg-green-100 dark:bg-green-900/20 p-4 mb-4",
        size === 'lg' && "p-6",
        variant === 'celebration' && "bg-yellow-100 dark:bg-yellow-900/20",
        variant === 'achievement' && "bg-purple-100 dark:bg-purple-900/20"
      )}>
        <Icon className={cn(
          sizes.icon,
          iconColors[variant],
          variant === 'celebration' && "animate-bounce"
        )} />
      </div>

      <h3 className={cn("font-semibold mb-2", sizes.title)}>
        {title}
      </h3>

      {description && (
        <p className={cn(
          "text-muted-foreground max-w-sm mb-6",
          sizes.description
        )}>
          {description}
        </p>
      )}

      {(action || secondaryAction) && (
        <div className="flex items-center gap-3">
          {action && (
            <Button onClick={action.onClick}>
              {action.label}
              <ArrowRight className="h-4 w-4 ml-2" />
            </Button>
          )}
          {secondaryAction && (
            <Button onClick={secondaryAction.onClick} variant="outline">
              {secondaryAction.label}
            </Button>
          )}
        </div>
      )}
    </div>
  )
}

// Preset success states
export function FormSubmitSuccess(props: Partial<SuccessStateProps>) {
  return (
    <SuccessState
      title="Successfully submitted!"
      description="Your form has been submitted successfully."
      variant="success"
      {...props}
    />
  )
}

export function PaymentSuccess(props: Partial<SuccessStateProps>) {
  return (
    <SuccessState
      title="Payment successful!"
      description="Your payment has been processed successfully."
      variant="success"
      icon={CheckCircle2}
      {...props}
    />
  )
}

export function AccountCreatedSuccess(props: Partial<SuccessStateProps>) {
  return (
    <SuccessState
      title="Welcome aboard!"
      description="Your account has been created successfully."
      variant="celebration"
      {...props}
    />
  )
}

export function AchievementUnlocked(props: Partial<SuccessStateProps>) {
  return (
    <SuccessState
      title="Achievement unlocked!"
      description="Congratulations on your achievement!"
      variant="achievement"
      {...props}
    />
  )
}