import React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

/**
 * Badge component refactored to use design tokens
 * Uses semantic tokens for consistent status indicators and labels
 */
const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-component-sm py-component-xs caption font-semibold transition-all duration-fast focus-ring',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-accent text-inverse hover:bg-accent-hover',
        secondary: 'border-transparent bg-surface text-primary hover:bg-muted',
        destructive: 'border-transparent bg-error text-inverse hover:bg-red-700',
        outline: 'text-primary border-default bg-canvas hover:bg-surface',
        success: 'border-transparent bg-success-muted text-success hover:opacity-80',
        warning: 'border-transparent bg-warning-muted text-warning hover:opacity-80',
        info: 'border-transparent bg-info-muted text-info hover:opacity-80',
      },
      size: {
        default: 'px-component-sm py-component-xs caption',
        sm: 'px-component-xs py-component-xs text-xs',
        lg: 'px-component-md py-component-sm body-small',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {
  children: React.ReactNode
}

const Badge = React.forwardRef<HTMLDivElement, BadgeProps>(
  ({ className, variant, size, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(badgeVariants({ variant, size }), className)}
        {...props}
      />
    )
  }
)
Badge.displayName = 'Badge'

export { Badge, badgeVariants }
export type { BadgeProps }

/**
 * Usage Examples with Design Tokens:
 *
 * // Status badges using semantic state tokens
 * <Badge variant="success">Active</Badge>
 * <Badge variant="warning">Pending</Badge>
 * <Badge variant="error">Failed</Badge>
 *
 * // Size variations with consistent spacing
 * <Badge size="sm">Small</Badge>
 * <Badge size="lg">Large Badge</Badge>
 *
 * // Outline variant using border tokens
 * <Badge variant="outline">Neutral</Badge>
 */