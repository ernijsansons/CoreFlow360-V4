import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-primary text-primary-foreground hover:bg-primary/80",
        secondary:
          "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        destructive:
          "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80",
        outline: "text-foreground",
        // CoreFlow360 Premium Brand Colors
        success:
          "border-transparent bg-success-500 text-white hover:bg-success-600 shadow-sm",
        warning:
          "border-transparent bg-warning-500 text-white hover:bg-warning-600 shadow-sm",
        error:
          "border-transparent bg-error-500 text-white hover:bg-error-600 shadow-sm",
        info:
          "border-transparent bg-info-500 text-white hover:bg-info-600 shadow-sm",
        // Brand variants
        brand:
          "border-transparent bg-brand-primary-600 text-white hover:bg-brand-primary-700 shadow-primary-sm",
        accent:
          "border-transparent bg-brand-accent-600 text-white hover:bg-brand-accent-700 shadow-sm",
        teal:
          "border-transparent bg-brand-teal-600 text-white hover:bg-brand-teal-700 shadow-sm",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export { Badge, badgeVariants }
