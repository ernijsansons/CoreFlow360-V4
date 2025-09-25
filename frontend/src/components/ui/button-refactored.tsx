import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

/**
 * Button component refactored to use design tokens
 * Uses semantic tokens from design-system/tokens.css
 */
const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap focus-ring transition-all duration-fast disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-accent text-inverse hover:bg-accent-hover rounded-button shadow-button",
        destructive:
          "bg-error text-inverse hover:bg-red-700 rounded-button shadow-button",
        outline:
          "border border-default bg-canvas hover:bg-surface text-primary rounded-button",
        secondary:
          "bg-surface text-primary hover:bg-muted border border-muted rounded-button",
        ghost: "hover:bg-surface text-primary rounded-button",
        link: "text-accent underline-offset-4 hover:underline bg-transparent",
      },
      size: {
        default: "h-10 px-component-md py-component-sm text-sm font-medium",
        sm: "h-9 px-component-sm py-component-xs text-sm font-medium rounded-button",
        lg: "h-11 px-component-lg py-component-md text-base font-medium rounded-button",
        icon: "h-10 w-10 p-component-sm",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
  loading?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, loading = false, children, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp
        className={cn(buttonVariants({ variant, size }), className)}
        ref={ref}
        disabled={loading || props.disabled}
        {...props}
      >
        {loading ? (
          <>
            <svg
              className="animate-spin -ml-1 mr-2 h-4 w-4"
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
            Loading...
          </>
        ) : (
          children
        )}
      </Comp>
    )
  }
)
Button.displayName = "Button"

export { Button, buttonVariants }

/**
 * Usage Examples with Design Tokens:
 * 
 * // Primary button using semantic tokens
 * <Button variant="default">Save Changes</Button>
 * 
 * // Destructive button using error tokens
 * <Button variant="destructive">Delete Item</Button>
 * 
 * // Ghost button with semantic spacing
 * <Button variant="ghost" size="sm">Cancel</Button>
 * 
 * // Loading state
 * <Button loading>Processing...</Button>
 */