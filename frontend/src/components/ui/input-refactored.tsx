import * as React from "react"
import { cn } from "@/lib/utils"

/**
 * Input component refactored to use design tokens
 * Uses semantic tokens for consistent styling and theming
 */
export interface InputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          "flex h-10 w-full rounded-input border border-default bg-canvas px-component-md py-component-sm body-base text-primary ring-offset-canvas file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-secondary focus-ring disabled:cursor-not-allowed disabled:opacity-50 transition-all duration-fast",
          className
        )}
        ref={ref}
        {...props}
      />
    )
  }
)
Input.displayName = "Input"

export { Input }

/**
 * Usage Examples with Design Tokens:
 *
 * // Basic input with semantic tokens
 * <Input placeholder="Enter your name" />
 *
 * // Email input with consistent styling
 * <Input type="email" placeholder="name@example.com" />
 *
 * // Disabled input maintains token consistency
 * <Input disabled placeholder="Disabled input" />
 */