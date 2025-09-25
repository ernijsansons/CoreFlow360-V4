import * as React from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface PasswordInputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  showStrength?: boolean
  onStrengthChange?: (strength: number) => void
}

const PasswordInput = React.forwardRef<HTMLInputElement, PasswordInputProps>(
  ({ className, showStrength = false, onStrengthChange, ...props }, ref) => {
    const [showPassword, setShowPassword] = React.useState(false)
    const [strength, setStrength] = React.useState(0)

    const calculateStrength = (password: string) => {
      let strengthScore = 0

      // Length check
      if (password.length >= 8) strengthScore++
      if (password.length >= 12) strengthScore++

      // Character variety checks
      if (/[a-z]/.test(password)) strengthScore++
      if (/[A-Z]/.test(password)) strengthScore++
      if (/[0-9]/.test(password)) strengthScore++
      if (/[^a-zA-Z0-9]/.test(password)) strengthScore++

      // Common pattern checks
      if (!/(.)\1{2,}/.test(password)) strengthScore++ // No repeated characters
      if (!/^[a-z]+$/i.test(password)) strengthScore++ // Not just letters

      const finalStrength = Math.min(Math.floor((strengthScore / 8) * 4), 4)
      setStrength(finalStrength)
      onStrengthChange?.(finalStrength)

      return finalStrength
    }

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      if (showStrength) {
        calculateStrength(e.target.value)
      }
      props.onChange?.(e)
    }

    const getStrengthColor = () => {
      switch (strength) {
        case 0:
        case 1:
          return 'bg-red-500'
        case 2:
          return 'bg-yellow-500'
        case 3:
          return 'bg-blue-500'
        case 4:
          return 'bg-green-500'
        default:
          return 'bg-gray-300'
      }
    }

    const getStrengthText = () => {
      switch (strength) {
        case 0:
          return ''
        case 1:
          return 'Weak'
        case 2:
          return 'Fair'
        case 3:
          return 'Good'
        case 4:
          return 'Strong'
        default:
          return ''
      }
    }

    return (
      <div className="space-y-2">
        <div className="relative">
          <input
            type={showPassword ? 'text' : 'password'}
            className={cn(
              'flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 pr-10 text-sm ring-offset-background',
              'file:border-0 file:bg-transparent file:text-sm file:font-medium',
              'placeholder:text-muted-foreground',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
              'disabled:cursor-not-allowed disabled:opacity-50',
              'aria-invalid:border-red-500 aria-invalid:focus-visible:ring-red-500',
              className
            )}
            ref={ref}
            onChange={handleChange}
            aria-label="Password"
            aria-describedby={showStrength ? 'password-strength' : undefined}
            {...props}
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-0 top-0 h-10 w-10 flex items-center justify-center text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
            aria-label={showPassword ? 'Hide password' : 'Show password'}
          >
            {showPassword ? (
              <EyeOff className="h-4 w-4" />
            ) : (
              <Eye className="h-4 w-4" />
            )}
          </button>
        </div>

        {showStrength && props.value && (
          <div id="password-strength" className="space-y-1">
            <div className="flex gap-1">
              {[1, 2, 3, 4].map((level) => (
                <div
                  key={level}
                  className={cn(
                    'h-1 flex-1 rounded-full transition-colors',
                    level <= strength ? getStrengthColor() : 'bg-gray-200 dark:bg-gray-700'
                  )}
                />
              ))}
            </div>
            {getStrengthText() && (
              <p className="text-xs text-muted-foreground">
                Password strength: <span className="font-medium">{getStrengthText()}</span>
              </p>
            )}
          </div>
        )}
      </div>
    )
  }
)

PasswordInput.displayName = 'PasswordInput'

export { PasswordInput }