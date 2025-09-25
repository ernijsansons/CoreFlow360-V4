import * as React from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import * as z from 'zod'
import {
  Lock,
  Eye,
  EyeOff,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Info
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'
import { cn } from '@/lib/utils'

const passwordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^a-zA-Z0-9]/, 'Password must contain at least one special character'),
  confirmPassword: z.string(),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
}).refine((data) => data.currentPassword !== data.newPassword, {
  message: "New password must be different from current password",
  path: ['newPassword'],
})

type PasswordFormData = z.infer<typeof passwordSchema>

export function SecurityForm() {
  const [isLoading, setIsLoading] = React.useState(false)
  const [success, setSuccess] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [showCurrentPassword, setShowCurrentPassword] = React.useState(false)
  const [showNewPassword, setShowNewPassword] = React.useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = React.useState(false)
  const [passwordStrength, setPasswordStrength] = React.useState(0)

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
    reset,
  } = useForm<PasswordFormData>({
    resolver: zodResolver(passwordSchema),
  })

  const newPassword = watch('newPassword')

  React.useEffect(() => {
    if (newPassword) {
      let strength = 0
      if (newPassword.length >= 8) strength++
      if (newPassword.length >= 12) strength++
      if (/[a-z]/.test(newPassword) && /[A-Z]/.test(newPassword)) strength++
      if (/[0-9]/.test(newPassword)) strength++
      if (/[^a-zA-Z0-9]/.test(newPassword)) strength++
      setPasswordStrength(Math.min(strength, 5))
    } else {
      setPasswordStrength(0)
    }
  }, [newPassword])

  const getPasswordStrengthLabel = () => {
    switch (passwordStrength) {
      case 0: return ''
      case 1: return 'Very Weak'
      case 2: return 'Weak'
      case 3: return 'Fair'
      case 4: return 'Good'
      case 5: return 'Strong'
      default: return ''
    }
  }

  const getPasswordStrengthColor = () => {
    switch (passwordStrength) {
      case 0: return 'bg-gray-200'
      case 1: return 'bg-red-500'
      case 2: return 'bg-orange-500'
      case 3: return 'bg-yellow-500'
      case 4: return 'bg-blue-500'
      case 5: return 'bg-green-500'
      default: return 'bg-gray-200'
    }
  }

  const onSubmit = async (data: PasswordFormData) => {
    setIsLoading(true)
    setError(null)
    setSuccess(false)

    try {
      await new Promise(resolve => setTimeout(resolve, 2000))

      if (data.currentPassword === 'wrongpassword') {
        throw new Error('Current password is incorrect')
      }

      if (Math.random() > 0.8) {
        throw new Error('Failed to update password. Please try again.')
      }

      setSuccess(true)
      reset()
      setTimeout(() => setSuccess(false), 5000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      {success && (
        <Alert className="bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800">
          <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400" />
          <AlertTitle className="text-green-900 dark:text-green-100">
            Password updated successfully
          </AlertTitle>
          <AlertDescription className="text-green-700 dark:text-green-300">
            Your password has been changed. Please use your new password for future logins.
          </AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Alert>
        <Info className="h-4 w-4" />
        <AlertTitle>Password Tips</AlertTitle>
        <AlertDescription>
          Use a unique password that you don't use on other websites. Consider using a password manager.
        </AlertDescription>
      </Alert>

      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="currentPassword">Current Password</Label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              id="currentPassword"
              type={showCurrentPassword ? 'text' : 'password'}
              className="pl-10 pr-10"
              {...register('currentPassword')}
              aria-invalid={!!errors.currentPassword}
              aria-describedby={errors.currentPassword ? 'currentPassword-error' : undefined}
            />
            <button
              type="button"
              onClick={() => setShowCurrentPassword(!showCurrentPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              aria-label={showCurrentPassword ? 'Hide password' : 'Show password'}
            >
              {showCurrentPassword ? (
                <EyeOff className="h-4 w-4" />
              ) : (
                <Eye className="h-4 w-4" />
              )}
            </button>
          </div>
          {errors.currentPassword && (
            <p id="currentPassword-error" className="text-xs text-red-500">
              {errors.currentPassword.message}
            </p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="newPassword">New Password</Label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              id="newPassword"
              type={showNewPassword ? 'text' : 'password'}
              className="pl-10 pr-10"
              {...register('newPassword')}
              aria-invalid={!!errors.newPassword}
              aria-describedby={errors.newPassword ? 'newPassword-error' : undefined}
            />
            <button
              type="button"
              onClick={() => setShowNewPassword(!showNewPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              aria-label={showNewPassword ? 'Hide password' : 'Show password'}
            >
              {showNewPassword ? (
                <EyeOff className="h-4 w-4" />
              ) : (
                <Eye className="h-4 w-4" />
              )}
            </button>
          </div>
          {errors.newPassword && (
            <p id="newPassword-error" className="text-xs text-red-500">
              {errors.newPassword.message}
            </p>
          )}

          {newPassword && (
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-500">Password strength:</span>
                <span className={cn(
                  "text-xs font-medium",
                  passwordStrength <= 2 && "text-red-500",
                  passwordStrength === 3 && "text-yellow-500",
                  passwordStrength === 4 && "text-blue-500",
                  passwordStrength === 5 && "text-green-500"
                )}>
                  {getPasswordStrengthLabel()}
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className={cn(
                    "h-2 rounded-full transition-all",
                    getPasswordStrengthColor()
                  )}
                  style={{ width: `${(passwordStrength / 5) * 100}%` }}
                />
              </div>
            </div>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="confirmPassword">Confirm New Password</Label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              id="confirmPassword"
              type={showConfirmPassword ? 'text' : 'password'}
              className="pl-10 pr-10"
              {...register('confirmPassword')}
              aria-invalid={!!errors.confirmPassword}
              aria-describedby={errors.confirmPassword ? 'confirmPassword-error' : undefined}
            />
            <button
              type="button"
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
            >
              {showConfirmPassword ? (
                <EyeOff className="h-4 w-4" />
              ) : (
                <Eye className="h-4 w-4" />
              )}
            </button>
          </div>
          {errors.confirmPassword && (
            <p id="confirmPassword-error" className="text-xs text-red-500">
              {errors.confirmPassword.message}
            </p>
          )}
        </div>

        <div className="pt-2">
          <Button
            type="button"
            variant="link"
            className="p-0 h-auto font-normal text-blue-600 hover:text-blue-700"
          >
            Forgot your current password?
          </Button>
        </div>
      </div>

      <div className="flex justify-between">
        <Button type="button" variant="outline">
          Cancel
        </Button>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Updating...
            </>
          ) : (
            'Update Password'
          )}
        </Button>
      </div>
    </form>
  )
}