import * as React from 'react'
import { createFileRoute, useNavigate, Link } from '@tanstack/react-router'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import * as z from 'zod'
import { Loader2, CheckCircle2, AlertCircle, Shield } from 'lucide-react'
import { AuthLayout } from '@/components/layouts/AuthLayout'
import { Button } from '@/components/ui/button'
import { PasswordInput } from '@/components/ui/PasswordInput'
import { Label } from '@/components/ui/label'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'

// Validation schema
const resetPasswordSchema = z.object({
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Must contain at least one number')
    .regex(/[^a-zA-Z0-9]/, 'Must contain at least one special character'),
  confirmPassword: z.string(),
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword']
})

type ResetPasswordForm = z.infer<typeof resetPasswordSchema>

// Search params schema for token validation
const searchParamsSchema = z.object({
  token: z.string(),
  email: z.string().email().optional(),
})

export const Route = createFileRoute('/auth/reset-password')({
  component: ResetPasswordPage,
  validateSearch: searchParamsSchema,
})

function ResetPasswordPage() {
  const navigate = useNavigate()
  const { token, email } = Route.useSearch()
  const [isLoading, setIsLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [success, setSuccess] = React.useState(false)
  const [tokenValid, setTokenValid] = React.useState(true)
  const [passwordStrength, setPasswordStrength] = React.useState(0)

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<ResetPasswordForm>({
    resolver: zodResolver(resetPasswordSchema),
  })

  // Validate token on mount
  React.useEffect(() => {
    const validateToken = async () => {
      try {
        // Mock token validation
        await new Promise(resolve => setTimeout(resolve, 500))

        // Simulate invalid token
        if (token === 'invalid' || token === 'expired') {
          setTokenValid(false)
          setError('This password reset link is invalid or has expired.')
        }
      } catch (err) {
        setTokenValid(false)
        setError('Unable to validate reset link. Please request a new one.')
      }
    }

    if (token) {
      validateToken()
    } else {
      setTokenValid(false)
      setError('No reset token provided. Please use the link from your email.')
    }
  }, [token])

  const onSubmit = async (data: ResetPasswordForm) => {
    if (!tokenValid) return

    setIsLoading(true)
    setError(null)

    try {
      // Mock API call
      await new Promise(resolve => setTimeout(resolve, 2000))

      // Simulate random error for demo
      if (Math.random() > 0.8) {
        throw new Error('Network error. Please try again.')
      }

      setSuccess(true)

      // Redirect to login after success
      setTimeout(() => {
        navigate({ to: '/login', search: { passwordReset: 'true' } })
      }, 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reset password. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  if (success) {
    return (
      <AuthLayout
        title="Password reset successful!"
        subtitle="Your password has been changed"
      >
        <div className="space-y-6">
          <div className="flex justify-center">
            <div className="h-16 w-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center">
              <Shield className="h-8 w-8 text-green-600 dark:text-green-400" />
            </div>
          </div>

          <div className="text-center space-y-3">
            <p className="text-gray-600 dark:text-gray-400">
              Your password has been successfully reset.
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-500">
              You'll be redirected to the login page in a moment...
            </p>
          </div>

          <div className="space-y-3">
            <Button className="w-full" asChild>
              <Link to="/login">Go to login</Link>
            </Button>
          </div>
        </div>
      </AuthLayout>
    )
  }

  if (!tokenValid) {
    return (
      <AuthLayout
        title="Invalid reset link"
        subtitle="This link has expired or is invalid"
      >
        <div className="space-y-6">
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Invalid or expired link</AlertTitle>
            <AlertDescription>
              {error || 'This password reset link is no longer valid.'}
            </AlertDescription>
          </Alert>

          <div className="text-center space-y-3">
            <p className="text-gray-600 dark:text-gray-400">
              Password reset links expire after 1 hour for security reasons.
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-500">
              Please request a new password reset link.
            </p>
          </div>

          <div className="space-y-3">
            <Button className="w-full" asChild>
              <Link to="/auth/forgot-password">Request new link</Link>
            </Button>

            <Button className="w-full" variant="outline" asChild>
              <Link to="/login">Back to login</Link>
            </Button>
          </div>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout
      title="Set new password"
      subtitle="Choose a strong password for your account"
    >
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {email && (
          <div className="text-center p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Resetting password for:
            </p>
            <p className="font-medium text-gray-900 dark:text-white">
              {email}
            </p>
          </div>
        )}

        <div className="space-y-2">
          <Label htmlFor="password">New password</Label>
          <PasswordInput
            id="password"
            placeholder="Enter your new password"
            showStrength
            onStrengthChange={setPasswordStrength}
            {...register('password')}
            aria-invalid={!!errors.password}
            aria-describedby={errors.password ? 'password-error' : 'password-requirements'}
            disabled={isLoading}
          />
          {errors.password ? (
            <p id="password-error" className="text-xs text-red-500" role="alert">
              {errors.password.message}
            </p>
          ) : (
            <div id="password-requirements" className="space-y-1">
              <p className="text-xs text-gray-500 dark:text-gray-400 font-medium">
                Password requirements:
              </p>
              <ul className="text-xs text-gray-500 dark:text-gray-400 space-y-0.5 ml-4">
                <li className="list-disc">At least 8 characters</li>
                <li className="list-disc">One uppercase letter</li>
                <li className="list-disc">One lowercase letter</li>
                <li className="list-disc">One number</li>
                <li className="list-disc">One special character</li>
              </ul>
            </div>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="confirmPassword">Confirm new password</Label>
          <PasswordInput
            id="confirmPassword"
            placeholder="Re-enter your new password"
            {...register('confirmPassword')}
            aria-invalid={!!errors.confirmPassword}
            aria-describedby={errors.confirmPassword ? 'confirmPassword-error' : undefined}
            disabled={isLoading}
          />
          {errors.confirmPassword && (
            <p id="confirmPassword-error" className="text-xs text-red-500" role="alert">
              {errors.confirmPassword.message}
            </p>
          )}
        </div>

        <Alert>
          <Shield className="h-4 w-4" />
          <AlertTitle>Security tip</AlertTitle>
          <AlertDescription>
            Create a unique password that you don't use for other accounts.
            Consider using a password manager for better security.
          </AlertDescription>
        </Alert>

        <Button
          type="submit"
          className="w-full"
          disabled={isLoading || passwordStrength < 3}
        >
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Resetting password...
            </>
          ) : (
            'Reset password'
          )}
        </Button>

        <div className="text-center">
          <Link
            to="/login"
            className="text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
          >
            Cancel and return to login
          </Link>
        </div>
      </form>
    </AuthLayout>
  )
}