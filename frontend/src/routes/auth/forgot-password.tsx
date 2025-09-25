import * as React from 'react'
import { createFileRoute, useNavigate, Link } from '@tanstack/react-router'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import * as z from 'zod'
import { Loader2, CheckCircle2, AlertCircle, ArrowLeft } from 'lucide-react'
import { AuthLayout } from '@/components/layouts/AuthLayout'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'
import { cn } from '@/lib/utils'

// Validation schema
const forgotPasswordSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
})

type ForgotPasswordForm = z.infer<typeof forgotPasswordSchema>

export const Route = createFileRoute('/auth/forgot-password')({
  component: ForgotPasswordPage,
})

function ForgotPasswordPage() {
  const navigate = useNavigate()
  const [isLoading, setIsLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [success, setSuccess] = React.useState(false)
  const [attemptCount, setAttemptCount] = React.useState(0)

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<ForgotPasswordForm>({
    resolver: zodResolver(forgotPasswordSchema),
  })

  const onSubmit = async (data: ForgotPasswordForm) => {
    setIsLoading(true)
    setError(null)
    setAttemptCount(prev => prev + 1)

    try {
      // Mock API call
      await new Promise(resolve => setTimeout(resolve, 1500))

      // Simulate validation
      if (data.email === 'notfound@example.com') {
        throw new Error('No account found with this email address')
      }

      // Rate limiting simulation
      if (attemptCount >= 3) {
        throw new Error('Too many attempts. Please try again in 15 minutes.')
      }

      setSuccess(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  if (success) {
    return (
      <AuthLayout
        title="Check your email"
        subtitle="Password reset instructions sent"
      >
        <div className="space-y-6">
          <div className="flex justify-center">
            <div className="h-16 w-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center">
              <CheckCircle2 className="h-8 w-8 text-green-600 dark:text-green-400" />
            </div>
          </div>

          <div className="text-center space-y-3">
            <p className="text-gray-600 dark:text-gray-400">
              We've sent password reset instructions to:
            </p>
            <p className="font-semibold text-gray-900 dark:text-white">
              {watch('email')}
            </p>
          </div>

          <Alert>
            <AlertTitle>Important</AlertTitle>
            <AlertDescription>
              The reset link will expire in 1 hour. If you don't see the email,
              check your spam folder or request a new link.
            </AlertDescription>
          </Alert>

          <div className="space-y-3">
            <Button
              className="w-full"
              variant="outline"
              onClick={() => window.location.href = 'mailto:'}
            >
              Open email app
            </Button>

            <Button
              className="w-full"
              variant="ghost"
              onClick={() => setSuccess(false)}
            >
              Didn't receive email? Try again
            </Button>
          </div>

          <div className="text-center">
            <Link
              to="/login"
              className="text-sm text-brand-600 hover:text-brand-700 font-medium inline-flex items-center"
            >
              <ArrowLeft className="mr-1 h-3 w-3" />
              Back to login
            </Link>
          </div>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout
      title="Forgot your password?"
      subtitle="No worries, we'll send you reset instructions"
    >
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="space-y-2">
          <Label htmlFor="email">Email address</Label>
          <Input
            id="email"
            type="email"
            placeholder="Enter your email"
            autoComplete="email"
            {...register('email')}
            aria-invalid={!!errors.email}
            aria-describedby={
              errors.email
                ? 'email-error'
                : 'email-description'
            }
            disabled={isLoading}
          />
          {errors.email ? (
            <p id="email-error" className="text-xs text-red-500" role="alert">
              {errors.email.message}
            </p>
          ) : (
            <p id="email-description" className="text-xs text-gray-500 dark:text-gray-400">
              Enter the email address associated with your account
            </p>
          )}
        </div>

        {attemptCount >= 2 && (
          <Alert>
            <AlertTitle>Need help?</AlertTitle>
            <AlertDescription>
              If you're having trouble accessing your account, please{' '}
              <Link
                to="/help/contact"
                className="text-brand-600 hover:underline font-medium"
              >
                contact support
              </Link>{' '}
              for assistance.
            </AlertDescription>
          </Alert>
        )}

        <Button
          type="submit"
          className="w-full"
          disabled={isLoading}
        >
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Sending instructions...
            </>
          ) : (
            'Send reset instructions'
          )}
        </Button>

        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <span className="w-full border-t border-gray-300 dark:border-gray-700" />
          </div>
          <div className="relative flex justify-center text-xs uppercase">
            <span className="bg-white dark:bg-gray-800 px-2 text-gray-500 dark:text-gray-400">
              Or
            </span>
          </div>
        </div>

        <div className="text-center space-y-3">
          <Link
            to="/login"
            className="text-sm text-brand-600 hover:text-brand-700 font-medium inline-flex items-center"
          >
            <ArrowLeft className="mr-1 h-3 w-3" />
            Back to login
          </Link>

          <p className="text-xs text-gray-500 dark:text-gray-500">
            Don't have an account?{' '}
            <Link
              to="/auth/register"
              className="text-brand-600 hover:text-brand-700 font-medium"
            >
              Sign up
            </Link>
          </p>
        </div>
      </form>
    </AuthLayout>
  )
}