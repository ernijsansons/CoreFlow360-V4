import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useEffect, useState } from 'react'

export const Route = createFileRoute('/checkout/success')({
  component: CheckoutSuccessPage,
  validateSearch: (search: Record<string, unknown>) => {
    return {
      plan: (search.plan as string) || 'professional',
    }
  },
})

function CheckoutSuccessPage() {
  const navigate = useNavigate()
  const { plan } = Route.useSearch()
  const [countdown, setCountdown] = useState(10)

  useEffect(() => {
    // Auto-redirect to dashboard after 10 seconds
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer)
          navigate({ to: '/dashboard' })
          return 0
        }
        return prev - 1
      })
    }, 1000)

    return () => clearInterval(timer)
  }, [navigate])

  return (
    <div className="min-h-screen bg-gradient-to-br from-brand-primary/10 via-background to-brand-accent/10 flex items-center justify-center p-4">
      <div className="max-w-2xl w-full">
        {/* Success Card */}
        <div className="bg-card rounded-2xl p-12 shadow-2xl border-2 border-brand-primary/20 text-center">
          {/* Success Icon */}
          <div className="mb-8">
            <div className="mx-auto w-24 h-24 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center">
              <svg
                className="w-12 h-12 text-green-600 dark:text-green-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={3}
                  d="M5 13l4 4L19 7"
                />
              </svg>
            </div>
          </div>

          {/* Title */}
          <h1 className="text-4xl font-bold mb-4">Welcome to CoreFlow360!</h1>
          <p className="text-xl text-muted-foreground mb-8">
            Your {plan} plan trial has started successfully
          </p>

          {/* What's Next */}
          <div className="bg-muted/30 rounded-xl p-6 mb-8 text-left">
            <h2 className="text-lg font-semibold mb-4">What happens next?</h2>
            <ul className="space-y-3">
              <li className="flex items-start gap-3">
                <span className="text-brand-primary text-xl flex-shrink-0">✓</span>
                <div>
                  <p className="font-medium">14-Day Free Trial</p>
                  <p className="text-sm text-muted-foreground">
                    Your trial starts now. You won't be charged until{' '}
                    {new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toLocaleDateString('en-US', {
                      month: 'long',
                      day: 'numeric',
                      year: 'numeric',
                    })}
                  </p>
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-brand-primary text-xl flex-shrink-0">✓</span>
                <div>
                  <p className="font-medium">Setup Your First Business</p>
                  <p className="text-sm text-muted-foreground">
                    Create your business profile and configure your workspace
                  </p>
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-brand-primary text-xl flex-shrink-0">✓</span>
                <div>
                  <p className="font-medium">Deploy AI Agents</p>
                  <p className="text-sm text-muted-foreground">
                    Activate Finance and CRM agents to automate operations
                  </p>
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-brand-primary text-xl flex-shrink-0">✓</span>
                <div>
                  <p className="font-medium">Connect Integrations</p>
                  <p className="text-sm text-muted-foreground">
                    Link your existing tools for seamless data sync
                  </p>
                </div>
              </li>
            </ul>
          </div>

          {/* Email Confirmation */}
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-8">
            <p className="text-sm text-blue-800 dark:text-blue-200">
              📧 We've sent a confirmation email with your account details and getting started guide
            </p>
          </div>

          {/* Actions */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/dashboard"
              className="px-8 py-4 bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg text-lg font-semibold transition-colors shadow-lg"
            >
              Go to Dashboard
            </Link>
            <Link
              to="/help"
              className="px-8 py-4 bg-white hover:bg-gray-50 dark:bg-muted dark:hover:bg-muted/80 text-brand-primary border-2 border-brand-primary rounded-lg text-lg font-semibold transition-colors"
            >
              View Getting Started Guide
            </Link>
          </div>

          {/* Auto-redirect notice */}
          <p className="text-sm text-muted-foreground mt-6">
            Redirecting to dashboard in {countdown} seconds...
          </p>
        </div>

        {/* Help Card */}
        <div className="mt-8 text-center">
          <p className="text-muted-foreground mb-4">
            Need help getting started?
          </p>
          <div className="flex gap-4 justify-center flex-wrap">
            <Link
              to="/help"
              className="text-brand-primary hover:underline font-medium"
            >
              Help Center
            </Link>
            <span className="text-muted-foreground">•</span>
            <Link
              to="/contact"
              className="text-brand-primary hover:underline font-medium"
            >
              Contact Support
            </Link>
            <span className="text-muted-foreground">•</span>
            <a
              href="https://api.coreflow360.com/docs"
              className="text-brand-primary hover:underline font-medium"
            >
              API Docs
            </a>
          </div>
        </div>
      </div>
    </div>
  )
}
