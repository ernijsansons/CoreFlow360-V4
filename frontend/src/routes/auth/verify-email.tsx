import { createFileRoute, Link } from '@tanstack/react-router'
import { Mail, ArrowRight } from 'lucide-react'
import { Button } from '@/components/ui/button'

export const Route = createFileRoute('/auth/verify-email')({
  component: VerifyEmailPage,
})

function VerifyEmailPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-brand-primary-950 to-gray-950 flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-8">
        <div className="bg-white/10 backdrop-blur-2xl rounded-3xl p-8 border border-white/20 shadow-2xl">
          <div className="flex justify-center mb-6">
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-r from-brand-primary-400 to-brand-accent-600 blur-xl opacity-75 animate-pulse" />
              <div className="relative bg-gradient-to-r from-brand-primary-600 to-brand-accent-600 p-4 rounded-2xl">
                <Mail className="h-12 w-12 text-white" />
              </div>
            </div>
          </div>

          <div className="text-center space-y-4">
            <h1 className="text-3xl font-bold text-white">Check your email</h1>
            <p className="text-brand-primary-200">
              We've sent a verification link to your email address.
            </p>

            <div className="pt-6">
              <Button
                className="w-full bg-gradient-to-r from-brand-primary-600 to-brand-accent-600"
                asChild
              >
                <Link to="/login">
                  Continue to Login
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}


