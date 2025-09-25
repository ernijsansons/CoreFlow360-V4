import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { LoginForm } from '@/modules/auth/login-form'
import { useAuthStore } from '@/stores'

export const Route = createFileRoute('/login')({
  component: LoginPage,
  beforeLoad: () => {
    const { isAuthenticated } = useAuthStore.getState()

    // Redirect to dashboard if already authenticated
    if (isAuthenticated) {
      throw new Error('Already authenticated')
    }
  },
  meta: () => [
    {
      title: 'Login - CoreFlow360',
      description: 'Sign in to your CoreFlow360 account',
    },
  ],
})

function LoginPage() {
  return (
    <div className="min-h-screen flex">
      {/* Left side - Branding */}
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-brand-600 to-brand-800 text-white p-12 flex-col justify-between">
        <div>
          <h1 className="text-4xl font-bold mb-4">CoreFlow360</h1>
          <p className="text-xl text-brand-100">
            AI-Native ERP Platform for Modern Businesses
          </p>
        </div>

        <div className="space-y-6">
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
            <h3 className="font-semibold mb-2">Unified Operations</h3>
            <p className="text-brand-100">
              Manage CRM, finance, projects, and more from a single platform
            </p>
          </div>

          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
            <h3 className="font-semibold mb-2">AI-Powered Insights</h3>
            <p className="text-brand-100">
              Get intelligent recommendations and automate routine tasks
            </p>
          </div>

          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6">
            <h3 className="font-semibold mb-2">Real-time Collaboration</h3>
            <p className="text-brand-100">
              Work together seamlessly with your team across all modules
            </p>
          </div>
        </div>
      </div>

      {/* Right side - Login form */}
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-foreground">Welcome back</h2>
            <p className="text-muted-foreground mt-2">
              Sign in to your account to continue
            </p>
          </div>

          <LoginForm />

          <div className="mt-8 text-center">
            <p className="text-sm text-muted-foreground">
              Don't have an account?{' '}
              <a
                href="/register"
                className="font-medium text-brand-600 hover:text-brand-500"
              >
                Sign up
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}