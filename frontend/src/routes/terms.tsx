import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/terms')({
  component: TermsPage,
})

function TermsPage() {
  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-4xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <div className="space-y-8">
          <div className="space-y-4">
            <h1 className="text-4xl font-bold tracking-tight">Terms of Service</h1>
            <p className="text-muted-foreground">
              Last updated: {new Date().toLocaleDateString()}
            </p>
          </div>

          <div className="prose prose-gray dark:prose-invert max-w-none space-y-6">
            <section className="space-y-4">
              <h2 className="text-2xl font-semibold">1. Agreement to Terms</h2>
              <p>
                By accessing or using CoreFlow360, you agree to be bound by these Terms of Service.
              </p>
            </section>

            <section className="space-y-4">
              <h2 className="text-2xl font-semibold">2. Use of Service</h2>
              <p>
                CoreFlow360 is an AI-powered business management platform. You agree to use the service
                in compliance with all applicable laws and regulations.
              </p>
            </section>
          </div>

          <div className="pt-8 border-t">
            <a 
              href="/auth/register"
              className="text-primary hover:underline"
            >
              ← Back to Registration
            </a>
          </div>
        </div>
      </div>
    </div>
  )
}


