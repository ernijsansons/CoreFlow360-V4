import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/privacy')({
  component: PrivacyPage,
})

function PrivacyPage() {
  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-4xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <div className="space-y-8">
          <div className="space-y-4">
            <h1 className="text-4xl font-bold tracking-tight">Privacy Policy</h1>
            <p className="text-muted-foreground">
              Last updated: {new Date().toLocaleDateString()}
            </p>
          </div>

          <div className="prose prose-gray dark:prose-invert max-w-none space-y-6">
            <section className="space-y-4">
              <h2 className="text-2xl font-semibold">1. Information We Collect</h2>
              <p>
                We collect information you provide directly to us, including account information,
                business data, and usage information.
              </p>
            </section>

            <section className="space-y-4">
              <h2 className="text-2xl font-semibold">2. How We Use Your Information</h2>
              <p>
                We use your information to provide, maintain, and improve our services, and to
                communicate with you about your account.
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


