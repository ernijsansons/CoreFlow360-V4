import { createFileRoute, Link } from '@tanstack/react-router'
import { Analytics } from '@/lib/analytics'
import { PublicHeader } from '@/components/layouts/PublicHeader'

export const Route = createFileRoute('/pricing')({
  component: PricingPage,
  head: () => ({
    meta: [
      {
        title: 'Pricing - CoreFlow360 | Simple, Transparent Plans for Every Business',
      },
      {
        name: 'description',
        content: 'Start free, scale as you grow. Transparent pricing for AI-powered business management. No hidden fees. Plans for startups to enterprises.',
      },
      {
        property: 'og:title',
        content: 'CoreFlow360 Pricing - Plans for Every Business',
      },
      {
        property: 'og:description',
        content: 'Simple, transparent pricing. Start free and scale as you grow with AI-powered business management.',
      },
    ],
  }),
})

function PricingPage() {
  return (
    <div className="min-h-screen bg-background">
      <PublicHeader />
      {/* Hero Section */}
      <section className="py-20 px-4 bg-gradient-to-br from-brand-primary/10 via-background to-brand-accent/10">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-brand-primary to-brand-accent bg-clip-text text-transparent">
            Simple, Transparent Pricing
          </h1>
          <p className="text-xl md:text-2xl text-muted-foreground mb-8 max-w-3xl mx-auto">
            Start free, scale as you grow. No hidden fees, no surprises.
          </p>
          <p className="text-lg text-brand-primary font-semibold">
            Free forever plan available • 14-day trial on paid plans • Cancel anytime
          </p>
        </div>
      </section>

      {/* Pricing Cards */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="grid md:grid-cols-4 gap-6">
            {/* Starter - Free Forever */}
            <div className="bg-card rounded-xl p-8 border-2 border-border shadow-sm hover:shadow-md transition-shadow">
              <div className="mb-6">
                <h3 className="text-2xl font-bold mb-2">Starter</h3>
                <div className="flex items-baseline mb-2">
                  <span className="text-5xl font-bold">$0</span>
                  <span className="text-muted-foreground ml-2">/month</span>
                </div>
                <p className="text-sm text-brand-primary font-semibold">Free Forever</p>
              </div>

              <ul className="space-y-3 mb-8">
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">1 business</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">2 AI agents (Finance + CRM)</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">1,000 AI tasks/month</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Basic analytics dashboard</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Community support</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">30-day data retention</span>
                </li>
              </ul>

              <Link
                to="/auth/register"
                className="block w-full text-center px-6 py-3 bg-muted hover:bg-muted/80 text-foreground rounded-lg font-semibold transition-colors"
                onClick={() => Analytics.trackFunnel.signupStarted()}
              >
                Get Started Free
              </Link>
            </div>

            {/* Professional - Most Popular */}
            <div className="bg-card rounded-xl p-8 border-2 border-brand-primary shadow-lg hover:shadow-xl transition-shadow relative">
              <div className="absolute -top-4 left-1/2 transform -translate-x-1/2 bg-brand-primary text-white px-4 py-1 rounded-full text-sm font-bold shadow-md">
                MOST POPULAR
              </div>

              <div className="mb-6">
                <h3 className="text-2xl font-bold mb-2">Professional</h3>
                <div className="flex items-baseline mb-2">
                  <span className="text-5xl font-bold">$99</span>
                  <span className="text-muted-foreground ml-2">/month</span>
                </div>
                <p className="text-sm text-brand-primary font-semibold">14-day free trial</p>
              </div>

              <ul className="space-y-3 mb-8">
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm font-semibold">Everything in Starter, plus:</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">5 businesses</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Unlimited AI agents</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">10,000 AI tasks/month</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Advanced analytics & reporting</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Priority email support</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">90-day data retention</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">API access</span>
                </li>
              </ul>

              <Link
                to="/auth/register"
                className="block w-full text-center px-6 py-3 bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg font-semibold transition-colors shadow-md"
                onClick={() => Analytics.trackFunnel.signupStarted()}
              >
                Start 14-Day Trial
              </Link>
            </div>

            {/* Premium */}
            <div className="bg-card rounded-xl p-8 border-2 border-border shadow-sm hover:shadow-md transition-shadow">
              <div className="mb-6">
                <h3 className="text-2xl font-bold mb-2">Premium</h3>
                <div className="flex items-baseline mb-2">
                  <span className="text-5xl font-bold">$299</span>
                  <span className="text-muted-foreground ml-2">/month</span>
                </div>
                <p className="text-sm text-brand-primary font-semibold">14-day free trial</p>
              </div>

              <ul className="space-y-3 mb-8">
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm font-semibold">Everything in Professional, plus:</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Unlimited businesses</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Unlimited AI tasks</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">ML-powered predictive analytics</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">White-label branding</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Dedicated success manager</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Custom integrations</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Unlimited data retention</span>
                </li>
              </ul>

              <Link
                to="/auth/register"
                className="block w-full text-center px-6 py-3 bg-muted hover:bg-muted/80 text-foreground rounded-lg font-semibold transition-colors"
                onClick={() => Analytics.trackFunnel.signupStarted()}
              >
                Start 14-Day Trial
              </Link>
            </div>

            {/* Enterprise */}
            <div className="bg-card rounded-xl p-8 border-2 border-border shadow-sm hover:shadow-md transition-shadow">
              <div className="mb-6">
                <h3 className="text-2xl font-bold mb-2">Enterprise</h3>
                <div className="flex items-baseline mb-2">
                  <span className="text-5xl font-bold">Custom</span>
                </div>
                <p className="text-sm text-muted-foreground">Tailored to your needs</p>
              </div>

              <ul className="space-y-3 mb-8">
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm font-semibold">Everything in Premium, plus:</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Custom SLA guarantees</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">On-premise deployment option</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">SAML/SSO authentication</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Custom AI model training</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Legal review & compliance support</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">Dedicated infrastructure</span>
                </li>
                <li className="flex items-start">
                  <span className="text-brand-primary mr-2 mt-1">✓</span>
                  <span className="text-sm">24/7 phone support</span>
                </li>
              </ul>

              <a
                href="mailto:enterprise@coreflow360.com"
                className="block w-full text-center px-6 py-3 bg-brand-accent hover:bg-brand-accent/90 text-white rounded-lg font-semibold transition-colors"
              >
                Contact Sales
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Comparison Table */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12">Feature Comparison</h2>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse bg-card rounded-lg overflow-hidden">
              <thead>
                <tr className="bg-muted">
                  <th className="text-left p-4 font-semibold">Feature</th>
                  <th className="text-center p-4 font-semibold">Starter</th>
                  <th className="text-center p-4 font-semibold">Professional</th>
                  <th className="text-center p-4 font-semibold">Premium</th>
                  <th className="text-center p-4 font-semibold">Enterprise</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-t">
                  <td className="p-4">Number of Businesses</td>
                  <td className="text-center p-4">1</td>
                  <td className="text-center p-4">5</td>
                  <td className="text-center p-4">Unlimited</td>
                  <td className="text-center p-4">Unlimited</td>
                </tr>
                <tr className="border-t bg-muted/30">
                  <td className="p-4">AI Agents</td>
                  <td className="text-center p-4">2</td>
                  <td className="text-center p-4">Unlimited</td>
                  <td className="text-center p-4">Unlimited</td>
                  <td className="text-center p-4">Unlimited + Custom</td>
                </tr>
                <tr className="border-t">
                  <td className="p-4">AI Tasks per Month</td>
                  <td className="text-center p-4">1,000</td>
                  <td className="text-center p-4">10,000</td>
                  <td className="text-center p-4">Unlimited</td>
                  <td className="text-center p-4">Unlimited</td>
                </tr>
                <tr className="border-t bg-muted/30">
                  <td className="p-4">Analytics</td>
                  <td className="text-center p-4">Basic</td>
                  <td className="text-center p-4">Advanced</td>
                  <td className="text-center p-4">ML-Powered</td>
                  <td className="text-center p-4">Custom ML Models</td>
                </tr>
                <tr className="border-t">
                  <td className="p-4">API Access</td>
                  <td className="text-center p-4">—</td>
                  <td className="text-center p-4">✓</td>
                  <td className="text-center p-4">✓</td>
                  <td className="text-center p-4">✓ Premium</td>
                </tr>
                <tr className="border-t bg-muted/30">
                  <td className="p-4">Support</td>
                  <td className="text-center p-4">Community</td>
                  <td className="text-center p-4">Priority Email</td>
                  <td className="text-center p-4">Dedicated Manager</td>
                  <td className="text-center p-4">24/7 Phone</td>
                </tr>
                <tr className="border-t">
                  <td className="p-4">Data Retention</td>
                  <td className="text-center p-4">30 days</td>
                  <td className="text-center p-4">90 days</td>
                  <td className="text-center p-4">Unlimited</td>
                  <td className="text-center p-4">Unlimited + Backup</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="py-20 px-4">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12">Pricing FAQ</h2>

          <div className="space-y-4">
            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">Can I switch plans at any time?</summary>
              <p className="mt-4 text-muted-foreground">
                Yes! You can upgrade or downgrade your plan at any time. Upgrades take effect immediately, while downgrades apply at the end of your current billing cycle. No penalties or fees for switching.
              </p>
            </details>

            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">What happens if I exceed my AI task limit?</summary>
              <p className="mt-4 text-muted-foreground">
                On the Starter plan, tasks will pause until the next billing cycle or you can upgrade instantly. On Professional, you'll receive a notification and can purchase additional task packages at $10 per 1,000 tasks.
              </p>
            </details>

            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">Is the free plan really free forever?</summary>
              <p className="mt-4 text-muted-foreground">
                Yes! Our Starter plan is completely free with no time limits. It's perfect for solo entrepreneurs or those wanting to test CoreFlow360 before scaling to multiple businesses.
              </p>
            </details>

            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">Do you offer annual billing discounts?</summary>
              <p className="mt-4 text-muted-foreground">
                Yes! Save 20% with annual billing. Professional plan is $950/year (save $238), Premium is $2,870/year (save $718). Contact sales for Enterprise annual pricing.
              </p>
            </details>

            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">What payment methods do you accept?</summary>
              <p className="mt-4 text-muted-foreground">
                We accept all major credit cards (Visa, Mastercard, Amex), PayPal, and for Enterprise customers, we can arrange ACH/wire transfers and custom invoicing.
              </p>
            </details>

            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">What's your refund policy?</summary>
              <p className="mt-4 text-muted-foreground">
                We offer a 30-day money-back guarantee on all paid plans. If you're not satisfied within the first 30 days, we'll refund your payment in full, no questions asked.
              </p>
            </details>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 px-4 bg-gradient-to-br from-brand-primary/10 to-brand-accent/10">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl font-bold mb-6">
            Start Building Your Business Empire Today
          </h2>
          <p className="text-xl text-muted-foreground mb-8">
            Join thousands of serial entrepreneurs scaling with AI
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/auth/register"
              className="inline-block px-8 py-4 bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg text-lg font-semibold transition-colors shadow-lg"
              onClick={() => Analytics.trackFunnel.signupStarted()}
            >
              Start Free Trial
            </Link>
            <a
              href="mailto:sales@coreflow360.com"
              className="inline-block px-8 py-4 bg-white hover:bg-gray-50 text-brand-primary border-2 border-brand-primary rounded-lg text-lg font-semibold transition-colors"
            >
              Talk to Sales
            </a>
          </div>
          <p className="mt-4 text-sm text-muted-foreground">
            No credit card required • 14-day free trial • Cancel anytime
          </p>
        </div>
      </section>
    </div>
  )
}
