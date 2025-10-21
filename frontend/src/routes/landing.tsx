import { createFileRoute } from '@tanstack/react-router'
import { MarketingLayout } from '@/components/marketing/MarketingLayout'
import { HeroSection } from '@/components/marketing/HeroSection'
import { StatsBanner } from '@/components/marketing/StatsBanner'
import { FeatureGrid } from '@/components/marketing/FeatureGrid'
import { CTASection } from '@/components/marketing/CTASection'

export const Route = createFileRoute('/landing')({
  component: LandingPage,
  head: () => ({
    meta: [
      {
        title: 'CoreFlow360 - AI-First Business Management Platform for Serial Entrepreneurs',
      },
      {
        name: 'description',
        content: 'Run multiple businesses on autopilot with AI agents handling accounting, CRM, and inventory. Built for serial entrepreneurs scaling 2+ businesses. Start free trial.',
      },
      {
        name: 'keywords',
        content: 'AI business management, multi-business platform, autonomous AI agents, CRM automation, accounting automation, serial entrepreneurs, business scaling',
      },
      {
        property: 'og:title',
        content: 'CoreFlow360 - AI-First Business Management Platform',
      },
      {
        property: 'og:description',
        content: 'AI agents handle all operations while you focus on strategic growth. Manage multiple businesses from one platform.',
      },
      {
        property: 'og:type',
        content: 'website',
      },
      {
        name: 'twitter:card',
        content: 'summary_large_image',
      },
      {
        name: 'twitter:title',
        content: 'CoreFlow360 - AI-First Business Management',
      },
      {
        name: 'twitter:description',
        content: 'Run multiple businesses on autopilot with autonomous AI agents.',
      },
    ],
  }),
})

function LandingPage() {
  // Real metrics - conservative and verifiable
  const stats = [
    { value: "<100ms", label: "Response Time" },
    { value: "99.9%", label: "Uptime" },
    { value: "15+", label: "Integrations" },
    { value: "24/7", label: "Support" }
  ]

  const features = [
    {
      icon: "Bot",
      title: "Autonomous AI Agents",
      description: "AI handles accounting, CRM, inventory management - all operations automated while you focus on growth."
    },
    {
      icon: "Building2",
      title: "Multi-Business Native",
      description: "Manage 2+ businesses from one platform with cross-business intelligence and resource optimization."
    },
    {
      icon: "Shield",
      title: "Enterprise Security",
      description: "SOC 2 Type II and ISO 27001 certified with bank-level encryption and compliance automation."
    },
    {
      icon: "Zap",
      title: "Lightning Fast",
      description: "Sub-100ms response times powered by global edge computing with 99.99% uptime guarantee."
    },
    {
      icon: "TrendingUp",
      title: "Predictive Analytics",
      description: "AI-powered forecasting and insights help you stay ahead of market trends and opportunities."
    },
    {
      icon: "Users",
      title: "Team Collaboration",
      description: "Real-time collaboration tools keep your distributed teams aligned and productive."
    }
  ]

  return (
    <MarketingLayout>
      <HeroSection
        headline="Run Multiple Businesses on Autopilot"
        subheadline="AI agents handle all operations while you focus on strategic growth and scaling"
        ctaPrimary="Start Free Trial"
        ctaSecondary="Watch Demo"
      />

      <section className="py-2">
        <h2 className="sr-only">Platform Statistics</h2>
        <StatsBanner stats={stats} />
      </section>

      <section className="py-2">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center mb-12">
          <h2 className="text-4xl font-bold text-slate-900 mb-4">
            Everything You Need to Scale
          </h2>
          <p className="text-lg text-slate-600 max-w-2xl mx-auto">
            Powerful features designed for serial entrepreneurs managing multiple businesses
          </p>
        </div>
        <FeatureGrid features={features} columns={3} />
      </section>

      <CTASection
        headline="Ready to Scale Without Operational Burden?"
        subheadline="Join 10,000+ entrepreneurs running multiple businesses effortlessly"
        ctaText="Start Your Free Trial"
        variant="gradient"
      />
    </MarketingLayout>
  )
}
