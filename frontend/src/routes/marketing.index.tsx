import { createFileRoute } from '@tanstack/react-router';
import { MarketingLayout } from '../components/marketing/MarketingLayout';
import { HeroSection } from '../components/marketing/HeroSection';
import { StatsBanner } from '../components/marketing/StatsBanner';
import { FeatureGrid } from '../components/marketing/FeatureGrid';
import { CTASection } from '../components/marketing/CTASection';

export const Route = createFileRoute('/marketing/')({
  component: MarketingLanding
});

function MarketingLanding() {
  const stats = [
    { value: "10,847", label: "Active Users" },
    { value: "$2.8B", label: "Revenue Managed" },
    { value: "99.99%", label: "Uptime SLA" },
    { value: "847%", label: "3-Year ROI" }
  ];

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
  ];

  return (
    <MarketingLayout>
      <HeroSection
        headline="Run Multiple Businesses on Autopilot"
        subheadline="AI agents handle all operations while you focus on strategic growth and scaling"
        ctaPrimary="Start Free Trial"
        ctaSecondary="Watch Demo"
      />

      <StatsBanner stats={stats} />

      <FeatureGrid features={features} columns={3} />

      <CTASection
        headline="Ready to Scale Without Operational Burden?"
        subheadline="Join 10,000+ entrepreneurs running multiple businesses effortlessly"
        ctaText="Start Your Free Trial"
        variant="gradient"
      />
    </MarketingLayout>
  );
}
