import { createFileRoute, Link } from '@tanstack/react-router'
import { Analytics } from '@/lib/analytics'
import { PublicHeader } from '@/components/layouts/PublicHeader'

export const Route = createFileRoute('/landing')({
  component: LandingPage,
})

function LandingPage() {
  return (
    <div className="min-h-screen bg-background">
      <PublicHeader />
      {/* Hero Section */}
      <section className="relative bg-gradient-to-br from-primary/10 via-background to-secondary/10 py-20 px-4">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent">
            Run Multiple Businesses<br />With Zero Operational Overhead
          </h1>
          <p className="text-xl md:text-2xl text-muted-foreground mb-8 max-w-3xl mx-auto">
            AI agents handle all your ERP/CRM operations autonomously. You focus on growth and strategy.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/auth/register"
              className="px-8 py-4 bg-primary text-primary-foreground rounded-lg text-lg font-semibold hover:bg-primary/90 transition-colors"
              onClick={() => Analytics.trackFunnel.signupStarted()}
            >
              Start Free Trial
            </Link>
            <a
              href="#demo"
              className="px-8 py-4 bg-secondary text-secondary-foreground rounded-lg text-lg font-semibold hover:bg-secondary/80 transition-colors"
            >
              Watch Demo
            </a>
          </div>
          <p className="mt-4 text-sm text-muted-foreground">
            Free forever • No credit card required • 2-minute setup
          </p>
        </div>
      </section>

      {/* Problem Statement */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">
            Running Multiple Businesses Shouldn't Mean Multiple Headaches
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            <div className="bg-background rounded-lg p-6 shadow-sm">
              <div className="text-4xl mb-4">⏰</div>
              <h3 className="text-xl font-semibold mb-2">Time Drain</h3>
              <p className="text-muted-foreground">
                Spending 60% of your time on operational tasks instead of growth and strategy
              </p>
            </div>
            <div className="bg-background rounded-lg p-6 shadow-sm">
              <div className="text-4xl mb-4">📈</div>
              <h3 className="text-xl font-semibold mb-2">Scaling Pain</h3>
              <p className="text-muted-foreground">
                Each new business multiplies complexity. Traditional tools don't scale with you.
              </p>
            </div>
            <div className="bg-background rounded-lg p-6 shadow-sm">
              <div className="text-4xl mb-4">💸</div>
              <h3 className="text-xl font-semibold mb-2">Costly Mistakes</h3>
              <p className="text-muted-foreground">
                Manual processes lead to errors, missed opportunities, and compliance issues
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Solution - AI Agents */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-4">
            Meet Your Autonomous AI Workforce
          </h2>
          <p className="text-xl text-muted-foreground text-center mb-12 max-w-3xl mx-auto">
            Deploy AI agents that handle your business operations 24/7, learning and improving continuously
          </p>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Finance Agent */}
            <div className="bg-background rounded-lg p-6 border border-border hover:border-primary transition-colors">
              <div className="text-4xl mb-4">🤖💰</div>
              <h3 className="text-xl font-semibold mb-2">Autonomous Finance Agent</h3>
              <p className="text-muted-foreground mb-4">
                Double-entry bookkeeping, invoicing, tax calculations, and cash flow forecasting—all automated
              </p>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>✓ Automatic journal entries</li>
                <li>✓ Multi-currency handling</li>
                <li>✓ Invoice generation & follow-up</li>
                <li>✓ Tax compliance</li>
              </ul>
            </div>

            {/* CRM Agent */}
            <div className="bg-background rounded-lg p-6 border border-border hover:border-primary transition-colors">
              <div className="text-4xl mb-4">🤖🤝</div>
              <h3 className="text-xl font-semibold mb-2">Intelligent CRM Agent</h3>
              <p className="text-muted-foreground mb-4">
                Lead qualification, nurturing, and deal progression without manual intervention
              </p>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>✓ AI-powered lead scoring</li>
                <li>✓ Automated follow-ups</li>
                <li>✓ Pipeline management</li>
                <li>✓ Customer intelligence</li>
              </ul>
            </div>

            {/* Inventory Agent */}
            <div className="bg-background rounded-lg p-6 border border-border hover:border-primary transition-colors">
              <div className="text-4xl mb-4">🤖📦</div>
              <h3 className="text-xl font-semibold mb-2">Smart Inventory Agent</h3>
              <p className="text-muted-foreground mb-4">
                Demand forecasting, automated ordering, and multi-location optimization
              </p>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>✓ Predictive inventory planning</li>
                <li>✓ Supplier coordination</li>
                <li>✓ Stock level balancing</li>
                <li>✓ Quality monitoring</li>
              </ul>
            </div>

            {/* Compliance Agent */}
            <div className="bg-background rounded-lg p-6 border border-border hover:border-primary transition-colors">
              <div className="text-4xl mb-4">🤖⚖️</div>
              <h3 className="text-xl font-semibold mb-2">Compliance Agent</h3>
              <p className="text-muted-foreground mb-4">
                Continuous regulatory monitoring and automated audit trail generation
              </p>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>✓ Regulatory monitoring</li>
                <li>✓ Audit trail automation</li>
                <li>✓ Risk assessment</li>
                <li>✓ Report generation</li>
              </ul>
            </div>

            {/* Growth Agent */}
            <div className="bg-background rounded-lg p-6 border border-border hover:border-primary transition-colors">
              <div className="text-4xl mb-4">🤖📊</div>
              <h3 className="text-xl font-semibold mb-2">Growth Prediction Agent</h3>
              <p className="text-muted-foreground mb-4">
                Scaling readiness analysis and cross-business optimization
              </p>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>✓ Infrastructure planning</li>
                <li>✓ Market opportunity analysis</li>
                <li>✓ Resource allocation</li>
                <li>✓ Performance optimization</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">
            How It Works
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="w-16 h-16 bg-primary text-primary-foreground rounded-full flex items-center justify-center text-2xl font-bold mx-auto mb-4">1</div>
              <h3 className="text-xl font-semibold mb-2">Connect Your Businesses</h3>
              <p className="text-muted-foreground">
                Link your existing tools and data sources in minutes. No complex migration required.
              </p>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-primary text-primary-foreground rounded-full flex items-center justify-center text-2xl font-bold mx-auto mb-4">2</div>
              <h3 className="text-xl font-semibold mb-2">Deploy AI Agents</h3>
              <p className="text-muted-foreground">
                Choose which operations to automate. Agents learn your business and start working immediately.
              </p>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-primary text-primary-foreground rounded-full flex items-center justify-center text-2xl font-bold mx-auto mb-4">3</div>
              <h3 className="text-xl font-semibold mb-2">Focus on Growth</h3>
              <p className="text-muted-foreground">
                Watch your dashboard as AI handles operations. You focus on strategy and scaling.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Social Proof */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">
            Trusted by Serial Entrepreneurs
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            <div className="bg-background rounded-lg p-6 shadow-sm border border-border">
              <div className="flex items-center mb-4">
                <div className="w-12 h-12 bg-primary/10 rounded-full mr-4"></div>
                <div>
                  <div className="font-semibold">Sarah Chen</div>
                  <div className="text-sm text-muted-foreground">3 E-commerce Businesses</div>
                </div>
              </div>
              <p className="text-muted-foreground mb-4">
                "CoreFlow360 saved me 40 hours per week. I went from drowning in operations to launching my 4th business."
              </p>
              <div className="text-sm font-semibold text-primary">ROI: 847% in 6 months</div>
            </div>

            <div className="bg-background rounded-lg p-6 shadow-sm border border-border">
              <div className="flex items-center mb-4">
                <div className="w-12 h-12 bg-primary/10 rounded-full mr-4"></div>
                <div>
                  <div className="font-semibold">Marcus Johnson</div>
                  <div className="text-sm text-muted-foreground">SaaS Portfolio (5 products)</div>
                </div>
              </div>
              <p className="text-muted-foreground mb-4">
                "The AI agents handle everything. I focus on product strategy while my revenue grew 3x."
              </p>
              <div className="text-sm font-semibold text-primary">Time saved: 35 hrs/week</div>
            </div>

            <div className="bg-background rounded-lg p-6 shadow-sm border border-border">
              <div className="flex items-center mb-4">
                <div className="w-12 h-12 bg-primary/10 rounded-full mr-4"></div>
                <div>
                  <div className="font-semibold">Elena Rodriguez</div>
                  <div className="text-sm text-muted-foreground">Digital Agency + 2 Service Businesses</div>
                </div>
              </div>
              <p className="text-muted-foreground mb-4">
                "I was skeptical about AI, but CoreFlow360 proved itself in week one. Now I can't imagine going back."
              </p>
              <div className="text-sm font-semibold text-primary">Errors reduced: 94%</div>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-4">
            Simple, Transparent Pricing
          </h2>
          <p className="text-center text-muted-foreground mb-12">
            Start free, scale as you grow
          </p>

          <div className="grid md:grid-cols-4 gap-6">
            {/* Starter */}
            <div className="bg-background rounded-lg p-6 border border-border">
              <h3 className="text-xl font-semibold mb-2">Starter</h3>
              <div className="text-3xl font-bold mb-4">$0<span className="text-base font-normal text-muted-foreground">/mo</span></div>
              <ul className="space-y-2 mb-6 text-sm">
                <li className="flex items-start"><span className="mr-2">✓</span>1 business</li>
                <li className="flex items-start"><span className="mr-2">✓</span>2 AI agents</li>
                <li className="flex items-start"><span className="mr-2">✓</span>1,000 tasks/month</li>
                <li className="flex items-start"><span className="mr-2">✓</span>Basic analytics</li>
              </ul>
              <Link
                to="/auth/register"
                className="block w-full text-center px-4 py-2 bg-secondary text-secondary-foreground rounded-md hover:bg-secondary/80"
              >
                Get Started
              </Link>
            </div>

            {/* Professional */}
            <div className="bg-background rounded-lg p-6 border-2 border-primary relative">
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-primary text-primary-foreground px-3 py-1 rounded-full text-xs font-semibold">
                POPULAR
              </div>
              <h3 className="text-xl font-semibold mb-2">Professional</h3>
              <div className="text-3xl font-bold mb-4">$99<span className="text-base font-normal text-muted-foreground">/mo</span></div>
              <ul className="space-y-2 mb-6 text-sm">
                <li className="flex items-start"><span className="mr-2">✓</span>5 businesses</li>
                <li className="flex items-start"><span className="mr-2">✓</span>Unlimited AI agents</li>
                <li className="flex items-start"><span className="mr-2">✓</span>10,000 tasks/month</li>
                <li className="flex items-start"><span className="mr-2">✓</span>Advanced analytics</li>
                <li className="flex items-start"><span className="mr-2">✓</span>Priority support</li>
              </ul>
              <Link
                to="/auth/register"
                className="block w-full text-center px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
              >
                Start Trial
              </Link>
            </div>

            {/* Premium */}
            <div className="bg-background rounded-lg p-6 border border-border">
              <h3 className="text-xl font-semibold mb-2">Premium</h3>
              <div className="text-3xl font-bold mb-4">$299<span className="text-base font-normal text-muted-foreground">/mo</span></div>
              <ul className="space-y-2 mb-6 text-sm">
                <li className="flex items-start"><span className="mr-2">✓</span>Unlimited businesses</li>
                <li className="flex items-start"><span className="mr-2">✓</span>Unlimited agents</li>
                <li className="flex items-start"><span className="mr-2">✓</span>Unlimited tasks</li>
                <li className="flex items-start"><span className="mr-2">✓</span>ML-powered analytics</li>
                <li className="flex items-start"><span className="mr-2">✓</span>White-label</li>
                <li className="flex items-start"><span className="mr-2">✓</span>Dedicated success manager</li>
              </ul>
              <Link
                to="/auth/register"
                className="block w-full text-center px-4 py-2 bg-secondary text-secondary-foreground rounded-md hover:bg-secondary/80"
              >
                Start Trial
              </Link>
            </div>

            {/* Enterprise */}
            <div className="bg-background rounded-lg p-6 border border-border">
              <h3 className="text-xl font-semibold mb-2">Enterprise</h3>
              <div className="text-3xl font-bold mb-4">Custom</div>
              <ul className="space-y-2 mb-6 text-sm">
                <li className="flex items-start"><span className="mr-2">✓</span>Everything in Premium</li>
                <li className="flex items-start"><span className="mr-2">✓</span>Custom SLA</li>
                <li className="flex items-start"><span className="mr-2">✓</span>On-premise option</li>
                <li className="flex items-start"><span className="mr-2">✓</span>SAML/SSO</li>
                <li className="flex items-start"><span className="mr-2">✓</span>Legal review support</li>
              </ul>
              <a
                href="mailto:enterprise@coreflow360.com"
                className="block w-full text-center px-4 py-2 bg-secondary text-secondary-foreground rounded-md hover:bg-secondary/80"
              >
                Contact Sales
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="py-20 px-4">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">
            Frequently Asked Questions
          </h2>
          <div className="space-y-6">
            <details className="bg-background rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">How is this different from traditional ERP/CRM systems?</summary>
              <p className="mt-4 text-muted-foreground">
                Traditional systems require manual data entry and human decision-making. CoreFlow360's AI agents operate autonomously, learning from your business patterns and handling operations without human intervention.
              </p>
            </details>

            <details className="bg-background rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">How long does setup take?</summary>
              <p className="mt-4 text-muted-foreground">
                Most customers are operational within 2-10 minutes. Connect your data sources, deploy your first AI agent, and watch it start working immediately. No complex migration or training required.
              </p>
            </details>

            <details className="bg-background rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">Is my data secure?</summary>
              <p className="mt-4 text-muted-foreground">
                Yes. We're SOC 2 Type II compliant with zero-trust architecture, end-to-end encryption, and granular access controls. Your data is isolated per business and never shared.
              </p>
            </details>

            <details className="bg-background rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">Can I cancel anytime?</summary>
              <p className="mt-4 text-muted-foreground">
                Absolutely. No contracts, no commitments. Cancel anytime with one click. Your data remains accessible for 30 days after cancellation.
              </p>
            </details>

            <details className="bg-background rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">What if the AI makes a mistake?</summary>
              <p className="mt-4 text-muted-foreground">
                All AI actions are logged with full audit trails. You can review, override, or rollback any automated action. Critical operations can require human approval before execution.
              </p>
            </details>
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            Ready to Scale Without the Operational Overhead?
          </h2>
          <p className="text-xl text-muted-foreground mb-8">
            Join serial entrepreneurs who are building empires while AI handles the operations
          </p>
          <Link
            to="/auth/register"
            className="inline-block px-8 py-4 bg-primary text-primary-foreground rounded-lg text-lg font-semibold hover:bg-primary/90 transition-colors"
            onClick={() => Analytics.trackFunnel.signupStarted()}
          >
            Start Free Trial — No Credit Card Required
          </Link>
          <p className="mt-4 text-sm text-muted-foreground">
            2-minute setup • Free forever plan available • Cancel anytime
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t py-12 px-4">
        <div className="max-w-7xl mx-auto grid md:grid-cols-4 gap-8">
          <div>
            <h3 className="font-semibold mb-4">CoreFlow360 V4</h3>
            <p className="text-sm text-muted-foreground">
              AI-first business platform for serial entrepreneurs
            </p>
          </div>
          <div>
            <h4 className="font-semibold mb-4">Product</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><a href="#features">Features</a></li>
              <li><a href="#pricing">Pricing</a></li>
              <li><a href="#demo">Demo</a></li>
            </ul>
          </div>
          <div>
            <h4 className="font-semibold mb-4">Resources</h4>
            <ul className="space-y-2 text-muted-foreground">
              <li><a href="/docs">Documentation</a></li>
              <li><a href="/api">API</a></li>
              <li><a href="/help">Help Center</a></li>
            </ul>
          </div>
          <div>
            <h4 className="font-semibold mb-4">Company</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><a href="/contact">Contact</a></li>
              <li><a href="/privacy">Privacy</a></li>
              <li><a href="/terms">Terms</a></li>
            </ul>
          </div>
        </div>
        <div className="max-w-7xl mx-auto mt-8 pt-8 border-t text-center text-sm text-muted-foreground">
          © 2025 CoreFlow360. All rights reserved.
        </div>
      </footer>
    </div>
  )
}
