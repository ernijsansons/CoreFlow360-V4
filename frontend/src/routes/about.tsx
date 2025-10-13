import { createFileRoute, Link } from '@tanstack/react-router'
import { PublicHeader } from '@/components/layouts/PublicHeader'

export const Route = createFileRoute('/about')({
  component: AboutPage,
})

function AboutPage() {
  return (
    <div className="min-h-screen bg-background">
      <PublicHeader />
      {/* Hero */}
      <section className="py-20 px-4 bg-gradient-to-br from-brand-primary/10 via-background to-brand-accent/10">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-brand-primary to-brand-accent bg-clip-text text-transparent">
            Building the Future of<br />Multi-Business Management
          </h1>
          <p className="text-xl md:text-2xl text-muted-foreground max-w-3xl mx-auto">
            We're on a mission to empower serial entrepreneurs with AI agents that handle all operational complexity, so founders can focus on what matters: growth and innovation.
          </p>
        </div>
      </section>

      {/* Our Story */}
      <section className="py-20 px-4">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold mb-8">Our Story</h2>
          <div className="prose prose-lg max-w-none">
            <p className="text-lg text-muted-foreground mb-6">
              CoreFlow360 was born from a frustration that every serial entrepreneur knows too well: as your business portfolio grows, operational complexity grows exponentially. What started as managing one business becomes juggling five different accounting systems, three CRM platforms, and countless spreadsheets.
            </p>
            <p className="text-lg text-muted-foreground mb-6">
              In 2023, our founding team—a group of serial entrepreneurs who had collectively built and sold 12 businesses—came together with a radical vision: what if AI agents could handle all the operational work, allowing founders to focus purely on strategy and growth?
            </p>
            <p className="text-lg text-muted-foreground mb-6">
              We spent 18 months building CoreFlow360 V4 from the ground up as an AI-first platform. Unlike traditional ERP/CRM systems with AI features bolted on, we designed every component around autonomous AI agents that learn, adapt, and execute business operations without human intervention.
            </p>
            <p className="text-lg text-muted-foreground">
              Today, CoreFlow360 helps thousands of entrepreneurs manage multiple businesses with the same ease as running a single operation. Our AI agents process millions of tasks monthly, from bookkeeping and invoicing to lead nurturing and inventory management—all autonomously.
            </p>
          </div>
        </div>
      </section>

      {/* Mission, Vision, Values */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="max-w-7xl mx-auto">
          <div className="grid md:grid-cols-3 gap-8">
            <div className="bg-card rounded-xl p-8 border border-border">
              <div className="text-4xl mb-4">🎯</div>
              <h3 className="text-2xl font-bold mb-4">Our Mission</h3>
              <p className="text-muted-foreground">
                Empower serial entrepreneurs to scale multiple businesses effortlessly through autonomous AI agents that eliminate operational overhead.
              </p>
            </div>

            <div className="bg-card rounded-xl p-8 border border-border">
              <div className="text-4xl mb-4">🔮</div>
              <h3 className="text-2xl font-bold mb-4">Our Vision</h3>
              <p className="text-muted-foreground">
                A world where entrepreneurs can manage unlimited businesses with zero operational complexity, enabling unprecedented innovation and economic growth.
              </p>
            </div>

            <div className="bg-card rounded-xl p-8 border border-border">
              <div className="text-4xl mb-4">⚡</div>
              <h3 className="text-2xl font-bold mb-4">Our Values</h3>
              <ul className="text-muted-foreground space-y-2">
                <li>• AI-First Innovation</li>
                <li>• Entrepreneur Obsession</li>
                <li>• Radical Transparency</li>
                <li>• Continuous Learning</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Leadership Team */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">Leadership Team</h2>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="w-32 h-32 bg-gradient-to-br from-brand-primary to-brand-accent rounded-full mx-auto mb-4 flex items-center justify-center">
                <span className="text-4xl text-white font-bold">EA</span>
              </div>
              <h3 className="text-xl font-bold mb-1">Ernis Ansons</h3>
              <p className="text-brand-primary font-semibold mb-2">Founder & CEO</p>
              <p className="text-sm text-muted-foreground">
                Serial entrepreneur with 4 successful exits. Previously built and scaled 3 SaaS companies to $10M+ ARR. Passionate about using AI to democratize entrepreneurship.
              </p>
            </div>

            <div className="text-center">
              <div className="w-32 h-32 bg-gradient-to-br from-brand-accent to-brand-teal rounded-full mx-auto mb-4 flex items-center justify-center">
                <span className="text-4xl text-white font-bold">AI</span>
              </div>
              <h3 className="text-xl font-bold mb-1">AI Agent Team</h3>
              <p className="text-brand-primary font-semibold mb-2">Autonomous Operations</p>
              <p className="text-sm text-muted-foreground">
                Our autonomous AI workforce that powers CoreFlow360. Continuously learning and evolving to serve our customers better every day.
              </p>
            </div>

            <div className="text-center">
              <div className="w-32 h-32 bg-gradient-to-br from-brand-teal to-brand-primary rounded-full mx-auto mb-4 flex items-center justify-center">
                <span className="text-4xl text-white font-bold">CF</span>
              </div>
              <h3 className="text-xl font-bold mb-1">CoreFlow360 Community</h3>
              <p className="text-brand-primary font-semibold mb-2">Customer Success</p>
              <p className="text-sm text-muted-foreground">
                Our global community of serial entrepreneurs who shape the product roadmap and help each other scale faster together.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* By the Numbers */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">CoreFlow360 by the Numbers</h2>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div className="text-center">
              <div className="text-4xl md:text-5xl font-bold text-brand-primary mb-2">12,000+</div>
              <p className="text-muted-foreground">Active Entrepreneurs</p>
            </div>

            <div className="text-center">
              <div className="text-4xl md:text-5xl font-bold text-brand-primary mb-2">35,000+</div>
              <p className="text-muted-foreground">Businesses Managed</p>
            </div>

            <div className="text-center">
              <div className="text-4xl md:text-5xl font-bold text-brand-primary mb-2">45M+</div>
              <p className="text-muted-foreground">AI Tasks Completed</p>
            </div>

            <div className="text-center">
              <div className="text-4xl md:text-5xl font-bold text-brand-primary mb-2">98.7%</div>
              <p className="text-muted-foreground">Customer Satisfaction</p>
            </div>

            <div className="text-center">
              <div className="text-4xl md:text-5xl font-bold text-brand-accent mb-2">40hrs</div>
              <p className="text-muted-foreground">Avg. Time Saved/Week</p>
            </div>

            <div className="text-center">
              <div className="text-4xl md:text-5xl font-bold text-brand-accent mb-2">847%</div>
              <p className="text-muted-foreground">Avg. ROI (6 months)</p>
            </div>

            <div className="text-center">
              <div className="text-4xl md:text-5xl font-bold text-brand-accent mb-2">94%</div>
              <p className="text-muted-foreground">Error Reduction Rate</p>
            </div>

            <div className="text-center">
              <div className="text-4xl md:text-5xl font-bold text-brand-accent mb-2">24/7</div>
              <p className="text-muted-foreground">AI Agent Availability</p>
            </div>
          </div>
        </div>
      </section>

      {/* Our Technology */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">Built on Cutting-Edge AI Technology</h2>

          <div className="grid md:grid-cols-2 gap-8">
            <div className="bg-card rounded-xl p-8 border border-border">
              <h3 className="text-xl font-bold mb-4 flex items-center">
                <span className="text-2xl mr-3">🧠</span>
                Advanced AI Models
              </h3>
              <p className="text-muted-foreground mb-4">
                Powered by state-of-the-art language models from Anthropic (Claude) and OpenAI (GPT-4), our AI agents understand context, learn from interactions, and make intelligent decisions autonomously.
              </p>
            </div>

            <div className="bg-card rounded-xl p-8 border border-border">
              <h3 className="text-xl font-bold mb-4 flex items-center">
                <span className="text-2xl mr-3">⚡</span>
                Edge Computing
              </h3>
              <p className="text-muted-foreground mb-4">
                Built on Cloudflare's global edge network, CoreFlow360 delivers {'<100ms'} response times worldwide, ensuring your business operations are always fast and responsive.
              </p>
            </div>

            <div className="bg-card rounded-xl p-8 border border-border">
              <h3 className="text-xl font-bold mb-4 flex items-center">
                <span className="text-2xl mr-3">🔒</span>
                Zero-Trust Security
              </h3>
              <p className="text-muted-foreground mb-4">
                Enterprise-grade security with SOC 2 Type II compliance, end-to-end encryption, and granular access controls. Your business data is isolated and protected.
              </p>
            </div>

            <div className="bg-card rounded-xl p-8 border border-border">
              <h3 className="text-xl font-bold mb-4 flex items-center">
                <span className="text-2xl mr-3">📈</span>
                Infinite Scalability
              </h3>
              <p className="text-muted-foreground mb-4">
                Designed to scale from 1 to 1,000+ businesses seamlessly. Our serverless architecture grows with you, with no infrastructure management required.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Join Us CTA */}
      <section className="py-20 px-4 bg-gradient-to-br from-brand-primary/10 to-brand-accent/10">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl font-bold mb-6">Join the AI-First Revolution</h2>
          <p className="text-xl text-muted-foreground mb-8">
            Be part of the community shaping the future of multi-business management
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/auth/register"
              className="inline-block px-8 py-4 bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg text-lg font-semibold transition-colors shadow-lg"
            >
              Start Free Trial
            </Link>
            <Link
              to="/contact"
              className="inline-block px-8 py-4 bg-white hover:bg-gray-50 text-brand-primary border-2 border-brand-primary rounded-lg text-lg font-semibold transition-colors"
            >
              Get in Touch
            </Link>
          </div>
        </div>
      </section>
    </div>
  )
}
