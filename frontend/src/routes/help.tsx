import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'

export const Route = createFileRoute('/help')({
  component: HelpCenterPage,
})

function HelpCenterPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [, setSelectedCategory] = useState<string | null>(null)

  const categories = [
    {
      id: 'getting-started',
      title: 'Getting Started',
      icon: '🚀',
      articles: [
        { title: 'Quick Start Guide', description: 'Get up and running in 2 minutes' },
        { title: 'Creating Your First Business', description: 'Step-by-step business setup' },
        { title: 'Deploying AI Agents', description: 'How to activate and configure AI agents' },
        { title: 'Connecting Integrations', description: 'Link your existing tools and data sources' },
      ],
    },
    {
      id: 'ai-agents',
      title: 'AI Agents',
      icon: '🤖',
      articles: [
        { title: 'Understanding AI Agents', description: 'What AI agents do and how they work' },
        { title: 'Finance Agent Guide', description: 'Automated bookkeeping and invoicing' },
        { title: 'CRM Agent Guide', description: 'Autonomous customer relationship management' },
        { title: 'Inventory Agent Guide', description: 'Smart inventory and demand forecasting' },
        { title: 'Customizing Agent Behavior', description: 'Configure agents to match your workflow' },
        { title: 'Agent Task Limits', description: 'Understanding and managing task quotas' },
      ],
    },
    {
      id: 'multi-business',
      title: 'Multi-Business Management',
      icon: '🏢',
      articles: [
        { title: 'Adding Multiple Businesses', description: 'How to scale to multiple businesses' },
        { title: 'Portfolio Dashboard', description: 'View all your businesses at a glance' },
        { title: 'Cross-Business Analytics', description: 'Consolidated reporting and insights' },
        { title: 'Business Isolation & Security', description: 'How data is separated between businesses' },
      ],
    },
    {
      id: 'billing',
      title: 'Billing & Subscriptions',
      icon: '💳',
      articles: [
        { title: 'Pricing Plans Explained', description: 'Compare plans and features' },
        { title: 'Upgrading Your Plan', description: 'How to upgrade to a paid plan' },
        { title: 'Managing Payment Methods', description: 'Update credit cards and billing info' },
        { title: 'Invoices & Receipts', description: 'Download invoices and payment history' },
        { title: 'Canceling Your Subscription', description: 'How to cancel and what happens next' },
      ],
    },
    {
      id: 'security',
      title: 'Security & Privacy',
      icon: '🔒',
      articles: [
        { title: 'Data Security Overview', description: 'How we protect your business data' },
        { title: 'Two-Factor Authentication', description: 'Enable 2FA for enhanced security' },
        { title: 'Role-Based Access Control', description: 'Managing team member permissions' },
        { title: 'Audit Logs', description: 'Track all actions in your account' },
        { title: 'GDPR Compliance', description: 'Data privacy and user rights' },
      ],
    },
    {
      id: 'integrations',
      title: 'Integrations & API',
      icon: '🔌',
      articles: [
        { title: 'Available Integrations', description: 'Connect with popular tools' },
        { title: 'API Documentation', description: 'Build custom integrations' },
        { title: 'Webhooks Guide', description: 'Real-time event notifications' },
        { title: 'Stripe Integration', description: 'Accept payments seamlessly' },
        { title: 'PayPal Integration', description: 'Alternative payment processing' },
      ],
    },
    {
      id: 'troubleshooting',
      title: 'Troubleshooting',
      icon: '🔧',
      articles: [
        { title: 'Common Login Issues', description: 'Resolve authentication problems' },
        { title: 'AI Agent Not Working', description: 'Debug agent activation issues' },
        { title: 'Data Sync Problems', description: 'Fix integration sync errors' },
        { title: 'Performance Issues', description: 'Optimize dashboard loading speed' },
        { title: 'Browser Compatibility', description: 'Supported browsers and versions' },
      ],
    },
  ]

  const popularArticles = [
    { title: 'Quick Start Guide', category: 'Getting Started', views: '12.5K' },
    { title: 'Understanding AI Agents', category: 'AI Agents', views: '8.3K' },
    { title: 'Pricing Plans Explained', category: 'Billing', views: '7.1K' },
    { title: 'Two-Factor Authentication', category: 'Security', views: '5.9K' },
  ]

  return (
    <div className="min-h-screen bg-background">
      <PublicHeader />
      {/* Hero & Search */}
      <section className="py-20 px-4 bg-gradient-to-br from-brand-primary/10 via-background to-brand-accent/10">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-brand-primary to-brand-accent bg-clip-text text-transparent">
            How can we help you?
          </h1>
          <p className="text-xl text-muted-foreground mb-8">
            Search our knowledge base or browse by category
          </p>

          <div className="relative max-w-2xl mx-auto">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search for articles, guides, and tutorials..."
              className="w-full px-6 py-4 pr-12 bg-card border-2 border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-brand-primary text-lg shadow-lg"
            />
            <button className="absolute right-4 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-brand-primary">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </button>
          </div>

          <div className="mt-6 flex flex-wrap gap-2 justify-center">
            <span className="text-sm text-muted-foreground">Popular searches:</span>
            <button className="text-sm text-brand-primary hover:underline">AI agents</button>
            <span className="text-muted-foreground">•</span>
            <button className="text-sm text-brand-primary hover:underline">billing</button>
            <span className="text-muted-foreground">•</span>
            <button className="text-sm text-brand-primary hover:underline">integrations</button>
            <span className="text-muted-foreground">•</span>
            <button className="text-sm text-brand-primary hover:underline">security</button>
          </div>
        </div>
      </section>

      {/* Quick Links */}
      <section className="py-12 px-4 bg-muted/30">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Link
              to="/auth/register"
              className="bg-card rounded-lg p-6 text-center border border-border hover:border-brand-primary transition-colors"
            >
              <div className="text-3xl mb-2">📖</div>
              <p className="font-semibold">Getting Started</p>
            </Link>

            <a
              href="https://api.coreflow360.com/docs"
              className="bg-card rounded-lg p-6 text-center border border-border hover:border-brand-primary transition-colors"
            >
              <div className="text-3xl mb-2">📚</div>
              <p className="font-semibold">API Docs</p>
            </a>

            <Link
              to="/contact"
              className="bg-card rounded-lg p-6 text-center border border-border hover:border-brand-primary transition-colors"
            >
              <div className="text-3xl mb-2">💬</div>
              <p className="font-semibold">Contact Support</p>
            </Link>

            <a
              href="#status"
              className="bg-card rounded-lg p-6 text-center border border-border hover:border-brand-primary transition-colors"
            >
              <div className="text-3xl mb-2">✅</div>
              <p className="font-semibold">System Status</p>
            </a>
          </div>
        </div>
      </section>

      {/* Categories */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl font-bold mb-12 text-center">Browse by Category</h2>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {categories.map((category) => (
              <div
                key={category.id}
                className="bg-card rounded-xl p-6 border border-border hover:border-brand-primary transition-colors cursor-pointer"
                onClick={() => setSelectedCategory(category.id)}
              >
                <div className="flex items-center mb-4">
                  <span className="text-4xl mr-4">{category.icon}</span>
                  <h3 className="text-xl font-bold">{category.title}</h3>
                </div>
                <ul className="space-y-2">
                  {category.articles.slice(0, 4).map((article, index) => (
                    <li key={index}>
                      <a href={`#${category.id}-${index}`} className="text-sm text-muted-foreground hover:text-brand-primary">
                        → {article.title}
                      </a>
                    </li>
                  ))}
                  {category.articles.length > 4 && (
                    <li>
                      <button className="text-sm text-brand-primary hover:underline">
                        View all {category.articles.length} articles →
                      </button>
                    </li>
                  )}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Popular Articles */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl font-bold mb-12 text-center">Most Popular Articles</h2>

          <div className="grid md:grid-cols-2 gap-6">
            {popularArticles.map((article, index) => (
              <a
                key={index}
                href={`#popular-${index}`}
                className="bg-card rounded-xl p-6 border border-border hover:border-brand-primary transition-colors flex items-start justify-between"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-2xl font-bold text-brand-primary">#{index + 1}</span>
                    <span className="text-xs bg-muted px-2 py-1 rounded">{article.category}</span>
                  </div>
                  <h3 className="text-lg font-semibold mb-1">{article.title}</h3>
                  <p className="text-sm text-muted-foreground">{article.views} views</p>
                </div>
                <svg className="w-5 h-5 text-muted-foreground flex-shrink-0 ml-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* Video Tutorials */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl font-bold mb-12 text-center">Video Tutorials</h2>

          <div className="grid md:grid-cols-3 gap-6">
            <div className="bg-card rounded-xl overflow-hidden border border-border hover:border-brand-primary transition-colors">
              <div className="aspect-video bg-gradient-to-br from-brand-primary to-brand-accent flex items-center justify-center">
                <div className="text-white text-6xl">▶️</div>
              </div>
              <div className="p-4">
                <h3 className="font-semibold mb-1">Getting Started with CoreFlow360</h3>
                <p className="text-sm text-muted-foreground">5:32</p>
              </div>
            </div>

            <div className="bg-card rounded-xl overflow-hidden border border-border hover:border-brand-primary transition-colors">
              <div className="aspect-video bg-gradient-to-br from-brand-accent to-brand-teal flex items-center justify-center">
                <div className="text-white text-6xl">▶️</div>
              </div>
              <div className="p-4">
                <h3 className="font-semibold mb-1">Deploying Your First AI Agent</h3>
                <p className="text-sm text-muted-foreground">8:14</p>
              </div>
            </div>

            <div className="bg-card rounded-xl overflow-hidden border border-border hover:border-brand-primary transition-colors">
              <div className="aspect-video bg-gradient-to-br from-brand-teal to-brand-primary flex items-center justify-center">
                <div className="text-white text-6xl">▶️</div>
              </div>
              <div className="p-4">
                <h3 className="font-semibold mb-1">Managing Multiple Businesses</h3>
                <p className="text-sm text-muted-foreground">12:45</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Still Need Help */}
      <section className="py-20 px-4 bg-gradient-to-br from-brand-primary/10 to-brand-accent/10">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl font-bold mb-6">Still need help?</h2>
          <p className="text-xl text-muted-foreground mb-8">
            Our support team is here to assist you
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/contact"
              className="inline-block px-8 py-4 bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg text-lg font-semibold transition-colors shadow-lg"
            >
              Contact Support
            </Link>
            <button className="inline-block px-8 py-4 bg-white hover:bg-gray-50 text-brand-primary border-2 border-brand-primary rounded-lg text-lg font-semibold transition-colors">
              Start Live Chat
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}
