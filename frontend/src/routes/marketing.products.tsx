import { createFileRoute } from '@tanstack/react-router';
import { MarketingLayout } from '../components/marketing/MarketingLayout';
import { Bot, Database, FileText, Users, TrendingUp, Workflow } from 'lucide-react';

export const Route = createFileRoute('/marketing/products')({
  component: ProductsPage
});

function ProductsPage() {
  const aiAgents = [
    {
      icon: FileText,
      name: "Finance Agent",
      description: "Handles accounting, invoicing, payments, and financial reporting autonomously",
      features: ["Double-entry bookkeeping", "Multi-currency support", "Tax calculations", "Financial forecasting"]
    },
    {
      icon: Users,
      name: "CRM Agent",
      description: "Manages customer relationships, lead nurturing, and sales pipeline automatically",
      features: ["Lead qualification", "Automated follow-ups", "Deal progression", "Customer intelligence"]
    },
    {
      icon: Database,
      name: "Inventory Agent",
      description: "Optimizes stock levels, supplier coordination, and demand forecasting",
      features: ["Demand forecasting", "Auto-reordering", "Multi-location sync", "Quality tracking"]
    },
    {
      icon: Workflow,
      name: "Workflow Agent",
      description: "Orchestrates business processes and automation across all systems",
      features: ["Process automation", "Task routing", "Integration sync", "Error handling"]
    },
    {
      icon: TrendingUp,
      name: "Analytics Agent",
      description: "Provides cross-business insights and predictive analytics",
      features: ["Real-time dashboards", "Predictive models", "Anomaly detection", "Custom reports"]
    },
    {
      icon: Bot,
      name: "Custom Agents",
      description: "Train specialized AI agents for your unique business processes",
      features: ["Custom training", "Industry-specific", "API integrations", "Continuous learning"]
    }
  ];

  return (
    <MarketingLayout>
      {/* Hero */}
      <section className="py-20 bg-gradient-to-b from-slate-50 to-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-4xl sm:text-6xl font-bold text-slate-900 mb-6">
            AI Agents That Run Your <span className="bg-gradient-to-r from-brand-primary-600 to-brand-accent-600 bg-clip-text text-transparent">Business</span>
          </h1>
          <p className="text-xl text-slate-600 max-w-3xl mx-auto">
            Autonomous AI agents handle all operations - from accounting to customer relations - while you focus on strategic growth
          </p>
        </div>
      </section>

      {/* AI Agents Grid */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {aiAgents.map((agent, index) => {
              const Icon = agent.icon;
              return (
                <div
                  key={index}
                  className="bg-slate-50 rounded-2xl p-8 border border-slate-200 hover:border-brand-primary-300 hover:shadow-lg transition-all"
                >
                  <div className="w-14 h-14 bg-gradient-to-br from-brand-primary-600 to-brand-accent-600 rounded-xl flex items-center justify-center mb-6">
                    <Icon className="text-white" size={28} />
                  </div>
                  <h3 className="text-2xl font-bold text-slate-900 mb-3">{agent.name}</h3>
                  <p className="text-slate-600 mb-6">{agent.description}</p>
                  <ul className="space-y-2">
                    {agent.features.map((feature, idx) => (
                      <li key={idx} className="flex items-center text-sm text-slate-700">
                        <div className="w-1.5 h-1.5 bg-brand-primary-600 rounded-full mr-2" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 bg-slate-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-slate-900 mb-4">
              How AI Agents Work
            </h2>
            <p className="text-xl text-slate-600 max-w-2xl mx-auto">
              Intelligent automation that learns and adapts to your business
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-12">
            <div className="text-center">
              <div className="w-16 h-16 bg-brand-primary-100 rounded-full flex items-center justify-center mx-auto mb-6">
                <span className="text-2xl font-bold text-brand-primary-600">1</span>
              </div>
              <h3 className="text-xl font-bold text-slate-900 mb-3">Connect & Learn</h3>
              <p className="text-slate-600">
                AI agents connect to your systems and learn your business processes automatically
              </p>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-brand-accent-100 rounded-full flex items-center justify-center mx-auto mb-6">
                <span className="text-2xl font-bold text-brand-accent-600">2</span>
              </div>
              <h3 className="text-xl font-bold text-slate-900 mb-3">Automate & Optimize</h3>
              <p className="text-slate-600">
                Agents handle tasks autonomously, making decisions based on your rules and preferences
              </p>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-6">
                <span className="text-2xl font-bold text-green-600">3</span>
              </div>
              <h3 className="text-xl font-bold text-slate-900 mb-3">Scale & Grow</h3>
              <p className="text-slate-600">
                As you add businesses, agents scale automatically with zero additional overhead
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Integrations */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl sm:text-4xl font-bold text-slate-900 mb-4">
            Integrates with Your Stack
          </h2>
          <p className="text-xl text-slate-600 mb-12 max-w-2xl mx-auto">
            Connect with 1000+ tools and platforms. If we don't have it, we'll build it.
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-6">
            {['Stripe', 'PayPal', 'QuickBooks', 'Salesforce', 'Shopify', 'Slack', 'Gmail', 'Twilio', 'AWS', 'Google Cloud', 'Zapier', 'API'].map((tool, index) => (
              <div key={index} className="bg-slate-50 rounded-lg p-6 border border-slate-200 hover:border-brand-primary-300 transition-colors">
                <div className="font-semibold text-slate-700">{tool}</div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </MarketingLayout>
  );
}
