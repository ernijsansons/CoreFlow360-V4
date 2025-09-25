import { memo, lazy, Suspense, useMemo } from 'react'
import { CheckCircle, ArrowRight, Zap, Shield, Users, BarChart3, Globe, Bot } from 'lucide-react'
import './App.css'

// Memoized feature data to prevent re-creation on every render
const featureData = [
  {
    icon: <Bot className="w-8 h-8 text-blue-600" />,
    title: "AI-Powered Automation",
    description: "Intelligent workflows that learn and adapt to your business processes automatically."
  },
  {
    icon: <Users className="w-8 h-8 text-purple-600" />,
    title: "Real-time Collaboration", 
    description: "Seamless team collaboration with live updates and instant notifications."
  },
  {
    icon: <BarChart3 className="w-8 h-8 text-green-600" />,
    title: "Advanced Analytics",
    description: "Deep insights into your operations with customizable dashboards and reports."
  },
  {
    icon: <Shield className="w-8 h-8 text-red-600" />,
    title: "Enterprise Security",
    description: "Bank-grade security with SOC2 compliance and advanced access controls."
  },
  {
    icon: <Globe className="w-8 h-8 text-indigo-600" />,
    title: "Multi-tenant Architecture",
    description: "Perfect data isolation with scalable infrastructure for any organization size."
  },
  {
    icon: <Zap className="w-8 h-8 text-yellow-600" />,
    title: "Edge Computing",
    description: "Lightning-fast performance with global edge deployment and caching."
  }
];

const pricingData = [
  {
    name: "Free",
    price: "$0",
    description: "Perfect for getting started",
    features: ["1,000 API calls/month", "3 users", "Basic workflows", "Community support"],
    popular: false
  },
  {
    name: "Starter",
    price: "$99",
    description: "For growing businesses", 
    features: ["10,000 API calls/month", "10 users", "Advanced workflows", "Priority support"],
    popular: false
  },
  {
    name: "Business",
    price: "$499",
    description: "For scaling organizations",
    features: ["100,000 API calls/month", "50 users", "Custom integrations", "Dedicated support"],
    popular: true
  },
  {
    name: "Enterprise",
    price: "Custom",
    description: "For large enterprises",
    features: ["Unlimited usage", "Unlimited users", "White-label options", "24/7 phone support"],
    popular: false
  }
];

const testimonialsData = [
  {
    quote: "CoreFlow360 transformed our operations completely. We've seen a 300% increase in productivity and our team loves the intuitive interface.",
    author: "Sarah Johnson",
    role: "CTO, TechCorp",
    company: "Fortune 500 Technology Company"
  },
  {
    quote: "The AI-powered automation features are game-changing. We've automated 80% of our manual processes and reduced errors by 95%.",
    author: "Michael Chen",
    role: "Operations Director", 
    company: "Global Manufacturing Leader"
  },
  {
    quote: "Security and compliance were our biggest concerns. CoreFlow360 exceeded all our expectations with SOC2 compliance and enterprise-grade security.",
    author: "Emily Rodriguez",
    role: "CISO, FinanceFirst",
    company: "Leading Financial Services"
  }
];

const App = memo(() => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      {/* Header */}
      <header className="border-b bg-white/95 backdrop-blur supports-[backdrop-filter]:bg-white/60">
        <div className="container mx-auto px-4 py-4">
          <nav className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="h-8 w-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-sm">CF</span>
              </div>
              <span className="text-xl font-bold text-gray-900">CoreFlow360</span>
              <span className="px-2 py-1 text-xs font-semibold bg-blue-100 text-blue-800 rounded-full">V4</span>
            </div>
            <div className="hidden md:flex items-center space-x-6">
              <a href="#features" className="text-gray-600 hover:text-gray-900 transition-colors">Features</a>
              <a href="#pricing" className="text-gray-600 hover:text-gray-900 transition-colors">Pricing</a>
              <a href="#testimonials" className="text-gray-600 hover:text-gray-900 transition-colors">Testimonials</a>
              <button className="px-3 py-2 text-sm border border-gray-300 bg-white hover:bg-gray-50 rounded-md transition-colors">Sign In</button>
              <button className="px-3 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors">Get Started</button>
            </div>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 lg:py-32">
        <div className="container mx-auto px-4 text-center">
          <span className="inline-flex items-center px-3 py-1 mb-4 text-sm font-semibold bg-blue-100 text-blue-800 rounded-full">
            <Zap className="w-3 h-3 mr-1" />
            AI-Powered Workflows
          </span>
          <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold text-gray-900 mb-6 leading-tight">
            Transform Your
            <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent"> Business </span>
            with Intelligent Automation
          </h1>
          <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto leading-relaxed">
            CoreFlow360 V4 delivers enterprise-grade workflow management with AI-powered automation,
            real-time collaboration, and advanced analytics. Scale your business operations with confidence.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-12">
            <button className="inline-flex items-center px-8 py-3 text-lg font-medium bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-md transition-colors">
              Start Free Trial
              <ArrowRight className="ml-2 h-4 w-4" />
            </button>
            <button className="inline-flex items-center px-8 py-3 text-lg font-medium border border-gray-300 bg-white hover:bg-gray-50 rounded-md transition-colors">
              Watch Demo
            </button>
          </div>

          {/* Status Indicators */}
          <div className="flex flex-wrap justify-center gap-8 text-sm text-gray-600">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span>System Operational</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-500" />
              <span>99.9% Uptime SLA</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-500" />
              <span>Enterprise Security</span>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 bg-white">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Powerful Features for Modern Businesses
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Everything you need to automate, optimize, and scale your operations
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {featureData.map((feature, index) => (
              <div key={index} className="group p-6 bg-white rounded-lg border border-gray-200 hover:border-blue-200 hover:shadow-lg transition-all duration-300">
                <div className="mb-4 group-hover:scale-110 transition-transform duration-300">
                  {feature.icon}
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-3">{feature.title}</h3>
                <p className="text-gray-600 text-base leading-relaxed">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-20 bg-gradient-to-br from-slate-50 to-blue-50">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Simple, Transparent Pricing
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Choose the perfect plan for your business needs
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8 max-w-7xl mx-auto">
            {pricingData.map((plan, index) => (
              <div key={index} className={`relative p-6 bg-white rounded-lg ${plan.popular ? 'border-2 border-blue-500 shadow-xl scale-105' : 'border border-gray-200'} hover:shadow-lg transition-all duration-300`}>
                {plan.popular && (
                  <span className="absolute -top-3 left-1/2 transform -translate-x-1/2 px-3 py-1 text-sm font-semibold bg-blue-600 text-white rounded-full">
                    Most Popular
                  </span>
                )}
                <div className="mb-6">
                  <h3 className="text-2xl font-bold text-gray-900 mb-2">{plan.name}</h3>
                  <div className="flex items-baseline mb-2">
                    <span className="text-4xl font-bold text-gray-900">{plan.price}</span>
                    {plan.price !== "Custom" && <span className="text-gray-600 ml-1">/month</span>}
                  </div>
                  <p className="text-gray-600">{plan.description}</p>
                </div>
                <ul className="space-y-3 mb-6">
                  {plan.features.map((feature, featureIndex) => (
                    <li key={featureIndex} className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-700">{feature}</span>
                    </li>
                  ))}
                </ul>
                <button className={`w-full px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                  plan.popular
                    ? 'bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white'
                    : plan.name === 'Free'
                      ? 'bg-gray-900 hover:bg-gray-800 text-white'
                      : 'border border-gray-300 bg-white hover:bg-gray-50 text-gray-900'
                }`}>
                  {plan.name === 'Free' ? 'Get Started' : plan.name === 'Enterprise' ? 'Contact Sales' : 'Start Trial'}
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section id="testimonials" className="py-20 bg-white">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Trusted by Industry Leaders
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              See what our customers are saying about CoreFlow360
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {testimonialsData.map((testimonial, index) => (
              <div key={index} className="p-6 bg-white rounded-lg border border-gray-200 hover:shadow-lg transition-all duration-300">
                <div className="flex mb-4">
                  {[...Array(5)].map((_, i) => (
                    <div key={i} className="w-5 h-5 text-yellow-400">⭐</div>
                  ))}
                </div>
                <blockquote className="text-gray-700 mb-6 italic leading-relaxed">
                  "{testimonial.quote}"
                </blockquote>
                <div>
                  <div className="font-semibold text-gray-900">{testimonial.author}</div>
                  <div className="text-gray-600">{testimonial.role}</div>
                  <div className="text-sm text-gray-500">{testimonial.company}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gradient-to-r from-blue-600 to-purple-600">
        <div className="container mx-auto px-4 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Ready to Transform Your Business?
          </h2>
          <p className="text-xl text-blue-100 mb-8 max-w-2xl mx-auto">
            Join thousands of companies already using CoreFlow360 to automate their workflows and boost productivity.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button className="inline-flex items-center px-8 py-3 text-lg font-medium bg-white text-blue-600 hover:bg-gray-100 rounded-md transition-colors">
              Start Free Trial
              <ArrowRight className="ml-2 h-4 w-4" />
            </button>
            <button className="inline-flex items-center px-8 py-3 text-lg font-medium border border-white text-white hover:bg-white hover:text-blue-600 rounded-md transition-colors">
              Schedule Demo
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-gray-300 py-12">
        <div className="container mx-auto px-4">
          <div className="grid md:grid-cols-4 gap-8">
            <div>
              <div className="flex items-center space-x-2 mb-4">
                <div className="h-8 w-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
                  <span className="text-white font-bold text-sm">CF</span>
                </div>
                <span className="text-xl font-bold text-white">CoreFlow360</span>
              </div>
              <p className="text-gray-400 mb-4">
                Enterprise workflow management with AI-powered automation.
              </p>
            </div>
            <div>
              <h3 className="text-white font-semibold mb-4">Product</h3>
              <ul className="space-y-2">
                <li><a href="#" className="hover:text-white transition-colors">Features</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Pricing</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Security</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Integrations</a></li>
              </ul>
            </div>
            <div>
              <h3 className="text-white font-semibold mb-4">Company</h3>
              <ul className="space-y-2">
                <li><a href="#" className="hover:text-white transition-colors">About</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Blog</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Careers</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Contact</a></li>
              </ul>
            </div>
            <div>
              <h3 className="text-white font-semibold mb-4">Support</h3>
              <ul className="space-y-2">
                <li><a href="#" className="hover:text-white transition-colors">Help Center</a></li>
                <li><a href="#" className="hover:text-white transition-colors">API Docs</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Status</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Privacy</a></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-gray-800 mt-8 pt-8 text-center text-gray-400">
            <p>&copy; 2024 CoreFlow360. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  )
})

App.displayName = 'App'

export default App
