export interface Feature {
  icon: string
  title: string
  description: string
  stat?: string
}

export interface Testimonial {
  name: string
  role: string
  company: string
  quote: string
  avatar: string
  rating: number
}

export interface PricingTier {
  name: string
  price: number
  period: string
  description: string
  features: string[]
  cta: string
  highlighted?: boolean
}

export const features: Feature[] = [
  {
    icon: 'rocket',
    title: 'Autonomous Finance Agent',
    description: 'AI-powered double-entry bookkeeping, tax calculations, and cash flow forecasting-all running in the background.',
    stat: '95% faster reconciliation',
  },
  {
    icon: 'users',
    title: 'Intelligent CRM Agent',
    description: 'Automated lead qualification, nurturing sequences, and deal progression without manual intervention.',
    stat: '2x lead conversion',
  },
  {
    icon: 'cube',
    title: 'Smart Inventory Agent',
    description: 'Demand forecasting, supplier coordination, and multi-location optimization powered by AI.',
    stat: '30% cost reduction',
  },
  {
    icon: 'shield',
    title: 'Compliance Agent',
    description: 'Continuous regulatory monitoring, automated audit trails, and proactive risk assessment.',
    stat: '100% audit-ready',
  },
  {
    icon: 'chart',
    title: 'Growth Prediction Agent',
    description: 'Scaling readiness analysis, market opportunity identification, and resource allocation optimization.',
    stat: '40% faster scaling',
  },
  {
    icon: 'bolt',
    title: 'Zero-Touch Operations',
    description: 'Multi-business portfolio management with autonomous decision-making and self-healing systems.',
    stat: '<100ms response time',
  },
]

export const testimonials: Testimonial[] = [
  {
    name: 'Sarah Chen',
    role: 'Founder & CEO',
    company: 'TechScale Ventures',
    quote: 'CoreFlow360 transformed how I manage my three SaaS companies. The AI agents handle everything—from invoicing to customer follow-ups—so I can focus purely on growth strategy.',
    avatar: '/avatars/sarah-chen.jpg',
    rating: 5,
  },
  {
    name: 'Marcus Rodriguez',
    role: 'Serial Entrepreneur',
    company: 'EcomStack Holdings',
    quote: 'I went from drowning in operational chaos to scaling four businesses simultaneously. The autonomous finance agent alone saved me 20 hours per week.',
    avatar: '/avatars/marcus-rodriguez.jpg',
    rating: 5,
  },
  {
    name: 'Emily Park',
    role: 'Managing Director',
    company: 'InnovateCo',
    quote: 'The cross-business intelligence is a game-changer. CoreFlow360 identifies synergies between my companies that I would have never spotted manually.',
    avatar: '/avatars/emily-park.jpg',
    rating: 5,
  },
]

export const pricingTiers: PricingTier[] = [
  {
    name: 'Starter',
    price: 0,
    period: 'month',
    description: 'Perfect for validating your first business idea',
    features: [
      '1 business',
      '2 AI agents (Finance + CRM)',
      'Basic analytics',
      '1,000 AI operations/month',
      'Email support',
    ],
    cta: 'Start Free',
  },
  {
    name: 'Growth',
    price: 299,
    period: 'month',
    description: 'For scaling entrepreneurs managing multiple ventures',
    features: [
      'Up to 5 businesses',
      'All 6 AI agents',
      'Advanced cross-business analytics',
      '50,000 AI operations/month',
      'Priority support',
      'Custom integrations',
    ],
    cta: 'Start 14-Day Trial',
    highlighted: true,
  },
  {
    name: 'Enterprise',
    price: 999,
    period: 'month',
    description: 'Unlimited scaling for serious portfolio entrepreneurs',
    features: [
      'Unlimited businesses',
      'All AI agents + custom agents',
      'White-label options',
      'Unlimited AI operations',
      'Dedicated success manager',
      'SLA guarantee (99.99% uptime)',
    ],
    cta: 'Contact Sales',
  },
]
