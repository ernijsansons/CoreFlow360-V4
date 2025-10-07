/**
 * Multi-Business Portfolio Dashboard
 * Fortune-50 caliber dashboard for serial entrepreneurs managing multiple businesses
 */

import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  TrendingUp,
  DollarSign,
  Users,
  ShoppingCart,
  Briefcase,
  Package,
  Activity,
  Target,
  Zap,
  ArrowUpRight,
  ArrowDownRight,
  ChevronRight,
  Sparkles,
  Brain,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'

interface Business {
  id: string
  name: string
  type: 'saas' | 'ecommerce' | 'consulting' | 'digital_products' | 'subscription'
  status: 'active' | 'scaling' | 'stable' | 'launching'
  health: 'excellent' | 'good' | 'fair' | 'needs_attention'
  revenue: number
  growth: number
  customers: number
  aiAgents: number
  sparklineData: number[]
  metrics: {
    mrr?: number
    churn?: number
    ltv?: number
    orders?: number
    conversion?: number
    utilization?: number
  }
}

const mockBusinesses: Business[] = [
  {
    id: '1',
    name: 'CloudSync Pro',
    type: 'saas',
    status: 'active',
    health: 'excellent',
    revenue: 284500,
    growth: 34.2,
    customers: 1247,
    aiAgents: 5,
    sparklineData: [45, 52, 48, 61, 68, 72, 78, 85],
    metrics: { mrr: 23708, churn: 2.1, ltv: 12450 },
  },
  {
    id: '2',
    name: 'StyleMarket',
    type: 'ecommerce',
    status: 'stable',
    health: 'good',
    revenue: 156800,
    growth: 12.8,
    customers: 3421,
    aiAgents: 4,
    sparklineData: [32, 35, 38, 36, 39, 42, 41, 44],
    metrics: { orders: 892, conversion: 3.4 },
  },
  {
    id: '3',
    name: 'Elite Consulting Group',
    type: 'consulting',
    status: 'active',
    health: 'good',
    revenue: 198600,
    growth: 18.5,
    customers: 67,
    aiAgents: 3,
    sparklineData: [28, 30, 34, 38, 41, 45, 48, 52],
    metrics: { utilization: 87 },
  },
  {
    id: '4',
    name: 'DigitalCourse Academy',
    type: 'digital_products',
    status: 'scaling',
    health: 'excellent',
    revenue: 94200,
    growth: 56.7,
    customers: 2145,
    aiAgents: 4,
    sparklineData: [18, 22, 28, 35, 44, 56, 68, 82],
    metrics: { conversion: 5.2 },
  },
  {
    id: '5',
    name: 'FitBox Monthly',
    type: 'subscription',
    status: 'stable',
    health: 'good',
    revenue: 87400,
    growth: 8.3,
    customers: 1834,
    aiAgents: 3,
    sparklineData: [22, 24, 23, 25, 26, 27, 28, 29],
    metrics: { mrr: 7283, churn: 4.2 },
  },
]

const portfolioRevenueData = [
  { month: 'Jan', saas: 185, ecommerce: 142, consulting: 168, digital: 60, subscription: 81 },
  { month: 'Feb', saas: 198, ecommerce: 138, consulting: 175, digital: 68, subscription: 79 },
  { month: 'Mar', saas: 215, ecommerce: 145, consulting: 182, digital: 78, subscription: 82 },
  { month: 'Apr', saas: 228, ecommerce: 151, consulting: 189, digital: 85, subscription: 84 },
  { month: 'May', saas: 245, ecommerce: 149, consulting: 193, digital: 89, subscription: 86 },
  { month: 'Jun', saas: 268, ecommerce: 154, consulting: 196, digital: 91, subscription: 88 },
  { month: 'Jul', saas: 285, ecommerce: 157, consulting: 199, digital: 94, subscription: 87 },
]

const businessTypeIcons = {
  saas: Zap,
  ecommerce: ShoppingCart,
  consulting: Briefcase,
  digital_products: Package,
  subscription: Target,
}

const healthColors = {
  excellent: 'text-green-600 bg-green-500/10',
  good: 'text-blue-600 bg-blue-500/10',
  fair: 'text-yellow-600 bg-yellow-500/10',
  needs_attention: 'text-red-600 bg-red-500/10',
}

const statusColors = {
  active: 'bg-green-500',
  scaling: 'bg-brand-accent-500',
  stable: 'bg-blue-500',
  launching: 'bg-orange-500',
}

export function PortfolioDashboard() {
  const [, setSelectedBusiness] = useState<Business | null>(null)

  const totalRevenue = mockBusinesses.reduce((sum, b) => sum + b.revenue, 0)
  const avgGrowth = mockBusinesses.reduce((sum, b) => sum + b.growth, 0) / mockBusinesses.length
  const totalCustomers = mockBusinesses.reduce((sum, b) => sum + b.customers, 0)
  const portfolioHealth = 92 // Calculated score

  return (
    <div className="space-y-8 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-brand-accent-600 via-brand-primary-600 to-orange-600 bg-clip-text text-transparent">
            Business Portfolio
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Managing {mockBusinesses.length} businesses with AI-powered automation
          </p>
        </div>
        <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
          <Button className="bg-gradient-to-r from-brand-accent-600 to-brand-primary-600 text-white">
            <Sparkles className="w-4 h-4 mr-2" />
            AI Insights
          </Button>
        </motion.div>
      </div>

      {/* Portfolio Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card className="glass-effect border-brand-accent-500/20 relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-brand-accent-500/5 to-transparent" />
            <CardContent className="pt-6 relative">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Total Revenue</p>
                  <p className="text-3xl font-bold mt-1">
                    ${(totalRevenue / 1000).toFixed(0)}K
                  </p>
                  <div className="flex items-center gap-1 mt-2 text-sm text-green-600">
                    <ArrowUpRight className="h-4 w-4" />
                    <span>+{avgGrowth.toFixed(1)}%</span>
                  </div>
                </div>
                <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-brand-accent-500 to-brand-primary-500 flex items-center justify-center">
                  <DollarSign className="h-6 w-6 text-white" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card className="glass-effect border-blue-500/20 relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-transparent" />
            <CardContent className="pt-6 relative">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Total Customers</p>
                  <p className="text-3xl font-bold mt-1">
                    {totalCustomers.toLocaleString()}
                  </p>
                  <div className="flex items-center gap-1 mt-2 text-sm text-blue-600">
                    <TrendingUp className="h-4 w-4" />
                    <span>Growing</span>
                  </div>
                </div>
                <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-brand-primary-500 to-brand-teal-500 flex items-center justify-center">
                  <Users className="h-6 w-6 text-white" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="glass-effect border-green-500/20 relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-green-500/5 to-transparent" />
            <CardContent className="pt-6 relative">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Portfolio Health</p>
                  <p className="text-3xl font-bold mt-1">{portfolioHealth}%</p>
                  <div className="flex items-center gap-1 mt-2 text-sm text-green-600">
                    <Activity className="h-4 w-4" />
                    <span>Excellent</span>
                  </div>
                </div>
                <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-green-500 to-emerald-500 flex items-center justify-center">
                  <Target className="h-6 w-6 text-white" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <Card className="glass-effect border-orange-500/20 relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-transparent" />
            <CardContent className="pt-6 relative">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">AI Agents Active</p>
                  <p className="text-3xl font-bold mt-1">
                    {mockBusinesses.reduce((sum, b) => sum + b.aiAgents, 0)}
                  </p>
                  <div className="flex items-center gap-1 mt-2 text-sm text-orange-600">
                    <Brain className="h-4 w-4" />
                    <span>Working 24/7</span>
                  </div>
                </div>
                <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-orange-500 to-brand-primary-500 flex items-center justify-center">
                  <Zap className="h-6 w-6 text-white" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Business Cards Grid */}
      <div>
        <h2 className="text-2xl font-bold mb-6">Your Businesses</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {mockBusinesses.map((business, index) => {
            const Icon = businessTypeIcons[business.type]
            return (
              <motion.div
                key={business.id}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: index * 0.1 }}
                whileHover={{ y: -8, scale: 1.02 }}
                onClick={() => setSelectedBusiness(business)}
                className="cursor-pointer"
              >
                <Card className="glass-effect hover:shadow-2xl transition-all duration-300 relative overflow-hidden">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-brand-accent-500/10 to-transparent rounded-bl-full" />

                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-brand-accent-500 to-brand-primary-500 flex items-center justify-center">
                          <Icon className="h-6 w-6 text-white" />
                        </div>
                        <div>
                          <CardTitle className="text-lg">{business.name}</CardTitle>
                          <div className="flex items-center gap-2 mt-1">
                            <div className={`h-2 w-2 rounded-full ${statusColors[business.status]} animate-pulse`} />
                            <span className="text-xs text-gray-600 dark:text-gray-400 capitalize">
                              {business.status}
                            </span>
                          </div>
                        </div>
                      </div>
                      <Badge className={healthColors[business.health]} variant="secondary">
                        {business.health}
                      </Badge>
                    </div>
                  </CardHeader>

                  <CardContent>
                    <div className="space-y-4">
                      {/* Revenue & Growth */}
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-xs text-gray-600 dark:text-gray-400">Revenue</p>
                          <p className="text-2xl font-bold text-brand-accent-600">
                            ${(business.revenue / 1000).toFixed(0)}K
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-600 dark:text-gray-400">Growth</p>
                          <p className={`text-2xl font-bold flex items-center gap-1 ${business.growth > 0 ? 'text-green-600' : 'text-red-600'}`}>
                            {business.growth > 0 ? <ArrowUpRight className="h-4 w-4" /> : <ArrowDownRight className="h-4 w-4" />}
                            {business.growth}%
                          </p>
                        </div>
                      </div>

                      {/* Sparkline */}
                      <div className="h-12">
                        <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={business.sparklineData.map((value, i) => ({ value, index: i }))}>
                            <defs>
                              <linearGradient id={`gradient-${business.id}`} x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="rgb(var(--brand-accent-600))" stopOpacity={0.3}/>
                                <stop offset="95%" stopColor="rgb(var(--brand-accent-600))" stopOpacity={0}/>
                              </linearGradient>
                            </defs>
                            <Area
                              type="monotone"
                              dataKey="value"
                              stroke="rgb(var(--brand-accent-600))"
                              fill={`url(#gradient-${business.id})`}
                              strokeWidth={2}
                            />
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>

                      {/* Footer */}
                      <div className="flex items-center justify-between pt-2 border-t border-gray-200 dark:border-gray-700">
                        <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                          <Users className="h-4 w-4" />
                          <span>{business.customers.toLocaleString()}</span>
                        </div>
                        <div className="flex items-center gap-2 text-sm text-brand-accent-600">
                          <Brain className="h-4 w-4" />
                          <span>{business.aiAgents} AI agents</span>
                        </div>
                        <ChevronRight className="h-4 w-4 text-gray-400" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            )
          })}
        </div>
      </div>

      {/* Portfolio Revenue Chart */}
      <Card className="glass-effect">
        <CardHeader>
          <CardTitle>Portfolio Revenue Trends</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={portfolioRevenueData}>
                <defs>
                  <linearGradient id="colorSaas" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0.1}/>
                  </linearGradient>
                  <linearGradient id="colorEcommerce" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.1}/>
                  </linearGradient>
                  <linearGradient id="colorConsulting" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.1}/>
                  </linearGradient>
                  <linearGradient id="colorDigital" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.1}/>
                  </linearGradient>
                  <linearGradient id="colorSubscription" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ec4899" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#ec4899" stopOpacity={0.1}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" className="stroke-gray-200 dark:stroke-gray-700" />
                <XAxis dataKey="month" className="text-xs" />
                <YAxis className="text-xs" />
                <Tooltip />
                <Legend />
                <Area type="monotone" dataKey="saas" stackId="1" stroke="#8b5cf6" fill="url(#colorSaas)" name="SaaS" />
                <Area type="monotone" dataKey="ecommerce" stackId="1" stroke="#3b82f6" fill="url(#colorEcommerce)" name="E-commerce" />
                <Area type="monotone" dataKey="consulting" stackId="1" stroke="#10b981" fill="url(#colorConsulting)" name="Consulting" />
                <Area type="monotone" dataKey="digital" stackId="1" stroke="#f59e0b" fill="url(#colorDigital)" name="Digital Products" />
                <Area type="monotone" dataKey="subscription" stackId="1" stroke="#ec4899" fill="url(#colorSubscription)" name="Subscription" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Business Comparison */}
      <Card className="glass-effect">
        <CardHeader>
          <CardTitle>Revenue Comparison</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={mockBusinesses}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-gray-200 dark:stroke-gray-700" />
                <XAxis dataKey="name" className="text-xs" />
                <YAxis className="text-xs" />
                <Tooltip />
                <Bar dataKey="revenue" fill="url(#barGradient)" radius={[8, 8, 0, 0]} />
                <defs>
                  <linearGradient id="barGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#8b5cf6" />
                    <stop offset="100%" stopColor="#ec4899" />
                  </linearGradient>
                </defs>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
