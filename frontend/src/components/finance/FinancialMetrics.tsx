import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  TrendingUp,
  TrendingDown,
  DollarSign,
  Users,
  ShoppingCart,
  CreditCard,
  ArrowUpRight,
  ArrowDownRight
} from 'lucide-react'

interface FinancialMetricsProps {
  timeRange?: string
}

export function FinancialMetrics({ timeRange = '30d' }: FinancialMetricsProps) {
  const getMetricsForTimeRange = () => {
    const baseMetrics = {
      revenue: 89800,
      growth: 12.5,
      customers: 1247,
      customerGrowth: 8.3,
      avgOrderValue: 72,
      aovGrowth: 4.2,
      transactions: 1826,
      transactionGrowth: 15.7
    }

    const multipliers: { [key: string]: number } = {
      '7d': 0.25,
      '30d': 1,
      '90d': 3.2,
      '12m': 12.5
    }

    const multiplier = multipliers[timeRange] || 1

    return {
      revenue: Math.round(baseMetrics.revenue * multiplier),
      growth: baseMetrics.growth,
      customers: Math.round(baseMetrics.customers * (timeRange === '7d' ? 0.6 : timeRange === '12m' ? 2.8 : 1)),
      customerGrowth: baseMetrics.customerGrowth,
      avgOrderValue: baseMetrics.avgOrderValue,
      aovGrowth: baseMetrics.aovGrowth,
      transactions: Math.round(baseMetrics.transactions * multiplier),
      transactionGrowth: baseMetrics.transactionGrowth
    }
  }

  const metrics = getMetricsForTimeRange()

  const metricCards = [
    {
      title: 'Total Revenue',
      value: `$${metrics.revenue.toLocaleString()}`,
      change: metrics.growth,
      icon: DollarSign,
      color: 'text-green-600',
      bgColor: 'bg-green-100 dark:bg-green-900/20',
      description: 'Total revenue for the period'
    },
    {
      title: 'Active Customers',
      value: metrics.customers.toLocaleString(),
      change: metrics.customerGrowth,
      icon: Users,
      color: 'text-blue-600',
      bgColor: 'bg-blue-100 dark:bg-blue-900/20',
      description: 'Unique paying customers'
    },
    {
      title: 'Avg. Order Value',
      value: `$${metrics.avgOrderValue}`,
      change: metrics.aovGrowth,
      icon: ShoppingCart,
      color: 'text-purple-600',
      bgColor: 'bg-purple-100 dark:bg-purple-900/20',
      description: 'Average transaction size'
    },
    {
      title: 'Transactions',
      value: metrics.transactions.toLocaleString(),
      change: metrics.transactionGrowth,
      icon: CreditCard,
      color: 'text-orange-600',
      bgColor: 'bg-orange-100 dark:bg-orange-900/20',
      description: 'Completed transactions'
    }
  ]

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {metricCards.map((metric, index) => {
        const Icon = metric.icon
        const isPositive = metric.change >= 0

        return (
          <Card key={index} className="hover:shadow-lg transition-shadow">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardDescription>{metric.title}</CardDescription>
                <div className={`p-2 rounded-lg ${metric.bgColor}`}>
                  <Icon className={`h-4 w-4 ${metric.color}`} />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <p className="text-2xl font-bold">{metric.value}</p>
                <div className="flex items-center space-x-2">
                  <div className={`flex items-center text-sm font-medium ${
                    isPositive ? 'text-green-600' : 'text-red-600'
                  }`}>
                    {isPositive ? (
                      <ArrowUpRight className="h-4 w-4" />
                    ) : (
                      <ArrowDownRight className="h-4 w-4" />
                    )}
                    <span>{isPositive ? '+' : ''}{metric.change}%</span>
                  </div>
                  <span className="text-xs text-gray-500">
                    vs previous period
                  </span>
                </div>
                <p className="text-xs text-gray-500">
                  {metric.description}
                </p>
              </div>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}