import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  TrendingUp,
  TrendingDown,
  Users,
  DollarSign,
  ArrowRight
} from 'lucide-react'

interface SubscriptionCardProps {
  plan: string
  price: number
  customers: number
  growth: number
  revenue: number
  description?: string
}

export function SubscriptionCard({
  plan,
  price,
  customers,
  growth,
  revenue,
  description
}: SubscriptionCardProps) {
  const isPositiveGrowth = growth >= 0

  return (
    <Card className="hover:shadow-lg transition-shadow">
      <CardHeader>
        <div className="flex justify-between items-start">
          <div>
            <CardTitle>{plan}</CardTitle>
            <CardDescription>
              ${price}/month
            </CardDescription>
          </div>
          <Badge 
            variant={isPositiveGrowth ? 'success' : 'destructive'} 
            className="flex items-center space-x-1"
          >
            {isPositiveGrowth ? (
              <TrendingUp className="h-3 w-3" />
            ) : (
              <TrendingDown className="h-3 w-3" />
            )}
            <span>{isPositiveGrowth ? '+' : ''}{growth}%</span>
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {description && (
          <p className="text-sm text-gray-600 dark:text-gray-400">
            {description}
          </p>
        )}

        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="flex items-center space-x-2 text-gray-500">
              <Users className="h-4 w-4" />
              <span className="text-sm">Customers</span>
            </div>
            <p className="text-2xl font-bold">{customers}</p>
            <p className="text-xs text-gray-500">
              {isPositiveGrowth ? '+' : '-'}{Math.abs(Math.round(customers * (growth / 100)))} this month
            </p>
          </div>

          <div className="space-y-2">
            <div className="flex items-center space-x-2 text-gray-500">
              <DollarSign className="h-4 w-4" />
              <span className="text-sm">Revenue</span>
            </div>
            <p className="text-2xl font-bold">
              ${(revenue / 1000).toFixed(1)}k
            </p>
            <p className="text-xs text-gray-500">
              Monthly recurring
            </p>
          </div>
        </div>

        <div className="pt-4 border-t">
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-500">Avg. Customer Value</span>
              <span className="font-medium">${price}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-500">Churn Rate</span>
              <span className="font-medium">{(100 - growth) / 25}%</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-500">Lifetime Value</span>
              <span className="font-medium">${(price * 12 * 2.5).toLocaleString()}</span>
            </div>
          </div>
        </div>

        <Button variant="outline" className="w-full">
          View Details
          <ArrowRight className="h-4 w-4 ml-2" />
        </Button>
      </CardContent>
    </Card>
  )
}