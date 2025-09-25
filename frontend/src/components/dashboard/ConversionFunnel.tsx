import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  TrendingUp,
  TrendingDown,
  Users,
  MousePointer,
  ShoppingCart,
  CreditCard,
  CheckCircle2,
  AlertCircle,
  ArrowDown,
  Filter,
  Download
} from 'lucide-react'

interface FunnelStage {
  name: string
  value: number
  percentage: number
  dropoff: number
  icon: any
  color: string
  bgColor: string
}

export function ConversionFunnel() {
  const [timeRange, setTimeRange] = React.useState('last-7-days')
  const [funnelType, setFunnelType] = React.useState('e-commerce')

  const getFunnelStages = (): FunnelStage[] => {
    if (funnelType === 'e-commerce') {
      return [
        {
          name: 'Site Visitors',
          value: 50000,
          percentage: 100,
          dropoff: 0,
          icon: Users,
          color: 'text-blue-600',
          bgColor: 'bg-blue-100 dark:bg-blue-900/20'
        },
        {
          name: 'Product Views',
          value: 25000,
          percentage: 50,
          dropoff: 50,
          icon: MousePointer,
          color: 'text-purple-600',
          bgColor: 'bg-purple-100 dark:bg-purple-900/20'
        },
        {
          name: 'Add to Cart',
          value: 8000,
          percentage: 16,
          dropoff: 68,
          icon: ShoppingCart,
          color: 'text-orange-600',
          bgColor: 'bg-orange-100 dark:bg-orange-900/20'
        },
        {
          name: 'Checkout',
          value: 3200,
          percentage: 6.4,
          dropoff: 60,
          icon: CreditCard,
          color: 'text-yellow-600',
          bgColor: 'bg-yellow-100 dark:bg-yellow-900/20'
        },
        {
          name: 'Purchase',
          value: 1280,
          percentage: 2.56,
          dropoff: 60,
          icon: CheckCircle2,
          color: 'text-green-600',
          bgColor: 'bg-green-100 dark:bg-green-900/20'
        }
      ]
    } else {
      // Sign-up funnel
      return [
        {
          name: 'Landing Page',
          value: 30000,
          percentage: 100,
          dropoff: 0,
          icon: Users,
          color: 'text-blue-600',
          bgColor: 'bg-blue-100 dark:bg-blue-900/20'
        },
        {
          name: 'Sign Up Form',
          value: 12000,
          percentage: 40,
          dropoff: 60,
          icon: MousePointer,
          color: 'text-purple-600',
          bgColor: 'bg-purple-100 dark:bg-purple-900/20'
        },
        {
          name: 'Email Verification',
          value: 8400,
          percentage: 28,
          dropoff: 30,
          icon: CreditCard,
          color: 'text-orange-600',
          bgColor: 'bg-orange-100 dark:bg-orange-900/20'
        },
        {
          name: 'Profile Setup',
          value: 6300,
          percentage: 21,
          dropoff: 25,
          icon: ShoppingCart,
          color: 'text-yellow-600',
          bgColor: 'bg-yellow-100 dark:bg-yellow-900/20'
        },
        {
          name: 'Onboarding Complete',
          value: 5040,
          percentage: 16.8,
          dropoff: 20,
          icon: CheckCircle2,
          color: 'text-green-600',
          bgColor: 'bg-green-100 dark:bg-green-900/20'
        }
      ]
    }
  }

  const stages = getFunnelStages()
  const overallConversionRate = (stages[stages.length - 1].value / stages[0].value) * 100

  return (
    <Card>
      <CardHeader>
        <div className="flex justify-between items-start">
          <div>
            <CardTitle>Conversion Funnel</CardTitle>
            <CardDescription>
              Track user progression through key conversion stages
            </CardDescription>
          </div>
          <div className="flex items-center space-x-2">
            <Select value={funnelType} onValueChange={setFunnelType}>
              <SelectTrigger className="w-36">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="e-commerce">E-commerce</SelectItem>
                <SelectItem value="sign-up">Sign Up</SelectItem>
              </SelectContent>
            </Select>
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="today">Today</SelectItem>
                <SelectItem value="yesterday">Yesterday</SelectItem>
                <SelectItem value="last-7-days">Last 7 Days</SelectItem>
                <SelectItem value="last-30-days">Last 30 Days</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm">
              <Download className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {/* Overall Conversion Rate */}
          <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <div className="flex justify-between items-center">
              <div>
                <p className="text-sm text-gray-500">Overall Conversion Rate</p>
                <p className="text-3xl font-bold">{overallConversionRate.toFixed(2)}%</p>
              </div>
              <div className="text-right">
                <div className="flex items-center space-x-1">
                  <TrendingUp className="h-4 w-4 text-green-500" />
                  <span className="text-sm font-medium text-green-600">+2.4%</span>
                </div>
                <p className="text-xs text-gray-500">vs previous period</p>
              </div>
            </div>
          </div>

          {/* Funnel Visualization */}
          <div className="space-y-3">
            {stages.map((stage, index) => {
              const Icon = stage.icon
              const widthPercentage = (stage.value / stages[0].value) * 100
              
              return (
                <div key={index} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <div className={`p-2 rounded-lg ${stage.bgColor}`}>
                        <Icon className={`h-4 w-4 ${stage.color}`} />
                      </div>
                      <div>
                        <p className="font-medium">{stage.name}</p>
                        <p className="text-xs text-gray-500">
                          {stage.value.toLocaleString()} users
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="font-bold">{stage.percentage.toFixed(1)}%</p>
                      {index > 0 && (
                        <div className="flex items-center space-x-1">
                          <TrendingDown className="h-3 w-3 text-red-500" />
                          <span className="text-xs text-red-600">
                            -{stage.dropoff}% dropoff
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  {/* Funnel Bar */}
                  <div className="relative">
                    <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded">
                      <div
                        className="h-full rounded transition-all"
                        style={{
                          width: `${widthPercentage}%`,
                          background: `linear-gradient(90deg, ${stage.color.replace('text', 'rgb').replace('-600', '').replace('blue', '59, 130, 246').replace('purple', '168, 85, 247').replace('orange', '251, 146, 60').replace('yellow', '250, 204, 21').replace('green', '34, 197, 94')} 0%, ${stage.color.replace('text', 'rgb').replace('-600', '').replace('blue', '59, 130, 246').replace('purple', '168, 85, 247').replace('orange', '251, 146, 60').replace('yellow', '250, 204, 21').replace('green', '34, 197, 94')} 100%)`
                        }}
                      />
                    </div>
                  </div>

                  {/* Dropoff Arrow */}
                  {index < stages.length - 1 && (
                    <div className="flex justify-center py-2">
                      <ArrowDown className="h-4 w-4 text-gray-400" />
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* Optimization Suggestions */}
          <div className="space-y-3 pt-4 border-t">
            <h4 className="font-medium text-sm">Optimization Opportunities</h4>
            <div className="space-y-2">
              {[
                {
                  stage: 'Product Views → Add to Cart',
                  issue: 'High dropoff rate (68%)',
                  suggestion: 'Improve product descriptions and images',
                  priority: 'high'
                },
                {
                  stage: 'Checkout → Purchase',
                  issue: 'Cart abandonment (60%)',
                  suggestion: 'Simplify checkout process, add guest checkout',
                  priority: 'high'
                },
                {
                  stage: 'Add to Cart → Checkout',
                  issue: 'Users not proceeding (60%)',
                  suggestion: 'Show shipping costs earlier, add trust badges',
                  priority: 'medium'
                }
              ].map((item, index) => (
                <div key={index} className="flex items-start space-x-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <AlertCircle className={`h-4 w-4 mt-0.5 ${
                    item.priority === 'high' ? 'text-red-500' : 'text-yellow-500'
                  }`} />
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium">{item.stage}</p>
                      <Badge 
                        variant={item.priority === 'high' ? 'destructive' : 'secondary'}
                        className="text-xs"
                      >
                        {item.priority} priority
                      </Badge>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">{item.issue}</p>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                      <span className="font-medium">Suggestion:</span> {item.suggestion}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}