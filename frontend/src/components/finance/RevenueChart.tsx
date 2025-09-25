import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Button } from '@/components/ui/button'
import { TrendingUp, Download } from 'lucide-react'

interface RevenueChartProps {
  detailed?: boolean
}

export function RevenueChart({ detailed = false }: RevenueChartProps) {
  const [chartType, setChartType] = React.useState('line')
  const [period, setPeriod] = React.useState('monthly')

  const generateChartData = () => {
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    const baseValues = [65000, 72000, 68000, 78000, 82000, 89000, 92000, 88000, 95000, 98000, 102000, 108000]
    
    if (period === 'daily') {
      return Array.from({ length: 30 }, (_, i) => ({
        label: `Day ${i + 1}`,
        value: Math.round(3000 + Math.random() * 2000)
      }))
    }
    
    if (period === 'weekly') {
      return ['Week 1', 'Week 2', 'Week 3', 'Week 4'].map((week, i) => ({
        label: week,
        value: Math.round(20000 + Math.random() * 5000)
      }))
    }
    
    return months.slice(0, detailed ? 12 : 6).map((month, i) => ({
      label: month,
      value: baseValues[i]
    }))
  }

  const chartData = generateChartData()
  const maxValue = Math.max(...chartData.map(d => d.value))
  const totalRevenue = chartData.reduce((sum, d) => sum + d.value, 0)
  const avgRevenue = Math.round(totalRevenue / chartData.length)

  return (
    <Card>
      <CardHeader>
        <div className="flex justify-between items-start">
          <div>
            <CardTitle>Revenue Overview</CardTitle>
            <CardDescription>
              {period === 'daily' ? 'Last 30 days' : period === 'weekly' ? 'Last 4 weeks' : 'Monthly revenue'}
            </CardDescription>
          </div>
          <div className="flex items-center space-x-2">
            {detailed && (
              <>
                <Select value={period} onValueChange={setPeriod}>
                  <SelectTrigger className="w-32">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="daily">Daily</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={chartType} onValueChange={setChartType}>
                  <SelectTrigger className="w-32">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="line">Line Chart</SelectItem>
                    <SelectItem value="bar">Bar Chart</SelectItem>
                    <SelectItem value="area">Area Chart</SelectItem>
                  </SelectContent>
                </Select>
              </>
            )}
            <Button variant="outline" size="sm">
              <Download className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {detailed && (
            <div className="grid grid-cols-3 gap-4 pb-4 border-b">
              <div>
                <p className="text-sm text-gray-500">Total Revenue</p>
                <p className="text-xl font-bold">
                  ${totalRevenue.toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Average</p>
                <p className="text-xl font-bold">
                  ${avgRevenue.toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Growth</p>
                <p className="text-xl font-bold text-green-600 flex items-center">
                  <TrendingUp className="h-4 w-4 mr-1" />
                  +15.3%
                </p>
              </div>
            </div>
          )}

          <div className="h-64 relative">
            <div className="absolute inset-0 flex items-end justify-between">
              {chartData.map((data, index) => {
                const height = (data.value / maxValue) * 100
                const isHighest = data.value === maxValue
                
                return (
                  <div
                    key={index}
                    className="flex-1 flex flex-col items-center"
                    style={{ marginRight: index === chartData.length - 1 ? 0 : 4 }}
                  >
                    <div className="w-full relative group">
                      {chartType === 'bar' ? (
                        <div
                          className={`w-full transition-all rounded-t ${isHighest ? 'bg-blue-600' : 'bg-blue-400'} hover:bg-blue-500`}
                          style={{ height: `${height}%`, minHeight: '2px' }}
                        />
                      ) : chartType === 'area' ? (
                        <div
                          className={`w-full transition-all ${isHighest ? 'bg-blue-200' : 'bg-blue-100'}`}
                          style={{ height: `${height}%`, minHeight: '2px' }}
                        />
                      ) : (
                        <div className="w-full flex items-end justify-center" style={{ height: '200px' }}>
                          <div
                            className="w-2 h-2 bg-blue-600 rounded-full"
                            style={{ marginBottom: `${(height / 100) * 200}px` }}
                          />
                        </div>
                      )}
                      
                      <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-gray-800 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
                        ${data.value.toLocaleString()}
                      </div>
                    </div>
                    <span className="text-xs text-gray-500 mt-2">
                      {data.label}
                    </span>
                  </div>
                )
              })}
            </div>

            {chartType === 'line' && (
              <svg className="absolute inset-0 pointer-events-none" style={{ height: '200px' }}>
                <polyline
                  fill="none"
                  stroke="rgb(59 130 246)"
                  strokeWidth="2"
                  points={chartData.map((data, index) => {
                    const x = (index / (chartData.length - 1)) * 100
                    const y = 100 - (data.value / maxValue) * 100
                    return `${x}%,${y}%`
                  }).join(' ')}
                  style={{
                    vectorEffect: 'non-scaling-stroke'
                  }}
                />
              </svg>
            )}
          </div>

          {!detailed && (
            <div className="flex justify-between items-center pt-4 border-t">
              <div>
                <p className="text-sm text-gray-500">Total Revenue</p>
                <p className="text-lg font-bold">${totalRevenue.toLocaleString()}</p>
              </div>
              <div className="text-right">
                <p className="text-sm text-gray-500">vs Last Period</p>
                <p className="text-lg font-bold text-green-600">+15.3%</p>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}