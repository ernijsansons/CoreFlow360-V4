import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import {
  BarChart3,
  LineChart,
  PieChart,
  Download,
  TrendingUp,
  Globe,
  Users,
  Eye
} from 'lucide-react'

export function TrafficChart() {
  const [chartType, setChartType] = React.useState('line')
  const [metric, setMetric] = React.useState('users')
  const [granularity, setGranularity] = React.useState('daily')

  const generateTrafficData = () => {
    const labels = granularity === 'hourly' 
      ? Array.from({ length: 24 }, (_, i) => `${i}:00`)
      : granularity === 'daily'
      ? ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
      : ['Week 1', 'Week 2', 'Week 3', 'Week 4']

    const generateValues = () => {
      return labels.map(() => Math.floor(Math.random() * 5000) + 2000)
    }

    return {
      labels,
      datasets: [
        {
          label: 'Users',
          data: generateValues(),
          color: 'rgb(59, 130, 246)'
        },
        {
          label: 'Sessions',
          data: generateValues().map(v => v * 1.3),
          color: 'rgb(34, 197, 94)'
        },
        {
          label: 'Page Views',
          data: generateValues().map(v => v * 2.5),
          color: 'rgb(168, 85, 247)'
        }
      ]
    }
  }

  const data = generateTrafficData()
  const maxValue = Math.max(...data.datasets.flatMap(d => d.data))

  const renderChart = () => {
    if (chartType === 'bar') {
      return (
        <div className="h-64 flex items-end justify-between space-x-2">
          {data.labels.map((label, index) => (
            <div key={index} className="flex-1 flex flex-col items-center">
              <div className="w-full flex items-end space-x-1" style={{ height: '200px' }}>
                {data.datasets.map((dataset, datasetIndex) => (
                  <div
                    key={datasetIndex}
                    className="flex-1 transition-all hover:opacity-80 rounded-t"
                    style={{
                      backgroundColor: dataset.color,
                      height: `${(dataset.data[index] / maxValue) * 100}%`,
                      opacity: 0.8 - (datasetIndex * 0.2)
                    }}
                    title={`${dataset.label}: ${dataset.data[index].toLocaleString()}`}
                  />
                ))}
              </div>
              <span className="text-xs text-gray-500 mt-2">{label}</span>
            </div>
          ))}
        </div>
      )
    } else if (chartType === 'area') {
      return (
        <div className="h-64 relative">
          {data.datasets.map((dataset, datasetIndex) => (
            <div
              key={datasetIndex}
              className="absolute inset-0 flex items-end"
              style={{ zIndex: data.datasets.length - datasetIndex }}
            >
              <svg className="w-full h-full">
                <defs>
                  <linearGradient id={`gradient-${datasetIndex}`} x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor={dataset.color} stopOpacity="0.6" />
                    <stop offset="100%" stopColor={dataset.color} stopOpacity="0.1" />
                  </linearGradient>
                </defs>
                <path
                  d={`
                    M 0,${200 - (dataset.data[0] / maxValue) * 200}
                    ${dataset.data.map((value, i) => 
                      `L ${(i / (dataset.data.length - 1)) * 100}%,${200 - (value / maxValue) * 200}`
                    ).join(' ')}
                    L 100%,200
                    L 0,200
                    Z
                  `}
                  fill={`url(#gradient-${datasetIndex})`}
                  className="transition-all"
                />
              </svg>
            </div>
          ))}
          <div className="absolute bottom-0 left-0 right-0 flex justify-between">
            {data.labels.map((label, index) => (
              <span key={index} className="text-xs text-gray-500">{label}</span>
            ))}
          </div>
        </div>
      )
    } else {
      // Line chart (default)
      return (
        <div className="h-64 relative">
          <div className="absolute inset-0">
            {/* Grid lines */}
            <div className="h-full flex flex-col justify-between">
              {[0, 1, 2, 3, 4].map((i) => (
                <div key={i} className="border-t border-gray-200 dark:border-gray-700" />
              ))}
            </div>
          </div>
          <div className="relative h-full">
            {data.datasets.map((dataset, datasetIndex) => (
              <svg key={datasetIndex} className="absolute inset-0 w-full h-full">
                <polyline
                  fill="none"
                  stroke={dataset.color}
                  strokeWidth="2"
                  points={dataset.data.map((value, i) => {
                    const x = (i / (dataset.data.length - 1)) * 100
                    const y = 100 - (value / maxValue) * 100
                    return `${x}%,${y}%`
                  }).join(' ')}
                />
                {dataset.data.map((value, i) => {
                  const x = (i / (dataset.data.length - 1)) * 100
                  const y = 100 - (value / maxValue) * 100
                  return (
                    <circle
                      key={i}
                      cx={`${x}%`}
                      cy={`${y}%`}
                      r="4"
                      fill={dataset.color}
                      className="hover:r-6 transition-all"
                    />
                  )
                })}
              </svg>
            ))}
          </div>
          <div className="absolute bottom-0 left-0 right-0 flex justify-between">
            {data.labels.map((label, index) => (
              <span key={index} className="text-xs text-gray-500">{label}</span>
            ))}
          </div>
        </div>
      )
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex justify-between items-start">
          <div>
            <CardTitle>Traffic Overview</CardTitle>
            <CardDescription>Website traffic and user engagement metrics</CardDescription>
          </div>
          <div className="flex items-center space-x-2">
            <Select value={granularity} onValueChange={setGranularity}>
              <SelectTrigger className="w-28">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="hourly">Hourly</SelectItem>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
              </SelectContent>
            </Select>
            <Tabs value={chartType} onValueChange={setChartType}>
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="line" className="px-2">
                  <LineChart className="h-4 w-4" />
                </TabsTrigger>
                <TabsTrigger value="bar" className="px-2">
                  <BarChart3 className="h-4 w-4" />
                </TabsTrigger>
                <TabsTrigger value="area" className="px-2">
                  <PieChart className="h-4 w-4" />
                </TabsTrigger>
              </TabsList>
            </Tabs>
            <Button variant="outline" size="sm">
              <Download className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Legend */}
          <div className="flex items-center justify-center space-x-6">
            {data.datasets.map((dataset, index) => (
              <div key={index} className="flex items-center space-x-2">
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: dataset.color }}
                />
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  {dataset.label}
                </span>
              </div>
            ))}
          </div>

          {/* Chart */}
          {renderChart()}

          {/* Stats */}
          <div className="grid grid-cols-3 gap-4 pt-4 border-t">
            <div className="text-center">
              <div className="flex items-center justify-center space-x-1">
                <Users className="h-4 w-4 text-blue-600" />
                <p className="text-2xl font-bold">48.2K</p>
              </div>
              <p className="text-xs text-gray-500">Total Users</p>
              <div className="flex items-center justify-center mt-1">
                <TrendingUp className="h-3 w-3 text-green-500 mr-1" />
                <span className="text-xs text-green-600">+12.3%</span>
              </div>
            </div>
            <div className="text-center">
              <div className="flex items-center justify-center space-x-1">
                <Globe className="h-4 w-4 text-green-600" />
                <p className="text-2xl font-bold">62.5K</p>
              </div>
              <p className="text-xs text-gray-500">Sessions</p>
              <div className="flex items-center justify-center mt-1">
                <TrendingUp className="h-3 w-3 text-green-500 mr-1" />
                <span className="text-xs text-green-600">+8.7%</span>
              </div>
            </div>
            <div className="text-center">
              <div className="flex items-center justify-center space-x-1">
                <Eye className="h-4 w-4 text-purple-600" />
                <p className="text-2xl font-bold">156K</p>
              </div>
              <p className="text-xs text-gray-500">Page Views</p>
              <div className="flex items-center justify-center mt-1">
                <TrendingUp className="h-3 w-3 text-green-500 mr-1" />
                <span className="text-xs text-green-600">+15.2%</span>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}