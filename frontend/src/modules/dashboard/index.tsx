import { useEffect } from 'react'
import { useAuthStore, useUIStore, useEntityStore } from '@/stores'
import { Card } from '@/components/ui/card-refactored'
import { KPICard } from '@/components/dashboard/widgets/KPICard'
import { TrendingUp, Users, DollarSign, ShoppingCart, Activity } from 'lucide-react'

export function Dashboard() {
  const { user } = useAuthStore()
  const { setBreadcrumbs } = useUIStore()
  const { currentEntity } = useEntityStore()

  useEffect(() => {
    setBreadcrumbs([{ label: 'Dashboard' }])
  }, [setBreadcrumbs])

  // Mock KPI data - replace with real API calls
  const kpis = [
    {
      title: 'Total Revenue',
      value: '$45,231.89',
      change: '+20.1% from last month',
      trend: 'up' as const,
      icon: DollarSign,
    },
    {
      title: 'Active Users',
      value: '2,350',
      change: '+180.1% from last month',
      trend: 'up' as const,
      icon: Users,
    },
    {
      title: 'Total Orders',
      value: '+12,234',
      change: '+19% from last month',
      trend: 'up' as const,
      icon: ShoppingCart,
    },
    {
      title: 'Active Now',
      value: '+573',
      change: '+201 since last hour',
      trend: 'up' as const,
      icon: Activity,
    },
  ]

  return (
    <div className="space-y-8">
      {/* Welcome Section */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          Welcome back, {user?.firstName || 'User'}!
        </h1>
        <p className="text-muted-foreground mt-2">
          {currentEntity?.name
            ? `Here's what's happening with ${currentEntity.name} today.`
            : "Here's what's happening with your business today."}
        </p>
      </div>

      {/* KPI Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {kpis.map((kpi, index) => (
          <KPICard
            key={index}
            title={kpi.title}
            value={kpi.value}
            change={kpi.change}
            trend={kpi.trend}
            icon={kpi.icon}
          />
        ))}
      </div>

      {/* Quick Actions */}
      <Card className="p-6">
        <h2 className="text-xl font-semibold mb-4">Quick Actions</h2>
        <div className="grid gap-4 md:grid-cols-3">
          <button className="p-4 border rounded-lg hover:bg-accent transition-colors text-left">
            <TrendingUp className="h-8 w-8 mb-2 text-brand-600" aria-hidden="true" />
            <h3 className="font-semibold">Create Invoice</h3>
            <p className="text-sm text-muted-foreground">
              Generate and send new invoice
            </p>
          </button>
          <button className="p-4 border rounded-lg hover:bg-accent transition-colors text-left">
            <Users className="h-8 w-8 mb-2 text-brand-600" aria-hidden="true" />
            <h3 className="font-semibold">Add Customer</h3>
            <p className="text-sm text-muted-foreground">
              Add new customer to CRM
            </p>
          </button>
          <button className="p-4 border rounded-lg hover:bg-accent transition-colors text-left">
            <ShoppingCart className="h-8 w-8 mb-2 text-brand-600" aria-hidden="true" />
            <h3 className="font-semibold">New Order</h3>
            <p className="text-sm text-muted-foreground">
              Process new order
            </p>
          </button>
        </div>
      </Card>

      {/* Recent Activity Placeholder */}
      <Card className="p-6">
        <h2 className="text-xl font-semibold mb-4">Recent Activity</h2>
        <div className="space-y-4">
          <div className="flex items-center justify-between pb-4 border-b">
            <div>
              <p className="font-medium">Invoice #1234 paid</p>
              <p className="text-sm text-muted-foreground">2 hours ago</p>
            </div>
            <span className="text-green-600 font-semibold">+$2,500</span>
          </div>
          <div className="flex items-center justify-between pb-4 border-b">
            <div>
              <p className="font-medium">New customer added</p>
              <p className="text-sm text-muted-foreground">5 hours ago</p>
            </div>
            <span className="text-blue-600 font-semibold">CRM</span>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Order #5678 shipped</p>
              <p className="text-sm text-muted-foreground">1 day ago</p>
            </div>
            <span className="text-purple-600 font-semibold">Fulfilled</span>
          </div>
        </div>
      </Card>
    </div>
  )
}
