import React from 'react'
import { Card } from '@/components/ui'
import {
  Users,
  UserPlus,
  TrendingUp,
  DollarSign,
  Activity,
  Target,
  Calendar,
  MessageSquare
} from 'lucide-react'

export function CRMDashboard() {
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">CRM Dashboard</h1>
          <p className="text-muted-foreground mt-1">
            Manage your customer relationships and sales pipeline
          </p>
        </div>
        <button className="btn btn-primary">
          <UserPlus className="w-4 h-4 mr-2" />
          Add Customer
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Total Customers</p>
              <p className="text-2xl font-bold mt-1">2,845</p>
              <p className="text-xs text-green-600 mt-2">+12.3% from last month</p>
            </div>
            <Users className="w-8 h-8 text-primary opacity-80" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Pipeline Value</p>
              <p className="text-2xl font-bold mt-1">$428,350</p>
              <p className="text-xs text-green-600 mt-2">+24.5% from last month</p>
            </div>
            <DollarSign className="w-8 h-8 text-primary opacity-80" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Active Deals</p>
              <p className="text-2xl font-bold mt-1">156</p>
              <p className="text-xs text-green-600 mt-2">+8 new this week</p>
            </div>
            <Target className="w-8 h-8 text-primary opacity-80" />
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Conversion Rate</p>
              <p className="text-2xl font-bold mt-1">24.8%</p>
              <p className="text-xs text-green-600 mt-2">+2.1% improvement</p>
            </div>
            <TrendingUp className="w-8 h-8 text-primary opacity-80" />
          </div>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activities */}
        <Card className="col-span-2 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Recent Activities</h3>
            <Activity className="w-5 h-5 text-muted-foreground" />
          </div>
          <div className="space-y-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="flex items-start space-x-3 pb-3 border-b last:border-0">
                <div className="w-2 h-2 rounded-full bg-primary mt-2" />
                <div className="flex-1">
                  <p className="text-sm font-medium">New lead from website contact form</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    John Doe - Software Developer at TechCorp
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">2 hours ago</p>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Upcoming Tasks */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Upcoming Tasks</h3>
            <Calendar className="w-5 h-5 text-muted-foreground" />
          </div>
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-start space-x-3">
                <input
                  type="checkbox"
                  className="mt-1 rounded border-gray-300"
                />
                <div className="flex-1">
                  <p className="text-sm">Follow up with Sarah Johnson</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Today, 2:00 PM
                  </p>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Pipeline Overview */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold">Sales Pipeline</h3>
          <button className="text-sm text-primary hover:underline">
            View all deals
          </button>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {['Lead', 'Qualified', 'Proposal', 'Negotiation', 'Closed'].map((stage, index) => (
            <div key={stage} className="text-center">
              <div className="bg-muted rounded-lg p-4 mb-2">
                <p className="text-2xl font-bold">{30 - index * 5}</p>
                <p className="text-sm text-muted-foreground mt-1">deals</p>
              </div>
              <p className="text-sm font-medium">{stage}</p>
              <p className="text-xs text-muted-foreground mt-1">
                ${(150 - index * 25).toFixed(0)}k value
              </p>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}

export default CRMDashboard