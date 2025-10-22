import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { CreditCard, Search, Filter, Plus } from 'lucide-react'

export const Route = createFileRoute('/finance/expenses')({
  component: ExpensesPage,
})

function ExpensesPage() {
  return (
    <MainLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Expenses</h1>
            <p className="text-muted-foreground mt-2">
              Track and manage business expenses
            </p>
          </div>
          <Button>
            <Plus className="h-4 w-4 mr-2" />
            Add Expense
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">This Month</p>
            <h3 className="text-2xl font-bold mt-2">$12,340</h3>
            <p className="text-xs text-muted-foreground mt-1">67 transactions</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Pending</p>
            <h3 className="text-2xl font-bold mt-2">$2,450</h3>
            <p className="text-xs text-orange-600 mt-1">12 pending</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Approved</p>
            <h3 className="text-2xl font-bold mt-2">$9,890</h3>
            <p className="text-xs text-green-600 mt-1">55 approved</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Average</p>
            <h3 className="text-2xl font-bold mt-2">$184</h3>
            <p className="text-xs text-muted-foreground mt-1">per transaction</p>
          </Card>
        </div>

        <Card className="p-6">
          <div className="flex items-center gap-4 mb-6">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input 
                placeholder="Search expenses..." 
                className="pl-10"
              />
            </div>
            <Button variant="outline">
              <Filter className="h-4 w-4 mr-2" />
              Filter
            </Button>
          </div>

          <div className="text-center py-12">
            <CreditCard className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">Expense Tracking Coming Soon</h3>
            <p className="text-muted-foreground mb-4">
              Automated expense tracking with receipt scanning and categorization
            </p>
            <Button>Get Notified</Button>
          </div>
        </Card>
      </div>
    </MainLayout>
  )
}

