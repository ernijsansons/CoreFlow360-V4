import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { FileText, Search, Filter, Plus } from 'lucide-react'

export const Route = createFileRoute('/finance/invoices')({
  component: InvoicesPage,
})

function InvoicesPage() {
  return (
    <MainLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Invoices</h1>
            <p className="text-muted-foreground mt-2">
              Create and manage customer invoices
            </p>
          </div>
          <Button>
            <Plus className="h-4 w-4 mr-2" />
            New Invoice
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Draft</p>
            <h3 className="text-2xl font-bold mt-2">12</h3>
            <p className="text-xs text-muted-foreground mt-1">$24,560</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Sent</p>
            <h3 className="text-2xl font-bold mt-2">45</h3>
            <p className="text-xs text-muted-foreground mt-1">$127,890</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Overdue</p>
            <h3 className="text-2xl font-bold mt-2">8</h3>
            <p className="text-xs text-red-600 mt-1">$15,320</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Paid</p>
            <h3 className="text-2xl font-bold mt-2">234</h3>
            <p className="text-xs text-green-600 mt-1">$890,450</p>
          </Card>
        </div>

        <Card className="p-6">
          <div className="flex items-center gap-4 mb-6">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input 
                placeholder="Search invoices..." 
                className="pl-10"
              />
            </div>
            <Button variant="outline">
              <Filter className="h-4 w-4 mr-2" />
              Filter
            </Button>
          </div>

          <div className="text-center py-12">
            <FileText className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">Invoice Management Coming Soon</h3>
            <p className="text-muted-foreground mb-4">
              Professional invoicing with automated reminders and payment tracking
            </p>
            <Button>Get Notified</Button>
          </div>
        </Card>
      </div>
    </MainLayout>
  )
}

