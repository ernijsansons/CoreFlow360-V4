import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Target, Search, Filter, Plus } from 'lucide-react'

export const Route = createFileRoute('/crm/deals')({
  component: DealsPage,
})

function DealsPage() {
  return (
    <MainLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Deals</h1>
            <p className="text-muted-foreground mt-2">
              Track your sales pipeline and opportunities
            </p>
          </div>
          <Button>
            <Plus className="h-4 w-4 mr-2" />
            New Deal
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Prospecting</p>
            <h3 className="text-2xl font-bold mt-2">$42K</h3>
            <p className="text-xs text-muted-foreground mt-1">8 deals</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Qualification</p>
            <h3 className="text-2xl font-bold mt-2">$127K</h3>
            <p className="text-xs text-muted-foreground mt-1">12 deals</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Proposal</p>
            <h3 className="text-2xl font-bold mt-2">$89K</h3>
            <p className="text-xs text-muted-foreground mt-1">5 deals</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm font-medium text-muted-foreground">Negotiation</p>
            <h3 className="text-2xl font-bold mt-2">$215K</h3>
            <p className="text-xs text-muted-foreground mt-1">3 deals</p>
          </Card>
        </div>

        <Card className="p-6">
          <div className="flex items-center gap-4 mb-6">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input 
                placeholder="Search deals..." 
                className="pl-10"
              />
            </div>
            <Button variant="outline">
              <Filter className="h-4 w-4 mr-2" />
              Filter
            </Button>
          </div>

          <div className="text-center py-12">
            <Target className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">Deal Pipeline Coming Soon</h3>
            <p className="text-muted-foreground mb-4">
              Visual pipeline management with AI-powered deal scoring
            </p>
            <Button>Get Notified</Button>
          </div>
        </Card>
      </div>
    </MainLayout>
  )
}

