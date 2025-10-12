import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Building2, Search, Filter } from 'lucide-react'

export const Route = createFileRoute('/crm/companies')({
  component: CompaniesPage,
})

function CompaniesPage() {
  return (
    <MainLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Companies</h1>
            <p className="text-muted-foreground mt-2">
              Manage your B2B accounts and organizations
            </p>
          </div>
          <Button>
            <Building2 className="h-4 w-4 mr-2" />
            Add Company
          </Button>
        </div>

        <Card className="p-6">
          <div className="flex items-center gap-4 mb-6">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input 
                placeholder="Search companies..." 
                className="pl-10"
              />
            </div>
            <Button variant="outline">
              <Filter className="h-4 w-4 mr-2" />
              Filter
            </Button>
          </div>

          <div className="text-center py-12">
            <Building2 className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">Company Management Coming Soon</h3>
            <p className="text-muted-foreground mb-4">
              Track accounts, relationships, and business opportunities
            </p>
            <Button>Get Notified</Button>
          </div>
        </Card>
      </div>
    </MainLayout>
  )
}

