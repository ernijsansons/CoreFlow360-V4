import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Mail, Inbox, Send, Archive } from 'lucide-react'

export const Route = createFileRoute('/email')({
  component: EmailPage,
})

function EmailPage() {
  return (
    <MainLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Email</h1>
          <p className="text-muted-foreground mt-2">
            Manage your business email communications
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Inbox</p>
                <h3 className="text-2xl font-bold mt-2">42</h3>
              </div>
              <Inbox className="h-8 w-8 text-blue-600" />
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Sent</p>
                <h3 className="text-2xl font-bold mt-2">128</h3>
              </div>
              <Send className="h-8 w-8 text-green-600" />
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Archived</p>
                <h3 className="text-2xl font-bold mt-2">315</h3>
              </div>
              <Archive className="h-8 w-8 text-gray-600" />
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Unread</p>
                <h3 className="text-2xl font-bold mt-2">12</h3>
              </div>
              <Mail className="h-8 w-8 text-red-600" />
            </div>
          </Card>
        </div>

        <Card className="p-6">
          <div className="flex items-center gap-4 mb-6">
            <div className="p-3 bg-primary/10 rounded-full">
              <Mail className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h2 className="text-xl font-semibold">Email Integration Coming Soon</h2>
              <p className="text-muted-foreground">
                Unified inbox for all your business email accounts
              </p>
            </div>
          </div>
          <p className="text-muted-foreground mb-6">
            Manage all your business email accounts from one place with AI-powered 
            sorting, templates, and automated responses.
          </p>
          <Button>Request Early Access</Button>
        </Card>
      </div>
    </MainLayout>
  )
}

