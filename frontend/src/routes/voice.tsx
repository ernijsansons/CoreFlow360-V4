import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Phone, PhoneCall, PhoneIncoming, PhoneOutgoing } from 'lucide-react'

export const Route = createFileRoute('/voice')({
  component: VoiceAgentPage,
})

function VoiceAgentPage() {
  return (
    <MainLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Voice Agent</h1>
          <p className="text-muted-foreground mt-2">
            AI-powered voice assistant for customer interactions
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Total Calls</p>
                <h3 className="text-2xl font-bold mt-2">1,234</h3>
                <p className="text-xs text-muted-foreground mt-1">This month</p>
              </div>
              <PhoneCall className="h-8 w-8 text-muted-foreground" />
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Incoming</p>
                <h3 className="text-2xl font-bold mt-2">856</h3>
                <p className="text-xs text-green-600 mt-1">69% answered</p>
              </div>
              <PhoneIncoming className="h-8 w-8 text-green-600" />
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Outgoing</p>
                <h3 className="text-2xl font-bold mt-2">378</h3>
                <p className="text-xs text-blue-600 mt-1">84% connected</p>
              </div>
              <PhoneOutgoing className="h-8 w-8 text-blue-600" />
            </div>
          </Card>
        </div>

        <Card className="p-6">
          <div className="flex items-center gap-4 mb-6">
            <div className="p-3 bg-primary/10 rounded-full">
              <Phone className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h2 className="text-xl font-semibold">AI Voice Agent Coming Soon</h2>
              <p className="text-muted-foreground">
                Automated voice calls with natural language processing
              </p>
            </div>
          </div>
          <p className="text-muted-foreground mb-6">
            Our AI voice agent will handle customer calls, schedule appointments, 
            answer questions, and escalate to human agents when needed.
          </p>
          <Button>Join Waitlist</Button>
        </Card>
      </div>
    </MainLayout>
  )
}

