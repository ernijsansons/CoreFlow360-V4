import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Calendar as CalendarIcon, Clock, Users, Video } from 'lucide-react'

export const Route = createFileRoute('/calendar')({
  component: CalendarPage,
})

function CalendarPage() {
  return (
    <MainLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Calendar</h1>
          <p className="text-muted-foreground mt-2">
            Schedule and manage your business meetings
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Today's Meetings</p>
                <h3 className="text-2xl font-bold mt-2">5</h3>
              </div>
              <CalendarIcon className="h-8 w-8 text-primary" />
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">This Week</p>
                <h3 className="text-2xl font-bold mt-2">23</h3>
              </div>
              <Clock className="h-8 w-8 text-blue-600" />
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Team Meetings</p>
                <h3 className="text-2xl font-bold mt-2">8</h3>
              </div>
              <Users className="h-8 w-8 text-green-600" />
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Video Calls</p>
                <h3 className="text-2xl font-bold mt-2">12</h3>
              </div>
              <Video className="h-8 w-8 text-purple-600" />
            </div>
          </Card>
        </div>

        <Card className="p-6">
          <div className="flex items-center gap-4 mb-6">
            <div className="p-3 bg-primary/10 rounded-full">
              <CalendarIcon className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h2 className="text-xl font-semibold">Calendar Integration Coming Soon</h2>
              <p className="text-muted-foreground">
                Smart scheduling with AI-powered meeting coordination
              </p>
            </div>
          </div>
          <p className="text-muted-foreground mb-6">
            Integrate with Google Calendar, Outlook, and other calendar services. 
            AI will automatically schedule meetings based on availability and preferences.
          </p>
          <Button>Join Waitlist</Button>
        </Card>
      </div>
    </MainLayout>
  )
}

