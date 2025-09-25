import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea, ScrollBar } from '@/components/ui/scroll-area'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  DollarSign,
  User,
  Calendar,
  MoreVertical,
  Plus,
  MoveRight,
  AlertCircle,
  CheckCircle2,
  Clock,
  TrendingUp
} from 'lucide-react'

interface Deal {
  id: string
  title: string
  company: string
  value: number
  contact: string
  probability: number
  daysInStage: number
  nextAction: string
  priority: 'low' | 'medium' | 'high' | 'urgent'
  owner: string
}

interface Stage {
  id: string
  name: string
  deals: Deal[]
  value: number
  color: string
}

export function PipelineBoard() {
  const [stages, setStages] = React.useState<Stage[]>([
    {
      id: 'lead',
      name: 'Lead',
      color: 'bg-gray-500',
      value: 450000,
      deals: [
        {
          id: '1',
          title: 'Enterprise Software License',
          company: 'Tech Corp',
          value: 125000,
          contact: 'John Smith',
          probability: 20,
          daysInStage: 3,
          nextAction: 'Schedule discovery call',
          priority: 'medium',
          owner: 'Sarah Johnson'
        },
        {
          id: '2',
          title: 'Cloud Migration Project',
          company: 'Global Industries',
          value: 89000,
          contact: 'Emily Brown',
          probability: 15,
          daysInStage: 7,
          nextAction: 'Send information packet',
          priority: 'low',
          owner: 'Mike Davis'
        }
      ]
    },
    {
      id: 'qualified',
      name: 'Qualified',
      color: 'bg-blue-500',
      value: 380000,
      deals: [
        {
          id: '3',
          title: 'Annual Service Contract',
          company: 'Acme Corp',
          value: 67000,
          contact: 'Robert Wilson',
          probability: 40,
          daysInStage: 5,
          nextAction: 'Technical assessment',
          priority: 'high',
          owner: 'Sarah Johnson'
        },
        {
          id: '4',
          title: 'Custom Integration',
          company: 'StartupHub',
          value: 45000,
          contact: 'Lisa Martinez',
          probability: 35,
          daysInStage: 2,
          nextAction: 'Requirements gathering',
          priority: 'medium',
          owner: 'Emily Chen'
        }
      ]
    },
    {
      id: 'proposal',
      name: 'Proposal',
      color: 'bg-yellow-500',
      value: 290000,
      deals: [
        {
          id: '5',
          title: 'Data Analytics Platform',
          company: 'Finance Plus',
          value: 98000,
          contact: 'Michael Johnson',
          probability: 60,
          daysInStage: 10,
          nextAction: 'Follow up on proposal',
          priority: 'urgent',
          owner: 'Mike Davis'
        },
        {
          id: '6',
          title: 'Security Audit Services',
          company: 'SecureNet',
          value: 55000,
          contact: 'Patricia Lee',
          probability: 55,
          daysInStage: 4,
          nextAction: 'Address technical questions',
          priority: 'high',
          owner: 'John Anderson'
        }
      ]
    },
    {
      id: 'negotiation',
      name: 'Negotiation',
      color: 'bg-purple-500',
      value: 185000,
      deals: [
        {
          id: '7',
          title: 'Multi-year Support Deal',
          company: 'Enterprise Co',
          value: 185000,
          contact: 'David Kim',
          probability: 80,
          daysInStage: 8,
          nextAction: 'Final pricing discussion',
          priority: 'urgent',
          owner: 'Sarah Johnson'
        }
      ]
    },
    {
      id: 'closed',
      name: 'Closed Won',
      color: 'bg-green-500',
      value: 245000,
      deals: [
        {
          id: '8',
          title: 'Premium Package',
          company: 'Success Corp',
          value: 120000,
          contact: 'Anna White',
          probability: 100,
          daysInStage: 1,
          nextAction: 'Send contract for signature',
          priority: 'high',
          owner: 'Mike Davis'
        },
        {
          id: '9',
          title: 'Consulting Services',
          company: 'Growth Ltd',
          value: 75000,
          contact: 'James Brown',
          probability: 100,
          daysInStage: 0,
          nextAction: 'Kickoff meeting',
          priority: 'medium',
          owner: 'Emily Chen'
        }
      ]
    }
  ])

  const [draggedDeal, setDraggedDeal] = React.useState<Deal | null>(null)
  const [draggedFromStage, setDraggedFromStage] = React.useState<string | null>(null)

  const handleDragStart = (deal: Deal, stageId: string) => {
    setDraggedDeal(deal)
    setDraggedFromStage(stageId)
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
  }

  const handleDrop = (e: React.DragEvent, targetStageId: string) => {
    e.preventDefault()
    if (!draggedDeal || !draggedFromStage) return

    if (draggedFromStage !== targetStageId) {
      setStages(prevStages => {
        const newStages = [...prevStages]
        const fromStage = newStages.find(s => s.id === draggedFromStage)
        const toStage = newStages.find(s => s.id === targetStageId)
        
        if (fromStage && toStage) {
          fromStage.deals = fromStage.deals.filter(d => d.id !== draggedDeal.id)
          toStage.deals = [...toStage.deals, { ...draggedDeal, daysInStage: 0 }]
        }
        
        return newStages
      })
    }

    setDraggedDeal(null)
    setDraggedFromStage(null)
  }

  const getPriorityColor = (priority: Deal['priority']) => {
    switch (priority) {
      case 'urgent': return 'text-red-600 bg-red-100 dark:bg-red-900/20'
      case 'high': return 'text-orange-600 bg-orange-100 dark:bg-orange-900/20'
      case 'medium': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/20'
      case 'low': return 'text-gray-600 bg-gray-100 dark:bg-gray-900/20'
    }
  }

  const getTotalPipelineValue = () => {
    return stages.reduce((total, stage) => {
      return total + stage.deals.reduce((stageTotal, deal) => stageTotal + deal.value, 0)
    }, 0)
  }

  const getWeightedPipelineValue = () => {
    return stages.reduce((total, stage) => {
      return total + stage.deals.reduce((stageTotal, deal) => {
        return stageTotal + (deal.value * deal.probability / 100)
      }, 0)
    }, 0)
  }

  return (
    <div className="space-y-6">
      {/* Pipeline Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Pipeline Value</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">
              ${getTotalPipelineValue().toLocaleString()}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Weighted Value</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">
              ${Math.round(getWeightedPipelineValue()).toLocaleString()}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Deals</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">
              {stages.reduce((total, stage) => total + stage.deals.length, 0)}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Avg. Deal Size</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">
              ${Math.round(getTotalPipelineValue() / stages.reduce((total, stage) => total + stage.deals.length, 0)).toLocaleString()}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Pipeline Board */}
      <ScrollArea className="w-full pb-4">
        <div className="flex space-x-4 min-w-max">
          {stages.map((stage) => (
            <div
              key={stage.id}
              className="flex-shrink-0 w-80"
              onDragOver={handleDragOver}
              onDrop={(e) => handleDrop(e, stage.id)}
            >
              <Card className="h-full">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className={`w-3 h-3 rounded-full ${stage.color}`} />
                      <CardTitle className="text-base">{stage.name}</CardTitle>
                      <Badge variant="secondary" className="text-xs">
                        {stage.deals.length}
                      </Badge>
                    </div>
                    <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  <CardDescription className="text-xs mt-1">
                    ${stage.deals.reduce((sum, deal) => sum + deal.value, 0).toLocaleString()}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {stage.deals.map((deal) => (
                    <div
                      key={deal.id}
                      draggable
                      onDragStart={() => handleDragStart(deal, stage.id)}
                      className="p-3 bg-white dark:bg-gray-800 border rounded-lg cursor-move hover:shadow-md transition-shadow"
                    >
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex-1">
                          <p className="font-medium text-sm">{deal.title}</p>
                          <p className="text-xs text-gray-500">{deal.company}</p>
                        </div>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                              <MoreVertical className="h-3 w-3" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem>View Details</DropdownMenuItem>
                            <DropdownMenuItem>Edit Deal</DropdownMenuItem>
                            <DropdownMenuItem>Add Activity</DropdownMenuItem>
                            <DropdownMenuItem className="text-red-600">Remove</DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>

                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-lg font-bold">${deal.value.toLocaleString()}</span>
                          <Badge className={`text-xs ${getPriorityColor(deal.priority)}`}>
                            {deal.priority}
                          </Badge>
                        </div>

                        <div className="flex items-center space-x-2 text-xs text-gray-500">
                          <User className="h-3 w-3" />
                          <span>{deal.contact}</span>
                        </div>

                        <div className="flex items-center space-x-2 text-xs text-gray-500">
                          <TrendingUp className="h-3 w-3" />
                          <span>{deal.probability}% probability</span>
                        </div>

                        <div className="flex items-center space-x-2 text-xs text-gray-500">
                          <Calendar className="h-3 w-3" />
                          <span>{deal.daysInStage} days in stage</span>
                        </div>

                        <div className="pt-2 border-t">
                          <p className="text-xs text-gray-600 dark:text-gray-400">
                            <span className="font-medium">Next:</span> {deal.nextAction}
                          </p>
                          <p className="text-xs text-gray-500 mt-1">
                            Owner: {deal.owner}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}

                  {stage.deals.length === 0 && (
                    <div className="py-8 text-center text-gray-400">
                      <p className="text-sm">No deals in this stage</p>
                      <p className="text-xs mt-1">Drag deals here to move them</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          ))}
        </div>
        <ScrollBar orientation="horizontal" />
      </ScrollArea>
    </div>
  )
}