import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  DollarSign,
  Calendar,
  MoreVertical,
  Plus,
  TrendingUp,
  AlertCircle,
  RefreshCw,
  Loader2,
  Filter,
  ChevronRight,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle
} from 'lucide-react'
import { usePipeline, useDeals, useMoveDealStage, useUpdateDeal, useCreateDeal } from '@/hooks/api/use-crm'
import { useToast } from '@/hooks/use-toast'
import { formatDistanceToNow } from 'date-fns'
import { DragDropContext, Droppable, Draggable } from '@hello-pangea/dnd'

interface Deal {
  id: string
  title: string
  company: string
  value: number
  stage: string
  probability: number
  owner: {
    name: string
    avatar?: string
  }
  expectedCloseDate: string
  lastActivity: string
  priority: 'low' | 'medium' | 'high' | 'critical'
  tags?: string[]
}

interface PipelineStage {
  id: string
  name: string
  color: string
  deals: Deal[]
  totalValue: number
  dealCount: number
}

const stageColors = {
  'prospecting': 'bg-blue-100 text-blue-800 border-blue-200',
  'qualification': 'bg-purple-100 text-purple-800 border-purple-200',
  'proposal': 'bg-yellow-100 text-yellow-800 border-yellow-200',
  'negotiation': 'bg-orange-100 text-orange-800 border-orange-200',
  'closing': 'bg-indigo-100 text-indigo-800 border-indigo-200',
  'won': 'bg-green-100 text-green-800 border-green-200',
  'lost': 'bg-red-100 text-red-800 border-red-200',
}

export function PipelineBoardEnhanced() {
  const { toast } = useToast()
  const [selectedOwner, setSelectedOwner] = React.useState<string>('all')
  const [showCreateDialog, setShowCreateDialog] = React.useState(false)

  // Fetch pipeline data
  const { data: pipelineData, isLoading: pipelineLoading, refetch: refetchPipeline } = usePipeline()
  const { data: dealsData, isLoading: dealsLoading, refetch: refetchDeals } = useDeals()

  // Mutations
  const moveDealStage = useMoveDealStage()
  const updateDeal = useUpdateDeal()
  const createDeal = useCreateDeal()

  const isLoading = pipelineLoading || dealsLoading

  // Mock data for development
  const mockStages: PipelineStage[] = [
    {
      id: 'prospecting',
      name: 'Prospecting',
      color: 'blue',
      deals: [
        {
          id: '1',
          title: 'Enterprise Software Deal',
          company: 'TechCorp Inc',
          value: 150000,
          stage: 'prospecting',
          probability: 20,
          owner: { name: 'John Doe', avatar: '/avatars/john.jpg' },
          expectedCloseDate: '2024-03-15',
          lastActivity: '2024-02-01',
          priority: 'high'
        },
        {
          id: '2',
          title: 'Cloud Migration Project',
          company: 'StartupXYZ',
          value: 75000,
          stage: 'prospecting',
          probability: 30,
          owner: { name: 'Jane Smith', avatar: '/avatars/jane.jpg' },
          expectedCloseDate: '2024-04-01',
          lastActivity: '2024-01-28',
          priority: 'medium'
        }
      ],
      totalValue: 225000,
      dealCount: 2
    },
    {
      id: 'qualification',
      name: 'Qualification',
      color: 'purple',
      deals: [
        {
          id: '3',
          title: 'SaaS Platform Integration',
          company: 'GlobalCorp',
          value: 200000,
          stage: 'qualification',
          probability: 40,
          owner: { name: 'Mike Johnson', avatar: '/avatars/mike.jpg' },
          expectedCloseDate: '2024-03-30',
          lastActivity: '2024-02-02',
          priority: 'critical'
        }
      ],
      totalValue: 200000,
      dealCount: 1
    },
    {
      id: 'proposal',
      name: 'Proposal',
      color: 'yellow',
      deals: [],
      totalValue: 0,
      dealCount: 0
    },
    {
      id: 'negotiation',
      name: 'Negotiation',
      color: 'orange',
      deals: [
        {
          id: '4',
          title: 'API Development Contract',
          company: 'DataTech Solutions',
          value: 95000,
          stage: 'negotiation',
          probability: 70,
          owner: { name: 'Sarah Lee', avatar: '/avatars/sarah.jpg' },
          expectedCloseDate: '2024-02-28',
          lastActivity: '2024-02-03',
          priority: 'high'
        }
      ],
      totalValue: 95000,
      dealCount: 1
    },
    {
      id: 'closing',
      name: 'Closing',
      color: 'indigo',
      deals: [],
      totalValue: 0,
      dealCount: 0
    }
  ]

  // Process pipeline data
  const stages = React.useMemo(() => {
    if (!pipelineData || !dealsData) return mockStages

    // Process and organize deals by stage
    const stageMap = new Map<string, PipelineStage>()

    // Initialize stages from pipeline data
    pipelineData.data?.stages?.forEach((stage: any) => {
      stageMap.set(stage.id, {
        id: stage.id,
        name: stage.name,
        color: stage.color || 'gray',
        deals: [],
        totalValue: 0,
        dealCount: 0
      })
    })

    // Add deals to appropriate stages
    dealsData.data?.forEach((deal: any) => {
      const stage = stageMap.get(deal.stage)
      if (stage) {
        stage.deals.push(deal)
        stage.totalValue += deal.value
        stage.dealCount++
      }
    })

    return Array.from(stageMap.values())
  }, [pipelineData, dealsData])

  // Calculate metrics
  const metrics = React.useMemo(() => {
    const totalDeals = stages.reduce((sum, stage) => sum + stage.dealCount, 0)
    const totalValue = stages.reduce((sum, stage) => sum + stage.totalValue, 0)
    const weightedValue = stages.reduce((sum, stage) => {
      return sum + stage.deals.reduce((stageSum, deal) => {
        return stageSum + (deal.value * (deal.probability / 100))
      }, 0)
    }, 0)

    return {
      totalDeals,
      totalValue,
      weightedValue,
      averageDealSize: totalDeals > 0 ? totalValue / totalDeals : 0
    }
  }, [stages])

  const handleDragEnd = async (result: any) => {
    if (!result.destination) return

    const { source, destination, draggableId } = result

    if (source.droppableId === destination.droppableId) {
      // Reordering within the same stage
      return
    }

    // Moving to a different stage
    try {
      await moveDealStage.mutateAsync({
        id: draggableId,
        stage: destination.droppableId
      })

      toast({
        title: 'Deal moved',
        description: 'Deal has been moved to the new stage.',
        variant: 'success',
      })
    } catch (error) {
      toast({
        title: 'Move failed',
        description: 'Failed to move deal. Please try again.',
        variant: 'destructive',
      })
    }
  }

  const handleUpdateDeal = async (dealId: string, updates: any) => {
    try {
      await updateDeal.mutateAsync({ id: dealId, data: updates })
      toast({
        title: 'Deal updated',
        description: 'Deal has been updated successfully.',
        variant: 'success',
      })
    } catch (error) {
      toast({
        title: 'Update failed',
        description: 'Failed to update deal. Please try again.',
        variant: 'destructive',
      })
    }
  }

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'critical':
        return <AlertCircle className="h-4 w-4 text-red-500" />
      case 'high':
        return <AlertTriangle className="h-4 w-4 text-orange-500" />
      case 'medium':
        return <Clock className="h-4 w-4 text-yellow-500" />
      case 'low':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      default:
        return null
    }
  }

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
    }).format(value)
  }

  const refetchData = () => {
    refetchPipeline()
    refetchDeals()
  }

  return (
    <div className="w-full space-y-4">
      {/* Header and Metrics */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="text-2xl">Sales Pipeline</CardTitle>
              <CardDescription>
                Track and manage your deals through the sales process
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="icon"
                onClick={refetchData}
                disabled={isLoading}
              >
                {isLoading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
              </Button>
              <Button onClick={() => setShowCreateDialog(true)}>
                <Plus className="h-4 w-4 mr-2" />
                New Deal
              </Button>
            </div>
          </div>

          {/* Metrics Cards */}
          <div className="grid grid-cols-4 gap-4 mt-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Total Deals</p>
                    <p className="text-2xl font-bold">{metrics.totalDeals}</p>
                  </div>
                  <TrendingUp className="h-8 w-8 text-blue-500" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Total Value</p>
                    <p className="text-2xl font-bold">{formatCurrency(metrics.totalValue)}</p>
                  </div>
                  <DollarSign className="h-8 w-8 text-green-500" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Weighted Value</p>
                    <p className="text-2xl font-bold">{formatCurrency(metrics.weightedValue)}</p>
                  </div>
                  <TrendingUp className="h-8 w-8 text-purple-500" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Avg Deal Size</p>
                    <p className="text-2xl font-bold">{formatCurrency(metrics.averageDealSize)}</p>
                  </div>
                  <ChevronRight className="h-8 w-8 text-orange-500" />
                </div>
              </CardContent>
            </Card>
          </div>
        </CardHeader>
      </Card>

      {/* Pipeline Stages */}
      {isLoading ? (
        <div className="flex gap-4 overflow-x-auto pb-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="min-w-[300px]">
              <Skeleton className="h-[600px] w-full" />
            </div>
          ))}
        </div>
      ) : (
        <DragDropContext onDragEnd={handleDragEnd}>
          <div className="flex gap-4 overflow-x-auto pb-4">
            {stages.map((stage) => (
              <div key={stage.id} className="min-w-[320px]">
                <Card className="h-full">
                  <CardHeader className={`py-3 ${stageColors[stage.id as keyof typeof stageColors] || 'bg-gray-100'}`}>
                    <div className="flex justify-between items-center">
                      <div>
                        <CardTitle className="text-lg">{stage.name}</CardTitle>
                        <CardDescription className="text-sm mt-1">
                          {stage.dealCount} deals • {formatCurrency(stage.totalValue)}
                        </CardDescription>
                      </div>
                      <Badge variant="secondary" className="font-bold">
                        {stage.dealCount}
                      </Badge>
                    </div>
                  </CardHeader>

                  <Droppable droppableId={stage.id}>
                    {(provided, snapshot) => (
                      <CardContent
                        ref={provided.innerRef}
                        {...provided.droppableProps}
                        className={`p-2 min-h-[400px] ${
                          snapshot.isDraggingOver ? 'bg-gray-50' : ''
                        }`}
                      >
                        {stage.deals.length === 0 ? (
                          <div className="text-center py-8 text-gray-500">
                            <p>No deals in this stage</p>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="mt-2"
                              onClick={() => setShowCreateDialog(true)}
                            >
                              <Plus className="h-4 w-4 mr-1" />
                              Add Deal
                            </Button>
                          </div>
                        ) : (
                          stage.deals.map((deal, index) => (
                            <Draggable key={deal.id} draggableId={deal.id} index={index}>
                              {(provided, snapshot) => (
                                <div
                                  ref={provided.innerRef}
                                  {...provided.draggableProps}
                                  {...provided.dragHandleProps}
                                  className={`mb-2 ${snapshot.isDragging ? 'opacity-50' : ''}`}
                                >
                                  <Card className="cursor-move hover:shadow-md transition-shadow">
                                    <CardContent className="p-3">
                                      <div className="flex justify-between items-start mb-2">
                                        <div className="flex-1">
                                          <h4 className="font-semibold text-sm line-clamp-1">
                                            {deal.title}
                                          </h4>
                                          <p className="text-xs text-gray-600 mt-1">
                                            {deal.company}
                                          </p>
                                        </div>
                                        <DropdownMenu>
                                          <DropdownMenuTrigger asChild>
                                            <Button variant="ghost" size="icon" className="h-6 w-6">
                                              <MoreVertical className="h-4 w-4" />
                                            </Button>
                                          </DropdownMenuTrigger>
                                          <DropdownMenuContent align="end">
                                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                                            <DropdownMenuItem>View Details</DropdownMenuItem>
                                            <DropdownMenuItem>Edit Deal</DropdownMenuItem>
                                            <DropdownMenuItem>Add Note</DropdownMenuItem>
                                            <DropdownMenuSeparator />
                                            <DropdownMenuItem
                                              onClick={() => handleUpdateDeal(deal.id, { status: 'won' })}
                                              className="text-green-600"
                                            >
                                              Mark as Won
                                            </DropdownMenuItem>
                                            <DropdownMenuItem
                                              onClick={() => handleUpdateDeal(deal.id, { status: 'lost' })}
                                              className="text-red-600"
                                            >
                                              Mark as Lost
                                            </DropdownMenuItem>
                                          </DropdownMenuContent>
                                        </DropdownMenu>
                                      </div>

                                      <div className="space-y-2">
                                        <div className="flex justify-between items-center">
                                          <span className="text-lg font-bold">
                                            {formatCurrency(deal.value)}
                                          </span>
                                          <div className="flex items-center gap-1">
                                            {getPriorityIcon(deal.priority)}
                                            <Badge variant="outline" className="text-xs">
                                              {deal.probability}%
                                            </Badge>
                                          </div>
                                        </div>

                                        <div className="flex items-center justify-between text-xs text-gray-600">
                                          <div className="flex items-center gap-1">
                                            <Avatar className="h-5 w-5">
                                              <AvatarImage src={deal.owner.avatar} />
                                              <AvatarFallback>
                                                {deal.owner.name.split(' ').map(n => n[0]).join('')}
                                              </AvatarFallback>
                                            </Avatar>
                                            <span>{deal.owner.name}</span>
                                          </div>
                                          <div className="flex items-center gap-1">
                                            <Calendar className="h-3 w-3" />
                                            <span>{new Date(deal.expectedCloseDate).toLocaleDateString()}</span>
                                          </div>
                                        </div>

                                        {deal.tags && deal.tags.length > 0 && (
                                          <div className="flex gap-1 flex-wrap">
                                            {deal.tags.map((tag, i) => (
                                              <Badge key={i} variant="secondary" className="text-xs">
                                                {tag}
                                              </Badge>
                                            ))}
                                          </div>
                                        )}
                                      </div>
                                    </CardContent>
                                  </Card>
                                </div>
                              )}
                            </Draggable>
                          ))
                        )}
                        {provided.placeholder}
                      </CardContent>
                    )}
                  </Droppable>
                </Card>
              </div>
            ))}
          </div>
        </DragDropContext>
      )}
    </div>
  )
}