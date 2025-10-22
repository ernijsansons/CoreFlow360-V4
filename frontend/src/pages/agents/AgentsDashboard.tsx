import { useState } from 'react'
import { useAgents, useAgentTasks, useEnableAgent, useDisableAgent } from '@/hooks/api'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import { Loader2, Play, Pause, Activity, CheckCircle2, XCircle, Clock } from 'lucide-react'

export function AgentsDashboard() {
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null)
  const { data: agents, isLoading: agentsLoading } = useAgents()
  const { data: tasks, isLoading: tasksLoading } = useAgentTasks({
    agent_id: selectedAgent || undefined,
    limit: 50
  })
  const enableAgent = useEnableAgent()
  const disableAgent = useDisableAgent()

  if (agentsLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
      </div>
    )
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-500'
      case 'idle': return 'bg-yellow-500'
      case 'error': return 'bg-red-500'
      case 'disabled': return 'bg-gray-500'
      default: return 'bg-gray-500'
    }
  }

  const getTaskStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle2 className="h-4 w-4 text-green-500" />
      case 'failed': return <XCircle className="h-4 w-4 text-red-500" />
      case 'in_progress': return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
      default: return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">AI Agents</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Manage your autonomous AI agents and monitor their tasks
        </p>
      </div>

      {/* Agents Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {agents?.data?.map((agent) => (
          <Card
            key={agent.id}
            className={`p-6 cursor-pointer transition-all hover:shadow-lg ${
              selectedAgent === agent.id ? 'ring-2 ring-brand-primary' : ''
            }`}
            onClick={() => setSelectedAgent(agent.id)}
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center space-x-3">
                <div className={`h-3 w-3 rounded-full ${getStatusColor(agent.status)}`} />
                <h3 className="font-semibold text-lg">{agent.name}</h3>
              </div>
              <Badge variant={agent.status === 'active' ? 'default' : 'secondary'}>
                {agent.status}
              </Badge>
            </div>

            <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
              {agent.type}
            </p>

            <div className="flex flex-wrap gap-2 mb-4">
              {agent.capabilities.slice(0, 3).map((capability) => (
                <Badge key={capability} variant="outline" className="text-xs">
                  {capability}
                </Badge>
              ))}
              {agent.capabilities.length > 3 && (
                <Badge variant="outline" className="text-xs">
                  +{agent.capabilities.length - 3} more
                </Badge>
              )}
            </div>

            <div className="flex items-center justify-between text-sm text-gray-500">
              <span className="flex items-center space-x-1">
                <Activity className="h-4 w-4" />
                <span>
                  {agent.last_active_at
                    ? new Date(agent.last_active_at).toLocaleDateString()
                    : 'Never'}
                </span>
              </span>
              {agent.status === 'active' ? (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={(e) => {
                    e.stopPropagation()
                    disableAgent.mutate(agent.id)
                  }}
                >
                  <Pause className="h-4 w-4 mr-1" />
                  Disable
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={(e) => {
                    e.stopPropagation()
                    enableAgent.mutate(agent.id)
                  }}
                >
                  <Play className="h-4 w-4 mr-1" />
                  Enable
                </Button>
              )}
            </div>
          </Card>
        ))}
      </div>

      {/* Selected Agent Tasks */}
      {selectedAgent && (
        <Card className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold">Recent Tasks</h2>
            <Button
              onClick={() => {
                // Open task creation dialog
                console.log('Create task for agent:', selectedAgent)
              }}
            >
              <Play className="h-4 w-4 mr-2" />
              Execute Task
            </Button>
          </div>

          {tasksLoading ? (
            <div className="flex items-center justify-center h-48">
              <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
            </div>
          ) : (
            <div className="space-y-3">
              {tasks?.data && tasks.data.length > 0 ? (
                tasks.data.map((task) => (
                  <div
                    key={task.id}
                    className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                  >
                    <div className="flex items-center space-x-4 flex-1">
                      {getTaskStatusIcon(task.status)}
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-medium">{task.task_type}</span>
                          <Badge variant="outline" className="text-xs">
                            {task.priority}
                          </Badge>
                        </div>
                        <p className="text-sm text-gray-500 mt-1">
                          Started: {new Date(task.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <Badge
                      variant={
                        task.status === 'completed'
                          ? 'default'
                          : task.status === 'failed'
                          ? 'destructive'
                          : 'secondary'
                      }
                    >
                      {task.status}
                    </Badge>
                  </div>
                ))
              ) : (
                <div className="text-center py-12 text-gray-500">
                  No tasks found for this agent
                </div>
              )}
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
