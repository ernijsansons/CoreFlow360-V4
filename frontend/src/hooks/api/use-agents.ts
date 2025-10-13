import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { agentsService } from '@/lib/api/services'
import { toast } from '@/hooks/use-toast'

// Query Keys
export const agentsKeys = {
  all: ['agents'] as const,
  list: () => [...agentsKeys.all, 'list'] as const,
  agent: (id: string) => [...agentsKeys.all, 'agent', id] as const,
  status: (id: string) => [...agentsKeys.all, 'status', id] as const,
  capabilities: (id: string) => [...agentsKeys.all, 'capabilities', id] as const,
  tasks: (filters?: unknown) => [...agentsKeys.all, 'tasks', filters] as const,
  task: (id: string) => [...agentsKeys.all, 'task', id] as const,
  metrics: (id: string, filters?: unknown) => [...agentsKeys.all, 'metrics', id, filters] as const,
}

// Agent Queries
export function useAgents() {
  return useQuery({
    queryKey: agentsKeys.list(),
    queryFn: () => agentsService.listAgents(),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

export function useAgent(id: string) {
  return useQuery({
    queryKey: agentsKeys.agent(id),
    queryFn: () => agentsService.getAgent(id),
    enabled: !!id,
  })
}

export function useAgentStatus(id: string) {
  return useQuery({
    queryKey: agentsKeys.status(id),
    queryFn: () => agentsService.getAgentStatus(id),
    enabled: !!id,
    refetchInterval: 10000, // Refresh every 10 seconds
  })
}

export function useAgentCapabilities(id: string) {
  return useQuery({
    queryKey: agentsKeys.capabilities(id),
    queryFn: () => agentsService.getAgentCapabilities(id),
    enabled: !!id,
  })
}

export function useAgentTasks(filters?: {
  agent_id?: string
  status?: 'pending' | 'in_progress' | 'completed' | 'failed'
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: agentsKeys.tasks(filters),
    queryFn: () => agentsService.listAgentTasks(filters),
    staleTime: 1000 * 30, // 30 seconds
  })
}

export function useAgentTask(taskId: string) {
  return useQuery({
    queryKey: agentsKeys.task(taskId),
    queryFn: () => agentsService.getAgentTask(taskId),
    enabled: !!taskId,
  })
}

export function useAgentMetrics(agentId: string, params?: {
  from_date?: string
  to_date?: string
}) {
  return useQuery({
    queryKey: agentsKeys.metrics(agentId, params),
    queryFn: () => agentsService.getAgentMetrics(agentId, params),
    enabled: !!agentId,
  })
}

// Agent Mutations
export function useExecuteAgentTask() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ agentId, task }: {
      agentId: string
      task: {
        task_type: string
        input_data: Record<string, unknown>
        priority?: 'low' | 'medium' | 'high' | 'urgent'
      }
    }) => agentsService.executeAgentTask(agentId, task),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentsKeys.tasks() })
      toast({
        title: 'Task started',
        description: 'The AI agent task has been initiated.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to execute task',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useCancelAgentTask() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (taskId: string) => agentsService.cancelAgentTask(taskId),
    onSuccess: (_, taskId) => {
      queryClient.invalidateQueries({ queryKey: agentsKeys.task(taskId) })
      queryClient.invalidateQueries({ queryKey: agentsKeys.tasks() })
      toast({
        title: 'Task cancelled',
        description: 'The agent task has been cancelled.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Failed to cancel task',
        description: error.message,
        variant: 'destructive',
      })
    },
  })
}

export function useEnableAgent() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (agentId: string) => agentsService.enableAgent(agentId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: agentsKeys.agent(data.data.id) })
      queryClient.invalidateQueries({ queryKey: agentsKeys.list() })
      toast({
        title: 'Agent enabled',
        description: 'The AI agent has been enabled.',
      })
    },
  })
}

export function useDisableAgent() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (agentId: string) => agentsService.disableAgent(agentId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: agentsKeys.agent(data.data.id) })
      queryClient.invalidateQueries({ queryKey: agentsKeys.list() })
      toast({
        title: 'Agent disabled',
        description: 'The AI agent has been disabled.',
      })
    },
  })
}
