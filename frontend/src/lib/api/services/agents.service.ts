import apiClient, { ApiResponse } from '../client'

export interface Agent {
  id: string
  name: string
  type: string
  status: 'active' | 'idle' | 'error' | 'disabled'
  capabilities: string[]
  last_active_at?: string
  created_at: string
}

export interface AgentTask {
  id: string
  agent_id: string
  task_type: string
  status: 'pending' | 'in_progress' | 'completed' | 'failed'
  priority: 'low' | 'medium' | 'high' | 'urgent'
  input_data: Record<string, unknown>
  output_data?: Record<string, unknown>
  error?: string
  created_at: string
  completed_at?: string
}

export interface AgentMetrics {
  total_tasks: number
  completed_tasks: number
  failed_tasks: number
  avg_completion_time_ms: number
  success_rate: number
}

class AgentsService {
  async listAgents(): Promise<ApiResponse<Agent[]>> {
    return apiClient.get<Agent[]>('/api/agents')
  }

  async getAgent(id: string): Promise<ApiResponse<Agent>> {
    return apiClient.get<Agent>(`/api/agents/${id}`)
  }

  async getAgentStatus(id: string): Promise<ApiResponse<{
    status: string
    active_tasks: number
    last_active_at?: string
  }>> {
    return apiClient.get(`/api/agents/${id}/status`)
  }

  async getAgentCapabilities(id: string): Promise<ApiResponse<{
    capabilities: Array<{
      name: string
      description: string
      parameters: Record<string, unknown>
    }>
  }>> {
    return apiClient.get(`/api/agents/${id}/capabilities`)
  }

  async executeAgentTask(agentId: string, task: {
    task_type: string
    input_data: Record<string, unknown>
    priority?: 'low' | 'medium' | 'high' | 'urgent'
  }): Promise<ApiResponse<AgentTask>> {
    return apiClient.post<AgentTask>(`/api/agents/${agentId}/execute`, task)
  }

  async listAgentTasks(params?: {
    agent_id?: string
    status?: 'pending' | 'in_progress' | 'completed' | 'failed'
    limit?: number
    offset?: number
  }): Promise<ApiResponse<AgentTask[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<AgentTask[]>(`/api/agents/tasks?${query}`)
  }

  async getAgentTask(taskId: string): Promise<ApiResponse<AgentTask>> {
    return apiClient.get<AgentTask>(`/api/agents/tasks/${taskId}`)
  }

  async cancelAgentTask(taskId: string): Promise<ApiResponse<void>> {
    return apiClient.post(`/api/agents/tasks/${taskId}/cancel`)
  }

  async getAgentMetrics(agentId: string, params?: {
    from_date?: string
    to_date?: string
  }): Promise<ApiResponse<AgentMetrics>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<AgentMetrics>(`/api/agents/${agentId}/metrics?${query}`)
  }

  async enableAgent(id: string): Promise<ApiResponse<Agent>> {
    return apiClient.post<Agent>(`/api/agents/${id}/enable`)
  }

  async disableAgent(id: string): Promise<ApiResponse<Agent>> {
    return apiClient.post<Agent>(`/api/agents/${id}/disable`)
  }
}

export const agentsService = new AgentsService()
export default agentsService
