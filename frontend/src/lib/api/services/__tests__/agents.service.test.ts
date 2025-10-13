import { describe, it, expect, vi, beforeEach } from 'vitest'
import { agentsService } from '../agents.service'
import apiClient from '../../client'

vi.mock('../../client')

describe('Agents Service', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('listAgents', () => {
    it('should list all agents with their status', async () => {
      const mockResponse = {
        data: [
          {
            id: 'agent-1',
            name: 'Finance Agent',
            type: 'finance',
            status: 'active',
            capabilities: ['invoice_creation', 'payment_processing'],
            last_active_at: '2025-10-12T10:00:00Z',
          },
          {
            id: 'agent-2',
            name: 'CRM Agent',
            type: 'crm',
            status: 'idle',
            capabilities: ['lead_qualification', 'email_automation'],
            last_active_at: '2025-10-12T09:30:00Z',
          },
        ],
        success: true,
      }

      vi.mocked(apiClient.get).mockResolvedValue(mockResponse)

      const result = await agentsService.listAgents()

      expect(apiClient.get).toHaveBeenCalledWith('/api/agents')
      expect(result.data).toHaveLength(2)
      expect(result.data[0].status).toBe('active')
    })
  })

  describe('getAgentStatus', () => {
    it('should get detailed agent status', async () => {
      const mockResponse = {
        data: {
          id: 'agent-1',
          status: 'active',
          current_task: {
            id: 'task-1',
            task_type: 'invoice_creation',
            status: 'in_progress',
            progress: 0.65,
          },
          metrics: {
            tasks_completed: 150,
            success_rate: 0.98,
            avg_response_time_ms: 250,
          },
        },
        success: true,
      }

      vi.mocked(apiClient.get).mockResolvedValue(mockResponse)

      const result = await agentsService.getAgentStatus('agent-1')

      expect(apiClient.get).toHaveBeenCalledWith('/api/agents/agent-1/status')
      expect(result.data.status).toBe('active')
      expect(result.data.metrics.success_rate).toBe(0.98)
    })
  })

  describe('executeAgentTask', () => {
    it('should execute a task with an agent', async () => {
      const mockResponse = {
        data: {
          id: 'task-1',
          agent_id: 'agent-1',
          task_type: 'invoice_creation',
          status: 'pending',
          priority: 'high',
          created_at: '2025-10-12T10:00:00Z',
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await agentsService.executeAgentTask('agent-1', {
        task_type: 'invoice_creation',
        input_data: { customer_id: 'cust-1', amount: 150 },
        priority: 'high',
      })

      expect(apiClient.post).toHaveBeenCalledWith('/api/agents/agent-1/execute', {
        task_type: 'invoice_creation',
        input_data: { customer_id: 'cust-1', amount: 150 },
        priority: 'high',
      })
      expect(result.data.status).toBe('pending')
    })
  })

  describe('listAgentTasks', () => {
    it('should list agent tasks with filters', async () => {
      const mockResponse = {
        data: [
          {
            id: 'task-1',
            agent_id: 'agent-1',
            task_type: 'invoice_creation',
            status: 'completed',
            priority: 'high',
            input_data: {},
            created_at: '2025-10-12T09:00:00Z',
            completed_at: '2025-10-12T09:05:00Z',
          },
        ],
        success: true,
      }

      vi.mocked(apiClient.get).mockResolvedValue(mockResponse)

      const result = await agentsService.listAgentTasks({
        agent_id: 'agent-1',
        status: 'completed',
        limit: 10,
      })

      expect(apiClient.get).toHaveBeenCalledWith(
        expect.stringContaining('/api/agents/tasks')
      )
      expect(result.data).toHaveLength(1)
      expect(result.data[0].status).toBe('completed')
    })
  })

  describe('enableAgent', () => {
    it('should enable an agent', async () => {
      const mockResponse = {
        data: {
          id: 'agent-1',
          status: 'active',
          message: 'Agent enabled successfully',
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await agentsService.enableAgent('agent-1')

      expect(apiClient.post).toHaveBeenCalledWith('/api/agents/agent-1/enable')
      expect(result.data.status).toBe('active')
    })
  })

  describe('disableAgent', () => {
    it('should disable an agent', async () => {
      const mockResponse = {
        data: {
          id: 'agent-1',
          status: 'disabled',
          message: 'Agent disabled successfully',
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await agentsService.disableAgent('agent-1')

      expect(apiClient.post).toHaveBeenCalledWith('/api/agents/agent-1/disable')
      expect(result.data.status).toBe('disabled')
    })
  })

  describe('getAgentCapabilities', () => {
    it('should get agent capabilities', async () => {
      const mockResponse = {
        data: {
          capabilities: [
            {
              name: 'invoice_creation',
              description: 'Create invoices automatically',
              parameters: {
                customer_id: 'string',
                amount: 'number',
              },
            },
          ],
        },
        success: true,
      }

      vi.mocked(apiClient.get).mockResolvedValue(mockResponse)

      const result = await agentsService.getAgentCapabilities('agent-1')

      expect(apiClient.get).toHaveBeenCalledWith('/api/agents/agent-1/capabilities')
      expect(result.data.capabilities).toHaveLength(1)
    })
  })
})
