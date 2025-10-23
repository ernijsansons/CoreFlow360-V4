/**
 * Agent Coordinator Service
 * Orchestrates multiple AI agents for autonomous business operations
 * Part of CoreFlow360 V4 AI-First Architecture
 */

import { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';

export interface AIAgent {
  id: string;
  name: string;
  type: 'finance' | 'crm' | 'operations' | 'support' | 'email';
  status: 'active' | 'inactive' | 'busy' | 'error';
  capabilities: string[];
  lastActivity: Date;
  performance: {
    tasksCompleted: number;
    averageResponseTime: number;
    successRate: number;
  };
}

export interface AgentTask {
  id: string;
  agentId: string;
  type: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  payload: Record<string, any>;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  createdAt: Date;
  completedAt?: Date;
  result?: Record<string, any>;
  error?: string;
}

export class AgentCoordinator {
  private agents: Map<string, AIAgent> = new Map();
  private taskQueue: AgentTask[] = [];
  private activeTaskIds: Set<string> = new Set();

  constructor() {
    this.initializeAgents();
  }

  private initializeAgents(): void {
    const defaultAgents: AIAgent[] = [
      {
        id: 'finance-agent-001',
        name: 'Autonomous Finance Agent',
        type: 'finance',
        status: 'active',
        capabilities: [
          'double-entry-bookkeeping',
          'invoice-automation',
          'tax-calculation',
          'cash-flow-prediction',
          'expense-categorization',
          'financial-reporting'
        ],
        lastActivity: new Date(),
        performance: {
          tasksCompleted: 0,
          averageResponseTime: 850,
          successRate: 98.5
        }
      },
      {
        id: 'crm-agent-001',
        name: 'Intelligent CRM Agent',
        type: 'crm',
        status: 'active',
        capabilities: [
          'lead-qualification',
          'contact-enrichment',
          'deal-progression',
          'follow-up-automation',
          'customer-segmentation',
          'pipeline-optimization'
        ],
        lastActivity: new Date(),
        performance: {
          tasksCompleted: 0,
          averageResponseTime: 1200,
          successRate: 96.8
        }
      },
      {
        id: 'operations-agent-001',
        name: 'Operations Management Agent',
        type: 'operations',
        status: 'active',
        capabilities: [
          'inventory-management',
          'supplier-coordination',
          'demand-forecasting',
          'quality-monitoring',
          'workflow-optimization',
          'resource-allocation'
        ],
        lastActivity: new Date(),
        performance: {
          tasksCompleted: 0,
          averageResponseTime: 950,
          successRate: 97.2
        }
      },
      {
        id: 'support-agent-001',
        name: 'Customer Support Agent',
        type: 'support',
        status: 'active',
        capabilities: [
          'ticket-triage',
          'response-generation',
          'escalation-management',
          'knowledge-base-queries',
          'customer-satisfaction-tracking',
          'issue-resolution'
        ],
        lastActivity: new Date(),
        performance: {
          tasksCompleted: 0,
          averageResponseTime: 650,
          successRate: 99.1
        }
      },
      {
        id: 'email-agent-001',
        name: 'Email Communication Agent',
        type: 'email',
        status: 'active',
        capabilities: [
          'email-composition',
          'template-personalization',
          'sending-optimization',
          'response-tracking',
          'campaign-automation',
          'deliverability-optimization'
        ],
        lastActivity: new Date(),
        performance: {
          tasksCompleted: 0,
          averageResponseTime: 450,
          successRate: 98.9
        }
      }
    ];

    defaultAgents.forEach(agent => {
      this.agents.set(agent.id, agent);
    });
  }

  /**
   * Get all registered agents
   */
  public getAgents(): AIAgent[] {
    return Array.from(this.agents.values());
  }

  /**
   * Get agent by ID
   */
  public getAgent(agentId: string): AIAgent | undefined {
    return this.agents.get(agentId);
  }

  /**
   * Get agents by type
   */
  public getAgentsByType(type: AIAgent['type']): AIAgent[] {
    return Array.from(this.agents.values()).filter(agent => agent.type === type);
  }

  /**
   * Assign task to appropriate agent
   */
  public async assignTask(task: Omit<AgentTask, 'id' | 'status' | 'createdAt'>): Promise<AgentTask> {
    const taskId = `task-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const newTask: AgentTask = {
      id: taskId,
      status: 'pending',
      createdAt: new Date(),
      ...task
    };

    // Validate agent exists and is available
    const agent = this.agents.get(task.agentId);
    if (!agent) {
      throw new HTTPException(404, { message: `Agent ${task.agentId} not found` });
    }

    if (agent.status !== 'active') {
      throw new HTTPException(400, { message: `Agent ${task.agentId} is not available (status: ${agent.status})` });
    }

    // Add to queue
    this.taskQueue.push(newTask);
    
    // Process task immediately if possible
    await this.processTask(newTask);

    return newTask;
  }

  /**
   * Process a task
   */
  private async processTask(task: AgentTask): Promise<void> {
    try {
      // Mark task as in progress
      task.status = 'in_progress';
      this.activeTaskIds.add(task.id);

      const agent = this.agents.get(task.agentId);
      if (!agent) {
        throw new Error(`Agent ${task.agentId} not found`);
      }

      // Update agent status
      agent.status = 'busy';
      agent.lastActivity = new Date();

      // Simulate task processing (in real implementation, this would call the actual agent)
      const startTime = Date.now();
      
      // Mock processing time based on task complexity
      const processingTime = this.calculateProcessingTime(task.type);
      await new Promise(resolve => setTimeout(resolve, processingTime));

      // Mock successful completion
      const endTime = Date.now();
      const responseTime = endTime - startTime;

      // Update task
      task.status = 'completed';
      task.completedAt = new Date();
      task.result = this.generateMockResult(task);

      // Update agent performance
      agent.performance.tasksCompleted += 1;
      agent.performance.averageResponseTime = 
        (agent.performance.averageResponseTime + responseTime) / 2;
      agent.status = 'active';

      this.activeTaskIds.delete(task.id);

    } catch (error) {
      // Handle task failure
      task.status = 'failed';
      task.error = error instanceof Error ? error.message : 'Unknown error';
      task.completedAt = new Date();

      const agent = this.agents.get(task.agentId);
      if (agent) {
        agent.status = 'error';
        agent.performance.successRate = Math.max(0, agent.performance.successRate - 0.1);
      }

      this.activeTaskIds.delete(task.id);
    }
  }

  /**
   * Calculate processing time based on task complexity
   */
  private calculateProcessingTime(taskType: string): number {
    const baseTime = 500; // 500ms base
    const complexityMultipliers: Record<string, number> = {
      'financial-calculation': 2,
      'lead-qualification': 1.5,
      'inventory-forecast': 3,
      'email-composition': 1,
      'customer-query': 1.2
    };

    return baseTime * (complexityMultipliers[taskType] || 1);
  }

  /**
   * Generate mock result for completed task
   */
  private generateMockResult(task: AgentTask): Record<string, any> {
    const baseResult = {
      taskId: task.id,
      agentId: task.agentId,
      completedAt: new Date().toISOString(),
      processingTimeMs: Date.now() - task.createdAt.getTime()
    };

    // Add task-specific results
    switch (task.type) {
      case 'financial-calculation':
        return {
          ...baseResult,
          calculation: {
            amount: Math.random() * 10000,
            currency: 'USD',
            category: 'revenue',
            confidence: 0.95
          }
        };
      
      case 'lead-qualification':
        return {
          ...baseResult,
          qualification: {
            score: Math.floor(Math.random() * 100),
            category: 'hot',
            nextAction: 'schedule-demo',
            confidence: 0.87
          }
        };
      
      default:
        return {
          ...baseResult,
          status: 'completed',
          data: task.payload
        };
    }
  }

  /**
   * Get task status
   */
  public getTask(taskId: string): AgentTask | undefined {
    return this.taskQueue.find(task => task.id === taskId);
  }

  /**
   * Get all tasks for an agent
   */
  public getTasksForAgent(agentId: string): AgentTask[] {
    return this.taskQueue.filter(task => task.agentId === agentId);
  }

  /**
   * Get system status
   */
  public getSystemStatus(): {
    totalAgents: number;
    activeAgents: number;
    totalTasks: number;
    activeTasks: number;
    avgResponseTime: number;
    overallSuccessRate: number;
  } {
    const agents = this.getAgents();
    const activeAgents = agents.filter(agent => agent.status === 'active').length;
    const totalTasks = agents.reduce((sum, agent) => sum + agent.performance.tasksCompleted, 0);
    const avgResponseTime = agents.reduce((sum, agent) => sum + agent.performance.averageResponseTime, 0) / agents.length;
    const overallSuccessRate = agents.reduce((sum, agent) => sum + agent.performance.successRate, 0) / agents.length;

    return {
      totalAgents: agents.length,
      activeAgents,
      totalTasks,
      activeTasks: this.activeTaskIds.size,
      avgResponseTime: Math.round(avgResponseTime),
      overallSuccessRate: Math.round(overallSuccessRate * 100) / 100
    };
  }

  /**
   * Update agent status
   */
  public updateAgentStatus(agentId: string, status: AIAgent['status']): boolean {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return false;
    }

    agent.status = status;
    agent.lastActivity = new Date();
    return true;
  }

  /**
   * Add new agent capability
   */
  public addAgentCapability(agentId: string, capability: string): boolean {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return false;
    }

    if (!agent.capabilities.includes(capability)) {
      agent.capabilities.push(capability);
    }
    return true;
  }

  /**
   * Remove agent capability
   */
  public removeAgentCapability(agentId: string, capability: string): boolean {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return false;
    }

    const index = agent.capabilities.indexOf(capability);
    if (index > -1) {
      agent.capabilities.splice(index, 1);
    }
    return true;
  }
}

// Singleton instance
export const agentCoordinator = new AgentCoordinator();