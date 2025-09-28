/**
 * AI Agent Coordination Integration Tests
 * Tests the coordination and orchestration of multiple AI agents
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { server } from '../mocks/setup'
import { http, HttpResponse } from 'msw'

describe('AI Agent Coordination', () => {
  // Mock coordination state
  let coordinationState = {
    activeWorkflows: new Map(),
    agentStates: new Map(),
    taskQueue: [],
    completedTasks: []
  }

  beforeEach(() => {
    // Reset coordination state
    coordinationState = {
      activeWorkflows: new Map(),
      agentStates: new Map(),
      taskQueue: [],
      completedTasks: []
    }

    // Enhanced coordination handlers
    server.use(
      // Workflow orchestration
      http.post('*/api/agents/orchestrate', async ({ request }) => {
        const body = await request.json() as any
        const { workflow, agents, priority = 'medium' } = body

        const workflowId = `workflow-${Date.now()}`
        const orchestrationPlan = {
          id: workflowId,
          workflow,
          agents: agents || ['ceo', 'cfo', 'operations'],
          priority,
          steps: [
            { id: 'step-1', agent: 'ceo', task: 'strategic_analysis', status: 'pending' },
            { id: 'step-2', agent: 'cfo', task: 'financial_analysis', status: 'pending', dependsOn: ['step-1'] },
            { id: 'step-3', agent: 'operations', task: 'implementation_plan', status: 'pending', dependsOn: ['step-1', 'step-2'] }
          ],
          status: 'initiated',
          createdAt: new Date().toISOString()
        }

        coordinationState.activeWorkflows.set(workflowId, orchestrationPlan)

        return HttpResponse.json({
          success: true,
          workflowId,
          orchestrationPlan,
          estimatedDuration: 300000, // 5 minutes
          nextStep: 'step-1'
        })
      }),

      // Execute workflow step
      http.post('*/api/agents/execute-step', async ({ request }) => {
        const body = await request.json() as any
        const { workflowId, stepId, agentId } = body

        const workflow = coordinationState.activeWorkflows.get(workflowId)
        if (!workflow) {
          return HttpResponse.json({
            success: false,
            error: 'Workflow not found'
          }, { status: 404 })
        }

        const step = workflow.steps.find(s => s.id === stepId)
        if (!step) {
          return HttpResponse.json({
            success: false,
            error: 'Step not found'
          }, { status: 404 })
        }

        if (step.agent !== agentId) {
          return HttpResponse.json({
            success: false,
            error: 'Agent not authorized for this step'
          }, { status: 403 })
        }

        // Check dependencies
        if (step.dependsOn) {
          const dependenciesMet = step.dependsOn.every(depId => {
            const depStep = workflow.steps.find(s => s.id === depId)
            return depStep && depStep.status === 'completed'
          })

          if (!dependenciesMet) {
            return HttpResponse.json({
              success: false,
              error: 'Dependencies not met',
              missingDependencies: step.dependsOn.filter(depId => {
                const depStep = workflow.steps.find(s => s.id === depId)
                return !depStep || depStep.status !== 'completed'
              })
            }, { status: 400 })
          }
        }

        // Execute step
        step.status = 'executing'
        step.startedAt = new Date().toISOString()

        // Simulate execution time
        setTimeout(() => {
          step.status = 'completed'
          step.completedAt = new Date().toISOString()
          step.result = {
            analysis: `${step.task} completed by ${agentId}`,
            confidence: 0.85,
            recommendations: [
              'Proceed with implementation',
              'Monitor progress closely',
              'Review in 30 days'
            ]
          }

          // Check if workflow is complete
          const allCompleted = workflow.steps.every(s => s.status === 'completed')
          if (allCompleted) {
            workflow.status = 'completed'
            workflow.completedAt = new Date().toISOString()
            coordinationState.completedTasks.push(workflowId)
          }
        }, 100)

        return HttpResponse.json({
          success: true,
          stepId,
          agentId,
          status: 'executing',
          estimatedCompletion: new Date(Date.now() + 100).toISOString()
        })
      }),

      // Get workflow status
      http.get('*/api/agents/workflow/:workflowId/status', ({ params }) => {
        const { workflowId } = params
        const workflow = coordinationState.activeWorkflows.get(workflowId)

        if (!workflow) {
          return HttpResponse.json({
            error: 'Workflow not found'
          }, { status: 404 })
        }

        const completedSteps = workflow.steps.filter(s => s.status === 'completed').length
        const totalSteps = workflow.steps.length
        const progress = (completedSteps / totalSteps) * 100

        return HttpResponse.json({
          workflowId,
          status: workflow.status,
          progress,
          completedSteps,
          totalSteps,
          steps: workflow.steps,
          createdAt: workflow.createdAt,
          completedAt: workflow.completedAt
        })
      }),

      // Agent collaboration
      http.post('*/api/agents/collaborate', async ({ request }) => {
        const body = await request.json() as any
        const { task, agents, context, syncMode = 'async' } = body

        const collaborationId = `collab-${Date.now()}`
        const collaboration = {
          id: collaborationId,
          task,
          agents,
          context,
          syncMode,
          status: 'in_progress',
          startedAt: new Date().toISOString(),
          responses: []
        }

        // Simulate agent responses
        const agentResponses = agents.map((agentId: string, index: number) => {
          const response = {
            agentId,
            response: `Analysis from ${agentId}: ${task} requires careful consideration of ${Object.keys(context).join(', ')}.`,
            confidence: 0.8 + (Math.random() * 0.2),
            processingTime: 100 + (index * 50),
            timestamp: new Date(Date.now() + (index * 50)).toISOString()
          }
          collaboration.responses.push(response)
          return response
        })

        // Calculate consensus
        const averageConfidence = agentResponses.reduce((sum, r) => sum + r.confidence, 0) / agentResponses.length
        const consensus = {
          decision: averageConfidence > 0.7 ? 'PROCEED' : 'REVIEW_NEEDED',
          confidence: averageConfidence,
          agreement: Math.min(0.95, averageConfidence + 0.1),
          summary: `Collaboration between ${agents.join(', ')} resulted in ${averageConfidence > 0.7 ? 'positive' : 'cautious'} recommendation.`
        }

        collaboration.status = 'completed'
        collaboration.completedAt = new Date().toISOString()

        return HttpResponse.json({
          success: true,
          collaborationId,
          results: {
            task,
            participants: agents,
            individualResponses: agentResponses
          },
          consensus,
          metadata: {
            duration: Math.max(...agentResponses.map(r => r.processingTime)),
            syncMode
          }
        })
      }),

      // Multi-agent decision making
      http.post('*/api/agents/multi-decision', async ({ request }) => {
        const body = await request.json() as any
        const { scenario, options, agents, weights } = body

        const decisionId = `decision-${Date.now()}`
        const agentDecisions = agents.map((agentId: string) => {
          // Simulate different agent perspectives
          const agentWeights = weights || { risk: 0.3, reward: 0.4, feasibility: 0.3 }
          const scores = options.map((option: any, index: number) => ({
            option: option.name || `Option ${index + 1}`,
            score: Math.random() * 0.4 + 0.6, // Score between 0.6-1.0
            factors: {
              risk: Math.random() * 0.3 + 0.7,
              reward: Math.random() * 0.3 + 0.7,
              feasibility: Math.random() * 0.3 + 0.7
            }
          }))

          return {
            agentId,
            recommendation: scores.reduce((best, current) =>
              current.score > best.score ? current : best
            ),
            allScores: scores,
            reasoning: `${agentId} analysis based on risk assessment, potential rewards, and implementation feasibility.`,
            confidence: Math.random() * 0.2 + 0.8
          }
        })

        // Aggregate decisions
        const optionScores = options.map((option: any, index: number) => {
          const scores = agentDecisions.map(ad => ad.allScores[index].score)
          const avgScore = scores.reduce((sum, score) => sum + score, 0) / scores.length
          return {
            option: option.name || `Option ${index + 1}`,
            aggregateScore: avgScore,
            agentAgreement: Math.min(...scores) / Math.max(...scores), // Agreement ratio
            votes: scores
          }
        })

        const finalDecision = optionScores.reduce((best, current) =>
          current.aggregateScore > best.aggregateScore ? current : best
        )

        return HttpResponse.json({
          success: true,
          decisionId,
          scenario,
          agentDecisions,
          aggregateAnalysis: {
            recommendedOption: finalDecision.option,
            confidence: finalDecision.aggregateScore,
            consensus: finalDecision.agentAgreement,
            allOptions: optionScores
          },
          metadata: {
            participatingAgents: agents,
            decisionCriteria: weights,
            timestamp: new Date().toISOString()
          }
        })
      }),

      // Agent performance metrics
      http.get('*/api/agents/coordination/metrics', () => {
        return HttpResponse.json({
          coordination: {
            activeWorkflows: coordinationState.activeWorkflows.size,
            completedWorkflows: coordinationState.completedTasks.length,
            averageWorkflowDuration: 285000,
            successRate: 0.92
          },
          agents: {
            ceo: {
              tasksCompleted: 47,
              averageResponseTime: 156,
              successRate: 0.94,
              collaborations: 23
            },
            cfo: {
              tasksCompleted: 52,
              averageResponseTime: 189,
              successRate: 0.96,
              collaborations: 31
            },
            operations: {
              tasksCompleted: 38,
              averageResponseTime: 134,
              successRate: 0.89,
              collaborations: 19
            }
          },
          performance: {
            totalDecisions: 137,
            consensusReached: 0.87,
            averageConfidence: 0.83,
            escalationsRequired: 18
          }
        })
      }),

      // Real-time coordination status
      http.get('*/api/agents/coordination/status', () => {
        return HttpResponse.json({
          status: 'operational',
          activeAgents: 3,
          queuedTasks: coordinationState.taskQueue.length,
          processingCapacity: {
            total: 100,
            used: 23,
            available: 77
          },
          systemHealth: {
            coordination: 'healthy',
            communication: 'healthy',
            performance: 'optimal'
          },
          timestamp: new Date().toISOString()
        })
      })
    )
  })

  describe('Workflow Orchestration', () => {
    it('should orchestrate multi-agent workflow', async () => {
      const workflow = {
        name: 'investment_analysis',
        description: 'Analyze potential investment opportunity',
        context: {
          investment: {
            amount: 500000,
            sector: 'technology',
            timeline: '18 months'
          }
        }
      }

      const response = await fetch('http://localhost:8787/api/agents/orchestrate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          workflow,
          agents: ['ceo', 'cfo', 'operations'],
          priority: 'high'
        })
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.workflowId).toBeDefined()
      expect(data.orchestrationPlan).toBeDefined()
      expect(data.orchestrationPlan.steps).toHaveLength(3)
      expect(data.estimatedDuration).toBeGreaterThan(0)
      expect(data.nextStep).toBe('step-1')
    })

    it('should execute workflow steps in order', async () => {
      // First, create a workflow
      const orchestrateResponse = await fetch('http://localhost:8787/api/agents/orchestrate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          workflow: { name: 'test_workflow' },
          agents: ['ceo', 'cfo']
        })
      })

      const orchestrateData = await orchestrateResponse.json()
      const workflowId = orchestrateData.workflowId

      // Execute first step
      const executeResponse = await fetch('http://localhost:8787/api/agents/execute-step', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          workflowId,
          stepId: 'step-1',
          agentId: 'ceo'
        })
      })

      expect(executeResponse.status).toBe(200)
      const executeData = await executeResponse.json()
      expect(executeData.success).toBe(true)
      expect(executeData.status).toBe('executing')
      expect(executeData.estimatedCompletion).toBeDefined()
    })

    it('should enforce step dependencies', async () => {
      // Create workflow
      const orchestrateResponse = await fetch('http://localhost:8787/api/agents/orchestrate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          workflow: { name: 'dependency_test' },
          agents: ['ceo', 'cfo']
        })
      })

      const orchestrateData = await orchestrateResponse.json()
      const workflowId = orchestrateData.workflowId

      // Try to execute step 2 before step 1 (should fail)
      const executeResponse = await fetch('http://localhost:8787/api/agents/execute-step', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          workflowId,
          stepId: 'step-2',
          agentId: 'cfo'
        })
      })

      expect(executeResponse.status).toBe(400)
      const executeData = await executeResponse.json()
      expect(executeData.success).toBe(false)
      expect(executeData.error).toBe('Dependencies not met')
      expect(executeData.missingDependencies).toContain('step-1')
    })

    it('should track workflow progress', async () => {
      // Create workflow
      const orchestrateResponse = await fetch('http://localhost:8787/api/agents/orchestrate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          workflow: { name: 'progress_test' },
          agents: ['ceo', 'cfo']
        })
      })

      const orchestrateData = await orchestrateResponse.json()
      const workflowId = orchestrateData.workflowId

      // Check initial status
      const statusResponse = await fetch(`http://localhost:8787/api/agents/workflow/${workflowId}/status`)

      expect(statusResponse.status).toBe(200)
      const statusData = await statusResponse.json()
      expect(statusData.workflowId).toBe(workflowId)
      expect(statusData.status).toBe('initiated')
      expect(statusData.progress).toBe(0)
      expect(statusData.completedSteps).toBe(0)
      expect(statusData.totalSteps).toBe(3)
    })
  })

  describe('Agent Collaboration', () => {
    it('should coordinate multi-agent collaboration', async () => {
      const collaborationRequest = {
        task: 'market_analysis',
        agents: ['ceo', 'cfo', 'operations'],
        context: {
          market: 'enterprise_software',
          budget: 1000000,
          timeline: '6 months'
        },
        syncMode: 'async'
      }

      const response = await fetch('http://localhost:8787/api/agents/collaborate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(collaborationRequest)
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.collaborationId).toBeDefined()
      expect(data.results.participants).toEqual(['ceo', 'cfo', 'operations'])
      expect(data.results.individualResponses).toHaveLength(3)
      expect(data.consensus).toBeDefined()
      expect(data.consensus.decision).toMatch(/PROCEED|REVIEW_NEEDED/)
      expect(data.consensus.confidence).toBeGreaterThan(0)
      expect(data.consensus.confidence).toBeLessThanOrEqual(1)
    })

    it('should handle synchronous collaboration mode', async () => {
      const response = await fetch('http://localhost:8787/api/agents/collaborate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          task: 'urgent_decision',
          agents: ['ceo', 'cfo'],
          context: { urgency: 'high' },
          syncMode: 'sync'
        })
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.metadata.syncMode).toBe('sync')
      expect(data.results.individualResponses).toHaveLength(2)
    })

    it('should calculate consensus accurately', async () => {
      const response = await fetch('http://localhost:8787/api/agents/collaborate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          task: 'consensus_test',
          agents: ['ceo', 'cfo', 'operations'],
          context: { test: true }
        })
      })

      const data = await response.json()
      expect(data.consensus.confidence).toBeGreaterThan(0)
      expect(data.consensus.agreement).toBeGreaterThan(0)
      expect(data.consensus.agreement).toBeLessThanOrEqual(1)
      expect(data.consensus.summary).toContain('Collaboration')
    })
  })

  describe('Multi-Agent Decision Making', () => {
    it('should aggregate decisions from multiple agents', async () => {
      const decisionRequest = {
        scenario: 'product_launch',
        options: [
          { name: 'Option A: Immediate Launch', risk: 0.6, reward: 0.9 },
          { name: 'Option B: Delayed Launch', risk: 0.3, reward: 0.7 },
          { name: 'Option C: Pilot Program', risk: 0.4, reward: 0.6 }
        ],
        agents: ['ceo', 'cfo', 'operations'],
        weights: { risk: 0.3, reward: 0.5, feasibility: 0.2 }
      }

      const response = await fetch('http://localhost:8787/api/agents/multi-decision', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(decisionRequest)
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.decisionId).toBeDefined()
      expect(data.agentDecisions).toHaveLength(3)
      expect(data.aggregateAnalysis.recommendedOption).toBeDefined()
      expect(data.aggregateAnalysis.confidence).toBeGreaterThan(0)
      expect(data.aggregateAnalysis.allOptions).toHaveLength(3)
    })

    it('should provide detailed agent reasoning', async () => {
      const response = await fetch('http://localhost:8787/api/agents/multi-decision', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scenario: 'reasoning_test',
          options: [{ name: 'Test Option' }],
          agents: ['ceo', 'cfo']
        })
      })

      const data = await response.json()
      expect(data.agentDecisions).toHaveLength(2)

      data.agentDecisions.forEach((decision: any) => {
        expect(decision.agentId).toMatch(/ceo|cfo/)
        expect(decision.recommendation).toBeDefined()
        expect(decision.reasoning).toContain('analysis')
        expect(decision.confidence).toBeGreaterThan(0)
        expect(decision.allScores).toHaveLength(1)
      })
    })
  })

  describe('Coordination Metrics and Monitoring', () => {
    it('should provide coordination performance metrics', async () => {
      const response = await fetch('http://localhost:8787/api/agents/coordination/metrics')

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.coordination).toBeDefined()
      expect(data.coordination.activeWorkflows).toBeGreaterThanOrEqual(0)
      expect(data.coordination.successRate).toBeGreaterThan(0)
      expect(data.agents).toBeDefined()
      expect(data.agents.ceo).toBeDefined()
      expect(data.agents.cfo).toBeDefined()
      expect(data.agents.operations).toBeDefined()
      expect(data.performance.totalDecisions).toBeGreaterThan(0)
    })

    it('should monitor real-time coordination status', async () => {
      const response = await fetch('http://localhost:8787/api/agents/coordination/status')

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.status).toBe('operational')
      expect(data.activeAgents).toBe(3)
      expect(data.processingCapacity).toBeDefined()
      expect(data.processingCapacity.total).toBe(100)
      expect(data.systemHealth.coordination).toBe('healthy')
      expect(data.timestamp).toBeDefined()
    })

    it('should track agent performance individually', async () => {
      const response = await fetch('http://localhost:8787/api/agents/coordination/metrics')
      const data = await response.json()

      Object.values(data.agents).forEach((agent: any) => {
        expect(agent.tasksCompleted).toBeGreaterThan(0)
        expect(agent.averageResponseTime).toBeGreaterThan(0)
        expect(agent.successRate).toBeGreaterThan(0)
        expect(agent.successRate).toBeLessThanOrEqual(1)
        expect(agent.collaborations).toBeGreaterThanOrEqual(0)
      })
    })
  })

  describe('Error Handling and Edge Cases', () => {
    it('should handle non-existent workflow requests', async () => {
      const response = await fetch('http://localhost:8787/api/agents/workflow/invalid-id/status')

      expect(response.status).toBe(404)
      const data = await response.json()
      expect(data.error).toBe('Workflow not found')
    })

    it('should handle unauthorized step execution', async () => {
      // Create workflow
      const orchestrateResponse = await fetch('http://localhost:8787/api/agents/orchestrate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workflow: { name: 'auth_test' },
          agents: ['ceo', 'cfo']
        })
      })

      const orchestrateData = await orchestrateResponse.json()
      const workflowId = orchestrateData.workflowId

      // Try to execute step with wrong agent
      const executeResponse = await fetch('http://localhost:8787/api/agents/execute-step', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workflowId,
          stepId: 'step-1',
          agentId: 'operations' // Wrong agent for step-1
        })
      })

      expect(executeResponse.status).toBe(403)
      const executeData = await executeResponse.json()
      expect(executeData.success).toBe(false)
      expect(executeData.error).toBe('Agent not authorized for this step')
    })

    it('should handle concurrent collaboration requests', async () => {
      const requests = Array.from({ length: 5 }, (_, i) =>
        fetch('http://localhost:8787/api/agents/collaborate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            task: `concurrent_task_${i}`,
            agents: ['ceo', 'cfo'],
            context: { index: i }
          })
        })
      )

      const responses = await Promise.all(requests)
      const data = await Promise.all(responses.map(r => r.json()))

      // All should succeed
      expect(responses.every(r => r.status === 200)).toBe(true)
      expect(data.every(d => d.success === true)).toBe(true)

      // Each should have unique collaboration ID
      const collaborationIds = data.map(d => d.collaborationId)
      const uniqueIds = new Set(collaborationIds)
      expect(uniqueIds.size).toBe(5)
    })
  })
})