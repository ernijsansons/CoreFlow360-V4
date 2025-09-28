/**
 * Agent System Mock Handlers
 * MSW handlers for agent-related API endpoints
 */

import { http, HttpResponse } from 'msw'

export const agentHandlers = [
  // AgentService Endpoints (/agents/*)
  http.get('*/agents/health', () => {
    return HttpResponse.json({
      status: 'healthy',
      agentSystem: {
        connected: true,
        version: '1.0.0',
        lastSync: new Date().toISOString()
      },
      timestamp: new Date().toISOString()
    })
  }),

  http.get('*/agents/status', () => {
    return HttpResponse.json({
      connected: true,
      syncStatus: {
        isRunning: false,
        lastSync: new Date().toISOString(),
        nextSync: null,
        totalRecordsProcessed: 0
      },
      agentSystem: {
        status: 'ready',
        activeAgents: 3,
        totalRequests: 127
      }
    })
  }),

  http.get('*/agents/list', () => {
    return HttpResponse.json({
      agents: [
        {
          id: 'ceo',
          name: 'CEO Agent',
          type: 'executive',
          capabilities: ['strategic_planning', 'financial_oversight', 'leadership'],
          status: 'active',
          lastActivity: new Date().toISOString()
        },
        {
          id: 'cfo',
          name: 'CFO Agent',
          type: 'financial',
          capabilities: ['financial_analysis', 'budget_management', 'risk_assessment'],
          status: 'active',
          lastActivity: new Date().toISOString()
        },
        {
          id: 'operations',
          name: 'Operations Agent',
          type: 'operational',
          capabilities: ['process_optimization', 'inventory_management', 'workflow_automation'],
          status: 'active',
          lastActivity: new Date().toISOString()
        }
      ],
      total: 3,
      timestamp: new Date().toISOString()
    })
  }),

  http.post('*/agents/decide', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      success: true,
      decision: {
        id: `decision-${Date.now()}`,
        type: body.type || 'strategic_financial',
        recommendation: 'APPROVE',
        confidence: 0.85,
        reasoning: 'Based on financial analysis, this investment shows strong potential ROI',
        factors: [
          { name: 'ROI Potential', score: 0.9, weight: 0.4 },
          { name: 'Risk Assessment', score: 0.7, weight: 0.3 },
          { name: 'Market Conditions', score: 0.8, weight: 0.3 }
        ],
        agentId: 'cfo',
        timestamp: new Date().toISOString()
      },
      metadata: {
        processingTime: 245,
        agentsConsulted: ['cfo', 'ceo']
      }
    })
  }),

  http.post('*/agents/collaborate', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      success: true,
      results: {
        taskId: `task-${Date.now()}`,
        task: body.task || 'evaluate_investment',
        participants: body.agents || ['ceo', 'cfo'],
        individualResponses: [
          {
            agentId: 'ceo',
            response: 'Strategic alignment looks good. Proceed with caution.',
            confidence: 0.8,
            timestamp: new Date().toISOString()
          },
          {
            agentId: 'cfo',
            response: 'Financial projections are solid. ROI expectations are realistic.',
            confidence: 0.9,
            timestamp: new Date().toISOString()
          }
        ]
      },
      consensus: {
        decision: 'APPROVE',
        confidence: 0.85,
        agreement: 0.92,
        summary: 'Both agents agree on proceeding with the investment with careful monitoring.',
        timestamp: new Date().toISOString()
      }
    })
  }),

  // Agent API Endpoints (/api/v4/agents/*)
  http.get('*/api/v4/agents/capabilities', () => {
    return HttpResponse.json({
      capabilities: [
        {
          id: 'ceo',
          name: 'CEO Agent',
          type: 'executive',
          description: 'Strategic decision making and leadership oversight',
          functions: ['strategic_planning', 'financial_oversight', 'leadership'],
          availability: 'active'
        },
        {
          id: 'cfo',
          name: 'CFO Agent',
          type: 'financial',
          description: 'Financial analysis and budget management',
          functions: ['financial_analysis', 'budget_management', 'risk_assessment'],
          availability: 'active'
        },
        {
          id: 'operations',
          name: 'Operations Agent',
          type: 'operational',
          description: 'Process optimization and workflow management',
          functions: ['process_optimization', 'inventory_management', 'workflow_automation'],
          availability: 'active'
        }
      ],
      total: 3,
      timestamp: new Date().toISOString()
    })
  }),

  http.get('*/api/v4/agents/capabilities/:agentId', ({ params }) => {
    const { agentId } = params
    const capabilities = {
      ceo: {
        id: 'ceo',
        name: 'CEO Agent',
        type: 'executive',
        description: 'Strategic decision making and leadership oversight',
        functions: ['strategic_planning', 'financial_oversight', 'leadership'],
        permissions: ['read_all', 'approve_high_value', 'strategic_decisions'],
        availability: 'active',
        lastActive: new Date().toISOString()
      },
      cfo: {
        id: 'cfo',
        name: 'CFO Agent',
        type: 'financial',
        description: 'Financial analysis and budget management',
        functions: ['financial_analysis', 'budget_management', 'risk_assessment'],
        permissions: ['read_financial', 'approve_budget', 'financial_reports'],
        availability: 'active',
        lastActive: new Date().toISOString()
      }
    }

    const capability = capabilities[agentId as keyof typeof capabilities]
    if (!capability) {
      return HttpResponse.json({ error: 'Agent not found' }, { status: 404 })
    }

    return HttpResponse.json({
      capability,
      timestamp: new Date().toISOString()
    })
  }),

  http.post('*/api/v4/agents/workflow/:workflowId/connect', ({ params }) => {
    const { workflowId } = params
    return HttpResponse.json({
      success: true,
      message: `Workflow ${workflowId} successfully connected to agent system`,
      workflowId,
      connectedAgents: ['ceo', 'cfo', 'operations'],
      status: 'connected',
      timestamp: new Date().toISOString()
    })
  }),

  http.get('*/api/v4/agents/sync/status', () => {
    return HttpResponse.json({
      statistics: {
        isRunning: false,
        lastSync: new Date(Date.now() - 60000).toISOString(),
        nextSync: null,
        totalRecordsProcessed: 1247,
        successfulSyncs: 98,
        failedSyncs: 2,
        averageProcessingTime: 245
      },
      status: 'idle',
      timestamp: new Date().toISOString()
    })
  }),

  // Proxy Endpoints (/api/ai/*)
  http.get('*/api/ai/health', () => {
    return HttpResponse.json({
      status: 'healthy',
      agents: {
        total: 3,
        active: 3,
        inactive: 0
      },
      system: {
        uptime: 86400,
        version: '1.0.0',
        environment: 'test'
      },
      timestamp: new Date().toISOString()
    })
  }),

  http.get('*/api/ai/api/agents/status', () => {
    return HttpResponse.json({
      status: 'operational',
      agents: [
        { id: 'ceo', status: 'active', load: 0.2 },
        { id: 'cfo', status: 'active', load: 0.3 },
        { id: 'operations', status: 'active', load: 0.1 }
      ],
      timestamp: new Date().toISOString()
    })
  }),

  http.post('*/api/ai/api/decision', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      id: `decision-${Date.now()}`,
      type: body.type || 'operational',
      decision: 'PROCEED',
      confidence: 0.78,
      reasoning: 'Operational metrics indicate optimal conditions for the requested action',
      recommendedActions: [
        'Proceed with inventory reorder',
        'Monitor stock levels closely',
        'Set up automatic reorder alerts'
      ],
      timestamp: new Date().toISOString()
    })
  }),

  // Data Synchronization
  http.post('*/agents/sync/start', () => {
    return HttpResponse.json({
      success: true,
      status: {
        isRunning: true,
        startedAt: new Date().toISOString(),
        estimatedDuration: 300000
      },
      message: 'Data synchronization started successfully'
    })
  }),

  http.post('*/agents/sync/full', () => {
    return HttpResponse.json({
      success: true,
      status: {
        totalRecordsProcessed: 1534,
        successfulRecords: 1532,
        failedRecords: 2,
        processingTime: 45000,
        completedAt: new Date().toISOString()
      },
      message: 'Full synchronization completed successfully'
    })
  }),

  http.post('*/agents/sync/stop', () => {
    return HttpResponse.json({
      success: true,
      status: {
        isRunning: false,
        stoppedAt: new Date().toISOString(),
        recordsProcessed: 856
      },
      message: 'Data synchronization stopped successfully'
    })
  }),

  // Real-time Communication
  http.get('*/agents/stream', () => {
    // Mock SSE stream
    const stream = new ReadableStream({
      start(controller) {
        // Send initial connection event
        controller.enqueue(new TextEncoder().encode('data: {"type":"connection","status":"connected"}\n\n'))

        // Send periodic updates
        const interval = setInterval(() => {
          const event = {
            type: 'agent_update',
            data: {
              agentId: 'ceo',
              status: 'processing',
              timestamp: new Date().toISOString()
            }
          }
          controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(event)}\n\n`))
        }, 1000)

        // Clean up after 5 seconds
        setTimeout(() => {
          clearInterval(interval)
          controller.close()
        }, 5000)
      }
    })

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      }
    })
  }),

  http.get('*/api/ai/stream', () => {
    // Mock SSE stream for AI proxy
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('data: {"type":"ai_stream","status":"connected"}\n\n'))

        setTimeout(() => {
          controller.close()
        }, 2000)
      }
    })

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      }
    })
  }),

  // Agent Metrics
  http.get('*/agents/metrics', () => {
    return HttpResponse.json({
      metrics: {
        totalRequests: 1247,
        successfulRequests: 1198,
        failedRequests: 49,
        averageResponseTime: 245,
        activeAgents: 3,
        totalProcessingTime: 305000,
        systemLoad: 0.23
      },
      period: {
        start: new Date(Date.now() - 86400000).toISOString(),
        end: new Date().toISOString()
      },
      timestamp: new Date().toISOString()
    })
  }),

  http.get('*/agents/metrics/:agentId', ({ params }) => {
    const { agentId } = params
    return HttpResponse.json({
      metrics: {
        agentId,
        requests: 412,
        successfulRequests: 401,
        failedRequests: 11,
        averageResponseTime: 189,
        totalProcessingTime: 77868,
        lastActivity: new Date().toISOString(),
        status: 'active'
      },
      period: {
        start: new Date(Date.now() - 86400000).toISOString(),
        end: new Date().toISOString()
      },
      timestamp: new Date().toISOString()
    })
  }),

  // Health check endpoint
  http.get('*/health', () => {
    return HttpResponse.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {
        agents: 'healthy',
        database: 'healthy',
        cache: 'healthy'
      }
    })
  }),

  http.get('*/api/status', () => {
    return HttpResponse.json({
      status: 'operational',
      version: '1.0.0',
      environment: 'test',
      timestamp: new Date().toISOString()
    })
  })
]