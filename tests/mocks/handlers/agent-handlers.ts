/**
 * Agent System MSW Handlers
 * Comprehensive mocking for all agent-related endpoints
 */

import { http, HttpResponse } from 'msw'

export const agentHandlers = [
  // Agent System Health Endpoints
  http.get('http://localhost:8787/agents/health', () => {
    return HttpResponse.json({
      status: 'healthy',
      agentSystem: {
        status: 'connected',
        version: '1.0.0',
        services: ['ceo', 'cfo', 'cto']
      },
      timestamp: new Date().toISOString()
    })
  }),

  http.get('http://localhost:8787/agents/status', () => {
    return HttpResponse.json({
      connected: true,
      syncStatus: {
        isRunning: false,
        lastSync: new Date().toISOString(),
        totalRecordsProcessed: 1250
      },
      activeAgents: ['ceo', 'cfo'],
      timestamp: new Date().toISOString()
    })
  }),

  http.get('http://localhost:8787/agents/list', () => {
    return HttpResponse.json({
      agents: [
        {
          id: 'ceo',
          name: 'CEO Agent',
          type: 'executive',
          capabilities: ['strategic_planning', 'financial_oversight'],
          status: 'active'
        },
        {
          id: 'cfo',
          name: 'CFO Agent',
          type: 'financial',
          capabilities: ['budget_analysis', 'risk_assessment'],
          status: 'active'
        },
        {
          id: 'cto',
          name: 'CTO Agent',
          type: 'technical',
          capabilities: ['tech_strategy', 'architecture_review'],
          status: 'idle'
        }
      ]
    })
  }),

  http.post('http://localhost:8787/agents/decide', () => {
    return HttpResponse.json({
      success: true,
      decision: {
        recommendation: 'approve',
        confidence: 0.85,
        reasoning: 'Investment shows strong ROI potential within acceptable risk parameters',
        timestamp: new Date().toISOString()
      }
    })
  }),

  http.post('http://localhost:8787/agents/collaborate', () => {
    return HttpResponse.json({
      success: true,
      results: {
        ceo: {
          decision: 'approve',
          reasoning: 'Strategic alignment with company goals'
        },
        cfo: {
          decision: 'approve_with_conditions',
          reasoning: 'ROI acceptable if budget constraints met'
        }
      },
      consensus: {
        decision: 'approve_with_conditions',
        confidence: 0.78
      }
    })
  }),

  // Agent API Endpoints
  http.get('http://localhost:8787/api/v4/agents/capabilities', () => {
    return HttpResponse.json({
      capabilities: [
        {
          id: 'strategic_planning',
          name: 'Strategic Planning',
          type: 'executive',
          agents: ['ceo']
        },
        {
          id: 'financial_analysis',
          name: 'Financial Analysis',
          type: 'financial',
          agents: ['cfo']
        }
      ]
    })
  }),

  http.get('http://localhost:8787/api/v4/agents/capabilities/:agentId', ({ params }) => {
    const { agentId } = params
    return HttpResponse.json({
      capability: {
        id: agentId,
        name: agentId === 'ceo' ? 'CEO Agent' : 'Agent',
        type: agentId === 'ceo' ? 'executive' : 'general',
        capabilities: ['decision_making', 'strategy'],
        status: 'active'
      }
    })
  }),

  http.post('http://localhost:8787/api/v4/agents/workflow/:workflowId/connect', ({ params }) => {
    const { workflowId } = params
    return HttpResponse.json({
      success: true,
      message: `Workflow ${workflowId} connected to agent system`,
      connectionId: `conn-${Date.now()}`
    })
  }),

  http.get('http://localhost:8787/api/v4/agents/sync/status', () => {
    return HttpResponse.json({
      statistics: {
        isRunning: false,
        lastSync: new Date().toISOString(),
        totalRecordsProcessed: 1250,
        errors: 0
      }
    })
  }),

  // Proxy AI Endpoints
  http.get('http://localhost:8787/api/ai/health', () => {
    return HttpResponse.json({
      status: 'healthy',
      agents: {
        available: ['ceo', 'cfo', 'cto'],
        active: ['ceo', 'cfo']
      }
    })
  }),

  http.get('http://localhost:8787/api/ai/api/agents/status', () => {
    return HttpResponse.json({
      status: 'operational',
      agents: 3,
      connections: 2
    })
  }),

  http.post('http://localhost:8787/api/ai/api/decision', () => {
    return HttpResponse.json({
      decision: 'proceed',
      confidence: 0.92,
      agent: 'cfo',
      reasoning: 'Inventory levels require immediate reordering'
    })
  }),

  // Data Sync Endpoints
  http.post('http://localhost:8787/agents/sync/start', () => {
    return HttpResponse.json({
      success: true,
      status: {
        isRunning: true,
        started: new Date().toISOString()
      }
    })
  }),

  http.post('http://localhost:8787/agents/sync/full', () => {
    return HttpResponse.json({
      success: true,
      status: {
        totalRecordsProcessed: 2500,
        duration: '45 seconds',
        completed: new Date().toISOString()
      }
    })
  }),

  http.post('http://localhost:8787/agents/sync/stop', () => {
    return HttpResponse.json({
      success: true,
      status: {
        isRunning: false,
        stopped: new Date().toISOString()
      }
    })
  }),

  // SSE Stream Endpoints
  http.get('http://localhost:8787/agents/stream', () => {
    return new HttpResponse(
      new ReadableStream({
        start(controller) {
          // Simulate SSE stream
          controller.enqueue(new TextEncoder().encode('data: {"type":"heartbeat","timestamp":"' + new Date().toISOString() + '"}\n\n'))
          setTimeout(() => {
            controller.close()
          }, 100)
        }
      }),
      {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive'
        }
      }
    )
  }),

  http.get('http://localhost:8787/api/ai/stream', () => {
    return new HttpResponse(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('data: {"agent":"ceo","message":"System operational"}\n\n'))
          setTimeout(() => {
            controller.close()
          }, 100)
        }
      }),
      {
        headers: {
          'Content-Type': 'text/event-stream'
        }
      }
    )
  }),

  // Metrics Endpoints
  http.get('http://localhost:8787/agents/metrics', () => {
    return HttpResponse.json({
      metrics: {
        totalRequests: 1250,
        activeAgents: 2,
        averageResponseTime: 145,
        successRate: 0.98
      }
    })
  }),

  http.get('http://localhost:8787/agents/metrics/:agentId', ({ params }) => {
    const { agentId } = params
    return HttpResponse.json({
      metrics: {
        agent: agentId,
        requests: 423,
        responseTime: 120,
        successRate: 0.99
      }
    })
  }),

  // System Health
  http.get('http://localhost:8787/health', () => {
    return HttpResponse.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {
        database: 'healthy',
        cache: 'healthy',
        agents: 'healthy'
      }
    })
  })
]