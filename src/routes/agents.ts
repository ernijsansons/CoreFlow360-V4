import { Hono } from 'hono';
import { CoreFlow360AgentBridge } from '../services/integration/agent-bridge';
import { AgentServiceConnector } from '../services/integration/agent-connector';
import { DataSynchronizationService } from '../services/integration/data-sync';

const agents = new Hono();

// Initialize integration services
let agentBridge: CoreFlow360AgentBridge;
let agentConnector: AgentServiceConnector;
let dataSync: DataSynchronizationService;

// Initialize services middleware
agents.use('*', async (c, next) => {
  if (!agentBridge) {
    const env = c.env as any;
    agentBridge = new CoreFlow360AgentBridge(
      {
        agentEndpoint: env.AGENT_SYSTEM_URL || 'http://localhost:3000',
        coreflowAPI: env.COREFLOW_API_URL || 'http://localhost:8787',
        apiKey: env.AGENT_API_KEY,
        enableRealtime: true
      },
      env
    );

    await agentBridge.initialize();
    agentConnector = new AgentServiceConnector(agentBridge, c.env);
    dataSync = new DataSynchronizationService(
      {
        syncInterval: 60000,
        enableBidirectional: true
      },
      c.env
    );
  }

  c.set('agentBridge', agentBridge);
  c.set('agentConnector', agentConnector);
  c.set('dataSync', dataSync);

  await next();
});

// === Agent System Status and Health ===
agents.get('/status', async (c: any) => {
  try {
    const bridge = c.get('agentBridge');
    const status = await bridge.getAgentStatus();

    return c.json({
      connected: true,
      agents: Object.fromEntries(status),
      timestamp: new Date()
    });
  } catch (error: any) {
    return c.json({
      connected: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date()
    }, 500);
  }
});

agents.get('/health', async (c: any) => {
  try {
    const response = await fetch(`${c.env.AGENT_SYSTEM_URL || 'http://localhost:3000'}/health`);
    const health = await response.json();

    return c.json({
      agentSystem: health,
      integration: {
        status: 'healthy',
        bridgeConnected: true,
        syncActive: c.get('dataSync').getSyncStatistics().isRunning
      }
    });
  } catch (error: any) {
    return c.json({
      agentSystem: { status: 'unreachable' },
      integration: {
        status: 'degraded',
        bridgeConnected: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    }, 503);
  }
});

// === Agent Capabilities ===
agents.get('/capabilities', async (c: any) => {
  try {
    const connector = c.get('agentConnector');
    const capabilities = await connector.getAvailableAgents();

    return c.json({ capabilities });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

agents.get('/capabilities/:agentId', async (c: any) => {
  try {
    const connector = c.get('agentConnector');
    const agentId = c.req.param('agentId');
    const capability = connector.getAgentCapability(agentId);

    if (!capability) {
      return c.json({ error: 'Agent not found' }, 404);
    }

    return c.json({ capability });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// === Decision Making ===
agents.post('/decision', async (c: any) => {
  try {
    const bridge = c.get('agentBridge');
    const context = await c.req.json();

    const decision = await bridge.requestAgentDecision({
      id: `api-${Date.now()}`,
      timestamp: new Date(),
      type: context.type || 'general',
      data: context.data || {},
      priority: context.priority || 'medium'
    });

    return c.json({ decision });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

agents.post('/agent/:agentId/request', async (c: any) => {
  try {
    const connector = c.get('agentConnector');
    const agentId = c.req.param('agentId');
    const request = await c.req.json();

    const response = await connector.requestAgentAction({
      agentType: agentId,
      action: request.action,
      context: request.context,
      parameters: request.parameters,
      timeout: request.timeout || 30000
    });

    return c.json({ response });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// === Workflow Integration ===
agents.post('/workflow/:workflowId/connect', async (c: any) => {
  try {
    const bridge = c.get('agentBridge');
    const workflowId = c.req.param('workflowId');
    const context = await c.req.json();

    await bridge.connectToWorkflow(workflowId, context);

    return c.json({
      success: true,
      message: `Workflow ${workflowId} connected to agent system`
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

agents.post('/workflow/:workflowId/execute', async (c: any) => {
  try {
    const bridge = c.get('agentBridge');
    const workflowId = c.req.param('workflowId');
    const input = await c.req.json();

    const result = await bridge.executeWithAgents(workflowId, input);

    return c.json({ result });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// === Multi-Agent Collaboration ===
agents.post('/collaborate', async (c: any) => {
  try {
    const connector = c.get('agentConnector');
    const { task, agents: requiredAgents, context } = await c.req.json();

    const result = await connector.executeMultiAgentTask(task, requiredAgents, context);

    return c.json({
      results: Object.fromEntries(result.results),
      consensus: result.consensus
    });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

agents.post('/orchestrate', async (c: any) => {
  try {
    const connector = c.get('agentConnector');
    const workflowDefinition = await c.req.json();

    const result = await connector.orchestrateWorkflow(workflowDefinition);

    return c.json({ result });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// === Data Synchronization ===
agents.post('/sync/start', async (c: any) => {
  try {
    const sync = c.get('dataSync');
    await sync.startSync();

    return c.json({
      success: true,
      message: 'Data synchronization started'
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

agents.post('/sync/stop', async (c: any) => {
  try {
    const sync = c.get('dataSync');
    sync.stopSync();

    return c.json({
      success: true,
      message: 'Data synchronization stopped'
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

agents.post('/sync/full', async (c: any) => {
  try {
    const sync = c.get('dataSync');
    const job = await sync.performFullSync();

    return c.json({ job });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

agents.get('/sync/status', async (c: any) => {
  try {
    const sync = c.get('dataSync');
    const statistics = sync.getSyncStatistics();

    return c.json({ statistics });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// === Metrics and Analytics ===
agents.get('/metrics', async (c: any) => {
  try {
    const connector = c.get('agentConnector');
    const metrics = await connector.getAgentMetrics();

    return c.json({ metrics });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

agents.get('/metrics/:agentId', async (c: any) => {
  try {
    const connector = c.get('agentConnector');
    const agentId = c.req.param('agentId');
    const metrics = await connector.getAgentMetrics(agentId);

    return c.json({ metrics });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// === Real-time Streaming ===
agents.get('/stream', async (c: any) => {
  try {
    const bridge = c.get('agentBridge');

    // Set up Server-Sent Events for real-time updates
    const headers = new Headers({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });

    const stream = new ReadableStream({
      start(controller) {
        // Subscribe to real-time updates
        bridge.streamUpdates((update) => {
          const data = `data: ${JSON.stringify(update)}\n\n`;
          controller.enqueue(new TextEncoder().encode(data));
        });

        // Send heartbeat every 30 seconds
        const heartbeat = setInterval(() => {
          const ping = `data: ${JSON.stringify({ type: 'ping', timestamp: new Date() })}\n\n`;
          controller.enqueue(new TextEncoder().encode(ping));
        }, 30000);

        // Cleanup on close
        const cleanup = () => {
          clearInterval(heartbeat);
          controller.close();
        };

        // Close after 1 hour
        setTimeout(cleanup, 3600000);
      }
    });

    return new Response(stream, { headers });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// === WebSocket endpoint for bidirectional communication ===
agents.get('/ws', async (c: any) => {
  const upgradeHeader = c.req.header('Upgrade');
  if (!upgradeHeader || upgradeHeader !== 'websocket') {
    return c.json({ error: 'Expected WebSocket' }, 426);
  }

  const bridge = c.get('agentBridge');
  const connector = c.get('agentConnector');

  // Handle WebSocket connection
  const { response, socket } = Deno.upgradeWebSocket(c.req.raw);

  socket.onopen = () => {
    socket.send(JSON.stringify({
      type: 'connected',
      message: 'Connected to CoreFlow360 Agent Integration'
    }));
  };

  socket.onmessage = async (event: any) => {
    try {
      const message = JSON.parse(event.data);

      switch (message.type) {
        case 'request_decision':
          const decision = await bridge.requestAgentDecision(message.context);
          socket.send(JSON.stringify({ type: 'decision', data: decision }));
          break;

        case 'agent_action':
          const response = await connector.requestAgentAction(message.request);
          socket.send(JSON.stringify({ type: 'action_response', data: response }));
          break;

        case 'subscribe':
          connector.subscribeToAgentEvents(message.eventType, (event) => {
            socket.send(JSON.stringify({ type: 'event', data: event }));
          });
          break;

        default:
          socket.send(JSON.stringify({ type: 'error', message: 'Unknown message type' }));
      }
    } catch (error: any) {
      socket.send(JSON.stringify({
        type: 'error',
        message: error instanceof Error ? error.message : 'Processing error'
      }));
    }
  };

  socket.onclose = () => {
  };

  return response;
});

// === Configuration Management ===
agents.get('/config', async (c: any) => {
  try {
    return c.json({
      agentEndpoint: c.env.AGENT_SYSTEM_URL || 'http://localhost:3000',
      coreflowAPI: c.env.COREFLOW_API_URL || 'http://localhost:8787',
      syncInterval: 60000,
      realtimeEnabled: true,
      bidirectionalSync: true
    });
  } catch (error: any) {
    return c.json({
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

agents.put('/config', async (c: any) => {
  try {
    const config = await c.req.json();

    // Update configuration
    // This would typically update environment variables or configuration storage

    return c.json({
      success: true,
      message: 'Configuration updated',
      config
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// === Testing and Debugging ===
agents.post('/test', async (c: any) => {
  try {
    const bridge = c.get('agentBridge');

    // Test decision with sample data
    const testContext = {
      id: 'test-integration',
      timestamp: new Date(),
      type: 'strategic_financial',
      data: {
        testMode: true,
        investment: 100000,
        expectedReturn: 150000
      },
      priority: 'low'
    };

    const decision = await bridge.requestAgentDecision(testContext);

    return c.json({
      success: true,
      testResult: decision,
      message: 'Agent integration test successful'
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Test failed'
    }, 500);
  }
});

export default agents;