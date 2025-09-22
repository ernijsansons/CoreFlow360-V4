import { Hono } from 'hono';
import { CoreFlow360AgentBridge } from './integration/agent-bridge';
import { AgentServiceConnector } from './integration/agent-connector';
import { DataSynchronizationService } from './integration/data-sync';

export // TODO: Consider splitting AgentService into smaller, focused classes
class AgentService {
  private static instance: AgentService;
  private bridge: CoreFlow360AgentBridge;
  private connector: AgentServiceConnector;
  private dataSync: DataSynchronizationService;
  private app: Hono;
  private initialized: boolean = false;
  private agentSystemUrl: string;

  private constructor() {
    this.app = new Hono();
    this.agentSystemUrl = process.env.AGENT_SYSTEM_URL || 'http://localhost:3000';
    this.setupRoutes();
  }

  public static getInstance(): AgentService {
    if (!AgentService.instance) {
      AgentService.instance = new AgentService();
    }
    return AgentService.instance;
  }

  public async initialize(env?: any): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      // Initialize the bridge
      this.bridge = new CoreFlow360AgentBridge(
        {
          agentEndpoint: this.agentSystemUrl,
          coreflowAPI: process.env.COREFLOW_API_URL || 'http://localhost:8787',
          apiKey: process.env.AGENT_API_KEY,
          enableRealtime: true
        },
        env
      );

      await this.bridge.initialize();

      // Initialize connector and sync services
      this.connector = new AgentServiceConnector(this.bridge, env);
      this.dataSync = new DataSynchronizationService(
        {
          syncInterval: 60000,
          enableBidirectional: true,
          conflictResolution: 'newest'
        },
        env
      );

      // Start automatic synchronization
      await this.dataSync.startSync();

      this.initialized = true;
    } catch (error) {
      throw error;
    }
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', async (c) => {
      const isHealthy = await this.checkHealth();
      return c.json({
        status: isHealthy ? 'healthy' : 'unhealthy',
        initialized: this.initialized,
        agentSystem: this.agentSystemUrl,
        timestamp: new Date()
      }, isHealthy ? 200 : 503);
    });

    // Agent status
    this.app.get('/status', async (c) => {
      if (!this.initialized) {
        return c.json({ error: 'Service not initialized' }, 503);
      }

      try {
        const status = await this.bridge.getAgentStatus();
        return c.json({
          connected: true,
          agents: Object.fromEntries(status),
          syncStatus: this.dataSync.getSyncStatistics()
        });
      } catch (error) {
        return c.json({
          connected: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        }, 500);
      }
    });

    // List available agents
    this.app.get('/list', async (c) => {
      if (!this.initialized) {
        return c.json({ error: 'Service not initialized' }, 503);
      }

      const agents = await this.connector.getAvailableAgents();
      return c.json({ agents });
    });

    // Request decision from agents
    this.app.post('/decide', async (c) => {
      if (!this.initialized) {
        return c.json({ error: 'Service not initialized' }, 503);
      }

      try {
        const body = await c.req.json();
        const decision = await this.bridge.requestAgentDecision({
          id: `svc-${Date.now()}`,
          timestamp: new Date(),
          type: body.type || 'general',
          data: body.data || {},
          priority: body.priority || 'medium'
        });

        return c.json({ success: true, decision });
      } catch (error) {
        return c.json({
          success: false,
          error: error instanceof Error ? error.message : 'Decision failed'
        }, 500);
      }
    });

    // Execute multi-agent task
    this.app.post('/collaborate', async (c) => {
      if (!this.initialized) {
        return c.json({ error: 'Service not initialized' }, 503);
      }

      try {
        const { task, agents, context } = await c.req.json();
        const result = await this.connector.executeMultiAgentTask(
          task,
          agents || ['ceo', 'cfo', 'cto'],
          context
        );

        return c.json({
          success: true,
          results: Object.fromEntries(result.results),
          consensus: result.consensus
        });
      } catch (error) {
        return c.json({
          success: false,
          error: error instanceof Error ? error.message : 'Collaboration failed'
        }, 500);
      }
    });

    // Connect workflow to agents
    this.app.post('/workflow/:id/connect', async (c) => {
      if (!this.initialized) {
        return c.json({ error: 'Service not initialized' }, 503);
      }

      try {
        const workflowId = c.req.param('id');
        const context = await c.req.json();
        await this.bridge.connectToWorkflow(workflowId, context);

        return c.json({
          success: true,
          message: `Workflow ${workflowId} connected to agent system`
        });
      } catch (error) {
        return c.json({
          success: false,
          error: error instanceof Error ? error.message : 'Connection failed'
        }, 500);
      }
    });

    // Sync control
    this.app.post('/sync/:action', async (c) => {
      if (!this.initialized) {
        return c.json({ error: 'Service not initialized' }, 503);
      }

      const action = c.req.param('action');

      try {
        switch (action) {
          case 'start':
            await this.dataSync.startSync();
            break;
          case 'stop':
            this.dataSync.stopSync();
            break;
          case 'full':
            await this.dataSync.performFullSync();
            break;
          case 'status':
            return c.json({ status: this.dataSync.getSyncStatistics() });
          default:
            return c.json({ error: 'Invalid sync action' }, 400);
        }

        return c.json({
          success: true,
          action,
          status: this.dataSync.getSyncStatistics()
        });
      } catch (error) {
        return c.json({
          success: false,
          error: error instanceof Error ? error.message : 'Sync action failed'
        }, 500);
      }
    });

    // Agent metrics
    this.app.get('/metrics/:agentId?', async (c) => {
      if (!this.initialized) {
        return c.json({ error: 'Service not initialized' }, 503);
      }

      try {
        const agentId = c.req.param('agentId');
        const metrics = await this.connector.getAgentMetrics(agentId);
        return c.json({ metrics });
      } catch (error) {
        return c.json({
          error: error instanceof Error ? error.message : 'Failed to get metrics'
        }, 500);
      }
    });

    // Stream events
    this.app.get('/stream', async (c) => {
      if (!this.initialized) {
        return c.json({ error: 'Service not initialized' }, 503);
      }

      const headers = new Headers({
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      });

      const stream = new ReadableStream({
        start: (controller) => {
          const sendEvent = (data: any) => {
            const event = `data: ${JSON.stringify(data)}\n\n`;
            controller.enqueue(new TextEncoder().encode(event));
          };

          // Subscribe to events
          const unsubscribe = this.connector.subscribeToAgentEvents('all', sendEvent);

          // Send heartbeat
          const heartbeat = setInterval(() => {
            sendEvent({ type: 'heartbeat', timestamp: new Date() });
          }, 30000);

          // Cleanup
          setTimeout(() => {
            unsubscribe();
            clearInterval(heartbeat);
            controller.close();
          }, 3600000); // 1 hour
        }
      });

      return new Response(stream, { headers });
    });
  }

  private async checkHealth(): Promise<boolean> {
    try {
      const response = await fetch(`${this.agentSystemUrl}/health`);
      return response.ok;
    } catch {
      return false;
    }
  }

  // Get the router for mounting in main app
  public router(): Hono {
    return this.app;
  }

  // Get service instances for direct access
  public getBridge(): CoreFlow360AgentBridge {
    if (!this.initialized) {
      throw new Error('AgentService not initialized');
    }
    return this.bridge;
  }

  public getConnector(): AgentServiceConnector {
    if (!this.initialized) {
      throw new Error('AgentService not initialized');
    }
    return this.connector;
  }

  public getDataSync(): DataSynchronizationService {
    if (!this.initialized) {
      throw new Error('AgentService not initialized');
    }
    return this.dataSync;
  }

  // Cleanup
  public async shutdown(): Promise<void> {
    if (!this.initialized) return;

    try {
      // Stop sync
      this.dataSync.stopSync();

      // Disconnect bridge
      await this.bridge.disconnect();

      // Cleanup connector
      this.connector.cleanup();

      this.initialized = false;
    } catch (error) {
    }
  }
}

// Export singleton instance
export const agentService = AgentService.getInstance();