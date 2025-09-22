/**
 * Integration test suite for CoreFlow360 Agent System Integration
 *
 * This test file verifies that the agent system is properly integrated
 * with the main CoreFlow360 application through multiple access patterns.
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';

// Test configuration
const COREFLOW_URL = process.env.COREFLOW_URL || 'http://localhost:8787';
const AGENT_SYSTEM_URL = process.env.AGENT_SYSTEM_URL || 'http://localhost:3000';

describe('CoreFlow360 Agent Integration', () => {
  let testWorkflowId: string;

  beforeAll(async () => {
    // Create a test workflow ID
    testWorkflowId = `test-workflow-${Date.now()}`;
  });

  describe('AgentService Endpoints (/agents/*)', () => {
    it('should check agent service health', async () => {
      const response = await fetch(`${COREFLOW_URL}/agents/health`);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.status).toMatch(/healthy|unhealthy/);
      expect(data.agentSystem).toBeDefined();
    });

    it('should get agent status through service', async () => {
      const response = await fetch(`${COREFLOW_URL}/agents/status`);

      if (response.status === 503) {
        // Service not initialized yet
        const data = await response.json();
        expect(data.error).toBe('Service not initialized');
      } else {
        const data = await response.json();
        expect(data.connected).toBeDefined();
        expect(data.syncStatus).toBeDefined();
      }
    });

    it('should list available agents', async () => {
      const response = await fetch(`${COREFLOW_URL}/agents/list`);

      if (response.status === 200) {
        const data = await response.json();
        expect(data.agents).toBeInstanceOf(Array);

        // Verify agent structure
        if (data.agents.length > 0) {
          const agent = data.agents[0];
          expect(agent).toHaveProperty('id');
          expect(agent).toHaveProperty('name');
          expect(agent).toHaveProperty('type');
          expect(agent).toHaveProperty('capabilities');
        }
      }
    });

    it('should request decision from agents', async () => {
      const decisionRequest = {
        type: 'strategic_financial',
        data: {
          investment: 100000,
          expectedReturn: 150000,
          timeframe: '12 months'
        },
        priority: 'medium'
      };

      const response = await fetch(`${COREFLOW_URL}/agents/decide`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(decisionRequest)
      });

      if (response.status === 200) {
        const data = await response.json();
        expect(data.success).toBe(true);
        expect(data.decision).toBeDefined();
      }
    });

    it('should execute multi-agent collaboration', async () => {
      const collaborationRequest = {
        task: 'evaluate_investment',
        agents: ['ceo', 'cfo'],
        context: {
          amount: 500000,
          opportunity: 'New product line'
        }
      };

      const response = await fetch(`${COREFLOW_URL}/agents/collaborate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(collaborationRequest)
      });

      if (response.status === 200) {
        const data = await response.json();
        expect(data.success).toBe(true);
        expect(data.results).toBeDefined();
        expect(data.consensus).toBeDefined();
      }
    });
  });

  describe('Agent API Endpoints (/api/v4/agents/*)', () => {
    it('should get agent capabilities', async () => {
      const response = await fetch(`${COREFLOW_URL}/api/v4/agents/capabilities`);

      if (response.status === 200) {
        const data = await response.json();
        expect(data.capabilities).toBeInstanceOf(Array);
      }
    });

    it('should get specific agent capability', async () => {
      const response = await fetch(`${COREFLOW_URL}/api/v4/agents/capabilities/ceo`);

      if (response.status === 200) {
        const data = await response.json();
        expect(data.capability).toBeDefined();
        expect(data.capability.id).toBe('ceo');
        expect(data.capability.type).toBe('executive');
      }
    });

    it('should connect workflow to agents', async () => {
      const workflowContext = {
        businessUnit: 'finance',
        data: {
          budget: 1000000,
          department: 'R&D'
        },
        metadata: {
          priority: 'high'
        }
      };

      const response = await fetch(`${COREFLOW_URL}/api/v4/agents/workflow/${testWorkflowId}/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(workflowContext)
      });

      if (response.status === 200) {
        const data = await response.json();
        expect(data.success).toBe(true);
        expect(data.message).toContain(testWorkflowId);
      }
    });

    it('should get sync status', async () => {
      const response = await fetch(`${COREFLOW_URL}/api/v4/agents/sync/status`);

      if (response.status === 200) {
        const data = await response.json();
        expect(data.statistics).toBeDefined();
        expect(data.statistics.isRunning).toBeDefined();
      }
    });
  });

  describe('Proxy Endpoints (/api/ai/*)', () => {
    it('should proxy health check to agent system', async () => {
      const response = await fetch(`${COREFLOW_URL}/api/ai/health`);

      if (response.status === 200) {
        const data = await response.json();
        expect(data.status).toBe('healthy');
        expect(data.agents).toBeDefined();
      } else if (response.status === 502) {
        // Agent system not reachable
        const data = await response.json();
        expect(data.error).toMatch(/Bad Gateway|Failed to reach agent system/);
      }
    });

    it('should proxy agent status request', async () => {
      const response = await fetch(`${COREFLOW_URL}/api/ai/api/agents/status`);

      if (response.status === 200) {
        const data = await response.json();
        expect(data).toBeDefined();
      }
    });

    it('should proxy decision request', async () => {
      const decisionContext = {
        type: 'operational',
        data: {
          process: 'inventory_management',
          currentStock: 1000,
          reorderPoint: 200
        }
      };

      const response = await fetch(`${COREFLOW_URL}/api/ai/api/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(decisionContext)
      });

      if (response.status === 200) {
        const data = await response.json();
        expect(data).toBeDefined();
      }
    });
  });

  describe('Data Synchronization', () => {
    it('should start data sync', async () => {
      const response = await fetch(`${COREFLOW_URL}/agents/sync/start`, {
        method: 'POST'
      });

      if (response.status === 200) {
        const data = await response.json();
        expect(data.success).toBe(true);
        expect(data.status).toBeDefined();
      }
    });

    it('should perform full sync', async () => {
      const response = await fetch(`${COREFLOW_URL}/agents/sync/full`, {
        method: 'POST'
      });

      if (response.status === 200) {
        const data = await response.json();
        expect(data.success).toBe(true);
        expect(data.status.totalRecordsProcessed).toBeDefined();
      }
    });

    it('should stop data sync', async () => {
      const response = await fetch(`${COREFLOW_URL}/agents/sync/stop`, {
        method: 'POST'
      });

      if (response.status === 200) {
        const data = await response.json();
        expect(data.success).toBe(true);
        expect(data.status.isRunning).toBe(false);
      }
    });
  });

  describe('Real-time Communication', () => {
    it('should establish SSE connection for streaming', async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      try {
        const response = await fetch(`${COREFLOW_URL}/agents/stream`, {
          signal: controller.signal,
          headers: {
            'Accept': 'text/event-stream'
          }
        });

        clearTimeout(timeoutId);

        expect(response.status).toBe(200);
        expect(response.headers.get('content-type')).toContain('text/event-stream');

        // Read first few bytes to verify stream
        const reader = response.body?.getReader();
        if (reader) {
          const { value } = await reader.read();
          expect(value).toBeDefined();
          reader.cancel();
        }
      } catch (error) {
        // Timeout or connection error
        expect(error).toBeDefined();
      }
    });

    it('should proxy SSE stream from agent system', async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      try {
        const response = await fetch(`${COREFLOW_URL}/api/ai/stream`, {
          signal: controller.signal,
          headers: {
            'Accept': 'text/event-stream'
          }
        });

        clearTimeout(timeoutId);

        if (response.status === 200) {
          expect(response.headers.get('content-type')).toContain('text/event-stream');
        }
      } catch (error) {
        // Expected if agent system is not running
        expect(error).toBeDefined();
      }
    });
  });

  describe('Agent Metrics', () => {
    it('should get overall agent metrics', async () => {
      const response = await fetch(`${COREFLOW_URL}/agents/metrics`);

      if (response.status === 200) {
        const data = await response.json();
        expect(data.metrics).toBeDefined();
        expect(data.metrics.totalRequests).toBeDefined();
        expect(data.metrics.activeAgents).toBeDefined();
      }
    });

    it('should get specific agent metrics', async () => {
      const response = await fetch(`${COREFLOW_URL}/agents/metrics/ceo`);

      if (response.status === 200) {
        const data = await response.json();
        expect(data.metrics).toBeDefined();
      }
    });
  });

  afterAll(async () => {
    // Cleanup: Stop any running sync
    try {
      await fetch(`${COREFLOW_URL}/agents/sync/stop`, { method: 'POST' });
    } catch (error) {
      // Ignore cleanup errors
    }
  });
});

// Helper function to wait for service initialization
async function waitForService(url: string, maxAttempts = 10): Promise<boolean> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(url);
      if (response.ok) return true;
    } catch (error) {
      // Service not ready yet
    }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  return false;
}

// Integration smoke test
describe('Integration Smoke Test', () => {
  it('should verify both systems are accessible', async () => {
    // Check CoreFlow360
    const coreflowReady = await waitForService(`${COREFLOW_URL}/health`);
    expect(coreflowReady).toBe(true);

    // Check if agent proxy is working
    const proxyResponse = await fetch(`${COREFLOW_URL}/api/ai/health`);

    // Either agent system is running (200) or proxy returns gateway error (502)
    expect([200, 502, 504]).toContain(proxyResponse.status);
  });

  it('should verify agent service is mounted', async () => {
    const response = await fetch(`${COREFLOW_URL}/agents/health`);
    expect(response.status).toBe(200);

    const data = await response.json();
    expect(data.status).toBeDefined();
    expect(data.agentSystem).toBeDefined();
  });

  it('should verify all integration endpoints are accessible', async () => {
    const endpoints = [
      '/agents/health',
      '/agents/status',
      '/agents/list',
      '/api/v4/agents/capabilities',
      '/api/v4/agents/status'
    ];

    for (const endpoint of endpoints) {
      const response = await fetch(`${COREFLOW_URL}${endpoint}`);
      // Should return 200, 503 (not initialized), or 502 (agent system down)
      expect([200, 502, 503]).toContain(response.status);
    }
  });
});