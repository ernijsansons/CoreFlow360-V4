import { EventEmitter } from 'events';

export interface AgentDecision {
  id: string;
  agentId: string;
  type: string;
  decision: any;
  confidence: number;
  reasoning: string[];
  timestamp: Date;
}

export interface WorkflowContext {
  workflowId: string;
  businessUnit: string;
  data: Record<string, any>;
  metadata: Record<string, any>;
}

export interface AgentSystemConfig {
  agentEndpoint: string;
  coreflowAPI: string;
  apiKey?: string;
  syncInterval?: number;
  enableRealtime?: boolean;
}

export class CoreFlow360AgentBridge extends EventEmitter {
  private agentEndpoint: string;
  private coreflowAPI: string;
  private apiKey?: string;
  private syncInterval: number;
  private syncTimer?: NodeJS.Timer;
  private wsConnection?: WebSocket;
  private isConnected: boolean = false;
  private env: any;

  constructor(config?: Partial<AgentSystemConfig>, env?: any) {
    super();
    this.agentEndpoint = config?.agentEndpoint || process.env.AGENT_SYSTEM_URL || 'http://localhost:3000';
    this.coreflowAPI = config?.coreflowAPI || process.env.COREFLOW_API_URL || 'http://localhost:8787';
    this.apiKey = config?.apiKey || process.env.AGENT_API_KEY;
    this.syncInterval = config?.syncInterval || 30000; // 30 seconds default
    this.env = env;

    if (config?.enableRealtime) {
      this.initializeRealtimeConnection();
    }
  }

  // Initialize the bridge connection
  async initialize(): Promise<void> {
    try {
      // Test connection to agent system
      const healthCheck = await this.checkAgentSystemHealth();
      if (!healthCheck.healthy) {
        throw new Error('Agent system is not healthy');
      }

      // Start data synchronization
      this.startDataSync();

      // Initialize event listeners
      this.setupEventListeners();

      this.isConnected = true;
      this.emit('connected', { timestamp: new Date() });

    } catch (error: any) {
      this.emit('error', error);
      throw error;
    }
  }

  // Connect agent decisions to CoreFlow360 workflows
  async connectToWorkflow(workflowId: string, context?: WorkflowContext): Promise<void> {
    try {
      const workflowData = context || await this.fetchWorkflowContext(workflowId);

      // Prepare decision context for agent system
      const decisionContext = {
        id: `wf-${workflowId}-${Date.now()}`,
        timestamp: new Date(),
        type: this.mapWorkflowTypeToAgentType(workflowData.businessUnit),
        data: {
          ...workflowData.data,
          workflowId,
          businessUnit: workflowData.businessUnit,
          metadata: workflowData.metadata
        },
        priority: this.determinePriority(workflowData)
      };

      // Request decision from agent system
      const decision = await this.requestAgentDecision(decisionContext);

      // Apply decision to workflow
      await this.applyDecisionToWorkflow(workflowId, decision);

      this.emit('workflowConnected', { workflowId, decision });
    } catch (error: any) {
      this.emit('workflowError', { workflowId, error });
      throw error;
    }
  }

  // Sync data between systems
  async syncData(): Promise<void> {
    try {
      // Fetch pending decisions from agent system
      const pendingDecisions = await this.fetchPendingDecisions();

      // Fetch active workflows from CoreFlow360
      const activeWorkflows = await this.fetchActiveWorkflows();

      // Match and sync
      for (const workflow of activeWorkflows) {
        const relevantDecisions = pendingDecisions.filter((d: any) => this.isDecisionRelevant(d, workflow)
        );

        for (const decision of relevantDecisions) {
          await this.applyDecisionToWorkflow(workflow.id, decision);
        }
      }

      // Sync business data to agent system
      await this.syncBusinessData();

      this.emit('dataSynced', { timestamp: new Date() });
    } catch (error: any) {
      this.emit('syncError', error);
    }
  }

  // Request a decision from the agent system
  async requestAgentDecision(context: any): Promise<AgentDecision> {
    const response = await fetch(`${this.agentEndpoint}/api/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(this.apiKey && { 'Authorization': `Bearer ${this.apiKey}` })
      },
      body: JSON.stringify(context)
    });

    if (!response.ok) {
      throw new Error(`Agent decision request failed: ${response.statusText}`);
    }

    return await response.json();
  }

  // Get agent system status
  async getAgentStatus(): Promise<Map<string, any>> {
    const response = await fetch(`${this.agentEndpoint}/api/agents/status`, {
      headers: {
        ...(this.apiKey && { 'Authorization': `Bearer ${this.apiKey}` })
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to get agent status: ${response.statusText}`);
    }

    const status = await response.json();
    return new Map(Object.entries(status));
  }

  // Execute a workflow with agent assistance
  async executeWithAgents(workflowId: string, input: any): Promise<any> {
    try {
      // Get workflow details
      const workflow = await this.fetchWorkflowContext(workflowId);

      // Determine which agents to involve
      const agentTypes = this.determineRequiredAgents(workflow);

      // Collect decisions from multiple agents
      const decisions = await Promise.all(
        agentTypes.map((type: any) => this.requestAgentDecision({
          id: `exec-${workflowId}-${Date.now()}`,
          timestamp: new Date(),
          type,
          data: { ...workflow.data, input },
          priority: 'high'
        }))
      );

      // Aggregate and apply decisions
      const aggregatedDecision = this.aggregateDecisions(decisions);
      const result = await this.executeWorkflowWithDecision(workflowId, aggregatedDecision);

      return result;
    } catch (error: any) {
      throw error;
    }
  }

  // Stream real-time updates between systems
  async streamUpdates(callback: (update: any) => void): Promise<void> {
    if (!this.wsConnection) {
      await this.initializeRealtimeConnection();
    }

    this.on('realtimeUpdate', callback);
  }

  // Private helper methods
  private async checkAgentSystemHealth(): Promise<{ healthy: boolean }> {
    try {
      const response = await fetch(`${this.agentEndpoint}/health`, {
        headers: {
          ...(this.apiKey && { 'Authorization': `Bearer ${this.apiKey}` })
        }
      });
      return { healthy: response.ok };
    } catch {
      return { healthy: false };
    }
  }

  private startDataSync(): void {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
    }

    this.syncTimer = setInterval(() => {
      this.syncData().catch((error: any) => {
      });
    }, this.syncInterval);
  }

  private setupEventListeners(): void {
    // Listen for CoreFlow360 events
    if (this.env?.WORKFLOW_EVENTS) {
      // Set up event subscription if available
    }
  }

  private async initializeRealtimeConnection(): Promise<void> {
    try {
      const wsUrl = this.agentEndpoint.replace('http', 'ws') + '/ws';
      this.wsConnection = new WebSocket(wsUrl);

      this.wsConnection.onopen = () => {
        this.emit('wsConnected');
      };

      this.wsConnection.onmessage = (event) => {
        const data = JSON.parse(event.data);
        this.handleRealtimeUpdate(data);
      };

      this.wsConnection.onerror = (error) => {
        this.emit('wsError', error);
      };

      this.wsConnection.onclose = () => {
        this.emit('wsDisconnected');
        // Attempt reconnection after 5 seconds
        setTimeout(() => this.initializeRealtimeConnection(), 5000);
      };
    } catch (error: any) {
    }
  }

  private handleRealtimeUpdate(data: any): void {
    this.emit('realtimeUpdate', data);

    // Handle specific update types
    switch (data.type) {
      case 'decision':
        this.handleRealtimeDecision(data);
        break;
      case 'status':
        this.handleAgentStatusUpdate(data);
        break;
      case 'alert':
        this.handleAgentAlert(data);
        break;
    }
  }

  private async handleRealtimeDecision(data: any): Promise<void> {
    // Apply real-time decisions to relevant workflows
    const relevantWorkflows = await this.findRelevantWorkflows(data);
    for (const workflow of relevantWorkflows) {
      await this.applyDecisionToWorkflow(workflow.id, data.decision);
    }
  }

  private handleAgentStatusUpdate(data: any): void {
    this.emit('agentStatusUpdate', data);
  }

  private handleAgentAlert(data: any): void {
    this.emit('agentAlert', data);
  }

  private async fetchWorkflowContext(workflowId: string): Promise<WorkflowContext> {
    // Fetch from CoreFlow360 API
    const response = await fetch(`${this.coreflowAPI}/api/workflows/${workflowId}`, {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch workflow context: ${response.statusText}`);
    }

    return await response.json();
  }

  private async fetchPendingDecisions(): Promise<AgentDecision[]> {
    const response = await fetch(`${this.agentEndpoint}/api/decisions/pending`, {
      headers: {
        ...(this.apiKey && { 'Authorization': `Bearer ${this.apiKey}` })
      }
    });

    if (!response.ok) {
      return [];
    }

    return await response.json();
  }

  private async fetchActiveWorkflows(): Promise<any[]> {
    const response = await fetch(`${this.coreflowAPI}/api/workflows/active`, {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      return [];
    }

    return await response.json();
  }

  private async applyDecisionToWorkflow(workflowId: string, decision: AgentDecision): Promise<void> {
    await fetch(`${this.coreflowAPI}/api/workflows/${workflowId}/apply-decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(decision)
    });
  }

  private async syncBusinessData(): Promise<void> {
    // Fetch latest business metrics
    const metrics = await this.fetchBusinessMetrics();

    // Send to agent system for learning
    await fetch(`${this.agentEndpoint}/api/data/sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(this.apiKey && { 'Authorization': `Bearer ${this.apiKey}` })
      },
      body: JSON.stringify(metrics)
    });
  }

  private async fetchBusinessMetrics(): Promise<any> {
    const response = await fetch(`${this.coreflowAPI}/api/metrics/current`, {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      return {};
    }

    return await response.json();
  }

  private mapWorkflowTypeToAgentType(businessUnit: string): string {
    const mapping: Record<string, string> = {
      'finance': 'financial',
      'strategy': 'strategic',
      'operations': 'operational',
      'hr': 'human_resources',
      'legal': 'legal_compliance',
      'it': 'technology',
      'marketing': 'market_analysis',
      'sales': 'sales_optimization',
      'risk': 'risk_assessment'
    };

    return mapping[businessUnit.toLowerCase()] || 'general';
  }

  private determinePriority(workflow: WorkflowContext): 'low' | 'medium' | 'high' | 'critical' {
    // Determine priority based on workflow metadata
    if (workflow.metadata?.priority) {
      return workflow.metadata.priority;
    }

    // Default priority logic
    const value = workflow.data?.value || workflow.data?.impact || 0;
    if (value > 1000000) return 'critical';
    if (value > 100000) return 'high';
    if (value > 10000) return 'medium';
    return 'low';
  }

  private isDecisionRelevant(decision: AgentDecision, workflow: any): boolean {
    // Check if decision is relevant to workflow
    return decision.type === this.mapWorkflowTypeToAgentType(workflow.businessUnit);
  }

  private determineRequiredAgents(workflow: WorkflowContext): string[] {
    const agents: string[] = [];

    // Determine which agents are needed based on workflow
    if (workflow.data?.financial) agents.push('financial');
    if (workflow.data?.strategic) agents.push('strategic');
    if (workflow.data?.operational) agents.push('operational');
    if (workflow.data?.compliance) agents.push('legal_compliance');

    return agents.length > 0 ? agents : ['general'];
  }

  private aggregateDecisions(decisions: AgentDecision[]): any {
    // Aggregate multiple agent decisions
    const aggregated = {
      id: `agg-${Date.now()}`,
      decisions: decisions.map((d: any) => ({
        agentId: d.agentId,
        decision: d.decision,
        confidence: d.confidence
      })),
      finalDecision: null as any,
      totalConfidence: 0,
      reasoning: [] as string[]
    };

    // Weight decisions by confidence
    let weightedSum = 0;
    let totalWeight = 0;

    decisions.forEach((d: any) => {
      weightedSum += d.confidence;
      totalWeight += 1;
      aggregated.reasoning.push(...d.reasoning);
    });

    aggregated.totalConfidence = weightedSum / totalWeight;

    // Select highest confidence decision as final
    const bestDecision = decisions.reduce((best, current) =>
      current.confidence > best.confidence ? current : best
    );

    aggregated.finalDecision = bestDecision.decision;

    return aggregated;
  }

  private async executeWorkflowWithDecision(workflowId: string, decision: any): Promise<any> {
    const response = await fetch(`${this.coreflowAPI}/api/workflows/${workflowId}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ decision })
    });

    if (!response.ok) {
      throw new Error(`Workflow execution failed: ${response.statusText}`);
    }

    return await response.json();
  }

  private async findRelevantWorkflows(data: any): Promise<any[]> {
    // Find workflows relevant to the real-time decision
    const response = await fetch(`${this.coreflowAPI}/api/workflows/search`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        type: data.type,
        tags: data.tags,
        active: true
      })
    });

    if (!response.ok) {
      return [];
    }

    return await response.json();
  }

  // Cleanup
  async disconnect(): Promise<void> {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
    }

    if (this.wsConnection) {
      this.wsConnection.close();
    }

    this.isConnected = false;
    this.emit('disconnected');
  }
}