import { CoreFlow360AgentBridge } from './agent-bridge';

export interface AgentCapability {
  id: string;
  name: string;
  description: string;
  type: 'executive' | 'department' | 'operational' | 'specialist';
  capabilities: string[];
  requiredData: string[];
  outputFormat: any;
}

export interface AgentRequest {
  agentType: string;
  action: string;
  context: any;
  parameters?: Record<string, any>;
  timeout?: number;
}

export interface AgentResponse {
  success: boolean;
  agentId: string;
  result?: any;
  error?: string;
  executionTime: number;
  metadata?: Record<string, any>;
}

export // TODO: Consider splitting AgentServiceConnector into smaller, focused classes
class AgentServiceConnector {
  private bridge: CoreFlow360AgentBridge;
  private agentCapabilities: Map<string, AgentCapability> = new Map();
  private activeRequests: Map<string, AbortController> = new Map();
  private env: any;

  constructor(bridge: CoreFlow360AgentBridge, env?: any) {
    this.bridge = bridge;
    this.env = env;
    this.initializeCapabilities();
  }

  private initializeCapabilities(): void {
    // Define agent capabilities
    const capabilities: AgentCapability[] = [
      {
        id: 'ceo',
        name: 'CEO Agent',
        description: 'Strategic decision making and company direction',
        type: 'executive',
        capabilities: ['strategic_planning', 'vision_setting', 'major_decisions'],
        requiredData: ['company_metrics', 'market_data', 'financial_reports'],
        outputFormat: { decision: 'string', reasoning: 'array', impact: 'object' }
      },
      {
        id: 'cfo',
        name: 'CFO Agent',
        description: 'Financial management and analysis',
        type: 'executive',
        capabilities: ['financial_analysis', 'budget_planning', 'investment_decisions'],
        requiredData: ['financial_data', 'cash_flow', 'budget_reports'],
        outputFormat: { analysis: 'object', recommendations: 'array', projections: 'object' }
      },
      {
        id: 'cto',
        name: 'CTO Agent',
        description: 'Technology strategy and innovation',
        type: 'executive',
        capabilities: ['tech_strategy', 'innovation_planning', 'system_architecture'],
        requiredData: ['tech_stack', 'performance_metrics', 'innovation_pipeline'],
        outputFormat: { strategy: 'object', technologies: 'array', roadmap: 'object' }
      },
      {
        id: 'coo',
        name: 'COO Agent',
        description: 'Chief Operating Officer - Operational excellence and efficiency',
        type: 'executive',
        capabilities: ['operational_excellence', 'cross_department_coordination', 'process_standardization', 'performance_optimization'],
        requiredData: ['operational_metrics', 'department_performance', 'process_data', 'resource_utilization'],
        outputFormat: { strategy: 'object', optimizations: 'array', coordination: 'object', kpis: 'object' }
      },
      {
        id: 'cmo',
        name: 'CMO Agent',
        description: 'Chief Marketing Officer - Marketing strategy and brand management',
        type: 'executive',
        capabilities: ['marketing_strategy', 'brand_management', 'campaign_orchestration', 'customer_acquisition'],
        requiredData: ['market_data', 'campaign_metrics', 'brand_health', 'customer_analytics'],
        outputFormat: { strategy: 'object', campaigns: 'array', brand_initiatives: 'object', roi_analysis: 'object' }
      },
      {
        id: 'clo',
        name: 'CLO Agent',
        description: 'Chief Legal Officer - Legal compliance and governance',
        type: 'executive',
        capabilities: ['legal_compliance', 'contract_management', 'risk_mitigation', 'regulatory_compliance'],
        requiredData: ['legal_requirements', 'contracts', 'compliance_status', 'regulatory_changes'],
        outputFormat: { compliance: 'object', legal_opinion: 'string', risks: 'array', recommendations: 'array' }
      },
      {
        id: 'chro',
        name: 'CHRO Agent',
        description: 'Chief Human Resources Officer - Strategic workforce and culture',
        type: 'executive',
        capabilities: ['strategic_workforce_planning', 'executive_talent_management', 'organizational_culture', 'compensation_strategy'],
        requiredData: ['workforce_analytics', 'talent_pipeline', 'culture_metrics', 'compensation_data'],
        outputFormat: { strategy: 'object', initiatives: 'array', metrics: 'object', recommendations: 'array' }
      },
      {
        id: 'sales_manager',
        name: 'Sales Manager Agent',
        description: 'Sales strategy and customer acquisition',
        type: 'department',
        capabilities: ['sales_forecasting', 'lead_qualification', 'deal_closing'],
        requiredData: ['sales_pipeline', 'customer_data', 'market_trends'],
        outputFormat: { forecast: 'object', opportunities: 'array', strategies: 'array' }
      },
      {
        id: 'operations',
        name: 'Operations Agent',
        description: 'Operational efficiency and process optimization',
        type: 'operational',
        capabilities: ['process_optimization', 'resource_allocation', 'workflow_automation'],
        requiredData: ['process_data', 'resource_utilization', 'bottlenecks'],
        outputFormat: { optimizations: 'array', allocations: 'object', automations: 'array' }
      },
      {
        id: 'risk_analyst',
        name: 'Risk Analyst Agent',
        description: 'Risk assessment and mitigation',
        type: 'specialist',
        capabilities: ['risk_assessment', 'compliance_checking', 'mitigation_planning'],
        requiredData: ['risk_factors', 'compliance_requirements', 'historical_incidents'],
        outputFormat: { risks: 'array', mitigation: 'object', compliance: 'object' }
      },
      {
        id: 'market_analyst',
        name: 'Market Analyst Agent',
        description: 'Market analysis and competitive intelligence',
        type: 'specialist',
        capabilities: ['market_research', 'competitor_analysis', 'trend_prediction'],
        requiredData: ['market_data', 'competitor_info', 'industry_trends'],
        outputFormat: { analysis: 'object', competitors: 'array', predictions: 'array' }
      }
    ];

    capabilities.forEach((cap: any) => {
      this.agentCapabilities.set(cap.id, cap);
    });
  }

  // Get available agents and their capabilities
  async getAvailableAgents(): Promise<AgentCapability[]> {
    return Array.from(this.agentCapabilities.values());
  }

  // Get specific agent capability
  getAgentCapability(agentId: string): AgentCapability | undefined {
    return this.agentCapabilities.get(agentId);
  }

  // Request action from specific agent
  async requestAgentAction(request: AgentRequest): Promise<AgentResponse> {
    const startTime = Date.now();
    const requestId = `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    try {
      // Create abort controller for timeout
      const abortController = new AbortController();
      this.activeRequests.set(requestId, abortController);

      // Set timeout if specified
      const timeoutId = request.timeout ? setTimeout(() => {
        abortController.abort();
      }, request.timeout) : undefined;

      // Prepare context for agent system
      const agentContext = {
        id: requestId,
        timestamp: new Date(),
        type: this.mapAgentTypeToDecisionType(request.agentType),
        data: {
          action: request.action,
          context: request.context,
          parameters: request.parameters,
          agentType: request.agentType
        },
        priority: this.determinePriorityFromRequest(request)
      };

      // Request decision from agent
      const decision = await this.bridge.requestAgentDecision(agentContext);

      // Clear timeout
      if (timeoutId) clearTimeout(timeoutId);

      // Process and return response
      return {
        success: true,
        agentId: request.agentType,
        result: decision.decision,
        executionTime: Date.now() - startTime,
        metadata: {
          confidence: decision.confidence,
          reasoning: decision.reasoning,
          decisionId: decision.id
        }
      };
    } catch (error: any) {
      return {
        success: false,
        agentId: request.agentType,
        error: error instanceof Error ? error.message : 'Unknown error',
        executionTime: Date.now() - startTime
      };
    } finally {
      this.activeRequests.delete(requestId);
    }
  }

  // Execute multi-agent collaboration
  async executeMultiAgentTask(
    task: string,
    requiredAgents: string[],
    context: any
  ): Promise<{ results: Map<string, AgentResponse>; consensus?: any }> {
    const results = new Map<string, AgentResponse>();

    // Request actions from all required agents in parallel
    const promises = requiredAgents.map((agentType: any) =>
      this.requestAgentAction({
        agentType,
        action: task,
        context,
        timeout: 30000 // 30 second timeout per agent
      }).then(response => {
        results.set(agentType, response);
        return response;
      })
    );

    await Promise.all(promises);

    // Build consensus if multiple agents involved
    let consensus;
    if (requiredAgents.length > 1) {
      consensus = await this.buildConsensus(results, task);
    }

    return { results, consensus };
  }

  // Orchestrate complex workflow with multiple agents
  async orchestrateWorkflow(
    workflowDefinition: WorkflowDefinition
  ): Promise<WorkflowExecutionResult> {
    const executionId = `wf-exec-${Date.now()}`;
    const executionResults: any[] = [];
    const startTime = Date.now();

    try {
      // Execute workflow stages
      for (const stage of workflowDefinition.stages) {
        const stageResult = await this.executeWorkflowStage(stage, executionResults);
        executionResults.push(stageResult);

        // Check if stage failed and should stop
        if (!stageResult.success && stage.critical) {
          throw new Error(`Critical stage ${stage.name} failed: ${stageResult.error}`);
        }
      }

      return {
        executionId,
        success: true,
        results: executionResults,
        executionTime: Date.now() - startTime,
        finalOutput: this.aggregateWorkflowResults(executionResults)
      };
    } catch (error: any) {
      return {
        executionId,
        success: false,
        results: executionResults,
        executionTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Workflow execution failed'
      };
    }
  }

  // Get agent performance metrics
  async getAgentMetrics(agentId?: string): Promise<AgentMetrics> {
    const status = await this.bridge.getAgentStatus();

    if (agentId) {
      const agentStatus = status.get(agentId);
      return this.extractMetrics(agentStatus);
    }

    // Return aggregated metrics for all agents
    const allMetrics: AgentMetrics = {
      totalRequests: 0,
      successRate: 0,
      averageResponseTime: 0,
      activeAgents: status.size,
      agentSpecificMetrics: new Map()
    };

    status.forEach((agentStatus, id) => {
      const metrics = this.extractMetrics(agentStatus);
      allMetrics.agentSpecificMetrics.set(id, metrics);
      allMetrics.totalRequests += metrics.totalRequests;
    });

    return allMetrics;
  }

  // Subscribe to agent events
  subscribeToAgentEvents(
    eventType: 'decision' | 'status' | 'alert' | 'all',
    callback: (event: any) => void
  ): () => void {
    const eventHandlers: Record<string, string> = {
      decision: 'agentDecision',
      status: 'agentStatusUpdate',
      alert: 'agentAlert',
      all: 'realtimeUpdate'
    };

    const eventName = eventHandlers[eventType];
    this.bridge.on(eventName, callback);

    // Return unsubscribe function
    return () => {
      this.bridge.off(eventName, callback);
    };
  }

  // Helper methods
  private mapAgentTypeToDecisionType(agentType: string): string {
    const mapping: Record<string, string> = {
      ceo: 'strategic_executive',
      cfo: 'financial_executive',
      cto: 'technology_executive',
      hr_manager: 'human_resources',
      sales_manager: 'sales_optimization',
      operations: 'operational',
      risk_analyst: 'risk_assessment',
      market_analyst: 'market_analysis'
    };

    return mapping[agentType] || 'general';
  }

  private determinePriorityFromRequest(request: AgentRequest): string {
    // Determine priority based on agent type and action
    const highPriorityAgents = ['ceo', 'cfo', 'cto'];
    const highPriorityActions = ['emergency', 'critical', 'urgent'];

    if (highPriorityAgents.includes(request.agentType)) {
      return 'high';
    }

    if (request.action && highPriorityActions.some(a => request.action.includes(a))) {
      return 'critical';
    }

    return request.parameters?.priority || 'medium';
  }

  private async buildConsensus(
    results: Map<string, AgentResponse>,
    task: string
  ): Promise<any> {
    const successfulResults = Array.from(results.values()).filter((r: any) => r.success);

    if (successfulResults.length === 0) {
      return null;
    }

    // Simple consensus: majority vote or average
    const decisions = successfulResults.map((r: any) => r.result);

    // If results are boolean, use majority vote
    if (typeof decisions[0] === 'boolean') {
      const trueCount = decisions.filter((d: any) => d === true).length;
      return trueCount > decisions.length / 2;
    }

    // If results are numeric, use average
    if (typeof decisions[0] === 'number') {
      return decisions.reduce((sum, d) => sum + d, 0) / decisions.length;
    }

    // For complex objects, return all with confidence scores
    return {
      task,
      decisions: successfulResults.map((r: any) => ({
        agent: r.agentId,
        decision: r.result,
        confidence: r.metadata?.confidence || 0
      })),
      consensusType: 'collection'
    };
  }

  private async executeWorkflowStage(
    stage: WorkflowStage,
    previousResults: any[]
  ): Promise<any> {
    const context = {
      ...stage.context,
      previousResults
    };

    if (stage.agents.length === 1) {
      // Single agent execution
      return await this.requestAgentAction({
        agentType: stage.agents[0],
        action: stage.action,
        context,
        parameters: stage.parameters
      });
    } else {
      // Multi-agent execution
      const result = await this.executeMultiAgentTask(
        stage.action,
        stage.agents,
        context
      );

      return {
        success: Array.from(result.results.values()).some(r => r.success),
        stage: stage.name,
        results: Object.fromEntries(result.results),
        consensus: result.consensus
      };
    }
  }

  private aggregateWorkflowResults(results: any[]): any {
    // Aggregate all workflow stage results
    return {
      stages: results.map((r: any) => ({
        name: r.stage || 'unknown',
        success: r.success,
        output: r.result || r.consensus
      })),
      overallSuccess: results.every(r => r.success !== false),
      summary: this.generateWorkflowSummary(results)
    };
  }

  private generateWorkflowSummary(results: any[]): string {
    const successful = results.filter((r: any) => r.success).length;
    const total = results.length;
    return `Workflow completed with ${successful}/${total} successful stages`;
  }

  private extractMetrics(agentStatus: any): AgentMetrics {
    return {
      totalRequests: agentStatus?.metrics?.totalRequests || 0,
      successRate: agentStatus?.metrics?.successRate || 0,
      averageResponseTime: agentStatus?.metrics?.averageResponseTime || 0,
      activeAgents: 1,
      agentSpecificMetrics: new Map()
    };
  }

  // Cancel active request
  cancelRequest(requestId: string): void {
    const controller = this.activeRequests.get(requestId);
    if (controller) {
      controller.abort();
      this.activeRequests.delete(requestId);
    }
  }

  // Cleanup
  cleanup(): void {
    // Cancel all active requests
    this.activeRequests.forEach((controller: any) => controller.abort());
    this.activeRequests.clear();
  }
}

// Type definitions
interface WorkflowDefinition {
  name: string;
  stages: WorkflowStage[];
  timeout?: number;
}

interface WorkflowStage {
  name: string;
  action: string;
  agents: string[];
  context: any;
  parameters?: any;
  critical?: boolean;
}

interface WorkflowExecutionResult {
  executionId: string;
  success: boolean;
  results: any[];
  executionTime: number;
  finalOutput?: any;
  error?: string;
}

interface AgentMetrics {
  totalRequests: number;
  successRate: number;
  averageResponseTime: number;
  activeAgents: number;
  agentSpecificMetrics: Map<string, any>;
}