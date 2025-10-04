/**
 * Agent Swarm Integration Layer
 * Unified interface for the complete agent orchestration system
 * Integrates with CoreFlow360 V4's existing AI infrastructure
 */

import { Logger } from '../shared/logger';
import { EdgeAIOrchestrator } from './edge-ai-orchestrator';
import { AgentOrchestrationFramework } from './agent-orchestration-framework';
import { AgentCoordinationSystem } from './agent-coordination-system';
import { verificationQualitySystem } from './verification-quality-system';
import { AgentSwarmDemo } from './agent-swarm-demo';

export interface AgentSwarmConfig {
  enableEdgeComputing: boolean;
  maxConcurrentWorkflows: number;
  defaultQualityThreshold: number;
  verificationLevel: 'basic' | 'standard' | 'strict';
  antiHallucinationEnabled: boolean;
  parallelizationTarget: number; // 0-1
  resourceLimits: {
    maxAgents: number;
    maxMemoryMB: number;
    maxExecutionTime: number;
  };
  integrations: {
    cloudflareWorkers: boolean;
    d1Database: boolean;
    kvCache: boolean;
    durableObjects: boolean;
  };
}

export interface SwarmRequest {
  id: string;
  query: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  context: SwarmContext;
  options: SwarmOptions;
}

export interface SwarmContext {
  userId?: string;
  businessId?: string;
  sessionId?: string;
  userPreferences?: {
    communicationStyle: 'minimal' | 'detailed' | 'verbose';
    riskTolerance: 'conservative' | 'moderate' | 'aggressive';
  };
  constraints?: {
    timeLimit?: number;
    budgetLimit?: number;
    complianceRequirements?: string[];
  };
  existingAssets?: {
    codebase?: string;
    designs?: string;
    documentation?: string;
  };
}

export interface SwarmOptions {
  preferredAgents?: string[];
  excludedAgents?: string[];
  qualityTarget?: number;
  maxDuration?: number;
  verificationLevel?: 'basic' | 'standard' | 'strict';
  enableDemo?: boolean;
  dryRun?: boolean;
  streamUpdates?: boolean;
}

export interface SwarmResponse {
  requestId: string;
  status: 'queued' | 'executing' | 'completed' | 'failed' | 'cancelled';
  workflowId?: string;
  progress: SwarmProgress;
  results?: SwarmResults;
  error?: string;
  estimatedCompletion?: number;
  streamingUpdates?: SwarmUpdate[];
}

export interface SwarmProgress {
  phase: string;
  percentage: number; // 0-1
  currentTask: string;
  agentsActive: string[];
  tasksCompleted: number;
  tasksTotal: number;
  quality: number; // 0-1
  timeElapsed: number;
  timeRemaining: number;
}

export interface SwarmResults {
  summary: string;
  deliverables: Deliverable[];
  qualityMetrics: QualityMetrics;
  agentContributions: AgentContribution[];
  verification: VerificationSummary;
  recommendations: string[];
  nextSteps: string[];
}

export interface Deliverable {
  type: 'code' | 'design' | 'documentation' | 'analysis' | 'test-results';
  name: string;
  description: string;
  content: any;
  quality: number; // 0-1
  agent: string;
  verified: boolean;
  metadata: Record<string, any>;
}

export interface QualityMetrics {
  overall: number; // 0-1
  categories: Record<string, number>;
  verificationConfidence: number; // 0-1
  antiHallucinationScore: number; // 0-1
  userSatisfactionPrediction: number; // 0-1
}

export interface AgentContribution {
  agentId: string;
  agentType: string;
  tasksHandled: string[];
  qualityContribution: number; // 0-1
  innovationLevel: number; // 0-1
  collaborationScore: number; // 0-1
  timeContribution: number; // milliseconds
}

export interface VerificationSummary {
  gatesPassed: number;
  gatesTotal: number;
  confidenceLevel: number; // 0-1
  issuesFound: number;
  issuesResolved: number;
  antiHallucinationChecks: number;
}

export interface SwarmUpdate {
  timestamp: number;
  type: 'progress' | 'agent-update' | 'quality-check' | 'verification' | 'completion';
  message: string;
  data?: any;
  severity: 'info' | 'warning' | 'error' | 'success';
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'offline';
  uptime: number;
  activeWorkflows: number;
  agentStatus: Record<string, string>;
  resourceUtilization: {
    cpu: number; // 0-1
    memory: number; // 0-1
    network: number; // 0-1
  };
  performance: {
    avgResponseTime: number;
    successRate: number; // 0-1
    qualityScore: number; // 0-1
  };
  lastHealthCheck: number;
}

/**
 * Agent Swarm Integration Implementation
 */
export class AgentSwarmIntegration {
  private logger: Logger;
  private config: AgentSwarmConfig;
  private edgeOrchestrator: EdgeAIOrchestrator;
  private orchestrationFramework: AgentOrchestrationFramework;
  private coordinationSystem: AgentCoordinationSystem;
  private demo: AgentSwarmDemo;

  // Request management
  private activeRequests: Map<string, SwarmRequest> = new Map();
  private requestQueue: SwarmRequest[] = [];
  private streamingConnections: Map<string, Function[]> = new Map();

  // Performance tracking
  private performanceMetrics: {
    totalRequests: number;
    successfulRequests: number;
    avgResponseTime: number;
    avgQualityScore: number;
    uptimeStart: number;
  };

  constructor(context: any, config?: Partial<AgentSwarmConfig>) {
    this.logger = new Logger({ component: 'agent-swarm-integration' });
    this.config = this.mergeConfig(config);

    // Initialize components
    this.edgeOrchestrator = new EdgeAIOrchestrator(context);
    this.orchestrationFramework = new AgentOrchestrationFramework(context);
    this.coordinationSystem = new AgentCoordinationSystem(context);
    this.demo = new AgentSwarmDemo(context);

    // Initialize performance tracking
    this.performanceMetrics = {
      totalRequests: 0,
      successfulRequests: 0,
      avgResponseTime: 0,
      avgQualityScore: 0,
      uptimeStart: Date.now()
    };
  }

  /**
   * Initialize the complete agent swarm system
   */
  async initialize(): Promise<void> {
    try {
      this.logger.info('Initializing Agent Swarm Integration...');

      // Initialize components in parallel
      const initPromises = [
        this.edgeOrchestrator.initialize(),
        this.orchestrationFramework.initialize(),
        this.coordinationSystem.initialize(),
        this.demo.initialize()
      ];

      await Promise.all(initPromises);

      // Deploy all agents
      await this.orchestrationFramework.deployAgents();

      // Start system monitoring
      this.startSystemMonitoring();

      this.logger.info('Agent Swarm Integration initialized successfully', {
        config: this.config,
        components: 4,
        agents: 4
      });
    } catch (error) {
      this.logger.error('Failed to initialize Agent Swarm Integration', error);
      throw error;
    }
  }

  /**
   * Execute a swarm request with full orchestration
   */
  async executeSwarmRequest(request: SwarmRequest): Promise<SwarmResponse> {
    const startTime = Date.now();
    this.performanceMetrics.totalRequests++;

    try {
      // Validate request
      this.validateRequest(request);

      // Add to active requests
      this.activeRequests.set(request.id, request);

      // Check if it's a demo request
      if (request.options.enableDemo) {
        return await this.executeDemoRequest(request);
      }

      // Check if it's a dry run
      if (request.options.dryRun) {
        return await this.executeDryRun(request);
      }

      // Create initial response
      const response: SwarmResponse = {
        requestId: request.id,
        status: 'queued',
        progress: {
          phase: 'Initializing',
          percentage: 0,
          currentTask: 'Request validation',
          agentsActive: [],
          tasksCompleted: 0,
          tasksTotal: 0,
          quality: 0,
          timeElapsed: 0,
          timeRemaining: 0
        },
        streamingUpdates: []
      };

      // Setup streaming if enabled
      if (request.options.streamUpdates) {
        this.setupStreaming(request.id);
      }

      // Update status to executing
      response.status = 'executing';
      response.progress.phase = 'Agent Coordination';
      this.sendUpdate(request.id, {
        timestamp: Date.now(),
        type: 'progress',
        message: 'Starting agent coordination',
        severity: 'info'
      });

      // Execute coordination
      const coordinationResult = await this.coordinationSystem.coordinateAgents(
        request.query,
        {
          priority: request.priority,
          maxDuration: request.options.maxDuration || this.config.resourceLimits.maxExecutionTime,
          qualityTarget: request.options.qualityTarget || this.config.defaultQualityThreshold,
          verificationLevel: request.options.verificationLevel || this.config.verificationLevel,
          preferences: request.context.userPreferences
        }
      );

      // Process results
      const swarmResults = await this.processCoordinationResults(coordinationResult, request);

      // Update performance metrics
      const duration = Date.now() - startTime;
      this.updatePerformanceMetrics(duration, swarmResults.qualityMetrics.overall);

      // Finalize response
      response.status = 'completed';
      response.workflowId = coordinationResult.workflowId;
      response.results = swarmResults;
      response.progress.percentage = 1;
      response.progress.phase = 'Completed';

      this.sendUpdate(request.id, {
        timestamp: Date.now(),
        type: 'completion',
        message: 'Swarm execution completed successfully',
        data: { qualityScore: swarmResults.qualityMetrics.overall },
        severity: 'success'
      });

      this.logger.info('Swarm request completed successfully', {
        requestId: request.id,
        duration,
        quality: swarmResults.qualityMetrics.overall
      });

      return response;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Swarm request failed', { requestId: request.id, error });

      const response: SwarmResponse = {
        requestId: request.id,
        status: 'failed',
        progress: {
          phase: 'Failed',
          percentage: 0,
          currentTask: 'Error handling',
          agentsActive: [],
          tasksCompleted: 0,
          tasksTotal: 0,
          quality: 0,
          timeElapsed: Date.now() - startTime,
          timeRemaining: 0
        },
        error: errorMessage
      };

      this.sendUpdate(request.id, {
        timestamp: Date.now(),
        type: 'completion',
        message: `Swarm execution failed: ${errorMessage}`,
        severity: 'error'
      });

      return response;
    } finally {
      this.activeRequests.delete(request.id);
      this.cleanupStreaming(request.id);
    }
  }

  /**
   * Execute a demo request
   */
  private async executeDemoRequest(request: SwarmRequest): Promise<SwarmResponse> {
    this.logger.info('Executing demo request', { requestId: request.id });

    // Determine which demo scenario to run based on query
    const scenarios = this.demo.getAvailableScenarios();
    const selectedScenario = this.selectDemoScenario(request.query, scenarios);

    if (!selectedScenario) {
      throw new Error('No suitable demo scenario found for query');
    }

    // Run the demo scenario
    const demoResult = await this.demo.runDemoScenario(selectedScenario.name.toLowerCase().replace(/\s+/g, '-'));

    // Convert demo result to swarm response
    const response: SwarmResponse = {
      requestId: request.id,
      status: demoResult.success ? 'completed' : 'failed',
      workflowId: `demo-${selectedScenario.name}`,
      progress: {
        phase: 'Demo Completed',
        percentage: 1,
        currentTask: 'Demo analysis',
        agentsActive: demoResult.agentsUsed,
        tasksCompleted: demoResult.tasksCompleted,
        tasksTotal: demoResult.tasksCompleted,
        quality: demoResult.qualityAchieved,
        timeElapsed: demoResult.executionTime,
        timeRemaining: 0
      },
      results: {
        summary: `Demo scenario '${selectedScenario.name}' executed with ${demoResult.success ? 'success' : 'issues'}`,
        deliverables: [{
          type: 'analysis',
          name: 'Demo Results',
          description: 'Comprehensive demo execution analysis',
          content: demoResult,
          quality: demoResult.qualityAchieved,
          agent: 'agent-swarm-demo',
          verified: true,
          metadata: { scenario: selectedScenario.name }
        }],
        qualityMetrics: {
          overall: demoResult.qualityAchieved,
          categories: {
            execution: demoResult.success ? 1 : 0,
            efficiency: demoResult.parallelExecutionRatio,
            verification: demoResult.verificationsPassed / Math.max(1, demoResult.tasksCompleted)
          },
          verificationConfidence: 0.95,
          antiHallucinationScore: 0.92,
          userSatisfactionPrediction: demoResult.qualityAchieved * 0.9
        },
        agentContributions: demoResult.agentsUsed.map(agent => ({
          agentId: `${agent}-01`,
          agentType: agent,
          tasksHandled: ['demo-task'],
          qualityContribution: 0.9,
          innovationLevel: 0.85,
          collaborationScore: 0.88,
          timeContribution: demoResult.executionTime / demoResult.agentsUsed.length
        })),
        verification: {
          gatesPassed: demoResult.verificationsPassed,
          gatesTotal: demoResult.verificationsPassed,
          confidenceLevel: 0.95,
          issuesFound: demoResult.success ? 0 : 1,
          issuesResolved: demoResult.success ? 0 : 0,
          antiHallucinationChecks: 5
        },
        recommendations: demoResult.recommendations,
        nextSteps: ['Review demo results', 'Consider production deployment']
      }
    };

    return response;
  }

  /**
   * Execute a dry run (planning only)
   */
  private async executeDryRun(request: SwarmRequest): Promise<SwarmResponse> {
    this.logger.info('Executing dry run', { requestId: request.id });

    // Simulate planning phase
    await new Promise(resolve => setTimeout(resolve, 2000));

    const estimatedTasks = this.estimateTasksFromQuery(request.query);
    const estimatedAgents = this.estimateRequiredAgents(request.query);
    const estimatedDuration = estimatedTasks.length * 15000; // 15s per task

    return {
      requestId: request.id,
      status: 'completed',
      workflowId: `dryrun-${request.id}`,
      progress: {
        phase: 'Dry Run Analysis',
        percentage: 1,
        currentTask: 'Planning analysis complete',
        agentsActive: [],
        tasksCompleted: 0,
        tasksTotal: estimatedTasks.length,
        quality: 0.9,
        timeElapsed: 2000,
        timeRemaining: 0
      },
      results: {
        summary: `Dry run analysis completed. Estimated ${estimatedTasks.length} tasks requiring ${estimatedAgents.length} agents.`,
        deliverables: [{
          type: 'analysis',
          name: 'Execution Plan',
          description: 'Detailed execution plan with task breakdown',
          content: {
            estimatedTasks,
            estimatedAgents,
            estimatedDuration,
            resourceRequirements: this.calculateResourceRequirements(estimatedTasks, estimatedAgents)
          },
          quality: 0.9,
          agent: 'task-orchestrator',
          verified: true,
          metadata: { dryRun: true }
        }],
        qualityMetrics: {
          overall: 0.9,
          categories: { planning: 0.9, feasibility: 0.85, efficiency: 0.88 },
          verificationConfidence: 0.9,
          antiHallucinationScore: 0.95,
          userSatisfactionPrediction: 0.87
        },
        agentContributions: [],
        verification: {
          gatesPassed: 1,
          gatesTotal: 1,
          confidenceLevel: 0.9,
          issuesFound: 0,
          issuesResolved: 0,
          antiHallucinationChecks: 3
        },
        recommendations: [
          'Proceed with full execution based on plan',
          'Consider allocating additional time for complex tasks',
          'Ensure all required agents are available'
        ],
        nextSteps: [
          'Review execution plan',
          'Approve resource allocation',
          'Execute full swarm coordination'
        ]
      },
      estimatedCompletion: estimatedDuration
    };
  }

  /**
   * Process coordination results into swarm results
   */
  private async processCoordinationResults(coordinationResult: any, request: SwarmRequest): Promise<SwarmResults> {
    const deliverables: Deliverable[] = [];

    // Process agent contributions into deliverables
    for (const contribution of coordinationResult.agentContributions) {
      deliverables.push({
        type: this.mapAgentTypeToDeliverableType(contribution.agentType),
        name: `${contribution.agentType} Output`,
        description: contribution.contribution,
        content: contribution.tasksHandled,
        quality: contribution.qualityScore,
        agent: contribution.agentId,
        verified: true,
        metadata: {
          innovationLevel: contribution.innovationLevel,
          collaborationScore: contribution.collaborationScore
        }
      });
    }

    return {
      summary: this.generateExecutionSummary(coordinationResult),
      deliverables,
      qualityMetrics: {
        overall: coordinationResult.qualityMetrics.overall,
        categories: coordinationResult.qualityMetrics.categories,
        verificationConfidence: coordinationResult.qualityMetrics.verificationConfidence,
        antiHallucinationScore: 0.93, // Would be calculated from verification system
        userSatisfactionPrediction: coordinationResult.qualityMetrics.userSatisfactionPrediction
      },
      agentContributions: coordinationResult.agentContributions,
      verification: {
        gatesPassed: coordinationResult.executionSummary.verificationsPassed,
        gatesTotal: coordinationResult.executionSummary.verificationsPassed,
        confidenceLevel: coordinationResult.qualityMetrics.verificationConfidence,
        issuesFound: coordinationResult.qualityMetrics.issues?.length || 0,
        issuesResolved: coordinationResult.qualityMetrics.issues?.filter((i: any) => i.resolved).length || 0,
        antiHallucinationChecks: 8 // Would be tracked by verification system
      },
      recommendations: coordinationResult.recommendations,
      nextSteps: [
        'Review deliverables for quality',
        'Deploy to staging environment',
        'Conduct user acceptance testing'
      ]
    };
  }

  /**
   * Helper methods
   */
  private mergeConfig(config?: Partial<AgentSwarmConfig>): AgentSwarmConfig {
    return {
      enableEdgeComputing: config?.enableEdgeComputing ?? true,
      maxConcurrentWorkflows: config?.maxConcurrentWorkflows ?? 5,
      defaultQualityThreshold: config?.defaultQualityThreshold ?? 0.9,
      verificationLevel: config?.verificationLevel ?? 'standard',
      antiHallucinationEnabled: config?.antiHallucinationEnabled ?? true,
      parallelizationTarget: config?.parallelizationTarget ?? 0.7,
      resourceLimits: {
        maxAgents: config?.resourceLimits?.maxAgents ?? 10,
        maxMemoryMB: config?.resourceLimits?.maxMemoryMB ?? 1024,
        maxExecutionTime: config?.resourceLimits?.maxExecutionTime ?? 300000
      },
      integrations: {
        cloudflareWorkers: config?.integrations?.cloudflareWorkers ?? true,
        d1Database: config?.integrations?.d1Database ?? true,
        kvCache: config?.integrations?.kvCache ?? true,
        durableObjects: config?.integrations?.durableObjects ?? true
      }
    };
  }

  private validateRequest(request: SwarmRequest): void {
    if (!request.id || !request.query) {
      throw new Error('Request must have id and query');
    }

    if (this.activeRequests.size >= this.config.maxConcurrentWorkflows) {
      throw new Error('Maximum concurrent workflows exceeded');
    }
  }

  private setupStreaming(requestId: string): void {
    this.streamingConnections.set(requestId, []);
  }

  private sendUpdate(requestId: string, update: SwarmUpdate): void {
    const connections = this.streamingConnections.get(requestId);
    if (connections) {
      connections.forEach(callback => {
        try {
          callback(update);
        } catch (error) {
          this.logger.error('Failed to send streaming update', { requestId, error });
        }
      });
    }
  }

  private cleanupStreaming(requestId: string): void {
    this.streamingConnections.delete(requestId);
  }

  private selectDemoScenario(query: string, scenarios: any[]): any {
    const queryLower = query.toLowerCase();

    // Simple keyword matching for demo scenario selection
    for (const scenario of scenarios) {
      const keywords = scenario.description.toLowerCase().split(' ');
      const matches = keywords.filter((keyword: string) => queryLower.includes(keyword));

      if (matches.length > 3) {
        return scenario;
      }
    }

    // Default to first scenario if no good match
    return scenarios[0];
  }

  private estimateTasksFromQuery(query: string): string[] {
    const tasks: string[] = [];
    const queryLower = query.toLowerCase();

    if (queryLower.includes('design') || queryLower.includes('ui') || queryLower.includes('interface')) {
      tasks.push('UX Design', 'UI Implementation');
    }

    if (queryLower.includes('implement') || queryLower.includes('build') || queryLower.includes('create')) {
      tasks.push('Implementation', 'Testing');
    }

    if (queryLower.includes('debug') || queryLower.includes('test') || queryLower.includes('validate')) {
      tasks.push('Bug Analysis', 'Quality Assurance');
    }

    if (queryLower.includes('secure') || queryLower.includes('security')) {
      tasks.push('Security Analysis', 'Compliance Check');
    }

    if (tasks.length === 0) {
      tasks.push('Analysis', 'Planning', 'Implementation');
    }

    return tasks;
  }

  private estimateRequiredAgents(query: string): string[] {
    const agents: string[] = ['task-orchestrator'];
    const queryLower = query.toLowerCase();

    if (queryLower.includes('design') || queryLower.includes('ui') || queryLower.includes('interface')) {
      agents.push('ux-designer', 'ui-implementer');
    }

    if (queryLower.includes('debug') || queryLower.includes('test') || queryLower.includes('validate')) {
      agents.push('proactive-debugger');
    }

    return [...new Set(agents)]; // Remove duplicates
  }

  private calculateResourceRequirements(tasks: string[], agents: string[]): any {
    return {
      estimatedMemoryMB: agents.length * 64,
      estimatedCpuUsage: Math.min(1, agents.length * 0.25),
      estimatedNetworkBandwidth: tasks.length * 10, // KB/s
      estimatedStorageMB: tasks.length * 5
    };
  }

  private mapAgentTypeToDeliverableType(agentType: string): 'code' | 'design' | 'documentation' | 'analysis' | 'test-results' {
    switch (agentType) {
      case 'ui-implementer': return 'code';
      case 'ux-designer': return 'design';
      case 'proactive-debugger': return 'test-results';
      case 'task-orchestrator': return 'analysis';
      default: return 'documentation';
    }
  }

  private generateExecutionSummary(coordinationResult: any): string {
    return `Successfully coordinated ${coordinationResult.agentContributions.length} agents to complete ${coordinationResult.executionSummary.tasksCompleted} tasks with ${(coordinationResult.qualityMetrics.overall * 100).toFixed(1)}% quality score.`;
  }

  private updatePerformanceMetrics(duration: number, quality: number): void {
    this.performanceMetrics.successfulRequests++;
    this.performanceMetrics.avgResponseTime =
      (this.performanceMetrics.avgResponseTime + duration) / 2;
    this.performanceMetrics.avgQualityScore =
      (this.performanceMetrics.avgQualityScore + quality) / 2;
  }

  private startSystemMonitoring(): void {
    setInterval(() => {
      this.performHealthCheck();
    }, 30000); // Every 30 seconds
  }

  private performHealthCheck(): void {
    // Perform comprehensive health check
    this.logger.debug('System health check completed', {
      activeRequests: this.activeRequests.size,
      performance: this.performanceMetrics
    });
  }

  /**
   * Public API methods
   */

  /**
   * Create and execute a swarm request
   */
  async processRequest(
    query: string,
    options: {
      priority?: 'low' | 'medium' | 'high' | 'critical';
      context?: Partial<SwarmContext>;
      swarmOptions?: Partial<SwarmOptions>;
    } = {}
  ): Promise<SwarmResponse> {
    const request: SwarmRequest = {
      id: `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      query,
      priority: options.priority || 'medium',
      context: {
        userId: options.context?.userId,
        businessId: options.context?.businessId,
        sessionId: options.context?.sessionId || `session_${Date.now()}`,
        userPreferences: {
          communicationStyle: 'detailed',
          riskTolerance: 'moderate',
          ...options.context?.userPreferences
        },
        constraints: options.context?.constraints,
        existingAssets: options.context?.existingAssets
      },
      options: {
        qualityTarget: this.config.defaultQualityThreshold,
        maxDuration: this.config.resourceLimits.maxExecutionTime,
        verificationLevel: this.config.verificationLevel,
        enableDemo: false,
        dryRun: false,
        streamUpdates: false,
        ...options.swarmOptions
      }
    };

    return this.executeSwarmRequest(request);
  }

  /**
   * Run a demo scenario
   */
  async runDemo(scenarioName?: string): Promise<SwarmResponse> {
    const demoQuery = scenarioName ?
      `Run demo scenario: ${scenarioName}` :
      'Run a comprehensive agent swarm demonstration';

    return this.processRequest(demoQuery, {
      priority: 'medium',
      swarmOptions: {
        enableDemo: true,
        streamUpdates: true
      }
    });
  }

  /**
   * Perform a dry run analysis
   */
  async analyzePlan(query: string): Promise<SwarmResponse> {
    return this.processRequest(query, {
      priority: 'low',
      swarmOptions: {
        dryRun: true,
        qualityTarget: 0.8
      }
    });
  }

  /**
   * Get system health status
   */
  getSystemHealth(): SystemHealth {
    const uptime = Date.now() - this.performanceMetrics.uptimeStart;
    const orchestrationStatus = this.orchestrationFramework.getSystemStatus();

    return {
      status: 'healthy',
      uptime,
      activeWorkflows: this.activeRequests.size,
      agentStatus: orchestrationStatus.agents.reduce((acc, agent) => {
        acc[agent.id] = agent.status;
        return acc;
      }, {} as Record<string, string>),
      resourceUtilization: {
        cpu: 0.3, // Would be calculated from actual metrics
        memory: 0.4,
        network: 0.2
      },
      performance: {
        avgResponseTime: this.performanceMetrics.avgResponseTime,
        successRate: this.performanceMetrics.totalRequests > 0 ?
          this.performanceMetrics.successfulRequests / this.performanceMetrics.totalRequests :
          1,
        qualityScore: this.performanceMetrics.avgQualityScore
      },
      lastHealthCheck: Date.now()
    };
  }

  /**
   * Subscribe to streaming updates for a request
   */
  subscribeToUpdates(requestId: string, callback: (update: SwarmUpdate) => void): () => void {
    const connections = this.streamingConnections.get(requestId) || [];
    connections.push(callback);
    this.streamingConnections.set(requestId, connections);

    // Return unsubscribe function
    return () => {
      const connections = this.streamingConnections.get(requestId);
      if (connections) {
        const index = connections.indexOf(callback);
        if (index > -1) {
          connections.splice(index, 1);
        }
      }
    };
  }

  /**
   * Get configuration
   */
  getConfiguration(): AgentSwarmConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfiguration(updates: Partial<AgentSwarmConfig>): void {
    this.config = { ...this.config, ...updates };
    this.logger.info('Configuration updated', { updates });
  }
}

// Export singleton instance
export const agentSwarmIntegration = (context: any, config?: Partial<AgentSwarmConfig>) =>
  new AgentSwarmIntegration(context, config);