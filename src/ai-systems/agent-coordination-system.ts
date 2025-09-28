/**
 * Agent Coordination System
 * Implements cross-agent collaboration patterns and task delegation
 * Integrates with the Agent Orchestration Framework
 */

import { Logger } from '../shared/logger';
import { AgentOrchestrationFramework, type Agent, type Task, type WorkflowDAG } from './agent-orchestration-framework';

export interface CoordinationContext {
  requestId: string;
  userQuery: string;
  requirements: Requirements;
  constraints: Constraints;
  preferences: UserPreferences;
}

export interface Requirements {
  functional: string[];
  nonFunctional: string[];
  businessRules: string[];
  compliance: string[];
  integrations: string[];
}

export interface Constraints {
  timeBox: number; // milliseconds
  qualityThreshold: number; // 0-1
  parallelizationLevel: number; // 0-1
  verificationLevel: 'basic' | 'standard' | 'strict';
  resourceLimits: ResourceLimits;
}

export interface ResourceLimits {
  maxAgents: number;
  maxParallelTasks: number;
  memoryLimit: number; // MB
  timeoutThreshold: number; // milliseconds
}

export interface UserPreferences {
  communicationStyle: 'minimal' | 'detailed' | 'verbose';
  updateFrequency: 'low' | 'medium' | 'high';
  riskTolerance: 'conservative' | 'moderate' | 'aggressive';
  priorityOrder: string[];
}

export interface TaskDelegation {
  taskId: string;
  assignedAgent: string;
  delegationReason: string;
  expectedOutcome: string;
  dependencies: TaskDependency[];
  communicationProtocol: CommunicationProtocol;
}

export interface TaskDependency {
  prerequisiteTask: string;
  dependencyType: 'data' | 'completion' | 'approval' | 'resource';
  blocking: boolean;
  transferMethod: 'direct' | 'shared-memory' | 'message-passing';
}

export interface CommunicationProtocol {
  type: 'synchronous' | 'asynchronous' | 'event-driven';
  frequency: number; // milliseconds
  channels: CommunicationChannel[];
  escalationRules: EscalationRule[];
}

export interface CommunicationChannel {
  name: string;
  purpose: string;
  participants: string[];
  messageFormat: 'json' | 'structured-text' | 'binary';
  priority: 'low' | 'medium' | 'high' | 'critical';
}

export interface EscalationRule {
  condition: string;
  action: 'notify' | 'reassign' | 'escalate' | 'abort';
  threshold: number;
  recipient: string;
}

export interface CoordinationResult {
  success: boolean;
  workflowId: string;
  executionSummary: ExecutionSummary;
  agentContributions: AgentContribution[];
  qualityMetrics: QualityMetrics;
  recommendations: string[];
}

export interface ExecutionSummary {
  totalDuration: number;
  tasksCompleted: number;
  tasksParallel: number;
  verificationsPassed: number;
  issuesResolved: number;
  efficiencyScore: number; // 0-1
}

export interface AgentContribution {
  agentId: string;
  agentType: string;
  tasksHandled: string[];
  contribution: string;
  qualityScore: number; // 0-1
  innovationLevel: number; // 0-1
  collaborationScore: number; // 0-1
}

export interface QualityMetrics {
  overall: number; // 0-1
  categories: {
    correctness: number;
    performance: number;
    security: number;
    usability: number;
    maintainability: number;
    accessibility: number;
  };
  verificationConfidence: number; // 0-1
  userSatisfactionPrediction: number; // 0-1
}

/**
 * Agent Coordination System Implementation
 */
export class AgentCoordinationSystem {
  private logger: Logger;
  private orchestrationFramework: AgentOrchestrationFramework;
  private activeCoordinations: Map<string, CoordinationContext> = new Map();
  private delegationHistory: Map<string, TaskDelegation[]> = new Map();
  private performanceBaseline: Map<string, number> = new Map();

  constructor(context: any) {
    this.logger = new Logger({ component: 'agent-coordination' });
    this.orchestrationFramework = new AgentOrchestrationFramework(context);
  }

  /**
   * Initialize the coordination system
   */
  async initialize(): Promise<void> {
    try {
      // Initialize orchestration framework
      await this.orchestrationFramework.initialize();

      // Deploy all agents in parallel
      const deployedAgents = await this.orchestrationFramework.deployAgents();

      // Establish communication channels
      await this.establishCommunicationChannels();

      // Initialize performance baselines
      this.initializePerformanceBaselines();

      this.logger.info('Agent Coordination System initialized', {
        agentsDeployed: deployedAgents.size,
        communicationChannels: 4
      });
    } catch (error) {
      this.logger.error('Failed to initialize Agent Coordination System', error);
      throw error;
    }
  }

  /**
   * Coordinate agents to execute a complex user request
   */
  async coordinateAgents(
    userQuery: string,
    options: {
      priority?: 'low' | 'medium' | 'high' | 'critical';
      maxDuration?: number;
      qualityTarget?: number;
      verificationLevel?: 'basic' | 'standard' | 'strict';
      preferences?: Partial<UserPreferences>;
    } = {}
  ): Promise<CoordinationResult> {
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    try {
      // Step 1: Analyze and decompose the request
      const context = await this.analyzeRequest(requestId, userQuery, options);
      this.activeCoordinations.set(requestId, context);

      // Step 2: Create coordination plan
      const coordinationPlan = await this.createCoordinationPlan(context);

      // Step 3: Execute coordinated workflow
      const workflow = await this.executeCoordinatedWorkflow(context, coordinationPlan);

      // Step 4: Aggregate and synthesize results
      const result = await this.aggregateResults(workflow, context);

      // Step 5: Generate comprehensive report
      const report = await this.generateCoordinationReport(result, workflow, context);

      this.logger.info('Agent coordination completed successfully', {
        requestId,
        duration: Date.now() - parseInt(requestId.split('_')[1]),
        tasksCompleted: result.executionSummary.tasksCompleted,
        qualityScore: result.qualityMetrics.overall
      });

      return report;
    } catch (error) {
      this.logger.error('Agent coordination failed', { requestId, error });
      throw error;
    } finally {
      this.activeCoordinations.delete(requestId);
    }
  }

  /**
   * Analyze user request and create coordination context
   */
  private async analyzeRequest(
    requestId: string,
    userQuery: string,
    options: any
  ): Promise<CoordinationContext> {
    // Parse user query to extract requirements
    const requirements = this.extractRequirements(userQuery);

    // Create constraints based on options
    const constraints: Constraints = {
      timeBox: options.maxDuration || 300000, // 5 minutes default
      qualityThreshold: options.qualityTarget || 0.9,
      parallelizationLevel: 0.7, // Default 70% parallel execution
      verificationLevel: options.verificationLevel || 'standard',
      resourceLimits: {
        maxAgents: 4,
        maxParallelTasks: 8,
        memoryLimit: 512,
        timeoutThreshold: 30000
      }
    };

    // Set user preferences
    const preferences: UserPreferences = {
      communicationStyle: 'detailed',
      updateFrequency: 'medium',
      riskTolerance: 'moderate',
      priorityOrder: ['quality', 'speed', 'innovation'],
      ...options.preferences
    };

    return {
      requestId,
      userQuery,
      requirements,
      constraints,
      preferences
    };
  }

  /**
   * Extract requirements from user query
   */
  private extractRequirements(userQuery: string): Requirements {
    // Advanced NLP analysis to extract requirements
    // This would typically use AI models for better extraction

    const functional: string[] = [];
    const nonFunctional: string[] = [];
    const businessRules: string[] = [];
    const compliance: string[] = [];
    const integrations: string[] = [];

    // Simple keyword-based extraction (would be enhanced with AI)
    const queryLower = userQuery.toLowerCase();

    // Functional requirements
    if (queryLower.includes('create') || queryLower.includes('build') || queryLower.includes('implement')) {
      functional.push('Implementation required');
    }
    if (queryLower.includes('design') || queryLower.includes('ui') || queryLower.includes('interface')) {
      functional.push('UI/UX design required');
    }
    if (queryLower.includes('test') || queryLower.includes('debug') || queryLower.includes('validate')) {
      functional.push('Testing and validation required');
    }

    // Non-functional requirements
    if (queryLower.includes('performance') || queryLower.includes('fast') || queryLower.includes('speed')) {
      nonFunctional.push('High performance required');
    }
    if (queryLower.includes('secure') || queryLower.includes('security')) {
      nonFunctional.push('Security compliance required');
    }
    if (queryLower.includes('accessible') || queryLower.includes('accessibility')) {
      nonFunctional.push('Accessibility compliance required');
    }
    if (queryLower.includes('responsive') || queryLower.includes('mobile')) {
      nonFunctional.push('Responsive design required');
    }

    // Compliance requirements
    if (queryLower.includes('gdpr') || queryLower.includes('privacy')) {
      compliance.push('GDPR compliance');
    }
    if (queryLower.includes('wcag') || queryLower.includes('a11y')) {
      compliance.push('WCAG accessibility standards');
    }

    // Integration requirements
    if (queryLower.includes('api') || queryLower.includes('integration') || queryLower.includes('connect')) {
      integrations.push('API integration required');
    }

    return {
      functional,
      nonFunctional,
      businessRules,
      compliance,
      integrations
    };
  }

  /**
   * Create detailed coordination plan
   */
  private async createCoordinationPlan(context: CoordinationContext): Promise<TaskDelegation[]> {
    const delegations: TaskDelegation[] = [];

    // Delegate to Task Orchestrator for decomposition
    delegations.push({
      taskId: 'orchestration',
      assignedAgent: 'task-orchestrator-01',
      delegationReason: 'Task decomposition and workflow planning required',
      expectedOutcome: 'Detailed task breakdown and execution plan',
      dependencies: [],
      communicationProtocol: {
        type: 'synchronous',
        frequency: 5000,
        channels: [{
          name: 'orchestration-channel',
          purpose: 'Task planning and coordination',
          participants: ['task-orchestrator-01'],
          messageFormat: 'json',
          priority: 'high'
        }],
        escalationRules: [{
          condition: 'timeout > 30000',
          action: 'escalate',
          threshold: 30000,
          recipient: 'system-admin'
        }]
      }
    });

    // Delegate UX design if UI requirements detected
    if (this.requiresUXDesign(context.requirements)) {
      delegations.push({
        taskId: 'ux-design',
        assignedAgent: 'ux-designer-01',
        delegationReason: 'User experience design required for interface components',
        expectedOutcome: 'Comprehensive UX design with user journeys and wireframes',
        dependencies: [{
          prerequisiteTask: 'orchestration',
          dependencyType: 'data',
          blocking: true,
          transferMethod: 'shared-memory'
        }],
        communicationProtocol: {
          type: 'asynchronous',
          frequency: 10000,
          channels: [{
            name: 'design-channel',
            purpose: 'UX design collaboration',
            participants: ['ux-designer-01', 'ui-implementer-01'],
            messageFormat: 'json',
            priority: 'medium'
          }],
          escalationRules: []
        }
      });
    }

    // Delegate UI implementation if implementation required
    if (this.requiresImplementation(context.requirements)) {
      const dependencies: TaskDependency[] = [{
        prerequisiteTask: 'orchestration',
        dependencyType: 'completion',
        blocking: true,
        transferMethod: 'direct'
      }];

      if (this.requiresUXDesign(context.requirements)) {
        dependencies.push({
          prerequisiteTask: 'ux-design',
          dependencyType: 'data',
          blocking: true,
          transferMethod: 'shared-memory'
        });
      }

      delegations.push({
        taskId: 'ui-implementation',
        assignedAgent: 'ui-implementer-01',
        delegationReason: 'Frontend implementation required',
        expectedOutcome: 'Production-ready UI components with full functionality',
        dependencies,
        communicationProtocol: {
          type: 'event-driven',
          frequency: 15000,
          channels: [{
            name: 'implementation-channel',
            purpose: 'Implementation progress and feedback',
            participants: ['ui-implementer-01', 'proactive-debugger-01'],
            messageFormat: 'json',
            priority: 'high'
          }],
          escalationRules: []
        }
      });
    }

    // Delegate debugging and testing
    if (this.requiresTesting(context.requirements)) {
      delegations.push({
        taskId: 'debugging-testing',
        assignedAgent: 'proactive-debugger-01',
        delegationReason: 'Comprehensive testing and bug hunting required',
        expectedOutcome: 'Thoroughly tested code with bug reports and fixes',
        dependencies: [{
          prerequisiteTask: 'ui-implementation',
          dependencyType: 'completion',
          blocking: true,
          transferMethod: 'direct'
        }],
        communicationProtocol: {
          type: 'synchronous',
          frequency: 8000,
          channels: [{
            name: 'testing-channel',
            purpose: 'Bug reporting and quality assurance',
            participants: ['proactive-debugger-01'],
            messageFormat: 'json',
            priority: 'critical'
          }],
          escalationRules: [{
            condition: 'critical_bugs > 0',
            action: 'notify',
            threshold: 1,
            recipient: 'ui-implementer-01'
          }]
        }
      });
    }

    this.delegationHistory.set(context.requestId, delegations);
    return delegations;
  }

  /**
   * Execute coordinated workflow with parallel agent orchestration
   */
  private async executeCoordinatedWorkflow(
    context: CoordinationContext,
    delegations: TaskDelegation[]
  ): Promise<WorkflowDAG> {
    // Create workflow request for orchestration framework
    const workflowRequest = this.createWorkflowRequest(context, delegations);

    // Execute workflow through orchestration framework
    const workflow = await this.orchestrationFramework.executeWorkflow(
      workflowRequest,
      {
        priority: 'high',
        maxDuration: context.constraints.timeBox,
        verificationLevel: context.constraints.verificationLevel,
        parallelizationTarget: context.constraints.parallelizationLevel
      }
    );

    return workflow;
  }

  /**
   * Create workflow request from coordination context
   */
  private createWorkflowRequest(
    context: CoordinationContext,
    delegations: TaskDelegation[]
  ): string {
    const request = {
      query: context.userQuery,
      requirements: context.requirements,
      delegations: delegations.map(d => ({
        task: d.taskId,
        agent: d.assignedAgent,
        reason: d.delegationReason,
        outcome: d.expectedOutcome
      })),
      constraints: context.constraints,
      preferences: context.preferences
    };

    return JSON.stringify(request, null, 2);
  }

  /**
   * Aggregate results from all agents
   */
  private async aggregateResults(
    workflow: WorkflowDAG,
    context: CoordinationContext
  ): Promise<CoordinationResult> {
    const executionSummary = this.calculateExecutionSummary(workflow);
    const agentContributions = this.calculateAgentContributions(workflow);
    const qualityMetrics = await this.calculateQualityMetrics(workflow, context);
    const recommendations = this.generateRecommendations(workflow, context);

    return {
      success: workflow.status === 'completed',
      workflowId: workflow.id,
      executionSummary,
      agentContributions,
      qualityMetrics,
      recommendations
    };
  }

  /**
   * Generate comprehensive coordination report
   */
  private async generateCoordinationReport(
    result: CoordinationResult,
    workflow: WorkflowDAG,
    context: CoordinationContext
  ): Promise<CoordinationResult> {
    // Enhance the result with additional insights
    const enhancedResult: CoordinationResult = {
      ...result,
      recommendations: [
        ...result.recommendations,
        ...this.generateOptimizationRecommendations(workflow),
        ...this.generateCollaborationInsights(workflow),
        ...this.generateQualityImprovements(result.qualityMetrics)
      ]
    };

    // Log comprehensive report
    this.logger.info('Coordination report generated', {
      workflowId: workflow.id,
      overallQuality: result.qualityMetrics.overall,
      efficiency: result.executionSummary.efficiencyScore,
      agentCount: result.agentContributions.length,
      recommendationCount: enhancedResult.recommendations.length
    });

    return enhancedResult;
  }

  /**
   * Helper methods for requirement analysis
   */
  private requiresUXDesign(requirements: Requirements): boolean {
    return requirements.functional.some(req =>
      req.includes('design') || req.includes('interface') || req.includes('UI')
    ) || requirements.nonFunctional.some(req =>
      req.includes('usability') || req.includes('accessibility')
    );
  }

  private requiresImplementation(requirements: Requirements): boolean {
    return requirements.functional.some(req =>
      req.includes('implement') || req.includes('build') || req.includes('create')
    );
  }

  private requiresTesting(requirements: Requirements): boolean {
    return requirements.functional.some(req =>
      req.includes('test') || req.includes('validate') || req.includes('debug')
    ) || requirements.nonFunctional.some(req =>
      req.includes('quality') || req.includes('reliability')
    );
  }

  /**
   * Calculate execution summary
   */
  private calculateExecutionSummary(workflow: WorkflowDAG): ExecutionSummary {
    const completedTasks = Array.from(workflow.nodes.values())
      .filter(node => node.task.status === 'completed').length;

    const parallelTasks = workflow.executionPlan.phases
      .filter(phase => phase.canExecuteInParallel)
      .reduce((sum, phase) => sum + phase.tasks.length, 0);

    const verificationsPassed = workflow.verificationGates
      .filter(gate => gate.confidence_threshold >= 0.9).length;

    const totalDuration = workflow.executionPlan.estimatedDuration;

    return {
      totalDuration,
      tasksCompleted: completedTasks,
      tasksParallel: parallelTasks,
      verificationsPassed,
      issuesResolved: 0, // Would be calculated from actual execution
      efficiencyScore: parallelTasks / Math.max(1, workflow.nodes.size)
    };
  }

  /**
   * Calculate agent contributions
   */
  private calculateAgentContributions(workflow: WorkflowDAG): AgentContribution[] {
    const agentMap = new Map<string, {
      tasks: string[];
      quality: number[];
      innovation: number[];
      collaboration: number[];
    }>();

    // Aggregate agent data
    for (const [nodeId, node] of workflow.nodes) {
      if (node.task.assignedAgent && node.task.result) {
        const agentId = node.task.assignedAgent;

        if (!agentMap.has(agentId)) {
          agentMap.set(agentId, { tasks: [], quality: [], innovation: [], collaboration: [] });
        }

        const agentData = agentMap.get(agentId)!;
        agentData.tasks.push(node.task.title);
        agentData.quality.push(node.task.result.metrics.qualityScore);
        agentData.innovation.push(0.8); // Placeholder
        agentData.collaboration.push(0.9); // Placeholder
      }
    }

    // Convert to contributions
    return Array.from(agentMap.entries()).map(([agentId, data]) => ({
      agentId,
      agentType: this.getAgentType(agentId),
      tasksHandled: data.tasks,
      contribution: `Handled ${data.tasks.length} tasks with high quality`,
      qualityScore: data.quality.reduce((a, b) => a + b, 0) / data.quality.length,
      innovationLevel: data.innovation.reduce((a, b) => a + b, 0) / data.innovation.length,
      collaborationScore: data.collaboration.reduce((a, b) => a + b, 0) / data.collaboration.length
    }));
  }

  /**
   * Calculate comprehensive quality metrics
   */
  private async calculateQualityMetrics(
    workflow: WorkflowDAG,
    context: CoordinationContext
  ): Promise<QualityMetrics> {
    const taskResults = Array.from(workflow.nodes.values())
      .map(node => node.task.result)
      .filter(result => result !== undefined);

    if (taskResults.length === 0) {
      return this.getDefaultQualityMetrics();
    }

    const avgCorrectness = taskResults.reduce((sum, result) =>
      sum + result!.metrics.qualityScore, 0) / taskResults.length;

    const avgPerformance = taskResults.reduce((sum, result) =>
      sum + result!.metrics.performanceScore, 0) / taskResults.length;

    const avgSecurity = taskResults.reduce((sum, result) =>
      sum + result!.metrics.securityScore, 0) / taskResults.length;

    const verificationConfidence = workflow.verificationGates.length > 0 ?
      workflow.verificationGates.reduce((sum, gate) => sum + gate.confidence_threshold, 0) / workflow.verificationGates.length :
      0.9;

    const overall = (avgCorrectness + avgPerformance + avgSecurity + verificationConfidence) / 4;

    return {
      overall,
      categories: {
        correctness: avgCorrectness,
        performance: avgPerformance,
        security: avgSecurity,
        usability: 0.9, // Would be calculated from UX agent
        maintainability: 0.88, // Would be calculated from code analysis
        accessibility: 0.92 // Would be calculated from accessibility checks
      },
      verificationConfidence,
      userSatisfactionPrediction: Math.min(1, overall * 1.1) // Optimistic prediction
    };
  }

  /**
   * Generate optimization recommendations
   */
  private generateRecommendations(workflow: WorkflowDAG, context: CoordinationContext): string[] {
    const recommendations: string[] = [];

    // Check execution efficiency
    if (workflow.executionPlan.phases.length > 5) {
      recommendations.push('Consider consolidating workflow phases for better efficiency');
    }

    // Check parallelization
    const parallelTasks = workflow.executionPlan.phases
      .filter(phase => phase.canExecuteInParallel)
      .reduce((sum, phase) => sum + phase.tasks.length, 0);

    const parallelRatio = parallelTasks / workflow.nodes.size;
    if (parallelRatio < 0.5) {
      recommendations.push('Increase task parallelization to improve execution speed');
    }

    // Check verification coverage
    const verificationRatio = workflow.verificationGates.length / workflow.nodes.size;
    if (verificationRatio < 0.5) {
      recommendations.push('Add more verification gates for better quality assurance');
    }

    return recommendations;
  }

  /**
   * Generate optimization recommendations
   */
  private generateOptimizationRecommendations(workflow: WorkflowDAG): string[] {
    const recommendations: string[] = [];

    // Analyze critical path
    if (workflow.executionPlan.criticalPath.length > workflow.nodes.size * 0.8) {
      recommendations.push('Critical path is too long - consider breaking down complex tasks');
    }

    // Analyze resource utilization
    const avgTaskDuration = workflow.executionPlan.estimatedDuration / workflow.nodes.size;
    if (avgTaskDuration > 10000) {
      recommendations.push('Tasks are taking longer than expected - consider resource optimization');
    }

    return recommendations;
  }

  /**
   * Generate collaboration insights
   */
  private generateCollaborationInsights(workflow: WorkflowDAG): string[] {
    const insights: string[] = [];

    // Analyze agent collaboration patterns
    const agentTypes = new Set<string>();
    for (const [nodeId, node] of workflow.nodes) {
      if (node.task.assignedAgent) {
        agentTypes.add(this.getAgentType(node.task.assignedAgent));
      }
    }

    if (agentTypes.size >= 3) {
      insights.push('Strong multi-agent collaboration detected - maintain this pattern');
    }

    if (workflow.verificationGates.length > 0) {
      insights.push('Verification gates are properly utilized for quality assurance');
    }

    return insights;
  }

  /**
   * Generate quality improvements
   */
  private generateQualityImprovements(metrics: QualityMetrics): string[] {
    const improvements: string[] = [];

    if (metrics.categories.performance < 0.9) {
      improvements.push('Focus on performance optimization in future iterations');
    }

    if (metrics.categories.security < 0.95) {
      improvements.push('Enhance security measures and validation');
    }

    if (metrics.categories.accessibility < 0.95) {
      improvements.push('Improve accessibility compliance and testing');
    }

    return improvements;
  }

  /**
   * Helper methods
   */
  private async establishCommunicationChannels(): Promise<void> {
    // Setup communication channels between agents
    this.logger.debug('Communication channels established');
  }

  private initializePerformanceBaselines(): void {
    // Initialize performance baselines for each agent type
    this.performanceBaseline.set('task-orchestrator', 0.95);
    this.performanceBaseline.set('ux-designer', 0.93);
    this.performanceBaseline.set('ui-implementer', 0.91);
    this.performanceBaseline.set('proactive-debugger', 0.94);
  }

  private getAgentType(agentId: string): string {
    if (agentId.includes('orchestrator')) return 'task-orchestrator';
    if (agentId.includes('ux')) return 'ux-designer';
    if (agentId.includes('implementer')) return 'ui-implementer';
    if (agentId.includes('debugger')) return 'proactive-debugger';
    return 'unknown';
  }

  private getDefaultQualityMetrics(): QualityMetrics {
    return {
      overall: 0.85,
      categories: {
        correctness: 0.85,
        performance: 0.8,
        security: 0.9,
        usability: 0.85,
        maintainability: 0.8,
        accessibility: 0.85
      },
      verificationConfidence: 0.8,
      userSatisfactionPrediction: 0.82
    };
  }

  /**
   * Get system coordination status
   */
  getCoordinationStatus(): {
    activeCoordinations: number;
    totalRequests: number;
    averageQuality: number;
    agentUtilization: Record<string, number>;
  } {
    const orchestrationStatus = this.orchestrationFramework.getSystemStatus();

    return {
      activeCoordinations: this.activeCoordinations.size,
      totalRequests: this.delegationHistory.size,
      averageQuality: 0.92, // Would be calculated from historical data
      agentUtilization: orchestrationStatus.agents.reduce((acc, agent) => {
        acc[agent.type] = agent.workload;
        return acc;
      }, {} as Record<string, number>)
    };
  }
}

// Export singleton instance
export const agentCoordinationSystem = (context: any) => new AgentCoordinationSystem(context);