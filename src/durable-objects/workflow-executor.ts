/**
 * Ultimate Workflow Executor - Durable Object
 * Handles real-time workflow execution with AI capabilities
 * Supports collaboration, streaming, and advanced orchestration
 */

import type { Env } from '../types/env';
import { getAIClient } from '../services/secure-ai-client';
import { validateInput } from '../utils/validation-schemas';
import { z } from 'zod';

// =====================================================
// TYPES AND INTERFACES
// =====================================================

interface SchemaProperty {
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  required?: boolean;
  description?: string;
  enum?: string[];
  properties?: Record<string, SchemaProperty>;
  items?: SchemaProperty;
}

interface WorkflowSchema {
  type: 'object';
  properties: Record<string, SchemaProperty>;
  required?: string[];
}

interface AIAgentConfig {
  agentId: string;
  model: string;
  temperature: number;
  maxTokens: number;
  systemPrompt?: string;
  tools?: string[];
  streaming?: boolean;
}

interface LogicNodeConfig {
  operation: 'transform' | 'filter' | 'aggregate' | 'calculate';
  expression: string;
  outputMapping: Record<string, string>;
}

interface IntegrationConfig {
  provider: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers?: Record<string, string>;
  authentication?: {
    type: 'bearer' | 'basic' | 'apikey';
    credentials: string;
  };
  mapping?: {
    input: Record<string, string>;
    output: Record<string, string>;
  };
}

interface ApprovalConfig {
  approvers: string[];
  requiredApprovals: number;
  timeoutHours: number;
  escalationRules?: {
    timeoutAction: 'approve' | 'reject' | 'escalate';
    escalateTo?: string[];
  };
}

interface TriggerConfig {
  type: 'webhook' | 'schedule' | 'event';
  webhook?: {
    path: string;
    method: string;
    authentication?: boolean;
  };
  schedule?: {
    cron: string;
    timezone: string;
  };
  event?: {
    source: string;
    eventType: string;
    filters?: Record<string, any>;
  };
}

type NodeConfig = AIAgentConfig | LogicNodeConfig | IntegrationConfig | ApprovalConfig | TriggerConfig;

interface ConditionConfig {
  operator: 'equals' | 'not_equals' | 'greater_than' | 'less_than' | 'contains' | 'exists';
  field: string;
  value: any;
  logic?: 'and' | 'or';
  conditions?: ConditionConfig[];
}

interface ExecutionNode {
  id: string;
  nodeKey: string;
  type: 'ai_agent' | 'logic' | 'integration' | 'approval' | 'trigger';
  subtype: string;
  config: NodeConfig;
  position: { x: number; y: number };
  inputSchema?: WorkflowSchema;
  outputSchema?: WorkflowSchema;
  retryEnabled: boolean;
  maxRetries: number;
  timeoutSeconds: number;
  dependsOn: string[];
  parallelGroup?: string;
}

interface ExecutionEdge {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  sourceHandle?: string;
  targetHandle?: string;
  conditionType: 'always' | 'success' | 'failure' | 'conditional';
  conditionExpression?: string;
  conditionConfig?: ConditionConfig;
}

interface WorkflowDefinition {
  id: string;
  businessId: string;
  name: string;
  version: string;
  nodes: ExecutionNode[];
  edges: ExecutionEdge[];
  executionMode: 'sequential' | 'parallel' | 'adaptive';
  maxParallelNodes: number;
  timeoutSeconds: number;
  retryPolicy: {
    maxRetries: number;
    backoffStrategy: 'linear' | 'exponential' | 'fixed';
    conditions: string[];
  };
}

interface WorkflowInputData {
  [key: string]: string | number | boolean | object | null;
}

interface WorkflowOutputData {
  [key: string]: string | number | boolean | object | null;
}

interface ExecutionContext {
  workflowId: string;
  executionId: string;
  businessId: string;
  triggeredBy: string;
  inputData: WorkflowInputData;
  variables: Record<string, string | number | boolean>;
  metadata: Record<string, string | number | boolean>;
}

interface NodeExecutionResult {
  nodeId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  inputData?: WorkflowInputData;
  outputData?: WorkflowOutputData;
  executionTimeMs: number;
  costCents: number;
  tokensUsed?: number;
  modelUsed?: string;
  confidenceScore?: number;
  errorMessage?: string;
  errorDetails?: {
    code?: string;
    details?: Record<string, any>;
    stack?: string;
  };
  retryCount: number;
  startedAt: string;
  completedAt?: string;
}

interface ExecutionUpdate {
  type: 'node_started' | 'node_completed' |
  'node_failed' | 'workflow_completed' | 'workflow_failed' | 'progress_update' |
  'execution_paused' | 'execution_resumed' | 'execution_cancelled' | 'node_retry';
  executionId: string;
  nodeId?: string;
  status: string;
  data?: WorkflowOutputData;
  progress: number;
  timestamp: string;
}

// =====================================================
// DURABLE OBJECT IMPLEMENTATION
// =====================================================

export class WorkflowExecutor {
  private state: DurableObjectState;
  private env: Env;
  private websockets: Set<WebSocket> = new Set();
  private executionGraph: Map<string, ExecutionNode> = new Map();
  private nodeResults: Map<string, NodeExecutionResult> = new Map();
  private executionQueue: string[] = [];
  private runningNodes: Set<string> = new Set();
  private parallelGroups: Map<string, Set<string>> = new Map();
  private circuitBreakers: Map<string, CircuitBreaker> = new Map();
  private executions: Map<string, any> = new Map();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case '/execute':
          return this.handleExecuteWorkflow(request);
        case '/status':
          return this.handleGetStatus(request);
        case '/pause':
          return this.handlePauseExecution(request);
        case '/resume':
          return this.handleResumeExecution(request);
        case '/cancel':
          return this.handleCancelExecution(request);
        case '/websocket':
          return this.handleWebSocket(request);
        case '/retry-node':
          return this.handleRetryNode(request);
        default:
          return new Response('Not found', { status: 404 });
      }
    } catch (error) {
      return new Response('Internal error', { status: 500 });
    }
  }

  // =====================================================
  // MAIN EXECUTION ENGINE
  // =====================================================

  private async handleExecuteWorkflow(request: Request): Promise<Response> {
    const { workflowDefinition, context } = await request.json() as {
      workflowDefinition: WorkflowDefinition;
      context: ExecutionContext;
    };


    // Initialize execution state
    await this.initializeExecution(workflowDefinition, context);

    // Start execution asynchronously
    this.executeWorkflowAsync(workflowDefinition, context).catch(error => {
      this.broadcastUpdate({
        type: 'workflow_failed',
        executionId: context.executionId,
        status: 'failed',
        data: { error: error.message },
        progress: 0,
        timestamp: new Date().toISOString()
      });
    });

    return new Response(JSON.stringify({
      success: true,
      executionId: context.executionId,
      status: 'started'
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  private async executeWorkflowAsync(
    workflow: WorkflowDefinition,
    context: ExecutionContext
  ): Promise<void> {
    const startTime = Date.now();

    try {
      // Parse workflow into execution graph
      this.buildExecutionGraph(workflow);

      // Validate workflow for logical errors
      await this.validateWorkflow(workflow);

      // Calculate optimal execution plan
      const executionPlan = await this.createExecutionPlan(workflow);

      // Execute workflow based on mode
      let result;
      switch (workflow.executionMode) {
        case 'sequential':
          result = await this.executeSequential(executionPlan, context);
          break;
        case 'parallel':
          result = await this.executeParallel(executionPlan, context);
          break;
        case 'adaptive':
          result = await this.executeAdaptive(executionPlan, context);
          break;
        default:
          throw new Error(`Unknown execution mode: ${workflow.executionMode}`);
      }

      // Calculate final metrics
      const executionTime = Date.now() - startTime;
      const totalCost = Array.from(this.nodeResults.values())
        .reduce((sum, result) => sum + result.costCents, 0);

      // Save execution results to database
      await this.saveExecutionResults(context, {
        status: 'completed',
        executionTimeMs: executionTime,
        costCents: totalCost,
        outputData: result,
        completedAt: new Date().toISOString()
      });

      // Broadcast completion
      this.broadcastUpdate({
        type: 'workflow_completed',
        executionId: context.executionId,
        status: 'completed',
        data: result,
        progress: 100,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      await this.saveExecutionResults(context, {
        status: 'failed',
        executionTimeMs: Date.now() - startTime,
        errorMessage,
        errorDetails: { stack: errorStack },
        completedAt: new Date().toISOString()
      });

      this.broadcastUpdate({
        type: 'workflow_failed',
        executionId: context.executionId,
        status: 'failed',
        data: { error: errorMessage },
        progress: 0,
        timestamp: new Date().toISOString()
      });
    }
  }

  // =====================================================
  // EXECUTION STRATEGIES
  // =====================================================

  private async executeSequential(
    executionPlan: string[],
    context: ExecutionContext
  ): Promise<any> {
    const results: Record<string, any> = {};

    for (const nodeId of executionPlan) {
      const node = this.executionGraph.get(nodeId);
      if (!node) continue;

      // Check dependencies
      if (!this.areDependenciesMet(node, results)) {
        continue;
      }

      // Execute node
      const result = await this.executeNode(node, context, results);
      results[nodeId] = result.outputData;

      // Update progress
      const progress = (Object.keys(results).length / executionPlan.length) * 100;
      this.broadcastUpdate({
        type: 'progress_update',
        executionId: context.executionId,
        status: 'running',
        progress,
        timestamp: new Date().toISOString()
      });
    }

    return results;
  }

  private async executeParallel(
    executionPlan: string[],
    context: ExecutionContext
  ): Promise<any> {
    const maxConcurrency = Math.min(
      this.executionGraph.size,
      Number(context.metadata.maxParallelNodes) || 5
    );

    const semaphore = new Semaphore(maxConcurrency);
    const promises: Promise<any>[] = [];
    const results: Record<string, any> = {};

    for (const nodeId of executionPlan) {
      const node = this.executionGraph.get(nodeId);
      if (!node) continue;

      const promise = semaphore.acquire().then(async (release) => {
        try {
          // Wait for dependencies
          await this.waitForDependencies(node, results);

          // Execute node
          const result = await this.executeNode(node, context, results);
          results[nodeId] = result.outputData;

          return result;
        } finally {
          release();
        }
      });

      promises.push(promise);
    }

    await Promise.all(promises);
    return results;
  }

  private async executeAdaptive(
    executionPlan: string[],
    context: ExecutionContext
  ): Promise<any> {
    // AI-powered adaptive execution that adjusts strategy based on:
    // - Node execution times
    // - Resource availability
    // - Cost constraints
    // - Historical patterns

    const aiClient = getAIClient(this.env);
    const executionMetrics = await this.gatherExecutionMetrics();

    const adaptationPrompt = `
      Analyze this workflow execution plan and recommend the optimal execution strategy:

      Execution Plan: ${JSON.stringify(executionPlan)}
      Historical Metrics: ${JSON.stringify(executionMetrics)}
      Available Resources: ${JSON.stringify({
        maxParallelNodes: context.metadata.maxParallelNodes,
        budgetCents: context.metadata.budgetCents,
        timeoutSeconds: context.metadata.timeoutSeconds
      })}

      Consider:
      1. Node dependencies and critical path
      2. Resource consumption patterns
      3. Cost optimization opportunities
      4. Failure probability and recovery strategies

      Return JSON:
      {
        "strategy": "sequential|parallel|hybrid",
        "parallelGroups": [["node1", "node2"], ["node3"]],
        "priorityOrder": ["high_priority_node", ...],
        "resourceAllocation": {"node1": {"cpu": 0.5, "memory": "512MB"}},
        "costOptimizations": ["suggestion1", "suggestion2"],
        "riskMitigation": ["strategy1", "strategy2"]
      }
    `;

    const adaptation = await aiClient.parseJSONResponse(adaptationPrompt);

    // Apply AI recommendations
    return await this.executeWithAdaptation(executionPlan, context, adaptation);
  }

  // =====================================================
  // NODE EXECUTION
  // =====================================================

  private async executeNode(
    node: ExecutionNode,
    context: ExecutionContext,
    availableData: Record<string, any>
  ): Promise<NodeExecutionResult> {
    const nodeResult: NodeExecutionResult = {
      nodeId: node.id,
      status: 'running',
      executionTimeMs: 0,
      costCents: 0,
      retryCount: 0,
      startedAt: new Date().toISOString()
    };

    // Store result for tracking
    this.nodeResults.set(node.id, nodeResult);
    this.runningNodes.add(node.id);

    // Broadcast node start
    this.broadcastUpdate({
      type: 'node_started',
      executionId: context.executionId,
      nodeId: node.id,
      status: 'running',
      timestamp: new Date().toISOString(),
      progress: this.calculateProgress()
    });

    const startTime = Date.now();

    try {
      // Prepare input data
      const inputData = this.prepareNodeInput(node, availableData, context);

      // Validate input against schema
      if (node.inputSchema) {
        validateInput(z.object(node.inputSchema.properties as any), inputData);
      }

      // Execute based on node type
      let outputData;
      switch (node.type) {
        case 'ai_agent':
          outputData = await this.executeAIAgentNode(node, inputData, context);
          break;
        case 'logic':
          outputData = await this.executeLogicNode(node, inputData, context);
          break;
        case 'integration':
          outputData = await this.executeIntegrationNode(node, inputData, context);
          break;
        case 'approval':
          outputData = await this.executeApprovalNode(node, inputData, context);
          break;
        case 'trigger':
          outputData = await this.executeTriggerNode(node, inputData, context);
          break;
        default:
          throw new Error(`Unknown node type: ${node.type}`);
      }

      // Validate output against schema
      if (node.outputSchema) {
        validateInput(z.object(node.outputSchema.properties as any), outputData);
      }

      // Update result
      nodeResult.status = 'completed';
      nodeResult.outputData = outputData;
      nodeResult.inputData = inputData;
      nodeResult.executionTimeMs = Date.now() - startTime;
      nodeResult.completedAt = new Date().toISOString();

      // Broadcast node completion
      this.broadcastUpdate({
        type: 'node_completed',
        executionId: context.executionId,
        nodeId: node.id,
        status: 'completed',
        data: outputData,
        timestamp: new Date().toISOString(),
        progress: this.calculateProgress()
      });

      return nodeResult;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;
      
      nodeResult.status = 'failed';
      nodeResult.errorMessage = errorMessage;
      nodeResult.errorDetails = { stack: errorStack };
      nodeResult.executionTimeMs = Date.now() - startTime;
      nodeResult.completedAt = new Date().toISOString();

      // Handle retries
      if (node.retryEnabled && nodeResult.retryCount < node.maxRetries) {
        await this.scheduleNodeRetry(node, context, nodeResult);
        return nodeResult;
      }

      // Broadcast node failure
      this.broadcastUpdate({
        type: 'node_failed',
        executionId: context.executionId,
        nodeId: node.id,
        status: 'failed',
        data: { error: errorMessage },
        timestamp: new Date().toISOString(),
        progress: this.calculateProgress()
      });

      throw error;
    } finally {
      this.runningNodes.delete(node.id);
      this.nodeResults.set(node.id, nodeResult);
    }
  }

  // =====================================================
  // NODE TYPE IMPLEMENTATIONS
  // =====================================================

  private async executeAIAgentNode(
    node: ExecutionNode,
    inputData: WorkflowInputData,
    context: ExecutionContext
  ): Promise<WorkflowOutputData> {
    const config = node.config;
    const aiClient = getAIClient(this.env);

    // Prepare AI prompt with context injection
    const prompt = this.injectVariables((config as any).prompt || '', {
      ...inputData,
      ...context.variables,
      businessContext: context.metadata.businessContext
    });

    const systemPrompt = (config as any).systemPrompt ?
      this.injectVariables((config as any).systemPrompt, context.variables) :
      undefined;

    // Execute AI call with node-specific settings
    const response = await aiClient.callAI({
      prompt,
      systemPrompt,
      model: (config as any).model || 'claude-3-haiku-20240307',
      temperature: (config as any).temperature || 0.7,
      maxTokens: (config as any).maxTokens || 2000
    });

    // Update metrics
    const nodeResult = this.nodeResults.get(node.id)!;
    nodeResult.modelUsed = (config as any).model || 'claude-3-haiku-20240307';
    nodeResult.tokensUsed = this.estimateTokens(prompt + response);
    nodeResult.costCents = this.calculateAICost(nodeResult.tokensUsed, (config as any).model);
    nodeResult.confidenceScore = 0.85; // Would be calculated based on response quality

    return {
      response,
      metadata: {
        model: nodeResult.modelUsed,
        tokens: nodeResult.tokensUsed,
        cost: nodeResult.costCents
      }
    };
  }

  private async executeLogicNode(
    node: ExecutionNode,
    inputData: WorkflowInputData,
    context: ExecutionContext
  ): Promise<WorkflowOutputData> {
    const config = node.config;

    switch (node.subtype) {
      case 'condition':
        return this.evaluateCondition((config as any).expression, inputData, context);

      case 'loop':
        return this.executeLoop(config, inputData, context);

      case 'transform':
        return this.transformData((config as any).transformation, inputData);

      case 'delay':
        await this.sleep((config as any).delayMs || 1000);
        return { delayed: true };

      case 'parallel_gate':
        return this.executeParallelGate(config, inputData, context);

      default:
        throw new Error(`Unknown logic node subtype: ${node.subtype}`);
    }
  }

  private async executeIntegrationNode(
    node: ExecutionNode,
    inputData: WorkflowInputData,
    context: ExecutionContext
  ): Promise<WorkflowOutputData> {
    const config = node.config;

    // Get circuit breaker for this integration
    const circuitBreaker = this.getCircuitBreaker(node.id);

    return await circuitBreaker.execute(async () => {
      switch (node.subtype) {
        case 'http_request':
          return this.executeHttpRequest(config, inputData);

        case 'database_query':
          return this.executeDatabaseQuery(config, inputData, context);

        case 'file_operation':
          return this.executeFileOperation(config, inputData);

        case 'email':
          return this.sendEmail(config, inputData, context);

        case 'slack':
          return this.sendSlackMessage(config, inputData);

        case 'webhook':
          return this.sendWebhook(config, inputData);

        default:
          throw new Error(`Unknown integration subtype: ${node.subtype}`);
      }
    });
  }

  private async executeApprovalNode(
    node: ExecutionNode,
    inputData: WorkflowInputData,
    context: ExecutionContext
  ): Promise<WorkflowOutputData> {
    const config = node.config;

    // Create approval chain in database
    const approvalChain = await this.createApprovalChain(node, context, inputData);

    // Send approval requests
    await this.sendApprovalRequests(approvalChain, config);

    // For now, return pending status
    // In real implementation, this would wait for approvals
    return {
      approvalChainId: approvalChain.id,
      status: 'pending',
      requiredApprovals: (config as any).requiredApprovals,
      escalationHours: (config as any).escalationHours
    };
  }

  private async executeTriggerNode(
    node: ExecutionNode,
    inputData: WorkflowInputData,
    context: ExecutionContext
  ): Promise<WorkflowOutputData> {
    const config = node.config;

    switch (node.subtype) {
      case 'webhook_trigger':
        return this.setupWebhookTrigger(config, context);

      case 'schedule_trigger':
        return this.setupScheduleTrigger(config, context);

      case 'event_trigger':
        return this.setupEventTrigger(config, context);

      default:
        throw new Error(`Unknown trigger subtype: ${node.subtype}`);
    }
  }

  // =====================================================
  // UTILITY METHODS
  // =====================================================

  private buildExecutionGraph(workflow: WorkflowDefinition): void {
    this.executionGraph.clear();

    for (const node of workflow.nodes) {
      this.executionGraph.set(node.id, node);
    }

    // Build parallel groups
    this.parallelGroups.clear();
    for (const node of workflow.nodes) {
      if (node.parallelGroup) {
        if (!this.parallelGroups.has(node.parallelGroup)) {
          this.parallelGroups.set(node.parallelGroup, new Set());
        }
        this.parallelGroups.get(node.parallelGroup)!.add(node.id);
      }
    }
  }

  private async createExecutionPlan(workflow: WorkflowDefinition): Promise<string[]> {
    // Topological sort of nodes based on dependencies
    const visited = new Set<string>();
    const visiting = new Set<string>();
    const plan: string[] = [];

    const visit = (nodeId: string) => {
      if (visiting.has(nodeId)) {
        throw new Error(`Circular dependency detected involving node: ${nodeId}`);
      }
      if (visited.has(nodeId)) {
        return;
      }

      visiting.add(nodeId);

      const node = this.executionGraph.get(nodeId);
      if (node) {
        for (const depId of node.dependsOn) {
          visit(depId);
        }
      }

      visiting.delete(nodeId);
      visited.add(nodeId);
      plan.push(nodeId);
    };

    for (const node of workflow.nodes) {
      if (!visited.has(node.id)) {
        visit(node.id);
      }
    }

    return plan;
  }

  private areDependenciesMet(node: ExecutionNode, results: Record<string, any>): boolean {
    return node.dependsOn.every(depId => results.hasOwnProperty(depId));
  }

  private async waitForDependencies(node: ExecutionNode, results: Record<string, any>): Promise<void> {
    while (!this.areDependenciesMet(node, results)) {
      await this.sleep(100); // Check every 100ms
    }
  }

  private prepareNodeInput(
    node: ExecutionNode,
    availableData: Record<string, WorkflowOutputData>,
    context: ExecutionContext
  ): WorkflowInputData {
    const input: WorkflowInputData = {
      nodeId: node.id,
      nodeType: node.type,
      businessId: context.businessId,
      workflowId: context.workflowId,
      executionId: context.executionId
    };

    // Add dependency outputs
    for (const depId of node.dependsOn) {
      if (availableData[depId]) {
        input[`dep_${depId}`] = availableData[depId];
      }
    }

    // Add workflow variables
    Object.assign(input, context.variables);

    // Add node-specific configuration
    Object.assign(input, (node.config as any).inputMapping || {});

    return input;
  }

  private injectVariables(template: string, variables: Record<string, any>): string {
    return template.replace(/\{\{(\w+)\}\}/g, (match, varName) => {
      return variables[varName] || match;
    });
  }

  private estimateTokens(text: string): number {
    // Rough estimation: 1 token ≈ 4 characters
    return Math.ceil(text.length / 4);
  }

  private calculateAICost(tokens: number, model: string): number {
    // Cost calculation based on model and tokens
    const costPerToken = {
      'claude-3-haiku-20240307': 0.00025, // $0.25 per 1K tokens
      'claude-3-sonnet-20240229': 0.003,  // $3 per 1K tokens
      'gpt-4': 0.03,                      // $30 per 1K tokens
      'gpt-3.5-turbo': 0.002             // $2 per 1K tokens
    };

    const rate = costPerToken[model as keyof typeof costPerToken] || 0.001;
    return Math.ceil(tokens * rate * 100); // Convert to cents
  }

  private calculateProgress(): number {
    const totalNodes = this.executionGraph.size;
    const completedNodes = Array.from(this.nodeResults.values())
      .filter(result => result.status === 'completed').length;

    return totalNodes > 0 ? (completedNodes / totalNodes) * 100 : 0;
  }

  private getCircuitBreaker(nodeId: string): CircuitBreaker {
    if (!this.circuitBreakers.has(nodeId)) {
      this.circuitBreakers.set(nodeId, new CircuitBreaker({
        threshold: 5,
        timeout: 30000,
        resetTimeout: 60000
      }));
    }
    return this.circuitBreakers.get(nodeId)!;
  }

  private async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private broadcastUpdate(update: ExecutionUpdate): void {
    const message = JSON.stringify(update);
    this.websockets.forEach(ws => {
      try {
        ws.send(message);
      } catch (error) {
      }
    });
  }

  // WebSocket handling
  private async handleWebSocket(request: Request): Promise<Response> {
    const { 0: client, 1: server } = new WebSocketPair();

    server.accept();
    this.websockets.add(server);

    server.addEventListener('close', () => {
      this.websockets.delete(server);
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  private async handleGetStatus(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const executionId = url.searchParams.get('executionId');
    
    if (!executionId) {
      return new Response(JSON.stringify({ error: 'Missing executionId' }), { status: 400 });
    }

    const execution = this.executions.get(executionId);
    if (!execution) {
      return new Response(JSON.stringify({ error: 'Execution not found' }), { status: 404 });
    }

    return new Response(JSON.stringify({
      executionId,
      status: execution.status,
      progress: execution.progress,
      currentNode: execution.currentNode,
      startedAt: execution.startedAt,
      completedAt: execution.completedAt,
      error: execution.error
    }));
  }

  private async handlePauseExecution(request: Request): Promise<Response> {
    const { executionId } = await request.json() as any;
    
    if (!executionId) {
      return new Response(JSON.stringify({ error: 'Missing executionId' }), { status: 400 });
    }

    const execution = this.executions.get(executionId);
    if (!execution) {
      return new Response(JSON.stringify({ error: 'Execution not found' }), { status: 404 });
    }

    if (execution.status === 'running') {
      execution.status = 'paused';
      execution.pausedAt = new Date().toISOString();
      
      this.broadcastUpdate({
        type: 'execution_paused',
        executionId,
        status: 'paused',
        timestamp: new Date().toISOString(),
        progress: this.calculateProgress()
      });
    }

    return new Response(JSON.stringify({ success: true, status: execution.status }));
  }

  private async handleResumeExecution(request: Request): Promise<Response> {
    const { executionId } = await request.json() as any;
    
    if (!executionId) {
      return new Response(JSON.stringify({ error: 'Missing executionId' }), { status: 400 });
    }

    const execution = this.executions.get(executionId);
    if (!execution) {
      return new Response(JSON.stringify({ error: 'Execution not found' }), { status: 404 });
    }

    if (execution.status === 'paused') {
      execution.status = 'running';
      execution.resumedAt = new Date().toISOString();
      
      this.broadcastUpdate({
        type: 'execution_resumed',
        executionId,
        status: 'running',
        timestamp: new Date().toISOString(),
        progress: this.calculateProgress()
      });
    }

    return new Response(JSON.stringify({ success: true, status: execution.status }));
  }

  private async handleCancelExecution(request: Request): Promise<Response> {
    const { executionId } = await request.json() as any;
    
    if (!executionId) {
      return new Response(JSON.stringify({ error: 'Missing executionId' }), { status: 400 });
    }

    const execution = this.executions.get(executionId);
    if (!execution) {
      return new Response(JSON.stringify({ error: 'Execution not found' }), { status: 404 });
    }

    execution.status = 'cancelled';
    execution.cancelledAt = new Date().toISOString();
    
    this.broadcastUpdate({
      type: 'execution_cancelled',
      executionId,
      status: 'cancelled',
      timestamp: new Date().toISOString(),
      progress: this.calculateProgress()
    });

    return new Response(JSON.stringify({ success: true, status: execution.status }));
  }

  private async handleRetryNode(request: Request): Promise<Response> {
    const { executionId, nodeId } = await request.json() as any;
    
    if (!executionId || !nodeId) {
      return new Response(JSON.stringify({ error: 'Missing executionId or nodeId' }), { status: 400 });
    }

    const execution = this.executions.get(executionId);
    if (!execution) {
      return new Response(JSON.stringify({ error: 'Execution not found' }), { status: 404 });
    }

    const node = this.executionGraph.get(nodeId);
    if (!node) {
      return new Response(JSON.stringify({ error: 'Node not found' }), { status: 404 });
    }

    // Reset node result and retry
    const nodeResult = this.nodeResults.get(nodeId);
    if (nodeResult) {
      nodeResult.status = 'pending';
      nodeResult.retryCount++;
      nodeResult.errorMessage = undefined;
      nodeResult.errorDetails = undefined;
    }

    this.broadcastUpdate({
      type: 'node_retry',
      executionId,
      nodeId,
      status: 'retrying',
      timestamp: new Date().toISOString(),
      progress: this.calculateProgress()
    });

    return new Response(JSON.stringify({ success: true }));
  }

  private async initializeExecution(workflow: WorkflowDefinition, context: ExecutionContext): Promise<void> {
    const execution = {
      id: context.executionId,
      workflowId: context.workflowId,
      businessId: context.businessId,
      status: 'running',
      progress: 0,
      currentNode: null,
      startedAt: new Date().toISOString(),
      completedAt: null,
      error: null,
      pausedAt: null,
      resumedAt: null,
      cancelledAt: null
    };

    this.executions.set(context.executionId, execution);
  }

  private async saveExecutionResults(context: ExecutionContext, results: any): Promise<void> {
    const db = this.env.DB_CRM;
    
    await db.prepare(`
      INSERT OR REPLACE INTO workflow_executions (
        id, workflow_id, business_id, status, execution_time_ms,
        cost_cents, output_data, error_message, error_details,
        started_at, completed_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      context.executionId,
      context.workflowId,
      context.businessId,
      results.status,
      results.executionTimeMs,
      results.costCents,
      JSON.stringify(results.outputData),
      results.errorMessage,
      JSON.stringify(results.errorDetails),
      results.startedAt,
      results.completedAt,
      new Date().toISOString(),
      new Date().toISOString()
    ).run();
  }

  private async validateWorkflow(workflow: WorkflowDefinition): Promise<void> {
    // Validate workflow structure
    if (!workflow.nodes || workflow.nodes.length === 0) {
      throw new Error('Workflow must have at least one node');
    }

    // Check for circular dependencies
    const visited = new Set<string>();
    const visiting = new Set<string>();

    const visit = (nodeId: string) => {
      if (visiting.has(nodeId)) {
        throw new Error(`Circular dependency detected involving node: ${nodeId}`);
      }
      if (visited.has(nodeId)) {
        return;
      }

      visiting.add(nodeId);
      const node = workflow.nodes.find(n => n.id === nodeId);
      if (node) {
        for (const depId of node.dependsOn) {
          visit(depId);
        }
      }
      visiting.delete(nodeId);
      visited.add(nodeId);
    };

    for (const node of workflow.nodes) {
      if (!visited.has(node.id)) {
        visit(node.id);
      }
    }
  }

  private async gatherExecutionMetrics(): Promise<any> {
    // Gather historical execution metrics for AI adaptation
    const db = this.env.DB_CRM;
    
    const metrics = await db.prepare(`
      SELECT 
        AVG(execution_time_ms) as avg_execution_time,
        AVG(cost_cents) as avg_cost,
        COUNT(*) as total_executions,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful_executions
      FROM workflow_executions
      WHERE created_at > datetime('now', '-30 days')
    `).first();

    return metrics;
  }

  private async executeWithAdaptation(executionPlan: string[], context: ExecutionContext, adaptation: any): Promise<any> {
    // Execute workflow with AI-optimized strategy
    if (adaptation.strategy === 'sequential') {
      return this.executeSequential(executionPlan, context);
    } else if (adaptation.strategy === 'parallel') {
      return this.executeParallel(executionPlan, context);
    } else {
      // Hybrid execution based on AI recommendations
      return this.executeHybrid(executionPlan, context, adaptation);
    }
  }

  private async executeHybrid(executionPlan: string[], context: ExecutionContext, adaptation: any): Promise<any> {
    // Implement hybrid execution strategy
    const results: Record<string, any> = {};
    
    // Execute parallel groups first
    for (const group of adaptation.parallelGroups || []) {
      const groupPromises = group.map(async (nodeId: string) => {
        const node = this.executionGraph.get(nodeId);
        if (node && this.areDependenciesMet(node, results)) {
          const result = await this.executeNode(node, context, results);
          results[nodeId] = result.outputData;
          return result;
        }
        return null;
      });
      
      await Promise.all(groupPromises);
    }

    // Execute remaining nodes sequentially
    for (const nodeId of executionPlan) {
      if (!results[nodeId]) {
        const node = this.executionGraph.get(nodeId);
        if (node && this.areDependenciesMet(node, results)) {
          const result = await this.executeNode(node, context, results);
          results[nodeId] = result.outputData;
        }
      }
    }

    return results;
  }

  private async scheduleNodeRetry(node: ExecutionNode, context: ExecutionContext, nodeResult: NodeExecutionResult): Promise<void> {
    // Schedule node retry with exponential backoff
    const delay = Math.min(1000 * Math.pow(2, nodeResult.retryCount), 30000);
    
    setTimeout(async () => {
      try {
        const result = await this.executeNode(node, context, {});
        this.nodeResults.set(node.id, result);
      } catch (error) {
        // Handle retry failure
        const errorMessage = error instanceof Error ? error.message : String(error);
        nodeResult.status = 'failed';
        nodeResult.errorMessage = errorMessage;
        this.nodeResults.set(node.id, nodeResult);
      }
    }, delay);
  }

  private async createApprovalChain(node: ExecutionNode, context: ExecutionContext, inputData: WorkflowInputData): Promise<any> {
    const db = this.env.DB_CRM;
    
    const approvalChain = {
      id: `approval_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      workflowId: context.workflowId,
      executionId: context.executionId,
      nodeId: node.id,
      status: 'pending',
      createdAt: new Date().toISOString()
    };

    await db.prepare(`
      INSERT INTO approval_chains (
        id, workflow_id, execution_id, node_id, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      approvalChain.id,
      approvalChain.workflowId,
      approvalChain.executionId,
      approvalChain.nodeId,
      approvalChain.status,
      approvalChain.createdAt
    ).run();

    return approvalChain;
  }

  private async sendApprovalRequests(approvalChain: any, config: any): Promise<void> {
    // Send approval requests to designated approvers
    // This would integrate with notification systems
    console.log(`Sending approval requests for chain ${approvalChain.id} to ${config.approvers.join(', ')}`);
  }

  private async executeHttpRequest(config: any, inputData: WorkflowInputData): Promise<WorkflowOutputData> {
    // Execute HTTP request integration
    const response = await fetch(config.endpoint, {
      method: config.method,
      headers: config.headers,
      body: config.method !== 'GET' ? JSON.stringify(inputData) : undefined
    });

    return await response.json();
  }

  private async executeDatabaseQuery(config: any, inputData: WorkflowInputData, context: ExecutionContext): Promise<WorkflowOutputData> {
    // Execute database query integration
    const db = this.env.DB_CRM;
    const result = await db.prepare(config.query).bind(...Object.values(inputData)).all();
    return { results: result.results };
  }

  private async executeFileOperation(config: any, inputData: WorkflowInputData): Promise<WorkflowOutputData> {
    // Execute file operation integration
    // This would integrate with R2 or other storage systems
    return { success: true, operation: config.operation };
  }

  private async sendEmail(config: any, inputData: WorkflowInputData, context: ExecutionContext): Promise<WorkflowOutputData> {
    // Send email integration
    // This would integrate with email services
    return { success: true, messageId: `email_${Date.now()}` };
  }

  private async sendSlackMessage(config: any, inputData: WorkflowInputData): Promise<WorkflowOutputData> {
    // Send Slack message integration
    // This would integrate with Slack API
    return { success: true, messageId: `slack_${Date.now()}` };
  }

  private async sendWebhook(config: any, inputData: WorkflowInputData): Promise<WorkflowOutputData> {
    // Send webhook integration
    const response = await fetch(config.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(inputData)
    });

    return await response.json();
  }

  private async setupWebhookTrigger(config: any, context: ExecutionContext): Promise<WorkflowOutputData> {
    // Setup webhook trigger
    return { webhookUrl: `${config.baseUrl}/webhook/${context.executionId}`, status: 'active' };
  }

  private async setupScheduleTrigger(config: any, context: ExecutionContext): Promise<WorkflowOutputData> {
    // Setup schedule trigger
    return { schedule: config.schedule, status: 'active' };
  }

  private async setupEventTrigger(config: any, context: ExecutionContext): Promise<WorkflowOutputData> {
    // Setup event trigger
    return { eventSource: config.source, eventType: config.eventType, status: 'active' };
  }

  private evaluateCondition(expression: string, inputData: WorkflowInputData, context: ExecutionContext): WorkflowOutputData {
    // Evaluate condition expression
    // This would use a safe expression evaluator
    try {
      const result = eval(expression); // In production, use a safe expression evaluator
      return { conditionResult: result };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return { conditionResult: false, error: errorMessage };
    }
  }

  private async executeLoop(config: any, inputData: WorkflowInputData, context: ExecutionContext): Promise<WorkflowOutputData> {
    // Execute loop logic
    const results = [];
    for (let i = 0; i < config.maxIterations; i++) {
      results.push({ iteration: i, data: inputData });
    }
    return { loopResults: results };
  }

  private transformData(transformation: any, inputData: WorkflowInputData): WorkflowOutputData {
    // Transform data based on configuration
    return { transformedData: inputData, transformation };
  }

  private async executeParallelGate(config: any, inputData: WorkflowInputData, context: ExecutionContext): Promise<WorkflowOutputData> {
    // Execute parallel gate logic
    return { gateResult: true, inputData };
  }

  // Additional helper methods would continue here...
  // This includes status management, pause/resume, cancellation, etc.
}

// =====================================================
// HELPER CLASSES
// =====================================================

class CircuitBreaker {
  private failures = 0;
  private lastFailureTime = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';

  constructor(private options: {
    threshold: number;
    timeout: number;
    resetTimeout: number;
  }) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime > this.options.timeout) {
        this.state = 'HALF_OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess() {
    this.failures = 0;
    this.state = 'CLOSED';
  }

  private onFailure() {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.options.threshold) {
      this.state = 'OPEN';
    }
  }
}

class Semaphore {
  private permits: number;
  private queue: Array<() => void> = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<() => void> {
    return new Promise((resolve) => {
      if (this.permits > 0) {
        this.permits--;
        resolve(() => this.release());
      } else {
        this.queue.push(() => {
          this.permits--;
          resolve(() => this.release());
        });
      }
    });
  }

  private release(): void {
    this.permits++;
    if (this.queue.length > 0) {
      const next = this.queue.shift()!;
      next();
    }
  }
}