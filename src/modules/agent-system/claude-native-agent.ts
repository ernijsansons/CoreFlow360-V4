/**
 * Claude Native Agent Implementation
 * Direct integration with Anthropic's Claude API
 */

import Anthropic from '@anthropic-ai/sdk';
import {
  IAgent,
  AgentTask,
  BusinessContext,
  AgentResult,
  ValidationResult,
  HealthStatus,
  ExecutionMetrics,
  TaskConstraints,
  StreamingChunk,
  DEPARTMENT_CAPABILITIES
} from './types';
import { Logger } from '../../shared/logger';
import { CorrelationId } from '../../shared/security-utils';
import { circuitBreakerRegistry, CircuitBreakerConfigs } from '../../shared/circuit-breaker';
import { errorHandler, ErrorFactories, ErrorCategory } from '../../shared/error-handling';
import {
  validateApiKeyFormat,
  maskApiKey,
  sanitizeErrorForUser,
  sanitizeForLogging,
  redactPII
} from './security-utils';
import { sanitizeUserInput, createSecureAIPrompt, validateAIPrompt } from '../../security/ai-prompt-sanitizer';

export class ClaudeNativeAgent implements IAgent {
  readonly id = 'claude-native';
  readonly name = 'Claude Native Integration';
  readonly type = 'native' as const;
  readonly capabilities = ['*']; // Can handle anything for now
  readonly department = ['finance', 'hr', 'sales', 'marketing', 'operations', 'it', 'legal'];
  readonly costPerCall = 0.002;
  readonly maxConcurrency = 50;

  private anthropic: Anthropic;
  private systemPrompts: Map<string, string>;
  private logger: Logger;

  // Model configurations
  private models = {
    haiku: 'claude-3-haiku-20240307',
    sonnet: 'claude-3-5-sonnet-20241022',
    opus: 'claude-3-opus-20240229'
  };

  // Cost per 1K tokens (input/output)
  private modelCosts = {
    [this.models.haiku]: { input: 0.00025, output: 0.00125 },
    [this.models.sonnet]: { input: 0.003, output: 0.015 },
    [this.models.opus]: { input: 0.015, output: 0.075 }
  };

  constructor(apiKey?: string) {
    this.logger = new Logger();

    // Get API key from environment if not provided
    const key = apiKey || process.env.ANTHROPIC_API_KEY;

    if (!key) {
      throw new Error('Anthropic API key is required (provide via constructor or ANTHROPIC_API_KEY env var)');
    }

    // Validate API key format
    if (!validateApiKeyFormat(key, 'sk-ant-')) {
      throw new Error('Invalid Anthropic API key format');
    }

    this.anthropic = new Anthropic({ apiKey: key });
    this.systemPrompts = new Map();
    this.initializeSystemPrompts();

    // Initialize circuit breaker for Claude API calls
    circuitBreakerRegistry.getOrCreate('claude-api', {
      ...CircuitBreakerConfigs.aiService,
      onStateChange: (state, name) => {
        this.logger.warn('Claude API circuit breaker state changed', {
          circuitName: name,
          newState: state,
          agentId: this.id
        });
      },
      onFailure: (error, name) => {
        this.logger.error('Claude API circuit breaker recorded failure', {
          circuitName: name,
          error: error.message,
          agentId: this.id
        });
      }
    });

    // Log initialization without exposing the key
    this.logger.info('Claude Native Agent initialized', {
      hasApiKey: true,
      keyMask: maskApiKey(key),
      modelCount: Object.keys(this.models).length,
      circuitBreakerReady: true
    });
  }

  /**
   * Execute a task using Claude
   */
  async execute(task: AgentTask, context: BusinessContext): Promise<AgentResult> {
    const startTime = Date.now();
    const taskId = task.id;

    return await errorHandler.withErrorBoundary(
      async () => {
        // Validate input
        const validation = this.validateInput(task.input);
        if (!validation.valid) {
          throw ErrorFactories.validation(
            `Invalid task input: ${validation.errors?.join(', ')}`,
            { operation: 'claude_execute', taskId, businessId: context.businessId }
          );
        }

        // Select appropriate model
        const model = this.selectModel(task);

        // Get system prompt
        const systemPrompt = this.getSystemPrompt(task.capability, context);

        // Format and sanitize user message
        const userMessage = this.formatTask(task, context);

        // Get tools for capability
        const tools = this.getToolsForCapability(task.capability);

        this.logger.debug('Executing Claude task', sanitizeForLogging({
          taskId,
          capability: task.capability,
          model,
          hasTools: tools.length > 0,
          department: context.department,
        }));

        // Validate system prompt for security
        if (!validateAIPrompt(systemPrompt)) {
          throw new Error('System prompt failed security validation');
        }

        // Execute with Claude using circuit breaker and retry logic
        const circuitBreaker = circuitBreakerRegistry.get('claude-api')!;

        const response = await circuitBreaker.executeWithRetry(async () => {
          return await this.anthropic.messages.create({
            model,
            max_tokens: task.constraints?.maxLatency ? 1000 : 4096,
            system: systemPrompt,
            messages: [{ role: 'user', content: userMessage }],
            tools: tools.length > 0 ? tools : undefined,
            temperature: this.getTemperature(task),
          });
        }, 2, 2000); // Max 2 retries with 2-second base delay

        // Process response
        const result = await this.processResponse(response, task, startTime, model);

        this.logger.info('Claude task completed successfully', sanitizeForLogging({
          taskId,
          capability: task.capability,
          model,
          latency: result.metrics.latency,
          cost: result.metrics.cost,
          tokensUsed: result.metrics.tokensUsed,
        }));

        return result;
      },
      { operation: 'claude_execute', taskId, businessId: context.businessId },
      // Fallback: return error result
      async () => {
        return this.createErrorResult(
          taskId,
          'Service temporarily unavailable. Please try again later.',
          startTime
        );
      }
    );
  }

  /**
   * Validate input for Claude
   */
  validateInput(input: unknown): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!input) {
      errors.push('Input is required');
      return { valid: false, errors };
    }

    // Check if input is an object with required fields
    if (typeof input === 'object' && input !== null) {
      const inputObj = input as Record<string, unknown>;

      // Validate prompt field
      if (!inputObj.prompt && !inputObj.message && !inputObj.content) {
        errors.push('Input must contain a prompt, message, or content field');
      }

      // Check for overly long prompts
      const prompt = inputObj.prompt || inputObj.message || inputObj.content;
      if (typeof prompt === 'string' && prompt.length > 100000) {
        warnings.push('Prompt is very long and may result in high costs');
      }

      // Validate file uploads if present
      if (inputObj.files && Array.isArray(inputObj.files)) {
        for (let i = 0; i < inputObj.files.length; i++) {
          const file = inputObj.files[i];
          if (!file || typeof file !== 'object') {
            errors.push(`File at index ${i} is invalid`);
          }
        }
      }
    } else if (typeof input === 'string') {
      // Simple string input is valid
      if (input.length > 100000) {
        warnings.push('Input is very long and may result in high costs');
      }
    } else {
      errors.push('Input must be a string or object');
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
      warnings: warnings.length > 0 ? warnings : undefined,
      sanitizedInput: input,
    };
  }

  /**
   * Estimate cost for a task
   */
  estimateCost(task: AgentTask): number {
    const model = this.selectModel(task);
    const costs = this.modelCosts[model];

    // Estimate token count (rough approximation)
    const inputText = this.formatTask(task, task.context);
    const estimatedInputTokens = Math.ceil(inputText.length / 4); // ~4 chars per token
    const estimatedOutputTokens = task.constraints?.maxLatency ? 250 : 1000; // Conservative estimate

    const inputCost = (estimatedInputTokens / 1000) * costs.input;
    const outputCost = (estimatedOutputTokens / 1000) * costs.output;

    return inputCost + outputCost;
  }

  /**
   * Health check for Claude API
   */
  async healthCheck(): Promise<HealthStatus> {
    const startTime = Date.now();

    // Check circuit breaker status first
    const circuitBreaker = circuitBreakerRegistry.get('claude-api');
    const circuitBreakerMetrics = circuitBreaker?.getMetrics();

    try {
      // If circuit is open, don't attempt health check
      if (circuitBreaker && !circuitBreaker.isHealthy()) {
        return {
          healthy: false,
          status: 'degraded',
          latency: 0,
          lastCheck: Date.now(),
          errors: ['Circuit breaker is open - API temporarily unavailable'],
          metadata: {
            circuitBreakerState: circuitBreakerMetrics?.state,
            failureRate: circuitBreakerMetrics?.failureRate,
            lastFailure: circuitBreakerMetrics?.lastFailureTime
          },
        };
      }

      // Execute health check with circuit breaker protection
      const response = await circuitBreaker!.execute(async () => {
        return await this.anthropic.messages.create({
          model: this.models.haiku, // Use cheapest model for health check
          max_tokens: 10,
          messages: [{ role: 'user', content: 'Health check. Respond with "OK".' }],
        });
      });

      const latency = Date.now() - startTime;
      const isHealthy = response.content.length > 0;

      return {
        healthy: isHealthy,
        status: isHealthy ? 'online' : 'degraded',
        latency,
        lastCheck: Date.now(),
        metadata: {
          model: this.models.haiku,
          responseLength: response.content.length,
          circuitBreakerState: circuitBreakerMetrics?.state,
          failureRate: circuitBreakerMetrics?.failureRate,
          totalRequests: circuitBreakerMetrics?.totalRequests
        },
      };

    } catch (error) {
      const latency = Date.now() - startTime;

      return {
        healthy: false,
        status: 'offline',
        latency,
        lastCheck: Date.now(),
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        metadata: {
          errorType: error instanceof Error ? error.constructor.name : 'UnknownError',
          circuitBreakerState: circuitBreakerMetrics?.state,
          failureRate: circuitBreakerMetrics?.failureRate
        },
      };
    }
  }

  /**
   * Stream response from Claude (for real-time interactions)
   */
  async *streamResponse(task: AgentTask, context: BusinessContext): AsyncGenerator<StreamingChunk> {
    const startTime = Date.now();

    try {
      yield {
        type: 'start',
        agentId: this.id,
        taskId: task.id,
        timestamp: Date.now(),
        metadata: { model: this.selectModel(task) },
      };

      const model = this.selectModel(task);
      const systemPrompt = this.getSystemPrompt(task.capability, context);
      const userMessage = this.formatTask(task, context);

      const stream = await this.anthropic.messages.create({
        model,
        max_tokens: 4096,
        system: systemPrompt,
        messages: [{ role: 'user', content: userMessage }],
        stream: true,
      });

      for await (const chunk of stream) {
        if (chunk.type === 'content_block_delta' && chunk.delta.type === 'text') {
          yield {
            type: 'data',
            agentId: this.id,
            taskId: task.id,
            data: chunk.delta.text,
            timestamp: Date.now(),
          };
        }
      }

      yield {
        type: 'end',
        agentId: this.id,
        taskId: task.id,
        timestamp: Date.now(),
        metadata: { totalTime: Date.now() - startTime },
      };

    } catch (error) {
      yield {
        type: 'error',
        agentId: this.id,
        taskId: task.id,
        data: error instanceof Error ? error.message : 'Unknown error',
        timestamp: Date.now(),
      };
    }
  }

  /**
   * Private helper methods
   */

  private selectModel(task: AgentTask): string {
    const constraints = task.constraints;

    // Use cost constraints to select model
    if (constraints?.maxCost && constraints.maxCost < 0.001) {
      return this.models.haiku;
    }

    // Use latency constraints
    if (constraints?.maxLatency && constraints.maxLatency < 5000) {
      return this.models.haiku;
    }

    // Check task complexity
    if (this.isComplexTask(task)) {
      return constraints?.maxCost && constraints.maxCost < 0.01
        ? this.models.sonnet
        : this.models.opus;
    }

    // Default to Sonnet for balanced performance
    return this.models.sonnet;
  }

  private isComplexTask(task: AgentTask): boolean {
    const complexity_indicators = [
      'analysis',
      'research',
      'planning',
      'strategy',
      'optimization',
      'complex',
      'detailed',
      'comprehensive',
      'advanced'
    ];

    const taskText = JSON.stringify(task.input).toLowerCase();
    return complexity_indicators.some(indicator => taskText.includes(indicator));
  }

  private getSystemPrompt(capability: string, context: BusinessContext): string {
    const department = context.department || this.getDepartmentFromCapability(capability);

    let basePrompt = this.systemPrompts.get(department) || this.systemPrompts.get('general') || '';

    // Add sanitized business context (no PII)
    basePrompt += `\n\nBusiness Context:
- Business ID: [CONTEXT_PROVIDED]
- User Department: ${context.department || 'Not specified'}
- Timezone: ${context.timezone}
- Currency: ${context.currency}
- Locale: ${context.locale}
- Available Permissions: ${context.permissions.join(', ')}`;

    // Add memory context if available (sanitized)
    if (context.memory?.shortTerm?.messages?.length) {
      const sanitizedMessages = context.memory.shortTerm.messages
        .slice(-3)
        .map(m => `${m.role}: ${redactPII(m.content)}`);
      basePrompt += `\n\nRecent Conversation Context:
${sanitizedMessages.join('\n')}`;
    }

    // Add real-time data if available (sanitized)
    if (context.realTimeData && Object.keys(context.realTimeData).length > 0) {
      const sanitizedData = sanitizeForLogging(context.realTimeData);
      basePrompt += `\n\nReal-time Business Data:
${JSON.stringify(sanitizedData, null, 2)}`;
    }

    return basePrompt;
  }

  private getDepartmentFromCapability(capability: string): string {
    // Map capabilities to departments
    for (const [dept, capabilities] of Object.entries(DEPARTMENT_CAPABILITIES)) {
      if (capabilities.includes(capability)) {
        return dept;
      }
    }

    // Check for partial matches
    const capabilityLower = capability.toLowerCase();
    if (capabilityLower.includes('financial') || capabilityLower.includes('budget')) return 'finance';
    if (capabilityLower.includes('employee') || capabilityLower.includes('hr')) return 'hr';
    if (capabilityLower.includes('sales') || capabilityLower.includes('crm')) return 'sales';
    if (capabilityLower.includes('marketing') || capabilityLower.includes('campaign')) return 'marketing';
    if (capabilityLower.includes('operations') || capabilityLower.includes('process')) return 'operations';
    if (capabilityLower.includes('system') || capabilityLower.includes('technical')) return 'it';
    if (capabilityLower.includes('legal') || capabilityLower.includes('contract')) return 'legal';

    return 'general';
  }

  private formatTask(task: AgentTask, context: BusinessContext): string {
    // Sanitize input to prevent prompt injection using new framework
    const inputText = typeof task.input === 'string'
      ? task.input
      : JSON.stringify(task.input);

    const sanitizationResult = sanitizeUserInput(inputText, {
      maxLength: 50000,
      strictMode: true,
      contextType: 'user_input'
    });

    if (sanitizationResult.blocked) {
      this.logger.error('Task input blocked due to security violations', {
        violations: sanitizationResult.violations,
        riskScore: sanitizationResult.riskScore,
        taskId: task.id
      });
      throw new Error('Task input contains security violations and cannot be processed');
    }

    if (sanitizationResult.modified) {
      this.logger.warn('Task input was modified during sanitization', {
        violations: sanitizationResult.violations,
        taskId: task.id
      });
    }

    let message = sanitizationResult.sanitized;

    // Add capability context
    if (task.capability !== '*') {
      message = `Capability: ${task.capability}\n\n${message}`;
    }

    // Add constraints if present
    if (task.constraints) {
      const constraints = [];
      if (task.constraints.maxCost) constraints.push(`Max cost: $${task.constraints.maxCost}`);
      if (task.constraints.maxLatency) constraints.push(`Max latency: ${task.constraints.maxLatency}ms`);
     
  if (task.constraints.requiredAccuracy) constraints.push(`Required accuracy: ${task.constraints.requiredAccuracy * 100}%`);

      if (constraints.length > 0) {
        message += `\n\nConstraints: ${constraints.join(', ')}`;
      }
    }

    // Final validation before sending to AI
    if (!validateAIPrompt(message)) {
      this.logger.error('Final prompt validation failed', { taskId: task.id });
      throw new Error('Prompt failed final security validation');
    }

    return message;
  }

  private getToolsForCapability(capability: string): any[] {
    // Define tools based on capability
    const tools: any[] = [];

    // Financial tools
    if (capability.includes('financial') || capability.includes('budget')) {
      tools.push({
        name: 'calculate_financial_metrics',
        description: 'Calculate financial metrics and ratios',
        input_schema: {
          type: 'object',
          properties: {
            revenue: { type: 'number' },
            expenses: { type: 'number' },
            assets: { type: 'number' },
            liabilities: { type: 'number' }
          }
        }
      });
    }

    // Data analysis tools
    if (capability.includes('analysis') || capability.includes('data')) {
      tools.push({
        name: 'analyze_data',
        description: 'Perform statistical analysis on data',
        input_schema: {
          type: 'object',
          properties: {
            data: { type: 'array' },
            analysis_type: { type: 'string', enum: ['descriptive', 'comparative', 'trend'] }
          }
        }
      });
    }

    return tools;
  }

  private getTemperature(task: AgentTask): number {
    // Adjust temperature based on task type
    const taskText = JSON.stringify(task.input).toLowerCase();

    if (taskText.includes('creative') || taskText.includes('brainstorm')) {
      return 0.8;
    }

    if (taskText.includes('analysis') || taskText.includes('calculation')) {
      return 0.1;
    }

    return 0.3; // Default balanced temperature
  }

  private async processResponse(
    response: Anthropic.Messages.Message,
    task: AgentTask,
    startTime: number,
    model: string
  ): Promise<AgentResult> {
    const endTime = Date.now();
    const latency = endTime - startTime;

    // Extract content
    const content = response.content.map(block => {
      if (block.type === 'text') {
        return block.text;
      }
      return '';
    }).join('');

    // Calculate cost
    const inputTokens = response.usage.input_tokens;
    const outputTokens = response.usage.output_tokens;
    const costs = this.modelCosts[model];
    const cost = (inputTokens / 1000) * costs.input + (outputTokens / 1000) * costs.output;

    // Determine confidence based on response characteristics
    const confidence = this.calculateConfidence(content, task);

    // Extract suggestions and next actions if present
    const suggestions = this.extractSuggestions(content);
    const nextActions = this.extractNextActions(content, task);

    return {
      taskId: task.id,
      agentId: this.id,
      success: true,
      data: {
        response: content,
        model,
        usage: response.usage,
      },
      confidence,
      metrics: {
        startTime,
        endTime,
        latency,
        cost,
        tokensUsed: inputTokens + outputTokens,
        modelUsed: model,
        retryCount: 0,
        memoryHits: 0,
      },
      suggestions,
      nextActions,
    };
  }

  private calculateConfidence(content: string, task: AgentTask): number {
    let confidence = 0.7; // Base confidence

    // Increase confidence for longer, detailed responses
    if (content.length > 500) confidence += 0.1;
    if (content.length > 1000) confidence += 0.1;

    // Decrease confidence for very short responses
    if (content.length < 50) confidence -= 0.2;

    // Check for uncertainty indicators
    const uncertaintyIndicators = ['might', 'possibly', 'unclear', 'unsure', 'maybe'];
    const uncertaintyCount = uncertaintyIndicators.filter(word =>
      content.toLowerCase().includes(word)
    ).length;
    confidence -= uncertaintyCount * 0.05;

    // Check for confidence indicators
    const confidenceIndicators = ['definitely', 'certain', 'confirmed', 'established'];
    const confidenceCount = confidenceIndicators.filter(word =>
      content.toLowerCase().includes(word)
    ).length;
    confidence += confidenceCount * 0.05;

    return Math.max(0.1, Math.min(1.0, confidence));
  }

  private extractSuggestions(content: string): string[] {
    const suggestions: string[] = [];

    // Look for common suggestion patterns
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('Suggestion:') || trimmed.startsWith('Recommendation:')) {
        suggestions.push(trimmed.substring(trimmed.indexOf(':') + 1).trim());
      }
    }

    return suggestions;
  }

  private extractNextActions(content: string, task: AgentTask): any[] {
    const nextActions: any[] = [];

    // Look for action items in the response
    const actionPatterns = [
      /next step:?\s*(.+)/gi,
      /action item:?\s*(.+)/gi,
      /todo:?\s*(.+)/gi,
      /follow.?up:?\s*(.+)/gi
    ];

    for (const pattern of actionPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          nextActions.push({
            type: 'task',
            description: match.trim(),
            priority: 'normal',
            estimatedCost: this.costPerCall,
            estimatedTime: 300000, // 5 minutes
          });
        }
      }
    }

    return nextActions;
  }

  private createErrorResult(taskId: string, error: string, startTime: number): AgentResult {
    return {
      taskId,
      agentId: this.id,
      success: false,
      error,
      metrics: {
        startTime,
        endTime: Date.now(),
        latency: Date.now() - startTime,
        cost: 0,
        retryCount: 0,
        memoryHits: 0,
      },
      retry: this.isRetryableError(error),
    };
  }

  private isRetryableError(error: string): boolean {
    const retryablePatterns = [
      'rate limit',
      'timeout',
      'server error',
      'network error',
      'temporary',
      'overloaded'
    ];

    const errorLower = error.toLowerCase();
    return retryablePatterns.some(pattern => errorLower.includes(pattern));
  }

  private initializeSystemPrompts(): void {
    this.systemPrompts.set('finance', `You are CoreFlow360's financial operations controller and expert analyst.

Core Responsibilities:
- Enforce double-entry bookkeeping rules and GAAP compliance
- Provide accurate financial analysis and insights
- Track every transaction in the audit log
- Ensure regulatory compliance (SOX, tax regulations)
- Optimize financial processes and cash flow

Guidelines:
- Always prioritize accuracy over speed
- Cite specific accounting standards when relevant
- Flag potential compliance issues immediately
- Provide clear explanations for all financial recommendations
- Maintain strict confidentiality of financial data

Response Format:
- Lead with key financial insights
- Include relevant metrics and ratios
- Highlight any risks or compliance concerns
- Suggest specific action items with timelines`);

    this.systemPrompts.set('sales', `You are CoreFlow360's sales automation specialist and revenue optimization expert.

Core Responsibilities:
- Focus on pipeline velocity and conversion optimization
- Personalize outreach while maintaining efficiency
- Track all activities in CRM
- Analyze sales performance and forecasting
- Support customer relationship management

Guidelines:
- Always prioritize customer value and relationship building
- Maintain ethical sales practices and transparency
- Protect customer confidential information
- Focus on long-term revenue growth over short-term gains
- Provide data-driven insights and recommendations

Response Format:
- Start with key sales insights or opportunities
- Include relevant metrics (conversion rates, pipeline health)
- Suggest specific action items for sales improvement
- Highlight customer relationship considerations`);

    this.systemPrompts.set('hr', `You are CoreFlow360's people operations manager and employee experience specialist.

Core Responsibilities:
- Ensure compliance with labor laws and regulations
- Maintain strict confidentiality of employee data
- Focus on employee experience and retention
- Support organizational development and culture
- Manage recruitment and performance processes

Guidelines:
- Always maintain employee privacy and confidentiality
- Ensure compliance with employment laws (EEOC, FLSA, etc.)
- Promote fair and equitable treatment of all employees
- Support diversity, equity, and inclusion initiatives
- Focus on employee development and engagement

Response Format:
- Begin with people-focused insights
- Include relevant HR metrics when appropriate
- Ensure all recommendations comply with employment law
- Suggest action items that improve employee experience`);

    this.systemPrompts.set('marketing', `You are CoreFlow360's marketing strategist and brand management expert.

Core Responsibilities:
- Develop and execute marketing strategies that drive growth
- Maintain consistent brand voice and messaging
- Analyze market trends and competitive landscape
- Optimize marketing ROI and campaign performance
- Support lead generation and customer acquisition

Guidelines:
- Maintain consistent brand voice and messaging
- Ensure all marketing activities comply with regulations
- Focus on measurable results and ROI
- Protect customer privacy and data
- Balance creativity with data-driven decision making

Response Format:
- Lead with marketing insights and opportunities
- Include relevant performance metrics
- Suggest specific campaigns or strategies
- Highlight brand consistency considerations`);

    this.systemPrompts.set('operations', `You are CoreFlow360's operations optimizer and efficiency specialist.

Core Responsibilities:
- Focus on process improvement and operational excellence
- Maintain quality standards while optimizing costs
- Analyze efficiency metrics and suggest improvements
- Manage vendor relationships and supply chain
- Support scalability and growth initiatives

Guidelines:
- Prioritize quality and customer satisfaction
- Focus on continuous improvement and efficiency
- Ensure compliance with operational standards
- Maintain cost-effectiveness without compromising quality
- Consider environmental and sustainability factors

Response Format:
- Start with operational insights and efficiency opportunities
- Include relevant KPIs and performance metrics
- Suggest specific process improvements
- Highlight quality and compliance considerations`);

    this.systemPrompts.set('it', `You are CoreFlow360's IT specialist and technology innovation leader.

Core Responsibilities:
- Ensure system reliability, security, and performance
- Support digital transformation initiatives
- Manage cybersecurity and data protection
- Optimize technology infrastructure and costs
- Provide technical support and user training

Guidelines:
- Prioritize data security and privacy above all
- Ensure system reliability and availability
- Follow established IT governance and compliance requirements
- Support business objectives through technology solutions
- Stay current with technology trends and best practices

Response Format:
- Begin with technical insights and recommendations
- Include security and compliance considerations
- Suggest specific technical solutions or improvements
- Highlight potential risks and mitigation strategies`);

    this.systemPrompts.set('legal', `You are CoreFlow360's legal advisor and compliance specialist.

Core Responsibilities:
- Ensure strict compliance with all applicable laws and regulations
- Provide conservative legal advice to minimize risk
- Manage contract review and negotiation support
- Monitor regulatory changes and compliance requirements
- Support corporate governance and risk management

Guidelines:
- Ensure strict compliance with all applicable laws and regulations
- Maintain attorney-client privilege and confidentiality
- Provide conservative legal advice to minimize risk
- Document all legal decisions and rationale
- Stay current with relevant legal developments

Response Format:
- Start with legal analysis and risk assessment
- Cite relevant laws, regulations, or precedents
- Provide clear recommendations with risk levels
- Include specific action items for compliance`);

    this.systemPrompts.set('general', `You are CoreFlow360's AI
  assistant, designed to help with business operations across all departments.

Core Responsibilities:
- Provide accurate, helpful, and professional assistance
- Maintain confidentiality and data security
- Support business objectives and productivity
- Ensure compliance with company policies
- Deliver high-quality, actionable insights

Guidelines:
- Always maintain professionalism and accuracy
- Protect sensitive business information
- Provide clear, actionable recommendations
- Consider cross-departmental impacts
- Support business growth and efficiency

Response Format:
- Begin with key insights or analysis
- Include relevant data and metrics when available
- Provide specific, actionable recommendations
- Highlight any important considerations or risks`);
  }
}