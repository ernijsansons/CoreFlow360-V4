/**
 * Anthropic Claude Agent Implementation
 * Production-ready agent with streaming, fallback, and error handling
 */

import {
  IAgent,
  AgentTask,
  BusinessContext,
  AgentResult,
  ValidationResult,
  HealthStatus,
  StreamingChunk,
  AgentError,
  CostLimitExceededError,
  RateLimitExceededError,
  AGENT_LIMITS,
  DEPARTMENT_CAPABILITIES
} from './types';
import { Logger } from '../../shared/logger';
import { SecurityError, InputValidator, PIIRedactor } from '../../shared/security-utils';
import { CapabilityManager } from '../capabilities';

interface ClaudeAPIResponse {
  id: string;
  type: string;
  role: string;
  content: Array<{
    type: string;
    text?: string;
    name?: string;
    input?: Record<string, unknown>;
  }>;
  model: string;
  stop_reason: string;
  stop_sequence?: string;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

interface ClaudeStreamChunk {
  type: string;
  message?: {
    id: string;
    type: string;
    role: string;
    content: any[];
    model: string;
    usage?: {
      input_tokens: number;
      output_tokens: number;
    };
  };
  content_block?: {
    type: string;
    text?: string;
  };
  delta?: {
    type: string;
    text?: string;
    partial_json?: string;
  };
  usage?: {
    input_tokens: number;
    output_tokens: number;
  };
}

export class ClaudeAgent implements IAgent {
  // Agent identity (can be overridden by config)
  readonly id: string;
  readonly name: string;
  readonly type = 'external' as const;
  readonly version = '3.5.0';

  // Agent capabilities (configurable)
  readonly capabilities: string[];
  readonly departments: string[];
  readonly tags = ['llm', 'anthropic', 'production', 'multi-modal'];

  // Agent characteristics (configurable)
  readonly costPerCall: number;
  readonly maxConcurrency: number;
  readonly averageLatency = 2500; // 2.5 seconds average
  readonly supportedLanguages = ['en', 'es', 'fr', 'de', 'it', 'pt', 'ja', 'ko', 'zh'];
  readonly supportedFormats = ['text', 'json', 'markdown', 'csv', 'xml'];

  // Configuration
  private apiKey: string;
  private baseUrl = 'https://api.anthropic.com/v1';
  private model = 'claude-3-5-sonnet-20241022';
  private fallbackModels = ['claude-3-haiku-20240307'];
  private maxTokens = 8192;
  private temperature = 0.1;
  private timeout = 60000;
  private maxRetries = 3;
  private retryDelay = 1000;

  // Department-specific prompts
  private departmentPrompts = {
    finance: `You are a financial analysis expert working for {companyName}. You have deep knowledge of:
- Financial reporting and analysis
- Budgeting and forecasting
- Compliance requirements (SOX, GAAP, IFRS)
- Cash flow management
- Risk assessment
- Tax implications

Current fiscal period: {currentFiscalPeriod}
Company size: {companySize}
Industry: {industry}

Always provide accurate, compliance-aware financial advice. Include confidence
  levels and cite relevant accounting standards when applicable.`,

    hr: `You are an HR specialist working for {companyName}. You excel at:
- Employee relations and engagement
- Recruitment and talent acquisition
- Performance management
- Policy development and compliance
- Benefits administration
- Training and development
- Legal compliance (EEOC, FMLA, etc.)

Company size: {companySize}
Industry: {industry}

Provide helpful, legally compliant HR guidance. Always consider employment law and company policies.`,

    sales: `You are a sales operations expert for {companyName}. Your expertise includes:
- Lead qualification and scoring
- Sales process optimization
- Pipeline analysis and forecasting
- Customer relationship management
- Proposal and contract development
- Market analysis and competitive intelligence
- Pricing strategies

Company industry: {industry}
Current market conditions: {marketConditions}

Focus on actionable insights that drive revenue growth while maintaining customer relationships.`,

    marketing: `You are a marketing strategist for {companyName}. You specialize in:
- Campaign development and optimization
- Market research and analysis
- Brand management and positioning
- Digital marketing and social media
- Content creation and strategy
- Customer segmentation and targeting
- ROI measurement and analytics

Company industry: {industry}
Target market: {targetMarket}

Provide data-driven marketing recommendations that align with business objectives.`,

    operations: `You are an operations expert for {companyName}. Your focus areas include:
- Process optimization and automation
- Supply chain management
- Quality control and assurance
- Resource planning and allocation
- Risk management and mitigation
- Performance monitoring and KPIs
- Vendor and supplier management

Company industry: {industry}
Company size: {companySize}

Provide operational insights that improve efficiency, reduce costs, and mitigate risks.`,
  };

  private logger: Logger;
  private capabilityManager?: CapabilityManager;
  private activeRequests = new Map<string, AbortController>();
  private rateLimitStatus = {
    remaining: 1000,
    resetAt: Date.now() + 60000,
    lastCheck: Date.now(),
  };

  constructor(config: { apiKey: string; [key: string]: any } | string, capabilityManager?: CapabilityManager) {
    // Handle backward compatibility: if first param is string, it's the old apiKey-only constructor
    if (typeof config === 'string') {
      this.apiKey = config;
      this.id = 'claude-3-5-sonnet';
      this.name = 'Claude 3.5 Sonnet';
      this.capabilities = ['analysis', 'generation', 'reasoning', 'planning'];
      this.departments = ['finance', 'hr', 'sales', 'marketing', 'operations'];
      this.costPerCall = 0.015;
      this.maxConcurrency = 20;
    } else {
      // New AgentConfig-based constructor
      this.apiKey = config.apiKey;
      this.id = config.id || 'claude-3-5-sonnet';
      this.name = config.name || 'Claude 3.5 Sonnet';
      this.capabilities = config.capabilities || ['analysis', 'generation', 'reasoning', 'planning'];
      this.departments = config.departments || ['all'];
      this.costPerCall = config.costPerCall || 0.015;
      this.maxConcurrency = config.maxConcurrency || 20;

      // Override model settings if provided in config
      if (config.model) this.model = config.model;
      if (config.maxTokens) this.maxTokens = config.maxTokens;
      if (config.temperature !== undefined) this.temperature = config.temperature;
    }

    this.capabilityManager = capabilityManager;
    this.logger = new Logger();

    if (!this.apiKey) {
      throw new AgentError(
        'Anthropic API key is required',
        'MISSING_API_KEY',
        'validation'
      );
    }
  }

  /**
   * Execute a task with the Claude API
   */
  async execute(task: AgentTask, context: BusinessContext): Promise<AgentResult> {
    const startTime = Date.now();
    const abortController = new AbortController();
    this.activeRequests.set(task.id, abortController);

    try {
      // Validate input
      const validation = await this.validateInput(task.input, task.capability);
      if (!validation.valid) {
        throw new AgentError(
          `Input validation failed: ${validation.errors?.map((e: any) => e.message).join(', ')}`,
          'VALIDATION_FAILED',
          'validation',
          false,
          { errors: validation.errors }
        );
      }

      // Check capability support
      if (!this.capabilities.includes(task.capability)) {
        throw new AgentError(
          `Capability '${task.capability}' not supported`,
          'CAPABILITY_NOT_SUPPORTED',
          'validation'
        );
      }

      // Estimate and check cost
      const estimatedCost = await this.estimateCost(task);
      if (task.constraints?.maxCost && estimatedCost > task.constraints.maxCost) {
        throw new CostLimitExceededError(estimatedCost, task.constraints.maxCost);
      }

      // Check rate limits
      await this.checkRateLimit();

      // Build context-aware prompt
      const prompt = await this.buildContextualPrompt(task, context);

      // Execute with streaming or regular API
      const result = task.constraints?.streamingEnabled
        ? await this.executeStreaming(task, prompt, context, abortController.signal)
        : await this.executeRegular(task, prompt, context, abortController.signal);

      // Calculate actual cost
      const actualCost = this.calculateActualCost(result.metrics.tokensUsed || 0);

      // Build final result
      const agentResult: AgentResult = {
        taskId: task.id,
        agentId: this.id,
        status: 'completed',
        result: {
          data: result.data,
          confidence: result.confidence,
          reasoning: result.reasoning,
          sources: result.sources,
        },
        metrics: {
          executionTime: Date.now() - startTime,
          tokensUsed: result.metrics.tokensUsed,
          costUSD: actualCost,
          modelUsed: result.metrics.modelUsed || this.model,
          retryCount: result.metrics.retryCount || 0,
          cacheHit: false,
        },
        startedAt: startTime,
        completedAt: Date.now(),
      };

      this.logger.info('Claude task completed', {
        taskId: task.id,
        capability: task.capability,
        executionTime: agentResult.metrics.executionTime,
        tokensUsed: agentResult.metrics.tokensUsed,
        cost: actualCost,
        correlationId: context.correlationId,
      });

      return agentResult;

    } catch (error: any) {
      const executionTime = Date.now() - startTime;
      const isRetryable = this.isRetryableError(error);

      const agentResult: AgentResult = {
        taskId: task.id,
        agentId: this.id,
        status: 'failed',
        error: {
          code: this.getErrorCode(error),
          message: error instanceof Error ? error.message : 'Unknown error',
          retryable: isRetryable,
          category: this.getErrorCategory(error),
          details: error instanceof AgentError ? error.details : undefined,
        },
        metrics: {
          executionTime,
          costUSD: 0,
          retryCount: 0,
        },
        startedAt: startTime,
        completedAt: Date.now(),
      };

      this.logger.error('Claude task failed', error, {
        taskId: task.id,
        capability: task.capability,
        executionTime,
        correlationId: context.correlationId,
      });

      return agentResult;

    } finally {
      this.activeRequests.delete(task.id);
    }
  }

  /**
   * Validate input for specific capability
   */
  async validateInput(input: unknown, capability: string): Promise<ValidationResult> {
    const errors: Array<{ field: string; code: string; message: string }> = [];
    const warnings: Array<{ field: string; message: string }> = [];

    try {
      // Basic input validation
      if (!input || typeof input !== 'object') {
        errors.push({
          field: 'input',
          code: 'INVALID_TYPE',
          message: 'Input must be an object',
        });
        return { valid: false, errors };
      }

      const inputObj = input as Record<string, unknown>;

      // Check for required prompt
      if (!inputObj.prompt && !inputObj.data) {
        errors.push({
          field: 'prompt',
          code: 'MISSING_REQUIRED',
          message: 'Either prompt or data is required',
        });
      }

      // Validate prompt if present
      if (inputObj.prompt) {
        if (typeof inputObj.prompt !== 'string') {
          errors.push({
            field: 'prompt',
            code: 'INVALID_TYPE',
            message: 'Prompt must be a string',
          });
        } else {
          const prompt = inputObj.prompt as string;

          // Check prompt length
          if (prompt.length > 200000) { // ~50K tokens limit
            errors.push({
              field: 'prompt',
              code: 'TOO_LONG',
              message: 'Prompt exceeds maximum length',
            });
          }

          // Check for potentially sensitive information
          if (this.containsSensitiveInformation(prompt)) {
            warnings.push({
              field: 'prompt',
              message: 'Prompt may contain sensitive information',
            });
          }

          // Validate no SQL injection patterns
          if (!InputValidator.validateAndSanitize(prompt, 'prompt')) {
            errors.push({
              field: 'prompt',
              code: 'SECURITY_VIOLATION',
              message: 'Prompt contains potentially dangerous patterns',
            });
          }
        }
      }

      // Validate files if present
      if (inputObj.files && Array.isArray(inputObj.files)) {
        const files = inputObj.files as any[];
        if (files.length > 10) {
          errors.push({
            field: 'files',
            code: 'TOO_MANY',
            message: 'Maximum 10 files allowed',
          });
        }

        for (let i = 0; i < files.length; i++) {
          const file = files[i];
          if (!file.name || !file.type || !file.url) {
            errors.push({
              field: `files[${i}]`,
              code: 'MISSING_FIELDS',
              message: 'File must have name, type, and url',
            });
          }

          if (file.size > AGENT_LIMITS.MAX_TASK_SIZE_MB * 1024 * 1024) {
            errors.push({
              field: `files[${i}]`,
              code: 'FILE_TOO_LARGE',
              message: `File size exceeds ${AGENT_LIMITS.MAX_TASK_SIZE_MB}MB limit`,
            });
          }
        }
      }

      // Capability-specific validation
      await this.validateCapabilitySpecificInput(inputObj, capability, errors, warnings);

      // Sanitize input
      const sanitizedInput = this.sanitizeInput(inputObj);

      return {
        valid: errors.length === 0,
        errors: errors.length > 0 ? errors : undefined,
        warnings: warnings.length > 0 ? warnings : undefined,
        sanitizedInput,
      };

    } catch (error: any) {
      this.logger.error('Input validation error', error, { capability });
      return {
        valid: false,
        errors: [{
          field: 'input',
          code: 'VALIDATION_ERROR',
          message: 'Input validation failed due to system error',
        }],
      };
    }
  }

  /**
   * Estimate cost for a task
   */
  async estimateCost(task: AgentTask): Promise<number> {
    try {
      // Estimate input tokens
      let inputTokens = 0;

      // Base system prompt tokens
      inputTokens += 200;

      // User prompt tokens
      if (task.input.prompt) {
        inputTokens += this.estimateTokens(task.input.prompt as string);
      }

      // Context injection tokens
      inputTokens += 300; // Business context

      // Department prompt tokens
      const department = task.metadata?.department || task.context.userContext.department;
      if (department && this.departmentPrompts[department as keyof typeof this.departmentPrompts]) {
        inputTokens += 150;
      }

      // Capability-specific context tokens
      inputTokens += 100;

      // Estimate output tokens based on capability
      const outputTokens = this.estimateOutputTokens(task.capability);

      // Calculate cost using Claude 3.5 Sonnet pricing
      const inputCost = (inputTokens / 1000) * 0.003; // $3 per 1M input tokens
      const outputCost = (outputTokens / 1000) * 0.015; // $15 per 1M output tokens
      const totalCost = inputCost + outputCost;

      // Add processing overhead
      const processingCost = totalCost * 0.1;

      return Math.round((totalCost + processingCost) * 100) / 100; // Round to cents

    } catch (error: any) {
      this.logger.error('Cost estimation failed', error, {
        taskId: task.id,
        capability: task.capability,
      });
      return this.costPerCall; // Return default cost
    }
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<HealthStatus> {
    const startTime = Date.now();

    try {
      // Test API connectivity with a minimal request
      const response = await fetch(`${this.baseUrl}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'claude-3-haiku-20240307', // Use cheapest model for health check
          max_tokens: 10,
          messages: [{ role: 'user', content: 'Hello' }],
        }),
        signal: AbortSignal.timeout(10000), // 10 second timeout
      });

      const latency = Date.now() - startTime;

      if (response.ok) {
        // Parse rate limit headers
        this.updateRateLimitStatus(response);

        return {
          status: 'online',
          latency,
          lastCheck: Date.now(),
          details: {
            apiConnectivity: true,
            rateLimitStatus: this.rateLimitStatus,
            activeConnections: this.activeRequests.size,
          },
        };
      } else if (response.status === 429) {
        return {
          status: 'degraded',
          latency,
          lastCheck: Date.now(),
          details: {
            apiConnectivity: true,
            rateLimitStatus: this.rateLimitStatus,
            activeConnections: this.activeRequests.size,
            recentErrors: ['Rate limit exceeded'],
          },
        };
      } else {
        return {
          status: 'error',
          latency,
          lastCheck: Date.now(),
          details: {
            apiConnectivity: false,
            activeConnections: this.activeRequests.size,
            recentErrors: [`HTTP ${response.status}: ${response.statusText}`],
          },
        };
      }

    } catch (error: any) {
      const latency = Date.now() - startTime;

      return {
        status: 'offline',
        latency,
        lastCheck: Date.now(),
        details: {
          apiConnectivity: false,
          activeConnections: this.activeRequests.size,
          recentErrors: [error instanceof Error ? error.message : 'Unknown error'],
        },
      };
    }
  }

  /**
   * Initialize agent with configuration
   */
  async initialize(config: Record<string, unknown>): Promise<void> {
    if (config.model && typeof config.model === 'string') {
      this.model = config.model;
    }

    if (config.maxTokens && typeof config.maxTokens === 'number') {
      this.maxTokens = config.maxTokens;
    }

    if (config.temperature && typeof config.temperature === 'number') {
      this.temperature = config.temperature;
    }

    if (config.timeout && typeof config.timeout === 'number') {
      this.timeout = config.timeout;
    }

    this.logger.info('Claude agent initialized', {
      model: this.model,
      maxTokens: this.maxTokens,
      temperature: this.temperature,
    });
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    // Abort all active requests
    for (const [taskId, controller] of this.activeRequests) {
      controller.abort();
      this.logger.warn('Aborted active request during cleanup', { taskId });
    }

    this.activeRequests.clear();
    this.logger.info('Claude agent cleanup completed');
  }

  /**
   * Private methods
   */

  private async buildContextualPrompt(task: AgentTask, context: BusinessContext): Promise<string> {
    const parts: string[] = [];

    // Department-specific system prompt
    const department = task.metadata?.department || context.userContext.department;
    if (department && this.departmentPrompts[department as keyof typeof this.departmentPrompts]) {
      const template = this.departmentPrompts[department as keyof typeof this.departmentPrompts];
      const systemPrompt = this.interpolateTemplate(template, context);
      parts.push(systemPrompt);
    }

    // Business context injection
    parts.push(this.buildBusinessContext(context));

    // Capability-specific context
    parts.push(this.buildCapabilityContext(task.capability, context));

    // User prompt
    if (task.input.prompt) {
      parts.push(`\nUser Request:\n${task.input.prompt}`);
    }

    // Data context if provided
    if (task.input.data) {
      parts.push(`\nData Context:\n${JSON.stringify(task.input.data, null, 2)}`);
    }

    // Response format instructions
    parts.push(this.buildResponseInstructions(task.capability, department));

    return parts.join('\n\n');
  }

  private buildBusinessContext(context: BusinessContext): string {
    const lines = [
      'Business Context:',
      `- Company: ${context.businessData.companyName}`,
      `- Industry: ${context.businessData.industry}`,
      `- Size: ${context.businessData.companySize}`,
      `- Currency: ${context.businessData.currency}`,
      `- Timezone: ${context.businessData.timezone}`,
    ];

    if (context.businessState) {
      lines.push(`- Current Fiscal Period: ${context.businessState.currentFiscalPeriod}`);

      if (context.businessState.keyMetrics && Object.keys(context.businessState.keyMetrics).length > 0) {
        lines.push('- Key Metrics:');
        for (const [metric, value] of Object.entries(context.businessState.keyMetrics)) {
          lines.push(`  - ${metric}: ${value}`);
        }
      }
    }

    return lines.join('\n');
  }

  private buildCapabilityContext(capability: string, context: BusinessContext): string {
    switch (capability) {
      case 'financial_analysis':
      case 'budget_planning':
      case 'cash_flow_analysis':
        return `Financial Analysis Context:
- Consider current fiscal period: ${context.businessState?.currentFiscalPeriod || 'N/A'}
- Apply relevant accounting standards (GAAP/IFRS)
- Include compliance considerations
- Provide confidence levels for projections`;

      case 'invoice_processing':
      case 'expense_analysis':
        return `Invoice/Expense Context:
- Use company currency: ${context.businessData.currency}
- Consider tax implications
- Apply expense policies
- Flag unusual amounts or patterns`;

      case 'lead_qualification':
      case 'customer_insights':
        return `Sales Context:
- Company industry: ${context.businessData.industry}
- Target market considerations
- Revenue impact analysis
- Customer lifecycle stage assessment`;

      case 'resume_analysis':
      case 'employee_onboarding':
        return `HR Context:
- Company size: ${context.businessData.companySize}
- Industry: ${context.businessData.industry}
- Legal compliance requirements
- Cultural fit assessment`;

      default:
        return `Task Context:
- Department: ${context.userContext.department}
- User role: ${context.userContext.role}
- Company context: ${context.businessData.companyName} (${context.businessData.industry})`;
    }
  }

  private buildResponseInstructions(capability: string, department?: string): string {
    const baseInstructions = [
      'Response Instructions:',
      '- Provide clear, actionable insights',
      '- Include confidence levels where appropriate',
      '- Cite relevant sources or standards',
      '- Use professional business language',
      '- Structure response logically with clear sections',
    ];

    // Add capability-specific instructions
    switch (capability) {
      case 'financial_analysis':
        baseInstructions.push(
          '- Include numerical analysis with calculations',
          '- Reference relevant accounting standards',
          '- Provide risk assessment',
          '- Suggest next steps or recommendations'
        );
        break;

      case 'contract_review':
        baseInstructions.push(
          '- Highlight key terms and conditions',
          '- Identify potential risks or concerns',
          '- Suggest modifications if needed',
          '- Note compliance requirements'
        );
        break;

      case 'market_analysis':
        baseInstructions.push(
          '- Include market size and trends',
          '- Competitive landscape analysis',
          '- Opportunity assessment',
          '- Data sources and methodology'
        );
        break;
    }

    // Add department-specific instructions
    if (department === 'finance') {
      baseInstructions.push('- Ensure all financial advice complies with accounting standards');
    } else if (department === 'hr') {
      baseInstructions.push('- Consider employment law and company policy compliance');
    } else if (department === 'sales') {
      baseInstructions.push('- Focus on revenue impact and customer value');
    }

    return baseInstructions.join('\n');
  }

  private interpolateTemplate(template: string, context: BusinessContext): string {
    return template
      .replace(/{companyName}/g, context.businessData.companyName)
      .replace(/{industry}/g, context.businessData.industry)
      .replace(/{companySize}/g, context.businessData.companySize)
      .replace(/{currentFiscalPeriod}/g, context.businessState?.currentFiscalPeriod || 'N/A')
      .replace(/{targetMarket}/g, context.businessData.industry) // Simplified
      .replace(/{marketConditions}/g, 'Current market conditions'); // Would be dynamic in production
  }

  private async executeRegular(
    task: AgentTask,
    prompt: string,
    context: BusinessContext,
    signal: AbortSignal
  ): Promise<any> {
    const requestBody = {
      model: this.model,
      max_tokens: this.maxTokens,
      temperature: this.temperature,
      messages: [{ role: 'user', content: prompt }],
    };

    const response = await this.makeAPIRequest('/messages', requestBody, signal);

    if (!response.ok) {
      await this.handleAPIError(response);
    }

    const result: ClaudeAPIResponse = await response.json();

    // Extract content
    const content = result.content
      .filter((block: any) => block.type === 'text')
      .map((block: any) => block.text)
      .join('\n');

    return {
      data: content,
      confidence: this.calculateConfidence(result),
      reasoning: this.extractReasoning(content),
      sources: this.extractSources(content),
      metrics: {
        tokensUsed: result.usage.input_tokens + result.usage.output_tokens,
        modelUsed: result.model,
      },
    };
  }

  private async executeStreaming(
    task: AgentTask,
    prompt: string,
    context: BusinessContext,
    signal: AbortSignal
  ): Promise<any> {
    const requestBody = {
      model: this.model,
      max_tokens: this.maxTokens,
      temperature: this.temperature,
      messages: [{ role: 'user', content: prompt }],
      stream: true,
    };

    const response = await this.makeAPIRequest('/messages', requestBody, signal);

    if (!response.ok) {
      await this.handleAPIError(response);
    }

    let fullContent = '';
    let totalTokens = 0;
    let modelUsed = this.model;

    const reader = response.body?.getReader();
    if (!reader) {
      throw new AgentError('No response body for streaming', 'NO_RESPONSE_BODY', 'api');
    }

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = new TextDecoder().decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            if (data === '[DONE]') continue;

            try {
              const parsed: ClaudeStreamChunk = JSON.parse(data);

              if (parsed.type === 'content_block_delta' && parsed.delta?.text) {
                fullContent += parsed.delta.text;
              }

              if (parsed.usage) {
                totalTokens = parsed.usage.input_tokens + parsed.usage.output_tokens;
              }

              if (parsed.message?.model) {
                modelUsed = parsed.message.model;
              }

            } catch (parseError) {
              // Ignore JSON parse errors for incomplete chunks
            }
          }
        }
      }

    } finally {
      reader.releaseLock();
    }

    return {
      data: fullContent,
      confidence: this.calculateConfidenceFromText(fullContent),
      reasoning: this.extractReasoning(fullContent),
      sources: this.extractSources(fullContent),
      metrics: {
        tokensUsed: totalTokens,
        modelUsed,
      },
    };
  }

  private async makeAPIRequest(
    endpoint: string,
    body: Record<string, unknown>,
    signal: AbortSignal
  ): Promise<Response> {
    const url = `${this.baseUrl}${endpoint}`;

    return fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
      signal,
    });
  }

  private async handleAPIError(response: Response): Promise<never> {
    const errorData = await response.json().catch(() => ({}));

    switch (response.status) {
      case 400:
        throw new AgentError(
          `Invalid request: ${errorData.error?.message || 'Bad request'}`,
          'INVALID_REQUEST',
          'validation',
          false,
          errorData
        );

      case 401:
        throw new AgentError(
          'Invalid API key',
          'INVALID_API_KEY',
          'permission',
          false
        );

      case 429:
        this.updateRateLimitStatus(response);
        throw new RateLimitExceededError(
          this.id,
          this.rateLimitStatus.resetAt
        );

      case 500:
      case 502:
      case 503:
      case 504:
        throw new AgentError(
          `Server error: ${response.status}`,
          'SERVER_ERROR',
          'api',
          true,
          { status: response.status }
        );

      default:
        throw new AgentError(
          `HTTP ${response.status}: ${response.statusText}`,
          'HTTP_ERROR',
          'api',
          true,
          { status: response.status }
        );
    }
  }

  private async checkRateLimit(): Promise<void> {
    const now = Date.now();

    // Reset rate limit if time has passed
    if (now > this.rateLimitStatus.resetAt) {
      this.rateLimitStatus.remaining = 1000; // Reset to default
      this.rateLimitStatus.resetAt = now + 60000; // 1 minute from now
    }

    if (this.rateLimitStatus.remaining <= 0) {
      throw new RateLimitExceededError(this.id, this.rateLimitStatus.resetAt);
    }
  }

  private updateRateLimitStatus(response: Response): void {
    const remaining = response.headers.get('anthropic-ratelimit-requests-remaining');
    const reset = response.headers.get('anthropic-ratelimit-requests-reset');

    if (remaining) {
      this.rateLimitStatus.remaining = parseInt(remaining, 10);
    }

    if (reset) {
      this.rateLimitStatus.resetAt = new Date(reset).getTime();
    }

    this.rateLimitStatus.lastCheck = Date.now();
  }

  private estimateTokens(text: string): number {
    // Rough token estimation: ~4 characters per token
    return Math.ceil(text.length / 4);
  }

  private estimateOutputTokens(capability: string): number {
    const estimates = {
      financial_analysis: 1500,
      budget_planning: 1200,
      invoice_processing: 500,
      expense_analysis: 800,
      lead_qualification: 600,
      proposal_generation: 2000,
      market_analysis: 1800,
      resume_analysis: 800,
      contract_review: 1200,
      document_analysis: 1000,
      report_generation: 2500,
    };

    return estimates[capability as keyof typeof estimates] || 1000;
  }

  private calculateActualCost(tokensUsed: number): number {
    // Approximate 60/40 split between input/output tokens
    const inputTokens = Math.floor(tokensUsed * 0.6);
    const outputTokens = Math.floor(tokensUsed * 0.4);

    const inputCost = (inputTokens / 1000) * 0.003;
    const outputCost = (outputTokens / 1000) * 0.015;

    return Math.round((inputCost + outputCost) * 100) / 100;
  }

  private calculateConfidence(result: ClaudeAPIResponse): number {
    // Simple confidence calculation based on response characteristics
    const hasReferences = result.content.some(block =>
      block.text?.includes('according to') ||
      block.text?.includes('based on') ||
      block.text?.includes('per')
    );

    const hasQualifiers = result.content.some(block =>
      block.text?.includes('likely') ||
      block.text?.includes('approximately') ||
      block.text?.includes('estimated')
    );

    if (hasReferences && !hasQualifiers) return 0.9;
    if (hasReferences) return 0.8;
    if (!hasQualifiers) return 0.7;
    return 0.6;
  }

  private calculateConfidenceFromText(text: string): number {
    const hasReferences = text.includes('according to') || text.includes('based on');
    const hasQualifiers = text.includes('likely') || text.includes('approximately');

    if (hasReferences && !hasQualifiers) return 0.9;
    if (hasReferences) return 0.8;
    if (!hasQualifiers) return 0.7;
    return 0.6;
  }

  private extractReasoning(content: string): string {
    // Extract reasoning sections from response
    const reasoningPatterns = [
      /reasoning[:\s]+([^\.]+\.)/i,
      /because[:\s]+([^\.]+\.)/i,
      /this is due to[:\s]+([^\.]+\.)/i,
    ];

    for (const pattern of reasoningPatterns) {
      const match = content.match(pattern);
      if (match) {
        return match[1].trim();
      }
    }

    // Fallback: return first sentence if no explicit reasoning found
    const sentences = content.split('.').filter((s: any) => s.trim().length > 20);
    return sentences[0]?.trim() + '.' || '';
  }

  private extractSources(content: string): string[] {
    const sources: string[] = [];

    // Extract references and citations
    const sourcePatterns = [
      /according to ([^,\.]+)/gi,
      /based on ([^,\.]+)/gi,
      /per ([^,\.]+)/gi,
      /\[([^\]]+)\]/g, // Bracketed references
    ];

    for (const pattern of sourcePatterns) {
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        sources.push(match[1].trim());
      }
    }

    return [...new Set(sources)]; // Remove duplicates
  }

  private containsSensitiveInformation(text: string): boolean {
    const sensitivePatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Credit card
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email (basic)
      /password/i,
      /secret/i,
      /confidential/i,
    ];

    return sensitivePatterns.some(pattern => pattern.test(text));
  }

  private async validateCapabilitySpecificInput(
    input: Record<string, unknown>,
    capability: string,
    errors: Array<{ field: string; code: string; message: string }>,
    warnings: Array<{ field: string; message: string }>
  ): Promise<void> {
    // Validate capability-specific requirements
    switch (capability) {
      case 'financial_analysis':
      case 'budget_planning':
        if (input.data && typeof input.data === 'object') {
          const data = input.data as Record<string, unknown>;
          if (!data.financialData && !data.period) {
            warnings.push({
              field: 'data',
              message: 'Financial analysis works best with structured financial data',
            });
          }
        }
        break;

      case 'invoice_processing':
        if (input.data) {
          const data = input.data as Record<string, unknown>;
          if (!data.invoiceData && !data.amount) {
            errors.push({
              field: 'data',
              code: 'MISSING_INVOICE_DATA',
              message: 'Invoice processing requires invoice data or amount information',
            });
          }
        }
        break;

      case 'contract_review':
        if (!input.data && !input.files) {
          errors.push({
            field: 'input',
            code: 'MISSING_CONTRACT',
            message: 'Contract review requires contract text or file',
          });
        }
        break;
    }
  }

  private sanitizeInput(input: Record<string, unknown>): Record<string, unknown> {
    const sanitized = { ...input };

    // Sanitize prompt
    if (sanitized.prompt && typeof sanitized.prompt === 'string') {
      sanitized.prompt = InputValidator.validateAndSanitize(
        sanitized.prompt,
        'prompt'
      ) || sanitized.prompt;
    }

    // Redact sensitive data
    if (sanitized.data) {
      sanitized.data = PIIRedactor.redactSensitiveData(sanitized.data);
    }

    return sanitized;
  }

  private isRetryableError(error: unknown): boolean {
    if (error instanceof AgentError) {
      return error.retryable;
    }

    if (error instanceof Error) {
      // Network errors are generally retryable
      return error.message.includes('fetch') ||
             error.message.includes('network') ||
             error.message.includes('timeout');
    }

    return false;
  }

  private getErrorCode(error: unknown): string {
    if (error instanceof AgentError) {
      return error.code;
    }

    if (error instanceof Error) {
      if (error.message.includes('timeout')) return 'TIMEOUT';
      if (error.message.includes('network')) return 'NETWORK_ERROR';
      if (error.message.includes('fetch')) return 'FETCH_ERROR';
    }

    return 'UNKNOWN_ERROR';
  }

  private getErrorCategory(error: unknown): string {
    if (error instanceof AgentError) {
      return error.category;
    }

    if (error instanceof RateLimitExceededError) {
      return 'rate_limit';
    }

    if (error instanceof CostLimitExceededError) {
      return 'cost';
    }

    return 'system';
  }
}