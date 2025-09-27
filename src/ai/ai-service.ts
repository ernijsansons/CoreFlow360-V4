// src/ai/ai-service.ts
import type { Ai } from '@cloudflare/ai';
import type { KVNamespace } from '../cloudflare/types/cloudflare';

// Type fixes for Workers AI responses
interface WorkersAIResponse {
  response?: string;
  text?: string;
  data?: any[];
}

interface AnthropicResponse {
  content?: Array<{ text?: string }>;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
  };
}

export interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface BusinessContext {
  businessId: string;
  industry?: string;
  preferences?: Record<string, any>;
  userData?: any;
}

export interface AIRequest {
  prompt: string;
  messages?: Message[];
  context: BusinessContext;
  complexity?: 'simple' | 'complex' | 'auto';
  maxTokens?: number;
  temperature?: number;
}

export interface AIResponse {
  content: string;
  model: string;
  tokens?: number;
  cached?: boolean;
  cost?: number;
}

// TODO: Consider splitting AIService into smaller, focused classes
export class AIService {
  constructor(
    private ai: Ai,
    private anthropicKey: string,
    private cache?: KVNamespace
  ) {}

  // Use Workers AI for simple tasks (fast & free)
  async quickResponse(prompt: string, maxTokens = 200): Promise<AIResponse> {
    const cacheKey = `ai:quick:${this.hashPrompt(prompt)}`;

    // Check cache first
    if (this.cache) {
      const cached = await this.cache.get(cacheKey, { type: 'json' });
      if (cached) {
        return {
          ...JSON.parse(cached as string) as AIResponse,
          cached: true
        };
      }
    }

    try {
      const response = await this.ai.run(
        '@cf/meta/llama-2-7b-chat-int8',
        {
          prompt: this.formatPromptForWorkers(prompt),
          max_tokens: maxTokens,
          temperature: 0.7
        }
      ) as WorkersAIResponse;

      const result: AIResponse = {
        content: response.response || response.text || '',
        model: 'llama-2-7b',
        tokens: maxTokens,
        cost: 0 // Workers AI is free
      };

      // Cache for 1 hour
      if (this.cache) {
        await this.cache.put(cacheKey, JSON.stringify(result), {
          expirationTtl: 3600
        });
      }

      return result;
    } catch (error: any) {
      throw new Error('Quick AI response failed');
    }
  }

  // Use Anthropic for complex tasks
  async complexResponse(
    messages: Message[],
    context: BusinessContext,
    maxTokens = 1000
  ): Promise<AIResponse> {
    const cacheKey = `ai:complex:${this.hashMessages(messages)}:${context.businessId}`;

    // Check cache first
    if (this.cache) {
      const cached = await this.cache.get(cacheKey, { type: 'json' });
      if (cached) {
        return {
          ...JSON.parse(cached as string) as AIResponse,
          cached: true
        };
      }
    }

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': this.anthropicKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-3-sonnet-20240229',
          messages,
          max_tokens: maxTokens,
          system: this.buildSystemPrompt(context),
          temperature: 0.3
        })
      });

      if (!response.ok) {
        throw new Error(`Anthropic API error: ${response.status}`);
      }

      const data = await response.json() as AnthropicResponse;

      const result: AIResponse = {
        content: data.content?.[0]?.text || '',
        model: 'claude-3-sonnet',
        tokens: data.usage?.output_tokens || 0,
        cost: this.calculateAnthropicCost(data.usage?.input_tokens || 0, data.usage?.output_tokens || 0)
      };

      // Cache for 30 minutes
      if (this.cache) {
        await this.cache.put(cacheKey, JSON.stringify(result), {
          expirationTtl: 1800
        });
      }

      return result;
    } catch (error: any) {
      throw new Error('Complex AI response failed');
    }
  }

  // Embeddings for semantic search
  async generateEmbedding(text: string): Promise<number[]> {
    const cacheKey = `ai:embed:${this.hashPrompt(text)}`;

    // Check cache first
    if (this.cache) {
      const cached = await this.cache.get(cacheKey, { type: 'json' });
      if (cached) {
        return JSON.parse(cached as string) as number[];
      }
    }

    try {
      const response = await this.ai.run(
        '@cf/baai/bge-base-en-v1.5',
        { text }
      ) as { data: number[][] };

      const embedding = response.data?.[0] || [];

      // Cache embeddings for 24 hours
      if (this.cache) {
        await this.cache.put(cacheKey, JSON.stringify(embedding), {
          expirationTtl: 86400
        });
      }

      return embedding;
    } catch (error: any) {
      throw new Error('Embedding generation failed');
    }
  }

  // Cost-optimized routing with business intelligence
  async route(request: AIRequest): Promise<AIResponse> {
    const complexity = request.complexity || this.detectComplexity(request);

    try {
      // Simple queries -> Workers AI (free)
      if (complexity === 'simple') {
        return await this.quickResponse(request.prompt, request.maxTokens);
      }

      // Complex queries -> Anthropic
      if (complexity === 'complex') {
        const messages: Message[] = request.messages || [{ role: 'user' as const, content: request.prompt }];
        return await this.complexResponse(messages, request.context, request.maxTokens);
      }

      // Auto-detect fallback
      if (request.prompt.length < 500 && !this.requiresComplexReasoning(request.prompt)) {
        try {
          return await this.quickResponse(request.prompt, request.maxTokens);
        } catch (error: any) {
          // Fallback to Anthropic on Workers AI failure
          const messages = [{ role: 'user' as const, content: request.prompt }];
          return await this.complexResponse(messages, request.context, request.maxTokens);
        }
      } else {
        const messages: Message[] = request.messages || [{ role: 'user' as const, content: request.prompt }];
        return await this.complexResponse(messages, request.context, request.maxTokens);
      }
    } catch (error: any) {
      throw new Error('AI service unavailable');
    }
  }

  // Business-aware chat with context
  async businessChat(
    message: string,
    context: BusinessContext,
    conversationHistory: Message[] = []
  ): Promise<AIResponse> {
    const messages: Message[] = [
      ...conversationHistory,
      { role: 'user', content: message }
    ];

    // Use complex routing for business chat
    return await this.complexResponse(messages, context);
  }

  // Document analysis and summarization
  async analyzeDocument(
    content: string,
    analysisType: 'summary' | 'insights' | 'action_items' | 'compliance',
    context: BusinessContext
  ): Promise<AIResponse> {
    const prompt = this.buildDocumentAnalysisPrompt(content, analysisType, context);

    // Always use Anthropic for document analysis
    return await this.complexResponse(
      [{ role: 'user', content: prompt }],
      context,
      1500
    );
  }

  // Data insights and reporting
  async generateInsights(
    data: any,
    insightType: 'financial' | 'operational' | 'performance' | 'predictive',
    context: BusinessContext
  ): Promise<AIResponse> {
    const prompt = this.buildInsightsPrompt(data, insightType, context);

    return await this.complexResponse(
      [{ role: 'user', content: prompt }],
      context,
      1200
    );
  }

  // Helper methods
  private detectComplexity(request: AIRequest): 'simple' | 'complex' {
    const prompt = request.prompt;

    // Complex if requires reasoning, analysis, or business context
    if (this.requiresComplexReasoning(prompt)) {
      return 'complex';
    }

    // Complex if has conversation history
    if (request.messages && request.messages.length > 1) {
      return 'complex';
    }

    // Complex if long prompt
    if (prompt.length > 500) {
      return 'complex';
    }

    return 'simple';
  }

  private requiresComplexReasoning(prompt: string): boolean {
    const complexKeywords = [
      'analyze', 'compare', 'explain', 'strategy', 'recommendation',
      'business', 'financial', 'report', 'insight', 'trend',
      'calculate', 'forecast', 'plan', 'optimize', 'evaluate'
    ];

    const lowerPrompt = prompt.toLowerCase();
    return complexKeywords.some(keyword => lowerPrompt.includes(keyword));
  }

  private buildSystemPrompt(context: BusinessContext): string {
    return `You are an AI assistant for ${context.businessId}.
Industry: ${context.industry || 'General Business'}
Preferences: ${JSON.stringify(context.preferences || {})}

Provide helpful, accurate, and business-focused responses.
Consider the business context in your answers.`;
  }

  private buildDocumentAnalysisPrompt(
    content: string,
    analysisType: string,
    context: BusinessContext
  ): string {
    const prompts = {
      summary: 'Provide a concise summary of this document:',
      insights: 'Extract key business insights from this document:',
      action_items: 'Identify action items and next steps from this document:',
      compliance: 'Review this document for compliance and regulatory considerations:'
    };

    return `${(prompts as any)[analysisType] || prompts.summary}

Business Context: ${context.businessId} (${context.industry || 'General'})

Document Content:
${content}

Please provide a structured analysis relevant to this business.`;
  }

  private buildInsightsPrompt(
    data: any,
    insightType: string,
    context: BusinessContext
  ): string {
    return `Generate ${insightType} insights for ${context.businessId} based on this data:

${JSON.stringify(data, null, 2)}

Provide actionable insights and recommendations.`;
  }

  private formatPromptForWorkers(prompt: string): string {
    // Format prompt for better Workers AI performance
    return `Human: ${prompt}\n\nAssistant: I'll help you with that.`;
  }

  private calculateAnthropicCost(inputTokens: number, outputTokens: number): number {
    // Claude 3 Sonnet pricing (approximate)
    const inputCostPer1K = 0.003;
    const outputCostPer1K = 0.015;

    return (inputTokens / 1000 * inputCostPer1K) + (outputTokens / 1000 * outputCostPer1K);
  }

  private hashPrompt(text: string): string {
    // Simple hash for cache keys
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  }

  private hashMessages(messages: Message[]): string {
    const combined = messages.map((m: any) => `${m.role}:${m.content}`).join('|');
    return this.hashPrompt(combined);
  }

  // Health check for AI services
  async healthCheck(): Promise<{
    workersAI: boolean;
    anthropic: boolean;
    embeddings: boolean;
  }> {
    const results = {
      workersAI: false,
      anthropic: false,
      embeddings: false
    };

    try {
      await this.ai.run('@cf/meta/llama-2-7b-chat-int8', {
        prompt: 'test',
        max_tokens: 1
      });
      results.workersAI = true;
    } catch (error: any) {
    }

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': this.anthropicKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-3-sonnet-20240229',
          messages: [{ role: 'user', content: 'test' }],
          max_tokens: 1
        })
      });
      results.anthropic = response.ok;
    } catch (error: any) {
    }

    try {
      await this.ai.run('@cf/baai/bge-base-en-v1.5', { text: 'test' });
      results.embeddings = true;
    } catch (error: any) {
    }

    return results;
  }
}

// Factory function
export function createAIService(
  ai: Ai,
  anthropicKey: string,
  cache?: KVNamespace
): AIService {
  return new AIService(ai, anthropicKey, cache);
}