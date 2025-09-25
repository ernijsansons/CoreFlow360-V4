/**
 * Secure AI Client Service
 * Handles all AI interactions without exposing API keys
 * Uses Cloudflare Workers AI for security and performance
 */

import type { Env } from '../types/env';

interface AIResponse {
  response: string;
  confidence?: number;
  usage?: {
    promptTokens: number;
    completionTokens: number;
  };
}

interface AIRequest {
  prompt: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  systemPrompt?: string;
}

export class SecureAIClient {
  private env: Env;
  private requestCount = 0;
  private lastReset = Date.now();
  private readonly MAX_REQUESTS_PER_MINUTE = 60;

  constructor(env: Env) {
    this.env = env;
  }

  /**
   * Main AI call method with rate limiting and error handling
   */
  async callAI(request: AIRequest): Promise<string> {
    // Rate limiting
    await this.checkRateLimit();

    try {
      // Use Cloudflare Workers AI for secure processing
      const response = await this.executeAICall(request);

      // Log usage for monitoring (without sensitive data)
      await this.logUsage(request.prompt.length, response.length);

      return response;
    } catch (error) {
      throw new Error('AI service temporarily unavailable');
    }
  }

  /**
   * Execute AI call with Cloudflare Workers AI
   */
  private async executeAICall(request: AIRequest): Promise<string> {
    const { prompt, temperature = 0.4, maxTokens = 2000 } = request;

    // Use Cloudflare AI (no API key needed)
    if (this.env.AI) {
      const result = await this.env.AI.run('@cf/meta/llama-2-7b-chat-int8', {
        prompt: this.formatPrompt(request),
        temperature,
        max_tokens: maxTokens,
      });

      return this.extractResponse(result);
    }

    // Fallback to API with secure key management
    return await this.fallbackToAPI(request);
  }

  /**
   * Fallback to external API if Cloudflare AI is not available
   */
  private async fallbackToAPI(request: AIRequest): Promise<string> {
    // Only use API key from environment, never hardcode
    const apiKey = this.env.ANTHROPIC_API_KEY;

    if (!apiKey) {
      throw new Error('AI service not configured');
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: request.model || 'claude-3-haiku-20240307',
        max_tokens: request.maxTokens || 2000,
        messages: [{
          role: 'user',
          content: this.formatPrompt(request)
        }],
        temperature: request.temperature || 0.4
      })
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }

    const result = await response.json() as any;
    return this.extractAnthropicResponse(result);
  }

  /**
   * Format prompt with system instructions
   */
  private formatPrompt(request: AIRequest): string {
    if (request.systemPrompt) {
      return `${request.systemPrompt}\n\nUser: ${request.prompt}`;
    }
    return request.prompt;
  }

  /**
   * Extract response from AI result
   */
  private extractResponse(result: any): string {
    if (typeof result === 'string') {
      return result;
    }

    if (result.response) {
      return result.response;
    }

    if (result.choices?.[0]?.text) {
      return result.choices[0].text;
    }

    return JSON.stringify(result);
  }

  /**
   * Extract response from Anthropic API
   */
  private extractAnthropicResponse(result: any): string {
    const content = result.content?.[0]?.text;

    if (!content) {
      throw new Error('Invalid API response');
    }

    // Extract JSON if present
    const jsonMatch = content.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
    return jsonMatch ? jsonMatch[0] : content;
  }

  /**
   * Rate limiting to prevent abuse
   */
  private async checkRateLimit(): Promise<void> {
    const now = Date.now();

    // Reset counter every minute
    if (now - this.lastReset > 60000) {
      this.requestCount = 0;
      this.lastReset = now;
    }

    this.requestCount++;

    if (this.requestCount > this.MAX_REQUESTS_PER_MINUTE) {
      const waitTime = 60000 - (now - this.lastReset);
      throw new Error(`Rate limit exceeded. Please wait ${Math.ceil(waitTime / 1000)} seconds.`);
    }
  }

  /**
   * Log usage for monitoring and billing
   */
  private async logUsage(promptLength: number, responseLength: number): Promise<void> {
    try {
      const usage = {
        timestamp: new Date().toISOString(),
        promptChars: promptLength,
        responseChars: responseLength,
        estimatedTokens: Math.ceil((promptLength + responseLength) / 4)
      };

      // Store in analytics database
      if (this.env.DB_ANALYTICS) {
        await this.env.DB_ANALYTICS.prepare(`
          INSERT INTO ai_usage (timestamp, prompt_chars, response_chars, estimated_tokens)
          VALUES (?, ?, ?, ?)
        `).bind(
          usage.timestamp,
          usage.promptChars,
          usage.responseChars,
          usage.estimatedTokens
        ).run();
      }
    } catch (error) {
      // Don't fail the request if logging fails
    }
  }

  /**
   * Sanitize error messages to remove sensitive data
   */
  private sanitizeError(error: any): any {
    if (!error) return error;

    const sanitized = {
      message: error.message || 'Unknown error',
      type: error.constructor.name
    };

    // Remove any API keys or sensitive data from error
    if (sanitized.message) {
      sanitized.message = sanitized.message
        .replace(/sk-[a-zA-Z0-9]+/g, '[API_KEY]')
        .replace(/Bearer [a-zA-Z0-9-._~+\/]+/g, 'Bearer [TOKEN]')
        .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[EMAIL]');
    }

    return sanitized;
  }

  /**
   * Parse JSON response safely
   */
  async parseJSONResponse(prompt: string): Promise<any> {
    const response = await this.callAI({ prompt });

    try {
      // Try to extract JSON from the response
      const jsonMatch = response.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }

      // If no JSON found, try to parse the entire response
      return JSON.parse(response);
    } catch (error) {
      // Return structured error response
      return {
        error: 'Failed to parse response',
        rawResponse: response.substring(0, 200) // Truncate for logging
      };
    }
  }

  /**
   * Specialized method for CRM analytics
   */
  async analyzeCRMData(data: any, analysisType: string): Promise<any> {
    const systemPrompt = `You are a CRM analytics expert. Analyze the provided data and return insights in JSON format.
    Focus on actionable recommendations and specific metrics.`;

    const prompt = `
      Analysis Type: ${analysisType}
      Data: ${JSON.stringify(data)}

      Provide analysis with:
      1. Key findings
      2. Actionable recommendations
      3. Risk factors
      4. Opportunities
      5. Metrics and KPIs
    `;

    return await this.parseJSONResponse(prompt);
  }

  /**
   * Specialized method for lead scoring
   */
  async scoreLead(leadData: any): Promise<{ score: number; factors: any }> {
    const prompt = `
      Score this lead from 0-100 based on:
      ${JSON.stringify(leadData)}

      Consider:
      - Company size and industry fit
      - Engagement level
      - Budget indicators
      - Timeline urgency
      - Decision-making authority

      Return JSON with:
      {
        "score": <number 0-100>,
        "factors": {
          "positive": [...],
          "negative": [...],
          "recommendations": [...]
        }
      }
    `;

    const result = await this.parseJSONResponse(prompt);

    // Ensure valid score
    if (typeof result.score !== 'number' || result.score < 0 || result.score > 100) {
      result.score = 50; // Default middle score
    }

    return result;
  }

  /**
   * Check if AI service is available
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.callAI({
        prompt: 'ping',
        maxTokens: 10
      });
      return response.length > 0;
    } catch {
      return false;
    }
  }
}

/**
 * Singleton instance management
 */
let aiClientInstance: SecureAIClient | null = null;

export function getAIClient(env: Env): SecureAIClient {
  if (!aiClientInstance) {
    aiClientInstance = new SecureAIClient(env);
  }
  return aiClientInstance;
}