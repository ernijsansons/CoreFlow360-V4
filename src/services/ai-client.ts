// CoreFlow360 V4 - AI Client Service
import type { Env } from '../types/env';

export class AIClient {
  private ai: Ai;
  private env: Env;
  private requestQueue: Array<() => Promise<any>> = [];
  private isProcessing = false;
  private readonly MAX_CONCURRENT_REQUESTS = 3;
  private readonly REQUEST_TIMEOUT = 30000; // 30 seconds

  constructor(env: Env) {
    this.ai = env.AI;
    this.env = env;
  }

  // Static method to get a singleton instance
  private static instance: AIClient | null = null;
  
  static getInstance(env: Env): AIClient {
    if (!AIClient.instance) {
      AIClient.instance = new AIClient(env);
    }
    return AIClient.instance;
  }

  private async processQueue(): Promise<void> {
    if (this.isProcessing || this.requestQueue.length === 0) {
      return;
    }

    this.isProcessing = true;
    
    try {
      const batch = this.requestQueue.splice(0, this.MAX_CONCURRENT_REQUESTS);
      await Promise.allSettled(batch.map((request: any) => request()));
    } finally {
      this.isProcessing = false;
      
      // Continue processing if there are more requests
      if (this.requestQueue.length > 0) {
        setImmediate(() => this.processQueue());
      }
    }
  }

  private async queueRequest<T>(requestFn: () => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error('AI request timeout'));
      }, this.REQUEST_TIMEOUT);

      const wrappedRequest = async () => {
        try {
          const result = await requestFn();
          clearTimeout(timeoutId);
          resolve(result);
        } catch (error: any) {
          clearTimeout(timeoutId);
          reject(error);
        }
      };

      this.requestQueue.push(wrappedRequest);
      this.processQueue();
    });
  }

  async generateText(prompt: string, options?: {
    model?: string;
    maxTokens?: number;
    temperature?: number;
    stream?: boolean;
  }): Promise<string> {
    return this.queueRequest(async () => {
      try {
        const response = await this.ai.run('@cf/meta/llama-3.1-8b-instruct', {
          prompt,
          max_tokens: Math.min(options?.maxTokens || 2048, 4096), // Limit token usage
          temperature: options?.temperature || 0.7,
          stream: options?.stream || false,
        });

        if (typeof response.response === 'string') {
          return response.response;
        }

        // Handle different response formats
        if (response.response && typeof response.response === 'object') {
          return JSON.stringify(response.response);
        }

        return String(response.response || '');

      } catch (error: any) {
        throw new Error(`AI generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });
  }

  async parseJSONResponse(prompt: string): Promise<any> {
    try {
      const response = await this.generateText(prompt
        + '\n\nReturn only valid JSON without any explanation or markdown formatting.');

      // Clean up the response to extract JSON
      let jsonStr = response.trim();

      // Remove markdown code blocks if present
      if (jsonStr.startsWith('```json')) {
        jsonStr = jsonStr.slice(7);
      }
      if (jsonStr.startsWith('```')) {
        jsonStr = jsonStr.slice(3);
      }
      if (jsonStr.endsWith('```')) {
        jsonStr = jsonStr.slice(0, -3);
      }

      // Remove any leading/trailing whitespace
      jsonStr = jsonStr.trim();

      // Try to parse the JSON
      return JSON.parse(jsonStr);

    } catch (error: any) {
      throw new Error(`JSON parsing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async generateStructuredResponse<T>(
    prompt: string,
    schema: any,
    options?: {
      model?: string;
      maxTokens?: number;
      temperature?: number;
    }
  ): Promise<T> {
    try {
      const schemaPrompt = `You must respond with valid JSON that matches this schema:
${JSON.stringify(schema, null, 2)}

${prompt}

Return only valid JSON without any explanation or markdown formatting.`;

      const response = await this.generateText(schemaPrompt, options);
      const parsed = await this.parseJSONResponse(schemaPrompt);
      
      return parsed as T;

    } catch (error: any) {
      throw new Error(`Structured response generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async generateCode(
    prompt: string,
    language: string,
    options?: {
      model?: string;
      maxTokens?: number;
      temperature?: number;
    }
  ): Promise<string> {
    try {
      const codePrompt = `Generate ${language} code for the following request:

${prompt}

Return only the code without any explanation or markdown formatting.`;

      const response = await this.generateText(codePrompt, options);
      
      // Clean up the response to extract code
      let code = response.trim();

      // Remove markdown code blocks if present
      if (code.startsWith(`\`\`\`${language}`)) {
        code = code.slice(language.length + 3);
      }
      if (code.startsWith('```')) {
        code = code.slice(3);
      }
      if (code.endsWith('```')) {
        code = code.slice(0, -3);
      }

      return code.trim();

    } catch (error: any) {
      throw new Error(`Code generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async generateDocumentation(
    code: string,
    language: string,
    options?: {
      model?: string;
      maxTokens?: number;
      temperature?: number;
    }
  ): Promise<string> {
    try {
      const docPrompt = `Generate documentation for the following ${language} code:

\`\`\`${language}
${code}
\`\`\`

Return comprehensive documentation including:
- Overview of what the code does
- Function/class descriptions
- Parameter explanations
- Usage examples
- Any important notes or warnings

Format the documentation in Markdown.`;

      return await this.generateText(docPrompt, options);

    } catch (error: any) {
      throw new Error(`Documentation generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async generateTests(
    code: string,
    language: string,
    testFramework: string,
    options?: {
      model?: string;
      maxTokens?: number;
      temperature?: number;
    }
  ): Promise<string> {
    try {
      const testPrompt = `Generate ${testFramework} tests for the following ${language} code:

\`\`\`${language}
${code}
\`\`\`

Return comprehensive tests including:
- Unit tests for all functions/methods
- Edge cases and error conditions
- Mock objects where appropriate
- Test data and fixtures
- Clear test descriptions

Format the tests in ${language} using ${testFramework}.`;

      return await this.generateText(testPrompt, options);

    } catch (error: any) {
      throw new Error(`Test generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async analyzeCode(
    code: string,
    language: string,
    options?: {
      model?: string;
      maxTokens?: number;
      temperature?: number;
    }
  ): Promise<{
    issues: Array<{
      type: 'error' | 'warning' | 'suggestion';
      message: string;
      line?: number;
      column?: number;
    }>;
    suggestions: string[];
    complexity: 'low' | 'medium' | 'high';
    maintainability: 'low' | 'medium' | 'high';
  }> {
    try {
      const analysisPrompt = `Analyze the following ${language} code and provide a comprehensive analysis:

\`\`\`${language}
${code}
\`\`\`

Return a JSON response with:
- issues: Array of issues found (errors, warnings, suggestions)
- suggestions: Array of improvement suggestions
- complexity: Overall complexity level (low/medium/high)
- maintainability: Maintainability score (low/medium/high)

Format as valid JSON.`;

      const response = await this.generateText(analysisPrompt, options);
      return await this.parseJSONResponse(analysisPrompt);

    } catch (error: any) {
      throw new Error(`Code analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async generateSummary(
    text: string,
    maxLength: number = 200,
    options?: {
      model?: string;
      maxTokens?: number;
      temperature?: number;
    }
  ): Promise<string> {
    try {
      const summaryPrompt = `Summarize the following text in ${maxLength} words or less:

${text}

Return only the summary without any introduction or explanation.`;

      return await this.generateText(summaryPrompt, options);

    } catch (error: any) {
      throw new Error(`Summary generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async translateText(
    text: string,
    targetLanguage: string,
    sourceLanguage?: string,
    options?: {
      model?: string;
      maxTokens?: number;
      temperature?: number;
    }
  ): Promise<string> {
    try {
      const translatePrompt = `Translate the following text${sourceLanguage ? ` from ${sourceLanguage}` : ''} to ${targetLanguage}:

${text}

Return only the translation without any explanation or formatting.`;

      return await this.generateText(translatePrompt, options);

    } catch (error: any) {
      throw new Error(`Translation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async generateEmbedding(
    text: string,
    options?: {
      model?: string;
      dimensions?: number;
    }
  ): Promise<number[]> {
    try {
      // This would typically use a dedicated embedding model
      // For now, we'll use a simple text generation approach
      const embeddingPrompt = `Generate a numerical embedding for the following text:

${text}

Return only a JSON array of numbers representing the embedding.`;

      const response = await this.generateText(embeddingPrompt, {
        ...options,
        maxTokens: 1000,
        temperature: 0.1,
      });

      const parsed = await this.parseJSONResponse(embeddingPrompt);
      return Array.isArray(parsed) ? parsed : [];

    } catch (error: any) {
      throw new Error(`Embedding generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async generateChatResponse(
    messages: Array<{
      role: 'system' | 'user' | 'assistant';
      content: string;
    }>,
    options?: {
      model?: string;
      maxTokens?: number;
      temperature?: number;
      stream?: boolean;
    }
  ): Promise<string> {
    try {
      // Convert messages to a single prompt
      const prompt = messages.map((msg: any) => {
        switch (msg.role) {
          case 'system':
            return `System: ${msg.content}`;
          case 'user':
            return `User: ${msg.content}`;
          case 'assistant':
            return `Assistant: ${msg.content}`;
          default:
            return msg.content;
        }
      }).join('\n\n');

      return await this.generateText(prompt, options);

    } catch (error: any) {
      throw new Error(`Chat response generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async generateImage(
    prompt: string,
    options?: {
      model?: string;
      size?: '256x256' | '512x512' | '1024x1024';
      quality?: 'standard' | 'hd';
      style?: 'vivid' | 'natural';
    }
  ): Promise<string> {
    try {
      // This would typically use a dedicated image generation model
      // For now, we'll return a placeholder
      throw new Error('Image generation not implemented in this AI client');

    } catch (error: any) {
      throw new Error(`Image generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async moderateContent(
    text: string,
    options?: {
      model?: string;
      categories?: string[];
    }
  ): Promise<{
    flagged: boolean;
    categories: string[];
    confidence: number;
    details: string;
  }> {
    try {
      const moderationPrompt = `Moderate the following content for inappropriate or harmful material:

${text}

Return a JSON response with:
- flagged: boolean indicating if content is flagged
- categories: array of flagged categories
- confidence: confidence score (0-1)
- details: explanation of the moderation decision

Format as valid JSON.`;

      const response = await this.generateText(moderationPrompt, {
        ...options,
        maxTokens: 500,
        temperature: 0.1,
      });

      return await this.parseJSONResponse(moderationPrompt);

    } catch (error: any) {
      throw new Error(`Content moderation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getModelInfo(model: string): Promise<{
    name: string;
    description: string;
    capabilities: string[];
    maxTokens: number;
    supportedLanguages: string[];
  }> {
    try {
      // This would typically query model metadata
      // For now, we'll return mock data
      return {
        name: model,
        description: 'AI model for text generation and analysis',
        capabilities: ['text-generation', 'code-generation', 'analysis', 'translation'],
        maxTokens: 2048,
        supportedLanguages: ['en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko'],
      };

    } catch (error: any) {
      throw new Error(`Model info retrieval failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getUsageStats(): Promise<{
    totalRequests: number;
    totalTokens: number;
    totalCost: number;
    averageLatency: number;
    errorRate: number;
  }> {
    try {
      // This would typically query usage statistics
      // For now, we'll return mock data
      return {
        totalRequests: 0,
        totalTokens: 0,
        totalCost: 0,
        averageLatency: 0,
        errorRate: 0,
      };

    } catch (error: any) {
      throw new Error(`Usage stats retrieval failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

// Export the getAIClient function for backward compatibility
export function getAIClient(env: Env): AIClient {
  return AIClient.getInstance(env);
}

