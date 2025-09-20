/**
 * AI Stream Adapter for integrating AI providers with SSE streaming
 * Provides unified interface for different AI services
 */

import {
  AIProvider,
  StreamStartData,
  TokenData,
  FunctionCallData,
  FunctionResultData,
  StreamEndData,
  ErrorData,
  SSEStreamConfig
} from './types';
import { SSEStreamController } from './stream-controller';
import { Logger } from '../../shared/logger';
import { SecurityError, InputValidator } from '../../shared/security-utils';

interface AIStreamRequest {
  prompt: string;
  model: string;
  businessId: string;
  userId: string;
  correlationId: string;
  options?: {
    temperature?: number;
    maxTokens?: number;
    stopSequences?: string[];
    systemPrompt?: string;
    functions?: Array<{
      name: string;
      description: string;
      parameters: Record<string, unknown>;
    }>;
  };
}

interface AIStreamResponse {
  streamId: string;
  response: Response;
  controller: SSEStreamController;
}

export class AIStreamAdapter {
  private logger: Logger;
  private providers: Map<string, AIProvider> = new Map();

  constructor() {
    this.logger = new Logger();
    this.initializeProviders();
  }

  /**
   * Creates AI response stream with SSE
   */
  async createAIStream(request: AIStreamRequest): Promise<AIStreamResponse> {
    // Validate inputs
    const validatedPrompt = InputValidator.validateAndSanitize(request.prompt, 'prompt');
    const validatedModel = InputValidator.validateResourceId(request.model, 'model');

    if (!validatedPrompt || validatedPrompt.length === 0) {
      throw new SecurityError('Invalid or empty prompt', {
        code: 'INVALID_PROMPT',
        correlationId: request.correlationId
      });
    }

    // Get AI provider for model
    const provider = this.getProviderForModel(validatedModel);
    if (!provider) {
      throw new SecurityError('Unsupported AI model', {
        code: 'UNSUPPORTED_MODEL',
        model: validatedModel,
        correlationId: request.correlationId
      });
    }

    // Create SSE stream configuration
    const streamConfig: SSEStreamConfig = {
      streamId: this.generateStreamId(),
      userId: request.userId,
      businessId: request.businessId,
      correlationId: request.correlationId,
      firstTokenTimeout: 150, // 150ms target
      heartbeatInterval: 15000, // 15s
      maxStreamDuration: 300000, // 5 minutes
      bufferSize: 1024,
      maxRetries: 3,
      retryBackoffMs: 1000,
      errorRecoveryMode: 'reconnect',
      maxConcurrentStreams: 5,
      streamPriority: 'normal',
      enableHeartbeat: true,
      enableBackpressure: true,
      enableCompression: false,
      enableMetrics: true
    };

    // Create stream controller
    const streamState = {
      streamId: streamConfig.streamId,
      status: 'starting' as const,
      startTime: Date.now(),
      lastActivityTime: Date.now(),
      tokenCount: 0,
      chunkCount: 0,
      errorCount: 0,
      retryCount: 0,
      bytesTransferred: 0,
      averageTokenTime: 0,
      tokensPerSecond: 0,
      clientInfo: {
        userAgent: 'CoreFlow360-AI-Stream',
        ipAddress: '127.0.0.1', // Will be replaced with actual client IP
        connectionId: streamConfig.streamId
      },
      bufferUsage: 0,
      droppedEvents: 0,
      lastHeartbeat: Date.now(),
      missedHeartbeats: 0
    };

    const controller = new SSEStreamController(streamConfig, streamState, null);

    // Start AI provider streaming
    const abortController = new AbortController();

    try {
      const aiStream = await provider.stream({
        prompt: validatedPrompt,
        model: validatedModel,
        options: {
          ...request.options,
          temperature: request.options?.temperature ?? 0.7,
          maxTokens: request.options?.maxTokens ?? 4096
        },
        onToken: async (token: string, position?: number) => {
          await controller.sendToken(token, position ?? 0);
        },
        onChunk: async (chunk: string, position?: number) => {
          await controller.sendChunk(chunk, position ?? 0);
        },
        onFunctionCall: async (call: FunctionCallData) => {
          // Function calls not implemented in this phase
          this.logger.info('Function call received', {
            functionName: call.name,
            streamId: streamConfig.streamId,
            correlationId: request.correlationId
          });
        },
        onComplete: async (result: StreamEndData) => {
          await controller.endStream('complete');
        },
        onError: async (error: ErrorData) => {
          await controller.sendError(new Error(error.message), error.retryable);
        },
        signal: abortController.signal
      });

      // Create response with SSE headers
      const response = new Response(controller.createStream(), {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Correlation-ID',
          'X-Stream-ID': streamConfig.streamId,
          'X-Correlation-ID': request.correlationId
        }
      });

      this.logger.info('AI stream created', {
        streamId: streamConfig.streamId,
        model: validatedModel,
        userId: request.userId,
        businessId: request.businessId,
        correlationId: request.correlationId
      });

      return {
        streamId: streamConfig.streamId,
        response,
        controller
      };

    } catch (error) {
      abortController.abort();
      await controller.sendError(error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  /**
   * Registers an AI provider
   */
  registerProvider(name: string, provider: AIProvider): void {
    this.providers.set(name, provider);
    this.logger.info('AI provider registered', {
      provider: name,
      supportsStreaming: provider.supportsStreaming,
      supportsFunction: provider.supportsFunction,
      maxTokens: provider.maxTokens
    });
  }

  /**
   * Gets provider for specific model
   */
  private getProviderForModel(model: string): AIProvider | undefined {
    // Simple model-to-provider mapping (can be made configurable)
    if (model.startsWith('claude-')) {
      return this.providers.get('anthropic');
    } else if (model.startsWith('gpt-')) {
      return this.providers.get('openai');
    } else if (model.startsWith('gemini-')) {
      return this.providers.get('google');
    }

    return this.providers.get('default');
  }

  /**
   * Initializes default AI providers
   */
  private initializeProviders(): void {
    // Mock provider for development/testing
    const mockProvider: AIProvider = {
      name: 'mock',
      supportsStreaming: true,
      supportsFunction: false,
      maxTokens: 4096,

      async stream(params) {
        const { onToken, onComplete, onError, signal } = params;

        return new ReadableStream<Uint8Array>({
          start: async (controller) => {
            try {
              // Simulate AI response streaming
              const response = `This is a mock AI response to: "${params.prompt}". `;
              const words = response.split(' ');

              for (let i = 0; i < words.length; i++) {
                if (signal?.aborted) break;

                const token = words[i] + (i < words.length - 1 ? ' ' : '');
                await onToken?.(token, i);

                // Simulate realistic streaming delay
                await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 100));
              }

              await onComplete?.({
                streamId: 'mock-stream',
                reason: 'complete',
                totalTokens: words.length,
                totalTime: Date.now(),
                tokensPerSecond: words.length / 2
              });

              controller.close();
            } catch (error) {
              await onError?.({
                code: 'MOCK_ERROR',
                message: error instanceof Error ? error.message : String(error),
                retryable: true,
                correlationId: 'mock-correlation'
              });
              controller.error(error);
            }
          }
        });
      }
    };

    this.registerProvider('mock', mockProvider);
    this.registerProvider('default', mockProvider);
  }

  /**
   * Generates unique stream ID
   */
  private generateStreamId(): string {
    return `stream-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

/**
 * Anthropic Claude provider implementation
 */
export class AnthropicProvider implements AIProvider {
  name = 'anthropic';
  supportsStreaming = true;
  supportsFunction = true;
  maxTokens = 100000;

  constructor(private apiKey: string) {}

  async stream(params: Parameters<AIProvider['stream']>[0]): Promise<ReadableStream<Uint8Array>> {
    const { prompt, model, options, onToken, onComplete, onError, signal } = params;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: model || 'claude-3-sonnet-20240229',
        max_tokens: options?.maxTokens || 4096,
        temperature: options?.temperature || 0.7,
        messages: [{ role: 'user', content: prompt }],
        stream: true
      }),
      signal
    });

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status} ${response.statusText}`);
    }

    return new ReadableStream<Uint8Array>({
      start: async (controller) => {
        try {
          const reader = response.body?.getReader();
          if (!reader) throw new Error('No response body');

          let position = 0;
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            // Parse SSE data from Anthropic
            const chunk = new TextDecoder().decode(value);
            const lines = chunk.split('\n');

            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const data = line.slice(6);
                if (data === '[DONE]') {
                  await onComplete?.({
                    streamId: 'anthropic-stream',
                    reason: 'complete',
                    totalTokens: position,
                    totalTime: Date.now(),
                    tokensPerSecond: position / 2
                  });
                  controller.close();
                  return;
                }

                try {
                  const parsed = JSON.parse(data);
                  if (parsed.type === 'content_block_delta' && parsed.delta?.text) {
                    await onToken?.(parsed.delta.text, position++);
                  }
                } catch (e) {
                  // Ignore parse errors for non-JSON lines
                }
              }
            }

            controller.enqueue(value);
          }
        } catch (error) {
          await onError?.({
            code: 'ANTHROPIC_ERROR',
            message: error instanceof Error ? error.message : String(error),
            retryable: true,
            correlationId: 'anthropic-correlation'
          });
          controller.error(error);
        }
      }
    });
  }
}

/**
 * OpenAI GPT provider implementation
 */
export class OpenAIProvider implements AIProvider {
  name = 'openai';
  supportsStreaming = true;
  supportsFunction = true;
  maxTokens = 128000;

  constructor(private apiKey: string) {}

  async stream(params: Parameters<AIProvider['stream']>[0]): Promise<ReadableStream<Uint8Array>> {
    const { prompt, model, options, onToken, onComplete, onError, signal } = params;

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`
      },
      body: JSON.stringify({
        model: model || 'gpt-4',
        max_tokens: options?.maxTokens || 4096,
        temperature: options?.temperature || 0.7,
        messages: [{ role: 'user', content: prompt }],
        stream: true
      }),
      signal
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
    }

    return new ReadableStream<Uint8Array>({
      start: async (controller) => {
        try {
          const reader = response.body?.getReader();
          if (!reader) throw new Error('No response body');

          let position = 0;
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            // Parse SSE data from OpenAI
            const chunk = new TextDecoder().decode(value);
            const lines = chunk.split('\n');

            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const data = line.slice(6);
                if (data === '[DONE]') {
                  await onComplete?.({
                    streamId: 'openai-stream',
                    reason: 'complete',
                    totalTokens: position,
                    totalTime: Date.now(),
                    tokensPerSecond: position / 2
                  });
                  controller.close();
                  return;
                }

                try {
                  const parsed = JSON.parse(data);
                  const delta = parsed.choices?.[0]?.delta?.content;
                  if (delta) {
                    await onToken?.(delta, position++);
                  }
                } catch (e) {
                  // Ignore parse errors for non-JSON lines
                }
              }
            }

            controller.enqueue(value);
          }
        } catch (error) {
          await onError?.({
            code: 'OPENAI_ERROR',
            message: error instanceof Error ? error.message : String(error),
            retryable: true,
            correlationId: 'openai-correlation'
          });
          controller.error(error);
        }
      }
    });
  }
}