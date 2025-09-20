/**
 * SSE Module Exports
 * Central entry point for Server-Sent Events functionality
 */

// Core SSE infrastructure
export { SSEStreamManager } from './stream-manager';
export { SSEStreamController } from './stream-controller';
export { AIStreamAdapter, AnthropicProvider, OpenAIProvider } from './ai-stream-adapter';
export { StreamMetricsCollector } from './stream-metrics';

// Type definitions
export type {
  SSEEventType,
  SSEEvent,
  StreamStartData,
  TokenData,
  ChunkData,
  FunctionCallData,
  FunctionResultData,
  StreamEndData,
  ErrorData,
  HeartbeatData,
  MetadataData,
  StreamStartEvent,
  TokenEvent,
  ChunkEvent,
  FunctionCallEvent,
  FunctionResultEvent,
  StreamEndEvent,
  ErrorEvent,
  HeartbeatEvent,
  MetadataEvent,
  AnySSEEvent,
  SSEStreamConfig,
  StreamState,
  StreamManagerState,
  BackpressureStrategy,
  BackpressureConfig,
  ErrorRecoveryConfig,
  StreamMetrics,
  AIProvider,
  StreamEventHandler,
  ConnectionQuality,
  StreamAnalytics
} from './types';

// Default configuration
export { DEFAULT_SSE_CONFIG } from './types';

// Validation schemas
export { StreamConfigSchema, SSEEventSchema } from './types';

/**
 * SSE Module factory function for easy initialization
 */
export class SSEModule {
  private streamManager?: SSEStreamManager;
  private aiAdapter?: AIStreamAdapter;
  private metricsCollector?: StreamMetricsCollector;

  /**
   * Initialize SSE module with KV storage
   */
  static async create(kv: any): Promise<SSEModule> {
    const module = new SSEModule();
    await module.initialize(kv);
    return module;
  }

  /**
   * Initialize the module
   */
  private async initialize(kv: any): Promise<void> {
    this.streamManager = new SSEStreamManager(kv);
    this.aiAdapter = new AIStreamAdapter();
    this.metricsCollector = new StreamMetricsCollector();

    // Register AI providers if API keys are available
    const anthropicKey = process.env.ANTHROPIC_API_KEY;
    const openaiKey = process.env.OPENAI_API_KEY;

    if (anthropicKey) {
      const { AnthropicProvider } = await import('./ai-stream-adapter');
      this.aiAdapter.registerProvider('anthropic', new AnthropicProvider(anthropicKey));
    }

    if (openaiKey) {
      const { OpenAIProvider } = await import('./ai-stream-adapter');
      this.aiAdapter.registerProvider('openai', new OpenAIProvider(openaiKey));
    }
  }

  /**
   * Get the stream manager
   */
  getStreamManager(): SSEStreamManager {
    if (!this.streamManager) {
      throw new Error('SSE module not initialized');
    }
    return this.streamManager;
  }

  /**
   * Get the AI adapter
   */
  getAIAdapter(): AIStreamAdapter {
    if (!this.aiAdapter) {
      throw new Error('SSE module not initialized');
    }
    return this.aiAdapter;
  }

  /**
   * Get the metrics collector
   */
  getMetricsCollector(): StreamMetricsCollector {
    if (!this.metricsCollector) {
      throw new Error('SSE module not initialized');
    }
    return this.metricsCollector;
  }

  /**
   * Create an AI response stream
   */
  async createAIStream(request: {
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
    };
  }): Promise<Response> {
    if (!this.aiAdapter) {
      throw new Error('SSE module not initialized');
    }

    const result = await this.aiAdapter.createAIStream(request);

    // Start collecting metrics for this stream
    if (this.metricsCollector) {
      // Metrics will be recorded by the stream controller
    }

    return result.response;
  }

  /**
   * Get system health and metrics
   */
  getSystemHealth() {
    if (!this.streamManager) {
      throw new Error('SSE module not initialized');
    }
    return this.streamManager.getSystemHealth();
  }

  /**
   * Get aggregated metrics
   */
  getMetrics() {
    if (!this.metricsCollector) {
      throw new Error('SSE module not initialized');
    }
    return this.metricsCollector.getAggregatedMetrics();
  }

  /**
   * Export metrics for monitoring
   */
  exportMetrics(format: 'prometheus' | 'json' | 'csv' = 'json'): string {
    if (!this.metricsCollector) {
      throw new Error('SSE module not initialized');
    }
    return this.metricsCollector.exportMetrics(format);
  }

  /**
   * Cleanup and shutdown
   */
  async destroy(): Promise<void> {
    if (this.streamManager) {
      await this.streamManager.destroy();
    }

    this.streamManager = undefined;
    this.aiAdapter = undefined;
    this.metricsCollector = undefined;
  }
}