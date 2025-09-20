/**
 * Server-Sent Events types for AI response streaming
 */

import { z } from 'zod';

/**
 * SSE Event types for AI responses
 */
export type SSEEventType =
  | 'stream_start'
  | 'token'
  | 'chunk'
  | 'function_call'
  | 'function_result'
  | 'stream_end'
  | 'error'
  | 'heartbeat'
  | 'retry'
  | 'metadata';

/**
 * Base SSE event structure
 */
export interface SSEEvent<T = unknown> {
  id: string;
  event: SSEEventType;
  data: T;
  timestamp: number;
  retry?: number;
}

/**
 * Stream start event data
 */
export interface StreamStartData {
  streamId: string;
  model: string;
  conversationId?: string;
  estimatedTokens?: number;
  maxTokens?: number;
  temperature?: number;
}

/**
 * Token streaming event data
 */
export interface TokenData {
  token: string;
  position: number;
  logprob?: number;
  isComplete: boolean;
  finishReason?: 'length' | 'stop' | 'function_call' | 'content_filter';
}

/**
 * Chunk streaming event data (for larger text blocks)
 */
export interface ChunkData {
  chunk: string;
  position: number;
  totalChunks?: number;
  encoding?: 'utf8' | 'base64';
}

/**
 * Function call event data
 */
export interface FunctionCallData {
  name: string;
  arguments: Record<string, unknown>;
  callId: string;
  timestamp: number;
}

/**
 * Function result event data
 */
export interface FunctionResultData {
  callId: string;
  result: unknown;
  error?: string;
  executionTime: number;
  timestamp: number;
}

/**
 * Stream end event data
 */
export interface StreamEndData {
  streamId: string;
  reason: 'complete' | 'stopped' | 'error' | 'timeout' | 'cancelled';
  totalTokens: number;
  totalTime: number;
  tokensPerSecond: number;
  firstTokenTime?: number;
}

/**
 * Error event data
 */
export interface ErrorData {
  code: string;
  message: string;
  retryable: boolean;
  retryAfter?: number;
  correlationId?: string;
  context?: Record<string, unknown>;
}

/**
 * Heartbeat event data
 */
export interface HeartbeatData {
  timestamp: number;
  uptime: number;
  activeStreams: number;
  serverHealth: 'healthy' | 'degraded' | 'unhealthy';
}

/**
 * Metadata event data
 */
export interface MetadataData {
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  model?: string;
  latency?: {
    firstToken: number;
    totalTime: number;
    tokensPerSecond: number;
  };
  quality?: {
    confidence: number;
    safety: boolean;
  };
}

/**
 * Typed SSE events
 */
export type StreamStartEvent = SSEEvent<StreamStartData>;
export type TokenEvent = SSEEvent<TokenData>;
export type ChunkEvent = SSEEvent<ChunkData>;
export type FunctionCallEvent = SSEEvent<FunctionCallData>;
export type FunctionResultEvent = SSEEvent<FunctionResultData>;
export type StreamEndEvent = SSEEvent<StreamEndData>;
export type ErrorEvent = SSEEvent<ErrorData>;
export type HeartbeatEvent = SSEEvent<HeartbeatData>;
export type MetadataEvent = SSEEvent<MetadataData>;

/**
 * Union type for all possible SSE events
 */
export type AnySSEEvent =
  | StreamStartEvent
  | TokenEvent
  | ChunkEvent
  | FunctionCallEvent
  | FunctionResultEvent
  | StreamEndEvent
  | ErrorEvent
  | HeartbeatEvent
  | MetadataEvent;

/**
 * SSE Stream configuration
 */
export interface SSEStreamConfig {
  streamId: string;
  userId: string;
  businessId: string;
  correlationId: string;

  // Performance settings
  firstTokenTimeout: number; // 150ms target
  heartbeatInterval: number; // 15s default
  maxStreamDuration: number; // Max time before forced close
  bufferSize: number; // Backpressure buffer size

  // Error handling
  maxRetries: number;
  retryBackoffMs: number;
  errorRecoveryMode: 'reconnect' | 'continue' | 'fail';

  // Concurrency
  maxConcurrentStreams: number;
  streamPriority: 'low' | 'normal' | 'high';

  // Feature flags
  enableHeartbeat: boolean;
  enableBackpressure: boolean;
  enableCompression: boolean;
  enableMetrics: boolean;
}

/**
 * Default SSE configuration
 */
export const DEFAULT_SSE_CONFIG: Omit<SSEStreamConfig, 'streamId' | 'userId' | 'businessId' | 'correlationId'> = {
  firstTokenTimeout: 150,
  heartbeatInterval: 15000,
  maxStreamDuration: 300000, // 5 minutes
  bufferSize: 1024, // 1KB buffer
  maxRetries: 3,
  retryBackoffMs: 1000,
  errorRecoveryMode: 'reconnect',
  maxConcurrentStreams: 5,
  streamPriority: 'normal',
  enableHeartbeat: true,
  enableBackpressure: true,
  enableCompression: false, // Can be enabled for large responses
  enableMetrics: true,
};

/**
 * Stream state tracking
 */
export interface StreamState {
  streamId: string;
  status: 'starting' | 'active' | 'paused' | 'ended' | 'error';
  startTime: number;
  firstTokenTime?: number;
  lastActivityTime: number;
  tokenCount: number;
  chunkCount: number;
  errorCount: number;
  retryCount: number;
  bytesTransferred: number;

  // Performance metrics
  averageTokenTime: number;
  tokensPerSecond: number;

  // Connection info
  clientInfo: {
    userAgent: string;
    ipAddress: string;
    connectionId: string;
  };

  // Backpressure info
  bufferUsage: number;
  droppedEvents: number;

  // Health metrics
  lastHeartbeat: number;
  missedHeartbeats: number;
}

/**
 * Stream manager state
 */
export interface StreamManagerState {
  activeStreams: Map<string, StreamState>;
  userStreams: Map<string, Set<string>>; // userId -> streamIds
  totalStreamsCreated: number;
  totalStreamsCompleted: number;
  totalErrors: number;
  lastCleanup: number;
}

/**
 * Backpressure strategy
 */
export type BackpressureStrategy =
  | 'drop_oldest'
  | 'drop_newest'
  | 'pause_stream'
  | 'compress_data'
  | 'increase_buffer';

/**
 * Backpressure configuration
 */
export interface BackpressureConfig {
  strategy: BackpressureStrategy;
  bufferSize: number;
  highWaterMark: number;
  lowWaterMark: number;
  maxBufferSize: number;
  compressionLevel?: number;
}

/**
 * Error recovery configuration
 */
export interface ErrorRecoveryConfig {
  maxRetries: number;
  retryBackoffMs: number;
  exponentialBackoff: boolean;
  jitterMs: number;
  retryableErrors: string[];
  nonRetryableErrors: string[];
  circuitBreakerThreshold: number;
  circuitBreakerResetTime: number;
}

/**
 * Performance metrics
 */
export interface StreamMetrics {
  streamId: string;
  startTime: number;
  endTime?: number;
  firstTokenTime?: number;
  totalTokens: number;
  totalChunks: number;
  totalBytes: number;

  // Timing metrics
  averageTokenLatency: number;
  tokensPerSecond: number;
  timeToFirstToken?: number;

  // Quality metrics
  errorRate: number;
  retryCount: number;
  droppedEventCount: number;
  bufferOverflowCount: number;

  // Connection metrics
  heartbeatCount: number;
  missedHeartbeats: number;
  reconnectCount: number;

  // Resource usage
  peakBufferUsage: number;
  averageBufferUsage: number;
  memoryUsage: number;
}

/**
 * Validation schemas
 */
export const StreamConfigSchema = z.object({
  streamId: z.string().min(1).max(128),
  userId: z.string().min(1).max(128),
  businessId: z.string().min(1).max(128),
  correlationId: z.string().min(1).max(128),
  firstTokenTimeout: z.number().min(50).max(5000),
  heartbeatInterval: z.number().min(1000).max(60000),
  maxStreamDuration: z.number().min(10000).max(1800000), // Max 30 minutes
  bufferSize: z.number().min(256).max(10240), // 256B to 10KB
  maxRetries: z.number().min(0).max(10),
  retryBackoffMs: z.number().min(100).max(30000),
  errorRecoveryMode: z.enum(['reconnect', 'continue', 'fail']),
  maxConcurrentStreams: z.number().min(1).max(20),
  streamPriority: z.enum(['low', 'normal', 'high']),
  enableHeartbeat: z.boolean(),
  enableBackpressure: z.boolean(),
  enableCompression: z.boolean(),
  enableMetrics: z.boolean(),
});

export const SSEEventSchema = z.object({
  id: z.string(),
  event: z.enum([
    'stream_start',
    'token',
    'chunk',
    'function_call',
    'function_result',
    'stream_end',
    'error',
    'heartbeat',
    'retry',
    'metadata'
  ]),
  data: z.unknown(),
  timestamp: z.number(),
  retry: z.number().optional(),
});

/**
 * AI Provider interface for streaming
 */
export interface AIProvider {
  name: string;
  supportsStreaming: boolean;
  supportsFunction: boolean;
  maxTokens: number;

  stream(params: {
    prompt: string;
    model: string;
    options?: Record<string, unknown>;
    onToken?: (token: string) => void;
    onChunk?: (chunk: string) => void;
    onFunctionCall?: (call: FunctionCallData) => void;
    onComplete?: (result: StreamEndData) => void;
    onError?: (error: ErrorData) => void;
    signal?: AbortSignal;
  }): Promise<ReadableStream<Uint8Array>>;
}

/**
 * Stream event handler interface
 */
export interface StreamEventHandler {
  onStreamStart?: (event: StreamStartEvent) => void | Promise<void>;
  onToken?: (event: TokenEvent) => void | Promise<void>;
  onChunk?: (event: ChunkEvent) => void | Promise<void>;
  onFunctionCall?: (event: FunctionCallEvent) => void | Promise<void>;
  onFunctionResult?: (event: FunctionResultEvent) => void | Promise<void>;
  onStreamEnd?: (event: StreamEndEvent) => void | Promise<void>;
  onError?: (event: ErrorEvent) => void | Promise<void>;
  onHeartbeat?: (event: HeartbeatEvent) => void | Promise<void>;
  onMetadata?: (event: MetadataEvent) => void | Promise<void>;
}

/**
 * Connection quality metrics
 */
export interface ConnectionQuality {
  latency: number;
  jitter: number;
  packetLoss: number;
  bandwidth: number;
  stability: 'excellent' | 'good' | 'fair' | 'poor';
  recommendedConfig: Partial<SSEStreamConfig>;
}

/**
 * Stream analytics data
 */
export interface StreamAnalytics {
  streamId: string;
  userId: string;
  businessId: string;
  model: string;

  // Performance data
  timeToFirstToken: number;
  averageTokenLatency: number;
  tokensPerSecond: number;
  totalDuration: number;

  // Quality data
  successRate: number;
  errorCount: number;
  retryCount: number;

  // Usage data
  totalTokens: number;
  totalBytes: number;

  // Connection data
  connectionQuality: ConnectionQuality;
  clientInfo: StreamState['clientInfo'];

  // Timestamps
  startTime: number;
  endTime: number;
}