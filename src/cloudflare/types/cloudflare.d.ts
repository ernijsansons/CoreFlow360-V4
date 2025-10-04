/**
 * CLOUDFLARE TYPES - CANONICAL RE-EXPORTS
 *
 * ARCHITECTURAL DECISION:
 * This file re-exports official @cloudflare/workers-types to maintain Single Source of Truth.
 * All Cloudflare type imports MUST come from @cloudflare/workers-types.
 *
 * This file exists ONLY for backward compatibility and to provide a central import point.
 *
 * VIOLATION PREVENTION:
 * - DO NOT duplicate type definitions here
 * - DO NOT modify official type signatures
 * - Only extend types if absolutely necessary for project-specific needs
 */

/// <reference types="@cloudflare/workers-types" />

// ==========================================
// RE-EXPORT OFFICIAL CLOUDFLARE TYPES
// ==========================================

export type {
  KVNamespace,
  R2Bucket,
  R2Object,
  AnalyticsEngineDataset,
  D1Database,
  D1PreparedStatement,
  D1Result,
  D1ExecResult,
  DurableObjectState,
  DurableObjectStorage,
  DurableObjectNamespace,
  DurableObjectId,
  DurableObjectStub,
  ExecutionContext,
  ScheduledEvent,
  MessageBatch,
  Message,
  Queue,
  Ai
} from '@cloudflare/workers-types';

// ==========================================
// GLOBAL EXTENSIONS (Web Standards)
// ==========================================

declare global {
  interface WebSocketPair {
    0: WebSocket;
    1: WebSocket;
  }

  const WebSocketPair: {
    new (): WebSocketPair;
  };
}

// ==========================================
// PROJECT-SPECIFIC EXTENSIONS (if needed)
// ==========================================

/**
 * DurableObject interface
 * Standard interface for Durable Objects
 */
export interface DurableObject {
  fetch(request: Request): Promise<Response>;
  alarm?(): Promise<void>;
}

/**
 * DurableObjectTransaction interface
 * For transactional operations in Durable Object Storage
 */
export interface DurableObjectTransaction {
  get<T = unknown>(key: string): Promise<T | undefined>;
  get<T = unknown>(keys: string[]): Promise<Map<string, T>>;
  put<T>(key: string, value: T): Promise<void>;
  put<T>(entries: Record<string, T>): Promise<void>;
  delete(key: string): Promise<boolean>;
  delete(keys: string[]): Promise<number>;
  list<T = unknown>(options?: {
    start?: string;
    startAfter?: string;
    end?: string;
    prefix?: string;
    reverse?: boolean;
    limit?: number;
  }): Promise<Map<string, T>>;
  rollback(): void;
}

/**
 * CloudflareEnv interface (DEPRECATED)
 * Use Env from src/types/env.ts instead
 * @deprecated Import Env from '../types/env' instead
 */
export interface CloudflareEnv {
  ENVIRONMENT: string;
  CACHE: KVNamespace;
  SESSIONS: KVNamespace;
  STORAGE: R2Bucket;
  BACKUPS: R2Bucket;
  DB: D1Database;
  ANALYTICS: AnalyticsEngineDataset;
  PERFORMANCE_ANALYTICS: AnalyticsEngineDataset;
  REALTIME_COORDINATOR: DurableObjectNamespace;
  USER_SESSION: DurableObjectNamespace;
  AI: any;
  Queue: any;
  AUTH_SECRET: string;
  ENCRYPTION_KEY: string;
  JWT_SECRET: string;
  API_KEY: string;
  CORS_ORIGINS?: string;
  CSP_POLICY?: string;
}