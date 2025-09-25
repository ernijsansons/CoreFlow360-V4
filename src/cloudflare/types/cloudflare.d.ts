/**
 * CLOUDFLARE TYPES
 * Type definitions for Cloudflare Workers APIs
 */

// Cloudflare Workers global types
declare global {
  interface WebSocketPair {
    0: WebSocket;
    1: WebSocket;
  }

  const WebSocketPair: {
    new (): WebSocketPair;
  };
}

// Cloudflare-specific interfaces
export interface KVNamespace {
  get(key: string, options?: { type?: 'text' | 'json' | 'arrayBuffer' | 'stream' }): Promise<string | null>;
  put(key: string, value: string | ArrayBuffer | ReadableStream, options?: {
    expiration?: number;
    expirationTtl?: number;
    metadata?: Record<string, any>;
  }): Promise<void>;
  delete(key: string): Promise<void>;
  list(options?: {
    prefix?: string;
    limit?: number;
    cursor?: string;
  }): Promise<{
    keys: Array<{ name: string; expiration?: number; metadata?: Record<string, any> }>;
    list_complete: boolean;
    cursor?: string;
  }>;
}

export interface R2Bucket {
  get(key: string): Promise<R2Object | null>;
  put(key: string, value: string | ArrayBuffer | ReadableStream, options?: {
    httpMetadata?: {
      contentType?: string;
      contentLanguage?: string;
      contentDisposition?: string;
      contentEncoding?: string;
      cacheControl?: string;
      expires?: Date;
    };
    customMetadata?: Record<string, string>;
  }): Promise<R2Object>;
  delete(key: string): Promise<void>;
  head(key: string): Promise<R2Object | null>;
  list(options?: {
    prefix?: string;
    delimiter?: string;
    cursor?: string;
    include?: string[];
    limit?: number;
  }): Promise<{
    objects: R2Object[];
    truncated: boolean;
    cursor?: string;
    delimitedPrefixes: string[];
  }>;
}

export interface R2Object {
  key: string;
  version: string;
  size: number;
  etag: string;
  uploaded: Date;
  httpMetadata: {
    contentType?: string;
    contentLanguage?: string;
    contentDisposition?: string;
    contentEncoding?: string;
    cacheControl?: string;
    expires?: Date;
  };
  customMetadata: Record<string, string>;
  body?: ReadableStream;
  json<T>(): Promise<T>;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export interface AnalyticsEngineDataset {
  writeDataPoint(data: {
    blobs?: string[];
    doubles?: number[];
    indexes?: string[];
  }): Promise<void>;
}

export interface DurableObjectState {
  storage: DurableObjectStorage;
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
  waitUntil(promise: Promise<any>): void;
  setAlarm(time: number | Date): Promise<void>;
  getAlarm(): Promise<number | null>;
  deleteAlarm(): Promise<void>;
}

export interface DurableObjectStorage {
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
  transaction<T>(callback: (txn: DurableObjectTransaction) => Promise<T>): Promise<T>;
}

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

export interface DurableObject {
  fetch(request: Request): Promise<Response>;
  alarm?(): Promise<void>;
}

export interface DurableObjectNamespace {
  newUniqueId(options?: { jurisdiction?: string }): DurableObjectId;
  idFromName(name: string): DurableObjectId;
  idFromString(id: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub;
}

export interface DurableObjectId {
  toString(): string;
  equals(other: DurableObjectId): boolean;
}

export interface DurableObjectStub {
  fetch(request: Request): Promise<Response>;
  id: DurableObjectId;
}

export interface ExecutionContext {
  waitUntil(promise: Promise<any>): void;
  passThroughOnException(): void;
}

export interface ScheduledEvent {
  type: 'scheduled';
  scheduledTime: number;
  cron: string;
}

export interface MessageBatch<T = any> {
  readonly queue: string;
  readonly messages: Message<T>[];
  retryAll(options?: { delaySeconds?: number }): void;
  ackAll(): void;
}

export interface Message<T = any> {
  readonly id: string;
  readonly timestamp: Date;
  readonly body: T;
  ack(): void;
  retry(options?: { delaySeconds?: number }): void;
}

// Environment interface
export interface CloudflareEnv {
  ENVIRONMENT: string;

  // KV Namespaces
  CACHE: KVNamespace;
  SESSIONS: KVNamespace;

  // R2 Buckets
  STORAGE: R2Bucket;
  BACKUPS: R2Bucket;

  // D1 Databases
  DB: D1Database;

  // Analytics Engine
  ANALYTICS: AnalyticsEngineDataset;
  PERFORMANCE_ANALYTICS: AnalyticsEngineDataset;

  // Durable Objects
  REALTIME_COORDINATOR: DurableObjectNamespace;
  USER_SESSION: DurableObjectNamespace;

  // AI
  AI: any;

  // Secrets and Variables
  AUTH_SECRET: string;
  ENCRYPTION_KEY: string;
  JWT_SECRET: string;
  API_KEY: string;
  CORS_ORIGINS?: string;
  CSP_POLICY?: string;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  dump(): Promise<ArrayBuffer>;
  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
  exec(query: string): Promise<D1ExecResult>;
}

export interface D1PreparedStatement {
  bind(...values: any[]): D1PreparedStatement;
  first<T = unknown>(colName?: string): Promise<T | null>;
  run(): Promise<D1Result>;
  all<T = unknown>(): Promise<D1Result<T>>;
  raw<T = unknown>(): Promise<T[]>;
}

export interface D1Result<T = Record<string, unknown>> {
  results: T[];
  success: boolean;
  meta: {
    duration: number;
    size_after: number;
    rows_read: number;
    rows_written: number;
    last_row_id: number;
    changed_db: boolean;
    changes: number;
  };
}

export interface D1ExecResult {
  count: number;
  duration: number;
}