// Import Cloudflare Workers types
/// <reference types="@cloudflare/workers-types" />

export interface Env {
  // Database bindings
  DB: D1Database;
  DB_MAIN: D1Database;
  DB_ANALYTICS: D1Database;

  // KV Namespaces
  KV_CACHE: KVNamespace;
  KV_SESSION: KVNamespace;
  KV_CONFIG: KVNamespace;
  WORKFLOW_STORAGE: KVNamespace;
  SSE_METRICS: KVNamespace;

  // R2 Buckets
  R2_DOCUMENTS: R2Bucket;
  R2_ASSETS: R2Bucket;
  R2_BACKUPS: R2Bucket;

  // Queues
  TASK_QUEUE: Queue;
  EMAIL_QUEUE: Queue;
  WEBHOOK_QUEUE: Queue;

  // Durable Objects
  USER_SESSION: DurableObjectNamespace;
  WORKFLOW_ENGINE: DurableObjectNamespace;
  WORKFLOW_ORCHESTRATOR: DurableObjectNamespace;
  SSE_STREAM_MANAGER: DurableObjectNamespace;
  REALTIME_SYNC: DurableObjectNamespace;
  DASHBOARD_STREAM: DurableObjectNamespace;
  WORKFLOW_EXECUTOR: DurableObjectNamespace;
  WORKFLOW_COLLABORATION: DurableObjectNamespace;

  // AI & Analytics
  AI: Ai;
  ANALYTICS: AnalyticsEngineDataset;

  // Service bindings
  AUTH_SERVICE?: Fetcher;
  NOTIFICATION_SERVICE?: Fetcher;

  // Rate limiting
  RATE_LIMITER?: any;

  // Core Application Variables
  APP_NAME: string;
  API_VERSION: string;
  LOG_LEVEL: string;
  ENVIRONMENT: string;

  // Observability Configuration
  DASHBOARD_URL?: string;
  EMAIL_API_ENDPOINT?: string;
  ORCHESTRATOR_API?: string;
  GATEWAY_API?: string;
  CACHE_API?: string;
  BIGQUERY_PROJECT_ID?: string;
  BIGQUERY_DATASET_ID?: string;
  R2_ENDPOINT?: string;
  R2_BUCKET?: string;
  R2_PUBLIC_URL?: string;

  // Secrets
  AUTH_SECRET?: string;
  ENCRYPTION_KEY?: string;
  JWT_SECRET?: string;
  API_KEY?: string;
  WEBHOOK_SECRET?: string;
  ADMIN_API_KEY?: string;
  EMAIL_API_KEY?: string;
  ORCHESTRATOR_TOKEN?: string;
  GATEWAY_TOKEN?: string;
  CACHE_TOKEN?: string;
  BIGQUERY_TOKEN?: string;
  R2_TOKEN?: string;
  DATADOG_API_KEY?: string;
  CLICKHOUSE_ENDPOINT?: string;
  CLICKHOUSE_TOKEN?: string;

  // Payment Gateway Secrets
  STRIPE_SECRET_KEY?: string;
  STRIPE_PUBLISHABLE_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  PAYPAL_CLIENT_ID?: string;
  PAYPAL_CLIENT_SECRET?: string;

  // AI Service Keys
  ANTHROPIC_API_KEY?: string;
  OPENAI_API_KEY?: string;

  // Other Configuration
  API_BASE_URL?: string;
  ALLOWED_ORIGINS?: string;
}

// Context type for Hono
export interface HonoContext {
  Bindings: Env;
  Variables: {
    user?: {
      id: string;
      businessId: string;
      role: string;
    };
    requestId?: string;
    traceId?: string;
    spanId?: string;
  };
}