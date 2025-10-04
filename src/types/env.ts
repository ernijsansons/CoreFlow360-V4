/**
 * CANONICAL ENV TYPE DEFINITION
 * Single source of truth for all Cloudflare Worker bindings
 * MATCHES wrangler.toml configuration exactly
 *
 * DO NOT DUPLICATE THIS TYPE - Import from this file only
 */

/// <reference types="@cloudflare/workers-types" />

export interface Env {
  // ==========================================
  // D1 DATABASE BINDINGS (from wrangler.toml)
  // ==========================================
  DB: D1Database;
  DB_MAIN: D1Database;
  DB_ANALYTICS: D1Database;

  // ==========================================
  // KV NAMESPACE BINDINGS (from wrangler.toml)
  // ==========================================
  KV_CACHE: KVNamespace;
  KV_SESSION: KVNamespace;
  KV_RATE_LIMIT_METRICS: KVNamespace;
  KV_AUTH: KVNamespace;

  // Agent-specific KV namespaces (from wrangler.toml)
  AGENT_CACHE?: KVNamespace;
  AGENT_MEMORY?: KVNamespace;
  PATTERN_CACHE?: KVNamespace;

  // ==========================================
  // R2 BUCKET BINDINGS (from wrangler.toml)
  // ==========================================
  R2_DOCUMENTS: R2Bucket;
  R2_BACKUPS: R2Bucket;

  // ==========================================
  // DURABLE OBJECTS (from wrangler.toml)
  // ==========================================
  RATE_LIMITER_DO?: DurableObjectNamespace;
  WORKFLOW_EXECUTOR?: DurableObjectNamespace;

  // ==========================================
  // AI BINDING (from wrangler.toml)
  // ==========================================
  AI?: Ai;

  // ==========================================
  // ANALYTICS
  // ==========================================
  ANALYTICS?: AnalyticsEngineDataset;

  // ==========================================
  // ENVIRONMENT VARIABLES (from wrangler.toml)
  // ==========================================
  APP_NAME: string;
  API_VERSION: string;
  LOG_LEVEL: string;
  ENVIRONMENT: string;

  // Agent configuration
  AGENT_SYSTEM_ENABLED?: string;
  MAX_AGENT_CONCURRENCY?: string;
  AGENT_TIMEOUT_MS?: string;

  // Sentry
  SENTRY_ENVIRONMENT?: string;

  // ==========================================
  // SECRETS (Set via wrangler secret)
  // ==========================================

  // Core security
  JWT_SECRET: string;
  AUTH_SECRET?: string;
  ENCRYPTION_KEY?: string;

  // AI Services
  ANTHROPIC_API_KEY?: string;
  OPENAI_API_KEY?: string;

  // Payment processors
  STRIPE_SECRET_KEY?: string;
  STRIPE_PUBLISHABLE_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  PAYPAL_CLIENT_ID?: string;
  PAYPAL_CLIENT_SECRET?: string;

  // Communication services
  EMAIL_API_KEY?: string;
  SMS_API_KEY?: string;
  TWILIO_ACCOUNT_SID?: string;
  TWILIO_AUTH_TOKEN?: string;
  SENDGRID_API_KEY?: string;

  // Data enrichment
  CLEARBIT_API_KEY?: string;
  APOLLO_API_KEY?: string;
  HUNTER_API_KEY?: string;
  LINKEDIN_USERNAME?: string;
  LINKEDIN_PASSWORD?: string;
  GOOGLE_NEWS_API_KEY?: string;
  NEWSAPI_KEY?: string;
  SERPAPI_KEY?: string;

  // Monitoring & Analytics
  DATADOG_API_KEY?: string;
  SENTRY_DSN?: string;
  CLICKHOUSE_ENDPOINT?: string;
  CLICKHOUSE_TOKEN?: string;

  // Internal service tokens
  API_KEY?: string;
  ADMIN_API_KEY?: string;
  WEBHOOK_SECRET?: string;
  ORCHESTRATOR_TOKEN?: string;
  GATEWAY_TOKEN?: string;
  CACHE_TOKEN?: string;

  // ==========================================
  // OPTIONAL CONFIGURATION
  // ==========================================
  API_BASE_URL?: string;
  ALLOWED_ORIGINS?: string;
  CDN_URL?: string;
  DASHBOARD_URL?: string;
  MIGRATION_WEBHOOK?: string;

  // Debug and feature flags
  DEBUG?: string;
  ENABLE_MFA?: string;
  ENABLE_AI?: string;
  ENABLE_ANALYTICS?: string;
  ENABLE_WEBSOCKETS?: string;
  ENABLE_QUEUE_PROCESSING?: string;

  // Rate limiting configuration
  GLOBAL_RATE_LIMIT?: string;
  USER_RATE_LIMIT?: string;
  IP_RATE_LIMIT?: string;
  API_KEY_RATE_LIMIT?: string;

  // Security configuration
  MAX_REQUEST_SIZE?: string;
  REQUEST_TIMEOUT?: string;
  JWT_EXPIRY?: string;
  CSP_REPORT_URI?: string;

  // CORS
  CORS_ORIGINS?: string;

  // Legacy/deprecated bindings (optional for backward compatibility)
  DB_CRM?: D1Database;
  KV_CONFIG?: KVNamespace;
  KV_RATE_LIMIT?: KVNamespace;
  CACHE?: KVNamespace; // Alias for KV_CACHE
  PERFORMANCE_ANALYTICS?: AnalyticsEngineDataset;
  R2_ASSETS?: R2Bucket;
  R2_CACHE?: R2Bucket;
  TASK_QUEUE?: Queue;
  EMAIL_QUEUE?: Queue;
  WEBHOOK_QUEUE?: Queue;
  REALTIME_COORDINATOR?: DurableObjectNamespace;

  // Execution context (runtime-provided)
  ctx?: ExecutionContext;
}

/**
 * Hono context type with proper Env bindings
 */
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

/**
 * Type guard to check if required bindings exist
 */
export function validateEnv(env: Partial<Env>): env is Env {
  return !!(
    env.DB &&
    env.DB_MAIN &&
    env.KV_CACHE &&
    env.KV_SESSION &&
    env.KV_AUTH &&
    env.JWT_SECRET &&
    env.APP_NAME &&
    env.API_VERSION &&
    env.ENVIRONMENT
  );
}