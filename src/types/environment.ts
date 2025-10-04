/**
 * Environment Types - Type-safe environment configuration
 */

export interface Env {
  // Core application
  ENVIRONMENT?: string;
  DEBUG?: string;
  API_VERSION?: string;

  // Security secrets
  JWT_SECRET: string;
  ENCRYPTION_KEY?: string;
  AUTH_SECRET?: string;

  // Database bindings
  DB?: D1Database;
  DB_MAIN?: D1Database;
  DB_ANALYTICS?: D1Database;

  // KV Storage
  KV_CACHE?: KVNamespace;
  KV_SESSION?: KVNamespace;
  KV_AUTH?: KVNamespace;
  KV_RATE_LIMIT_METRICS?: KVNamespace;

  // R2 Storage
  R2_DOCUMENTS?: R2Bucket;
  R2_BACKUPS?: R2Bucket;

  // AI Services
  AI?: any; // Cloudflare AI binding
  ANTHROPIC_API_KEY?: string;
  OPENAI_API_KEY?: string;

  // Communication
  EMAIL_API_KEY?: string;
  SMS_API_KEY?: string;

  // External services
  STRIPE_SECRET_KEY?: string;
  STRIPE_PUBLISHABLE_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;

  // Analytics
  ANALYTICS?: AnalyticsEngineDataset;
  PERFORMANCE_ANALYTICS?: AnalyticsEngineDataset;

  // Queue bindings
  TASK_QUEUE?: Queue;
  EMAIL_QUEUE?: Queue;
  WEBHOOK_QUEUE?: Queue;

  // Durable Objects
  RATE_LIMITER_DO?: DurableObjectNamespace;
  WORKFLOW_EXECUTOR_DO?: DurableObjectNamespace;
  REALTIME_DO?: DurableObjectNamespace;

  // Configuration
  ALLOWED_ORIGINS?: string;
  API_BASE_URL?: string;
  CDN_URL?: string;

  // Rate limiting
  GLOBAL_RATE_LIMIT?: string;
  USER_RATE_LIMIT?: string;
  IP_RATE_LIMIT?: string;
  API_KEY_RATE_LIMIT?: string;

  // Security
  MAX_REQUEST_SIZE?: string;
  REQUEST_TIMEOUT?: string;
  JWT_EXPIRY?: string;
  ENABLE_MFA?: string;
  CSP_REPORT_URI?: string;

  // Feature flags
  ENABLE_AI?: string;
  ENABLE_ANALYTICS?: string;
  ENABLE_WEBSOCKETS?: string;
  ENABLE_QUEUE_PROCESSING?: string;
}

export interface SecurityHeaders {
  'X-Content-Type-Options': string;
  'X-Frame-Options': string;
  'X-XSS-Protection': string;
  'Referrer-Policy': string;
  'Content-Security-Policy': string;
  'Permissions-Policy': string;
  'Strict-Transport-Security'?: string;
  'Cross-Origin-Embedder-Policy': string;
  'Cross-Origin-Opener-Policy': string;
  'Cross-Origin-Resource-Policy': string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}