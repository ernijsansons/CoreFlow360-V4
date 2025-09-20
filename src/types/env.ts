export interface Env {
  DB_MAIN: D1Database;
  DB_ANALYTICS: D1Database;

  KV_CACHE: KVNamespace;
  KV_SESSION: KVNamespace;
  KV_CONFIG: KVNamespace;

  R2_DOCUMENTS: R2Bucket;
  R2_ASSETS: R2Bucket;
  R2_BACKUPS: R2Bucket;

  TASK_QUEUE: Queue;
  EMAIL_QUEUE: Queue;
  WEBHOOK_QUEUE: Queue;

  USER_SESSION: DurableObjectNamespace;
  WORKFLOW_ENGINE: DurableObjectNamespace;
  REALTIME_SYNC: DurableObjectNamespace;

  AI: Ai;
  ANALYTICS: AnalyticsEngineDataset;

  AUTH_SERVICE?: Fetcher;
  NOTIFICATION_SERVICE?: Fetcher;

  APP_NAME: string;
  API_VERSION: string;
  LOG_LEVEL: string;
  ENVIRONMENT: string;

  AUTH_SECRET?: string;
  ENCRYPTION_KEY?: string;
  JWT_SECRET?: string;
  API_KEY?: string;
  WEBHOOK_SECRET?: string;
  ADMIN_API_KEY?: string;
}