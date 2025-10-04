/**
 * Structured Logging System with Correlation IDs
 * SECURITY: Comprehensive audit trail and debugging capabilities
 * Implements log aggregation, correlation, and security event tracking
 */

import type { AppContext, Next } from '../types/hono-context';

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  CRITICAL = 4,
  SECURITY = 5
}

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  levelName: string;
  correlationId: string;
  requestId: string;
  message: string;
  context: LogContext;
  metadata?: Record<string, any>;
  error?: ErrorInfo;
  performance?: PerformanceInfo;
  security?: SecurityInfo;
}

export interface LogContext {
  userId?: string;
  businessId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  method?: string;
  path?: string;
  query?: Record<string, any>;
  headers?: Record<string, string>;
  environment?: string;
  service?: string;
  version?: string;
}

export interface ErrorInfo {
  message: string;
  stack?: string;
  code?: string;
  type?: string;
}

export interface PerformanceInfo {
  duration: number;
  cpuUsage?: number;
  memoryUsage?: number;
  dbQueries?: number;
  cacheHits?: number;
  cacheMisses?: number;
}

export interface SecurityInfo {
  event: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: Record<string, any>;
  remediation?: string;
}

export interface LoggerConfig {
  minLevel: LogLevel;
  includeHeaders: boolean;
  sanitizeData: boolean;
  enableCorrelation: boolean;
  enablePerformanceTracking: boolean;
  maxMetadataDepth: number;
  bufferSize: number;
  flushInterval: number;
  env: 'development' | 'staging' | 'production';
}

export class StructuredLogger {
  private readonly config: LoggerConfig;
  private readonly kv?: KVNamespace;
  private readonly analytics?: AnalyticsEngineDataset;
  private readonly logPrefix = 'log:';
  private readonly buffer: LogEntry[] = [];
  private flushTimer?: any;

  constructor(
    config?: Partial<LoggerConfig>,
    kv?: KVNamespace,
    analytics?: AnalyticsEngineDataset
  ) {
    this.config = {
      minLevel: config?.minLevel ?? (config?.env === 'production' ? LogLevel.INFO : LogLevel.DEBUG),
      includeHeaders: config?.includeHeaders ?? false,
      sanitizeData: config?.sanitizeData ?? true,
      enableCorrelation: config?.enableCorrelation ?? true,
      enablePerformanceTracking: config?.enablePerformanceTracking ?? true,
      maxMetadataDepth: config?.maxMetadataDepth ?? 3,
      bufferSize: config?.bufferSize ?? 100,
      flushInterval: config?.flushInterval ?? 5000, // 5 seconds
      env: config?.env ?? 'production'
    };
    this.kv = kv;
    this.analytics = analytics;

    // Start buffer flush timer
    if (this.config.bufferSize > 1) {
      this.startFlushTimer();
    }
  }

  /**
   * Logging middleware
   */
  middleware() {
    return async (c: AppContext, next: Next) => {
      const startTime = Date.now();

      // Generate correlation ID
      const correlationId = c.req.header('X-Correlation-ID') || crypto.randomUUID();
      const requestId = c.req.header('X-Request-ID') || crypto.randomUUID();

      // Set in context for downstream use
      c.set('correlationId', correlationId);
      c.set('requestId', requestId);

      // Add to response headers
      c.header('X-Correlation-ID', correlationId);
      c.header('X-Request-ID', requestId);

      // Log request
      this.info('Request received', {
        correlationId,
        requestId,
        method: c.req.method,
        path: c.req.path,
        query: c.req.query(),
        headers: this.config.includeHeaders ? this.sanitizeHeaders(c.req.header()) : undefined
      }, c);

      try {
        await next();

        // Log response
        const duration = Date.now() - startTime;
        this.info('Request completed', {
          correlationId,
          requestId,
          status: c.res.status,
          duration,
          performance: {
            duration,
            cpuUsage: (global as any).process?.cpuUsage?.().user,
            memoryUsage: (global as any).process?.memoryUsage?.().heapUsed
          }
        }, c);

      } catch (error: any) {
        // Log error
        const duration = Date.now() - startTime;
        this.error('Request failed', error, {
          correlationId,
          requestId,
          duration
        }, c);

        throw error; // Re-throw for error handler
      }
    };
  }

  /**
   * Log debug message
   */
  debug(message: string, metadata?: Record<string, any>, context?: AppContext): void {
    this.log(LogLevel.DEBUG, message, metadata, context);
  }

  /**
   * Log info message
   */
  info(message: string, metadata?: Record<string, any>, context?: AppContext): void {
    this.log(LogLevel.INFO, message, metadata, context);
  }

  /**
   * Log warning message
   */
  warn(message: string, metadata?: Record<string, any>, context?: AppContext): void {
    this.log(LogLevel.WARN, message, metadata, context);
  }

  /**
   * Log error message
   */
  error(message: string, error?: any, metadata?: Record<string, any>, context?: AppContext): void {
    const errorInfo: ErrorInfo = {
      message: error?.message || 'Unknown error',
      stack: this.config.env !== 'production' ? error?.stack : undefined,
      code: error?.code,
      type: error?.constructor?.name
    };

    this.log(LogLevel.ERROR, message, { ...metadata, error: errorInfo }, context);
  }

  /**
   * Log critical message
   */
  critical(message: string, metadata?: Record<string, any>, context?: AppContext): void {
    this.log(LogLevel.CRITICAL, message, metadata, context);
  }

  /**
   * Log security event
   */
  security(event: string, severity: SecurityInfo['severity'], details: Record<string, any>, context?: AppContext): void {
    const securityInfo: SecurityInfo = {
      event,
      severity,
      details: this.config.sanitizeData ? this.sanitizeData(details) : details
    };

    this.log(LogLevel.SECURITY, `Security event: ${event}`, { security: securityInfo }, context);
  }

  /**
   * Main logging method
   */
  private log(level: LogLevel, message: string, metadata?: Record<string, any>, context?: AppContext): void {
    if (level < this.config.minLevel) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      levelName: LogLevel[level],
      correlationId: context?.get('correlationId') || 'system',
      requestId: context?.get('requestId') || 'system',
      message,
      context: this.buildContext(context),
      metadata: this.config.sanitizeData && metadata ? this.sanitizeData(metadata) : metadata
    };

    // Console output
    this.consoleOutput(entry);

    // Buffer or write immediately
    if (this.config.bufferSize > 1) {
      this.buffer.push(entry);
      if (this.buffer.length >= this.config.bufferSize) {
        this.flush();
      }
    } else {
      this.write(entry);
    }
  }

  /**
   * Build log context from request
   */
  private buildContext(context?: AppContext): LogContext {
    if (!context) {
      return {
        environment: this.config.env,
        service: 'coreflow360',
        version: '4.0.0'
      };
    }

    return {
      userId: context.get('userId'),
      businessId: context.get('businessId'),
      sessionId: context.get('sessionId'),
      ipAddress: context.req.header('CF-Connecting-IP') || context.req.header('X-Forwarded-For'),
      userAgent: context.req.header('User-Agent'),
      method: context.req.method,
      path: context.req.path,
      query: context.req.query(),
      environment: this.config.env,
      service: 'coreflow360',
      version: '4.0.0'
    };
  }

  /**
   * Sanitize sensitive data
   */
  private sanitizeData(data: any, depth = 0): any {
    if (depth > this.config.maxMetadataDepth) return '[MAX_DEPTH]';

    if (Array.isArray(data)) {
      return data.map(item => this.sanitizeData(item, depth + 1));
    }

    if (typeof data === 'object' && data !== null) {
      const sanitized: Record<string, any> = {};
      const sensitiveKeys = ['password', 'token', 'secret', 'apiKey', 'authorization', 'cookie', 'session', 'credit'];

      for (const [key, value] of Object.entries(data)) {
        const lowerKey = key.toLowerCase();

        if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
          sanitized[key] = '[REDACTED]';
        } else if (typeof value === 'string' && value.length > 1000) {
          sanitized[key] = value.substring(0, 1000) + '...[TRUNCATED]';
        } else {
          sanitized[key] = this.sanitizeData(value, depth + 1);
        }
      }

      return sanitized;
    }

    return data;
  }

  /**
   * Sanitize headers
   */
  private sanitizeHeaders(headers: Record<string, string> | undefined): Record<string, string> {
    if (!headers) return {};

    const sanitized: Record<string, string> = {};
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key', 'x-auth-token'];

    for (const [key, value] of Object.entries(headers)) {
      const lowerKey = key.toLowerCase();

      if (sensitiveHeaders.includes(lowerKey)) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Console output with formatting
   */
  private consoleOutput(entry: LogEntry): void {
    const color = this.getLogColor(entry.level);
    const prefix = `[${entry.levelName}] ${entry.timestamp} [${entry.correlationId.substring(0, 8)}]`;
    const message = `${prefix} ${entry.message}`;

    // Format metadata if present
    const metadata = entry.metadata ? JSON.stringify(entry.metadata, null, 2) : '';

    switch (entry.level) {
      case LogLevel.ERROR:
      case LogLevel.CRITICAL:
      case LogLevel.SECURITY:
        console.error(color + message + '\x1b[0m', metadata);
        break;
      case LogLevel.WARN:
        console.warn(color + message + '\x1b[0m', metadata);
        break;
      default:
        console.log(color + message + '\x1b[0m', metadata);
    }
  }

  /**
   * Get console color for log level
   */
  private getLogColor(level: LogLevel): string {
    switch (level) {
      case LogLevel.DEBUG: return '\x1b[36m'; // Cyan
      case LogLevel.INFO: return '\x1b[32m'; // Green
      case LogLevel.WARN: return '\x1b[33m'; // Yellow
      case LogLevel.ERROR: return '\x1b[31m'; // Red
      case LogLevel.CRITICAL: return '\x1b[35m'; // Magenta
      case LogLevel.SECURITY: return '\x1b[91m'; // Bright Red
      default: return '\x1b[0m'; // Reset
    }
  }

  /**
   * Write log entry to storage
   */
  private async write(entry: LogEntry): Promise<void> {
    // Write to KV if available
    if (this.kv) {
      try {
        const key = `${this.logPrefix}${entry.timestamp}_${entry.requestId}`;
        await this.kv.put(key, JSON.stringify(entry), {
          expirationTtl: 30 * 24 * 60 * 60 // 30 days
        });
      } catch (error) {
        console.error('Failed to write log to KV:', error);
      }
    }

    // Write to Analytics Engine if available
    if (this.analytics && entry.level >= LogLevel.INFO) {
      try {
        await this.analytics.writeDataPoint({
          indexes: [
            entry.levelName,
            entry.context.businessId || 'system',
            entry.context.userId || 'anonymous'
          ],
          blobs: [
            entry.message,
            JSON.stringify(entry.metadata || {}),
            entry.correlationId
          ],
          doubles: [
            Date.parse(entry.timestamp),
            entry.level,
            entry.performance?.duration || 0
          ]
        });
      } catch (error) {
        console.error('Failed to write log to Analytics:', error);
      }
    }
  }

  /**
   * Flush buffered logs
   */
  private async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const entries = [...this.buffer];
    this.buffer.length = 0;

    // Write all entries
    for (const entry of entries) {
      await this.write(entry);
    }
  }

  /**
   * Start flush timer
   */
  private startFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      this.flush();
    }, this.config.flushInterval);
  }

  /**
   * Stop flush timer
   */
  stopFlushTimer(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flush(); // Final flush
    }
  }

  /**
   * Query logs
   */
  async queryLogs(
    filters: {
      correlationId?: string;
      userId?: string;
      businessId?: string;
      level?: LogLevel;
      startTime?: string;
      endTime?: string;
    },
    limit = 100
  ): Promise<LogEntry[]> {
    if (!this.kv) return [];

    const { keys } = await this.kv.list({ prefix: this.logPrefix, limit: limit * 2 });
    const results: LogEntry[] = [];

    for (const key of keys) {
      const data = await this.kv.get(key.name);
      if (data) {
        const entry: LogEntry = JSON.parse(data);

        // Apply filters
        if (filters.correlationId && entry.correlationId !== filters.correlationId) continue;
        if (filters.userId && entry.context.userId !== filters.userId) continue;
        if (filters.businessId && entry.context.businessId !== filters.businessId) continue;
        if (filters.level !== undefined && entry.level < filters.level) continue;
        if (filters.startTime && entry.timestamp < filters.startTime) continue;
        if (filters.endTime && entry.timestamp > filters.endTime) continue;

        results.push(entry);
        if (results.length >= limit) break;
      }
    }

    return results.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  }
}

// Export factory function
export function createStructuredLogger(
  config?: Partial<LoggerConfig>,
  kv?: KVNamespace,
  analytics?: AnalyticsEngineDataset
): StructuredLogger {
  return new StructuredLogger(config, kv, analytics);
}