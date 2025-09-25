/**
 * LOGGER UTILITIES
 * Production-ready logging for Cloudflare Workers
 */

import type { AnalyticsEngineDataset } from '../types/cloudflare';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'critical';

export interface LogContext {
  requestId?: string;
  userId?: string;
  businessId?: string;
  ip?: string;
  userAgent?: string;
  environment?: string;
  [key: string]: any;
}

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: LogContext;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  performance?: {
    duration: number;
    operation: string;
  };
}

export class Logger {
  private context: LogContext;
  private minLevel: LogLevel;

  constructor(context: LogContext = {}, minLevel: LogLevel = 'info') {
    this.context = context;
    this.minLevel = minLevel;
  }

  /**
   * Create child logger with additional context
   */
  child(additionalContext: LogContext): Logger {
    return new Logger(
      { ...this.context, ...additionalContext },
      this.minLevel
    );
  }

  /**
   * Log debug message
   */
  debug(message: string, context?: LogContext): void {
    this.log('debug', message, context);
  }

  /**
   * Log info message
   */
  info(message: string, context?: LogContext): void {
    this.log('info', message, context);
  }

  /**
   * Log warning message
   */
  warn(message: string, context?: LogContext): void {
    this.log('warn', message, context);
  }

  /**
   * Log error message
   */
  error(message: string, error?: Error | any, context?: LogContext): void {
    const errorInfo = error instanceof Error ? {
      name: error.name,
      message: error.message,
      stack: error.stack
    } : error ? {
      name: 'Error',
      message: String(error),
      stack: undefined
    } : undefined;

    this.log('error', message, context, errorInfo);
  }

  /**
   * Log performance metric
   */
  performance(operation: string, duration: number, context?: LogContext): void {
    this.log('info', `Performance: ${operation}`, context, undefined, {
      operation,
      duration
    });
  }

  /**
   * Core logging method
   */
  private log(
    level: LogLevel,
    message: string,
    context?: LogContext,
    error?: any,
    performance?: any
  ): void {
    if (!this.shouldLog(level)) {
      return;
    }

    const logEntry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      context: { ...this.context, ...context }
    };

    if (error) {
      logEntry.error = error;
    }

    if (performance) {
      logEntry.performance = performance;
    }

    // Output to console with appropriate method
    const output = this.formatLogEntry(logEntry);

    switch (level) {
      case 'debug':
        console.debug(output);
        break;
      case 'info':
        console.info(output);
        break;
      case 'warn':
        break;
      case 'error':
        break;
    }
  }

  /**
   * Check if log level should be logged
   */
  private shouldLog(level: LogLevel): boolean {
    const levels: Record<LogLevel, number> = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3,
      critical: 4
    };

    return levels[level] >= levels[this.minLevel];
  }

  /**
   * Format log entry for output
   */
  private formatLogEntry(entry: LogEntry): string {
    const base = `[${entry.timestamp}] ${entry.level.toUpperCase()}: ${entry.message}`;

    const parts = [base];

    // Add context
    if (entry.context && Object.keys(entry.context).length > 0) {
      parts.push(`Context: ${JSON.stringify(entry.context)}`);
    }

    // Add error
    if (entry.error) {
      parts.push(`Error: ${entry.error.name}: ${entry.error.message}`);
      if (entry.error.stack) {
        parts.push(`Stack: ${entry.error.stack}`);
      }
    }

    // Add performance
    if (entry.performance) {
      parts.push(`Performance: ${entry.performance.operation} took ${entry.performance.duration}ms`);
    }

    return parts.join(' | ');
  }
}

/**
 * Structured logger for analytics
 */
export class StructuredLogger {
  private analytics?: AnalyticsEngineDataset;
  private context: LogContext;
  private minLevel: LogLevel;

  constructor(
    context: LogContext = {},
    minLevel: LogLevel = 'info',
    analytics?: AnalyticsEngineDataset
  ) {
    this.context = context;
    this.minLevel = minLevel;
    this.analytics = analytics;
  }

  /**
   * Core log method to also send to analytics
   */
  private log(
    level: LogLevel,
    message: string,
    context?: LogContext,
    error?: any,
    performance?: any
  ): void {
    // Check log level
    const levels = ['debug', 'info', 'warn', 'error', 'critical'];
    const currentLevel = levels.indexOf(this.minLevel);
    const messageLevel = levels.indexOf(level);

    if (messageLevel < currentLevel) {
      return;
    }

    // Create structured log entry
    const logEntry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      context: { ...this.context, ...context },
      error,
      performance
    };

    // Output to console
    this.outputToConsole(logEntry);

    // Send to analytics if configured
    if (this.analytics) {
      this.sendToAnalytics(level, message, context, error, performance);
    }
  }

  /**
   * Send log entry to analytics
   */
  private async sendToAnalytics(
    level: LogLevel,
    message: string,
    context?: LogContext,
    error?: any,
    performance?: any
  ): Promise<void> {
    try {
      const logData = {
        level,
        message,
        context: { ...this.context, ...context },
        error,
        performance,
        timestamp: Date.now()
      };

      await this.analytics!.writeDataPoint({
        blobs: [
          level,
          message,
          this.context.environment || 'unknown',
          this.context.requestId || 'unknown'
        ],
        doubles: [
          Date.now(),
          performance?.duration || 0,
          error ? 1 : 0
        ],
        indexes: [level, this.context.environment || 'unknown']
      });

    } catch (analyticsError) {
      // Don't let analytics failures break logging
    }
  }

  /**
   * Output log entry to console
   */
  private outputToConsole(entry: LogEntry): void {
    const output = this.formatLogEntry(entry);

    switch (entry.level) {
      case 'debug':
        console.debug(output);
        break;
      case 'info':
        console.info(output);
        break;
      case 'warn':
        break;
      case 'error':
      case 'critical':
        break;
      default:
    }
  }

  /**
   * Format log entry for output
   */
  private formatLogEntry(entry: LogEntry): string {
    const parts = [
      entry.timestamp,
      `[${entry.level.toUpperCase()}]`,
      entry.message
    ];

    if (entry.context && Object.keys(entry.context).length > 0) {
      parts.push(`Context: ${JSON.stringify(entry.context)}`);
    }

    if (entry.error) {
      parts.push(`Error: ${JSON.stringify(entry.error)}`);
    }

    if (entry.performance) {
      parts.push(`Performance: ${JSON.stringify(entry.performance)}`);
    }

    return parts.join(' | ');
  }

  // Public logging methods
  debug(message: string, context?: LogContext): void {
    this.log('debug', message, context);
  }

  info(message: string, context?: LogContext): void {
    this.log('info', message, context);
  }

  warn(message: string, context?: LogContext, error?: any): void {
    this.log('warn', message, context, error);
  }

  error(message: string, error?: any, context?: LogContext): void {
    this.log('error', message, context, error);
  }

  critical(message: string, error?: any, context?: LogContext): void {
    this.log('critical', message, context, error);
  }
}

/**
 * Request logger middleware
 */
export class RequestLogger {
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  /**
   * Log request start
   */
  logRequest(request: Request): { requestId: string; startTime: number } {
    const requestId = crypto.randomUUID();
    const startTime = Date.now();

    const url = new URL(request.url);

    this.logger.child({ requestId }).info('Request started', {
      method: request.method,
      path: url.pathname,
      query: url.search,
      ip: request.headers.get('CF-Connecting-IP') || undefined,
      userAgent: request.headers.get('User-Agent') || undefined,
      referer: request.headers.get('Referer') || undefined
    });

    return { requestId, startTime };
  }

  /**
   * Log request completion
   */
  logResponse(
    requestId: string,
    startTime: number,
    response: Response,
    additionalContext?: LogContext
  ): void {
    const duration = Date.now() - startTime;

    this.logger.child({ requestId }).info('Request completed', {
      status: response.status,
      duration,
      cacheStatus: response.headers.get('X-Cache'),
      ...additionalContext
    });

    // Log performance
    this.logger.performance('request_total', duration, { requestId });
  }

  /**
   * Log request error
   */
  logError(
    requestId: string,
    startTime: number,
    error: Error,
    additionalContext?: LogContext
  ): void {
    const duration = Date.now() - startTime;

    this.logger.child({ requestId }).error('Request failed', error, {
      duration,
      ...additionalContext
    });
  }
}

/**
 * Create logger from environment
 */
export function createLogger(env: any): Logger | StructuredLogger {
  const logLevel = (env.LOG_LEVEL || 'info') as LogLevel;
  const environment = env.ENVIRONMENT || 'unknown';

  const context: LogContext = {
    environment,
    service: 'coreflow360-worker'
  };

  // Use structured logger if analytics is available
  if (env.ANALYTICS) {
    return new StructuredLogger(context, logLevel, env.ANALYTICS);
  }

  return new Logger(context, logLevel);
}

/**
 * Performance monitoring decorator
 */
export function withPerformanceLogging(logger: Logger, operation: string) {
  return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const startTime = Date.now();

      try {
        const result = await method.apply(this, args);
        const duration = Date.now() - startTime;

        logger.performance(`${operation}_${propertyName}`, duration);

        return result;

      } catch (error) {
        const duration = Date.now() - startTime;

        logger.error(`${operation}_${propertyName} failed`, error, {
          duration
        });

        throw error;
      }
    };

    return descriptor;
  };
}

/**
 * Async error handler with logging
 */
export function withErrorLogging(logger: Logger, operation: string) {
  return function <T>(fn: () => Promise<T>): Promise<T> {
    return fn().catch(error => {
      logger.error(`${operation} failed`, error);
      throw error;
    });
  };
}