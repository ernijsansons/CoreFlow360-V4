/**
 * Structured logging framework for CoreFlow360 V4
 * Provides secure, performant, and correlation-aware logging
 */

import { PIIRedactor, InputValidator, type SecurityContext } from './security-utils';

/**
 * Log levels in order of severity
 */
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  CRITICAL = 4,
}

/**
 * Log entry structure
 */
export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  correlationId?: string;
  userId?: string;
  businessId?: string;
  operation?: string;
  component: string;
  context?: Record<string, unknown>;
  error?: {
    name: string;
    message: string;
    stack?: string;
    code?: string;
  };
  performance?: {
    duration?: number;
    startTime?: number;
    endTime?: number;
  };
  security?: {
    ipAddress?: string;
    userAgent?: string;
    sessionId?: string;
  };
}

/**
 * Logger configuration
 */
export interface LoggerConfig {
  level: LogLevel;
  environment: 'development' | 'staging' | 'production';
  component: string;
  enableConsole: boolean;
  enableRedaction: boolean;
  maxContextSize: number;
  bufferSize: number;
  flushInterval: number;
}

/**
 * Default logger configuration
 */
const DEFAULT_CONFIG: LoggerConfig = {
  level: LogLevel.INFO,
  environment: 'production',
  component: 'unknown',
  enableConsole: true,
  enableRedaction: true,
  maxContextSize: 1000,
  bufferSize: 100,
  flushInterval: 5000, // 5 seconds
};

/**
 * Structured logger with security features
 */
export class Logger {
  private config: LoggerConfig;
  private buffer: LogEntry[] = [];
  private flushTimer?: NodeJS.Timeout;
  private stats = {
    logsGenerated: 0,
    logsSuppressed: 0,
    errorsEncountered: 0,
    lastFlush: 0,
  };

  constructor(config: Partial<LoggerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    // Don't start timer in constructor (not allowed in Workers global scope)
    // Timer will be started on first log
  }

  /**
   * Debug level logging
   */
  debug(message: string, context?: Record<string, unknown>, securityContext?: SecurityContext): void {
    this.log(LogLevel.DEBUG, message, context, securityContext);
  }

  /**
   * Info level logging
   */
  info(message: string, context?: Record<string, unknown>, securityContext?: SecurityContext): void {
    this.log(LogLevel.INFO, message, context, securityContext);
  }

  /**
   * Warning level logging
   */
  warn(message: string, context?: Record<string, unknown>, securityContext?: SecurityContext): void {
    this.log(LogLevel.WARN, message, context, securityContext);
  }

  /**
   * Error level logging
   */
  error(
    message: string,
    error?: Error | unknown,
    context?: Record<string, unknown>,
    securityContext?: SecurityContext
  ): void {
    const errorInfo = this.extractErrorInfo(error);
    this.log(LogLevel.ERROR, message, { ...context, error: errorInfo }, securityContext);
  }

  /**
   * Critical level logging
   */
  critical(
    message: string,
    error?: Error | unknown,
    context?: Record<string, unknown>,
    securityContext?: SecurityContext
  ): void {
    const errorInfo = this.extractErrorInfo(error);
    this.log(LogLevel.CRITICAL, message, { ...context, error: errorInfo }, securityContext);
  }

  /**
   * Performance logging
   */
  performance(
    operation: string,
    duration: number,
    context?: Record<string, unknown>,
    securityContext?: SecurityContext
  ): void {
    this.log(
      LogLevel.INFO,
      `Performance: ${operation}`,
      {
        ...context,
        performance: {
          operation,
          duration,
          endTime: Date.now(),
          startTime: Date.now() - duration,
        },
      },
      securityContext
    );
  }

  /**
   * Security event logging
   */
  security(
    event: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    context?: Record<string, unknown>,
    securityContext?: SecurityContext
  ): void {
    const level = severity === 'critical' ? LogLevel.CRITICAL :
                  severity === 'high' ? LogLevel.ERROR :
                  severity === 'medium' ? LogLevel.WARN : LogLevel.INFO;

    this.log(
      level,
      `Security: ${event}`,
      {
        ...context,
        securityEvent: true,
        severity,
      },
      securityContext
    );
  }

  /**
   * Audit logging for compliance
   */
  audit(
    action: string,
    resource?: {
      type: string;
      id?: string;
    },
    context?: Record<string, unknown>,
    securityContext?: SecurityContext
  ): void {
    this.log(
      LogLevel.INFO,
      `Audit: ${action}`,
      {
        ...context,
        audit: true,
        action,
        resource,
        timestamp: new Date().toISOString(),
      },
      securityContext
    );
  }

  /**
   * ABAC-specific logging
   */
  abac(
    operation: 'permission_check' | 'policy_evaluation' | 'cache_operation' | 'invalidation',
    result: 'allow' | 'deny' | 'error' | 'success',
    details: {
      capability?: string;
      evaluationTimeMs?: number;
      cacheHit?: boolean;
      fastPath?: string;
      policyCount?: number;
    },
    context?: Record<string, unknown>,
    securityContext?: SecurityContext
  ): void {
    this.log(
      result === 'error' ? LogLevel.ERROR : LogLevel.INFO,
      `ABAC: ${operation} - ${result}`,
      {
        ...context,
        abac: true,
        operation,
        result,
        details,
      },
      securityContext
    );
  }

  /**
   * Core logging method
   */
  private log(
    level: LogLevel,
    message: string,
    context?: Record<string, unknown>,
    securityContext?: SecurityContext
  ): void {
    try {
      // Start flush timer on first log (lazy initialization for Workers compatibility)
      if (!this.flushTimer && typeof setInterval !== 'undefined') {
        this.startFlushTimer();
      }

      // Check if we should log at this level
      if (level < this.config.level) {
        this.stats.logsSuppressed++;
        return;
      }

      // Create log entry
      const entry = this.createLogEntry(level, message, context, securityContext);

      // Add to buffer
      this.buffer.push(entry);
      this.stats.logsGenerated++;

      // Immediate console output for errors and critical logs
      if (this.config.enableConsole && (level >= LogLevel.ERROR || this.config.environment === 'development')) {
        this.outputToConsole(entry);
      }

      // Flush buffer if full
      if (this.buffer.length >= this.config.bufferSize) {
        this.flush();
      }

      // Immediate flush for critical logs
      if (level >= LogLevel.CRITICAL) {
        this.flush();
      }

    } catch (error: any) {
      this.stats.errorsEncountered++;

      // Fallback console logging if logger fails
    }
  }

  /**
   * Create structured log entry
   */
  private createLogEntry(
    level: LogLevel,
    message: string,
    context?: Record<string, unknown>,
    securityContext?: SecurityContext
  ): LogEntry {
    const timestamp = new Date().toISOString();

    // Sanitize and redact context
    let sanitizedContext = context ? this.sanitizeContext(context) : undefined;

    if (this.config.enableRedaction && sanitizedContext) {
      sanitizedContext = PIIRedactor.redactSensitiveData(sanitizedContext);
    }

    const entry: LogEntry = {
      timestamp,
      level,
      message: InputValidator.sanitizeForLogging(message),
      component: this.config.component,
    };

    // Add security context if available
    if (securityContext) {
      entry.correlationId = securityContext.correlationId;
      entry.userId = this.config.enableRedaction
        ? PIIRedactor.redactUserId(securityContext.userId)
        : securityContext.userId;
      entry.businessId = this.config.enableRedaction
        ? PIIRedactor.redactUserId(securityContext.businessId) // Using same redaction as userId
        : securityContext.businessId;
      entry.operation = securityContext.operation;
      entry.security = {
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        sessionId: this.config.enableRedaction
          ? PIIRedactor.redactSessionId(securityContext.sessionId)
          : securityContext.sessionId,
      };
    }

    // Add context if provided
    if (sanitizedContext) {
      entry.context = sanitizedContext;
    }

    return entry;
  }

  /**
   * Sanitize context object
   */
  private sanitizeContext(context: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(context)) {
      try {
        // Limit context size
        const serialized = JSON.stringify(value);
        if (serialized.length > this.config.maxContextSize) {
          sanitized[key] = `[TRUNCATED:${serialized.length}]`;
        } else {
          sanitized[key] = value;
        }
      } catch (error: any) {
        sanitized[key] = '[UNSERIALIZABLE]';
      }
    }

    return sanitized;
  }

  /**
   * Extract error information safely
   */
  private extractErrorInfo(error?: Error | unknown): Record<string, unknown> | undefined {
    if (!error) return undefined;

    if (error instanceof Error) {
      return {
        name: error.name,
        message: error.message,
        stack: this.config.environment === 'development' ? error.stack : undefined,
        code: 'code' in error ? error.code : undefined,
      };
    }

    return {
      name: 'UnknownError',
      message: String(error),
    };
  }

  /**
   * Output to console with formatting
   */
  private outputToConsole(entry: LogEntry): void {
    const levelNames = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'];
    const levelName = levelNames[entry.level] || 'UNKNOWN';

    const logLine = {
      timestamp: entry.timestamp,
      level: levelName,
      component: entry.component,
      message: entry.message,
      correlationId: entry.correlationId,
      ...(entry.context && { context: entry.context }),
      ...(entry.error && { error: entry.error }),
      ...(entry.performance && { performance: entry.performance }),
      ...(entry.security && { security: entry.security }),
    };

    switch (entry.level) {
      case LogLevel.DEBUG:
        console.debug(JSON.stringify(logLine));
        break;
      case LogLevel.INFO:
        break;
      case LogLevel.WARN:
        break;
      case LogLevel.ERROR:
      case LogLevel.CRITICAL:
        break;
    }
  }

  /**
   * Flush buffered logs
   */
  flush(): void {
    if (this.buffer.length === 0) return;

    try {
      // In a real implementation, you might send to external logging service
      if (this.config.enableConsole && this.config.environment !== 'development') {
        this.buffer.forEach((entry: any) => this.outputToConsole(entry));
      }

      // Clear buffer
      this.buffer = [];
      this.stats.lastFlush = Date.now();

    } catch (error: any) {
      this.stats.errorsEncountered++;
    }
  }

  /**
   * Start automatic buffer flushing
   */
  private startFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      this.flush();
    }, this.config.flushInterval);
  }

  /**
   * Stop logger and flush remaining logs
   */
  destroy(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    this.flush();
  }

  /**
   * Get logger statistics
   */
  getStats(): typeof this.stats & { bufferSize: number } {
    return {
      ...this.stats,
      bufferSize: this.buffer.length,
    };
  }

  /**
   * Update logger configuration
   */
  updateConfig(config: Partial<LoggerConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Check if logging is enabled for level
   */
  isLevelEnabled(level: LogLevel): boolean {
    return level >= this.config.level;
  }
}

/**
 * Logger factory for different components
 */
export class LoggerFactory {
  private static loggers = new Map<string, Logger>();
  private static globalConfig: Partial<LoggerConfig> = {};

  /**
   * Set global configuration for all loggers
   */
  static setGlobalConfig(config: Partial<LoggerConfig>): void {
    this.globalConfig = { ...this.globalConfig, ...config };

    // Update existing loggers
    this.loggers.forEach((logger: any) => {
      logger.updateConfig(config);
    });
  }

  /**
   * Get or create logger for component
   */
  static getLogger(component: string, config?: Partial<LoggerConfig>): Logger {
    if (!this.loggers.has(component)) {
      const loggerConfig = {
        ...this.globalConfig,
        ...config,
        component,
      };

      this.loggers.set(component, new Logger(loggerConfig));
    }

    return this.loggers.get(component)!;
  }

  /**
   * Get all active loggers
   */
  static getAllLoggers(): Map<string, Logger> {
    return new Map(this.loggers);
  }

  /**
   * Destroy all loggers
   */
  static destroyAll(): void {
    this.loggers.forEach((logger: any) => logger.destroy());
    this.loggers.clear();
  }

  /**
   * Get aggregated statistics
   */
  static getAggregatedStats(): {
    totalLoggers: number;
    totalLogsGenerated: number;
    totalLogsSuppressed: number;
    totalErrorsEncountered: number;
    componentStats: Record<string, ReturnType<Logger['getStats']>>;
  } {
    const componentStats: Record<string, ReturnType<Logger['getStats']>> = {};
    let totalLogsGenerated = 0;
    let totalLogsSuppressed = 0;
    let totalErrorsEncountered = 0;

    this.loggers.forEach((logger, component) => {
      const stats = logger.getStats();
      componentStats[component] = stats;
      totalLogsGenerated += stats.logsGenerated;
      totalLogsSuppressed += stats.logsSuppressed;
      totalErrorsEncountered += stats.errorsEncountered;
    });

    return {
      totalLoggers: this.loggers.size,
      totalLogsGenerated,
      totalLogsSuppressed,
      totalErrorsEncountered,
      componentStats,
    };
  }
}

/**
 * Default logger instances for common components
 * Using lazy initialization to avoid global scope issues in Workers
 */
let _logger: Logger | undefined;
let _securityLogger: Logger | undefined;
let _abacLogger: Logger | undefined;
let _performanceLogger: Logger | undefined;
let _auditLogger: Logger | undefined;

export const logger = {
  debug: (message: string, context?: any) => (_logger || (_logger = LoggerFactory.getLogger('core'))).debug(message, context),
  info: (message: string, context?: any) => (_logger || (_logger = LoggerFactory.getLogger('core'))).info(message, context),
  warn: (message: string, context?: any) => (_logger || (_logger = LoggerFactory.getLogger('core'))).warn(message, context),
  error: (message: string, context?: any) => (_logger || (_logger = LoggerFactory.getLogger('core'))).error(message, context),
};

export const securityLogger = {
  debug: (message: string, context?: any) => (_securityLogger || (_securityLogger = LoggerFactory.getLogger('security'))).debug(message, context),
  info: (message: string, context?: any) => (_securityLogger || (_securityLogger = LoggerFactory.getLogger('security'))).info(message, context),
  warn: (message: string, context?: any) => (_securityLogger || (_securityLogger = LoggerFactory.getLogger('security'))).warn(message, context),
  error: (message: string, context?: any) => (_securityLogger || (_securityLogger = LoggerFactory.getLogger('security'))).error(message, context),
};

export const abacLogger = {
  debug: (message: string, context?: any) => (_abacLogger || (_abacLogger = LoggerFactory.getLogger('abac'))).debug(message, context),
  info: (message: string, context?: any) => (_abacLogger || (_abacLogger = LoggerFactory.getLogger('abac'))).info(message, context),
  warn: (message: string, context?: any) => (_abacLogger || (_abacLogger = LoggerFactory.getLogger('abac'))).warn(message, context),
  error: (message: string, context?: any) => (_abacLogger || (_abacLogger = LoggerFactory.getLogger('abac'))).error(message, context),
};

export const performanceLogger = {
  debug: (message: string, context?: any) => (_performanceLogger || (_performanceLogger = LoggerFactory.getLogger('performance'))).debug(message, context),
  info: (message: string, context?: any) => (_performanceLogger || (_performanceLogger = LoggerFactory.getLogger('performance'))).info(message, context),
  warn: (message: string, context?: any) => (_performanceLogger || (_performanceLogger = LoggerFactory.getLogger('performance'))).warn(message, context),
  error: (message: string, context?: any) => (_performanceLogger || (_performanceLogger = LoggerFactory.getLogger('performance'))).error(message, context),
};

export const auditLogger = {
  debug: (message: string, context?: any) => (_auditLogger || (_auditLogger = LoggerFactory.getLogger('audit'))).debug(message, context),
  info: (message: string, context?: any) => (_auditLogger || (_auditLogger = LoggerFactory.getLogger('audit'))).info(message, context),
  warn: (message: string, context?: any) => (_auditLogger || (_auditLogger = LoggerFactory.getLogger('audit'))).warn(message, context),
  error: (message: string, context?: any) => (_auditLogger || (_auditLogger = LoggerFactory.getLogger('audit'))).error(message, context),
};

/**
 * Initialize logging with environment configuration
 */
export function initializeLogging(environment: string): void {
  const config: Partial<LoggerConfig> = {
    environment: environment as LoggerConfig['environment'],
    level: environment === 'development' ? LogLevel.DEBUG : LogLevel.INFO,
    enableConsole: true,
    enableRedaction: environment !== 'development',
  };

  LoggerFactory.setGlobalConfig(config);
}

/**
 * Performance measurement utility
 */
export class PerformanceTimer {
  private startTime: number;
  private operation: string;
  private logger: Logger;
  private context?: Record<string, unknown>;
  private securityContext?: SecurityContext;

  constructor(
    operation: string,
    logger: any = performanceLogger,
    context?: Record<string, unknown>,
    securityContext?: SecurityContext
  ) {
    this.startTime = performance.now();
    this.operation = operation;
    this.logger = logger;
    this.context = context;
    this.securityContext = securityContext;
  }

  /**
   * End timing and log result
   */
  end(): number {
    const duration = performance.now() - this.startTime;

    this.logger.performance(
      this.operation,
      duration,
      this.context,
      this.securityContext
    );

    return duration;
  }

  /**
   * Get current duration without logging
   */
  getDuration(): number {
    return performance.now() - this.startTime;
  }
}

/**
 * Decorator for automatic performance logging
 */
export function logPerformance(operation?: string) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    const operationName = operation || `${target.constructor.name}.${propertyKey}`;

    descriptor.value = async function (...args: any[]) {
      const timer = new PerformanceTimer(operationName);

      try {
        const result = await originalMethod.apply(this, args);
        timer.end();
        return result;
      } catch (error: any) {
        const duration = timer.getDuration();
        performanceLogger.error(
          `Performance: ${operationName} failed`,
          { error, duration }
        );
        throw error;
      }
    };

    return descriptor;
  };
}