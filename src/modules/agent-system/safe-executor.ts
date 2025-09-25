/**
 * Safe Executor for Promise Handling
 * Prevents uncaught rejections and provides error boundaries
 */

import { Logger } from '../../shared/logger';

export interface ExecutionResult<T> {
  success: boolean;
  data?: T;
  error?: Error;
  duration: number;
  retries: number;
}

export interface ExecutorConfig {
  timeout?: number;
  retries?: number;
  retryDelay?: number;
  exponentialBackoff?: boolean;
  onError?: (error: Error) => void;
  onRetry?: (attempt: number, error: Error) => void;
  captureStackTrace?: boolean;
}

export class SafeExecutor {
  private logger: Logger;
  private unhandledRejections = new Map<Promise<any>, { error: any; timestamp: number }>();
  private executionStats = {
    total: 0,
    successful: 0,
    failed: 0,
    timedOut: 0,
    retried: 0
  };

  constructor() {
    this.logger = new Logger();
    this.setupGlobalHandlers();
  }

  /**
   * Setup global error handlers
   */
  private setupGlobalHandlers(): void {
    // Handle unhandled promise rejections
    if (typeof process !== 'undefined') {
      process.on('unhandledRejection', (reason, promise) => {
        this.handleUnhandledRejection(reason, promise);
      });

      process.on('uncaughtException', (error) => {
        this.handleUncaughtException(error);
      });
    }

    // Browser/Worker environment
    if (typeof self !== 'undefined' && self.addEventListener) {
      self.addEventListener('unhandledrejection', (event) => {
        this.handleUnhandledRejection(event.reason, event.promise);
        event.preventDefault();
      });

      self.addEventListener('error', (event) => {
        this.handleUncaughtException(event.error);
      });
    }
  }

  /**
   * Execute async function safely with retries and timeout
   */
  async execute<T>(
    fn: () => Promise<T>,
    config: ExecutorConfig = {}
  ): Promise<ExecutionResult<T>> {
    const {
      timeout = 30000,
      retries = 0,
      retryDelay = 1000,
      exponentialBackoff = true,
      onError,
      onRetry,
      captureStackTrace = true
    } = config;

    const startTime = Date.now();
    let lastError: Error | undefined;
    let attemptCount = 0;

    this.executionStats.total++;

    for (let attempt = 0; attempt <= retries; attempt++) {
      attemptCount = attempt;

      try {
        // Create timeout promise
        const timeoutPromise = timeout > 0
          ? new Promise<never>((_, reject) => {
              setTimeout(() => reject(new TimeoutError(`Execution timed out after ${timeout}ms`)), timeout);
            })
          : null;

        // Execute function with timeout
        const result = timeoutPromise
          ? await Promise.race([fn(), timeoutPromise])
          : await fn();

        this.executionStats.successful++;

        return {
          success: true,
          data: result,
          duration: Date.now() - startTime,
          retries: attempt
        };

      } catch (error) {
        lastError = this.normalizeError(error, captureStackTrace);

        // Log the error
        this.logger.error('Execution failed', lastError, {
          attempt: attempt + 1,
          maxRetries: retries + 1
        });

        // Call error handler
        if (onError) {
          try {
            onError(lastError);
          } catch (handlerError) {
            this.logger.error('Error handler failed', handlerError);
          }
        }

        // Check if it's a timeout
        if (lastError instanceof TimeoutError) {
          this.executionStats.timedOut++;
        }

        // If not the last attempt, retry
        if (attempt < retries) {
          this.executionStats.retried++;

          // Calculate delay
          const delay = exponentialBackoff
            ? retryDelay * Math.pow(2, attempt)
            : retryDelay;

          // Call retry handler
          if (onRetry) {
            try {
              onRetry(attempt + 1, lastError);
            } catch (handlerError) {
              this.logger.error('Retry handler failed', handlerError);
            }
          }

          this.logger.info(`Retrying after ${delay}ms`, {
            attempt: attempt + 1,
            delay
          });

          await this.sleep(delay);
        }
      }
    }

    this.executionStats.failed++;

    return {
      success: false,
      error: lastError,
      duration: Date.now() - startTime,
      retries: attemptCount
    };
  }

  /**
   * Execute multiple promises safely in parallel
   */
  async executeParallel<T>(
    tasks: Array<() => Promise<T>>,
    config: ExecutorConfig & { concurrency?: number } = {}
  ): Promise<Array<ExecutionResult<T>>> {
    const { concurrency = Infinity, ...executorConfig } = config;

    if (concurrency === Infinity) {
      // Execute all in parallel
      return Promise.all(
        tasks.map(task => this.execute(task, executorConfig))
      );
    }

    // Execute with limited concurrency
    const results: Array<ExecutionResult<T>> = [];
    const executing: Array<Promise<void>> = [];

    for (let i = 0; i < tasks.length; i++) {
      const task = tasks[i];

      const promise = this.execute(task, executorConfig).then(result => {
        results[i] = result;
      });

      executing.push(promise);

      if (executing.length >= concurrency) {
        await Promise.race(executing);
        // Remove completed promises
        executing.splice(
          executing.findIndex(p => p === promise),
          1
        );
      }
    }

    await Promise.all(executing);
    return results;
  }

  /**
   * Execute with circuit breaker pattern
   */
  createCircuitBreaker<T>(
    fn: () => Promise<T>,
    options: {
      threshold: number;
      timeout: number;
      resetTimeout: number;
    }
  ): () => Promise<T> {
    let failures = 0;
    let lastFailureTime = 0;
    let state: 'closed' | 'open' | 'half-open' = 'closed';

    return async () => {
      // Check if circuit should be reset
      if (state === 'open' && Date.now() - lastFailureTime > options.resetTimeout) {
        state = 'half-open';
        failures = 0;
      }

      // If circuit is open, reject immediately
      if (state === 'open') {
        throw new CircuitBreakerError('Circuit breaker is open');
      }

      try {
        const result = await this.execute(fn, { timeout: options.timeout });

        if (result.success) {
          // Reset on success
          if (state === 'half-open') {
            state = 'closed';
          }
          failures = 0;
          return result.data!;
        } else {
          throw result.error || new Error('Execution failed');
        }

      } catch (error) {
        failures++;
        lastFailureTime = Date.now();

        if (failures >= options.threshold) {
          state = 'open';
          this.logger.warn('Circuit breaker opened', {
            failures,
            threshold: options.threshold
          });
        }

        throw error;
      }
    };
  }

  /**
   * Create error boundary for synchronous code
   */
  errorBoundary<T>(
    fn: () => T,
    fallback?: T | ((error: Error) => T)
  ): T {
    try {
      return fn();
    } catch (error) {
      const normalizedError = this.normalizeError(error, true);
      this.logger.error('Error boundary caught error', normalizedError);

      if (fallback !== undefined) {
        if (typeof fallback === 'function') {
          try {
            return (fallback as (error: Error) => T)(normalizedError);
          } catch (fallbackError) {
            this.logger.error('Fallback function failed', fallbackError);
            throw normalizedError;
          }
        }
        return fallback;
      }

      throw normalizedError;
    }
  }

  /**
   * Wrap async function with automatic error handling
   */
  wrap<T extends (...args: any[]) => Promise<any>>(
    fn: T,
    config?: ExecutorConfig
  ): T {
    return (async (...args: Parameters<T>) => {
      const result = await this.execute(() => fn(...args), config);
      if (result.success) {
        return result.data;
      }
      throw result.error;
    }) as T;
  }

  /**
   * Handle unhandled promise rejection
   */
  private handleUnhandledRejection(reason: any, promise: Promise<any>): void {
    const error = this.normalizeError(reason, true);

    this.unhandledRejections.set(promise, {
      error,
      timestamp: Date.now()
    });

    this.logger.error('Unhandled promise rejection', error, {
      rejectionCount: this.unhandledRejections.size
    });

    // Clean up old rejections (older than 5 minutes)
    const cutoff = Date.now() - 300000;
    for (const [p, info] of this.unhandledRejections) {
      if (info.timestamp < cutoff) {
        this.unhandledRejections.delete(p);
      }
    }
  }

  /**
   * Handle uncaught exception
   */
  private handleUncaughtException(error: any): void {
    const normalizedError = this.normalizeError(error, true);

    this.logger.error('Uncaught exception', normalizedError, {
      fatal: true
    });

    // In production, you might want to gracefully shutdown
    // For now, we'll just log it
  }

  /**
   * Normalize error object
   */
  private normalizeError(error: any, captureStack: boolean): Error {
    if (error instanceof Error) {
      if (captureStack && !error.stack) {
        Error.captureStackTrace(error);
      }
      return error;
    }

    const normalizedError = new Error(
      typeof error === 'string' ? error : JSON.stringify(error)
    );

    if (captureStack) {
      Error.captureStackTrace(normalizedError);
    }

    return normalizedError;
  }

  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get execution statistics
   */
  getStats(): typeof this.executionStats {
    return { ...this.executionStats };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.executionStats = {
      total: 0,
      successful: 0,
      failed: 0,
      timedOut: 0,
      retried: 0
    };
  }

  /**
   * Get unhandled rejections
   */
  getUnhandledRejections(): Array<{ error: Error; timestamp: number }> {
    return Array.from(this.unhandledRejections.values());
  }
}

/**
 * Custom error types
 */
export class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TimeoutError';
  }
}

export class CircuitBreakerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CircuitBreakerError';
  }
}

/**
 * Promise utilities
 */
export class PromiseUtils {
  /**
   * Create a deferred promise
   */
  static deferred<T>(): {
    promise: Promise<T>;
    resolve: (value: T) => void;
    reject: (error: any) => void;
  } {
    let resolve: (value: T) => void;
    let reject: (error: any) => void;

    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });

    return { promise, resolve: resolve!, reject: reject! };
  }

  /**
   * Promise with timeout
   */
  static withTimeout<T>(promise: Promise<T>, timeout: number): Promise<T> {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        setTimeout(() => reject(new TimeoutError(`Promise timed out after ${timeout}ms`)), timeout);
      })
    ]);
  }

  /**
   * Retry promise
   */
  static async retry<T>(
    fn: () => Promise<T>,
    retries: number = 3,
    delay: number = 1000,
    exponential: boolean = true
  ): Promise<T> {
    let lastError: Error;

    for (let i = 0; i <= retries; i++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (i < retries) {
          const waitTime = exponential ? delay * Math.pow(2, i) : delay;
          await new Promise(resolve => setTimeout(resolve, waitTime));
        }
      }
    }

    throw lastError!;
  }

  /**
   * All settled with timeout
   */
  static allSettledWithTimeout<T>(
    promises: Array<Promise<T>>,
    timeout: number
  ): Promise<Array<PromiseSettledResult<T>>> {
    const wrappedPromises = promises.map(p =>
      this.withTimeout(p, timeout).catch(error => Promise.reject(error))
    );

    return Promise.allSettled(wrappedPromises);
  }

  /**
   * Map with concurrency limit
   */
  static async mapLimit<T, R>(
    items: T[],
    limit: number,
    fn: (item: T, index: number) => Promise<R>
  ): Promise<R[]> {
    const results: R[] = new Array(items.length);
    const executing: Promise<void>[] = [];

    for (let i = 0; i < items.length; i++) {
      const promise = fn(items[i], i).then(result => {
        results[i] = result;
      });

      executing.push(promise as Promise<void>);

      if (executing.length >= limit) {
        await Promise.race(executing);
        executing.splice(
          executing.findIndex(p => p === promise),
          1
        );
      }
    }

    await Promise.all(executing);
    return results;
  }
}

// Export singleton instance
export const safeExecutor = new SafeExecutor();