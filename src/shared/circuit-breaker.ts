/**
 * Circuit Breaker Pattern Implementation
 * Prevents cascading failures by stopping calls to failing services
 */

import { Logger } from './logger';

export interface CircuitBreakerOptions {
  failureThreshold: number; // Number of failures before opening circuit
  resetTimeout: number; // Time in ms before attempting to close circuit
  monitoringPeriod: number; // Time window for failure counting
  timeout: number; // Request timeout in ms
  onStateChange?: (state: CircuitBreakerState, name: string) => void;
  onFailure?: (error: Error, name: string) => void;
}

export enum CircuitBreakerState {
  CLOSED = 'closed',     // Normal operation, requests allowed
  OPEN = 'open',         // Circuit is open, requests rejected
  HALF_OPEN = 'half_open' // Testing if service recovered
}

export interface CircuitBreakerMetrics {
  state: CircuitBreakerState;
  failureCount: number;
  successCount: number;
  totalRequests: number;
  lastFailureTime?: number;
  lastSuccessTime?: number;
  failureRate: number;
}

export class CircuitBreaker {
  private state: CircuitBreakerState = CircuitBreakerState.CLOSED;
  private failureCount = 0;
  private successCount = 0;
  private totalRequests = 0;
  private lastFailureTime?: number;
  private lastSuccessTime?: number;
  private nextAttempt = 0;
  private logger: Logger;

  constructor(
    private name: string,
    private options: CircuitBreakerOptions
  ) {
    this.logger = new Logger();
    this.validateOptions();
  }

  /**
   * Execute a function with circuit breaker protection
   */
  async execute<T>(operation: () => Promise<T>): Promise<T> {
    this.totalRequests++;

    // Check if circuit is open and should remain so
    if (this.state === CircuitBreakerState.OPEN) {
      if (Date.now() < this.nextAttempt) {
        const error = new Error(`Circuit breaker [${this.name}] is OPEN`);
        this.logger.warn('Circuit breaker rejected request', {
          circuitName: this.name,
          state: this.state,
          failureCount: this.failureCount,
          nextAttempt: new Date(this.nextAttempt).toISOString()
        });
        throw error;
      }

      // Time to test if service recovered
      this.state = CircuitBreakerState.HALF_OPEN;
      this.notifyStateChange();
    }

    try {
      // Execute with timeout
      const result = await Promise.race([
        operation(),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`Operation timeout after ${this.options.timeout}ms`)), this.options.timeout)
        )
      ]);

      this.onSuccess();
      return result;

    } catch (error: any) {
      this.onFailure(error as Error);
      throw error;
    }
  }

  /**
   * Execute operation with retry logic
   */
  async executeWithRetry<T>(
    operation: () => Promise<T>,
    retries: number = 3,
    retryDelay: number = 1000
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 1; attempt <= retries + 1; attempt++) {
      try {
        return await this.execute(operation);
      } catch (error: any) {
        lastError = error as Error;

        // Don't retry if circuit is open
        if (this.state === CircuitBreakerState.OPEN) {
          throw error;
        }

        // Don't retry on the last attempt
        if (attempt === retries + 1) {
          break;
        }

        this.logger.debug('Operation failed, retrying', {
          circuitName: this.name,
          attempt,
          totalRetries: retries,
          error: lastError.message
        });

        // Exponential backoff
        const delay = retryDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw lastError!;
  }

  /**
   * Get current circuit breaker metrics
   */
  getMetrics(): CircuitBreakerMetrics {
    const failureRate = this.totalRequests > 0
      ? (this.failureCount / this.totalRequests) * 100
      : 0;

    return {
      state: this.state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      totalRequests: this.totalRequests,
      lastFailureTime: this.lastFailureTime,
      lastSuccessTime: this.lastSuccessTime,
      failureRate: Math.round(failureRate * 100) / 100
    };
  }

  /**
   * Manually reset circuit breaker
   */
  reset(): void {
    this.state = CircuitBreakerState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.totalRequests = 0;
    this.lastFailureTime = undefined;
    this.lastSuccessTime = undefined;
    this.nextAttempt = 0;

    this.logger.info('Circuit breaker manually reset', {
      circuitName: this.name
    });

    this.notifyStateChange();
  }

  /**
   * Force circuit to open state
   */
  forceOpen(): void {
    this.state = CircuitBreakerState.OPEN;
    this.nextAttempt = Date.now() + this.options.resetTimeout;

    this.logger.warn('Circuit breaker forced open', {
      circuitName: this.name,
      nextAttempt: new Date(this.nextAttempt).toISOString()
    });

    this.notifyStateChange();
  }

  /**
   * Get current state
   */
  getState(): CircuitBreakerState {
    return this.state;
  }

  /**
   * Check if circuit breaker is healthy
   */
  isHealthy(): boolean {
    if (this.state === CircuitBreakerState.OPEN) {
      return false;
    }

    if (this.totalRequests === 0) {
      return true;
    }

    const failureRate = (this.failureCount / this.totalRequests) * 100;
    return failureRate < 50; // Consider healthy if less than 50% failure rate
  }

  private onSuccess(): void {
    this.successCount++;
    this.lastSuccessTime = Date.now();

    if (this.state === CircuitBreakerState.HALF_OPEN) {
      // Service appears to be recovered
      this.state = CircuitBreakerState.CLOSED;
      this.failureCount = 0; // Reset failure count
      this.logger.info('Circuit breaker closed - service recovered', {
        circuitName: this.name,
        successCount: this.successCount
      });
      this.notifyStateChange();
    }

    // Clean up old failures outside monitoring period
    this.cleanupOldFailures();
  }

  private onFailure(error: Error): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    this.logger.warn('Circuit breaker recorded failure', {
      circuitName: this.name,
      failureCount: this.failureCount,
      threshold: this.options.failureThreshold,
      error: error.message
    });

    // Notify failure callback
    this.options.onFailure?.(error, this.name);

    if (this.state === CircuitBreakerState.HALF_OPEN) {
      // Failed during testing, back to open
      this.state = CircuitBreakerState.OPEN;
      this.nextAttempt = Date.now() + this.options.resetTimeout;
      this.logger.warn('Circuit breaker reopened after failed test', {
        circuitName: this.name,
        nextAttempt: new Date(this.nextAttempt).toISOString()
      });
      this.notifyStateChange();
    } else if (this.state === CircuitBreakerState.CLOSED && this.failureCount >= this.options.failureThreshold) {
      // Too many failures, open circuit
      this.state = CircuitBreakerState.OPEN;
      this.nextAttempt = Date.now() + this.options.resetTimeout;
      this.logger.error('Circuit breaker opened due to failure threshold', {
        circuitName: this.name,
        failureCount: this.failureCount,
        threshold: this.options.failureThreshold,
        nextAttempt: new Date(this.nextAttempt).toISOString()
      });
      this.notifyStateChange();
    }
  }

  private cleanupOldFailures(): void {
    // In a real implementation, we'd track individual failure timestamps
    // and clean up failures outside the monitoring period
    const cutoff = Date.now() - this.options.monitoringPeriod;

    if (this.lastFailureTime && this.lastFailureTime < cutoff) {
      this.failureCount = Math.max(0, this.failureCount - 1);
    }
  }

  private notifyStateChange(): void {
    this.options.onStateChange?.(this.state, this.name);
  }

  private validateOptions(): void {
    if (this.options.failureThreshold <= 0) {
      throw new Error('Failure threshold must be greater than 0');
    }
    if (this.options.resetTimeout <= 0) {
      throw new Error('Reset timeout must be greater than 0');
    }
    if (this.options.monitoringPeriod <= 0) {
      throw new Error('Monitoring period must be greater than 0');
    }
    if (this.options.timeout <= 0) {
      throw new Error('Timeout must be greater than 0');
    }
  }
}

/**
 * Circuit Breaker Registry for managing multiple circuit breakers
 */
export class CircuitBreakerRegistry {
  private breakers: Map<string, CircuitBreaker> = new Map();
  private logger: Logger;

  constructor() {
    this.logger = new Logger();
  }

  /**
   * Get or create a circuit breaker
   */
  getOrCreate(name: string, options: CircuitBreakerOptions): CircuitBreaker {
    if (!this.breakers.has(name)) {
      const breaker = new CircuitBreaker(name, options);
      this.breakers.set(name, breaker);

      this.logger.info('Circuit breaker created', {
        circuitName: name,
        options: {
          failureThreshold: options.failureThreshold,
          resetTimeout: options.resetTimeout,
          timeout: options.timeout
        }
      });
    }

    return this.breakers.get(name)!;
  }

  /**
   * Get all circuit breaker metrics
   */
  getAllMetrics(): Record<string, CircuitBreakerMetrics> {
    const metrics: Record<string, CircuitBreakerMetrics> = {};

    for (const [name, breaker] of this.breakers) {
      metrics[name] = breaker.getMetrics();
    }

    return metrics;
  }

  /**
   * Get health status of all circuit breakers
   */
  getHealthStatus(): {
    healthy: string[];
    unhealthy: string[];
    totalBreakers: number;
  } {
    const healthy: string[] = [];
    const unhealthy: string[] = [];

    for (const [name, breaker] of this.breakers) {
      if (breaker.isHealthy()) {
        healthy.push(name);
      } else {
        unhealthy.push(name);
      }
    }

    return {
      healthy,
      unhealthy,
      totalBreakers: this.breakers.size
    };
  }

  /**
   * Reset all circuit breakers
   */
  resetAll(): void {
    for (const [name, breaker] of this.breakers) {
      breaker.reset();
    }

    this.logger.info('All circuit breakers reset', {
      breakerCount: this.breakers.size
    });
  }

  /**
   * Remove a circuit breaker
   */
  remove(name: string): boolean {
    return this.breakers.delete(name);
  }

  /**
   * Get circuit breaker by name
   */
  get(name: string): CircuitBreaker | undefined {
    return this.breakers.get(name);
  }
}

// Global registry instance
export const circuitBreakerRegistry = new CircuitBreakerRegistry();

// Common circuit breaker configurations
export const CircuitBreakerConfigs = {
  // For database operations
  database: {
    failureThreshold: 5,
    resetTimeout: 30000, // 30 seconds
    monitoringPeriod: 60000, // 1 minute
    timeout: 10000 // 10 seconds
  },

  // For external API calls
  externalApi: {
    failureThreshold: 3,
    resetTimeout: 60000, // 1 minute
    monitoringPeriod: 120000, // 2 minutes
    timeout: 15000 // 15 seconds
  },

  // For AI service calls
  aiService: {
    failureThreshold: 3,
    resetTimeout: 45000, // 45 seconds
    monitoringPeriod: 90000, // 1.5 minutes
    timeout: 30000 // 30 seconds
  },

  // For critical operations
  critical: {
    failureThreshold: 2,
    resetTimeout: 120000, // 2 minutes
    monitoringPeriod: 300000, // 5 minutes
    timeout: 5000 // 5 seconds
  }
};