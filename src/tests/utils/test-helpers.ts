/**
 * Test Utilities and Helpers
 * Common testing utilities for CoreFlow360 V4
 */

import { expect } from 'vitest';
import type { Context } from 'hono';
import type { Env } from '../../types/env';

/**
 * Wait for a condition to be true with timeout
 */
export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  options: {
    timeout?: number;
    interval?: number;
    message?: string;
  } = {}
): Promise<void> {
  const { timeout = 5000, interval = 100, message = 'Condition not met' } = options;

  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, interval));
  }

  throw new Error(message);
}

/**
 * Wait for specified duration
 */
export function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retry a function until it succeeds or max attempts reached
 */
export async function retry<T>(
  fn: () => T | Promise<T>,
  options: {
    maxAttempts?: number;
    delay?: number;
    backoff?: number;
  } = {}
): Promise<T> {
  const { maxAttempts = 3, delay = 100, backoff = 2 } = options;

  let lastError: Error | null = null;
  let currentDelay = delay;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt < maxAttempts) {
        await wait(currentDelay);
        currentDelay *= backoff;
      }
    }
  }

  throw lastError || new Error('Retry failed');
}

/**
 * Assert that a promise rejects with specific error
 */
export async function expectError(
  promise: Promise<any>,
  errorMatch?: string | RegExp | Error
): Promise<void> {
  try {
    await promise;
    throw new Error('Expected promise to reject, but it resolved');
  } catch (error) {
    if (errorMatch) {
      if (typeof errorMatch === 'string') {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain(errorMatch);
      } else if (errorMatch instanceof RegExp) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toMatch(errorMatch);
      } else {
        expect(error).toBeInstanceOf(errorMatch.constructor);
        expect((error as Error).message).toBe(errorMatch.message);
      }
    }
  }
}

/**
 * Create a spy function that tracks calls
 */
export function createSpy<T extends (...args: any[]) => any>(
  implementation?: T
): T & {
  calls: Array<{ args: Parameters<T>; result: ReturnType<T> }>;
  callCount: number;
  reset: () => void;
} {
  const calls: Array<{ args: Parameters<T>; result: ReturnType<T> }> = [];

  const spy = ((...args: Parameters<T>) => {
    const result = implementation ? implementation(...args) : undefined;
    calls.push({ args, result });
    return result;
  }) as any;

  spy.calls = calls;
  Object.defineProperty(spy, 'callCount', {
    get: () => calls.length,
  });
  spy.reset = () => {
    calls.length = 0;
  };

  return spy;
}

/**
 * Mock console methods for testing
 */
export function mockConsole(): {
  restore: () => void;
  getLogs: () => string[];
  getWarnings: () => string[];
  getErrors: () => string[];
} {
  const originalLog = console.log;
  const originalWarn = console.warn;
  const originalError = console.error;

  const logs: string[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];

  console.log = (...args: any[]) => {
    logs.push(args.map(String).join(' '));
  };

  console.warn = (...args: any[]) => {
    warnings.push(args.map(String).join(' '));
  };

  console.error = (...args: any[]) => {
    errors.push(args.map(String).join(' '));
  };

  return {
    restore: () => {
      console.log = originalLog;
      console.warn = originalWarn;
      console.error = originalError;
    },
    getLogs: () => [...logs],
    getWarnings: () => [...warnings],
    getErrors: () => [...errors],
  };
}

/**
 * Create mock Hono context for testing
 */
export function createMockContext(overrides?: Partial<{
  env: Env;
  req: Request;
  var: Record<string, any>;
}>): Context {
  const mockContext = {
    req: overrides?.req || new Request('http://localhost:8787/test'),
    env: overrides?.env || {},
    var: overrides?.var || {},
    executionCtx: {
      waitUntil: () => {},
      passThroughOnException: () => {},
    },
    get: function (key: string) {
      return this.var[key];
    },
    set: function (key: string, value: any) {
      this.var[key] = value;
    },
    header: () => {},
    status: () => {},
    json: (data: any) => Response.json(data),
    text: (text: string) => new Response(text),
    html: (html: string) => new Response(html, {
      headers: { 'content-type': 'text/html' },
    }),
    redirect: (url: string) => Response.redirect(url),
    notFound: () => new Response('Not Found', { status: 404 }),
  } as any;

  return mockContext;
}

/**
 * Generate random test data
 */
export const random = {
  string: (length: number = 10): string => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    return Array.from({ length }, () =>
      chars.charAt(Math.floor(Math.random() * chars.length))
    ).join('');
  },

  number: (min: number = 0, max: number = 100): number => {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  },

  email: (): string => {
    return `test-${random.string(8)}@example.com`;
  },

  uuid: (): string => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  },

  boolean: (): boolean => {
    return Math.random() > 0.5;
  },

  date: (daysFromNow: number = 0): Date => {
    const date = new Date();
    date.setDate(date.getDate() + daysFromNow);
    return date;
  },

  element: <T>(array: T[]): T => {
    return array[Math.floor(Math.random() * array.length)];
  },
};

/**
 * Assert response properties
 */
export async function assertResponse(
  response: Response,
  expected: {
    status?: number;
    headers?: Record<string, string>;
    json?: any;
    text?: string;
  }
): Promise<void> {
  if (expected.status !== undefined) {
    expect(response.status).toBe(expected.status);
  }

  if (expected.headers) {
    for (const [key, value] of Object.entries(expected.headers)) {
      expect(response.headers.get(key)).toBe(value);
    }
  }

  if (expected.json !== undefined) {
    const data = await response.json();
    expect(data).toEqual(expected.json);
  }

  if (expected.text !== undefined) {
    const text = await response.text();
    expect(text).toBe(expected.text);
  }
}

/**
 * Deep clone object
 */
export function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Deep equality check
 */
export function deepEqual(a: any, b: any): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Suppress console output during test execution
 */
export function suppressConsole(fn: () => void | Promise<void>): Promise<void> {
  const mock = mockConsole();
  try {
    return Promise.resolve(fn()).finally(() => mock.restore());
  } catch (error) {
    mock.restore();
    throw error;
  }
}

/**
 * Create time-based test isolation
 */
export class TimeController {
  private originalNow: typeof Date.now;
  private mockTime: number;

  constructor(initialTime?: number) {
    this.originalNow = Date.now;
    this.mockTime = initialTime || Date.now();
  }

  /**
   * Install mock time
   */
  install(): void {
    Date.now = () => this.mockTime;
  }

  /**
   * Restore original time
   */
  restore(): void {
    Date.now = this.originalNow;
  }

  /**
   * Advance time by milliseconds
   */
  advance(ms: number): void {
    this.mockTime += ms;
  }

  /**
   * Set specific time
   */
  setTime(time: number | Date): void {
    this.mockTime = typeof time === 'number' ? time : time.getTime();
  }

  /**
   * Get current mock time
   */
  now(): number {
    return this.mockTime;
  }
}

/**
 * Performance measurement helper
 */
export async function measurePerformance<T>(
  fn: () => T | Promise<T>
): Promise<{ result: T; duration: number }> {
  const start = performance.now();
  const result = await fn();
  const duration = performance.now() - start;
  return { result, duration };
}

/**
 * Assert performance requirements
 */
export async function assertPerformance<T>(
  fn: () => T | Promise<T>,
  maxDuration: number,
  message?: string
): Promise<T> {
  const { result, duration } = await measurePerformance(fn);

  if (duration > maxDuration) {
    throw new Error(
      message ||
        `Performance assertion failed: ${duration.toFixed(2)}ms > ${maxDuration}ms`
    );
  }

  return result;
}
