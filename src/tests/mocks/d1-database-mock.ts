/**
 * Production-Quality MockD1Database
 * Fully implements Cloudflare D1Database interface for testing
 *
 * Features:
 * - Complete method signature matching
 * - D1PreparedStatement support
 * - Batch operations
 * - Type-safe implementation
 *
 * @see @cloudflare/workers-types D1Database
 */

import type { D1Database, D1PreparedStatement, D1Result, D1ExecResult } from '@cloudflare/workers-types';

/**
 * Mock D1PreparedStatement implementation
 */
class MockD1PreparedStatement implements D1PreparedStatement {
  private boundValues: any[] = [];

  constructor(
    private query: string,
    private mockResults: any[] = [],
    private mockMeta: any = {}
  ) {}

  bind(...values: any[]): D1PreparedStatement {
    this.boundValues = values;
    return this;
  }

  async first<T = unknown>(): Promise<T | null> {
    return (this.mockResults[0] as T) || null;
  }

  async run<T = unknown>(): Promise<D1Result<T>> {
    return {
      success: true,
      results: this.mockResults as T[],
      meta: this.mockMeta
    };
  }

  async all<T = unknown>(): Promise<D1Result<T>> {
    return {
      success: true,
      results: this.mockResults as T[],
      meta: this.mockMeta
    };
  }

  async raw<T = unknown>(): Promise<[string[], ...any[]]> {
    // Return empty columns array as first element, then rows
    return [[], ...this.mockResults] as [string[], ...any[]];
  }
}

/**
 * MockD1Database - Production-quality mock for Cloudflare D1Database
 */
export class MockD1Database implements D1Database {
  private tables = new Map<string, any[]>();
  private mockResults = new Map<string, any[]>();
  private mockMeta: any = {
    duration: 0,
    rows_read: 0,
    rows_written: 0,
    size_after: 0
  };

  /**
   * Set mock results for a specific query pattern
   */
  setMockResults(queryPattern: string, results: any[], meta?: any): void {
    this.mockResults.set(queryPattern, results);
    if (meta) {
      this.mockMeta = { ...this.mockMeta, ...meta };
    }
  }

  /**
   * Clear all mock data
   */
  clear(): void {
    this.tables.clear();
    this.mockResults.clear();
  }

  prepare(query: string): D1PreparedStatement {
    // Find matching mock results
    let results: any[] = [];
    for (const [pattern, data] of this.mockResults.entries()) {
      if (query.includes(pattern) || query.match(new RegExp(pattern, 'i'))) {
        results = data;
        break;
      }
    }

    return new MockD1PreparedStatement(query, results, this.mockMeta);
  }

  async dump(): Promise<ArrayBuffer> {
    // Return empty ArrayBuffer for testing
    return new ArrayBuffer(0);
  }

  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    const results: D1Result<T>[] = [];

    for (const statement of statements) {
      const result = await statement.run<T>();
      results.push(result);
    }

    return results;
  }

  async exec(query: string): Promise<D1ExecResult> {
    return {
      count: 1,
      duration: 0
    };
  }
}

/**
 * Factory function to create MockD1Database instances
 */
export function createMockD1(): MockD1Database {
  return new MockD1Database();
}
