/**
 * Query Optimizer for CoreFlow360
 * Optimizes database queries to prevent N+1 problems and implements batching
 */

export interface QueryBatch {
  table: string;
  ids: string[];
  fields: string[];
  conditions?: Record<string, any>;
}

export class QueryOptimizer {
  private batchQueue: Map<string, QueryBatch> = new Map();
  private batchTimer: NodeJS.Timeout | null = null;
  private readonly BATCH_SIZE = 100;
  private readonly BATCH_DELAY = 10; // ms

  /**
   * Add query to batch queue
   */
  async batchQuery<T>(
    table: string,
    id: string,
    fields: string[] = ['*']
  ): Promise<T> {
    const key = `${table}:${fields.join(',')}`;

    if (!this.batchQueue.has(key)) {
      this.batchQueue.set(key, {
        table,
        ids: [],
        fields
      });
    }

    const batch = this.batchQueue.get(key)!;
    batch.ids.push(id);

    // Schedule batch execution
    if (!this.batchTimer) {
      this.batchTimer = setTimeout(() => this.executeBatches(), this.BATCH_DELAY);
    }

    // Return promise that resolves when batch executes
    return new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        const result = this.getResult(table, id);
        if (result) {
          clearInterval(checkInterval);
          resolve(result as T);
        }
      }, 5);
    });
  }

  /**
   * Execute all pending batches
   */
  private async executeBatches() {
    const batches = Array.from(this.batchQueue.values());
    this.batchQueue.clear();
    this.batchTimer = null;

    await Promise.all(
      batches.map(async (batch) => {
        // Split into chunks if necessary
        const chunks = this.chunkArray(batch.ids, this.BATCH_SIZE);

        for (const chunk of chunks) {
          await this.executeBatchQuery(batch.table, chunk, batch.fields);
        }
      })
    );
  }

  /**
   * Execute a single batch query
   */
  private async executeBatchQuery(
    table: string,
    ids: string[],
    fields: string[]
  ) {
    const placeholders = ids.map(() => '?').join(',');
    const fieldsList = fields.join(',');

    const query = `SELECT ${fieldsList} FROM ${table} WHERE id IN (${placeholders})`;

    // This would be replaced with actual D1 database call
    // For now, returning mock data
    return {
      query,
      ids,
      results: ids.map(id => ({ id, data: `mock-${id}` }))
    };
  }

  /**
   * Chunk array into smaller pieces
   */
  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  /**
   * Get cached result
   */
  private getResult(table: string, id: string): any {
    // In production, this would check actual cache
    return null;
  }

  /**
   * Optimize joins to prevent N+1 queries
   */
  optimizeJoins(
    primaryTable: string,
    joins: Array<{ table: string; on: string; fields: string[] }>
  ): string {
    const joinClauses = joins.map(join => {
      return `LEFT JOIN ${join.table} ON ${join.on}`;
    }).join(' ');

    const selectFields = [
      `${primaryTable}.*`,
      ...joins.flatMap(join =>
        join.fields.map(field => `${join.table}.${field} as ${join.table}_${field}`)
      )
    ].join(', ');

    return `SELECT ${selectFields} FROM ${primaryTable} ${joinClauses}`;
  }

  /**
   * Implement query result caching
   */
  private cache = new Map<string, { data: any; timestamp: number }>();
  private readonly CACHE_TTL = 60000; // 1 minute

  getCached(key: string): any {
    const cached = this.cache.get(key);
    if (!cached) return null;

    if (Date.now() - cached.timestamp > this.CACHE_TTL) {
      this.cache.delete(key);
      return null;
    }

    return cached.data;
  }

  setCache(key: string, data: any): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });

    // Clean old entries
    if (this.cache.size > 1000) {
      const sortedEntries = Array.from(this.cache.entries())
        .sort((a, b) => a[1].timestamp - b[1].timestamp);

      for (let i = 0; i < 100; i++) {
        this.cache.delete(sortedEntries[i][0]);
      }
    }
  }

  /**
   * Generate optimized pagination query
   */
  paginateQuery(
    table: string,
    page: number,
    limit: number,
    orderBy: string = 'id'
  ): string {
    const offset = (page - 1) * limit;
    return `SELECT * FROM ${table} ORDER BY ${orderBy} LIMIT ${limit} OFFSET ${offset}`;
  }

  /**
   * Bulk insert optimization
   */
  generateBulkInsert(
    table: string,
    records: Array<Record<string, any>>
  ): string {
    if (records.length === 0) return '';

    const columns = Object.keys(records[0]);
    const values = records.map(record => {
      const vals = columns.map(col => {
        const val = record[col];
        return typeof val === 'string' ? `'${val}'` : val;
      });
      return `(${vals.join(',')})`;
    });

    return `INSERT INTO ${table} (${columns.join(',')}) VALUES ${values.join(',')}`;
  }
}

// Export singleton instance
export const queryOptimizer = new QueryOptimizer();