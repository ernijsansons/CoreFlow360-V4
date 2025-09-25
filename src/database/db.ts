// src/database/db.ts
import type { D1Database, KVNamespace } from '../cloudflare/types/cloudflare';

export class Database {
  constructor(private db: D1Database, private cache: KVNamespace) {}

  // Smart query with caching
  async query<T>(
    sql: string,
    params: any[],
    options: { cache?: number } = {}
  ): Promise<T[]> {
    const cacheKey = `query:${sql}:${JSON.stringify(params)}`;

    // Check cache if specified
    if (options.cache) {
      const cached = await this.cache.get(cacheKey, { type: 'json' });
      if (cached) return cached as unknown as T[];
    }

    // Execute query
    const result = await this.db
      .prepare(sql)
      .bind(...params)
      .all<T>();

    // Cache if specified
    if (options.cache && result.success) {
      await this.cache.put(
        cacheKey,
        JSON.stringify(result.results),
        { expirationTtl: options.cache }
      );
    }

    return result.results || [];
  }

  // Single record query with caching
  async queryFirst<T>(
    sql: string,
    params: any[],
    options: { cache?: number } = {}
  ): Promise<T | null> {
    const results = await this.query<T>(sql, params, options);
    return results[0] || null;
  }

  // Execute without return
  async execute(
    sql: string,
    params: any[]
  ): Promise<{ success: boolean; changes: number }> {
    const result = await this.db.prepare(sql).bind(...params).run();
    return {
      success: result.success,
      changes: result.meta?.changes || 0
    };
  }

  // Batch operations for efficiency
  async batchInsert(
    table: string,
    records: any[]
  ): Promise<void> {
    if (records.length === 0) return;

    const chunks = this.chunk(records, 100);

    for (const chunk of chunks) {
      const placeholders = chunk.map(
        () => `(${Object.keys(chunk[0]).map(() => '?').join(',')})`
      ).join(',');

      const sql = `
        INSERT INTO ${table} (${Object.keys(chunk[0]).join(',')})
        VALUES ${placeholders}
      `;

      const params = chunk.flatMap(record => Object.values(record));
      await this.db.prepare(sql).bind(...params).run();
    }
  }

  // Batch statements for complex operations
  async batch(statements: { sql: string; params: any[] }[]): Promise<void> {
    const prepared = statements.map(stmt =>
      this.db.prepare(stmt.sql).bind(...stmt.params)
    );
    await this.db.batch(prepared);
  }

  // Connection pooling simulation for D1
  async transaction<T>(
    callback: (tx: D1Database) => Promise<T>
  ): Promise<T> {
    const tx = this.db; // D1 handles this internally
    return await callback(tx);
  }

  // Business operations with smart caching
  async getBusiness(id: string): Promise<any> {
    return this.queryFirst(
      'SELECT * FROM businesses WHERE id = ?',
      [id],
      { cache: 300 } // Cache for 5 minutes
    );
  }

  async getBusinessUsers(businessId: string, limit = 50): Promise<any[]> {
    return this.query(
      `SELECT * FROM users WHERE business_id = ?
       ORDER BY created_at DESC LIMIT ?`,
      [businessId, limit],
      { cache: 60 } // Cache for 1 minute
    );
  }

  async createUser(
    id: string,
    businessId: string,
    email: string,
    role: string,
    settings = {}
  ): Promise<void> {
    await this.execute(
      `INSERT INTO users (id, business_id, email, role, settings, created_at)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      [id, businessId, email, role, JSON.stringify(settings)]
    );

    // Invalidate cache
    await this.invalidateUserCache(businessId);
  }

  async createLedgerEntry(
    id: string,
    businessId: string,
    accountId: string,
    amount: number,
    type: 'debit' | 'credit',
    description?: string,
    metadata = {}
  ): Promise<void> {
    await this.execute(
      `INSERT INTO ledger_entries (id, business_id, account_id, amount, type, description, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [id, businessId, accountId, amount, type, description, JSON.stringify(metadata)]
    );

    // Invalidate balance cache
    await this.invalidateBalanceCache(businessId, accountId);
  }

  async createLedgerTransaction(entries: Array<{
    id: string;
    businessId: string;
    accountId: string;
    amount: number;
    type: 'debit' | 'credit';
    description?: string;
    metadata?: any;
  }>): Promise<void> {
    const statements = entries.map(entry => ({
      sql: `
        INSERT INTO ledger_entries (id, business_id, account_id, amount, type, description, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `,
      params: [
        entry.id,
        entry.businessId,
        entry.accountId,
        entry.amount,
        entry.type,
        entry.description || null,
        JSON.stringify(entry.metadata || {})
      ]
    }));

    await this.batch(statements);

    // Invalidate relevant caches
    const businessIds = Array.from(new Set(entries.map(e => e.businessId)));
    const accountIds = Array.from(new Set(entries.map(e => e.accountId)));

    for (const businessId of businessIds) {
      for (const accountId of accountIds) {
        await this.invalidateBalanceCache(businessId, accountId);
      }
    }
  }

  async getAccountBalance(businessId: string, accountId: string): Promise<number> {
    const result = await this.queryFirst<{debits: number, credits: number}>(
      `SELECT
        SUM(CASE WHEN type = 'debit' THEN amount ELSE 0 END) as debits,
        SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END) as credits
      FROM ledger_entries
      WHERE business_id = ? AND account_id = ?`,
      [businessId, accountId],
      { cache: 30 } // Cache for 30 seconds
    );

    if (!result) return 0;

    const debits = Number(result.debits) || 0;
    const credits = Number(result.credits) || 0;
    return debits - credits;
  }

  async getLedgerEntries(
    businessId: string,
    accountId?: string,
    limit = 100
  ): Promise<any[]> {
    if (accountId) {
      return this.query(
        `SELECT * FROM ledger_entries
         WHERE business_id = ? AND account_id = ?
         ORDER BY created_at DESC LIMIT ?`,
        [businessId, accountId, limit],
        { cache: 60 }
      );
    }

    return this.query(
      `SELECT * FROM ledger_entries
       WHERE business_id = ?
       ORDER BY created_at DESC LIMIT ?`,
      [businessId, limit],
      { cache: 60 }
    );
  }

  async logAudit(
    businessId: string,
    action: string,
    userId?: string,
    resource?: string,
    metadata = {}
  ): Promise<void> {
    await this.execute(
      `INSERT INTO audit_log (business_id, user_id, action, resource, metadata, timestamp)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      [businessId, userId, action, resource, JSON.stringify(metadata)]
    );
  }

  async getAuditLogs(businessId: string, limit = 100): Promise<any[]> {
    return this.query(
      `SELECT * FROM audit_log
       WHERE business_id = ?
       ORDER BY timestamp DESC LIMIT ?`,
      [businessId, limit],
      { cache: 30 }
    );
  }

  async getBusinessStats(businessId: string): Promise<{
    totalUsers: number;
    totalLedgerEntries: number;
    totalDebits: number;
    totalCredits: number;
    netBalance: number;
  }> {
    const [userCount, ledgerStats] = await Promise.all([
      this.queryFirst<{count: number}>(
        'SELECT COUNT(*) as count FROM users WHERE business_id = ?',
        [businessId],
        { cache: 300 }
      ),
      this.queryFirst<{count: number, debits: number, credits: number}>(
        `SELECT
          COUNT(*) as count,
          SUM(CASE WHEN type = 'debit' THEN amount ELSE 0 END) as debits,
          SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END) as credits
        FROM ledger_entries WHERE business_id = ?`,
        [businessId],
        { cache: 300 }
      )
    ]);

    const totalDebits = Number(ledgerStats?.debits) || 0;
    const totalCredits = Number(ledgerStats?.credits) || 0;

    return {
      totalUsers: Number(userCount?.count) || 0,
      totalLedgerEntries: Number(ledgerStats?.count) || 0,
      totalDebits,
      totalCredits,
      netBalance: totalDebits - totalCredits
    };
  }

  async createBusiness(id: string, name: string, settings = {}): Promise<void> {
    await this.execute(
      `INSERT INTO businesses (id, name, settings, created_at, updated_at)
       VALUES (?, ?, ?, datetime('now'), datetime('now'))`,
      [id, name, JSON.stringify(settings)]
    );
  }

  // Cache invalidation helpers
  private async invalidateUserCache(businessId: string): Promise<void> {
    const patterns = [
      `query:SELECT * FROM users WHERE business_id = ?
       ORDER BY created_at DESC LIMIT ?:["${businessId}",50]`,
      `query:SELECT * FROM users WHERE business_id = ?
       ORDER BY created_at DESC LIMIT ?:["${businessId}",100]`
    ];

    await Promise.all(patterns.map(pattern =>
      this.cache.delete(pattern).catch(() => {})
    ));
  }

  private async invalidateBalanceCache(businessId: string, accountId: string): Promise<void> {
    const pattern = `query:SELECT
        SUM(CASE WHEN type = 'debit' THEN amount ELSE 0 END) as debits,
        SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END) as credits
      FROM ledger_entries
      WHERE business_id = ? AND account_id = ?:["${businessId}","${accountId}"]`;

    await this.cache.delete(pattern).catch(() => {});
  }

  // Health check
  async healthCheck(): Promise<boolean> {
    try {
      await this.queryFirst('SELECT 1', []);
      return true;
    } catch {
      return false;
    }
  }

  private chunk<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }
}

// Factory function
export function createDatabase(db: D1Database, cache: KVNamespace): Database {
  return new Database(db, cache);
}