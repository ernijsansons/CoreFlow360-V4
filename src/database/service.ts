// src/database/service.ts - Simplified Production Database Service
import type { D1Database } from '../cloudflare/types/cloudflare';

/**
 * Simple, fast database service optimized for production
 */
export class DB {
  constructor(private d1: D1Database) {}

  // Raw query execution with type safety
  async query<T = any>(sql: string, ...params: any[]): Promise<T[]> {
    const result = await this.d1.prepare(sql).bind(...params).all();
    return result.results as T[];
  }

  async queryFirst<T = any>(sql: string, ...params: any[]): Promise<T | null> {
    const result = await this.d1.prepare(sql).bind(...params).first();
    return result as T | null;
  }

  async execute(sql: string, ...params: any[]): Promise<{ success: boolean; changes: number }> {
    const result = await this.d1.prepare(sql).bind(...params).run();
    return {
      success: result.success,
      changes: result.meta?.changes || 0
    };
  }

  async batch(statements: { sql: string; params: any[] }[]): Promise<void> {
    const prepared = statements.map(stmt =>
      this.d1.prepare(stmt.sql).bind(...stmt.params)
    );
    await this.d1.batch(prepared);
  }

  // Business operations
  async createBusiness(id: string, name: string, settings = {}): Promise<void> {
    await this.execute(`
      INSERT INTO businesses (id, name, settings, created_at, updated_at)
      VALUES (?, ?, ?, datetime('now'), datetime('now'))
    `, id, name, JSON.stringify(settings));
  }

  async getBusiness(id: string): Promise<any> {
    const result = await this.queryFirst(`
      SELECT id, name, settings, created_at, updated_at
      FROM businesses WHERE id = ?
    `, id);

    if (!result) return null;

    return {
      ...result,
      settings: result.settings ? JSON.parse(result.settings) : {}
    };
  }

  // User operations
  async createUser(id: string, businessId: string, email: string, role: string, settings = {}): Promise<void> {
    await this.execute(`
      INSERT INTO users (id, business_id, email, role, settings, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `, id, businessId, email, role, JSON.stringify(settings));
  }

  async getUser(id: string): Promise<any> {
    const result = await this.queryFirst(`
      SELECT id, business_id, email, role, settings, created_at
      FROM users WHERE id = ?
    `, id);

    if (!result) return null;

    return {
      ...result,
      settings: result.settings ? JSON.parse(result.settings) : {}
    };
  }

  async getUserByEmail(email: string): Promise<any> {
    const result = await this.queryFirst(`
      SELECT id, business_id, email, role, settings, created_at
      FROM users WHERE email = ?
    `, email);

    if (!result) return null;

    return {
      ...result,
      settings: result.settings ? JSON.parse(result.settings) : {}
    };
  }

  async getBusinessUsers(businessId: string, limit = 50): Promise<any[]> {
    return this.query(`
      SELECT id, business_id, email, role, settings, created_at
      FROM users WHERE business_id = ?
      ORDER BY created_at DESC LIMIT ?
    `, businessId, limit);
  }

  // Ledger operations
  async createLedgerEntry(
    id: string,
    businessId: string,
    accountId: string,
    amount: number,
    type: 'debit' | 'credit',
    description?: string,
    metadata = {}
  ): Promise<void> {
    await this.execute(`
      INSERT INTO ledger_entries (id, business_id, account_id, amount, type, description, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `, id, businessId, accountId, amount, type, description, JSON.stringify(metadata));
  }

  async getLedgerEntries(businessId: string, accountId?: string, limit = 100): Promise<any[]> {
    if (accountId) {
      return this.query(`
        SELECT * FROM ledger_entries
        WHERE business_id = ? AND account_id = ?
        ORDER BY created_at DESC LIMIT ?
      `, businessId, accountId, limit);
    }

    return this.query(`
      SELECT * FROM ledger_entries
      WHERE business_id = ?
      ORDER BY created_at DESC LIMIT ?
    `, businessId, limit);
  }

  async getAccountBalance(businessId: string, accountId: string): Promise<number> {
    const result = await this.queryFirst(`
      SELECT
        SUM(CASE WHEN type = 'debit' THEN amount ELSE 0 END) as debits,
        SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END) as credits
      FROM ledger_entries
      WHERE business_id = ? AND account_id = ?
    `, businessId, accountId);

    if (!result) return 0;

    const debits = Number(result.debits) || 0;
    const credits = Number(result.credits) || 0;
    return debits - credits;
  }

  // Batch ledger creation for transactions
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
  }

  // Audit logging
  async logAudit(
    businessId: string,
    action: string,
    userId?: string,
    resource?: string,
    metadata = {}
  ): Promise<void> {
    await this.execute(`
      INSERT INTO audit_log (business_id, user_id, action, resource, metadata, timestamp)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `, businessId, userId, action, resource, JSON.stringify(metadata));
  }

  async getAuditLogs(businessId: string, limit = 100): Promise<any[]> {
    return this.query(`
      SELECT * FROM audit_log
      WHERE business_id = ?
      ORDER BY timestamp DESC LIMIT ?
    `, businessId, limit);
  }

  // Analytics
  async getBusinessStats(businessId: string): Promise<{
    totalUsers: number;
    totalLedgerEntries: number;
    totalDebits: number;
    totalCredits: number;
    netBalance: number;
  }> {
    const [userCount, ledgerStats] = await Promise.all([
      this.queryFirst(`SELECT COUNT(*) as count FROM users WHERE business_id = ?`, businessId),
      this.queryFirst(`
        SELECT
          COUNT(*) as count,
          SUM(CASE WHEN type = 'debit' THEN amount ELSE 0 END) as debits,
          SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END) as credits
        FROM ledger_entries WHERE business_id = ?
      `, businessId)
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

  // Utilities
  async healthCheck(): Promise<boolean> {
    try {
      await this.queryFirst('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async vacuum(): Promise<void> {
    await this.d1.exec('VACUUM');
  }
}

// Factory function
export function createDB(d1: D1Database): DB {
  return new DB(d1);
}