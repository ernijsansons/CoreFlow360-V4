// src/database/index.ts - Production Database Layer
import type { D1Database } from '../cloudflare/types/cloudflare';

export interface Business {
  id: string;
  name: string;
  settings?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface User {
  id: string;
  business_id: string;
  email: string;
  role: string;
  settings?: Record<string, any>;
  created_at: string;
}

export interface LedgerEntry {
  id: string;
  business_id: string;
  account_id: string;
  amount: number;
  type: 'debit' | 'credit';
  description?: string;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface AuditLog {
  id: number;
  business_id: string;
  user_id?: string;
  action: string;
  resource?: string;
  metadata?: Record<string, any>;
  timestamp: string;
}

/**
 * Production Database Service
 * Optimized for Cloudflare D1 with proper error handling and caching
 */
export // TODO: Consider splitting DatabaseService into smaller, focused classes
class DatabaseService {
  constructor(private db: D1Database) {}

  // Business operations
  async createBusiness(business: Omit<Business, 'created_at' | 'updated_at'>): Promise<Business> {
    const now = new Date().toISOString();
    const newBusiness = { ...business, created_at: now, updated_at: now };

    await this.db.prepare(`
      INSERT INTO businesses (id, name, settings, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(
      newBusiness.id,
      newBusiness.name,
      JSON.stringify(newBusiness.settings || {}),
      newBusiness.created_at,
      newBusiness.updated_at
    ).run();

    return newBusiness;
  }

  async getBusiness(id: string): Promise<Business | null> {
    const result = await this.db.prepare(`
      SELECT * FROM businesses WHERE id = ?
    `).bind(id).first();

    if (!result) return null;

    const business = result as any;
    return {
      id: business.id,
      name: business.name,
      settings: business.settings ? JSON.parse(business.settings) : {},
      created_at: business.created_at,
      updated_at: business.updated_at
    };
  }

  async updateBusiness(id: string, updates: Partial<Omit<Business, 'id' | 'created_at'>>): Promise<boolean> {
    const now = new Date().toISOString();
    const setClause = [];
    const values = [];

    if (updates.name) {
      setClause.push('name = ?');
      values.push(updates.name);
    }
    if (updates.settings) {
      setClause.push('settings = ?');
      values.push(JSON.stringify(updates.settings));
    }
    setClause.push('updated_at = ?');
    values.push(now);

    const result = await this.db.prepare(`
      UPDATE businesses SET ${setClause.join(', ')} WHERE id = ?
    `).bind(...values, id).run();

    return result.success && (result.meta?.changes || 0) > 0;
  }

  // User operations
  async createUser(user: Omit<User, 'created_at'>): Promise<User> {
    const now = new Date().toISOString();
    const newUser = { ...user, created_at: now };

    await this.db.prepare(`
      INSERT INTO users (id, business_id, email, role, settings, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      newUser.id,
      newUser.business_id,
      newUser.email,
      newUser.role,
      JSON.stringify(newUser.settings || {}),
      newUser.created_at
    ).run();

    return newUser;
  }

  async getUser(id: string): Promise<User | null> {
    const result = await this.db.prepare(`
      SELECT * FROM users WHERE id = ?
    `).bind(id).first();

    if (!result) return null;

    const user = result as any;
    return {
      id: user.id,
      business_id: user.business_id,
      email: user.email,
      role: user.role,
      settings: user.settings ? JSON.parse(user.settings) : {},
      created_at: user.created_at
    };
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const result = await this.db.prepare(`
      SELECT * FROM users WHERE email = ?
    `).bind(email).first() as any;

    if (!result) return null;

    return {
      ...result,
      settings: result.settings ? JSON.parse(result.settings as string) : {}
    } as User;
  }

  async getBusinessUsers(businessId: string, limit = 50, offset = 0): Promise<User[]> {
    const results = await this.db.prepare(`
      SELECT * FROM users
      WHERE business_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).bind(businessId, limit, offset).all();

    return results.results.map((user: any) => ({
      ...user,
      settings: user.settings ? JSON.parse(user.settings as string) : {}
    })) as User[];
  }

  // Ledger operations
  async createLedgerEntry(entry: Omit<LedgerEntry, 'created_at'>): Promise<LedgerEntry> {
    const now = new Date().toISOString();
    const newEntry = { ...entry, created_at: now };

    await this.db.prepare(`
      INSERT INTO ledger_entries (id, business_id, account_id, amount, type, description, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      newEntry.id,
      newEntry.business_id,
      newEntry.account_id,
      newEntry.amount,
      newEntry.type,
      newEntry.description || null,
      JSON.stringify(newEntry.metadata || {}),
      newEntry.created_at
    ).run();

    return newEntry;
  }

  async getLedgerEntries(
    businessId: string,
    accountId?: string,
    limit = 100,
    offset = 0
  ): Promise<LedgerEntry[]> {
    let query = `
      SELECT * FROM ledger_entries
      WHERE business_id = ?
    `;
    const params = [businessId];

    if (accountId) {
      query += ` AND account_id = ?`;
      params.push(accountId);
    }

    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit.toString(), offset.toString());

    const results = await this.db.prepare(query).bind(...params).all();

    return results.results.map((entry: any) => ({
      ...entry,
      metadata: entry.metadata ? JSON.parse(entry.metadata as string) : {}
    })) as LedgerEntry[];
  }

  async getAccountBalance(businessId: string, accountId: string): Promise<number> {
    const result = await this.db.prepare(`
      SELECT
        SUM(CASE WHEN type = 'debit' THEN amount ELSE 0 END) as debits,
        SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END) as credits
      FROM ledger_entries
      WHERE business_id = ? AND account_id = ?
    `).bind(businessId, accountId).first() as any;

    if (!result) return 0;

    const debits = (result.debits as number) || 0;
    const credits = (result.credits as number) || 0;
    return debits - credits;
  }

  // Batch ledger operations for performance
  async createLedgerEntries(entries: Omit<LedgerEntry, 'created_at'>[]): Promise<void> {
    const now = new Date().toISOString();
    const statements = entries.map(entry =>
      this.db.prepare(`
        INSERT INTO ledger_entries (id, business_id, account_id, amount, type, description, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        entry.id,
        entry.business_id,
        entry.account_id,
        entry.amount,
        entry.type,
        entry.description || null,
        JSON.stringify(entry.metadata || {}),
        now
      )
    );

    await this.db.batch(statements);
  }

  // Audit logging
  async logAudit(log: Omit<AuditLog, 'id' | 'timestamp'>): Promise<void> {
    await this.db.prepare(`
      INSERT INTO audit_log (business_id, user_id, action, resource, metadata, timestamp)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(
      log.business_id,
      log.user_id || null,
      log.action,
      log.resource || null,
      JSON.stringify(log.metadata || {})
    ).run();
  }

  async getAuditLogs(
    businessId: string,
    userId?: string,
    limit = 100,
    offset = 0
  ): Promise<AuditLog[]> {
    let query = `
      SELECT * FROM audit_log
      WHERE business_id = ?
    `;
    const params = [businessId];

    if (userId) {
      query += ` AND user_id = ?`;
      params.push(userId);
    }

    query += ` ORDER BY timestamp DESC LIMIT ? OFFSET ?`;
    params.push(limit.toString(), offset.toString());

    const results = await this.db.prepare(query).bind(...params).all();

    return results.results.map((log: any) => ({
      ...log,
      metadata: log.metadata ? JSON.parse(log.metadata as string) : {}
    })) as AuditLog[];
  }

  // Analytics and reporting
  async getBusinessStats(businessId: string): Promise<{
    totalUsers: number;
    totalLedgerEntries: number;
    totalDebits: number;
    totalCredits: number;
    lastActivity: string;
  }> {
    const [userStats, ledgerStats, activityStats] = await Promise.all([
      this.db.prepare(`
        SELECT COUNT(*) as count FROM users WHERE business_id = ?
      `).bind(businessId).first() as any,

      this.db.prepare(`
        SELECT
          COUNT(*) as count,
          SUM(CASE WHEN type = 'debit' THEN amount ELSE 0 END) as debits,
          SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END) as credits
        FROM ledger_entries WHERE business_id = ?
      `).bind(businessId).first() as any,

      this.db.prepare(`
        SELECT MAX(timestamp) as last_activity FROM audit_log WHERE business_id = ?
      `).bind(businessId).first() as any
    ]);

    return {
      totalUsers: (userStats?.count as number) || 0,
      totalLedgerEntries: (ledgerStats?.count as number) || 0,
      totalDebits: (ledgerStats?.debits as number) || 0,
      totalCredits: (ledgerStats?.credits as number) || 0,
      lastActivity: (activityStats?.last_activity as string) || new Date().toISOString()
    };
  }

  // Database maintenance
  async vacuum(): Promise<void> {
    await this.db.exec('VACUUM');
  }

  async analyze(): Promise<void> {
    await this.db.exec('ANALYZE');
  }

  // Health check
  async healthCheck(): Promise<boolean> {
    try {
      await this.db.prepare('SELECT 1').first();
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Database Factory - Creates optimized database service instance
 */
export function createDatabase(db: D1Database): DatabaseService {
  return new DatabaseService(db);
}

/**
 * Transaction helper for complex operations
 */
export class DatabaseTransaction {
  private statements: any[] = [];

  constructor(private db: D1Database) {}

  add(statement: any): void {
    this.statements.push(statement);
  }

  async execute(): Promise<void> {
    if (this.statements.length === 0) return;
    await this.db.batch(this.statements);
    this.statements = [];
  }

  clear(): void {
    this.statements = [];
  }
}

/**
 * Migration utilities
 */
export async function runMigrations(db: D1Database): Promise<void> {
  // Check if schema exists
  const tableCheck = await db.prepare(`
    SELECT name FROM sqlite_master
    WHERE type='table' AND name IN ('businesses', 'users', 'ledger_entries', 'audit_log')
  `).all();

  if (tableCheck.results.length < 4) {

    // Read and execute schema
    const fs = await import('fs');
    const path = await import('path');

    try {
      const schemaPath = path.join(process.cwd(), 'src/database/schema.sql');
      const schema = fs.readFileSync(schemaPath, 'utf8');

      // Split by semicolon and execute each statement
      const statements = schema.split(';').filter(stmt => stmt.trim());

      for (const statement of statements) {
        if (statement.trim()) {
          await db.exec(statement);
        }
      }

    } catch (error) {
      throw error;
    }
  }
}