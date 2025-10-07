/**
 * Journal Entry Management
 * Double-entry bookkeeping with automatic balancing and validation
 */
import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  JournalEntry,
  JournalLine,
  JournalEntryType,
  JournalEntryStatus,
  CreateJournalEntryRequest,
  PostJournalEntryRequest,
  AuditAction,
  ChartAccount
} from './types';
import { FinanceAuditLogger } from './audit-logger';
import { ChartOfAccountsManager } from './chart-of-accounts';
import { CurrencyManager } from './currency-manager';
import { PeriodManager } from './period-manager';
import { TransactionManager } from '../agent-system/transaction-manager';
import { validateBusinessId, generateEntryNumber } from './utils';

export // TODO: Consider splitting JournalEntryManager into smaller, focused classes
class JournalEntryManager {
  private logger: Logger;
  private db: D1Database;
  private auditLogger: FinanceAuditLogger;
  private chartManager: ChartOfAccountsManager;
  private currencyManager: CurrencyManager;
  private periodManager: PeriodManager;
  private transactionManager: TransactionManager;

  constructor(
    db: D1Database,
    chartManager: ChartOfAccountsManager,
    currencyManager: CurrencyManager,
    periodManager: PeriodManager
  ) {
    this.logger = new Logger();
    this.db = db;
    this.auditLogger = new FinanceAuditLogger(db);
    this.chartManager = chartManager;
    this.currencyManager = currencyManager;
    this.periodManager = periodManager;
    this.transactionManager = new TransactionManager(db);
  }

  /**
   * Create a journal entry
   */
  async createEntry(
    businessId: string,
    request: CreateJournalEntryRequest,
    userId: string
  ): Promise<JournalEntry> {
    // Validate business ID
    validateBusinessId(businessId);

    // Validate entry data
    await this.validateEntryData(businessId, request);

    // Generate entry number
    const entryNumber = await generateEntryNumber(this.db, businessId);

    // Get period for date
    const period = await this.periodManager.getPeriod(businessId, request.date.toString());
    if (!period) {
      throw new Error('No accounting period found for the specified date');
    }

    // Process journal lines to add IDs and account details
    const processedLines: JournalLine[] = await Promise.all(request.lines.map(async (line) => {
      const account = await this.chartManager.getAccount(businessId, line.accountId);
      if (!account) {
        throw new Error(`Account ${line.accountId} not found`);
      }

      const debit = line.debit || 0;
      const credit = line.credit || 0;
      const currency = line.currency || 'USD';
      const exchangeRate = 1; // TODO: Get from currency manager

      return {
        id: `jl_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        journalEntryId: '', // Will be set after entry is created
        accountId: line.accountId,
        accountCode: account.code,
        accountName: account.name,
        debit,
        credit,
        currency,
        exchangeRate,
        baseDebit: debit * exchangeRate,
        baseCredit: credit * exchangeRate,
        description: line.description,
        departmentId: line.departmentId,
        projectId: line.projectId,
        customerId: undefined,
        vendorId: undefined,
        employeeId: undefined,
        metadata: {},
      };
    }));

    // Create journal entry ID first
    const entryId = `je_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Create journal entry
    const entry: JournalEntry = {
      id: entryId,
      businessId,
      entryNumber,
      type: request.type || JournalEntryType.STANDARD,
      status: JournalEntryStatus.DRAFT,
      description: request.description,
      reference: request.reference,
      date: request.date,
      lines: processedLines.map(line => ({ ...line, journalEntryId: entryId })),
      periodId: period.id,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      createdBy: userId,
      updatedBy: userId,
      metadata: {}
    };

    // Validate balance (totals are calculated from lines)
    this.validateBalance(entry);

    // Validate double-entry balance
    this.validateBalance(entry);

    // Store in database
    await this.storeEntry(entry);

    // Log audit trail
    this.logger.info('Journal entry created', {
      businessId,
      entryId: entry.id,
      entryNumber: entry.entryNumber,
      userId
    });

    this.logger.info('Journal entry created', { entryId: entry.id, entryNumber: entry.entryNumber });
    return entry;
  }

  /**
   * Post a journal entry
   */
  async postEntry(
    businessId: string,
    entryId: string,
    userId: string
  ): Promise<JournalEntry> {
    // Get entry
    const entry = await this.getEntry(businessId, entryId);
    if (!entry) {
      throw new Error('Journal entry not found');
    }

    if (entry.status !== JournalEntryStatus.DRAFT) {
      throw new Error('Only draft entries can be posted');
    }

    // Validate posting requirements
    await this.validatePostingRequirements(businessId, entry);

    // Update entry status
    entry.status = JournalEntryStatus.POSTED;
    entry.postedAt = Date.now();
    entry.postedBy = userId;
    entry.updatedAt = Date.now();
    entry.updatedBy = userId;

    // Store updated entry
    await this.storeEntry(entry);

    // Create ledger entries
    await this.createLedgerEntries(businessId, entry);

    // Log audit trail
    const totalDebits = entry.lines.reduce((sum, line) => sum + line.debit, 0);
    const totalCredits = entry.lines.reduce((sum, line) => sum + line.credit, 0);

    this.logger.info('Journal entry posted', {
      businessId,
      entryId: entry.id,
      entryNumber: entry.entryNumber,
      totalDebits,
      totalCredits,
      userId
    });

    this.logger.info('Journal entry posted', { entryId: entry.id, entryNumber: entry.entryNumber });
    return entry;
  }

  /**
   * Get a journal entry
   */
  async getEntry(businessId: string, entryId: string): Promise<JournalEntry | null> {
    const result = await this.db.prepare(`
      SELECT * FROM journal_entries
      WHERE id = ? AND business_id = ?
    `).bind(entryId, businessId).first();

    if (!result) return null;

    return this.mapRowToEntry(result);
  }

  /**
   * Get journal entries
   */
  async getEntries(
    businessId: string,
    filters: {
      status?: JournalEntryStatus;
      type?: JournalEntryType;
      dateFrom?: Date;
      dateTo?: Date;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<JournalEntry[]> {
    let query = 'SELECT * FROM journal_entries WHERE business_id = ?';
    const params: any[] = [businessId];

    if (filters.status) {
      query += ' AND status = ?';
      params.push(filters.status);
    }

    if (filters.type) {
      query += ' AND type = ?';
      params.push(filters.type);
    }

    if (filters.dateFrom) {
      query += ' AND date >= ?';
      params.push(filters.dateFrom.getTime());
    }

    if (filters.dateTo) {
      query += ' AND date <= ?';
      params.push(filters.dateTo.getTime());
    }

    query += ' ORDER BY date DESC, created_at DESC';

    if (filters.limit) {
      query += ' LIMIT ?';
      params.push(filters.limit);
    }

    if (filters.offset) {
      query += ' OFFSET ?';
      params.push(filters.offset);
    }

    const result = await this.db.prepare(query).bind(...params).all();
    return result.results.map((row: any) => this.mapRowToEntry(row));
  }

  /**
   * Update a journal entry
   */
  async updateEntry(
    businessId: string,
    entryId: string,
    updates: Partial<CreateJournalEntryRequest>,
    userId: string
  ): Promise<JournalEntry> {
    const entry = await this.getEntry(businessId, entryId);
    if (!entry) {
      throw new Error('Journal entry not found');
    }

    if (entry.status === JournalEntryStatus.POSTED) {
      throw new Error('Posted entries cannot be modified');
    }

    // Update entry fields
    if (updates.description !== undefined) entry.description = updates.description;
    if (updates.reference !== undefined) entry.reference = updates.reference;
    if (updates.date !== undefined) entry.date = updates.date;
    if (updates.lines !== undefined) {
      // Process updated lines similar to create
      const processedLines: JournalLine[] = await Promise.all(updates.lines.map(async (line) => {
        const account = await this.chartManager.getAccount(businessId, line.accountId);
        if (!account) {
          throw new Error(`Account ${line.accountId} not found`);
        }

        const debit = line.debit || 0;
        const credit = line.credit || 0;
        const currency = line.currency || 'USD';
        const exchangeRate = 1;

        return {
          id: `jl_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          journalEntryId: entry.id,
          accountId: line.accountId,
          accountCode: account.code,
          accountName: account.name,
          debit,
          credit,
          currency,
          exchangeRate,
          baseDebit: debit * exchangeRate,
          baseCredit: credit * exchangeRate,
          description: line.description,
          departmentId: line.departmentId,
          projectId: line.projectId,
          customerId: undefined,
          vendorId: undefined,
          employeeId: undefined,
          metadata: {},
        };
      }));
      entry.lines = processedLines;
    }

    entry.updatedAt = Date.now();
    entry.updatedBy = userId;

    // Validate balance
    this.validateBalance(entry);

    // Store updated entry
    await this.storeEntry(entry);

    // Log audit trail
    this.logger.info('Journal entry updated', {
      businessId,
      entryId: entry.id,
      entryNumber: entry.entryNumber,
      userId
    });

    this.logger.info('Journal entry updated', { entryId: entry.id, entryNumber: entry.entryNumber });
    return entry;
  }

  /**
   * Delete a journal entry
   */
  async deleteEntry(businessId: string, entryId: string, userId: string): Promise<boolean> {
    const entry = await this.getEntry(businessId, entryId);
    if (!entry) {
      return false;
    }

    if (entry.status === JournalEntryStatus.POSTED) {
      throw new Error('Posted entries cannot be deleted');
    }

    // Delete from database
    await this.db.prepare(`
      DELETE FROM journal_entries
      WHERE id = ? AND business_id = ?
    `).bind(entryId, businessId).run();

    // Log audit trail
    this.logger.info('Journal entry deleted', {
      businessId,
      entryId: entry.id,
      entryNumber: entry.entryNumber,
      userId
    });

    this.logger.info('Journal entry deleted', { entryId: entry.id, entryNumber: entry.entryNumber });
    return true;
  }

  /**
   * Validate entry data
   */
  private async validateEntryData(businessId: string, request: CreateJournalEntryRequest): Promise<void> {
    if (!request.lines || request.lines.length === 0) {
      throw new Error('Journal entry must have at least one line');
    }

    if (!request.description || request.description.trim() === '') {
      throw new Error('Journal entry must have a description');
    }

    if (!request.date) {
      throw new Error('Journal entry must have a date');
    }

    // Validate each line
    for (const line of request.lines) {
      if (!line.accountId) {
        throw new Error('Journal line must have an account ID');
      }

      if (!line.debit && !line.credit) {
        throw new Error('Journal line must have either debit or credit amount');
      }

      if (line.debit && line.credit) {
        throw new Error('Journal line cannot have both debit and credit amounts');
      }

      if (line.debit && line.debit <= 0) {
        throw new Error('Debit amount must be positive');
      }

      if (line.credit && line.credit <= 0) {
        throw new Error('Credit amount must be positive');
      }

      // Validate account exists
      const account = await this.chartManager.getAccount(businessId, line.accountId);
      if (!account) {
        throw new Error(`Account ${line.accountId} not found`);
      }
    }
  }

  /**
   * Validate double-entry balance
   */
  private validateBalance(entry: JournalEntry): void {
    const totalDebits = entry.lines.reduce((sum, line) => sum + line.debit, 0);
    const totalCredits = entry.lines.reduce((sum, line) => sum + line.credit, 0);

    if (Math.abs(totalDebits - totalCredits) > 0.01) {
      throw new Error(`Journal entry is not balanced. Debits: ${totalDebits}, Credits: ${totalCredits}`);
    }
  }

  /**
   * Validate posting requirements
   */
  private async validatePostingRequirements(businessId: string, entry: JournalEntry): Promise<void> {
    // Check if period is open
    const period = await this.periodManager.getPeriod(businessId, entry.date.toString());
    if (!period || period.status !== 'OPEN') {
      throw new Error('Cannot post entry to closed period');
    }

    // Currency validation can be added when needed
    // Currently all entries use the business's base currency
  }

  /**
   * Create ledger entries
   */
  private async createLedgerEntries(businessId: string, entry: JournalEntry): Promise<void> {
    for (const line of entry.lines) {
      await this.db.prepare(`
        INSERT INTO ledger_entries (
          id, business_id, account_id, journal_entry_id, date, description,
          debit_amount, credit_amount, balance, currency, exchange_rate,
          created_at, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        `le_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        businessId,
        line.accountId,
        entry.id,
        entry.date,
        line.description || entry.description,
        line.debit || 0,
        line.credit || 0,
        line.debit || -(line.credit || 0),
        line.currency,
        line.exchangeRate,
        Date.now(),
        entry.postedBy
      ).run();
    }
  }

  /**
   * Store entry in database
   */
  private async storeEntry(entry: JournalEntry): Promise<void> {
    await this.db.prepare(`
      INSERT OR REPLACE INTO journal_entries (
        id, business_id, entry_number, type, status, description, reference,
        date, lines, period_id,
        created_at, updated_at, created_by, updated_by, posted_at, posted_by, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      entry.id,
      entry.businessId,
      entry.entryNumber,
      entry.type,
      entry.status,
      entry.description,
      entry.reference,
      entry.date,
      JSON.stringify(entry.lines),
      entry.periodId,
      entry.createdAt,
      entry.updatedAt,
      entry.createdBy,
      entry.updatedBy,
      entry.postedAt,
      entry.postedBy,
      JSON.stringify(entry.metadata)
    ).run();
  }

  /**
   * Map database row to JournalEntry
   */
  private mapRowToEntry(row: any): JournalEntry {
    return {
      id: row.id,
      businessId: row.business_id,
      entryNumber: row.entry_number,
      type: row.type,
      status: row.status,
      description: row.description,
      reference: row.reference,
      date: Number(row.date),
      lines: JSON.parse(row.lines),
      periodId: row.period_id,
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
      createdBy: row.created_by,
      updatedBy: row.updated_by,
      postedAt: row.posted_at ? Number(row.posted_at) : undefined,
      postedBy: row.posted_by,
      metadata: JSON.parse(row.metadata || '{}')
    };
  }
}

