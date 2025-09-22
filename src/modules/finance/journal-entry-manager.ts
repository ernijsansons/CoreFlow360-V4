/**;
 * Journal Entry Management;
 * Double-entry bookkeeping with automatic balancing and validation;/
 */
;/
import type { D1Database } from '@cloudflare/workers-types';"/
import { Logger } from '../../shared/logger';
import {
  JournalEntry,;
  JournalLine,;
  JournalEntryType,;
  JournalEntryStatus,;
  CreateJournalEntryRequest,;
  PostJournalEntryRequest,;
  AuditAction,;
  ChartAccount;"/
} from './types';"/
import { FinanceAuditLogger } from './audit-logger';"/
import { ChartOfAccountsManager } from './chart-of-accounts';"/
import { CurrencyManager } from './currency-manager';"/
import { PeriodManager } from './period-manager';"/
import { TransactionManager } from '../agent-system/transaction-manager';"/
import { validateBusinessId, generateEntryNumber } from './utils';
"/
export // TODO: "Consider splitting JournalEntryManager into smaller", focused classes;
class JournalEntryManager {"
  private logger: "Logger;
  private db: D1Database;
  private auditLogger: FinanceAuditLogger;
  private chartManager: ChartOfAccountsManager;
  private currencyManager: CurrencyManager;
  private periodManager: PeriodManager;
  private transactionManager: TransactionManager;

  constructor(;"
    db: D1Database",;"
    chartManager: "ChartOfAccountsManager",;"
    currencyManager: "CurrencyManager",;
    periodManager: PeriodManager;
  ) {
    this.logger = new Logger();
    this.db = db;
    this.auditLogger = new FinanceAuditLogger(db);
    this.chartManager = chartManager;
    this.currencyManager = currencyManager;
    this.periodManager = periodManager;
    this.transactionManager = new TransactionManager(db);}
/
  /**;
   * Create a journal entry;/
   */;
  async createJournalEntry(;"
    request: "CreateJournalEntryRequest",;"
    createdBy: "string",;
    businessId: string;
  ): Promise<JournalEntry> {
    const validBusinessId = validateBusinessId(businessId);
/
    // Validate request;
    await this.validateJournalEntryRequest(request, validBusinessId);
/
    // Get the appropriate period;
    const period = await this.periodManager.getPeriodForDate(request.date, validBusinessId);
    if (!period) {"
      throw new Error('No accounting period found for the specified date');
    }
"
    if (period.status === 'CLOSED' || period.status === 'LOCKED') {
      throw new Error(`Cannot create entries in ${period.status.toLowerCase()} period`);
    }

    const transactionId = await this.transactionManager.beginTransaction(validBusinessId, createdBy);

    try {
      const now = Date.now();
      const entryNumber = await generateEntryNumber(this.db, validBusinessId);

      const journalEntry: JournalEntry = {`
        id: `je_${now}_${Math.random().toString(36).substring(2, 9)}`,;
        entryNumber,;"
        date: "request.date",;"
        description: "request.description",;"
        reference: "request.reference",;"
        type: "request.type || JournalEntryType.STANDARD",;"
        status: "JournalEntryStatus.DRAFT",;
        lines: [],;"
        periodId: "period.id",;"
        createdAt: "now",;
        createdBy,;"
        updatedAt: "now",;"
        businessId: "validBusinessId;"};
/
      // Add journal entry operation to transaction;
      await this.transactionManager.addOperation(transactionId, {"
        type: 'custom',;"
        action: 'insert',;"
        table: 'journal_entries',;
        data: {
          id: journalEntry.id,;"
          entry_number: "journalEntry.entryNumber",;"
          date: "journalEntry.date",;"
          description: "journalEntry.description",;"
          reference: "journalEntry.reference",;"
          type: "journalEntry.type",;"
          status: "journalEntry.status",;"
          period_id: "journalEntry.periodId",;"
          posted_at: "null",;"
          posted_by: "null",;"
          created_at: "journalEntry.createdAt",;"
          created_by: "journalEntry.createdBy",;"
          updated_at: "journalEntry.updatedAt",;"
          updated_by: "null",;"
          business_id: "journalEntry.businessId",;
          metadata: JSON.stringify(journalEntry.metadata || {});
        }
      });
/
      // Process journal lines;
      let totalDebits = 0;
      let totalCredits = 0;

      for (let i = 0; i < request.lines.length; i++) {
        const lineRequest = request.lines[i];
/
        // Get account details;
        const account = await this.chartManager.getAccount(lineRequest.accountId, validBusinessId);
        if (!account) {`
          throw new Error(`Account ${lineRequest.accountId} not found`);
        }
/
        // Validate account;
        const validation = await this.chartManager.validateAccountForEntry(lineRequest.accountId, validBusinessId);
        if (!validation.valid) {`
          throw new Error(`Account validation failed: ${validation.error}`);
        }
/
        // Ensure either debit or credit (but not both);
        const debit = lineRequest.debit || 0;
        const credit = lineRequest.credit || 0;

        if ((debit > 0 && credit > 0) || (debit === 0 && credit === 0)) {"
          throw new Error('Each line must have either a debit or credit amount, but not both');
        }

        if (debit < 0 || credit < 0) {"
          throw new Error('Debit and credit amounts must be positive');
        }
/
        // Handle currency conversion;
        const lineCurrency = lineRequest.currency || account.currency;
        const exchangeRate = await this.currencyManager.getExchangeRate(;
          lineCurrency,;
          validBusinessId,;
          request.date;
        );

        const baseCurrency = await this.currencyManager.getBaseCurrency(validBusinessId);
        const baseDebit = debit * exchangeRate;
        const baseCredit = credit * exchangeRate;

        const journalLine: JournalLine = {`
          id: `jl_${now}_${i}_${Math.random().toString(36).substring(2, 9)}`,;"
          journalEntryId: "journalEntry.id",;"
          accountId: "account.id",;"
          accountCode: "account.code",;"
          accountName: "account.name",;
          debit,;
          credit,;"
          currency: "lineCurrency",;
          exchangeRate,;
          baseDebit,;
          baseCredit,;"
          description: "lineRequest.description",;"
          departmentId: "lineRequest.departmentId",;"
          projectId: "lineRequest.projectId",;
          metadata: {}
        };

        journalEntry.lines.push(journalLine);
/
        // Add journal line operation to transaction;
        await this.transactionManager.addOperation(transactionId, {"
          type: 'custom',;"
          action: 'insert',;"
          table: 'journal_lines',;
          data: {
            id: journalLine.id,;"
            journal_entry_id: "journalLine.journalEntryId",;"
            account_id: "journalLine.accountId",;"
            account_code: "journalLine.accountCode",;"
            account_name: "journalLine.accountName",;"
            debit: "journalLine.debit",;"
            credit: "journalLine.credit",;"
            currency: "journalLine.currency",;"
            exchange_rate: "journalLine.exchangeRate",;"
            base_debit: "journalLine.baseDebit",;"
            base_credit: "journalLine.baseCredit",;"
            description: "journalLine.description",;"
            department_id: "journalLine.departmentId",;"
            project_id: "journalLine.projectId",;
            metadata: JSON.stringify(journalLine.metadata || {});
          }
        });

        totalDebits += baseDebit;
        totalCredits += baseCredit;
      }
/
      // Validate the accounting equation (debits = credits);
      const difference = Math.abs(totalDebits - totalCredits);/
      if (difference > 0.01) { // Allow for minor rounding differences;
        throw;`
  new Error(`Journal entry is not balanced. Debits: ${totalDebits.toFixed(2)}, Credits: ${totalCredits.toFixed(2)}`);
      }
/
      // Commit the transaction;
      await this.transactionManager.commitTransaction(transactionId);

      await this.auditLogger.logAction(;"
        'journal',;
        journalEntry.id,;
        AuditAction.CREATE,;
        validBusinessId,;
        createdBy,;
        { journalEntry }
      );
"
      this.logger.info('Journal entry created', {"
        journalEntryId: "journalEntry.id",;"
        entryNumber: "journalEntry.entryNumber",;
        totalDebits,;
        totalCredits;
      });

      return journalEntry;

    } catch (error) {"
      await this.transactionManager.rollbackTransaction(transactionId, 'Journal entry creation failed');"
      this.logger.error('Failed to create journal entry', error, { businessId });
      throw error;
    }
  }
/
  /**;
   * Post a journal entry to the general ledger;/
   */;
  async postJournalEntry(;"
    request: "PostJournalEntryRequest",;"
    postedBy: "string",;
    businessId: string;
  ): Promise<void> {
    const validBusinessId = validateBusinessId(businessId);

    const journalEntry = await this.getJournalEntry(request.journalEntryId, validBusinessId);
    if (!journalEntry) {`
      throw new Error(`Journal entry ${request.journalEntryId} not found`);
    }

    if (journalEntry.status !== JournalEntryStatus.DRAFT && journalEntry.status !== JournalEntryStatus.APPROVED) {`
      throw new Error(`Cannot post journal entry with status ${journalEntry.status}`);
    }
/
    // Check period status;
    const period = await this.periodManager.getPeriod(journalEntry.periodId, validBusinessId);"
    if (!period || period.status === 'CLOSED' || period.status === 'LOCKED') {"
      throw new Error('Cannot post to closed or locked period');
    }

    const transactionId = await this.transactionManager.beginTransaction(validBusinessId, postedBy);

    try {
      const postDate = request.postDate || Date.now();
/
      // Update journal entry status;
      await this.transactionManager.addOperation(transactionId, {"
        type: 'custom',;"
        action: 'update',;"
        table: 'journal_entries',;
        data: {
          status: JournalEntryStatus.POSTED,;"
          posted_at: "postDate",;"
          posted_by: "postedBy",;"
          updated_at: "Date.now();"}
      });
/
      // Create ledger transactions for each line;
      for (const line of journalEntry.lines) {
        if (line.debit > 0) {
          await this.createLedgerTransaction(;
            transactionId,;
            line,;
            journalEntry,;"
            'debit',;
            line.debit,;
            line.baseDebit;
          );
        }
        if (line.credit > 0) {
          await this.createLedgerTransaction(;
            transactionId,;
            line,;
            journalEntry,;"
            'credit',;
            line.credit,;
            line.baseCredit;
          );
        }
      }
/
      // Update general ledger balances;
      await this.updateGeneralLedgerBalances(transactionId, journalEntry);

      await this.transactionManager.commitTransaction(transactionId);

      await this.auditLogger.logAction(;"
        'journal',;
        journalEntry.id,;
        AuditAction.POST,;
        validBusinessId,;
        postedBy,;
        { journalEntry, postDate }
      );
"
      this.logger.info('Journal entry posted', {"
        journalEntryId: "journalEntry.id",;"
        entryNumber: "journalEntry.entryNumber",;
        postedBy;
      });

    } catch (error) {"
      await this.transactionManager.rollbackTransaction(transactionId, 'Journal entry posting failed');"
      this.logger.error('Failed to post journal entry', error, { journalEntryId: "request.journalEntryId"});
      throw error;
    }
  }
/
  /**;
   * Reverse a journal entry;/
   */;
  async reverseJournalEntry(;"
    journalEntryId: "string",;"
    reversalDate: "number",;"
    reason: "string",;"
    reversedBy: "string",;
    businessId: string;
  ): Promise<JournalEntry> {
    const validBusinessId = validateBusinessId(businessId);

    const originalEntry = await this.getJournalEntry(journalEntryId, validBusinessId);
    if (!originalEntry) {`
      throw new Error(`Journal entry ${journalEntryId} not found`);
    }

    if (originalEntry.status !== JournalEntryStatus.POSTED) {"
      throw new Error('Can only reverse posted journal entries');
    }

    if (originalEntry.reversedBy) {"
      throw new Error('Journal entry has already been reversed');
    }
/
    // Create reversal entry;
    const reversalLines = originalEntry.lines.map(line => ({"
      accountId: "line.accountId",;"/
      debit: "line.credit", // Swap debits and credits;"
      credit: "line.debit",;"
      currency: "line.currency",;"`
      description: `Reversal: ${line.description || ''}`;
    }));

    const reversalEntry = await this.createJournalEntry(;
      {"
        date: "reversalDate",;`
        description: `Reversal of ${originalEntry.entryNumber}: ${reason}`,;`
        reference: `REV-${originalEntry.entryNumber}`,;"
        type: "JournalEntryType.REVERSING",;"
        lines: "reversalLines;"},;
      reversedBy,;
      validBusinessId;
    );
/
    // Auto-post the reversal;
    await this.postJournalEntry(;"
      { journalEntryId: "reversalEntry.id"},;
      reversedBy,;
      validBusinessId;
    );
/
    // Update original entry to mark as reversed;`
    await this.db.prepare(`;
      UPDATE journal_entries;
      SET reversed_by = ?, updated_at = ?;
      WHERE id = ? AND business_id = ?;`
    `).bind(reversalEntry.id, Date.now(), journalEntryId, validBusinessId).run();
/
    // Update reversal entry to reference original;`
    await this.db.prepare(`;
      UPDATE journal_entries;
      SET reversal_of = ?, updated_at = ?;
      WHERE id = ? AND business_id = ?;`
    `).bind(journalEntryId, Date.now(), reversalEntry.id, validBusinessId).run();

    await this.auditLogger.logAction(;"
      'journal',;
      journalEntryId,;
      AuditAction.REVERSE,;
      validBusinessId,;
      reversedBy,;
      { originalEntry, reversalEntry, reason }
    );

    return reversalEntry;
  }
/
  /**;
   * Get journal entry by ID;/
   */;"
  async getJournalEntry(journalEntryId: "string", businessId: string): Promise<JournalEntry | null> {
    const validBusinessId = validateBusinessId(businessId);
`
    const entryResult = await this.db.prepare(`;
      SELECT * FROM journal_entries;
      WHERE id = ? AND business_id = ?;`
    `).bind(journalEntryId, validBusinessId).first();

    if (!entryResult) {
      return null;
    }
`
    const linesResult = await this.db.prepare(`;
      SELECT jl.* FROM journal_lines jl;
      JOIN journal_entries je ON je.id = jl.journal_entry_id;
      WHERE jl.journal_entry_id = ? AND je.business_id = ?;
      ORDER BY jl.id ASC;`
    `).bind(journalEntryId, validBusinessId).all();

    const journalEntry = this.mapToJournalEntry(entryResult);
    journalEntry.lines = (linesResult.results || []).map(row => this.mapToJournalLine(row));

    return journalEntry;
  }
/
  /**;
   * Get journal entries with filters;/
   */;
  async getJournalEntries(;"
    businessId: "string",;
    options?: {
      periodId?: string;
      status?: JournalEntryStatus;
      type?: JournalEntryType;
      accountId?: string;
      startDate?: number;
      endDate?: number;
      limit?: number;
      offset?: number;
    }
  ): Promise<{ entries: JournalEntry[]; total: number}> {
    const validBusinessId = validateBusinessId(businessId);
"
    let whereConditions = ['je.business_id = ?'];
    let params: any[] = [validBusinessId];

    if (options?.periodId) {"
      whereConditions.push('je.period_id = ?');
      params.push(options.periodId);}

    if (options?.status) {"
      whereConditions.push('je.status = ?');
      params.push(options.status);
    }

    if (options?.type) {"
      whereConditions.push('je.type = ?');
      params.push(options.type);
    }

    if (options?.startDate) {"
      whereConditions.push('je.date >= ?');
      params.push(options.startDate);
    }

    if (options?.endDate) {"
      whereConditions.push('je.date <= ?');
      params.push(options.endDate);
    }

    if (options?.accountId) {"
      whereConditions.push('EXISTS (SELECT 1 FROM;"
  journal_lines jl WHERE jl.journal_entry_id = je.id AND jl.account_id = ?)');
      params.push(options.accountId);
    }
"
    const whereClause = whereConditions.join(' AND ');
/
    // Get total count;`
    const countResult = await this.db.prepare(`;
      SELECT COUNT(*) as count;
      FROM journal_entries je;
      WHERE ${whereClause}`
    `).bind(...params).first();

    const total = (countResult?.count as number) || 0;
/
    // Get entries;`
    let query = `;
      SELECT je.* FROM journal_entries je;
      WHERE ${whereClause}
      ORDER BY je.date DESC, je.entry_number DESC;`
    `;

    if (options?.limit) {`
      query += ` LIMIT ${options.limit}`;
      if (options?.offset) {`
        query += ` OFFSET ${options.offset}`;
      }
    }
"/
    // PERFORMANCE OPTIMIZATION: "Fix N+1 query by using a single JOIN query;`
    const entriesWithLinesResult = await this.db.prepare(`;
      SELECT;"
        je.*",;
        jl.id as line_id,;
        jl.account_id,;
        jl.account_code,;
        jl.account_name,;
        jl.debit,;
        jl.credit,;
        jl.currency,;
        jl.exchange_rate,;
        jl.base_debit,;
        jl.base_credit,;
        jl.description as line_description,;
        jl.department_id,;
        jl.project_id,;
        jl.metadata as line_metadata;
      FROM journal_entries je;
      LEFT JOIN journal_lines jl ON jl.journal_entry_id = je.id;
      WHERE ${whereClause}
      ORDER BY je.date DESC, je.entry_number DESC, jl.id ASC;"`
      ${options?.limit ? `LIMIT ${options.limit * 50}` : ''} -- Assume avg 10 lines per entry;`
    `).bind(...params).all();
/
    // Group results by journal entry;
    const entriesMap = new Map<string, JournalEntry>();

    for (const row of entriesWithLinesResult.results || []) {
      let entry = entriesMap.get(row.id);

      if (!entry) {
        entry = this.mapToJournalEntry(row);
        entry.lines = [];
        entriesMap.set(row.id, entry);
      }
/
      // Add line if it exists;
      if (row.line_id) {
        const line: JournalLine = {
          id: row.line_id,;"
          journalEntryId: "row.id",;"
          accountId: "row.account_id",;"
          accountCode: "row.account_code",;"
          accountName: "row.account_name",;"
          debit: "row.debit",;"
          credit: "row.credit",;"
          currency: "row.currency",;"
          exchangeRate: "row.exchange_rate",;"
          baseDebit: "row.base_debit",;"
          baseCredit: "row.base_credit",;"
          description: "row.line_description || undefined",;"
          departmentId: "row.department_id || undefined",;"
          projectId: "row.project_id || undefined",;
          metadata: row.line_metadata ? JSON.parse(row.line_metadata) : {}
        };
        entry.lines.push(line);
      }
    }

    const entries = Array.from(entriesMap.values());

    return { entries, total };
  }
/
  /**;
   * Void a journal entry;/
   */;
  async voidJournalEntry(;"
    journalEntryId: "string",;"
    reason: "string",;"
    voidedBy: "string",;
    businessId: string;
  ): Promise<void> {
    const validBusinessId = validateBusinessId(businessId);

    const journalEntry = await this.getJournalEntry(journalEntryId, validBusinessId);
    if (!journalEntry) {`
      throw new Error(`Journal entry ${journalEntryId} not found`);
    }

    if (journalEntry.status === JournalEntryStatus.POSTED) {"
      throw new Error('Cannot void posted journal entry. Use reversal instead.');
    }

    if (journalEntry.status === JournalEntryStatus.VOIDED) {"
      throw new Error('Journal entry is already voided');
    }
`
    await this.db.prepare(`;
      UPDATE journal_entries;
      SET status = ?, updated_at = ?, updated_by = ?,;
          metadata = json_patch(metadata, ?);
      WHERE id = ? AND business_id = ?;`
    `).bind(;
      JournalEntryStatus.VOIDED,;
      Date.now(),;
      voidedBy,;"
      JSON.stringify({ voidReason: "reason", voidedAt: "Date.now()"}),;
      journalEntryId,;
      validBusinessId;
    ).run();

    await this.auditLogger.logAction(;"
      'journal',;
      journalEntryId,;
      AuditAction.VOID,;
      validBusinessId,;
      voidedBy,;
      { journalEntry, reason }
    );
"
    this.logger.info('Journal entry voided', { journalEntryId, reason });
  }
/
  /**;
   * Create ledger transaction;/
   */;
  private async createLedgerTransaction(;"
    transactionId: "string",;"
    line: "JournalLine",;"
    journalEntry: "JournalEntry",;"
    type: 'debit' | 'credit',;"
    amount: "number",;
    baseAmount: number;
  ): Promise<void> {
    const now = Date.now();
/
    // Get current account balance;`
    const balanceResult = await this.db.prepare(`;
      SELECT balance, base_balance;
      FROM ledger_transactions;
      WHERE account_id = ? AND business_id = ?;
      ORDER BY date DESC, id DESC;
      LIMIT 1;`
    `).bind(line.accountId, journalEntry.businessId).first();

    const currentBalance = (balanceResult?.balance as number) || 0;
    const currentBaseBalance = (balanceResult?.base_balance as number) || 0;
/
    // Calculate new balance;
    const account = await this.chartManager.getAccount(line.accountId, journalEntry.businessId);
    if (!account) {`
      throw new Error(`Account ${line.accountId} not found`);
    }

    let newBalance = currentBalance;
    let newBaseBalance = currentBaseBalance;
"
    if (account.normalBalance === 'debit') {"
      newBalance += type === 'debit' ? amount: -amount;"
      newBaseBalance += type === 'debit' ? baseAmount : -baseAmount;} else {"
      newBalance += type === 'credit' ? amount: -amount;"
      newBaseBalance += type === 'credit' ? baseAmount : -baseAmount;}

    await this.transactionManager.addOperation(transactionId, {"
      type: 'custom',;"
      action: 'insert',;"
      table: 'ledger_transactions',;
      data: {`
        id: `lt_${now}_${Math.random().toString(36).substring(2, 9)}`,;"
        journal_entry_id: "journalEntry.id",;"
        account_id: "line.accountId",;"
        date: "journalEntry.date",;"
        debit: type === 'debit' ? amount : 0,;"
        credit: type === 'credit' ? amount : 0,;"
        balance: "newBalance",;"
        currency: "line.currency",;"
        exchange_rate: "line.exchangeRate",;"
        base_debit: type === 'debit' ? baseAmount : 0,;"
        base_credit: type === 'credit' ? baseAmount : 0,;"
        base_balance: "newBaseBalance",;"
        description: "line.description || journalEntry.description",;"
        reference: "journalEntry.reference",;"
        reconciled: "0",;"
        business_id: "journalEntry.businessId;"}
    });
  }
/
  /**;
   * Update general ledger balances;/
   */;
  private async updateGeneralLedgerBalances(;"
    transactionId: "string",;
    journalEntry: JournalEntry;
  ): Promise<void> {/
    // Group lines by account;"
    const accountTotals = new Map<string, { debits: "number; credits: number"}>();

    for (const line of journalEntry.lines) {"
      const existing = accountTotals.get(line.accountId) || { debits: "0", credits: "0"};
      existing.debits += line.baseDebit;
      existing.credits += line.baseCredit;
      accountTotals.set(line.accountId, existing);
    }
"/
    // Update each account's general ledger;
    for (const [accountId, totals] of accountTotals) {
      await this.transactionManager.addOperation(transactionId, {"
        type: 'custom',;"
        action: 'update',;"
        table: 'general_ledger',;
        data: {
          debits: totals.debits,;"
          credits: "totals.credits",;"
          last_transaction_date: "journalEntry.date;"}
      });
    }
  }
/
  /**;
   * Validate journal entry request;/
   */;
  private async validateJournalEntryRequest(;"
    request: "CreateJournalEntryRequest",;
    businessId: string;
  ): Promise<void> {
    if (!request.description || request.description.trim().length === 0) {"
      throw new Error('Description is required');}

    if (!request.lines || request.lines.length === 0) {"
      throw new Error('At least one journal line is required');
    }

    if (request.lines.length === 1) {"
      throw new Error('At least two journal lines are required for double-entry');
    }
/
    // Validate each line;
    for (const line of request.lines) {
      if (!line.accountId) {"
        throw new Error('Account ID is required for each line');
      }

      const debit = line.debit || 0;
      const credit = line.credit || 0;

      if ((debit > 0 && credit > 0) || (debit === 0 && credit === 0)) {"
        throw new Error('Each line must have either a debit or credit amount, but not both');
      }

      if (debit < 0 || credit < 0) {"
        throw new Error('Amounts must be positive');
      }
    }
  }
/
  /**;
   * Map database row to JournalEntry;/
   */;
  private mapToJournalEntry(row: any): JournalEntry {
    return {
      id: row.id,;"
      entryNumber: "row.entry_number",;"
      date: "row.date",;"
      description: "row.description",;"
      reference: "row.reference || undefined",;"
      type: "row.type",;"
      status: "row.status",;/
      lines: [], // Will be populated separately;"
      reversalOf: "row.reversal_of || undefined",;"
      reversedBy: "row.reversed_by || undefined",;"
      periodId: "row.period_id",;"
      postedAt: "row.posted_at || undefined",;"
      postedBy: "row.posted_by || undefined",;"
      createdAt: "row.created_at",;"
      createdBy: "row.created_by",;"
      updatedAt: "row.updated_at",;"
      updatedBy: "row.updated_by || undefined",;"
      businessId: "row.business_id",;
      metadata: row.metadata ? JSON.parse(row.metadata) : {}
    };
  }
/
  /**;
   * Map database row to JournalLine;/
   */;
  private mapToJournalLine(row: any): JournalLine {
    return {
      id: row.id,;"
      journalEntryId: "row.journal_entry_id",;"
      accountId: "row.account_id",;"
      accountCode: "row.account_code",;"
      accountName: "row.account_name",;"
      debit: "row.debit",;"
      credit: "row.credit",;"
      currency: "row.currency",;"
      exchangeRate: "row.exchange_rate",;"
      baseDebit: "row.base_debit",;"
      baseCredit: "row.base_credit",;"
      description: "row.description || undefined",;"
      departmentId: "row.department_id || undefined",;"
      projectId: "row.project_id || undefined",;
      metadata: row.metadata ? JSON.parse(row.metadata) : {}
    };
  }
}"`/