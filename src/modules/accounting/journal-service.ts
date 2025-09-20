import { z } from 'zod';
import type { Env } from '../../types/env';
import { createErrorResponse } from '../../shared/utils';

// Validation schemas
const JournalLineSchema = z.object({
  accountId: z.string().uuid(),
  debitAmount: z.number().min(0).default(0),
  creditAmount: z.number().min(0).default(0),
  description: z.string().optional(),
  departmentId: z.string().uuid().optional(),
  projectId: z.string().uuid().optional(),
});

const JournalEntrySchema = z.object({
  businessId: z.string().uuid(),
  entryDate: z.string().datetime(),
  description: z.string().min(1),
  entryType: z.enum(['standard', 'adjusting', 'closing', 'reversing', 'recurring', 'opening', 'correction']),
  lines: z.array(JournalLineSchema).min(2), // At least 2 lines for double entry
});

export class JournalService {
  private db: D1Database;
  private businessId: string;
  private userId: string;

  constructor(db: D1Database, businessId: string, userId: string) {
    this.db = db;
    this.businessId = businessId;
    this.userId = userId;
  }

  /**
   * Create a journal entry with automatic validation and balancing
   */
  async createJournalEntry(data: z.infer<typeof JournalEntrySchema>) {
    const validated = JournalEntrySchema.parse(data);

    // Verify business access
    if (validated.businessId !== this.businessId) {
      throw new Error('Unauthorized: Cannot create entry for different business');
    }

    // Calculate totals and verify balance
    let totalDebit = 0;
    let totalCredit = 0;

    for (const line of validated.lines) {
      if (line.debitAmount > 0 && line.creditAmount > 0) {
        throw new Error('A line cannot have both debit and credit amounts');
      }
      totalDebit += line.debitAmount;
      totalCredit += line.creditAmount;
    }

    // Double-entry validation
    if (Math.abs(totalDebit - totalCredit) > 0.01) {
      throw new Error(`Entry does not balance: Debit ${totalDebit} != Credit ${totalCredit}`);
    }

    // Begin transaction
    const entryId = crypto.randomUUID();
    const entryNumber = await this.generateEntryNumber();
    const period = validated.entryDate.substring(0, 7); // YYYY-MM
    const fiscalYear = parseInt(validated.entryDate.substring(0, 4));

    try {
      // Create journal entry header
      await this.db.prepare(`
        INSERT INTO journal_entries (
          id, business_id, entry_number, entry_date, period, fiscal_year,
          entry_type, description, total_debit, total_credit,
          status, created_by_user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `).bind(
        entryId,
        this.businessId,
        entryNumber,
        validated.entryDate,
        period,
        fiscalYear,
        validated.entryType,
        validated.description,
        totalDebit,
        totalCredit,
        'draft',
        this.userId
      ).run();

      // Create journal lines
      let lineNumber = 1;
      for (const line of validated.lines) {
        const lineId = crypto.randomUUID();

        // Verify account exists and belongs to business
        const account = await this.db.prepare(`
          SELECT id, status FROM accounts
          WHERE id = ? AND business_id = ? AND status = 'active'
        `).bind(line.accountId, this.businessId).first();

        if (!account) {
          throw new Error(`Invalid account: ${line.accountId}`);
        }

        await this.db.prepare(`
          INSERT INTO journal_lines (
            id, business_id, journal_entry_id, line_number, account_id,
            debit_amount, credit_amount, description,
            department_id, project_id,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).bind(
          lineId,
          this.businessId,
          entryId,
          lineNumber++,
          line.accountId,
          line.debitAmount,
          line.creditAmount,
          line.description || validated.description,
          line.departmentId,
          line.projectId
        ).run();

        // Update account current balance (for draft tracking)
        if (line.debitAmount > 0) {
          await this.updateAccountBalance(line.accountId, line.debitAmount, 0);
        } else if (line.creditAmount > 0) {
          await this.updateAccountBalance(line.accountId, 0, line.creditAmount);
        }
      }

      // Log audit entry
      await this.logAudit('journal_entry_created', entryId, {
        entryNumber,
        totalDebit,
        totalCredit,
        lineCount: validated.lines.length
      });

      return {
        success: true,
        entryId,
        entryNumber,
        totalDebit,
        totalCredit,
      };

    } catch (error) {
      // Rollback by marking entry as failed if it was created
      try {
        await this.db.prepare(`
          UPDATE journal_entries
          SET status = 'voided', voided_at = datetime('now')
          WHERE id = ?
        `).bind(entryId).run();
      } catch {}

      await this.logAudit('journal_entry_failed', entryId, {
        error: String(error)
      });

      throw error;
    }
  }

  /**
   * Post a journal entry (make it permanent)
   */
  async postJournalEntry(entryId: string) {
    // Verify entry exists and belongs to business
    const entry = await this.db.prepare(`
      SELECT id, status, total_debit, total_credit
      FROM journal_entries
      WHERE id = ? AND business_id = ?
    `).bind(entryId, this.businessId).first<any>();

    if (!entry) {
      throw new Error('Journal entry not found');
    }

    if (entry.status === 'posted') {
      throw new Error('Entry is already posted');
    }

    if (entry.status !== 'approved' && entry.status !== 'draft') {
      throw new Error(`Cannot post entry in status: ${entry.status}`);
    }

    // Final balance check
    if (Math.abs(entry.total_debit - entry.total_credit) > 0.01) {
      throw new Error('Entry does not balance');
    }

    // Update entry status
    await this.db.prepare(`
      UPDATE journal_entries
      SET status = 'posted',
          posted_by_user_id = ?,
          posted_at = datetime('now'),
          updated_at = datetime('now')
      WHERE id = ? AND business_id = ?
    `).bind(this.userId, entryId, this.businessId).run();

    // Update general ledger
    await this.updateGeneralLedger(entryId);

    await this.logAudit('journal_entry_posted', entryId, {});

    return { success: true };
  }

  /**
   * Reverse a posted journal entry
   */
  async reverseJournalEntry(entryId: string, reason: string) {
    const entry = await this.db.prepare(`
      SELECT * FROM journal_entries
      WHERE id = ? AND business_id = ? AND status = 'posted'
    `).bind(entryId, this.businessId).first<any>();

    if (!entry) {
      throw new Error('Posted journal entry not found');
    }

    if (entry.is_reversal) {
      throw new Error('Cannot reverse a reversal entry');
    }

    // Get all lines
    const lines = await this.db.prepare(`
      SELECT * FROM journal_lines
      WHERE journal_entry_id = ? AND business_id = ?
    `).bind(entryId, this.businessId).all();

    // Create reversal entry
    const reversalId = crypto.randomUUID();
    const reversalNumber = await this.generateEntryNumber();

    await this.db.prepare(`
      INSERT INTO journal_entries (
        id, business_id, entry_number, entry_date, period, fiscal_year,
        entry_type, description, total_debit, total_credit,
        status, created_by_user_id, is_reversal, reversed_entry_id,
        reversal_reason, created_at, updated_at
      ) VALUES (
        ?, ?, ?, datetime('now'), ?, ?,
        'reversing', ?, ?, ?,
        'posted', ?, 1, ?,
        ?, datetime('now'), datetime('now')
      )
    `).bind(
      reversalId,
      this.businessId,
      reversalNumber,
      new Date().toISOString().substring(0, 7),
      new Date().getFullYear(),
      `Reversal of ${entry.entry_number}: ${reason}`,
      entry.total_credit, // Swap debit and credit
      entry.total_debit,
      this.userId,
      entryId,
      reason
    ).run();

    // Create reversal lines (swap debits and credits)
    for (const line of lines.results || []) {
      await this.db.prepare(`
        INSERT INTO journal_lines (
          id, business_id, journal_entry_id, line_number, account_id,
          debit_amount, credit_amount, description,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `).bind(
        crypto.randomUUID(),
        this.businessId,
        reversalId,
        line.line_number,
        line.account_id,
        line.credit_amount, // Swap
        line.debit_amount,  // Swap
        `Reversal: ${line.description}`
      ).run();
    }

    // Mark original as reversed
    await this.db.prepare(`
      UPDATE journal_entries
      SET status = 'reversed',
          reversal_entry_id = ?,
          reversed_at = datetime('now'),
          updated_at = datetime('now')
      WHERE id = ?
    `).bind(reversalId, entryId).run();

    // Update general ledger
    await this.updateGeneralLedger(reversalId);

    await this.logAudit('journal_entry_reversed', entryId, {
      reversalId,
      reason
    });

    return { success: true, reversalId };
  }

  /**
   * Generate unique entry number
   */
  private async generateEntryNumber(): Promise<string> {
    const yearMonth = new Date().toISOString().substring(0, 7).replace('-', '');
    const lastEntry = await this.db.prepare(`
      SELECT entry_number
      FROM journal_entries
      WHERE business_id = ? AND entry_number LIKE ?
      ORDER BY entry_number DESC
      LIMIT 1
    `).bind(this.businessId, `JE-${yearMonth}-%`).first<any>();

    let sequence = 1;
    if (lastEntry?.entry_number) {
      const parts = lastEntry.entry_number.split('-');
      sequence = parseInt(parts[2]) + 1;
    }

    return `JE-${yearMonth}-${String(sequence).padStart(5, '0')}`;
  }

  /**
   * Update account balance
   */
  private async updateAccountBalance(accountId: string, debit: number, credit: number) {
    await this.db.prepare(`
      UPDATE accounts
      SET ytd_debit = ytd_debit + ?,
          ytd_credit = ytd_credit + ?,
          current_balance = current_balance + ? - ?,
          updated_at = datetime('now')
      WHERE id = ? AND business_id = ?
    `).bind(debit, credit, debit, credit, accountId, this.businessId).run();
  }

  /**
   * Update general ledger
   */
  private async updateGeneralLedger(entryId: string) {
    const entry = await this.db.prepare(`
      SELECT period, fiscal_year FROM journal_entries
      WHERE id = ? AND business_id = ?
    `).bind(entryId, this.businessId).first<any>();

    const lines = await this.db.prepare(`
      SELECT account_id, SUM(debit_amount) as debit, SUM(credit_amount) as credit
      FROM journal_lines
      WHERE journal_entry_id = ? AND business_id = ?
      GROUP BY account_id
    `).bind(entryId, this.businessId).all();

    for (const line of lines.results || []) {
      // Update or insert general ledger record
      await this.db.prepare(`
        INSERT INTO general_ledger (
          id, business_id, account_id, period, fiscal_year,
          period_debit, period_credit, transaction_count,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))
        ON CONFLICT(business_id, account_id, period) DO UPDATE SET
          period_debit = period_debit + excluded.period_debit,
          period_credit = period_credit + excluded.period_credit,
          transaction_count = transaction_count + 1,
          updated_at = datetime('now')
      `).bind(
        crypto.randomUUID(),
        this.businessId,
        line.account_id,
        entry.period,
        entry.fiscal_year,
        line.debit,
        line.credit
      ).run();
    }
  }

  /**
   * Log audit entry
   */
  private async logAudit(eventName: string, resourceId: string, data: any) {
    try {
      await this.db.prepare(`
        INSERT INTO audit_logs (
          id, business_id, event_type, event_name,
          resource_type, resource_id, user_id,
          new_values, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        crypto.randomUUID(),
        this.businessId,
        'create',
        eventName,
        'journal_entry',
        resourceId,
        this.userId,
        JSON.stringify(data)
      ).run();
    } catch (error) {
      console.error('Failed to log audit:', error);
    }
  }
}