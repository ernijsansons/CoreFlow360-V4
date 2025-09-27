/**
 * Period Manager
 * Manages accounting periods, closing, and locking
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  AccountingPeriod,
  PeriodStatus,
  ClosePeriodRequest,
  ClosingEntry,
  AuditAction,
  ChartAccount,
  AccountType,
  JournalEntryType
} from './types';
import { FinanceAuditLogger } from './audit-logger';
import { ChartOfAccountsManager } from './chart-of-accounts';
import { JournalEntryManager } from './journal-entry-manager';
import { TransactionManager } from '../agent-system/transaction-manager';
import {
  validateBusinessId,
  getFiscalYear,
  getFiscalPeriod,
  getFiscalPeriodDateRange,
  generateFiscalCalendar
} from './utils';

export // TODO: Consider splitting PeriodManager into smaller, focused classes
class PeriodManager {
  private logger: Logger;
  private db: D1Database;
  private auditLogger: FinanceAuditLogger;
  private chartManager: ChartOfAccountsManager;
  private journalManager?: JournalEntryManager;
  private transactionManager: TransactionManager;

  constructor(
    db: D1Database,
    chartManager: ChartOfAccountsManager
  ) {
    this.logger = new Logger();
    this.db = db;
    this.auditLogger = new FinanceAuditLogger(db);
    this.chartManager = chartManager;
    this.transactionManager = new TransactionManager(db);
  }

  /**
   * Set journal manager (to avoid circular dependency)
   */
  setJournalManager(journalManager: JournalEntryManager): void {
    this.journalManager = journalManager;
  }

  /**
   * Create accounting periods for fiscal year
   */
  async createPeriodsForFiscalYear(
    fiscalYear: number,
    businessId: string,
    createdBy: string,
    options?: {
      fiscalYearStart?: number;
      periodType?: 'monthly' | 'quarterly';
    }
  ): Promise<AccountingPeriod[]> {
    const validBusinessId = validateBusinessId(businessId);
    const fiscalYearStart = options?.fiscalYearStart || 1;
    const periodType = options?.periodType || 'monthly';

    // Check if periods already exist for this fiscal year
    const existingPeriods = await this.getPeriodsForFiscalYear(fiscalYear, validBusinessId);
    if (existingPeriods.length > 0) {
      throw new Error(`Periods already exist for fiscal year ${fiscalYear}`);
    }

    const calendar = generateFiscalCalendar(fiscalYear, fiscalYearStart, periodType);
    const periods: AccountingPeriod[] = [];

    const transactionId = await this.transactionManager.beginTransaction(validBusinessId, createdBy);

    try {
      for (const calendarPeriod of calendar) {
        const period: AccountingPeriod = {
          id: `period_${fiscalYear}_${calendarPeriod.period}_${Date.now()}`,
          name: calendarPeriod.name,
          startDate: calendarPeriod.startDate,
          endDate: calendarPeriod.endDate,
          fiscalYear,
          fiscalPeriod: calendarPeriod.period,
          status: PeriodStatus.FUTURE,
          businessId: validBusinessId
        };

        // Determine status based on current date
        const now = Date.now();
        if (now >= period.startDate && now <= period.endDate) {
          period.status = PeriodStatus.OPEN;
        } else if (now > period.endDate) {
          period.status = PeriodStatus.OPEN; // Allow retroactive entries initially
        }

        await this.transactionManager.addOperation(transactionId, {
          type: 'custom',
          action: 'insert',
          table: 'accounting_periods',
          data: {
            id: period.id,
            name: period.name,
            start_date: period.startDate,
            end_date: period.endDate,
            fiscal_year: period.fiscalYear,
            fiscal_period: period.fiscalPeriod,
            status: period.status,
            business_id: period.businessId,
            created_at: Date.now(),
            created_by: createdBy
          }
        });

        periods.push(period);
      }

      await this.transactionManager.commitTransaction(transactionId);

      await this.auditLogger.logAction(
        'period',
        `fiscal_${fiscalYear}`,
        AuditAction.CREATE,
        validBusinessId,
        createdBy,
        {
          fiscalYear,
          periodCount: periods.length,
          periodType,
          fiscalYearStart
        }
      );

      this.logger.info('Fiscal year periods created', {
        fiscalYear,
        periodCount: periods.length,
        businessId: validBusinessId
      });

      return periods;

    } catch (error: any) {
      await this.transactionManager.rollbackTransaction(transactionId, 'Period creation failed');
      this.logger.error('Failed to create fiscal year periods', error, {
        fiscalYear,
        businessId
      });
      throw error;
    }
  }

  /**
   * Get period by ID
   */
  async getPeriod(periodId: string, businessId: string): Promise<AccountingPeriod | null> {
    const validBusinessId = validateBusinessId(businessId);

    const result = await this.db.prepare(`
      SELECT * FROM accounting_periods
      WHERE id = ? AND business_id = ?
    `).bind(periodId, validBusinessId).first();

    if (!result) {
      return null;
    }

    return this.mapToPeriod(result);
  }

  /**
   * Get period for specific date
   */
  async getPeriodForDate(date: number, businessId: string): Promise<AccountingPeriod | null> {
    const validBusinessId = validateBusinessId(businessId);

    const result = await this.db.prepare(`
      SELECT * FROM accounting_periods
      WHERE business_id = ?
      AND start_date <= ? AND end_date >= ?
      ORDER BY start_date DESC
      LIMIT 1
    `).bind(validBusinessId, date, date).first();

    if (!result) {
      return null;
    }

    return this.mapToPeriod(result);
  }

  /**
   * Get periods for fiscal year
   */
  async getPeriodsForFiscalYear(
    fiscalYear: number,
    businessId: string
  ): Promise<AccountingPeriod[]> {
    const validBusinessId = validateBusinessId(businessId);

    const result = await this.db.prepare(`
      SELECT * FROM accounting_periods
      WHERE fiscal_year = ? AND business_id = ?
      ORDER BY fiscal_period ASC
    `).bind(fiscalYear, validBusinessId).all();

    return (result.results || []).map((row: any) => this.mapToPeriod(row));
  }

  /**
   * Get all periods for business
   */
  async getPeriods(
    businessId: string,
    options?: {
      status?: PeriodStatus;
      fiscalYear?: number;
      startDate?: number;
      endDate?: number;
    }
  ): Promise<AccountingPeriod[]> {
    const validBusinessId = validateBusinessId(businessId);

    let query = 'SELECT * FROM accounting_periods WHERE business_id = ?';
    const params: any[] = [validBusinessId];

    if (options?.status) {
      query += ' AND status = ?';
      params.push(options.status);
    }

    if (options?.fiscalYear) {
      query += ' AND fiscal_year = ?';
      params.push(options.fiscalYear);
    }

    if (options?.startDate) {
      query += ' AND end_date >= ?';
      params.push(options.startDate);
    }

    if (options?.endDate) {
      query += ' AND start_date <= ?';
      params.push(options.endDate);
    }

    query += ' ORDER BY start_date ASC';

    const result = await this.db.prepare(query).bind(...params).all();

    return (result.results || []).map((row: any) => this.mapToPeriod(row));
  }

  /**
   * Close accounting period
   */
  async closePeriod(
    request: ClosePeriodRequest,
    closedBy: string,
    businessId: string
  ): Promise<{ period: AccountingPeriod; closingEntries: string[] }> {
    const validBusinessId = validateBusinessId(businessId);

    if (!this.journalManager) {
      throw new Error('Journal manager not initialized');
    }

    const period = await this.getPeriod(request.periodId, validBusinessId);
    if (!period) {
      throw new Error(`Period ${request.periodId} not found`);
    }

    if (period.status !== PeriodStatus.OPEN) {
      throw new Error(`Period is not open for closing (status: ${period.status})`);
    }

    // Check for unposted entries in the period
    const unpostedEntries = await this.journalManager.getJournalEntries(validBusinessId, {
      periodId: request.periodId,
      status: 'DRAFT'
    });

    if (unpostedEntries.total > 0) {
      throw new Error(`Cannot close period with ${unpostedEntries.total} unposted entries`);
    }

    const transactionId = await this.transactionManager.beginTransaction(validBusinessId, closedBy);

    try {
      const closingEntries: string[] = [];

      // Process adjusting entries if provided
      if (request.adjustingEntries && request.adjustingEntries.length > 0) {
        for (const adjustingEntry of request.adjustingEntries) {
          const entry = await this.journalManager.createJournalEntry(
            {
              ...adjustingEntry,
              type: JournalEntryType.ADJUSTING
            },
            closedBy,
            validBusinessId
          );

          await this.journalManager.postJournalEntry(
            { journalEntryId: entry.id },
            closedBy,
            validBusinessId
          );

          closingEntries.push(entry.id);
        }
      }

      // Create closing entries
      const generatedClosingEntries = await this.generateClosingEntries(
        period,
        closedBy,
        validBusinessId
      );

      closingEntries.push(...generatedClosingEntries);

      // Update period status
      const now = Date.now();
      await this.transactionManager.addOperation(transactionId, {
        type: 'custom',
        action: 'update',
        table: 'accounting_periods',
        data: {
          status: PeriodStatus.CLOSED,
          closed_at: now,
          closed_by: closedBy
        }
      });

      period.status = PeriodStatus.CLOSED;
      period.closedAt = now;
      period.closedBy = closedBy;

      await this.transactionManager.commitTransaction(transactionId);

      await this.auditLogger.logPeriodClosed(
        period.id,
        validBusinessId,
        closedBy,
        period.name,
        closingEntries.length
      );

      this.logger.info('Accounting period closed', {
        periodId: period.id,
        periodName: period.name,
        closingEntries: closingEntries.length
      });

      return { period, closingEntries };

    } catch (error: any) {
      await this.transactionManager.rollbackTransaction(transactionId, 'Period closing failed');
      this.logger.error('Failed to close accounting period', error, {
        periodId: request.periodId
      });
      throw error;
    }
  }

  /**
   * Lock accounting period
   */
  async lockPeriod(
    periodId: string,
    lockedBy: string,
    businessId: string
  ): Promise<AccountingPeriod> {
    const validBusinessId = validateBusinessId(businessId);

    const period = await this.getPeriod(periodId, validBusinessId);
    if (!period) {
      throw new Error(`Period ${periodId} not found`);
    }

    if (period.status !== PeriodStatus.CLOSED) {
      throw new Error('Can only lock closed periods');
    }

    const now = Date.now();

    await this.db.prepare(`
      UPDATE accounting_periods
      SET status = ?, locked_at = ?, locked_by = ?
      WHERE id = ? AND business_id = ?
    `).bind(
      PeriodStatus.LOCKED,
      now,
      lockedBy,
      periodId,
      validBusinessId
    ).run();

    period.status = PeriodStatus.LOCKED;
    period.lockedAt = now;
    period.lockedBy = lockedBy;

    await this.auditLogger.logAction(
      'period',
      periodId,
      AuditAction.LOCK_PERIOD,
      validBusinessId,
      lockedBy,
      { periodName: period.name }
    );

    this.logger.info('Accounting period locked', {
      periodId,
      periodName: period.name
    });

    return period;
  }

  /**
   * Unlock accounting period
   */
  async unlockPeriod(
    periodId: string,
    unlockedBy: string,
    businessId: string,
    reason: string
  ): Promise<AccountingPeriod> {
    const validBusinessId = validateBusinessId(businessId);

    const period = await this.getPeriod(periodId, validBusinessId);
    if (!period) {
      throw new Error(`Period ${periodId} not found`);
    }

    if (period.status !== PeriodStatus.LOCKED) {
      throw new Error('Period is not locked');
    }

    await this.db.prepare(`
      UPDATE accounting_periods
      SET status = ?, locked_at = NULL, locked_by = NULL
      WHERE id = ? AND business_id = ?
    `).bind(
      PeriodStatus.CLOSED,
      periodId,
      validBusinessId
    ).run();

    period.status = PeriodStatus.CLOSED;
    period.lockedAt = undefined;
    period.lockedBy = undefined;

    await this.auditLogger.logAction(
      'period',
      periodId,
      AuditAction.UNLOCK_PERIOD,
      validBusinessId,
      unlockedBy,
      {
        periodName: period.name,
        reason
      }
    );

    this.logger.info('Accounting period unlocked', {
      periodId,
      periodName: period.name,
      reason
    });

    return period;
  }

  /**
   * Generate closing entries
   */
  private async generateClosingEntries(
    period: AccountingPeriod,
    closedBy: string,
    businessId: string
  ): Promise<string[]> {
    if (!this.journalManager) {
      throw new Error('Journal manager not initialized');
    }

    const closingAccounts = await this.chartManager.getClosingAccounts(businessId);

    if (!closingAccounts.incomeSummaryAccount || !closingAccounts.retainedEarningsAccount) {
      throw new Error('Income Summary and Retained Earnings accounts are required for closing');
    }

    const closingEntries: string[] = [];

    // 1. Close revenue accounts to Income Summary
    if (closingAccounts.revenueAccounts.length > 0) {
      const revenueBalances = await this.getAccountBalancesForPeriod(
        closingAccounts.revenueAccounts.map((a: any) => a.id),
        period,
        businessId
      );

      const totalRevenue = revenueBalances.reduce((sum, balance) => sum + balance.credit - balance.debit, 0);

      if (totalRevenue !== 0) {
        const revenueClosingLines = revenueBalances
          .filter((balance: any) => (balance.credit - balance.debit) !== 0)
          .map((balance: any) => ({
            accountId: balance.accountId,
            debit: balance.credit - balance.debit, // Close credit balances with debits
            credit: 0
          }));

        revenueClosingLines.push({
          accountId: closingAccounts.incomeSummaryAccount.id,
          debit: 0,
          credit: totalRevenue
        });

        const revenueEntry = await this.journalManager.createJournalEntry(
          {
            date: period.endDate,
            description: `Close revenue accounts for ${period.name}`,
            type: JournalEntryType.CLOSING,
            lines: revenueClosingLines
          },
          closedBy,
          businessId
        );

        await this.journalManager.postJournalEntry(
          { journalEntryId: revenueEntry.id },
          closedBy,
          businessId
        );

        closingEntries.push(revenueEntry.id);
      }
    }

    // 2. Close expense accounts to Income Summary
    if (closingAccounts.expenseAccounts.length > 0) {
      const expenseBalances = await this.getAccountBalancesForPeriod(
        closingAccounts.expenseAccounts.map((a: any) => a.id),
        period,
        businessId
      );

      const totalExpenses = expenseBalances.reduce((sum, balance) => sum + balance.debit - balance.credit, 0);

      if (totalExpenses !== 0) {
        const expenseClosingLines = expenseBalances
          .filter((balance: any) => (balance.debit - balance.credit) !== 0)
          .map((balance: any) => ({
            accountId: balance.accountId,
            debit: 0,
            credit: balance.debit - balance.credit // Close debit balances with credits
          }));

        expenseClosingLines.push({
          accountId: closingAccounts.incomeSummaryAccount.id,
          debit: totalExpenses,
          credit: 0
        });

        const expenseEntry = await this.journalManager.createJournalEntry(
          {
            date: period.endDate,
            description: `Close expense accounts for ${period.name}`,
            type: JournalEntryType.CLOSING,
            lines: expenseClosingLines
          },
          closedBy,
          businessId
        );

        await this.journalManager.postJournalEntry(
          { journalEntryId: expenseEntry.id },
          closedBy,
          businessId
        );

        closingEntries.push(expenseEntry.id);
      }
    }

    // 3. Close Income Summary to Retained Earnings
    const incomeSummaryBalance = await this.getAccountBalancesForPeriod(
      [closingAccounts.incomeSummaryAccount.id],
      period,
      businessId
    );

    if (incomeSummaryBalance.length > 0) {
      const netIncome = incomeSummaryBalance[0].credit - incomeSummaryBalance[0].debit;

      if (netIncome !== 0) {
        const incomeSummaryLines = [
          {
            accountId: closingAccounts.incomeSummaryAccount.id,
            debit: netIncome > 0 ? netIncome : 0,
            credit: netIncome < 0 ? Math.abs(netIncome) : 0
          },
          {
            accountId: closingAccounts.retainedEarningsAccount.id,
            debit: netIncome < 0 ? Math.abs(netIncome) : 0,
            credit: netIncome > 0 ? netIncome : 0
          }
        ];

        const incomeSummaryEntry = await this.journalManager.createJournalEntry(
          {
            date: period.endDate,
            description: `Close Income Summary to Retained Earnings for ${period.name}`,
            type: JournalEntryType.CLOSING,
            lines: incomeSummaryLines
          },
          closedBy,
          businessId
        );

        await this.journalManager.postJournalEntry(
          { journalEntryId: incomeSummaryEntry.id },
          closedBy,
          businessId
        );

        closingEntries.push(incomeSummaryEntry.id);
      }
    }

    return closingEntries;
  }

  /**
   * Get account balances for period
   */
  private async getAccountBalancesForPeriod(
    accountIds: string[],
    period: AccountingPeriod,
    businessId: string
  ): Promise<Array<{ accountId: string; debit: number; credit: number }>> {
    if (accountIds.length === 0) {
      return [];
    }

    const placeholders = accountIds.map(() => '?').join(',');

    const result = await this.db.prepare(`
      SELECT
        jl.account_id,
        SUM(jl.base_debit) as total_debit,
        SUM(jl.base_credit) as total_credit
      FROM journal_lines jl
      JOIN journal_entries je ON jl.journal_entry_id = je.id
      WHERE jl.account_id IN (${placeholders})
      AND je.business_id = ?
      AND je.status = 'POSTED'
      AND je.date >= ? AND je.date <= ?
      GROUP BY jl.account_id
    `).bind(...accountIds, businessId, period.startDate, period.endDate).all();

    return (result.results || []).map((row: any) => ({
      accountId: row.account_id as string,
      debit: (row.total_debit as number) || 0,
      credit: (row.total_credit as number) || 0
    }));
  }

  /**
   * Check if period allows entries
   */
  async isPeriodOpenForEntries(periodId: string, businessId: string): Promise<boolean> {
    const period = await this.getPeriod(periodId, businessId);
    return period?.status === PeriodStatus.OPEN;
  }

  /**
   * Get current open period
   */
  async getCurrentPeriod(businessId: string): Promise<AccountingPeriod | null> {
    const now = Date.now();
    return await this.getPeriodForDate(now, businessId);
  }

  /**
   * Map database row to AccountingPeriod
   */
  private mapToPeriod(row: any): AccountingPeriod {
    return {
      id: row.id,
      name: row.name,
      startDate: row.start_date,
      endDate: row.end_date,
      fiscalYear: row.fiscal_year,
      fiscalPeriod: row.fiscal_period,
      status: row.status,
      closedAt: row.closed_at || undefined,
      closedBy: row.closed_by || undefined,
      lockedAt: row.locked_at || undefined,
      lockedBy: row.locked_by || undefined,
      businessId: row.business_id
    };
  }
}