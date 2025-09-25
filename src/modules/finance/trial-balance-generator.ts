/**
 * Trial Balance Generator
 * Generates trial balance reports with validation
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  TrialBalance,
  TrialBalanceAccount,
  GenerateTrialBalanceRequest,
  AccountType,
  AccountingPeriod,
  ChartAccount
} from './types';
import { ChartOfAccountsManager } from './chart-of-accounts';
import { PeriodManager } from './period-manager';
import { CurrencyManager } from './currency-manager';
import { validateBusinessId, roundToCurrency } from './utils';

export class TrialBalanceGenerator {
  private logger: Logger;
  private db: D1Database;
  private chartManager: ChartOfAccountsManager;
  private periodManager: PeriodManager;
  private currencyManager: CurrencyManager;

  constructor(
    db: D1Database,
    chartManager: ChartOfAccountsManager,
    periodManager: PeriodManager,
    currencyManager: CurrencyManager
  ) {
    this.logger = new Logger();
    this.db = db;
    this.chartManager = chartManager;
    this.periodManager = periodManager;
    this.currencyManager = currencyManager;
  }

  /**
   * Generate trial balance
   */
  async generateTrialBalance(
    request: GenerateTrialBalanceRequest,
    businessId: string
  ): Promise<TrialBalance> {
    const validBusinessId = validateBusinessId(businessId);

    // Get period information
    const period = await this.periodManager.getPeriod(request.periodId, validBusinessId);
    if (!period) {
      throw new Error(`Period ${request.periodId} not found`);
    }

    const asOfDate = request.asOfDate || period.endDate;
    const baseCurrency = await this.currencyManager.getBaseCurrency(validBusinessId);

    // Get all active accounts
    const accounts = await this.chartManager.getAccounts(validBusinessId, {
      isActive: true
    });

    // Calculate balances for each account
    const trialBalanceAccounts: TrialBalanceAccount[] = [];
    let totalDebits = 0;
    let totalCredits = 0;

    for (const account of accounts) {
      const balances = await this.calculateAccountBalances(
        account,
        period,
        asOfDate,
        validBusinessId
      );

      // Skip zero balances if requested
      if (!request.includeZeroBalances &&
          balances.openingDebit === 0 &&
          balances.openingCredit === 0 &&
          balances.periodDebit === 0 &&
          balances.periodCredit === 0) {
        continue;
      }

      const trialAccount: TrialBalanceAccount = {
        accountId: account.id,
        accountCode: account.code,
        accountName: account.name,
        accountType: account.type,
        openingDebit: roundToCurrency(balances.openingDebit),
        openingCredit: roundToCurrency(balances.openingCredit),
        periodDebit: roundToCurrency(balances.periodDebit),
        periodCredit: roundToCurrency(balances.periodCredit),
        closingDebit: roundToCurrency(balances.closingDebit),
        closingCredit: roundToCurrency(balances.closingCredit)
      };

      trialBalanceAccounts.push(trialAccount);

      // Add to totals (using closing balances)
      totalDebits += trialAccount.closingDebit;
      totalCredits += trialAccount.closingCredit;
    }

    // Sort accounts
    if (request.groupByType) {
      trialBalanceAccounts.sort((a, b) => {
        // First by account type
        const typeOrder = this.getAccountTypeOrder(a.accountType) - this.getAccountTypeOrder(b.accountType);
        if (typeOrder !== 0) return typeOrder;

        // Then by account code
        return a.accountCode.localeCompare(b.accountCode);
      });
    } else {
      trialBalanceAccounts.sort((a, b) => a.accountCode.localeCompare(b.accountCode));
    }

    const trialBalance: TrialBalance = {
      periodId: request.periodId,
      date: asOfDate,
      accounts: trialBalanceAccounts,
      totalDebits: roundToCurrency(totalDebits),
      totalCredits: roundToCurrency(totalCredits),
      isBalanced: Math.abs(totalDebits - totalCredits) < 0.01,
      currency: baseCurrency,
      businessId: validBusinessId
    };

    this.logger.info('Trial balance generated', {
      periodId: request.periodId,
      accountCount: trialBalanceAccounts.length,
      totalDebits: trialBalance.totalDebits,
      totalCredits: trialBalance.totalCredits,
      isBalanced: trialBalance.isBalanced
    });

    return trialBalance;
  }

  /**
   * Generate adjusted trial balance
   */
  async generateAdjustedTrialBalance(
    request: GenerateTrialBalanceRequest,
    adjustmentEntries: string[],
    businessId: string
  ): Promise<TrialBalance> {
    const validBusinessId = validateBusinessId(businessId);

    // Generate base trial balance
    const baseTrialBalance = await this.generateTrialBalance(request, validBusinessId);

    // Apply adjustments
    const adjustmentMap = new Map<string, { debit: number; credit: number }>();

    // Get adjustment entries
    for (const entryId of adjustmentEntries) {
      const adjustments = await this.getAdjustmentAmounts(entryId, validBusinessId);
      for (const [accountId, amounts] of adjustments) {
        const existing = adjustmentMap.get(accountId) || { debit: 0, credit: 0 };
        existing.debit += amounts.debit;
        existing.credit += amounts.credit;
        adjustmentMap.set(accountId, existing);
      }
    }

    // Apply adjustments to trial balance accounts
    for (const account of baseTrialBalance.accounts) {
      const adjustments = adjustmentMap.get(account.accountId);
      if (adjustments) {
        account.periodDebit += adjustments.debit;
        account.periodCredit += adjustments.credit;

        // Recalculate closing balances
        const netDebit = account.openingDebit + account.periodDebit;
        const netCredit = account.openingCredit + account.periodCredit;

        if (netDebit > netCredit) {
          account.closingDebit = netDebit - netCredit;
          account.closingCredit = 0;
        } else {
          account.closingDebit = 0;
          account.closingCredit = netCredit - netDebit;
        }
      }
    }

    // Recalculate totals
    baseTrialBalance.totalDebits = baseTrialBalance.accounts.reduce(
      (sum, account) => sum + account.closingDebit, 0
    );
    baseTrialBalance.totalCredits = baseTrialBalance.accounts.reduce(
      (sum, account) => sum + account.closingCredit, 0
    );

    baseTrialBalance.isBalanced = Math.abs(
      baseTrialBalance.totalDebits - baseTrialBalance.totalCredits
    ) < 0.01;

    return baseTrialBalance;
  }

  /**
   * Generate comparative trial balance
   */
  async generateComparativeTrialBalance(
    currentRequest: GenerateTrialBalanceRequest,
    priorRequest: GenerateTrialBalanceRequest,
    businessId: string
  ): Promise<{
    current: TrialBalance;
    prior: TrialBalance;
    variance: Array<{
      accountId: string;
      accountCode: string;
      accountName: string;
      currentDebit: number;
      currentCredit: number;
      priorDebit: number;
      priorCredit: number;
      debitVariance: number;
      creditVariance: number;
      debitVariancePercent: number;
      creditVariancePercent: number;
    }>;
  }> {
    const [current, prior] = await Promise.all([
      this.generateTrialBalance(currentRequest, businessId),
      this.generateTrialBalance(priorRequest, businessId)
    ]);

    // Create account map for prior period
    const priorAccountMap = new Map<string, TrialBalanceAccount>();
    for (const account of prior.accounts) {
      priorAccountMap.set(account.accountId, account);
    }

    // Calculate variances
    const variance = current.accounts.map(currentAccount => {
      const priorAccount = priorAccountMap.get(currentAccount.accountId);
      const priorDebit = priorAccount?.closingDebit || 0;
      const priorCredit = priorAccount?.closingCredit || 0;

      const debitVariance = currentAccount.closingDebit - priorDebit;
      const creditVariance = currentAccount.closingCredit - priorCredit;

      const debitVariancePercent = priorDebit !== 0
        ? (debitVariance / priorDebit) * 100
        : currentAccount.closingDebit > 0 ? 100 : 0;

      const creditVariancePercent = priorCredit !== 0
        ? (creditVariance / priorCredit) * 100
        : currentAccount.closingCredit > 0 ? 100 : 0;

      return {
        accountId: currentAccount.accountId,
        accountCode: currentAccount.accountCode,
        accountName: currentAccount.accountName,
        currentDebit: currentAccount.closingDebit,
        currentCredit: currentAccount.closingCredit,
        priorDebit,
        priorCredit,
        debitVariance: roundToCurrency(debitVariance),
        creditVariance: roundToCurrency(creditVariance),
        debitVariancePercent: roundToCurrency(debitVariancePercent),
        creditVariancePercent: roundToCurrency(creditVariancePercent)
      };
    });

    return { current, prior, variance };
  }

  /**
   * Validate trial balance
   */
  async validateTrialBalance(
    trialBalance: TrialBalance
  ): Promise<{
    isValid: boolean;
    errors: string[];
    warnings: string[];
  }> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check if trial balance is balanced
    if (!trialBalance.isBalanced) {
      const difference = Math.abs(trialBalance.totalDebits - trialBalance.totalCredits);
      errors.push(`Trial balance is not balanced. Difference: ${difference.toFixed(2)}`);
    }

    // Check for unusual balances
    for (const account of trialBalance.accounts) {
      const isDebitAccount = this.isNormalDebitAccount(account.accountType);

      if (isDebitAccount && account.closingCredit > account.closingDebit) {
        warnings.push(`${account.accountCode} - ${account.accountName} has unusual credit balance`);
      } else if (!isDebitAccount && account.closingDebit > account.closingCredit) {
        warnings.push(`${account.accountCode} - ${account.accountName} has unusual debit balance`);
      }

      // Check for very large balances (potential data entry errors)
      const maxBalance = Math.max(account.closingDebit, account.closingCredit);
      if (maxBalance > 1000000) { // $1M threshold
       
  warnings.push(`${account.accountCode} - ${account.accountName} has unusually large balance: ${maxBalance.toFixed(2)}`);
      }
    }

    // Check for missing standard accounts
    const accountTypes = new Set(trialBalance.accounts.map(a => a.accountType));
    const requiredTypes = [AccountType.ASSET, AccountType.LIABILITY, AccountType.EQUITY];

    for (const requiredType of requiredTypes) {
      if (!accountTypes.has(requiredType)) {
        warnings.push(`No ${requiredType.toLowerCase()} accounts found in trial balance`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Export trial balance to different formats
   */
  async exportTrialBalance(
    trialBalance: TrialBalance,
    format: 'csv' | 'xlsx' | 'pdf' = 'csv'
  ): Promise<{
    data: string | Uint8Array;
    filename: string;
    mimeType: string;
  }> {
    const periodName = trialBalance.periodId.replace(/[^a-zA-Z0-9]/g, '_');
    const dateStr = new Date(trialBalance.date).toISOString().split('T')[0];

    switch (format) {
      case 'csv':
        return {
          data: this.generateCSV(trialBalance),
          filename: `trial_balance_${periodName}_${dateStr}.csv`,
          mimeType: 'text/csv'
        };

      case 'xlsx':
        // Would integrate with a library like ExcelJS
        throw new Error('XLSX export not implemented');

      case 'pdf':
        // Would integrate with a PDF library
        throw new Error('PDF export not implemented');

      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Calculate account balances for trial balance
   */
  private async calculateAccountBalances(
    account: ChartAccount,
    period: AccountingPeriod,
    asOfDate: number,
    businessId: string
  ): Promise<{
    openingDebit: number;
    openingCredit: number;
    periodDebit: number;
    periodCredit: number;
    closingDebit: number;
    closingCredit: number;
  }> {
    // Get opening balance (from previous periods)
    const openingBalanceResult = await this.db.prepare(`
      SELECT
        SUM(CASE WHEN jl.base_debit > jl.base_credit THEN jl.base_debit - jl.base_credit ELSE 0 END) as opening_debit,
        SUM(CASE WHEN jl.base_credit > jl.base_debit THEN jl.base_credit - jl.base_debit ELSE 0 END) as opening_credit
      FROM journal_lines jl
      JOIN journal_entries je ON jl.journal_entry_id = je.id
      WHERE jl.account_id = ?
      AND je.business_id = ?
      AND je.status = 'POSTED'
      AND je.date < ?
    `).bind(account.id, businessId, period.startDate).first();

    const openingDebit = (openingBalanceResult?.opening_debit as number) || 0;
    const openingCredit = (openingBalanceResult?.opening_credit as number) || 0;

    // Get period activity
    const periodActivityResult = await this.db.prepare(`
      SELECT
        SUM(jl.base_debit) as period_debit,
        SUM(jl.base_credit) as period_credit
      FROM journal_lines jl
      JOIN journal_entries je ON jl.journal_entry_id = je.id
      WHERE jl.account_id = ?
      AND je.business_id = ?
      AND je.status = 'POSTED'
      AND je.date >= ? AND je.date <= ?
    `).bind(account.id, businessId, period.startDate, asOfDate).first();

    const periodDebit = (periodActivityResult?.period_debit as number) || 0;
    const periodCredit = (periodActivityResult?.period_credit as number) || 0;

    // Calculate closing balances
    const totalDebit = openingDebit + periodDebit;
    const totalCredit = openingCredit + periodCredit;

    let closingDebit = 0;
    let closingCredit = 0;

    if (totalDebit > totalCredit) {
      closingDebit = totalDebit - totalCredit;
    } else if (totalCredit > totalDebit) {
      closingCredit = totalCredit - totalDebit;
    }

    return {
      openingDebit,
      openingCredit,
      periodDebit,
      periodCredit,
      closingDebit,
      closingCredit
    };
  }

  /**
   * Get adjustment amounts from journal entry
   */
  private async getAdjustmentAmounts(
    entryId: string,
    businessId: string
  ): Promise<Map<string, { debit: number; credit: number }>> {
    const result = await this.db.prepare(`
      SELECT jl.account_id, jl.base_debit, jl.base_credit
      FROM journal_lines jl
      JOIN journal_entries je ON jl.journal_entry_id = je.id
      WHERE je.id = ?
      AND je.business_id = ?
      AND je.status = 'POSTED'
    `).bind(entryId, businessId).all();

    const adjustmentMap = new Map<string, { debit: number; credit: number }>();

    for (const row of result.results || []) {
      const accountId = row.account_id as string;
      const existing = adjustmentMap.get(accountId) || { debit: 0, credit: 0 };
      existing.debit += (row.base_debit as number) || 0;
      existing.credit += (row.base_credit as number) || 0;
      adjustmentMap.set(accountId, existing);
    }

    return adjustmentMap;
  }

  /**
   * Get account type order for sorting
   */
  private getAccountTypeOrder(accountType: AccountType): number {
    const order = {
      [AccountType.ASSET]: 1,
      [AccountType.CONTRA_ASSET]: 2,
      [AccountType.LIABILITY]: 3,
      [AccountType.CONTRA_LIABILITY]: 4,
      [AccountType.EQUITY]: 5,
      [AccountType.CONTRA_EQUITY]: 6,
      [AccountType.REVENUE]: 7,
      [AccountType.CONTRA_REVENUE]: 8,
      [AccountType.EXPENSE]: 9,
      [AccountType.CONTRA_EXPENSE]: 10
    };

    return order[accountType] || 999;
  }

  /**
   * Check if account normally has debit balance
   */
  private isNormalDebitAccount(accountType: AccountType): boolean {
    return [
      AccountType.ASSET,
      AccountType.EXPENSE,
      AccountType.CONTRA_LIABILITY,
      AccountType.CONTRA_EQUITY,
      AccountType.CONTRA_REVENUE
    ].includes(accountType);
  }

  /**
   * Generate CSV export
   */
  private generateCSV(trialBalance: TrialBalance): string {
    const headers = [
      'Account Code',
      'Account Name',
      'Account Type',
      'Opening Debit',
      'Opening Credit',
      'Period Debit',
      'Period Credit',
      'Closing Debit',
      'Closing Credit'
    ];

    const rows = [headers.join(',')];

    for (const account of trialBalance.accounts) {
      const row = [
        account.accountCode,
        `"${account.accountName}"`,
        account.accountType,
        account.openingDebit.toFixed(2),
        account.openingCredit.toFixed(2),
        account.periodDebit.toFixed(2),
        account.periodCredit.toFixed(2),
        account.closingDebit.toFixed(2),
        account.closingCredit.toFixed(2)
      ];
      rows.push(row.join(','));
    }

    // Add totals row
    rows.push('');
    rows.push([
      'TOTALS',
      '',
      '',
      '',
      '',
      '',
      '',
      trialBalance.totalDebits.toFixed(2),
      trialBalance.totalCredits.toFixed(2)
    ].join(','));

    // Add balance check
    rows.push('');
    rows.push([
      'BALANCE CHECK',
      trialBalance.isBalanced ? 'BALANCED' : 'OUT OF BALANCE',
      '',
      '',
      '',
      '',
      '',
      '',
      Math.abs(trialBalance.totalDebits - trialBalance.totalCredits).toFixed(2)
    ].join(','));

    return rows.join('\n');
  }
}