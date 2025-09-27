/**
 * Balance Sheet Generator
 * Generates balance sheets with account rollups and hierarchical structure
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  BalanceSheet,
  BalanceSheetComparison,
  AssetSection,
  LiabilitySection,
  EquitySection,
  ReportParameters,
  ReportInfo,
  ReportSection,
  ReportLine,
  AccountType,
  AccountCategory,
  ChartAccount
} from './types';
import { validateBusinessId, roundToCurrency, formatDate } from './utils';
import { CurrencyManager } from './currency-manager';

export class BalanceSheetGenerator {
  private logger: Logger;
  private db: D1Database;
  private currencyManager: CurrencyManager;

  constructor(db: D1Database, currencyManager: CurrencyManager) {
    this.logger = new Logger();
    this.db = db;
    this.currencyManager = currencyManager;
  }

  /**
   * Generate Balance Sheet
   */
  async generateBalanceSheet(
    parameters: ReportParameters,
    businessId: string,
    businessName: string = 'Business'
  ): Promise<BalanceSheet> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      this.logger.info('Generating Balance Sheet', {
        asOfDate: parameters.endDate,
        businessId: validBusinessId
      });

      // Get base currency for business
      const baseCurrency = await this.currencyManager.getBaseCurrency(validBusinessId);

      // Generate report info
      const reportInfo = this.createReportInfo(parameters, businessName, baseCurrency);

      // Get account balances as of the end date
      const accountBalances = await this.getBalanceSheetAccountBalances(parameters, validBusinessId, baseCurrency);

      // Build balance sheet sections
      const assets = await this.buildAssetSection(accountBalances, parameters);
      const liabilities = await this.buildLiabilitySection(accountBalances, parameters);
      const equity = await this.buildEquitySection(accountBalances, parameters, assets.totalAssets.amount);

      // Calculate totals
      const totalAssets = assets.totalAssets;
      const totalLiabilitiesAndEquity: ReportLine = {
        description: 'Total Liabilities and Equity',
        amount: roundToCurrency(liabilities.totalLiabilities.amount + equity.totalEquity.amount),
        level: 0,
        isTotal: true
      };

      // Check if balance sheet balances
      const isBalanced = Math.abs(totalAssets.amount - totalLiabilitiesAndEquity.amount) < 0.01;

      // Generate comparison if requested
      let comparison: BalanceSheetComparison | undefined;
      if (parameters.comparisonPeriod) {
       
  comparison = await this.generateComparison(parameters, validBusinessId, baseCurrency, totalAssets.amount, liabilities.totalLiabilities.amount, equity.totalEquity.amount);
      }

      const balanceSheet: BalanceSheet = {
        reportInfo,
        assets,
        liabilities,
        equity,
        totalAssets,
        totalLiabilitiesAndEquity,
        isBalanced,
        comparison
      };

      this.logger.info('Balance Sheet generated successfully', {
        totalAssets: totalAssets.amount,
        totalLiabilities: liabilities.totalLiabilities.amount,
        totalEquity: equity.totalEquity.amount,
        isBalanced,
        businessId: validBusinessId
      });

      return balanceSheet;

    } catch (error: any) {
      this.logger.error('Failed to generate Balance Sheet', error, {
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Create report information header
   */
  private createReportInfo(parameters: ReportParameters, businessName: string, baseCurrency: string): ReportInfo {
    return {
      title: 'Balance Sheet',
      subtitle: 'Statement of Financial Position',
      businessName,
      periodDescription: `As of ${formatDate(parameters.endDate)}`,
      startDate: parameters.startDate,
      endDate: parameters.endDate,
      generatedAt: Date.now(),
      currency: parameters.currency || baseCurrency
    };
  }

  /**
   * Get account balances for balance sheet (cumulative as of end date)
   */
  private async getBalanceSheetAccountBalances(
    parameters: ReportParameters,
    businessId: string,
    baseCurrency: string
  ): Promise<Map<string, { account: ChartAccount; balance: number }>> {
    const result = await this.db.prepare(`
      SELECT
        coa.id,
        coa.code,
        coa.name,
        coa.type,
        coa.category,
        coa.parent_id,
        coa.normal_balance,
        COALESCE(SUM(
          CASE
            WHEN je.date <= ? AND je.status = 'POSTED'
            THEN jl.base_debit - jl.base_credit
            ELSE 0
          END
        ), 0) as cumulative_balance
      FROM chart_of_accounts coa
      LEFT JOIN journal_lines jl ON coa.id = jl.account_id
      LEFT JOIN journal_entries je ON jl.journal_entry_id = je.id
      WHERE coa.business_id = ?
      AND coa.is_active = 1
      AND coa.type IN ('ASSET', 'LIABILITY', 'EQUITY', 'CONTRA_ASSET', 'CONTRA_LIABILITY', 'CONTRA_EQUITY')
      ${parameters.accountIds ? `AND coa.id IN (${parameters.accountIds.map(() => '?').join(',')})` : ''}
      GROUP BY coa.id, coa.code, coa.name, coa.type, coa.category, coa.parent_id, coa.normal_balance
      ${parameters.includeZeroBalances ? '' : 'HAVING cumulative_balance != 0'}
      ORDER BY coa.code
    `).bind(
      parameters.endDate,
      businessId,
      ...(parameters.accountIds || [])
    ).all();

    const balances = new Map<string, { account: ChartAccount; balance: number }>();

    for (const row of result.results || []) {
      const account: ChartAccount = {
        id: row.id as string,
        code: row.code as string,
        name: row.name as string,
        type: row.type as AccountType,
        category: row.category as AccountCategory,
        parentId: row.parent_id as string || undefined,
        normalBalance: row.normal_balance as 'debit' | 'credit',
        currency: baseCurrency,
        isActive: true,
        isSystemAccount: false,
        isReconcilable: false,
        isCashAccount: false,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        businessId
      };

      let balance = row.cumulative_balance as number;

      // Adjust balance based on normal balance and account type
      if (account.type ===
  AccountType.ASSET || account.type === AccountType.CONTRA_LIABILITY || account.type === AccountType.CONTRA_EQUITY) {
        // Asset accounts: debit balance is positive
        balance = account.normalBalance === 'debit' ? balance : -balance;
      } else if (account.type
  === AccountType.LIABILITY || account.type === AccountType.EQUITY || account.type === AccountType.CONTRA_ASSET) {
        // Liability and Equity accounts: credit balance is positive
        balance = account.normalBalance === 'credit' ? -balance : balance;
      }

      balances.set(account.id, { account, balance: roundToCurrency(balance) });
    }

    return balances;
  }

  /**
   * Build assets section with rollups
   */
  private async buildAssetSection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    parameters: ReportParameters
  ): Promise<AssetSection> {
    // Current Assets
    const currentAssets = this.buildAccountSection(
      accountBalances,
      'Current Assets',
      (account) => account.type === AccountType.ASSET && account.category === AccountCategory.CURRENT_ASSET
    );

    // Fixed Assets
    const fixedAssets = this.buildAccountSection(
      accountBalances,
      'Fixed Assets',
      (account) => account.type === AccountType.ASSET && account.category === AccountCategory.FIXED_ASSET
    );

    // Intangible Assets
    const intangibleAssets = this.buildAccountSection(
      accountBalances,
      'Intangible Assets',
      (account) => account.type === AccountType.ASSET && account.category === AccountCategory.INTANGIBLE_ASSET
    );

    // Other Assets
    const otherAssets = this.buildAccountSection(
      accountBalances,
      'Other Assets',
      (account) => account.type === AccountType.ASSET && account.category === AccountCategory.INVESTMENT
    );

    // Total Assets
    const totalAssetsAmount = currentAssets.subtotal.amount + fixedAssets.subtotal.amount +
                             intangibleAssets.subtotal.amount + otherAssets.subtotal.amount;

    const totalAssets: ReportLine = {
      description: 'Total Assets',
      amount: roundToCurrency(totalAssetsAmount),
      level: 0,
      isTotal: true
    };

    return {
      currentAssets,
      fixedAssets,
      intangibleAssets,
      otherAssets,
      totalAssets
    };
  }

  /**
   * Build liabilities section
   */
  private async buildLiabilitySection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    parameters: ReportParameters
  ): Promise<LiabilitySection> {
    // Current Liabilities
    const currentLiabilities = this.buildAccountSection(
      accountBalances,
      'Current Liabilities',
      (account) => account.type === AccountType.LIABILITY && account.category === AccountCategory.CURRENT_LIABILITY
    );

    // Long-term Liabilities
    const longTermLiabilities = this.buildAccountSection(
      accountBalances,
      'Long-term Liabilities',
      (account) => account.type === AccountType.LIABILITY && account.category === AccountCategory.LONG_TERM_LIABILITY
    );

    // Total Liabilities
    const totalLiabilitiesAmount = currentLiabilities.subtotal.amount + longTermLiabilities.subtotal.amount;

    const totalLiabilities: ReportLine = {
      description: 'Total Liabilities',
      amount: roundToCurrency(totalLiabilitiesAmount),
      level: 0,
      isSubtotal: true
    };

    return {
      currentLiabilities,
      longTermLiabilities,
      totalLiabilities
    };
  }

  /**
   * Build equity section
   */
  private async buildEquitySection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    parameters: ReportParameters,
    totalAssets: number
  ): Promise<EquitySection> {
    // Owner's Equity
    const ownersEquity = this.buildAccountSection(
      accountBalances,
      "Owner's Equity",
      (account) => account.type === AccountType.EQUITY && account.category === AccountCategory.OWNERS_EQUITY
    );

    // Get retained earnings (calculated or from specific account)
    let retainedEarningsAmount = 0;
    for (const [accountId, { account, balance }] of accountBalances) {
      if (account.category === AccountCategory.RETAINED_EARNINGS) {
        retainedEarningsAmount += balance;
      }
    }

    const retainedEarnings: ReportLine = {
      description: 'Retained Earnings',
      amount: roundToCurrency(retainedEarningsAmount),
      level: 1
    };

    // Total Equity
    const totalEquityAmount = ownersEquity.subtotal.amount + retainedEarningsAmount;

    const totalEquity: ReportLine = {
      description: 'Total Equity',
      amount: roundToCurrency(totalEquityAmount),
      level: 0,
      isSubtotal: true
    };

    return {
      ownersEquity,
      retainedEarnings,
      totalEquity
    };
  }

  /**
   * Build a generic account section with rollups
   */
  private buildAccountSection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    title: string,
    filter: (account: ChartAccount) => boolean
  ): ReportSection {
    const accounts: ReportLine[] = [];
    let totalAmount = 0;

    // Group accounts by parent
    const accountsByParent = new Map<string | undefined, Array<{ account: ChartAccount; balance: number }>>();

    for (const [accountId, { account, balance }] of accountBalances) {
      if (filter(account)) {
        const parentId = account.parentId;
        if (!accountsByParent.has(parentId)) {
          accountsByParent.set(parentId, []);
        }
        accountsByParent.get(parentId)!.push({ account, balance });
        totalAmount += balance;
      }
    }

    // Build hierarchical structure
    if (accountsByParent.has(undefined)) {
      // Top-level accounts (no parent)
      const topLevelAccounts = accountsByParent.get(undefined)!;
      topLevelAccounts.sort((a, b) => a.account.code.localeCompare(b.account.code));

      for (const { account, balance } of topLevelAccounts) {
        accounts.push({
          id: account.id,
          accountId: account.id,
          accountCode: account.code,
          accountName: account.name,
          description: account.name,
          amount: balance,
          level: 1
        });

        // Add child accounts if consolidation is not enabled
        const children = accountsByParent.get(account.id);
        if (children && children.length > 0) {
          children.sort((a, b) => a.account.code.localeCompare(b.account.code));
          for (const { account: childAccount, balance: childBalance } of children) {
            accounts.push({
              id: childAccount.id,
              accountId: childAccount.id,
              accountCode: childAccount.code,
              accountName: childAccount.name,
              description: childAccount.name,
              amount: childBalance,
              level: 2,
              parentId: account.id
            });
          }
        }
      }
    }

    // Add orphaned child accounts (parent not found in this section)
    for (const [parentId, children] of accountsByParent) {
      if (parentId && !accountBalances.has(parentId)) {
        children.sort((a, b) => a.account.code.localeCompare(b.account.code));
        for (const { account, balance } of children) {
          accounts.push({
            id: account.id,
            accountId: account.id,
            accountCode: account.code,
            accountName: account.name,
            description: account.name,
            amount: balance,
            level: 1
          });
        }
      }
    }

    return {
      title,
      accounts,
      subtotal: {
        description: `Total ${title}`,
        amount: roundToCurrency(totalAmount),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Generate comparison with previous period
   */
  private async generateComparison(
    parameters: ReportParameters,
    businessId: string,
    baseCurrency: string,
    currentAssets: number,
    currentLiabilities: number,
    currentEquity: number
  ): Promise<BalanceSheetComparison> {
    if (!parameters.comparisonPeriod) {
      throw new Error('Comparison period not specified');
    }

    try {
      // Generate balance sheet for comparison period
      const comparisonParameters: ReportParameters = {
        ...parameters,
        endDate: parameters.comparisonPeriod.endDate,
        comparisonPeriod: undefined // Avoid recursive comparison
      };

     
  const comparisonBalances = await this.getBalanceSheetAccountBalances(comparisonParameters, businessId, baseCurrency);

      // Calculate previous period totals
      let previousAssets = 0;
      let previousLiabilities = 0;
      let previousEquity = 0;

      for (const [accountId, { account, balance }] of comparisonBalances) {
        switch (account.type) {
          case AccountType.ASSET:
            previousAssets += balance;
            break;
          case AccountType.LIABILITY:
            previousLiabilities += balance;
            break;
          case AccountType.EQUITY:
            previousEquity += balance;
            break;
          case AccountType.CONTRA_ASSET:
            previousAssets -= balance;
            break;
          case AccountType.CONTRA_LIABILITY:
            previousLiabilities -= balance;
            break;
          case AccountType.CONTRA_EQUITY:
            previousEquity -= balance;
            break;
        }
      }

      const assetChange = currentAssets - previousAssets;
      const liabilityChange = currentLiabilities - previousLiabilities;
      const equityChange = currentEquity - previousEquity;

      return {
        previousPeriod: {
          totalAssets: roundToCurrency(previousAssets),
          totalLiabilities: roundToCurrency(previousLiabilities),
          totalEquity: roundToCurrency(previousEquity),
          assetChange: roundToCurrency(assetChange),
          liabilityChange: roundToCurrency(liabilityChange),
          equityChange: roundToCurrency(equityChange)
        }
      };

    } catch (error: any) {
      this.logger.error('Failed to generate Balance Sheet comparison', error, { businessId });
      throw error;
    }
  }

  /**
   * Calculate financial ratios
   */
  calculateFinancialRatios(balanceSheet: BalanceSheet): {
    currentRatio: number;
    quickRatio: number;
    debtToEquityRatio: number;
    debtToAssetsRatio: number;
    equityRatio: number;
  } {
    const currentAssets = balanceSheet.assets.currentAssets.subtotal.amount;
    const currentLiabilities = balanceSheet.liabilities.currentLiabilities.subtotal.amount;
    const totalAssets = balanceSheet.totalAssets.amount;
    const totalLiabilities = balanceSheet.liabilities.totalLiabilities.amount;
    const totalEquity = balanceSheet.equity.totalEquity.amount;

    // Current Ratio = Current Assets / Current Liabilities
    const currentRatio = currentLiabilities !== 0 ? currentAssets / currentLiabilities : 0;

    // Quick Ratio (simplified - assumes current assets without inventory)
    const quickRatio = currentLiabilities !== 0 ? currentAssets / currentLiabilities : 0;

    // Debt-to-Equity Ratio = Total Liabilities / Total Equity
    const debtToEquityRatio = totalEquity !== 0 ? totalLiabilities / totalEquity : 0;

    // Debt-to-Assets Ratio = Total Liabilities / Total Assets
    const debtToAssetsRatio = totalAssets !== 0 ? totalLiabilities / totalAssets : 0;

    // Equity Ratio = Total Equity / Total Assets
    const equityRatio = totalAssets !== 0 ? totalEquity / totalAssets : 0;

    return {
      currentRatio: Math.round(currentRatio * 100) / 100,
      quickRatio: Math.round(quickRatio * 100) / 100,
      debtToEquityRatio: Math.round(debtToEquityRatio * 100) / 100,
      debtToAssetsRatio: Math.round(debtToAssetsRatio * 100) / 100,
      equityRatio: Math.round(equityRatio * 100) / 100
    };
  }
}