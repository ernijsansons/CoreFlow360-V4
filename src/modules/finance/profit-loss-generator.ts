/**
 * Profit & Loss Statement Generator
 * Generates comprehensive income statements with comparison periods
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  ProfitLossStatement,
  ProfitLossComparison,
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

export class ProfitLossGenerator {
  private logger: Logger;
  private db: D1Database;
  private currencyManager: CurrencyManager;

  constructor(db: D1Database, currencyManager: CurrencyManager) {
    this.logger = new Logger();
    this.db = db;
    this.currencyManager = currencyManager;
  }

  /**
   * Generate Profit & Loss statement
   */
  async generateProfitLoss(
    parameters: ReportParameters,
    businessId: string,
    businessName: string = 'Business'
  ): Promise<ProfitLossStatement> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      this.logger.info('Generating Profit & Loss statement', {
        startDate: parameters.startDate,
        endDate: parameters.endDate,
        businessId: validBusinessId
      });

      // Get base currency for business
      const baseCurrency = await this.currencyManager.getBaseCurrency(validBusinessId);

      // Generate report info
      const reportInfo = this.createReportInfo(parameters, businessName, baseCurrency);

      // Get account balances for the period
      const accountBalances = await this.getAccountBalances(parameters, validBusinessId, baseCurrency);

      // Build report sections
      const revenue = await this.buildRevenueSection(accountBalances, parameters);
      const costOfGoodsSold = await this.buildCOGSSection(accountBalances, parameters);
      const operatingExpenses = await this.buildOperatingExpensesSection(accountBalances, parameters);
      const otherIncome = await this.buildOtherIncomeSection(accountBalances, parameters);
      const otherExpenses = await this.buildOtherExpensesSection(accountBalances, parameters);
      const taxes = await this.buildTaxesSection(accountBalances, parameters);

      // Calculate totals and subtotals
      const grossProfit = this.calculateGrossProfit(revenue, costOfGoodsSold);
      const operatingIncome = this.calculateOperatingIncome(grossProfit, operatingExpenses);
      const incomeBeforeTaxes = this.calculateIncomeBeforeTaxes(operatingIncome, otherIncome, otherExpenses);
      const netIncome = this.calculateNetIncome(incomeBeforeTaxes, taxes);

      // Generate comparison if requested
      let comparison: ProfitLossComparison | undefined;
      if (parameters.comparisonPeriod) {
        comparison = await this.generateComparison(parameters, validBusinessId, netIncome.amount);
      }

      const statement: ProfitLossStatement = {
        reportInfo,
        revenue,
        costOfGoodsSold,
        grossProfit,
        operatingExpenses,
        operatingIncome,
        otherIncome,
        otherExpenses,
        incomeBeforeTaxes,
        taxes,
        netIncome,
        comparison
      };

      this.logger.info('Profit & Loss statement generated successfully', {
        revenue: revenue.subtotal.amount,
        grossProfit: grossProfit.amount,
        operatingIncome: operatingIncome.amount,
        netIncome: netIncome.amount,
        businessId: validBusinessId
      });

      return statement;

    } catch (error) {
      this.logger.error('Failed to generate Profit & Loss statement', error, {
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Create report information header
   */
  private createReportInfo(parameters: ReportParameters, businessName: string, baseCurrency: string): ReportInfo {
    const startDate = new Date(parameters.startDate);
    const endDate = new Date(parameters.endDate);

    let periodDescription: string;
    if (parameters.periodType) {
      switch (parameters.periodType) {
        case 'MONTHLY':
          periodDescription = `Month Ended ${formatDate(parameters.endDate)}`;
          break;
        case 'QUARTERLY':
          periodDescription = `Quarter Ended ${formatDate(parameters.endDate)}`;
          break;
        case 'YEARLY':
          periodDescription = `Year Ended ${formatDate(parameters.endDate)}`;
          break;
        default:
          periodDescription = `${formatDate(parameters.startDate)} - ${formatDate(parameters.endDate)}`;
      }
    } else {
      periodDescription = `${formatDate(parameters.startDate)} - ${formatDate(parameters.endDate)}`;
    }

    return {
      title: 'Profit & Loss Statement',
      subtitle: 'Income Statement',
      businessName,
      periodDescription,
      startDate: parameters.startDate,
      endDate: parameters.endDate,
      generatedAt: Date.now(),
      currency: parameters.currency || baseCurrency
    };
  }

  /**
   * Get account balances for the specified period
   */
  private async getAccountBalances(
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
            WHEN je.date BETWEEN ? AND ? AND je.status = 'POSTED'
            THEN jl.base_debit - jl.base_credit
            ELSE 0
          END
        ), 0) as period_balance
      FROM chart_of_accounts coa
      LEFT JOIN journal_lines jl ON coa.id = jl.account_id
      LEFT JOIN journal_entries je ON jl.journal_entry_id = je.id
      WHERE coa.business_id = ?
      AND coa.is_active = 1
      AND (coa.type IN ('REVENUE', 'EXPENSE') OR coa.category IN ('COST_OF_GOODS_SOLD', 'TAX_EXPENSE'))
      ${parameters.accountIds ? `AND coa.id IN (${parameters.accountIds.map(() => '?').join(',')})` : ''}
      GROUP BY coa.id, coa.code, coa.name, coa.type, coa.category, coa.parent_id, coa.normal_balance
      ${parameters.includeZeroBalances ? '' : 'HAVING period_balance != 0'}
      ORDER BY coa.code
    `).bind(
      parameters.startDate,
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

      let balance = row.period_balance as number;

      // Adjust balance based on normal balance and account type
      if (account.type === AccountType.REVENUE || account.type === AccountType.CONTRA_EXPENSE) {
        // Revenue accounts: credit balance is positive
        balance = account.normalBalance === 'credit' ? -balance : balance;
      } else if (account.type === AccountType.EXPENSE || account.category === AccountCategory.COST_OF_GOODS_SOLD) {
        // Expense accounts: debit balance is positive
        balance = account.normalBalance === 'debit' ? balance : -balance;
      }

      balances.set(account.id, { account, balance: roundToCurrency(balance) });
    }

    return balances;
  }

  /**
   * Build revenue section
   */
  private async buildRevenueSection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    parameters: ReportParameters
  ): Promise<ReportSection> {
    const revenueAccounts: ReportLine[] = [];
    let totalRevenue = 0;

    for (const [accountId, { account, balance }] of accountBalances) {
      if (account.type === AccountType.REVENUE && account.category === AccountCategory.OPERATING_REVENUE) {
        revenueAccounts.push({
          id: accountId,
          accountId,
          accountCode: account.code,
          accountName: account.name,
          description: account.name,
          amount: balance,
          level: 1
        });
        totalRevenue += balance;
      }
    }

    // Sort by account code
    revenueAccounts.sort((a, b) => (a.accountCode || '').localeCompare(b.accountCode || ''));

    return {
      title: 'Revenue',
      accounts: revenueAccounts,
      subtotal: {
        description: 'Total Revenue',
        amount: roundToCurrency(totalRevenue),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Build Cost of Goods Sold section
   */
  private async buildCOGSSection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    parameters: ReportParameters
  ): Promise<ReportSection> {
    const cogsAccounts: ReportLine[] = [];
    let totalCOGS = 0;

    for (const [accountId, { account, balance }] of accountBalances) {
      if (account.category === AccountCategory.COST_OF_GOODS_SOLD) {
        cogsAccounts.push({
          id: accountId,
          accountId,
          accountCode: account.code,
          accountName: account.name,
          description: account.name,
          amount: balance,
          level: 1
        });
        totalCOGS += balance;
      }
    }

    // Sort by account code
    cogsAccounts.sort((a, b) => (a.accountCode || '').localeCompare(b.accountCode || ''));

    return {
      title: 'Cost of Goods Sold',
      accounts: cogsAccounts,
      subtotal: {
        description: 'Total Cost of Goods Sold',
        amount: roundToCurrency(totalCOGS),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Build operating expenses section
   */
  private async buildOperatingExpensesSection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    parameters: ReportParameters
  ): Promise<ReportSection> {
    const expenseAccounts: ReportLine[] = [];
    let totalExpenses = 0;

    for (const [accountId, { account, balance }] of accountBalances) {
      if (account.type === AccountType.EXPENSE && account.category === AccountCategory.OPERATING_EXPENSE) {
        expenseAccounts.push({
          id: accountId,
          accountId,
          accountCode: account.code,
          accountName: account.name,
          description: account.name,
          amount: balance,
          level: 1
        });
        totalExpenses += balance;
      }
    }

    // Sort by account code
    expenseAccounts.sort((a, b) => (a.accountCode || '').localeCompare(b.accountCode || ''));

    return {
      title: 'Operating Expenses',
      accounts: expenseAccounts,
      subtotal: {
        description: 'Total Operating Expenses',
        amount: roundToCurrency(totalExpenses),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Build other income section
   */
  private async buildOtherIncomeSection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    parameters: ReportParameters
  ): Promise<ReportSection> {
    const incomeAccounts: ReportLine[] = [];
    let totalIncome = 0;

    for (const [accountId, { account, balance }] of accountBalances) {
      if (account.type === AccountType.REVENUE && account.category === AccountCategory.NON_OPERATING_REVENUE) {
        incomeAccounts.push({
          id: accountId,
          accountId,
          accountCode: account.code,
          accountName: account.name,
          description: account.name,
          amount: balance,
          level: 1
        });
        totalIncome += balance;
      }
    }

    // Sort by account code
    incomeAccounts.sort((a, b) => (a.accountCode || '').localeCompare(b.accountCode || ''));

    return {
      title: 'Other Income',
      accounts: incomeAccounts,
      subtotal: {
        description: 'Total Other Income',
        amount: roundToCurrency(totalIncome),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Build other expenses section
   */
  private async buildOtherExpensesSection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    parameters: ReportParameters
  ): Promise<ReportSection> {
    const expenseAccounts: ReportLine[] = [];
    let totalExpenses = 0;

    for (const [accountId, { account, balance }] of accountBalances) {
      if (account.type === AccountType.EXPENSE && account.category === AccountCategory.NON_OPERATING_EXPENSE) {
        expenseAccounts.push({
          id: accountId,
          accountId,
          accountCode: account.code,
          accountName: account.name,
          description: account.name,
          amount: balance,
          level: 1
        });
        totalExpenses += balance;
      }
    }

    // Sort by account code
    expenseAccounts.sort((a, b) => (a.accountCode || '').localeCompare(b.accountCode || ''));

    return {
      title: 'Other Expenses',
      accounts: expenseAccounts,
      subtotal: {
        description: 'Total Other Expenses',
        amount: roundToCurrency(totalExpenses),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Build taxes section
   */
  private async buildTaxesSection(
    accountBalances: Map<string, { account: ChartAccount; balance: number }>,
    parameters: ReportParameters
  ): Promise<ReportSection> {
    const taxAccounts: ReportLine[] = [];
    let totalTaxes = 0;

    for (const [accountId, { account, balance }] of accountBalances) {
      if (account.category === AccountCategory.TAX_EXPENSE) {
        taxAccounts.push({
          id: accountId,
          accountId,
          accountCode: account.code,
          accountName: account.name,
          description: account.name,
          amount: balance,
          level: 1
        });
        totalTaxes += balance;
      }
    }

    // Sort by account code
    taxAccounts.sort((a, b) => (a.accountCode || '').localeCompare(b.accountCode || ''));

    return {
      title: 'Taxes',
      accounts: taxAccounts,
      subtotal: {
        description: 'Total Taxes',
        amount: roundToCurrency(totalTaxes),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Calculate gross profit
   */
  private calculateGrossProfit(revenue: ReportSection, cogs: ReportSection): ReportLine {
    const grossProfit = revenue.subtotal.amount - cogs.subtotal.amount;
    return {
      description: 'Gross Profit',
      amount: roundToCurrency(grossProfit),
      level: 0,
      isSubtotal: true
    };
  }

  /**
   * Calculate operating income
   */
  private calculateOperatingIncome(grossProfit: ReportLine, operatingExpenses: ReportSection): ReportLine {
    const operatingIncome = grossProfit.amount - operatingExpenses.subtotal.amount;
    return {
      description: 'Operating Income',
      amount: roundToCurrency(operatingIncome),
      level: 0,
      isSubtotal: true
    };
  }

  /**
   * Calculate income before taxes
   */
  private calculateIncomeBeforeTaxes(
    operatingIncome: ReportLine,
    otherIncome: ReportSection,
    otherExpenses: ReportSection
  ): ReportLine {
    const incomeBeforeTaxes = operatingIncome.amount + otherIncome.subtotal.amount - otherExpenses.subtotal.amount;
    return {
      description: 'Income Before Taxes',
      amount: roundToCurrency(incomeBeforeTaxes),
      level: 0,
      isSubtotal: true
    };
  }

  /**
   * Calculate net income
   */
  private calculateNetIncome(incomeBeforeTaxes: ReportLine, taxes: ReportSection): ReportLine {
    const netIncome = incomeBeforeTaxes.amount - taxes.subtotal.amount;
    return {
      description: 'Net Income',
      amount: roundToCurrency(netIncome),
      level: 0,
      isTotal: true
    };
  }

  /**
   * Generate comparison with previous period
   */
  private async generateComparison(
    parameters: ReportParameters,
    businessId: string,
    currentNetIncome: number
  ): Promise<ProfitLossComparison> {
    if (!parameters.comparisonPeriod) {
      throw new Error('Comparison period not specified');
    }

    try {
      // Generate P&L for comparison period
      const comparisonParameters: ReportParameters = {
        ...parameters,
        startDate: parameters.comparisonPeriod.startDate,
        endDate: parameters.comparisonPeriod.endDate,
        comparisonPeriod: undefined // Avoid recursive comparison
      };

      const comparisonBalances = await this.getAccountBalances(comparisonParameters, businessId);

      // Calculate previous period net income
      let previousRevenue = 0;
      let previousCOGS = 0;
      let previousOperatingExpenses = 0;
      let previousOtherIncome = 0;
      let previousOtherExpenses = 0;
      let previousTaxes = 0;

      for (const [accountId, { account, balance }] of comparisonBalances) {
        switch (account.type) {
          case AccountType.REVENUE:
            if (account.category === AccountCategory.OPERATING_REVENUE) {
              previousRevenue += balance;
            } else if (account.category === AccountCategory.NON_OPERATING_REVENUE) {
              previousOtherIncome += balance;
            }
            break;
          case AccountType.EXPENSE:
            if (account.category === AccountCategory.OPERATING_EXPENSE) {
              previousOperatingExpenses += balance;
            } else if (account.category === AccountCategory.NON_OPERATING_EXPENSE) {
              previousOtherExpenses += balance;
            }
            break;
        }

        if (account.category === AccountCategory.COST_OF_GOODS_SOLD) {
          previousCOGS += balance;
        } else if (account.category === AccountCategory.TAX_EXPENSE) {
          previousTaxes += balance;
        }
      }

      const previousGrossProfit = previousRevenue - previousCOGS;
      const previousOperatingIncome = previousGrossProfit - previousOperatingExpenses;
      const previousIncomeBeforeTaxes = previousOperatingIncome + previousOtherIncome - previousOtherExpenses;
      const previousNetIncome = previousIncomeBeforeTaxes - previousTaxes;

      const changeAmount = currentNetIncome - previousNetIncome;
      const changePercentage = previousNetIncome !== 0 ? (changeAmount / Math.abs(previousNetIncome)) * 100 : 0;

      return {
        previousPeriod: {
          netIncome: roundToCurrency(previousNetIncome),
          changeAmount: roundToCurrency(changeAmount),
          changePercentage: Math.round(changePercentage * 100) / 100
        }
      };

    } catch (error) {
      this.logger.error('Failed to generate P&L comparison', error, { businessId });
      throw error;
    }
  }

  /**
   * Calculate profit margins and percentages
   */
  calculateProfitMargins(statement: ProfitLossStatement): {
    grossProfitMargin: number;
    operatingMargin: number;
    netProfitMargin: number;
  } {
    const totalRevenue = statement.revenue.subtotal.amount;

    const grossProfitMargin = totalRevenue !== 0 ? (statement.grossProfit.amount / totalRevenue) * 100 : 0;
    const operatingMargin = totalRevenue !== 0 ? (statement.operatingIncome.amount / totalRevenue) * 100 : 0;
    const netProfitMargin = totalRevenue !== 0 ? (statement.netIncome.amount / totalRevenue) * 100 : 0;

    return {
      grossProfitMargin: Math.round(grossProfitMargin * 100) / 100,
      operatingMargin: Math.round(operatingMargin * 100) / 100,
      netProfitMargin: Math.round(netProfitMargin * 100) / 100
    };
  }
}