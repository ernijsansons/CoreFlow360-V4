/**
 * Cash Flow Statement Generator
 * Generates cash flow statements using indirect method
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  CashFlowStatement,
  CashFlowSection,
  CashFlowComparison,
  ReportParameters,
  ReportInfo,
  ReportLine,
  AccountType,
  AccountCategory,
  ChartAccount
} from './types';
import { validateBusinessId, roundToCurrency, formatDate } from './utils';

export interface CashFlowAccount {
  account: ChartAccount;
  beginningBalance: number;
  endingBalance: number;
  change: number;
}

export class CashFlowGenerator {
  private logger: Logger;
  private db: D1Database;

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  /**
   * Generate Cash Flow Statement using indirect method
   */
  async generateCashFlowStatement(
    parameters: ReportParameters,
    businessId: string,
    businessName: string = 'Business'
  ): Promise<CashFlowStatement> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      this.logger.info('Generating Cash Flow Statement', {
        startDate: parameters.startDate,
        endDate: parameters.endDate,
        businessId: validBusinessId
      });

      // Generate report info
      const reportInfo = this.createReportInfo(parameters, businessName);

      // Get net income from P&L
      const netIncome = await this.getNetIncome(parameters, validBusinessId);

      // Get account balance changes for the period
      const accountChanges = await this.getAccountBalanceChanges(parameters, validBusinessId);

      // Build cash flow sections
      const operatingActivities = await this.buildOperatingActivitiesSection(
        netIncome,
        accountChanges,
        parameters
      );

      const investingActivities = await this.buildInvestingActivitiesSection(
        accountChanges,
        parameters
      );

      const financingActivities = await this.buildFinancingActivitiesSection(
        accountChanges,
        parameters
      );

      // Calculate net cash flow
      const netCashFlow: ReportLine = {
        description: 'Net Change in Cash',
        amount: roundToCurrency(
          operatingActivities.subtotal.amount +
          investingActivities.subtotal.amount +
          financingActivities.subtotal.amount
        ),
        level: 0,
        isTotal: true
      };

      // Get beginning and ending cash balances
      const { beginningCash, endingCash } = await this.getCashBalances(parameters, validBusinessId);

      // Generate comparison if requested
      let comparison: CashFlowComparison | undefined;
      if (parameters.comparisonPeriod) {
        comparison = await this.generateComparison(parameters, validBusinessId);
      }

      const statement: CashFlowStatement = {
        reportInfo,
        operatingActivities,
        investingActivities,
        financingActivities,
        netCashFlow,
        beginningCash,
        endingCash,
        comparison
      };

      this.logger.info('Cash Flow Statement generated successfully', {
        netCashFlow: netCashFlow.amount,
        operatingCashFlow: operatingActivities.subtotal.amount,
        investingCashFlow: investingActivities.subtotal.amount,
        financingCashFlow: financingActivities.subtotal.amount,
        businessId: validBusinessId
      });

      return statement;

    } catch (error: any) {
      this.logger.error('Failed to generate Cash Flow Statement', error, {
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Create report information header
   */
  private createReportInfo(parameters: ReportParameters, businessName: string): ReportInfo {
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
      title: 'Cash Flow Statement',
      subtitle: 'Statement of Cash Flows (Indirect Method)',
      businessName,
      periodDescription,
      startDate: parameters.startDate,
      endDate: parameters.endDate,
      generatedAt: Date.now(),
      currency: parameters.currency || 'USD'
    };
  }

  /**
   * Get net income for the period
   */
  private async getNetIncome(parameters: ReportParameters, businessId: string): Promise<number> {
    const result = await this.db.prepare(`
      SELECT
        COALESCE(SUM(
          CASE
            WHEN coa.type = 'REVENUE' THEN -(jl.base_debit - jl.base_credit)
            WHEN coa.type = 'EXPENSE' OR coa.category = 'COST_OF_GOODS_SOLD' OR coa.category = 'TAX_EXPENSE'
            THEN (jl.base_debit - jl.base_credit)
            ELSE 0
          END
        ), 0) as net_income
      FROM journal_lines jl
      INNER JOIN journal_entries je ON jl.journal_entry_id = je.id
      INNER JOIN chart_of_accounts coa ON jl.account_id = coa.id
      WHERE coa.business_id = ?
      AND je.date BETWEEN ? AND ?
      AND je.status = 'POSTED'
      AND (coa.type IN ('REVENUE', 'EXPENSE') OR coa.category IN ('COST_OF_GOODS_SOLD', 'TAX_EXPENSE'))
    `).bind(businessId, parameters.startDate, parameters.endDate).first();

    return roundToCurrency((result?.net_income as number) || 0);
  }

  /**
   * Get account balance changes between beginning and end of period
   */
  private async getAccountBalanceChanges(
    parameters: ReportParameters,
    businessId: string
  ): Promise<Map<string, CashFlowAccount>> {
    // Get beginning balances (day before start date)
    const beginningDate = parameters.startDate - (24 * 60 * 60 * 1000); // One day before start

    const result = await this.db.prepare(`
      SELECT
        coa.id,
        coa.code,
        coa.name,
        coa.type,
        coa.category,
        coa.normal_balance,
        coa.is_cash_account,
        COALESCE(SUM(
          CASE
            WHEN je.date <= ? AND je.status = 'POSTED'
            THEN jl.base_debit - jl.base_credit
            ELSE 0
          END
        ), 0) as beginning_balance,
        COALESCE(SUM(
          CASE
            WHEN je.date <= ? AND je.status = 'POSTED'
            THEN jl.base_debit - jl.base_credit
            ELSE 0
          END
        ), 0) as ending_balance
      FROM chart_of_accounts coa
      LEFT JOIN journal_lines jl ON coa.id = jl.account_id
      LEFT JOIN journal_entries je ON jl.journal_entry_id = je.id
      WHERE coa.business_id = ?
      AND coa.is_active = 1
      AND coa.type IN ('ASSET', 'LIABILITY', 'EQUITY')
      GROUP BY coa.id, coa.code, coa.name, coa.type, coa.category, coa.normal_balance, coa.is_cash_account
      HAVING beginning_balance != 0 OR ending_balance != 0
      ORDER BY coa.code
    `).bind(beginningDate, parameters.endDate, businessId).all();

    const changes = new Map<string, CashFlowAccount>();

    for (const row of result.results || []) {
      const account: ChartAccount = {
        id: row.id as string,
        code: row.code as string,
        name: row.name as string,
        type: row.type as AccountType,
        category: row.category as AccountCategory,
        normalBalance: row.normal_balance as 'debit' | 'credit',
        currency: 'USD',
        isActive: true,
        isSystemAccount: false,
        isReconcilable: false,
        isCashAccount: Boolean(row.is_cash_account),
        createdAt: Date.now(),
        updatedAt: Date.now(),
        businessId
      };

      let beginningBalance = row.beginning_balance as number;
      let endingBalance = row.ending_balance as number;

      // Adjust balances based on normal balance
      if (account.type === AccountType.ASSET) {
        beginningBalance = account.normalBalance === 'debit' ? beginningBalance : -beginningBalance;
        endingBalance = account.normalBalance === 'debit' ? endingBalance : -endingBalance;
      } else if (account.type === AccountType.LIABILITY || account.type === AccountType.EQUITY) {
        beginningBalance = account.normalBalance === 'credit' ? -beginningBalance : beginningBalance;
        endingBalance = account.normalBalance === 'credit' ? -endingBalance : endingBalance;
      }

      const change = endingBalance - beginningBalance;

      changes.set(account.id, {
        account,
        beginningBalance: roundToCurrency(beginningBalance),
        endingBalance: roundToCurrency(endingBalance),
        change: roundToCurrency(change)
      });
    }

    return changes;
  }

  /**
   * Build operating activities section (indirect method)
   */
  private async buildOperatingActivitiesSection(
    netIncome: number,
    accountChanges: Map<string, CashFlowAccount>,
    parameters: ReportParameters
  ): Promise<CashFlowSection> {
    const items: ReportLine[] = [];

    // Start with net income
    items.push({
      description: 'Net Income',
      amount: netIncome,
      level: 1
    });

    // Adjustments for non-cash items
    items.push({
      description: 'Adjustments to reconcile net income to cash:',
      amount: 0,
      level: 1
    });

    // Depreciation and amortization (would need to be tracked separately)
    // For now, we'll estimate based on account changes

    let totalAdjustments = 0;

    // Changes in current assets and liabilities
    for (const [accountId, { account, change }] of accountChanges) {
      if (account.type
  === AccountType.ASSET && account.category === AccountCategory.CURRENT_ASSET && !account.isCashAccount) {
        // Increase in current assets reduces cash flow
        if (Math.abs(change) > 0.01) {
          items.push({
            description: `${change > 0 ? 'Increase' : 'Decrease'} in ${account.name}`,
            amount: -change,
            level: 2
          });
          totalAdjustments -= change;
        }
      } else if (account.type === AccountType.LIABILITY && account.category === AccountCategory.CURRENT_LIABILITY) {
        // Increase in current liabilities increases cash flow
        if (Math.abs(change) > 0.01) {
          items.push({
            description: `${change > 0 ? 'Increase' : 'Decrease'} in ${account.name}`,
            amount: change,
            level: 2
          });
          totalAdjustments += change;
        }
      }
    }

    const operatingCashFlow = netIncome + totalAdjustments;

    return {
      title: 'Cash Flows from Operating Activities',
      items,
      subtotal: {
        description: 'Net Cash Provided by Operating Activities',
        amount: roundToCurrency(operatingCashFlow),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Build investing activities section
   */
  private async buildInvestingActivitiesSection(
    accountChanges: Map<string, CashFlowAccount>,
    parameters: ReportParameters
  ): Promise<CashFlowSection> {
    const items: ReportLine[] = [];
    let totalInvestingCashFlow = 0;

    // Changes in fixed assets and investments
    for (const [accountId, { account, change }] of accountChanges) {
      if (account.type === AccountType.ASSET &&
          (account.category === AccountCategory.FIXED_ASSET ||
           account.category === AccountCategory.INVESTMENT ||
           account.category === AccountCategory.INTANGIBLE_ASSET)) {

        if (Math.abs(change) > 0.01) {
          let description: string;
          let amount: number;

          if (change > 0) {
            // Increase in fixed assets = cash outflow (purchase)
            description = `Purchase of ${account.name}`;
            amount = -change;
          } else {
            // Decrease in fixed assets = cash inflow (sale)
            description = `Sale of ${account.name}`;
            amount = -change;
          }

          items.push({
            description,
            amount,
            level: 1
          });
          totalInvestingCashFlow += amount;
        }
      }
    }

    // If no investing activities, add a placeholder
    if (items.length === 0) {
      items.push({
        description: 'No investing activities',
        amount: 0,
        level: 1
      });
    }

    return {
      title: 'Cash Flows from Investing Activities',
      items,
      subtotal: {
        description: 'Net Cash Used in Investing Activities',
        amount: roundToCurrency(totalInvestingCashFlow),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Build financing activities section
   */
  private async buildFinancingActivitiesSection(
    accountChanges: Map<string, CashFlowAccount>,
    parameters: ReportParameters
  ): Promise<CashFlowSection> {
    const items: ReportLine[] = [];
    let totalFinancingCashFlow = 0;

    // Changes in long-term liabilities and equity
    for (const [accountId, { account, change }] of accountChanges) {
      if ((account.type === AccountType.LIABILITY && account.category === AccountCategory.LONG_TERM_LIABILITY) ||
          account.type === AccountType.EQUITY) {

        if (Math.abs(change) > 0.01) {
          let description: string;
          let amount: number;

          if (account.type === AccountType.LIABILITY) {
            if (change > 0) {
              description = `Proceeds from ${account.name}`;
              amount = change;
            } else {
              description = `Repayment of ${account.name}`;
              amount = change;
            }
          } else { // Equity
            if (change > 0) {
              description = `Issuance of ${account.name}`;
              amount = change;
            } else {
              description = `Payment of ${account.name}`;
              amount = change;
            }
          }

          items.push({
            description,
            amount,
            level: 1
          });
          totalFinancingCashFlow += amount;
        }
      }
    }

    // If no financing activities, add a placeholder
    if (items.length === 0) {
      items.push({
        description: 'No financing activities',
        amount: 0,
        level: 1
      });
    }

    return {
      title: 'Cash Flows from Financing Activities',
      items,
      subtotal: {
        description: 'Net Cash Provided by Financing Activities',
        amount: roundToCurrency(totalFinancingCashFlow),
        level: 0,
        isSubtotal: true
      }
    };
  }

  /**
   * Get beginning and ending cash balances
   */
  private async getCashBalances(
    parameters: ReportParameters,
    businessId: string
  ): Promise<{ beginningCash: ReportLine; endingCash: ReportLine }> {
    const beginningDate = parameters.startDate - (24 * 60 * 60 * 1000); // One day before start

    const result = await this.db.prepare(`
      SELECT
        COALESCE(SUM(
          CASE
            WHEN je.date <= ? AND je.status = 'POSTED'
            THEN jl.base_debit - jl.base_credit
            ELSE 0
          END
        ), 0) as beginning_cash,
        COALESCE(SUM(
          CASE
            WHEN je.date <= ? AND je.status = 'POSTED'
            THEN jl.base_debit - jl.base_credit
            ELSE 0
          END
        ), 0) as ending_cash
      FROM chart_of_accounts coa
      LEFT JOIN journal_lines jl ON coa.id = jl.account_id
      LEFT JOIN journal_entries je ON jl.journal_entry_id = je.id
      WHERE coa.business_id = ?
      AND coa.is_active = 1
      AND coa.is_cash_account = 1
    `).bind(beginningDate, parameters.endDate, businessId).first();

    const beginningCash = roundToCurrency((result?.beginning_cash as number) || 0);
    const endingCash = roundToCurrency((result?.ending_cash as number) || 0);

    return {
      beginningCash: {
        description: 'Cash at Beginning of Period',
        amount: beginningCash,
        level: 0
      },
      endingCash: {
        description: 'Cash at End of Period',
        amount: endingCash,
        level: 0
      }
    };
  }

  /**
   * Generate comparison with previous period
   */
  private async generateComparison(
    parameters: ReportParameters,
    businessId: string
  ): Promise<CashFlowComparison> {
    if (!parameters.comparisonPeriod) {
      throw new Error('Comparison period not specified');
    }

    try {
      // Generate cash flow for comparison period
      const comparisonParameters: ReportParameters = {
        ...parameters,
        startDate: parameters.comparisonPeriod.startDate,
        endDate: parameters.comparisonPeriod.endDate,
        comparisonPeriod: undefined // Avoid recursive comparison
      };

      const comparisonStatement = await this.generateCashFlowStatement(
        comparisonParameters,
        businessId,
        'Comparison'
      );

      return {
        previousPeriod: {
          netCashFlow: comparisonStatement.netCashFlow.amount,
          operatingCashFlow: comparisonStatement.operatingActivities.subtotal.amount,
          investingCashFlow: comparisonStatement.investingActivities.subtotal.amount,
          financingCashFlow: comparisonStatement.financingActivities.subtotal.amount
        }
      };

    } catch (error: any) {
      this.logger.error('Failed to generate Cash Flow comparison', error, { businessId });
      throw error;
    }
  }

  /**
   * Calculate cash flow ratios
   */
  calculateCashFlowRatios(
    statement: CashFlowStatement,
    currentLiabilities: number,
    totalDebt: number
  ): {
    operatingCashFlowRatio: number;
    cashCoverageRatio: number;
    freeCashFlow: number;
  } {
    const operatingCashFlow = statement.operatingActivities.subtotal.amount;
    const investingCashFlow = statement.investingActivities.subtotal.amount;

    // Operating Cash Flow Ratio = Operating Cash Flow / Current Liabilities
    const operatingCashFlowRatio = currentLiabilities !== 0 ? operatingCashFlow / currentLiabilities : 0;

    // Cash Coverage Ratio = Operating Cash Flow / Total Debt
    const cashCoverageRatio = totalDebt !== 0 ? operatingCashFlow / totalDebt : 0;

    // Free Cash Flow = Operating Cash Flow - Capital Expenditures
    // Approximating capital expenditures as negative investing cash flow
    const capitalExpenditures = Math.min(0, investingCashFlow);
    const freeCashFlow = operatingCashFlow + capitalExpenditures;

    return {
      operatingCashFlowRatio: Math.round(operatingCashFlowRatio * 100) / 100,
      cashCoverageRatio: Math.round(cashCoverageRatio * 100) / 100,
      freeCashFlow: roundToCurrency(freeCashFlow)
    };
  }
}