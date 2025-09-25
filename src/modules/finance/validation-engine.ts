/**
 * Finance Validation Engine
 * Comprehensive validation rules for financial data integrity
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  ValidationRule,
  JournalEntry,
  ChartAccount,
  AccountingPeriod,
  AccountType
} from './types';
import { validateBusinessId } from './utils';

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

export interface ValidationError {
  code: string;
  message: string;
  field?: string;
  value?: any;
  severity: 'error' | 'warning';
}

export interface ValidationWarning {
  code: string;
  message: string;
  suggestion?: string;
}

export class FinanceValidationEngine {
  private logger: Logger;
  private db: D1Database;
  private rules = new Map<string, ValidationRule>();

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
    this.initializeStandardRules();
  }

  /**
   * Validate journal entry
   */
  async validateJournalEntry(
    journalEntry: JournalEntry,
    businessId: string
  ): Promise<ValidationResult> {
    const validBusinessId = validateBusinessId(businessId);
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Basic structure validation
    if (!journalEntry.description || journalEntry.description.trim().length === 0) {
      errors.push({
        code: 'MISSING_DESCRIPTION',
        message: 'Journal entry description is required',
        field: 'description',
        severity: 'error'
      });
    }

    if (!journalEntry.lines || journalEntry.lines.length === 0) {
      errors.push({
        code: 'NO_LINES',
        message: 'Journal entry must have at least one line',
        field: 'lines',
        severity: 'error'
      });
    } else if (journalEntry.lines.length === 1) {
      errors.push({
        code: 'SINGLE_LINE',
        message: 'Journal entry must have at least two lines for double-entry',
        field: 'lines',
        severity: 'error'
      });
    }

    // Date validation
    if (journalEntry.date > Date.now() + 86400000) { // More than 1 day in future
      warnings.push({
        code: 'FUTURE_DATE',
        message: 'Journal entry date is in the future',
        suggestion: 'Verify the entry date is correct'
      });
    }

    // Period validation
    if (journalEntry.periodId) {
      const period = await this.getPeriod(journalEntry.periodId, validBusinessId);
      if (period) {
        if (period.status === 'CLOSED') {
          errors.push({
            code: 'CLOSED_PERIOD',
            message: 'Cannot create entries in closed period',
            field: 'periodId',
            severity: 'error'
          });
        } else if (period.status === 'LOCKED') {
          errors.push({
            code: 'LOCKED_PERIOD',
            message: 'Cannot create entries in locked period',
            field: 'periodId',
            severity: 'error'
          });
        }

        // Check if date falls within period
        if (journalEntry.date < period.startDate || journalEntry.date > period.endDate) {
          errors.push({
            code: 'DATE_OUTSIDE_PERIOD',
            message: 'Journal entry date is outside the period range',
            field: 'date',
            severity: 'error'
          });
        }
      }
    }

    // Line-by-line validation
    let totalDebits = 0;
    let totalCredits = 0;
    const accountIds = new Set<string>();

    for (let i = 0; i < journalEntry.lines.length; i++) {
      const line = journalEntry.lines[i];
      const lineErrors = await this.validateJournalLine(line, i, validBusinessId);
      errors.push(...lineErrors);

      // Check for duplicate accounts
      if (accountIds.has(line.accountId)) {
        warnings.push({
          code: 'DUPLICATE_ACCOUNT',
          message: `Account ${line.accountCode} appears multiple times`,
          suggestion: 'Consider combining entries for the same account'
        });
      }
      accountIds.add(line.accountId);

      totalDebits += line.baseDebit;
      totalCredits += line.baseCredit;
    }

    // Balance validation
    const difference = Math.abs(totalDebits - totalCredits);
    if (difference > 0.01) {
      errors.push({
        code: 'UNBALANCED_ENTRY',
        message: `Journal entry is not balanced. Difference: ${difference.toFixed(2)}`,
        field: 'lines',
        value: { totalDebits, totalCredits, difference },
        severity: 'error'
      });
    }

    // Amount validation
    if (totalDebits === 0 && totalCredits === 0) {
      errors.push({
        code: 'ZERO_AMOUNT',
        message: 'Journal entry has no amounts',
        field: 'lines',
        severity: 'error'
      });
    }

    // Large amount warning
    const maxAmount = Math.max(totalDebits, totalCredits);
    if (maxAmount > 1000000) { // $1M threshold
      warnings.push({
        code: 'LARGE_AMOUNT',
        message: `Journal entry has unusually large amount: ${maxAmount.toFixed(2)}`,
        suggestion: 'Verify amounts are correct'
      });
    }

    // Apply custom validation rules
    const customValidation = await this.applyCustomRules(journalEntry, 'journal', validBusinessId);
    errors.push(...customValidation.errors);
    warnings.push(...customValidation.warnings);

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate journal line
   */
  private async validateJournalLine(
    line: any,
    index: number,
    businessId: string
  ): Promise<ValidationError[]> {
    const errors: ValidationError[] = [];

    // Account validation
    if (!line.accountId) {
      errors.push({
        code: 'MISSING_ACCOUNT',
        message: `Line ${index + 1}: Account is required`,
        field: `lines[${index}].accountId`,
        severity: 'error'
      });
    } else {
      const account = await this.getAccount(line.accountId, businessId);
      if (!account) {
        errors.push({
          code: 'INVALID_ACCOUNT',
          message: `Line ${index + 1}: Account not found`,
          field: `lines[${index}].accountId`,
          value: line.accountId,
          severity: 'error'
        });
      } else if (!account.isActive) {
        errors.push({
          code: 'INACTIVE_ACCOUNT',
          message: `Line ${index + 1}: Account is inactive`,
          field: `lines[${index}].accountId`,
          value: line.accountId,
          severity: 'error'
        });
      }
    }

    // Amount validation
    const debit = line.debit || 0;
    const credit = line.credit || 0;

    if (debit < 0 || credit < 0) {
      errors.push({
        code: 'NEGATIVE_AMOUNT',
        message: `Line ${index + 1}: Amounts cannot be negative`,
        field: `lines[${index}]`,
        severity: 'error'
      });
    }

    if ((debit > 0 && credit > 0) || (debit === 0 && credit === 0)) {
      errors.push({
        code: 'INVALID_AMOUNT_COMBINATION',
        message: `Line ${index + 1}: Must have either debit or credit, but not both`,
        field: `lines[${index}]`,
        severity: 'error'
      });
    }

    if (!Number.isFinite(debit) || !Number.isFinite(credit)) {
      errors.push({
        code: 'INVALID_NUMBER',
        message: `Line ${index + 1}: Amounts must be valid numbers`,
        field: `lines[${index}]`,
        severity: 'error'
      });
    }

    // Currency validation
    if (line.currency && line.exchangeRate) {
      if (line.exchangeRate <= 0) {
        errors.push({
          code: 'INVALID_EXCHANGE_RATE',
          message: `Line ${index + 1}: Exchange rate must be positive`,
          field: `lines[${index}].exchangeRate`,
          severity: 'error'
        });
      }
    }

    return errors;
  }

  /**
   * Validate account
   */
  async validateAccount(
    account: ChartAccount,
    businessId: string
  ): Promise<ValidationResult> {
    const validBusinessId = validateBusinessId(businessId);
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Code validation
    if (!account.code || account.code.trim().length === 0) {
      errors.push({
        code: 'MISSING_CODE',
        message: 'Account code is required',
        field: 'code',
        severity: 'error'
      });
    } else {
      // Check for duplicate codes
      const existing = await this.getAccountByCode(account.code, validBusinessId);
      if (existing && existing.id !== account.id) {
        errors.push({
          code: 'DUPLICATE_CODE',
          message: 'Account code already exists',
          field: 'code',
          value: account.code,
          severity: 'error'
        });
      }

      // Code format validation
      if (!/^[a-zA-Z0-9-]+$/.test(account.code)) {
        errors.push({
          code: 'INVALID_CODE_FORMAT',
          message: 'Account code contains invalid characters',
          field: 'code',
          value: account.code,
          severity: 'error'
        });
      }
    }

    // Name validation
    if (!account.name || account.name.trim().length === 0) {
      errors.push({
        code: 'MISSING_NAME',
        message: 'Account name is required',
        field: 'name',
        severity: 'error'
      });
    } else if (account.name.length > 200) {
      errors.push({
        code: 'NAME_TOO_LONG',
        message: 'Account name is too long (max 200 characters)',
        field: 'name',
        severity: 'error'
      });
    }

    // Type and category validation
    if (!account.type) {
      errors.push({
        code: 'MISSING_TYPE',
        message: 'Account type is required',
        field: 'type',
        severity: 'error'
      });
    }

    if (!account.category) {
      errors.push({
        code: 'MISSING_CATEGORY',
        message: 'Account category is required',
        field: 'category',
        severity: 'error'
      });
    }

    // Parent validation
    if (account.parentId) {
      const parent = await this.getAccount(account.parentId, validBusinessId);
      if (!parent) {
        errors.push({
          code: 'INVALID_PARENT',
          message: 'Parent account not found',
          field: 'parentId',
          value: account.parentId,
          severity: 'error'
        });
      } else if (parent.type !== account.type) {
        errors.push({
          code: 'PARENT_TYPE_MISMATCH',
          message: 'Parent account must have the same type',
          field: 'parentId',
          severity: 'error'
        });
      } else if (parent.id === account.id) {
        errors.push({
          code: 'CIRCULAR_REFERENCE',
          message: 'Account cannot be its own parent',
          field: 'parentId',
          severity: 'error'
        });
      }
    }

    // Currency validation
    if (!account.currency) {
      errors.push({
        code: 'MISSING_CURRENCY',
        message: 'Account currency is required',
        field: 'currency',
        severity: 'error'
      });
    } else if (!/^[A-Z]{3}$/.test(account.currency)) {
      errors.push({
        code: 'INVALID_CURRENCY',
        message: 'Currency must be a valid 3-letter code',
        field: 'currency',
        value: account.currency,
        severity: 'error'
      });
    }

    // Apply custom validation rules
    const customValidation = await this.applyCustomRules(account, 'account', validBusinessId);
    errors.push(...customValidation.errors);
    warnings.push(...customValidation.warnings);

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate period closing
   */
  async validatePeriodClosing(
    period: AccountingPeriod,
    businessId: string
  ): Promise<ValidationResult> {
    const validBusinessId = validateBusinessId(businessId);
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Period status validation
    if (period.status !== 'OPEN') {
      errors.push({
        code: 'INVALID_PERIOD_STATUS',
        message: `Cannot close period with status: ${period.status}`,
        field: 'status',
        severity: 'error'
      });
    }

    // Check for unposted entries
    const unpostedCount = await this.getUnpostedEntriesCount(period.id, validBusinessId);
    if (unpostedCount > 0) {
      errors.push({
        code: 'UNPOSTED_ENTRIES',
        message: `Period has ${unpostedCount} unposted entries`,
        field: 'entries',
        severity: 'error'
      });
    }

    // Check for unreconciled accounts
    const unreconciledAccounts = await this.getUnreconciledAccounts(period.id, validBusinessId);
    if (unreconciledAccounts.length > 0) {
      warnings.push({
        code: 'UNRECONCILED_ACCOUNTS',
        message: `${unreconciledAccounts.length} accounts are not reconciled`,
        suggestion: 'Consider reconciling all accounts before closing'
      });
    }

    // Check trial balance
    const trialBalanceValid = await this.validateTrialBalanceForPeriod(period.id, validBusinessId);
    if (!trialBalanceValid) {
      errors.push({
        code: 'UNBALANCED_TRIAL_BALANCE',
        message: 'Trial balance is not balanced',
        field: 'trialBalance',
        severity: 'error'
      });
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Apply custom validation rules
   */
  private async applyCustomRules(
    entity: any,
    entityType: 'account' | 'journal' | 'period',
    businessId: string
  ): Promise<{ errors: ValidationError[]; warnings: ValidationWarning[] }> {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    try {
      const rules = await this.getValidationRules(entityType, businessId);

      for (const rule of rules) {
        if (!rule.isActive) continue;

        const isValid = this.evaluateRule(rule.condition, entity);

        if (!isValid) {
          if (rule.severity === 'error') {
            errors.push({
              code: `CUSTOM_${rule.id}`,
              message: rule.errorMessage,
              severity: 'error'
            });
          } else {
            warnings.push({
              code: `CUSTOM_${rule.id}`,
              message: rule.errorMessage
            });
          }
        }
      }
    } catch (error) {
      this.logger.error('Error applying custom validation rules', error);
    }

    return { errors, warnings };
  }

  /**
   * Evaluate validation rule condition
   */
  private evaluateRule(condition: string, entity: any): boolean {
    try {
      // Simple expression evaluator
      // In production, use a proper expression parser
      const context = { entity, Math, Date };
      const func = new Function('context', `
        with (context) {
          return ${condition};
        }
      `);
      return func(context);
    } catch (error) {
      this.logger.warn('Failed to evaluate validation rule', { condition, error });
      return true; // Assume valid if evaluation fails
    }
  }

  /**
   * Initialize standard validation rules
   */
  private async initializeStandardRules(): Promise<void> {
    const standardRules: Omit<ValidationRule, 'id'>[] = [
      {
        name: 'Account Code Format',
        type: 'account',
        condition: '/^[0-9]{4,6}$/.test(entity.code)',
        errorMessage: 'Account code must be 4-6 digits',
        severity: 'warning',
        isActive: true
      },
      {
        name: 'Journal Entry Amount Limit',
        type: 'journal',
        condition: 'entity.lines.every(line => (line.debit || 0) + (line.credit || 0) <= 1000000)',
        errorMessage: 'Individual line amounts cannot exceed $1,000,000',
        severity: 'warning',
        isActive: true
      },
      {
        name: 'Future Date Warning',
        type: 'journal',
        condition: 'entity.date <= Date.now() + 86400000',
        errorMessage: 'Journal entry date should not be more than 1 day in the future',
        severity: 'warning',
        isActive: true
      }
    ];

    for (const rule of standardRules) {
      this.rules.set(rule.name, {
        ...rule,
        id: `std_${rule.name.replace(/\s+/g, '_').toLowerCase()}`
      } as ValidationRule);
    }
  }

  /**
   * Helper methods for database queries
   */
  private async getPeriod(periodId: string, businessId: string): Promise<AccountingPeriod | null> {
    const result = await this.db.prepare(`
      SELECT * FROM accounting_periods
      WHERE id = ? AND business_id = ?
    `).bind(periodId, businessId).first();

    return result ? {
      id: result.id as string,
      name: result.name as string,
      startDate: result.start_date as number,
      endDate: result.end_date as number,
      fiscalYear: result.fiscal_year as number,
      fiscalPeriod: result.fiscal_period as number,
      status: result.status as any,
      businessId: result.business_id as string
    } : null;
  }

  private async getAccount(accountId: string, businessId: string): Promise<ChartAccount | null> {
    const result = await this.db.prepare(`
      SELECT * FROM chart_of_accounts
      WHERE id = ? AND business_id = ?
    `).bind(accountId, businessId).first();

    return result ? {
      id: result.id as string,
      code: result.code as string,
      name: result.name as string,
      type: result.type as AccountType,
      category: result.category as any,
      currency: result.currency as string,
      normalBalance: result.normal_balance as 'debit' | 'credit',
      isActive: (result.is_active as number) === 1,
      isSystemAccount: (result.is_system_account as number) === 1,
      isReconcilable: (result.is_reconcilable as number) === 1,
      isCashAccount: (result.is_cash_account as number) === 1,
      createdAt: result.created_at as number,
      updatedAt: result.updated_at as number,
      businessId: result.business_id as string
    } : null;
  }

  private async getAccountByCode(code: string, businessId: string): Promise<ChartAccount | null> {
    const result = await this.db.prepare(`
      SELECT * FROM chart_of_accounts
      WHERE code = ? AND business_id = ?
    `).bind(code, businessId).first();

    return result ? this.getAccount(result.id as string, businessId) : null;
  }

  private async getUnpostedEntriesCount(periodId: string, businessId: string): Promise<number> {
    const result = await this.db.prepare(`
      SELECT COUNT(*) as count
      FROM journal_entries
      WHERE period_id = ? AND business_id = ? AND status != 'POSTED'
    `).bind(periodId, businessId).first();

    return (result?.count as number) || 0;
  }

  private async getUnreconciledAccounts(periodId: string, businessId: string): Promise<string[]> {
    const result = await this.db.prepare(`
      SELECT DISTINCT coa.id
      FROM chart_of_accounts coa
      LEFT JOIN account_reconciliation ar ON coa.id = ar.account_id
      WHERE coa.business_id = ?
      AND coa.is_reconcilable = 1
      AND coa.is_active = 1
      AND (ar.id IS NULL OR ar.status != 'completed')
    `).bind(businessId).all();

    return (result.results || []).map(row => row.id as string);
  }

  private async validateTrialBalanceForPeriod(periodId: string, businessId: string): Promise<boolean> {
    const result = await this.db.prepare(`
      SELECT
        SUM(jl.base_debit) as total_debits,
        SUM(jl.base_credit) as total_credits
      FROM journal_lines jl
      JOIN journal_entries je ON jl.journal_entry_id = je.id
      WHERE je.period_id = ? AND je.business_id = ? AND je.status = 'POSTED'
    `).bind(periodId, businessId).first();

    if (!result) return true;

    const totalDebits = (result.total_debits as number) || 0;
    const totalCredits = (result.total_credits as number) || 0;

    return Math.abs(totalDebits - totalCredits) < 0.01;
  }

  private async getValidationRules(
    type: 'account' | 'journal' | 'period',
    businessId: string
  ): Promise<ValidationRule[]> {
    const result = await this.db.prepare(`
      SELECT * FROM validation_rules
      WHERE type = ? AND (business_id = ? OR business_id IS NULL)
      AND is_active = 1
      ORDER BY id
    `).bind(type, businessId).all();

    return (result.results || []).map(row => ({
      id: row.id as string,
      name: row.name as string,
      type: row.type as any,
      condition: row.condition as string,
      errorMessage: row.error_message as string,
      severity: row.severity as 'error' | 'warning',
      isActive: (row.is_active as number) === 1
    }));
  }
}