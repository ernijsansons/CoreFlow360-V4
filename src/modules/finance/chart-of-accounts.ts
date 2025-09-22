/**
 * Chart of Accounts Management
 * Standard account structure and hierarchy
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  ChartAccount,
  AccountType,
  AccountCategory,
  AuditAction,
  ValidationRule
} from './types';
import { FinanceAuditLogger } from './audit-logger';
import { generateAccountCode, validateBusinessId, validateAccountCode } from './utils';

export // TODO: Consider splitting ChartOfAccountsManager into smaller, focused classes
class ChartOfAccountsManager {
  private logger: Logger;
  private db: D1Database;
  private auditLogger: FinanceAuditLogger;
  private accountCache = new Map<string, ChartAccount>();
  private hierarchyCache = new Map<string, ChartAccount[]>();

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
    this.auditLogger = new FinanceAuditLogger(db);
  }

  /**
   * Create standard chart of accounts
   */
  async createStandardChart(businessId: string, currency: string = 'USD'): Promise<void> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      await this.db.batch([
        // Assets (1000-1999)
       
  this.createAccountStatement('1000', 'Cash and Cash Equivalents', AccountType.ASSET, AccountCategory.CURRENT_ASSET, validBusinessId, currency),
      
   this.createAccountStatement('1010', 'Petty Cash', AccountType.ASSET, AccountCategory.CURRENT_ASSET, validBusinessId, currency),
      
   this.createAccountStatement('1100', 'Accounts Receivable', AccountType.ASSET, AccountCategory.CURRENT_ASSET, validBusinessId, currency),
       
  this.createAccountStatement('1110', 'Allowance for Doubtful Accounts', AccountType.CONTRA_ASSET, AccountCategory.CURRENT_ASSET, validBusinessId, currency),
      
   this.createAccountStatement('1200', 'Inventory', AccountType.ASSET, AccountCategory.CURRENT_ASSET, validBusinessId, currency),
      
   this.createAccountStatement('1300', 'Prepaid Expenses', AccountType.ASSET, AccountCategory.CURRENT_ASSET, validBusinessId, currency),
       
  this.createAccountStatement('1500', 'Property, Plant & Equipment', AccountType.ASSET, AccountCategory.FIXED_ASSET, validBusinessId, currency),
      
   this.createAccountStatement('1510', 'Accumulated Depreciation', AccountType.CONTRA_ASSET, AccountCategory.FIXED_ASSET, validBusinessId, currency),
      
   this.createAccountStatement('1600', 'Intangible Assets', AccountType.ASSET, AccountCategory.INTANGIBLE_ASSET, validBusinessId, currency),
      
   this.createAccountStatement('1700', 'Investments', AccountType.ASSET, AccountCategory.INVESTMENT, validBusinessId, currency),

        // Liabilities (2000-2999)
      
   this.createAccountStatement('2000', 'Accounts Payable', AccountType.LIABILITY, AccountCategory.CURRENT_LIABILITY, validBusinessId, currency),
      
   this.createAccountStatement('2100', 'Accrued Expenses', AccountType.LIABILITY, AccountCategory.CURRENT_LIABILITY, validBusinessId, currency),
       
  this.createAccountStatement('2200', 'Sales Tax Payable', AccountType.LIABILITY, AccountCategory.CURRENT_LIABILITY, validBusinessId, currency),
      
   this.createAccountStatement('2300', 'Payroll Liabilities', AccountType.LIABILITY, AccountCategory.CURRENT_LIABILITY, validBusinessId, currency),
      
   this.createAccountStatement('2400', 'Unearned Revenue', AccountType.LIABILITY, AccountCategory.CURRENT_LIABILITY, validBusinessId, currency),
      
   this.createAccountStatement('2500', 'Short-term Loans', AccountType.LIABILITY, AccountCategory.CURRENT_LIABILITY, validBusinessId, currency),
        this.createAccountStatement('2600',
  'Current Portion of Long-term Debt', AccountType.LIABILITY, AccountCategory.CURRENT_LIABILITY, validBusinessId, currency),
      
   this.createAccountStatement('2700', 'Long-term Loans', AccountType.LIABILITY, AccountCategory.LONG_TERM_LIABILITY, validBusinessId, currency),
      
   this.createAccountStatement('2800', 'Bonds Payable', AccountType.LIABILITY, AccountCategory.LONG_TERM_LIABILITY, validBusinessId, currency),

        // Equity (3000-3999)
      
   this.createAccountStatement('3000', 'Common Stock', AccountType.EQUITY, AccountCategory.OWNERS_EQUITY, validBusinessId, currency),
      
   this.createAccountStatement('3100', 'Preferred Stock', AccountType.EQUITY, AccountCategory.OWNERS_EQUITY, validBusinessId, currency),
       
  this.createAccountStatement('3200', 'Additional Paid-in Capital', AccountType.EQUITY, AccountCategory.OWNERS_EQUITY, validBusinessId, currency),
       
  this.createAccountStatement('3300', 'Retained Earnings', AccountType.EQUITY, AccountCategory.RETAINED_EARNINGS, validBusinessId, currency, true),
      
   this.createAccountStatement('3400', 'Dividends', AccountType.CONTRA_EQUITY, AccountCategory.OWNERS_EQUITY, validBusinessId, currency),
      
   this.createAccountStatement('3500', 'Treasury Stock', AccountType.CONTRA_EQUITY, AccountCategory.OWNERS_EQUITY, validBusinessId, currency),
       
  this.createAccountStatement('3900', 'Income Summary', AccountType.EQUITY, AccountCategory.RETAINED_EARNINGS, validBusinessId, currency, true),

        // Revenue (4000-4999)
      
   this.createAccountStatement('4000', 'Sales Revenue', AccountType.REVENUE, AccountCategory.OPERATING_REVENUE, validBusinessId, currency),
      
   this.createAccountStatement('4100', 'Service Revenue', AccountType.REVENUE, AccountCategory.OPERATING_REVENUE, validBusinessId, currency),
       
  this.createAccountStatement('4200', 'Sales Returns and Allowances', AccountType.CONTRA_REVENUE, AccountCategory.OPERATING_REVENUE, validBusinessId, currency),
      
   this.createAccountStatement('4300', 'Sales Discounts', AccountType.CONTRA_REVENUE, AccountCategory.OPERATING_REVENUE, validBusinessId, currency),
      
   this.createAccountStatement('4500', 'Interest Income', AccountType.REVENUE, AccountCategory.NON_OPERATING_REVENUE, validBusinessId, currency),
      
   this.createAccountStatement('4600', 'Dividend Income', AccountType.REVENUE, AccountCategory.NON_OPERATING_REVENUE, validBusinessId, currency),
        this.createAccountStatement('4700',
  'Gain on Sale of Assets', AccountType.REVENUE, AccountCategory.NON_OPERATING_REVENUE, validBusinessId, currency),
       
  this.createAccountStatement('4800', 'Foreign Exchange Gain', AccountType.REVENUE, AccountCategory.NON_OPERATING_REVENUE, validBusinessId, currency),

        // Expenses (5000-5999)
       
  this.createAccountStatement('5000', 'Cost of Goods Sold', AccountType.EXPENSE, AccountCategory.COST_OF_GOODS_SOLD, validBusinessId, currency),
       
  this.createAccountStatement('5100', 'Salaries and Wages', AccountType.EXPENSE, AccountCategory.OPERATING_EXPENSE, validBusinessId, currency),
      
   this.createAccountStatement('5200', 'Rent Expense', AccountType.EXPENSE, AccountCategory.OPERATING_EXPENSE, validBusinessId, currency),
      
   this.createAccountStatement('5300', 'Utilities Expense', AccountType.EXPENSE, AccountCategory.OPERATING_EXPENSE, validBusinessId, currency),
      
   this.createAccountStatement('5400', 'Insurance Expense', AccountType.EXPENSE, AccountCategory.OPERATING_EXPENSE, validBusinessId, currency),
      
   this.createAccountStatement('5500', 'Depreciation Expense', AccountType.EXPENSE, AccountCategory.OPERATING_EXPENSE, validBusinessId, currency),
      
   this.createAccountStatement('5600', 'Advertising Expense', AccountType.EXPENSE, AccountCategory.OPERATING_EXPENSE, validBusinessId, currency),
       
  this.createAccountStatement('5700', 'Office Supplies Expense', AccountType.EXPENSE, AccountCategory.OPERATING_EXPENSE, validBusinessId, currency),
      
   this.createAccountStatement('5800', 'Professional Fees', AccountType.EXPENSE, AccountCategory.OPERATING_EXPENSE, validBusinessId, currency),
      
   this.createAccountStatement('5900', 'Interest Expense', AccountType.EXPENSE, AccountCategory.NON_OPERATING_EXPENSE, validBusinessId, currency),
       
  this.createAccountStatement('5950', 'Foreign Exchange Loss', AccountType.EXPENSE, AccountCategory.NON_OPERATING_EXPENSE, validBusinessId, currency),
       
  this.createAccountStatement('5990', 'Income Tax Expense', AccountType.EXPENSE, AccountCategory.TAX_EXPENSE, validBusinessId, currency)
      ]);

      this.logger.info('Standard chart of accounts created', { businessId: validBusinessId });

      await this.auditLogger.logAction(
        'account',
        'STANDARD_CHART',
        AuditAction.CREATE,
        validBusinessId,
        'system',
        { message: 'Standard chart of accounts created' }
      );

    } catch (error) {
      this.logger.error('Failed to create standard chart of accounts', error, { businessId });
      throw error;
    }
  }

  /**
   * Create a new account
   */
  async createAccount(
    account: Omit<ChartAccount, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<ChartAccount> {
    const validBusinessId = validateBusinessId(account.businessId);
    const validCode = validateAccountCode(account.code);

    // Validate account doesn't already exist
    const existing = await this.getAccountByCode(validCode, validBusinessId);
    if (existing) {
      throw new Error(`Account with code ${validCode} already exists`);
    }

    // Determine normal balance based on account type
    const normalBalance = this.getNormalBalance(account.type);

    const now = Date.now();
    const newAccount: ChartAccount = {
      ...account,
      id: `acc_${now}_${Math.random().toString(36).substring(2, 9)}`,
      code: validCode,
      normalBalance,
      businessId: validBusinessId,
      createdAt: now,
      updatedAt: now
    };

    // Validate parent account exists if specified
    if (newAccount.parentId) {
      const parent = await this.getAccount(newAccount.parentId, validBusinessId);
      if (!parent) {
        throw new Error(`Parent account ${newAccount.parentId} not found`);
      }
      if (parent.type !== newAccount.type) {
        throw new Error('Child account must have same type as parent');
      }
    }

    await this.db.prepare(`
      INSERT INTO chart_of_accounts (
        id, code, name, type, category, parent_id,
        description, currency, normal_balance, is_active,
        is_system_account, is_reconcilable, is_cash_account,
        metadata, created_at, updated_at, business_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      newAccount.id,
      newAccount.code,
      newAccount.name,
      newAccount.type,
      newAccount.category,
      newAccount.parentId || null,
      newAccount.description || null,
      newAccount.currency,
      newAccount.normalBalance,
      newAccount.isActive ? 1 : 0,
      newAccount.isSystemAccount ? 1 : 0,
      newAccount.isReconcilable ? 1 : 0,
      newAccount.isCashAccount ? 1 : 0,
      JSON.stringify(newAccount.metadata || {}),
      newAccount.createdAt,
      newAccount.updatedAt,
      newAccount.businessId
    ).run();

    // Clear cache
    this.accountCache.delete(newAccount.id);
    this.hierarchyCache.clear();

    await this.auditLogger.logAction(
      'account',
      newAccount.id,
      AuditAction.CREATE,
      validBusinessId,
      'user',
      { account: newAccount }
    );

    this.logger.info('Account created', {
      accountId: newAccount.id,
      code: newAccount.code,
      name: newAccount.name
    });

    return newAccount;
  }

  /**
   * Update an account
   */
  async updateAccount(
    accountId: string,
    updates: Partial<ChartAccount>,
    userId: string,
    businessId: string
  ): Promise<ChartAccount> {
    const validBusinessId = validateBusinessId(businessId);

    const existing = await this.getAccount(accountId, validBusinessId);
    if (!existing) {
      throw new Error(`Account ${accountId} not found`);
    }

    if (existing.isSystemAccount && !updates.isActive) {
      throw new Error('Cannot deactivate system account');
    }

    // Don't allow changing critical fields
    delete updates.id;
    delete updates.businessId;
    delete updates.createdAt;
    delete updates.type; // Type changes would break the accounting equation

    const updated: ChartAccount = {
      ...existing,
      ...updates,
      updatedAt: Date.now()
    };

    await this.db.prepare(`
      UPDATE chart_of_accounts
      SET name = ?, category = ?, parent_id = ?,
          description = ?, currency = ?, is_active = ?,
          is_reconcilable = ?, is_cash_account = ?,
          metadata = ?, updated_at = ?
      WHERE id = ? AND business_id = ?
    `).bind(
      updated.name,
      updated.category,
      updated.parentId || null,
      updated.description || null,
      updated.currency,
      updated.isActive ? 1 : 0,
      updated.isReconcilable ? 1 : 0,
      updated.isCashAccount ? 1 : 0,
      JSON.stringify(updated.metadata || {}),
      updated.updatedAt,
      accountId,
      validBusinessId
    ).run();

    // Clear cache
    this.accountCache.delete(accountId);
    this.hierarchyCache.clear();

    await this.auditLogger.logAction(
      'account',
      accountId,
      AuditAction.UPDATE,
      validBusinessId,
      userId,
      { before: existing, after: updated }
    );

    return updated;
  }

  /**
   * Get account by ID
   */
  async getAccount(accountId: string, businessId: string): Promise<ChartAccount | null> {
    const validBusinessId = validateBusinessId(businessId);

    // Check cache
    if (this.accountCache.has(accountId)) {
      return this.accountCache.get(accountId)!;
    }

    const result = await this.db.prepare(`
      SELECT * FROM chart_of_accounts
      WHERE id = ? AND business_id = ?
    `).bind(accountId, validBusinessId).first();

    if (!result) {
      return null;
    }

    const account = this.mapToAccount(result);
    this.accountCache.set(accountId, account);

    return account;
  }

  /**
   * Get account by code
   */
  async getAccountByCode(code: string, businessId: string): Promise<ChartAccount | null> {
    const validBusinessId = validateBusinessId(businessId);
    const validCode = validateAccountCode(code);

    const result = await this.db.prepare(`
      SELECT * FROM chart_of_accounts
      WHERE code = ? AND business_id = ?
    `).bind(validCode, validBusinessId).first();

    if (!result) {
      return null;
    }

    return this.mapToAccount(result);
  }

  /**
   * Get all accounts for a business
   */
  async getAccounts(
    businessId: string,
    options?: {
      type?: AccountType;
      category?: AccountCategory;
      isActive?: boolean;
      parentId?: string;
    }
  ): Promise<ChartAccount[]> {
    const validBusinessId = validateBusinessId(businessId);

    let query = `
      SELECT * FROM chart_of_accounts
      WHERE business_id = ?
    `;
    const params: any[] = [validBusinessId];

    if (options?.type) {
      query += ' AND type = ?';
      params.push(options.type);
    }

    if (options?.category) {
      query += ' AND category = ?';
      params.push(options.category);
    }

    if (options?.isActive !== undefined) {
      query += ' AND is_active = ?';
      params.push(options.isActive ? 1 : 0);
    }

    if (options?.parentId !== undefined) {
      query += options.parentId ? ' AND parent_id = ?' : ' AND parent_id IS NULL';
      if (options.parentId) params.push(options.parentId);
    }

    query += ' ORDER BY code ASC';

    const result = await this.db.prepare(query).bind(...params).all();

    return (result.results || []).map(row => this.mapToAccount(row));
  }

  /**
   * Get account hierarchy
   */
  async getAccountHierarchy(
    businessId: string,
    parentId?: string
  ): Promise<ChartAccount[]> {
    const validBusinessId = validateBusinessId(businessId);
    const cacheKey = `${validBusinessId}:${parentId || 'root'}`;

    if (this.hierarchyCache.has(cacheKey)) {
      return this.hierarchyCache.get(cacheKey)!;
    }

    const accounts = await this.getAccounts(validBusinessId, { parentId });

    // Recursively get children
    for (const account of accounts) {
      const children = await this.getAccountHierarchy(validBusinessId, account.id);
      if (children.length > 0) {
        (account as any).children = children;
      }
    }

    this.hierarchyCache.set(cacheKey, accounts);
    return accounts;
  }

  /**
   * Delete account (soft delete)
   */
  async deleteAccount(
    accountId: string,
    userId: string,
    businessId: string
  ): Promise<void> {
    const validBusinessId = validateBusinessId(businessId);

    const account = await this.getAccount(accountId, validBusinessId);
    if (!account) {
      throw new Error(`Account ${accountId} not found`);
    }

    if (account.isSystemAccount) {
      throw new Error('Cannot delete system account');
    }

    // Check if account has transactions
    const hasTransactions = await this.hasTransactions(accountId, validBusinessId);
    if (hasTransactions) {
      throw new Error('Cannot delete account with transactions');
    }

    // Check if account has children
    const children = await this.getAccounts(validBusinessId, { parentId: accountId });
    if (children.length > 0) {
      throw new Error('Cannot delete account with sub-accounts');
    }

    // Soft delete
    await this.updateAccount(
      accountId,
      { isActive: false },
      userId,
      validBusinessId
    );

    await this.auditLogger.logAction(
      'account',
      accountId,
      AuditAction.DELETE,
      validBusinessId,
      userId,
      { account }
    );

    this.logger.info('Account deleted', { accountId, businessId: validBusinessId });
  }

  /**
   * Check if account has transactions
   */
  private async hasTransactions(accountId: string, businessId: string): Promise<boolean> {
    const result = await this.db.prepare(`
      SELECT COUNT(*) as count
      FROM ledger_transactions
      WHERE account_id = ? AND business_id = ?
    `).bind(accountId, businessId).first();

    return (result?.count as number) > 0;
  }

  /**
   * Get normal balance for account type
   */
  private getNormalBalance(type: AccountType): 'debit' | 'credit' {
    switch (type) {
      case AccountType.ASSET:
      case AccountType.EXPENSE:
      case AccountType.CONTRA_LIABILITY:
      case AccountType.CONTRA_EQUITY:
      case AccountType.CONTRA_REVENUE:
        return 'debit';
      case AccountType.LIABILITY:
      case AccountType.EQUITY:
      case AccountType.REVENUE:
      case AccountType.CONTRA_ASSET:
      case AccountType.CONTRA_EXPENSE:
        return 'credit';
      default:
        return 'debit';
    }
  }

  /**
   * Create account SQL statement
   */
  private createAccountStatement(
    code: string,
    name: string,
    type: AccountType,
    category: AccountCategory,
    businessId: string,
    currency: string,
    isSystem: boolean = false
  ): any {
    const now = Date.now();
    const id = `acc_${code}_${now}`;
    const normalBalance = this.getNormalBalance(type);

    return this.db.prepare(`
      INSERT OR IGNORE INTO chart_of_accounts (
        id, code, name, type, category, parent_id,
        description, currency, normal_balance, is_active,
        is_system_account, is_reconcilable, is_cash_account,
        metadata, created_at, updated_at, business_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      code,
      name,
      type,
      category,
      null, // parent_id
      null, // description
      currency,
      normalBalance,
      1, // is_active
      isSystem ? 1 : 0,
      code.startsWith('1') ? 1 : 0, // is_reconcilable (assets)
      code === '1000' || code === '1010' ? 1 : 0, // is_cash_account
      '{}', // metadata
      now,
      now,
      businessId
    );
  }

  /**
   * Map database row to ChartAccount
   */
  private mapToAccount(row: any): ChartAccount {
    return {
      id: row.id,
      code: row.code,
      name: row.name,
      type: row.type,
      category: row.category,
      parentId: row.parent_id || undefined,
      description: row.description || undefined,
      currency: row.currency,
      normalBalance: row.normal_balance,
      isActive: row.is_active === 1,
      isSystemAccount: row.is_system_account === 1,
      isReconcilable: row.is_reconcilable === 1,
      isCashAccount: row.is_cash_account === 1,
      metadata: row.metadata ? JSON.parse(row.metadata) : {},
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      businessId: row.business_id
    };
  }

  /**
   * Validate account for journal entry
   */
  async validateAccountForEntry(
    accountId: string,
    businessId: string
  ): Promise<{ valid: boolean; error?: string }> {
    const account = await this.getAccount(accountId, businessId);

    if (!account) {
      return { valid: false, error: 'Account not found' };
    }

    if (!account.isActive) {
      return { valid: false, error: 'Account is inactive' };
    }

    return { valid: true };
  }

  /**
   * Get accounts for closing entries
   */
  async getClosingAccounts(businessId: string): Promise<{
    revenueAccounts: ChartAccount[];
    expenseAccounts: ChartAccount[];
    incomeSummaryAccount: ChartAccount | null;
    retainedEarningsAccount: ChartAccount | null;
  }> {
    const validBusinessId = validateBusinessId(businessId);

    const [revenues, expenses, incomeSummary, retainedEarnings] = await Promise.all([
      this.getAccounts(validBusinessId, { type: AccountType.REVENUE, isActive: true }),
      this.getAccounts(validBusinessId, { type: AccountType.EXPENSE, isActive: true }),
      this.getAccountByCode('3900', validBusinessId),
      this.getAccountByCode('3300', validBusinessId)
    ]);

    return {
      revenueAccounts: revenues,
      expenseAccounts: expenses,
      incomeSummaryAccount: incomeSummary,
      retainedEarningsAccount: retainedEarnings
    };
  }
}