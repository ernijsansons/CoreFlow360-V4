/**
 * Multi-Currency Accounting Service
 * Handles accounting operations with multi-currency support
 */

import type { Env } from '../../types/env';
import { CurrencyService } from './currency-service';

// ==================
// Types
// ==================

export interface MultiCurrencyLedgerEntry {
  id: string;
  business_id: string;
  account_id: string;
  transaction_date: string;
  amount: number;
  currency: string;
  original_amount: number | null;
  original_currency: string | null;
  exchange_rate: number | null;
  description: string;
  base_currency_amount: number;
}

export interface AccountBalance {
  account_id: string;
  currency: string;
  balance: number;
  base_currency_balance: number;
  exchange_rate: number;
}

// ==================
// Multi-Currency Accounting Service
// ==================

export class MultiCurrencyAccountingService {
  private currencyService: CurrencyService;
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.currencyService = new CurrencyService(env);
  }

  /**
   * Create multi-currency ledger entry
   */
  async createLedgerEntry(params: {
    businessId: string;
    accountId: string;
    transactionDate: string;
    amount: number;
    currency: string;
    description: string;
    referenceId?: string;
    referenceType?: string;
  }): Promise<string> {
    const db = this.env.DB_MAIN;

    // Get business base currency
    const businessCurrencies = await this.currencyService.getBusinessCurrencies(
      params.businessId
    );
    const baseCurrency = businessCurrencies.base_currency;

    let originalAmount = params.amount;
    let originalCurrency = params.currency;
    let exchangeRate = 1.0;
    let baseCurrencyAmount = params.amount;

    // Convert to base currency if needed
    if (params.currency !== baseCurrency) {
      exchangeRate = await this.currencyService.getExchangeRate(
        params.currency,
        baseCurrency
      );
      baseCurrencyAmount = params.amount * exchangeRate;
    }

    // Create ledger entry
    const entryId = crypto.randomUUID();
    await db
      .prepare(
        `INSERT INTO ledger_entries (
          id, business_id, account_id, transaction_date, amount, currency,
          original_amount, original_currency, exchange_rate, exchange_rate_date,
          description, reference_id, reference_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        entryId,
        params.businessId,
        params.accountId,
        params.transactionDate,
        baseCurrencyAmount,
        baseCurrency,
        originalAmount,
        originalCurrency,
        exchangeRate,
        new Date().toISOString(),
        params.description,
        params.referenceId || null,
        params.referenceType || null
      )
      .run();

    // Create multi-currency amount record
    await db
      .prepare(
        `INSERT INTO multi_currency_amounts (
          ledger_entry_id, currency, amount, exchange_rate, base_currency_amount
        ) VALUES (?, ?, ?, ?, ?)`
      )
      .bind(entryId, params.currency, params.amount, exchangeRate, baseCurrencyAmount)
      .run();

    return entryId;
  }

  /**
   * Get account balance in multiple currencies
   */
  async getAccountBalance(
    accountId: string,
    currency?: string
  ): Promise<AccountBalance[]> {
    const db = this.env.DB_MAIN;

    // Get base currency for the business
    const account = await db
      .prepare('SELECT business_id, currency FROM accounts WHERE id = ?')
      .bind(accountId)
      .first<{ business_id: string; currency: string }>();

    if (!account) {
      throw new Error(`Account ${accountId} not found`);
    }

    const businessCurrencies = await this.currencyService.getBusinessCurrencies(
      account.business_id
    );
    const baseCurrency = businessCurrencies.base_currency;

    // Get balances by currency
    let query = `
      SELECT
        mca.currency,
        SUM(mca.amount) as balance,
        SUM(mca.base_currency_amount) as base_currency_balance,
        AVG(mca.exchange_rate) as exchange_rate
      FROM multi_currency_amounts mca
      JOIN ledger_entries le ON mca.ledger_entry_id = le.id
      WHERE le.account_id = ?
    `;

    const params: any[] = [accountId];

    if (currency) {
      query += ' AND mca.currency = ?';
      params.push(currency);
    }

    query += ' GROUP BY mca.currency';

    const { results } = await db
      .prepare(query)
      .bind(...params)
      .all<{
        currency: string;
        balance: number;
        base_currency_balance: number;
        exchange_rate: number;
      }>();

    return results.map((r) => ({
      account_id: accountId,
      currency: r.currency,
      balance: r.balance,
      base_currency_balance: r.base_currency_balance,
      exchange_rate: r.exchange_rate,
    }));
  }

  /**
   * Revalue account balances to current exchange rates
   */
  async revalueAccountBalances(businessId: string): Promise<{
    revaluations: Array<{
      account_id: string;
      currency: string;
      old_value: number;
      new_value: number;
      unrealized_gain_loss: number;
    }>;
    total_unrealized_gain_loss: number;
  }> {
    const db = this.env.DB_MAIN;

    // Get all accounts for the business with foreign currency balances
    const accounts = await db
      .prepare('SELECT id, currency FROM accounts WHERE business_id = ?')
      .bind(businessId)
      .all<{ id: string; currency: string }>();

    const businessCurrencies = await this.currencyService.getBusinessCurrencies(businessId);
    const baseCurrency = businessCurrencies.base_currency;

    const revaluations = [];
    let totalUnrealizedGainLoss = 0;

    for (const account of accounts.results) {
      const balances = await this.getAccountBalance(account.id);

      for (const balance of balances) {
        if (balance.currency !== baseCurrency) {
          // Get current exchange rate
          const currentRate = await this.currencyService.getExchangeRate(
            balance.currency,
            baseCurrency
          );

          // Calculate new value
          const oldValue = balance.base_currency_balance;
          const newValue = balance.balance * currentRate;
          const unrealizedGainLoss = newValue - oldValue;

          if (Math.abs(unrealizedGainLoss) > 0.01) {
            revaluations.push({
              account_id: account.id,
              currency: balance.currency,
              old_value: oldValue,
              new_value: newValue,
              unrealized_gain_loss: unrealizedGainLoss,
            });

            totalUnrealizedGainLoss += unrealizedGainLoss;

            // Record unrealized gain/loss
            await db
              .prepare(
                `INSERT INTO currency_gains_losses (
                  business_id, currency, unrealized_gain_loss, calculation_date,
                  original_rate, current_rate, original_amount, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
              )
              .bind(
                businessId,
                balance.currency,
                unrealizedGainLoss,
                new Date().toISOString(),
                balance.exchange_rate,
                currentRate,
                balance.balance,
                `Revaluation: ${balance.currency} to ${baseCurrency}`
              )
              .run();
          }
        }
      }
    }

    return {
      revaluations,
      total_unrealized_gain_loss: totalUnrealizedGainLoss,
    };
  }

  /**
   * Get multi-currency trial balance
   */
  async getTrialBalance(
    businessId: string,
    options?: {
      asOfDate?: string;
      currency?: string;
    }
  ): Promise<
    Array<{
      account_id: string;
      account_name: string;
      currency: string;
      debit: number;
      credit: number;
      balance: number;
      base_currency_balance: number;
    }>
  > {
    const db = this.env.DB_MAIN;

    let query = `
      SELECT
        a.id as account_id,
        a.name as account_name,
        mca.currency,
        SUM(CASE WHEN mca.amount > 0 THEN mca.amount ELSE 0 END) as debit,
        SUM(CASE WHEN mca.amount < 0 THEN ABS(mca.amount) ELSE 0 END) as credit,
        SUM(mca.amount) as balance,
        SUM(mca.base_currency_amount) as base_currency_balance
      FROM accounts a
      JOIN ledger_entries le ON a.id = le.account_id
      JOIN multi_currency_amounts mca ON le.id = mca.ledger_entry_id
      WHERE a.business_id = ?
    `;

    const params: any[] = [businessId];

    if (options?.asOfDate) {
      query += ' AND le.transaction_date <= ?';
      params.push(options.asOfDate);
    }

    if (options?.currency) {
      query += ' AND mca.currency = ?';
      params.push(options.currency);
    }

    query += ' GROUP BY a.id, a.name, mca.currency ORDER BY a.name, mca.currency';

    const { results } = await db.prepare(query).bind(...params).all();

    return results as any[];
  }

  /**
   * Convert historical transaction to different currency
   */
  async convertHistoricalTransaction(params: {
    ledgerEntryId: string;
    toCurrency: string;
  }): Promise<{
    original_amount: number;
    original_currency: string;
    converted_amount: number;
    converted_currency: string;
    exchange_rate: number;
  }> {
    const db = this.env.DB_MAIN;

    // Get original transaction
    const entry = await db
      .prepare('SELECT * FROM ledger_entries WHERE id = ?')
      .bind(params.ledgerEntryId)
      .first<{
        original_amount: number;
        original_currency: string;
        exchange_rate_date: string;
      }>();

    if (!entry) {
      throw new Error(`Ledger entry ${params.ledgerEntryId} not found`);
    }

    // Get historical exchange rate
    const historicalRate = await db
      .prepare(
        `SELECT rate FROM exchange_rate_history
         WHERE from_currency = ? AND to_currency = ?
         AND rate_date <= ?
         ORDER BY rate_date DESC
         LIMIT 1`
      )
      .bind(entry.original_currency, params.toCurrency, entry.exchange_rate_date)
      .first<{ rate: number }>();

    const exchangeRate = historicalRate?.rate || 1.0;
    const convertedAmount = entry.original_amount * exchangeRate;

    return {
      original_amount: entry.original_amount,
      original_currency: entry.original_currency,
      converted_amount: convertedAmount,
      converted_currency: params.toCurrency,
      exchange_rate: exchangeRate,
    };
  }

  /**
   * Get currency exposure report
   */
  async getCurrencyExposure(businessId: string): Promise<
    Array<{
      currency: string;
      total_assets: number;
      total_liabilities: number;
      net_exposure: number;
      base_currency_value: number;
    }>
  > {
    const db = this.env.DB_MAIN;

    const { results } = await db
      .prepare(
        `SELECT
          mca.currency,
          SUM(CASE WHEN a.type IN ('asset', 'expense') THEN mca.amount ELSE 0 END) as total_assets,
          SUM(CASE WHEN a.type IN ('liability', 'equity', 'revenue') THEN mca.amount ELSE 0 END) as total_liabilities,
          SUM(mca.amount) as net_exposure,
          SUM(mca.base_currency_amount) as base_currency_value
        FROM accounts a
        JOIN ledger_entries le ON a.id = le.account_id
        JOIN multi_currency_amounts mca ON le.id = mca.ledger_entry_id
        WHERE a.business_id = ?
        GROUP BY mca.currency
        ORDER BY ABS(SUM(mca.base_currency_amount)) DESC`
      )
      .bind(businessId)
      .all();

    return results as any[];
  }
}
