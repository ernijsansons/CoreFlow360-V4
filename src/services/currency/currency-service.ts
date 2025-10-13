// @ts-nocheck
/**
 * Currency Service
 * Manages exchange rates and currency conversions
 */

import type { Env } from '../../types/env';

// ==================
// Types
// ==================

export interface Currency {
  code: string;
  name: string;
  symbol: string;
  decimal_places: number;
  is_active: boolean;
}

export interface ExchangeRate {
  id: string;
  from_currency: string;
  to_currency: string;
  rate: number;
  inverse_rate: number;
  source: string;
  valid_from: string;
  valid_to: string | null;
}

export interface ConversionResult {
  from_currency: string;
  to_currency: string;
  original_amount: number;
  converted_amount: number;
  exchange_rate: number;
  rate_date: string;
}

export interface CurrencyGainLoss {
  id: string;
  currency: string;
  realized_gain_loss: number;
  unrealized_gain_loss: number;
  calculation_date: string;
  original_rate: number;
  current_rate: number;
}

// ==================
// Currency Service
// ==================

export class CurrencyService {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  /**
   * Get all active currencies
   */
  async getActiveCurrencies(): Promise<Currency[]> {
    const { results } = await this.env.DB_MAIN.prepare(
      'SELECT * FROM currencies WHERE is_active = 1 ORDER BY code'
    ).all<Currency>();

    return results;
  }

  /**
   * Get business currency settings
   */
  async getBusinessCurrencies(businessId: string) {
    const result = await this.env.DB_MAIN.prepare(
      'SELECT * FROM business_currencies WHERE business_id = ?'
    )
      .bind(businessId)
      .first() as any;

    if (!result) {
      // Return defaults
      return {
        business_id: businessId,
        base_currency: 'USD',
        functional_currency: 'USD',
        allowed_currencies: ['USD'],
        auto_conversion: true,
      };
    }

    return {
      ...result,
      allowed_currencies: JSON.parse(result.allowed_currencies as string),
    };
  }

  /**
   * Update business currency settings
   */
  async updateBusinessCurrencies(params: {
    businessId: string;
    baseCurrency: string;
    functionalCurrency: string;
    allowedCurrencies: string[];
    autoConversion: boolean;
  }): Promise<void> {
    const existing = await this.env.DB_MAIN.prepare(
      'SELECT id FROM business_currencies WHERE business_id = ?'
    )
      .bind(params.businessId)
      .first() as any;

    if (existing) {
      await this.env.DB_MAIN.prepare(
        `UPDATE business_currencies
         SET base_currency = ?, functional_currency = ?, allowed_currencies = ?,
             auto_conversion = ?, updated_at = datetime('now')
         WHERE business_id = ?`
      )
        .bind(
          params.baseCurrency,
          params.functionalCurrency,
          JSON.stringify(params.allowedCurrencies),
          params.autoConversion ? 1 : 0,
          params.businessId
        )
        .run();
    } else {
      await this.env.DB_MAIN.prepare(
        `INSERT INTO business_currencies (business_id, base_currency, functional_currency, allowed_currencies, auto_conversion)
         VALUES (?, ?, ?, ?, ?)`
      )
        .bind(
          params.businessId,
          params.baseCurrency,
          params.functionalCurrency,
          JSON.stringify(params.allowedCurrencies),
          params.autoConversion ? 1 : 0
        )
        .run();
    }
  }

  /**
   * Get current exchange rate
   */
  async getExchangeRate(fromCurrency: string, toCurrency: string): Promise<number> {
    // Same currency - rate is 1.0
    if (fromCurrency === toCurrency) {
      return 1.0;
    }

    // Get latest rate
    const rate = await this.env.DB_MAIN.prepare(
      `SELECT rate FROM exchange_rates
       WHERE from_currency = ? AND to_currency = ?
       AND valid_to IS NULL
       ORDER BY valid_from DESC
       LIMIT 1`
    )
      .bind(fromCurrency, toCurrency)
      .first<{ rate: number }>();

    if (rate) {
      return rate.rate;
    }

    // Try inverse rate
    const inverseRate = await this.env.DB_MAIN.prepare(
      `SELECT inverse_rate FROM exchange_rates
       WHERE from_currency = ? AND to_currency = ?
       AND valid_to IS NULL
       ORDER BY valid_from DESC
       LIMIT 1`
    )
      .bind(toCurrency, fromCurrency)
      .first<{ inverse_rate: number }>();

    if (inverseRate) {
      return inverseRate.inverse_rate;
    }

    // Rate not found - fetch from external API
    return await this.fetchExchangeRate(fromCurrency, toCurrency);
  }

  /**
   * Fetch exchange rate from external API
   */
  private async fetchExchangeRate(
    fromCurrency: string,
    toCurrency: string
  ): Promise<number> {
    try {
      // Use Open Exchange Rates API (or ECB, or other provider)
      const apiKey = this.env.EXCHANGE_RATE_API_KEY;
      const response = await fetch(
        `https://openexchangerates.org/api/latest.json?app_id=${apiKey}&base=${fromCurrency}&symbols=${toCurrency}`
      );

      if (!response.ok) {
        throw new Error(`Exchange rate API error: ${response.status}`);
      }

      const data = await response.json();
      const rate = data.rates[toCurrency];

      if (!rate) {
        throw new Error(`Exchange rate not found: ${fromCurrency} -> ${toCurrency}`);
      }

      // Store rate in database
      await this.storeExchangeRate(fromCurrency, toCurrency, rate, 'openexchangerates');

      return rate;
    } catch (error) {
      console.error('Failed to fetch exchange rate:', error);
      // Fallback to 1.0 if API fails
      return 1.0;
    }
  }

  /**
   * Store exchange rate in database
   */
  private async storeExchangeRate(
    fromCurrency: string,
    toCurrency: string,
    rate: number,
    source: string
  ): Promise<void> {
    const inverseRate = 1 / rate;
    const validFrom = new Date().toISOString();

    // Mark previous rate as expired
    await this.env.DB_MAIN.prepare(
      `UPDATE exchange_rates
       SET valid_to = ?
       WHERE from_currency = ? AND to_currency = ? AND valid_to IS NULL`
    )
      .bind(validFrom, fromCurrency, toCurrency)
      .run();

    // Insert new rate
    await this.env.DB_MAIN.prepare(
      `INSERT INTO exchange_rates (from_currency, to_currency, rate, inverse_rate, source, valid_from)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(fromCurrency, toCurrency, rate, inverseRate, source, validFrom)
      .run();

    // Store in history
    await this.env.DB_MAIN.prepare(
      `INSERT INTO exchange_rate_history (from_currency, to_currency, rate, rate_date, source)
       VALUES (?, ?, ?, ?, ?)`
    )
      .bind(fromCurrency, toCurrency, rate, validFrom, source)
      .run();
  }

  /**
   * Convert amount between currencies
   */
  async convertAmount(params: {
    amount: number;
    fromCurrency: string;
    toCurrency: string;
  }): Promise<ConversionResult> {
    const rate = await this.getExchangeRate(params.fromCurrency, params.toCurrency);
    const convertedAmount = params.amount * rate;

    return {
      from_currency: params.fromCurrency,
      to_currency: params.toCurrency,
      original_amount: params.amount,
      converted_amount: convertedAmount,
      exchange_rate: rate,
      rate_date: new Date().toISOString(),
    };
  }

  /**
   * Calculate currency gain/loss
   */
  async calculateGainLoss(params: {
    businessId: string;
    currency: string;
    originalAmount: number;
    originalRate: number;
    currentRate?: number;
  }): Promise<number> {
    const currentRate = params.currentRate || (await this.getExchangeRate(params.currency, 'USD'));

    const originalValue = params.originalAmount * params.originalRate;
    const currentValue = params.originalAmount * currentRate;

    return currentValue - originalValue;
  }

  /**
   * Record realized gain/loss
   */
  async recordRealizedGainLoss(params: {
    businessId: string;
    ledgerEntryId: string;
    currency: string;
    realizedGainLoss: number;
    originalRate: number;
    currentRate: number;
    originalAmount: number;
    description: string;
  }): Promise<string> {
    const id = crypto.randomUUID();

    await this.env.DB_MAIN.prepare(
      `INSERT INTO currency_gains_losses (
        id, business_id, ledger_entry_id, currency, realized_gain_loss,
        unrealized_gain_loss, calculation_date, original_rate, current_rate,
        original_amount, description
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        params.businessId,
        params.ledgerEntryId,
        params.currency,
        params.realizedGainLoss,
        0,
        new Date().toISOString(),
        params.originalRate,
        params.currentRate,
        params.originalAmount,
        params.description
      )
      .run();

    return id;
  }

  /**
   * Get currency gains/losses for a business
   */
  async getGainsLosses(
    businessId: string,
    options?: {
      currency?: string;
      startDate?: string;
      endDate?: string;
    }
  ): Promise<CurrencyGainLoss[]> {
    let query = 'SELECT * FROM currency_gains_losses WHERE business_id = ?';
    const params: any[] = [businessId];

    if (options?.currency) {
      query += ' AND currency = ?';
      params.push(options.currency);
    }

    if (options?.startDate) {
      query += ' AND calculation_date >= ?';
      params.push(options.startDate);
    }

    if (options?.endDate) {
      query += ' AND calculation_date <= ?';
      params.push(options.endDate);
    }

    query += ' ORDER BY calculation_date DESC';

    const { results } = await this.env.DB_MAIN.prepare(query)
      .bind(...params)
      .all<CurrencyGainLoss>();

    return results;
  }

  /**
   * Get exchange rate history
   */
  async getExchangeRateHistory(
    fromCurrency: string,
    toCurrency: string,
    startDate: string,
    endDate: string
  ): Promise<Array<{ rate: number; rate_date: string }>> {
    const { results } = await this.env.DB_MAIN.prepare(
      `SELECT rate, rate_date FROM exchange_rate_history
       WHERE from_currency = ? AND to_currency = ?
       AND rate_date >= ? AND rate_date <= ?
       ORDER BY rate_date`
    )
      .bind(fromCurrency, toCurrency, startDate, endDate)
      .all<{ rate: number; rate_date: string }>();

    return results;
  }

  /**
   * Refresh all exchange rates for a business
   */
  async refreshExchangeRates(businessId: string): Promise<number> {
    const businessCurrencies = await this.getBusinessCurrencies(businessId);
    const baseCurrency = businessCurrencies.base_currency;
    const allowedCurrencies = businessCurrencies.allowed_currencies;

    let refreshedCount = 0;

    for (const currency of allowedCurrencies) {
      if (currency !== baseCurrency) {
        try {
          await this.fetchExchangeRate(currency, baseCurrency);
          refreshedCount++;
        } catch (error) {
          console.error(`Failed to refresh rate for ${currency}:`, error);
        }
      }
    }

    return refreshedCount;
  }
}
