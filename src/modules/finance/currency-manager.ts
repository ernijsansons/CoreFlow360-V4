/**
 * Currency Manager
 * Multi-currency support with exchange rates and conversions
 */

import type { D1Database, KVNamespace } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { Currency, ExchangeRate, AuditAction } from './types';
import { FinanceAuditLogger } from './audit-logger';
import { validateBusinessId } from './utils';

export // TODO: Consider splitting CurrencyManager into smaller, focused classes
class CurrencyManager {
  private logger: Logger;
  private db: D1Database;
  private kv?: KVNamespace;
  private auditLogger: FinanceAuditLogger;

  private currencyCache = new Map<string, Currency>();
  private rateCache = new Map<string, ExchangeRate>();
  private cacheExpiry = 300000; // 5 minutes
  private lastRateUpdate = new Map<string, number>();

  // Standard currencies
  private readonly STANDARD_CURRENCIES: Currency[] = [
    { code: 'USD', name: 'US Dollar', symbol: '$', decimalPlaces: 2, isBaseCurrency: true },
    { code: 'EUR', name: 'Euro', symbol: '€', decimalPlaces: 2, isBaseCurrency: false },
    { code: 'GBP', name: 'British Pound', symbol: '£', decimalPlaces: 2, isBaseCurrency: false },
    { code: 'JPY', name: 'Japanese Yen', symbol: '¥', decimalPlaces: 0, isBaseCurrency: false },
    { code: 'CAD', name: 'Canadian Dollar', symbol: 'C$', decimalPlaces: 2, isBaseCurrency: false },
    { code: 'AUD', name: 'Australian Dollar', symbol: 'A$', decimalPlaces: 2, isBaseCurrency: false },
    { code: 'CHF', name: 'Swiss Franc', symbol: 'CHF', decimalPlaces: 2, isBaseCurrency: false },
    { code: 'CNY', name: 'Chinese Yuan', symbol: '¥', decimalPlaces: 2, isBaseCurrency: false },
    { code: 'INR', name: 'Indian Rupee', symbol: '₹', decimalPlaces: 2, isBaseCurrency: false },
    { code: 'BRL', name: 'Brazilian Real', symbol: 'R$', decimalPlaces: 2, isBaseCurrency: false }
  ];

  constructor(db: D1Database, kv?: KVNamespace) {
    this.logger = new Logger();
    this.db = db;
    this.kv = kv;
    this.auditLogger = new FinanceAuditLogger(db);

    this.initializeStandardCurrencies();
  }

  /**
   * Initialize standard currencies
   */
  private async initializeStandardCurrencies(): Promise<void> {
    try {
      for (const currency of this.STANDARD_CURRENCIES) {
        this.currencyCache.set(currency.code, currency);
      }

      // Insert currencies into database if they don't exist
      const batch = this.db.batch([]);
      for (const currency of this.STANDARD_CURRENCIES) {
        batch.push(
          this.db.prepare(`
            INSERT OR IGNORE INTO currencies (
              code, name, symbol, decimal_places, is_base_currency
            ) VALUES (?, ?, ?, ?, ?)
          `).bind(
            currency.code,
            currency.name,
            currency.symbol,
            currency.decimalPlaces,
            currency.isBaseCurrency ? 1 : 0
          )
        );
      }
      await this.db.batch(batch);

    } catch (error: any) {
      this.logger.error('Failed to initialize standard currencies', error);
    }
  }

  /**
   * Get base currency for business
   */
  async getBaseCurrency(businessId: string): Promise<string> {
    const validBusinessId = validateBusinessId(businessId);

    // Try to get from business config
    const configResult = await this.db.prepare(`
      SELECT base_currency FROM finance_config
      WHERE business_id = ?
    `).bind(validBusinessId).first();

    if (configResult?.base_currency) {
      return configResult.base_currency as string;
    }

    // Default to USD
    return 'USD';
  }

  /**
   * Set base currency for business
   */
  async setBaseCurrency(
    businessId: string,
    currencyCode: string,
    updatedBy: string
  ): Promise<void> {
    const validBusinessId = validateBusinessId(businessId);

    // Validate currency exists
    const currency = await this.getCurrency(currencyCode);
    if (!currency) {
      throw new Error(`Currency ${currencyCode} not found`);
    }

    // Update business configuration
    await this.db.prepare(`
      INSERT OR REPLACE INTO finance_config (
        business_id, base_currency, updated_at, updated_by
      ) VALUES (?, ?, ?, ?)
    `).bind(
      validBusinessId,
      currencyCode,
      Date.now(),
      updatedBy
    ).run();

    await this.auditLogger.logAction(
      'currency',
      `base_${validBusinessId}`,
      AuditAction.UPDATE,
      validBusinessId,
      updatedBy,
      { newBaseCurrency: currencyCode }
    );

    this.logger.info('Base currency updated', {
      businessId: validBusinessId,
      currency: currencyCode
    });
  }

  /**
   * Get currency information
   */
  async getCurrency(code: string): Promise<Currency | null> {
    // Check cache first
    if (this.currencyCache.has(code)) {
      return this.currencyCache.get(code)!;
    }

    const result = await this.db.prepare(`
      SELECT * FROM currencies WHERE code = ?
    `).bind(code).first();

    if (!result) {
      return null;
    }

    const currency: Currency = {
      code: result.code as string,
      name: result.name as string,
      symbol: result.symbol as string,
      decimalPlaces: result.decimal_places as number,
      isBaseCurrency: (result.is_base_currency as number) === 1
    };

    this.currencyCache.set(code, currency);
    return currency;
  }

  /**
   * Get all available currencies
   */
  async getCurrencies(): Promise<Currency[]> {
    const result = await this.db.prepare(`
      SELECT * FROM currencies
      ORDER BY code ASC
    `).all();

    return (result.results || []).map((row: any) => ({
      code: row.code as string,
      name: row.name as string,
      symbol: row.symbol as string,
      decimalPlaces: row.decimal_places as number,
      isBaseCurrency: (row.is_base_currency as number) === 1
    }));
  }

  /**
   * Add custom currency
   */
  async addCurrency(
    currency: Omit<Currency, 'isBaseCurrency'>,
    addedBy: string,
    businessId: string
  ): Promise<void> {
    const validBusinessId = validateBusinessId(businessId);

    // Validate currency doesn't exist
    const existing = await this.getCurrency(currency.code);
    if (existing) {
      throw new Error(`Currency ${currency.code} already exists`);
    }

    await this.db.prepare(`
      INSERT INTO currencies (
        code, name, symbol, decimal_places, is_base_currency,
        added_by, business_id, created_at
      ) VALUES (?, ?, ?, ?, 0, ?, ?, ?)
    `).bind(
      currency.code,
      currency.name,
      currency.symbol,
      currency.decimalPlaces,
      addedBy,
      validBusinessId,
      Date.now()
    ).run();

    // Update cache
    this.currencyCache.set(currency.code, { ...currency, isBaseCurrency: false });

    await this.auditLogger.logAction(
      'currency',
      currency.code,
      AuditAction.CREATE,
      validBusinessId,
      addedBy,
      { currency }
    );

    this.logger.info('Custom currency added', { currency: currency.code });
  }

  /**
   * Get exchange rate
   */
  async getExchangeRate(
    fromCurrency: string,
    businessId: string,
    effectiveDate?: number
  ): Promise<number> {
    const validBusinessId = validateBusinessId(businessId);
    const baseCurrency = await this.getBaseCurrency(validBusinessId);

    // If same currency or base currency, return 1
    if (fromCurrency === baseCurrency) {
      return 1.0;
    }

    const cacheKey = `${fromCurrency}_${baseCurrency}_${effectiveDate || 'latest'}`;

    // Check cache first
    if (this.rateCache.has(cacheKey)) {
      const cached = this.rateCache.get(cacheKey)!;
      const lastUpdate = this.lastRateUpdate.get(cacheKey) || 0;

      if (Date.now() - lastUpdate < this.cacheExpiry) {
        return cached.rate;
      }
    }

    // Get from database
    let query = `
      SELECT * FROM exchange_rates
      WHERE from_currency = ? AND to_currency = ?
    `;
    let params = [fromCurrency, baseCurrency];

    if (effectiveDate) {
      query += ` AND effective_date <= ? AND (expiry_date IS NULL OR expiry_date > ?)`;
      params.push(effectiveDate, effectiveDate);
    } else {
      query += ` AND (expiry_date IS NULL OR expiry_date > ?)`;
      params.push(Date.now());
    }

    query += ` ORDER BY effective_date DESC LIMIT 1`;

    const result = await this.db.prepare(query).bind(...params).first();

    if (result) {
      const rate: ExchangeRate = {
        id: result.id as string,
        fromCurrency: result.from_currency as string,
        toCurrency: result.to_currency as string,
        rate: result.rate as number,
        effectiveDate: result.effective_date as number,
        expiryDate: result.expiry_date as number | undefined,
        source: result.source as string,
        isAutomatic: (result.is_automatic as number) === 1,
        businessId: result.business_id as string
      };

      this.rateCache.set(cacheKey, rate);
      this.lastRateUpdate.set(cacheKey, Date.now());

      return rate.rate;
    }

    // Try to fetch from external API if no rate found
    if (this.kv) {
      try {
        const fetchedRate = await this.fetchExchangeRate(fromCurrency, baseCurrency);
        if (fetchedRate) {
          // Store the fetched rate
          await this.setExchangeRate(
            fromCurrency,
            baseCurrency,
            fetchedRate,
            'system',
            validBusinessId,
            true
          );
          return fetchedRate;
        }
      } catch (error: any) {
        this.logger.warn('Failed to fetch exchange rate from external API', error);
      }
    }

    // Default to 1.0 if no rate found (with warning)
    this.logger.warn('No exchange rate found, defaulting to 1.0', {
      fromCurrency,
      toCurrency: baseCurrency,
      effectiveDate
    });

    return 1.0;
  }

  /**
   * Set exchange rate
   */
  async setExchangeRate(
    fromCurrency: string,
    toCurrency: string,
    rate: number,
    setBy: string,
    businessId: string,
    isAutomatic: boolean = false,
    effectiveDate?: number,
    expiryDate?: number
  ): Promise<string> {
    const validBusinessId = validateBusinessId(businessId);

    if (rate <= 0) {
      throw new Error('Exchange rate must be positive');
    }

    const rateId = `rate_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const effective = effectiveDate || Date.now();

    const exchangeRate: ExchangeRate = {
      id: rateId,
      fromCurrency,
      toCurrency,
      rate,
      effectiveDate: effective,
      expiryDate,
      source: isAutomatic ? 'external_api' : 'manual',
      isAutomatic,
      businessId: validBusinessId
    };

    await this.db.prepare(`
      INSERT INTO exchange_rates (
        id, from_currency, to_currency, rate, effective_date,
        expiry_date, source, is_automatic, business_id,
        created_at, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      rateId,
      fromCurrency,
      toCurrency,
      rate,
      effective,
      expiryDate || null,
      exchangeRate.source,
      isAutomatic ? 1 : 0,
      validBusinessId,
      Date.now(),
      setBy
    ).run();

    // Clear cache
    const cacheKey = `${fromCurrency}_${toCurrency}_latest`;
    this.rateCache.delete(cacheKey);
    this.lastRateUpdate.delete(cacheKey);

    if (!isAutomatic) {
      await this.auditLogger.logAction(
        'currency',
        rateId,
        AuditAction.CREATE,
        validBusinessId,
        setBy,
        { exchangeRate }
      );
    }

    this.logger.info('Exchange rate set', {
      fromCurrency,
      toCurrency,
      rate,
      effectiveDate: effective
    });

    return rateId;
  }

  /**
   * Get exchange rate history
   */
  async getExchangeRateHistory(
    fromCurrency: string,
    toCurrency: string,
    businessId: string,
    startDate?: number,
    endDate?: number
  ): Promise<ExchangeRate[]> {
    const validBusinessId = validateBusinessId(businessId);

    let query = `
      SELECT * FROM exchange_rates
      WHERE from_currency = ? AND to_currency = ? AND business_id = ?
    `;
    let params = [fromCurrency, toCurrency, validBusinessId];

    if (startDate) {
      query += ` AND effective_date >= ?`;
      params.push(startDate);
    }

    if (endDate) {
      query += ` AND effective_date <= ?`;
      params.push(endDate);
    }

    query += ` ORDER BY effective_date DESC`;

    const result = await this.db.prepare(query).bind(...params).all();

    return (result.results || []).map((row: any) => ({
      id: row.id as string,
      fromCurrency: row.from_currency as string,
      toCurrency: row.to_currency as string,
      rate: row.rate as number,
      effectiveDate: row.effective_date as number,
      expiryDate: row.expiry_date as number | undefined,
      source: row.source as string,
      isAutomatic: (row.is_automatic as number) === 1,
      businessId: row.business_id as string
    }));
  }

  /**
   * Convert amount between currencies
   */
  async convertAmount(
    amount: number,
    fromCurrency: string,
    toCurrency: string,
    businessId: string,
    effectiveDate?: number
  ): Promise<{
    convertedAmount: number;
    exchangeRate: number;
    fromCurrency: string;
    toCurrency: string;
  }> {
    if (fromCurrency === toCurrency) {
      return {
        convertedAmount: amount,
        exchangeRate: 1.0,
        fromCurrency,
        toCurrency
      };
    }

    const rate = await this.getExchangeRate(fromCurrency, businessId, effectiveDate);
    const convertedAmount = amount * rate;

    return {
      convertedAmount,
      exchangeRate: rate,
      fromCurrency,
      toCurrency
    };
  }

  /**
   * Format currency amount
   */
  formatCurrency(amount: number, currencyCode: string): string {
    const currency = this.currencyCache.get(currencyCode);
    if (!currency) {
      return `${amount.toFixed(2)} ${currencyCode}`;
    }

    const formatted = amount.toFixed(currency.decimalPlaces);
    return `${currency.symbol}${formatted}`;
  }

  /**
   * Update exchange rates from external API
   */
  async updateExchangeRates(
    baseCurrency: string,
    businessId: string
  ): Promise<{ updated: number; errors: string[] }> {
    const validBusinessId = validateBusinessId(businessId);
    const currencies = await this.getCurrencies();
    const errors: string[] = [];
    let updated = 0;

    for (const currency of currencies) {
      if (currency.code === baseCurrency) continue;

      try {
        const rate = await this.fetchExchangeRate(currency.code, baseCurrency);
        if (rate) {
          await this.setExchangeRate(
            currency.code,
            baseCurrency,
            rate,
            'system',
            validBusinessId,
            true,
            Date.now(),
            Date.now() + 86400000 // Expire in 24 hours
          );
          updated++;
        }
      } catch (error: any) {
        errors.push(`Failed to update ${currency.code}: ${error}`);
      }
    }

    this.logger.info('Exchange rates updated', { updated, errors: errors.length });

    return { updated, errors };
  }

  /**
   * Fetch exchange rate from external API
   */
  private async fetchExchangeRate(
    fromCurrency: string,
    toCurrency: string
  ): Promise<number | null> {
    if (!this.kv) return null;

    try {
      // Check cache first
      const cacheKey = `ext_rate_${fromCurrency}_${toCurrency}`;
      const cached = await this.kv.get(cacheKey, 'json');

      if (cached && typeof cached === 'object' && 'rate' in cached && 'timestamp' in cached) {
        const { rate, timestamp } = cached as { rate: number; timestamp: number };
        if (Date.now() - timestamp < 3600000) { // 1 hour cache
          return rate;
        }
      }

      // Fetch from API (example using exchangerate-api.com)
      const response = await fetch(
        `https://api.exchangerate-api.com/v4/latest/${fromCurrency}`
      );

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }

      const data = await response.json();
      const rate = (data as any).rates?.[toCurrency];

      if (typeof rate !== 'number') {
        throw new Error(`Invalid rate received for ${fromCurrency}/${toCurrency}`);
      }

      // Cache the result
      await this.kv.put(cacheKey, JSON.stringify({
        rate,
        timestamp: Date.now()
      }), { expirationTtl: 3600 }); // 1 hour TTL

      return rate;

    } catch (error: any) {
      this.logger.error('Failed to fetch exchange rate from external API', error, {
        fromCurrency,
        toCurrency
      });
      return null;
    }
  }

  /**
   * Get currency statistics
   */
  async getCurrencyStats(businessId: string): Promise<{
    baseCurrency: string;
    supportedCurrencies: number;
    activeRates: number;
    lastRateUpdate: number | null;
  }> {
    const validBusinessId = validateBusinessId(businessId);

    const [baseCurrency, currencies, ratesResult] = await Promise.all([
      this.getBaseCurrency(validBusinessId),
      this.getCurrencies(),
      this.db.prepare(`
        SELECT COUNT(*) as count, MAX(created_at) as last_update
        FROM exchange_rates
        WHERE business_id = ?
        AND (expiry_date IS NULL OR expiry_date > ?)
      `).bind(validBusinessId, Date.now()).first()
    ]);

    return {
      baseCurrency,
      supportedCurrencies: currencies.length,
      activeRates: (ratesResult?.count as number) || 0,
      lastRateUpdate: (ratesResult?.last_update as number) || null
    };
  }

  /**
   * Clean up expired rates
   */
  async cleanupExpiredRates(): Promise<number> {
    const result = await this.db.prepare(`
      DELETE FROM exchange_rates
      WHERE expiry_date IS NOT NULL
      AND expiry_date < ?
    `).bind(Date.now()).run();

    const deleted = result.meta.changes || 0;

    if (deleted > 0) {
      this.logger.info('Cleaned up expired exchange rates', { deleted });
      // Clear cache
      this.rateCache.clear();
      this.lastRateUpdate.clear();
    }

    return deleted;
  }
}