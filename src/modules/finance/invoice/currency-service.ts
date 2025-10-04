/**
 * Multi-Currency Service
 * Advanced currency conversion and formatting with real-time rates
 */

import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'

export interface Currency {
  code: string
  name: string
  symbol: string
  decimalPlaces: number
  isActive: boolean
  isBaseCurrency: boolean
}

export interface ExchangeRate {
  id: string
  fromCurrency: string
  toCurrency: string
  rate: number
  timestamp: string
  source: 'manual' | 'api' | 'bank'
  expiresAt?: string
}

export interface CurrencyConversionRequest {
  amount: number
  fromCurrency: string
  toCurrency: string
  date?: string
  useHistoricalRate?: boolean
}

export interface CurrencyConversionResult {
  originalAmount: number
  convertedAmount: number
  fromCurrency: string
  toCurrency: string
  exchangeRate: number
  conversionDate: string
  rateSource: string
  rateTimestamp: string
}

export interface CurrencyFormattingOptions {
  locale?: string
  notation?: 'standard' | 'compact'
  showCurrencyCode?: boolean
  minimumFractionDigits?: number
  maximumFractionDigits?: number
}

export // TODO: Consider splitting CurrencyService into smaller, focused classes
class CurrencyService {
  private currencies: Map<string, Currency> = new Map()
  private exchangeRates: Map<string, ExchangeRate> = new Map()
  private rateCache: Map<string, { rate: number; timestamp: number; ttl: number }> = new Map()
  private baseCurrency: string = 'USD'
  private apiKey?: string
  private rateProvider: 'fixer' | 'exchangerate' | 'openexchange' = 'fixer'

  constructor(config?: {
    baseCurrency?: string
    apiKey?: string
    rateProvider?: typeof this.rateProvider
  }) {
    if (config?.baseCurrency) this.baseCurrency = config.baseCurrency
    if (config?.apiKey) this.apiKey = config.apiKey
    if (config?.rateProvider) this.rateProvider = config.rateProvider

    this.initializeDefaultCurrencies()
  }

  async convertCurrency(request: CurrencyConversionRequest): Promise<CurrencyConversionResult> {
    try {
      auditLogger.log({
        action: 'currency_conversion_started',
        metadata: {
          amount: request.amount,
          fromCurrency: request.fromCurrency,
          toCurrency: request.toCurrency,
          date: request.date
        }
      })

      // Validate request
      this.validateConversionRequest(request)

      // If same currency, return as-is
      if (request.fromCurrency === request.toCurrency) {
        return {
          originalAmount: request.amount,
          convertedAmount: request.amount,
          fromCurrency: request.fromCurrency,
          toCurrency: request.toCurrency,
          exchangeRate: 1,
          conversionDate: request.date || new Date().toISOString(),
          rateSource: 'same_currency',
          rateTimestamp: new Date().toISOString()
        }
      }

      // Get exchange rate
      const exchangeRateData = await this.getExchangeRate(
        request.fromCurrency,
        request.toCurrency,
        request.date,
        request.useHistoricalRate
      )

      // Calculate converted amount
      const convertedAmount = this.roundToDecimalPlaces(
        request.amount * exchangeRateData.rate,
        request.toCurrency
      )

      const result: CurrencyConversionResult = {
        originalAmount: request.amount,
        convertedAmount,
        fromCurrency: request.fromCurrency,
        toCurrency: request.toCurrency,
        exchangeRate: exchangeRateData.rate,
        conversionDate: request.date || new Date().toISOString(),
        rateSource: exchangeRateData.source,
        rateTimestamp: exchangeRateData.timestamp
      }

      auditLogger.log({
        action: 'currency_conversion_completed',
        metadata: {
          ...result,
          rateUsed: exchangeRateData.rate
        }
      })

      return result

    } catch (error: any) {
      auditLogger.log({
        action: 'currency_conversion_failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: request
      })

      throw new AppError(
        'Currency conversion failed',
        'CURRENCY_CONVERSION_ERROR',
        500,
        { originalError: error, request }
      )
    }
  }

  async getExchangeRate(
    fromCurrency: string,
    toCurrency: string,
    date?: string,
    useHistoricalRate = false
  ): Promise<ExchangeRate> {
    const rateKey = `${fromCurrency}-${toCurrency}-${date || 'current'}`

    // Check cache first
    const cachedRate = this.rateCache.get(rateKey)
    if (cachedRate && Date.now() < cachedRate.timestamp + cachedRate.ttl) {
      return {
        id: `cached-${rateKey}`,
        fromCurrency,
        toCurrency,
        rate: cachedRate.rate,
        timestamp: new Date(cachedRate.timestamp).toISOString(),
        source: 'api'
      }
    }

    // Check stored rates
    const storedRate = this.exchangeRates.get(rateKey)
    if (storedRate && (!storedRate.expiresAt || new Date() < new Date(storedRate.expiresAt))) {
      return storedRate
    }

    // Fetch from external API
    if (useHistoricalRate && date) {
      return await this.fetchHistoricalRate(fromCurrency, toCurrency, date)
    } else {
      return await this.fetchCurrentRate(fromCurrency, toCurrency)
    }
  }

  private async fetchCurrentRate(fromCurrency: string, toCurrency: string): Promise<ExchangeRate> {
    if (!this.apiKey) {
      throw new AppError(
        'Exchange rate API key not configured',
        'MISSING_API_KEY',
        500
      )
    }

    try {
      let rate: number
      let timestamp: string
      let source: ExchangeRate['source'] = 'api'

      switch (this.rateProvider) {
        case 'fixer':
          ({ rate, timestamp } = await this.fetchFromFixer(fromCurrency, toCurrency))
          break
        case 'exchangerate':
          ({ rate, timestamp } = await this.fetchFromExchangeRateAPI(fromCurrency, toCurrency))
          break
        case 'openexchange':
          ({ rate, timestamp } = await this.fetchFromOpenExchange(fromCurrency, toCurrency))
          break
        default:
          throw new AppError('Invalid rate provider', 'INVALID_RATE_PROVIDER', 500)
      }

      const exchangeRate: ExchangeRate = {
        id: `${fromCurrency}-${toCurrency}-${Date.now()}`,
        fromCurrency,
        toCurrency,
        rate,
        timestamp,
        source,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString() // 15 minutes
      }

      // Cache the rate
      this.rateCache.set(`${fromCurrency}-${toCurrency}-current`, {
        rate,
        timestamp: Date.now(),
        ttl: 15 * 60 * 1000 // 15 minutes
      })

      // Store the rate
      this.exchangeRates.set(`${fromCurrency}-${toCurrency}-current`, exchangeRate)

      return exchangeRate

    } catch (error: any) {
      throw new AppError(
        `Failed to fetch exchange rate from ${this.rateProvider}`,
        'RATE_FETCH_ERROR',
        500,
        { fromCurrency, toCurrency, provider: this.rateProvider, originalError: error }
      )
    }
  }

  private async fetchHistoricalRate(
    fromCurrency: string,
    toCurrency: string,
    date: string
  ): Promise<ExchangeRate> {
    // Historical rates are typically cached longer and don't expire
    const rateKey = `${fromCurrency}-${toCurrency}-${date}`
    const storedRate = this.exchangeRates.get(rateKey)

    if (storedRate) {
      return storedRate
    }

    // Fetch historical rate from API
    if (!this.apiKey) {
      throw new AppError(
        'Exchange rate API key not configured',
        'MISSING_API_KEY',
        500
      )
    }

    try {
      let rate: number
      let timestamp: string

      switch (this.rateProvider) {
        case 'fixer':
          ({ rate, timestamp } = await this.fetchHistoricalFromFixer(fromCurrency, toCurrency, date))
          break
        case 'exchangerate':
          ({ rate, timestamp } = await this.fetchHistoricalFromExchangeRateAPI(fromCurrency, toCurrency, date))
          break
        case 'openexchange':
          ({ rate, timestamp } = await this.fetchHistoricalFromOpenExchange(fromCurrency, toCurrency, date))
          break
        default:
          throw new AppError('Invalid rate provider', 'INVALID_RATE_PROVIDER', 500)
      }

      const exchangeRate: ExchangeRate = {
        id: `${fromCurrency}-${toCurrency}-${date}`,
        fromCurrency,
        toCurrency,
        rate,
        timestamp,
        source: 'api'
      }

      // Store historical rate (no expiration)
      this.exchangeRates.set(rateKey, exchangeRate)

      return exchangeRate

    } catch (error: any) {
      throw new AppError(
        `Failed to fetch historical exchange rate`,
        'HISTORICAL_RATE_FETCH_ERROR',
        500,
        { fromCurrency, toCurrency, date, originalError: error }
      )
    }
  }

  private async fetchFromFixer(fromCurrency: string, toCurrency: string): Promise<{ rate: number; timestamp: string }> {
    const response = await fetch(
      `https://api.fixer.io/latest?access_key=${this.apiKey}&base=${fromCurrency}&symbols=${toCurrency}`
    )

    if (!response.ok) {
      throw new Error(`Fixer API error: ${response.status}`)
    }

    const data = await response.json()

    if (!(data as any).success) {
      throw new Error(`Fixer API error: ${(data as any).error?.info || 'Unknown error'}`)
    }

    return {
      rate: (data as any).rates[toCurrency],
      timestamp: new Date((data as any).timestamp * 1000).toISOString()
    }
  }

  private async fetchFromExchangeRateAPI(fromCurrency: string, toCurrency:
  string): Promise<{ rate: number; timestamp: string }> {
    const response = await fetch(
      `https://api.exchangerate-api.com/v4/latest/${fromCurrency}`
    )

    if (!response.ok) {
      throw new Error(`ExchangeRate-API error: ${response.status}`)
    }

    const data = await response.json()

    return {
      rate: (data as any).rates[toCurrency],
      timestamp: new Date((data as any).date).toISOString()
    }
  }

  private async fetchFromOpenExchange(fromCurrency: string, toCurrency:
  string): Promise<{ rate: number; timestamp: string }> {
    const response = await fetch(
      `https://openexchangerates.org/api/latest.json?app_id=${this.apiKey}&base=${fromCurrency}&symbols=${toCurrency}`
    )

    if (!response.ok) {
      throw new Error(`Open Exchange Rates error: ${response.status}`)
    }

    const data = await response.json()

    return {
      rate: (data as any).rates[toCurrency],
      timestamp: new Date((data as any).timestamp * 1000).toISOString()
    }
  }

  private async fetchHistoricalFromFixer(fromCurrency: string, toCurrency: string,
  date: string): Promise<{ rate: number; timestamp: string }> {
    const dateStr = date.split('T')[0] // Get YYYY-MM-DD format
    const response = await fetch(
      `https://api.fixer.io/${dateStr}?access_key=${this.apiKey}&base=${fromCurrency}&symbols=${toCurrency}`
    )

    if (!response.ok) {
      throw new Error(`Fixer API error: ${response.status}`)
    }

    const data = await response.json()

    if (!(data as any).success) {
      throw new Error(`Fixer API error: ${(data as any).error?.info || 'Unknown error'}`)
    }

    return {
      rate: (data as any).rates[toCurrency],
      timestamp: new Date((data as any).date).toISOString()
    }
  }

  private async fetchHistoricalFromExchangeRateAPI(fromCurrency: string, toCurrency: string,
  date: string): Promise<{ rate: number; timestamp: string }> {
    const dateStr = date.split('T')[0]
    const response = await fetch(
      `https://api.exchangerate-api.com/v4/history/${fromCurrency}/${dateStr}`
    )

    if (!response.ok) {
      throw new Error(`ExchangeRate-API error: ${response.status}`)
    }

    const data = await response.json()

    return {
      rate: (data as any).rates[toCurrency],
      timestamp: new Date((data as any).date).toISOString()
    }
  }

  private async fetchHistoricalFromOpenExchange(fromCurrency: string, toCurrency: string,
  date: string): Promise<{ rate: number; timestamp: string }> {
    const dateStr = date.split('T')[0]
    const response = await fetch(
      `https://openexchangerates.org/api/historical/${dateStr}.json?app_id=${this.apiKey}&base=${fromCurrency}&symbols=${toCurrency}`
    )

    if (!response.ok) {
      throw new Error(`Open Exchange Rates error: ${response.status}`)
    }

    const data = await response.json()

    return {
      rate: (data as any).rates[toCurrency],
      timestamp: new Date((data as any).timestamp * 1000).toISOString()
    }
  }

  formatCurrency(
    amount: number,
    currencyCode: string,
    options: CurrencyFormattingOptions = {}
  ): string {
    const currency = this.currencies.get(currencyCode)
    if (!currency) {
      throw new AppError(
        `Currency ${currencyCode} not found`,
        'CURRENCY_NOT_FOUND',
        400
      )
    }

    const locale = options.locale || 'en-US'
    const formatter = new Intl.NumberFormat(locale, {
      style: 'currency',
      currency: currencyCode,
      notation: options.notation || 'standard',
      minimumFractionDigits: options.minimumFractionDigits ?? currency.decimalPlaces,
      maximumFractionDigits: options.maximumFractionDigits ?? currency.decimalPlaces
    })

    let formatted = formatter.format(amount)

    // Add currency code if requested
    if (options.showCurrencyCode && !formatted.includes(currencyCode)) {
      formatted = `${formatted} ${currencyCode}`
    }

    return formatted
  }

  private validateConversionRequest(request: CurrencyConversionRequest): void {
    if (!request.fromCurrency || !request.toCurrency) {
      throw new AppError(
        'From and to currencies are required',
        'INVALID_CURRENCY_REQUEST',
        400
      )
    }

    if (!this.currencies.has(request.fromCurrency)) {
      throw new AppError(
        `Currency ${request.fromCurrency} not supported`,
        'UNSUPPORTED_CURRENCY',
        400
      )
    }

    if (!this.currencies.has(request.toCurrency)) {
      throw new AppError(
        `Currency ${request.toCurrency} not supported`,
        'UNSUPPORTED_CURRENCY',
        400
      )
    }

    if (typeof request.amount !== 'number' || request.amount < 0) {
      throw new AppError(
        'Amount must be a non-negative number',
        'INVALID_AMOUNT',
        400
      )
    }

    if (request.date && !this.isValidDate(request.date)) {
      throw new AppError(
        'Invalid date format',
        'INVALID_DATE',
        400
      )
    }
  }

  private isValidDate(dateString: string): boolean {
    const date = new Date(dateString)
    return !isNaN(date.getTime())
  }

  private roundToDecimalPlaces(amount: number, currencyCode: string): number {
    const currency = this.currencies.get(currencyCode)
    const decimalPlaces = currency?.decimalPlaces || 2
    return Math.round(amount * Math.pow(10, decimalPlaces)) / Math.pow(10, decimalPlaces)
  }

  private initializeDefaultCurrencies(): void {
    const defaultCurrencies: Currency[] = [
      { code: 'USD', name: 'US Dollar', symbol: '$', decimalPlaces: 2, isActive: true, isBaseCurrency: true },
      { code: 'EUR', name: 'Euro', symbol: '€', decimalPlaces: 2, isActive: true, isBaseCurrency: false },
      { code: 'GBP', name: 'British Pound', symbol: '£', decimalPlaces: 2, isActive: true, isBaseCurrency: false },
      { code: 'CAD', name: 'Canadian Dollar', symbol: 'C$', decimalPlaces: 2, isActive: true, isBaseCurrency: false },
      { code: 'AUD', name: 'Australian Dollar', symbol: 'A$', decimalPlaces: 2, isActive: true, isBaseCurrency: false },
      { code: 'JPY', name: 'Japanese Yen', symbol: '¥', decimalPlaces: 0, isActive: true, isBaseCurrency: false },
      { code: 'CHF', name: 'Swiss Franc', symbol: 'CHF', decimalPlaces: 2, isActive: true, isBaseCurrency: false },
      { code: 'CNY', name: 'Chinese Yuan', symbol: '¥', decimalPlaces: 2, isActive: true, isBaseCurrency: false },
      { code: 'INR', name: 'Indian Rupee', symbol: '₹', decimalPlaces: 2, isActive: true, isBaseCurrency: false },
      { code: 'BRL', name: 'Brazilian Real', symbol: 'R$', decimalPlaces: 2, isActive: true, isBaseCurrency: false }
    ]

    for (const currency of defaultCurrencies) {
      this.currencies.set(currency.code, currency)
    }
  }

  // Public methods for currency management
  async getSupportedCurrencies(): Promise<Currency[]> {
    return Array.from(this.currencies.values()).filter((c: any) => c.isActive)
  }

  async addCurrency(currency: Omit<Currency, 'isActive'>): Promise<Currency> {
    const newCurrency: Currency = { ...currency, isActive: true }
    this.currencies.set(currency.code, newCurrency)

    auditLogger.log({
      action: 'currency_added',
      metadata: { currencyCode: currency.code, name: currency.name }
    })

    return newCurrency
  }

  async setManualExchangeRate(
    fromCurrency: string,
    toCurrency: string,
    rate: number,
    expiresAt?: string
  ): Promise<ExchangeRate> {
    const exchangeRate: ExchangeRate = {
      id: `manual-${fromCurrency}-${toCurrency}-${Date.now()}`,
      fromCurrency,
      toCurrency,
      rate,
      timestamp: new Date().toISOString(),
      source: 'manual',
      expiresAt
    }

    this.exchangeRates.set(`${fromCurrency}-${toCurrency}-current`, exchangeRate)

    auditLogger.log({
      action: 'manual_exchange_rate_set',
      metadata: { fromCurrency, toCurrency, rate, expiresAt }
    })

    return exchangeRate
  }

  getBaseCurrency(): string {
    return this.baseCurrency
  }

  setBaseCurrency(currencyCode: string): void {
    if (!this.currencies.has(currencyCode)) {
      throw new AppError(
        `Currency ${currencyCode} not supported`,
        'UNSUPPORTED_CURRENCY',
        400
      )
    }

    // Update base currency flags
    for (const [code, currency] of this.currencies) {
      currency.isBaseCurrency = code === currencyCode
    }

    this.baseCurrency = currencyCode

    auditLogger.log({
      action: 'base_currency_changed',
      metadata: { newBaseCurrency: currencyCode }
    })
  }
}