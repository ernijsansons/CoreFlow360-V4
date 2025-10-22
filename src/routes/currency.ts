// @ts-nocheck
/**
 * Currency API Routes
 * Handles multi-currency operations and exchange rates
 */

import { Hono } from 'hono';
import { Logger } from '../shared/logger';
const logger = new Logger({ component: 'currency' });
import type { Env } from '../types/env';
import { CurrencyService } from '../services/currency/currency-service';
import { MultiCurrencyAccountingService } from '../services/currency/multi-currency-accounting-service';

const currency = new Hono<{ Bindings: Env }>();

// ==================
// Middleware
// ==================

// Get business_id from auth context
currency.use('*', async (c, next) => {
  // TODO: Get from JWT token
  const businessId = c.req.header('x-business-id') || 'default-business-id';
  c.set('businessId' as any, businessId);
  await next();
});

// ==================
// Currency Routes
// ==================

/**
 * GET /currency/list
 * Get all active currencies
 */
currency.get('/list', async (c) => {
  try {
    const service = new CurrencyService(c.env);
    const currencies = await service.getActiveCurrencies();

    return c.json({
      success: true,
      data: { currencies },
    });
  } catch (error: any) {
    logger.error('Error listing currencies:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to list currencies',
      },
      500
    );
  }
});

/**
 * GET /currency/settings
 * Get business currency settings
 */
currency.get('/settings', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const service = new CurrencyService(c.env);
    const settings = await service.getBusinessCurrencies(businessId);

    return c.json({
      success: true,
      data: settings,
    });
  } catch (error: any) {
    logger.error('Error getting currency settings:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get currency settings',
      },
      500
    );
  }
});

/**
 * PUT /currency/settings
 * Update business currency settings
 */
currency.put('/settings', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { base_currency, functional_currency, allowed_currencies, auto_conversion } =
      await c.req.json();

    if (!base_currency || !functional_currency || !allowed_currencies) {
      return c.json(
        {
          success: false,
          error: 'base_currency, functional_currency, and allowed_currencies are required',
        },
        400
      );
    }

    const service = new CurrencyService(c.env);
    await service.updateBusinessCurrencies({
      businessId,
      baseCurrency: base_currency,
      functionalCurrency: functional_currency,
      allowedCurrencies: allowed_currencies,
      autoConversion: auto_conversion !== false,
    });

    return c.json({
      success: true,
      data: { message: 'Currency settings updated successfully' },
    });
  } catch (error: any) {
    logger.error('Error updating currency settings:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to update currency settings',
      },
      500
    );
  }
});

/**
 * GET /currency/exchange-rate/:from/:to
 * Get current exchange rate
 */
currency.get('/exchange-rate/:from/:to', async (c) => {
  try {
    const fromCurrency = c.req.param('from').toUpperCase();
    const toCurrency = c.req.param('to').toUpperCase();

    const service = new CurrencyService(c.env);
    const rate = await service.getExchangeRate(fromCurrency, toCurrency);

    return c.json({
      success: true,
      data: {
        from_currency: fromCurrency,
        to_currency: toCurrency,
        rate,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error: any) {
    logger.error('Error getting exchange rate:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get exchange rate',
      },
      500
    );
  }
});

/**
 * POST /currency/convert
 * Convert amount between currencies
 */
currency.post('/convert', async (c) => {
  try {
    const { amount, from_currency, to_currency } = await c.req.json();

    if (!amount || !from_currency || !to_currency) {
      return c.json(
        {
          success: false,
          error: 'amount, from_currency, and to_currency are required',
        },
        400
      );
    }

    const service = new CurrencyService(c.env);
    const result = await service.convertAmount({
      amount: parseFloat(amount),
      fromCurrency: from_currency.toUpperCase(),
      toCurrency: to_currency.toUpperCase(),
    });

    return c.json({
      success: true,
      data: result,
    });
  } catch (error: any) {
    logger.error('Error converting amount:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to convert amount',
      },
      500
    );
  }
});

/**
 * POST /currency/refresh-rates
 * Refresh exchange rates for all allowed currencies
 */
currency.post('/refresh-rates', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const service = new CurrencyService(c.env);
    const refreshedCount = await service.refreshExchangeRates(businessId);

    return c.json({
      success: true,
      data: {
        message: `Refreshed ${refreshedCount} exchange rates`,
        refreshed_count: refreshedCount,
      },
    });
  } catch (error: any) {
    logger.error('Error refreshing exchange rates:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to refresh exchange rates',
      },
      500
    );
  }
});

/**
 * GET /currency/exchange-rate-history/:from/:to
 * Get exchange rate history
 */
currency.get('/exchange-rate-history/:from/:to', async (c) => {
  try {
    const fromCurrency = c.req.param('from').toUpperCase();
    const toCurrency = c.req.param('to').toUpperCase();
    const { start_date, end_date } = c.req.query();

    if (!start_date || !end_date) {
      return c.json(
        {
          success: false,
          error: 'start_date and end_date query parameters are required',
        },
        400
      );
    }

    const service = new CurrencyService(c.env);
    const history = await service.getExchangeRateHistory(
      fromCurrency,
      toCurrency,
      start_date,
      end_date
    );

    return c.json({
      success: true,
      data: {
        from_currency: fromCurrency,
        to_currency: toCurrency,
        history,
      },
    });
  } catch (error: any) {
    logger.error('Error getting exchange rate history:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get exchange rate history',
      },
      500
    );
  }
});

// ==================
// Accounting Routes
// ==================

/**
 * GET /currency/account-balance/:accountId
 * Get account balance in multiple currencies
 */
currency.get('/account-balance/:accountId', async (c) => {
  try {
    const accountId = c.req.param('accountId');
    const { currency: currencyFilter } = c.req.query();

    const service = new MultiCurrencyAccountingService(c.env);
    const balances = await service.getAccountBalance(
      accountId,
      currencyFilter?.toUpperCase()
    );

    return c.json({
      success: true,
      data: { balances },
    });
  } catch (error: any) {
    logger.error('Error getting account balance:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get account balance',
      },
      500
    );
  }
});

/**
 * POST /currency/revalue-balances
 * Revalue all account balances to current exchange rates
 */
currency.post('/revalue-balances', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;

    const service = new MultiCurrencyAccountingService(c.env);
    const result = await service.revalueAccountBalances(businessId);

    return c.json({
      success: true,
      data: result,
    });
  } catch (error: any) {
    logger.error('Error revaluing balances:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to revalue balances',
      },
      500
    );
  }
});

/**
 * GET /currency/trial-balance
 * Get multi-currency trial balance
 */
currency.get('/trial-balance', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { as_of_date, currency: currencyFilter } = c.req.query();

    const service = new MultiCurrencyAccountingService(c.env);
    const trialBalance = await service.getTrialBalance(businessId, {
      asOfDate: as_of_date,
      currency: currencyFilter?.toUpperCase(),
    });

    return c.json({
      success: true,
      data: { trial_balance: trialBalance },
    });
  } catch (error: any) {
    logger.error('Error getting trial balance:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get trial balance',
      },
      500
    );
  }
});

/**
 * GET /currency/gains-losses
 * Get currency gains and losses
 */
currency.get('/gains-losses', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;
    const { currency: currencyFilter, start_date, end_date } = c.req.query();

    const service = new CurrencyService(c.env);
    const gainsLosses = await service.getGainsLosses(businessId, {
      currency: currencyFilter?.toUpperCase(),
      startDate: start_date,
      endDate: end_date,
    });

    return c.json({
      success: true,
      data: { gains_losses: gainsLosses },
    });
  } catch (error: any) {
    logger.error('Error getting gains/losses:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get gains/losses',
      },
      500
    );
  }
});

/**
 * GET /currency/exposure
 * Get currency exposure report
 */
currency.get('/exposure', async (c) => {
  try {
    const businessId = c.get('businessId' as any) as string;

    const service = new MultiCurrencyAccountingService(c.env);
    const exposure = await service.getCurrencyExposure(businessId);

    return c.json({
      success: true,
      data: { exposure },
    });
  } catch (error: any) {
    logger.error('Error getting currency exposure:', error);
    return c.json(
      {
        success: false,
        error: error.message || 'Failed to get currency exposure',
      },
      500
    );
  }
});

export default currency;
