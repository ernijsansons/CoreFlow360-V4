import { http, HttpResponse } from 'msw';

// Type definitions for mock responses
interface StripePaymentIntent {
  id: string;
  amount: number;
  currency: string;
  status: 'requires_payment_method' | 'requires_confirmation' | 'succeeded' | 'canceled';
  client_secret: string;
  metadata: Record<string, string>;
  created: number;
}

interface PayPalOrder {
  id: string;
  status: 'CREATED' | 'APPROVED' | 'COMPLETED' | 'CANCELLED';
  intent: 'CAPTURE' | 'AUTHORIZE';
  purchase_units: Array<{
    amount: {
      currency_code: string;
      value: string;
    };
    reference_id?: string;
  }>;
  create_time: string;
}

interface ExchangeRateResponse {
  base: string;
  date: string;
  rates: Record<string, number>;
  success: boolean;
  timestamp: number;
}

interface TaxCalculationResponse {
  tax: {
    amount_to_collect: number;
    rate: number;
    has_nexus: boolean;
    freight_taxable: boolean;
    tax_source: string;
  };
  jurisdictions: {
    country: string;
    state: string;
    county: string;
    city: string;
  };
}

// MSW Request Handlers
export const handlers = [
  // Stripe Payment Intent API
  http.post('https://api.stripe.com/v1/payment_intents', async ({ request }) => {
    const body = await request.text();
    const params = new URLSearchParams(body);

    const amount = parseInt(params.get('amount') || '0');
    const currency = params.get('currency') || 'usd';

    const paymentIntent: StripePaymentIntent = {
      id: `pi_${Math.random().toString(36).substring(2, 15)}`,
      amount,
      currency,
      status: 'requires_payment_method',
      client_secret: `pi_${Math.random().toString(36).substring(2, 15)}_secret_${Math.random().toString(36).substring(2, 15)}`,
      metadata: {
        business_id: params.get('metadata[business_id]') || '',
        invoice_id: params.get('metadata[invoice_id]') || '',
      },
      created: Math.floor(Date.now() / 1000),
    };

    return HttpResponse.json(paymentIntent);
  }),

  http.get('https://api.stripe.com/v1/payment_intents/:id', ({ params }) => {
    const { id } = params;

    const paymentIntent: StripePaymentIntent = {
      id: id as string,
      amount: 2000,
      currency: 'usd',
      status: 'succeeded',
      client_secret: `${id}_secret_test`,
      metadata: {
        business_id: 'business123',
        invoice_id: 'inv_123',
      },
      created: Math.floor(Date.now() / 1000),
    };

    return HttpResponse.json(paymentIntent);
  }),

  http.post('https://api.stripe.com/v1/payment_intents/:id/confirm', ({ params }) => {
    const { id } = params;

    const confirmedIntent: StripePaymentIntent = {
      id: id as string,
      amount: 2000,
      currency: 'usd',
      status: 'succeeded',
      client_secret: `${id}_secret_test`,
      metadata: {},
      created: Math.floor(Date.now() / 1000),
    };

    return HttpResponse.json(confirmedIntent);
  }),

  // Stripe Webhook Events
  http.post('https://api.stripe.com/v1/webhook_endpoints', () => {
    return HttpResponse.json({
      id: `we_${Math.random().toString(36).substring(2, 15)}`,
      object: 'webhook_endpoint',
      url: 'https://api.coreflow360.com/webhooks/stripe',
      enabled_events: ['payment_intent.succeeded', 'payment_intent.payment_failed'],
      status: 'enabled',
      created: Math.floor(Date.now() / 1000),
    });
  }),

  // PayPal Orders API
  http.post('https://api.paypal.com/v2/checkout/orders', async ({ request }) => {
    const body = await request.json() as any;

    const order: PayPalOrder = {
      id: `ORDER_${Math.random().toString(36).substring(2, 15).toUpperCase()}`,
      status: 'CREATED',
      intent: body.intent || 'CAPTURE',
      purchase_units: body.purchase_units || [],
      create_time: new Date().toISOString(),
    };

    return HttpResponse.json(order);
  }),

  http.get('https://api.paypal.com/v2/checkout/orders/:id', ({ params }) => {
    const { id } = params;

    const order: PayPalOrder = {
      id: id as string,
      status: 'APPROVED',
      intent: 'CAPTURE',
      purchase_units: [
        {
          amount: {
            currency_code: 'USD',
            value: '100.00',
          },
          reference_id: 'invoice_123',
        },
      ],
      create_time: new Date().toISOString(),
    };

    return HttpResponse.json(order);
  }),

  http.post('https://api.paypal.com/v2/checkout/orders/:id/capture', ({ params }) => {
    const { id } = params;

    const capturedOrder: PayPalOrder = {
      id: id as string,
      status: 'COMPLETED',
      intent: 'CAPTURE',
      purchase_units: [
        {
          amount: {
            currency_code: 'USD',
            value: '100.00',
          },
        },
      ],
      create_time: new Date().toISOString(),
    };

    return HttpResponse.json(capturedOrder);
  }),

  // PayPal OAuth Token
  http.post('https://api.paypal.com/v1/oauth2/token', () => {
    return HttpResponse.json({
      scope: 'https://uri.paypal.com/services/checkout/one-click-payment',
      access_token: `A21AAK${Math.random().toString(36).substring(2, 50)}`,
      token_type: 'Bearer',
      app_id: 'APP-80W284485P519543T',
      expires_in: 32400,
      nonce: `${Date.now()}_${Math.random().toString(36).substring(2, 15)}`,
    });
  }),

  // Exchange Rate API (example: fixer.io or exchangerate-api.com)
  http.get('https://api.exchangerate-api.com/v4/latest/:base', ({ params, request }) => {
    const { base } = params;
    const url = new URL(request.url);
    const symbols = url.searchParams.get('symbols');

    const baseRates: Record<string, Record<string, number>> = {
      USD: { EUR: 0.85, GBP: 0.73, CAD: 1.25, AUD: 1.35, JPY: 110.0 },
      EUR: { USD: 1.18, GBP: 0.86, CAD: 1.47, AUD: 1.59, JPY: 129.5 },
      GBP: { USD: 1.37, EUR: 1.16, CAD: 1.71, AUD: 1.85, JPY: 150.8 },
    };

    const rates = baseRates[base as string] || baseRates.USD;

    let filteredRates = rates;
    if (symbols) {
      const symbolList = symbols.split(',');
      filteredRates = {};
      symbolList.forEach(symbol => {
        if (rates[symbol]) {
          filteredRates[symbol] = rates[symbol];
        }
      });
    }

    const response: ExchangeRateResponse = {
      base: base as string,
      date: new Date().toISOString().split('T')[0],
      rates: filteredRates,
      success: true,
      timestamp: Math.floor(Date.now() / 1000),
    };

    return HttpResponse.json(response);
  }),

  // Alternative exchange rate API (fixer.io)
  http.get('https://api.fixer.io/latest', ({ request }) => {
    const url = new URL(request.url);
    const base = url.searchParams.get('base') || 'EUR';
    const symbols = url.searchParams.get('symbols');

    const rates = {
      USD: 1.18,
      GBP: 0.86,
      CAD: 1.47,
      AUD: 1.59,
      JPY: 129.5,
    };

    let filteredRates = rates;
    if (symbols) {
      const symbolList = symbols.split(',');
      filteredRates = {};
      symbolList.forEach(symbol => {
        if (rates[symbol as keyof typeof rates]) {
          filteredRates[symbol as keyof typeof rates] = rates[symbol as keyof typeof rates];
        }
      });
    }

    return HttpResponse.json({
      success: true,
      timestamp: Math.floor(Date.now() / 1000),
      base,
      date: new Date().toISOString().split('T')[0],
      rates: filteredRates,
    });
  }),

  // Tax Calculation API (example: TaxJar)
  http.post('https://api.taxjar.com/v2/taxes', async ({ request }) => {
    const body = await request.json() as any;

    // Simulate tax calculation based on location and amount
    const amount = parseFloat(body.amount || '0');
    const state = body.to_state || 'CA';

    // Mock tax rates by state
    const stateTaxRates: Record<string, number> = {
      CA: 0.0725,  // California
      NY: 0.08,    // New York
      TX: 0.0625,  // Texas
      FL: 0.06,    // Florida
      WA: 0.065,   // Washington
    };

    const taxRate = stateTaxRates[state] || 0.05;
    const taxAmount = amount * taxRate;

    const response: TaxCalculationResponse = {
      tax: {
        amount_to_collect: Math.round(taxAmount * 100) / 100,
        rate: taxRate,
        has_nexus: true,
        freight_taxable: false,
        tax_source: 'destination',
      },
      jurisdictions: {
        country: 'US',
        state: state,
        county: 'Test County',
        city: 'Test City',
      },
    };

    return HttpResponse.json(response);
  }),

  // Tax rates lookup
  http.get('https://api.taxjar.com/v2/rates/:zip', ({ params }) => {
    const { zip } = params;

    return HttpResponse.json({
      rate: {
        zip: zip,
        state: 'CA',
        state_rate: '0.0625',
        county_rate: '0.0025',
        city_rate: '0.01',
        combined_district_rate: '0.0',
        combined_rate: '0.075',
        freight_taxable: false,
      },
    });
  }),

  // Email Service API (example: SendGrid)
  http.post('https://api.sendgrid.com/v3/mail/send', async ({ request }) => {
    const body = await request.json() as any;

    // Simulate successful email sending
    return HttpResponse.json({
      message: 'Email sent successfully',
      id: `email_${Math.random().toString(36).substring(2, 15)}`,
    }, { status: 202 });
  }),

  // SMS Service API (example: Twilio)
  http.post('https://api.twilio.com/2010-04-01/Accounts/:accountSid/Messages.json', ({ params }) => {
    const { accountSid } = params;

    return HttpResponse.json({
      sid: `SM${Math.random().toString(36).substring(2, 32).toUpperCase()}`,
      account_sid: accountSid,
      status: 'queued',
      direction: 'outbound-api',
      date_created: new Date().toISOString(),
      date_updated: new Date().toISOString(),
      price: null,
      price_unit: 'USD',
    });
  }),

  // Banking API (example: Plaid)
  http.post('https://production.plaid.com/transactions/get', async ({ request }) => {
    const body = await request.json() as any;

    return HttpResponse.json({
      accounts: [
        {
          account_id: 'acc_123',
          name: 'Business Checking',
          type: 'depository',
          subtype: 'checking',
          balances: {
            available: 25000.50,
            current: 25000.50,
            limit: null,
            iso_currency_code: 'USD',
          },
        },
      ],
      transactions: [
        {
          transaction_id: 'txn_123',
          account_id: 'acc_123',
          amount: 1250.00,
          date: new Date().toISOString().split('T')[0],
          name: 'Customer Payment',
          merchant_name: 'Customer Inc',
          category: ['Transfer', 'Deposit'],
          category_id: '21006000',
          account_owner: null,
          pending: false,
        },
      ],
      total_transactions: 1,
      request_id: `req_${Math.random().toString(36).substring(2, 15)}`,
    });
  }),

  // AI/ML Service API (example: OpenAI)
  http.post('https://api.openai.com/v1/chat/completions', async ({ request }) => {
    const body = await request.json() as any;

    // Mock AI responses based on the prompt
    const messages = body.messages || [];
    const lastMessage = messages[messages.length - 1]?.content || '';

    let mockResponse = 'This is a mock AI response for testing purposes.';

    if (lastMessage.includes('invoice')) {
      mockResponse = 'Based on the invoice data, I recommend following up with the customer in 7 days if payment is not received.';
    } else if (lastMessage.includes('financial')) {
      mockResponse = 'The financial analysis shows positive cash flow trends with a 15% increase over the previous quarter.';
    } else if (lastMessage.includes('customer')) {
      mockResponse = 'Customer sentiment analysis indicates high satisfaction with a positive engagement score of 8.5/10.';
    }

    return HttpResponse.json({
      id: `chatcmpl-${Math.random().toString(36).substring(2, 15)}`,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: body.model || 'gpt-3.5-turbo',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: mockResponse,
          },
          finish_reason: 'stop',
        },
      ],
      usage: {
        prompt_tokens: 50,
        completion_tokens: 25,
        total_tokens: 75,
      },
    });
  }),

  // Document Storage API (example: AWS S3 or Cloudflare R2)
  http.put('https://storage.googleapis.com/:bucket/:key', ({ params }) => {
    const { bucket, key } = params;

    return HttpResponse.json({
      bucket,
      key,
      etag: `"${Math.random().toString(36).substring(2, 32)}"`,
      location: `https://storage.googleapis.com/${bucket}/${key}`,
      size: 1024,
      content_type: 'application/pdf',
    });
  }),

  http.get('https://storage.googleapis.com/:bucket/:key', ({ params }) => {
    const { bucket, key } = params;

    // Return mock PDF content
    return HttpResponse.arrayBuffer(
      new ArrayBuffer(1024),
      {
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Length': '1024',
          'ETag': `"${Math.random().toString(36).substring(2, 32)}"`,
        },
      }
    );
  }),

  // Analytics API (example: Google Analytics)
  http.post('https://www.googleapis.com/analytics/v3/data/ga', () => {
    return HttpResponse.json({
      kind: 'analytics#gaData',
      id: 'https://www.googleapis.com/analytics/v3/data/ga',
      totalResults: 1,
      rows: [
        ['20241201', '100', '2500.00', '0.25'],
      ],
      columnHeaders: [
        { name: 'ga:date', columnType: 'DIMENSION', dataType: 'STRING' },
        { name: 'ga:sessions', columnType: 'METRIC', dataType: 'INTEGER' },
        { name: 'ga:revenue', columnType: 'METRIC', dataType: 'CURRENCY' },
        { name: 'ga:conversionRate', columnType: 'METRIC', dataType: 'PERCENT' },
      ],
    });
  }),

  // Error simulation endpoints for testing error handling
  http.get('https://api.test.com/error/500', () => {
    return HttpResponse.json(
      { error: 'Internal Server Error', message: 'Simulated server error' },
      { status: 500 }
    );
  }),

  http.get('https://api.test.com/error/timeout', () => {
    // Simulate timeout by delaying response
    return new Promise(() => {
      // Never resolve to simulate timeout
    });
  }),

  http.get('https://api.test.com/error/rate-limit', () => {
    return HttpResponse.json(
      { error: 'Rate limit exceeded', retry_after: 60 },
      { status: 429 }
    );
  }),

  // Health check endpoints
  http.get('https://api.stripe.com/v1/ping', () => {
    return HttpResponse.json({ status: 'ok' });
  }),

  http.get('https://api.paypal.com/v1/oauth2/token/userinfo', () => {
    return HttpResponse.json({
      user_id: 'test_user',
      name: 'Test User',
      email: 'test@example.com',
    });
  }),

  // Fallback handler for unmatched requests
  http.all('*', ({ request }) => {
    console.warn(`Unhandled ${request.method} request to ${request.url}`);
    return HttpResponse.json(
      { error: 'Not Found', message: 'Mock handler not implemented' },
      { status: 404 }
    );
  }),
];

// Helper functions for dynamic mock responses
export const createMockStripePaymentIntent = (overrides: Partial<StripePaymentIntent> = {}): StripePaymentIntent => ({
  id: `pi_${Math.random().toString(36).substring(2, 15)}`,
  amount: 2000,
  currency: 'usd',
  status: 'requires_payment_method',
  client_secret: `pi_test_${Math.random().toString(36).substring(2, 15)}`,
  metadata: {},
  created: Math.floor(Date.now() / 1000),
  ...overrides,
});

export const createMockPayPalOrder = (overrides: Partial<PayPalOrder> = {}): PayPalOrder => ({
  id: `ORDER_${Math.random().toString(36).substring(2, 15).toUpperCase()}`,
  status: 'CREATED',
  intent: 'CAPTURE',
  purchase_units: [],
  create_time: new Date().toISOString(),
  ...overrides,
});

// Error simulation helpers
export const simulateNetworkError = () => {
  throw new Error('Network error: Failed to fetch');
};

export const simulateTimeoutError = () => {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error('Request timeout')), 5000);
  });
};

// Mock data generators
export const generateMockTransactionData = (count: number = 10) => {
  return Array.from({ length: count }, (_, i) => ({
    transaction_id: `txn_${i + 1}`,
    account_id: 'acc_123',
    amount: parseFloat((Math.random() * 1000).toFixed(2)),
    date: new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    name: `Transaction ${i + 1}`,
    category: ['Transfer', 'Deposit'],
    pending: false,
  }));
};

export const generateMockExchangeRates = (baseCurrency: string = 'USD') => {
  const rates: Record<string, number> = {};
  const currencies = ['EUR', 'GBP', 'CAD', 'AUD', 'JPY', 'CHF', 'CNY'];

  currencies.forEach(currency => {
    if (currency !== baseCurrency) {
      rates[currency] = parseFloat((Math.random() * 2 + 0.5).toFixed(4));
    }
  });

  return rates;
};

export default handlers;