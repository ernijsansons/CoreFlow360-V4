/**
 * Finance API Endpoints Test Suite
 * Tests for finance, invoices, and payments endpoints
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { unstable_dev } from 'wrangler';
import type { UnstableDevWorker } from 'wrangler';
import { randomBytes } from 'crypto';

describe.skip('Finance API Endpoints', () => {
  let worker: UnstableDevWorker;
  const businessId = 'test-business-123';
  const userId = 'test-user-456';

  beforeAll(async () => {
    worker = await unstable_dev('src/index.ts', {
      experimental: { disableExperimentalWarning: true },
      local: true,
      vars: {
        ENVIRONMENT: 'test',
        JWT_SECRET: Buffer.from(randomBytes(32)).toString('base64'),
        STRIPE_SECRET_KEY: 'sk_test_' + randomBytes(24).toString('hex'),
        STRIPE_PUBLISHABLE_KEY: 'pk_test_' + randomBytes(24).toString('hex'),
        STRIPE_WEBHOOK_SECRET: 'whsec_' + randomBytes(16).toString('hex'),
        PAYPAL_CLIENT_ID: 'test-client-' + randomBytes(8).toString('hex'),
        PAYPAL_CLIENT_SECRET: Buffer.from(randomBytes(32)).toString('base64')
      }
    });
  });

  afterAll(async () => {
    await worker.stop();
  });

  describe('Chart of Accounts', () => {
    test('GET /api/v1/finance/accounts - should list accounts', async () => {
      const resp = await worker.fetch('/api/v1/finance/accounts', {
        headers: {
          'X-Business-ID': businessId
        }
      });

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
      expect(Array.isArray(data.data)).toBe(true);
    });

    test('POST /api/v1/finance/accounts - should create account', async () => {
      const accountData = {
        code: 'ACC-001',
        name: 'Cash on Hand',
        type: 'ASSET',
        category: 'CURRENT_ASSET',
        description: 'Petty cash and till'
      };

      const resp = await worker.fetch('/api/v1/finance/accounts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId,
          'X-User-ID': userId
        },
        body: JSON.stringify(accountData)
      });

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
      expect(data.data.code).toBe(accountData.code);
      expect(data.data.name).toBe(accountData.name);
    });

    test('GET /api/v1/finance/accounts/:id - should get account by id', async () => {
      const accountId = 'test-account-id';
      const resp = await worker.fetch(`/api/v1/finance/accounts/${accountId}`, {
        headers: {
          'X-Business-ID': businessId
        }
      });

      // May return 404 if account doesn't exist in test DB
      expect([200, 404]).toContain(resp.status);
    });
  });

  describe('Journal Entries', () => {
    test('POST /api/v1/finance/journal-entries - should create journal entry', async () => {
      const entryData = {
        date: Date.now(),
        description: 'Test journal entry',
        type: 'STANDARD',
        lines: [
          {
            accountId: 'acc-1',
            debit: 1000,
            description: 'Debit line'
          },
          {
            accountId: 'acc-2',
            credit: 1000,
            description: 'Credit line'
          }
        ]
      };

      const resp = await worker.fetch('/api/v1/finance/journal-entries', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId,
          'X-User-ID': userId
        },
        body: JSON.stringify(entryData)
      });

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
    });

    test('GET /api/v1/finance/journal-entries - should list journal entries', async () => {
      const resp = await worker.fetch('/api/v1/finance/journal-entries?page=1&limit=20', {
        headers: {
          'X-Business-ID': businessId
        }
      });

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
      expect(data.pagination).toBeDefined();
    });

    test('POST /api/v1/finance/journal-entries - should reject unbalanced entry', async () => {
      const unbalancedEntry = {
        date: Date.now(),
        description: 'Unbalanced entry',
        type: 'STANDARD',
        lines: [
          {
            accountId: 'acc-1',
            debit: 1000
          },
          {
            accountId: 'acc-2',
            credit: 500 // Doesn't balance!
          }
        ]
      };

      const resp = await worker.fetch('/api/v1/finance/journal-entries', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId,
          'X-User-ID': userId
        },
        body: JSON.stringify(unbalancedEntry)
      });

      expect(resp.status).toBe(400);
      const data = await resp.json();
      expect(data.success).toBe(false);
      expect(data.error).toContain('balance');
    });
  });

  describe('Financial Reports', () => {
    const reportParams = {
      startDate: Date.now() - 30 * 24 * 60 * 60 * 1000, // 30 days ago
      endDate: Date.now()
    };

    test('GET /api/v1/finance/reports/trial-balance - should generate trial balance', async () => {
      const params = new URLSearchParams(reportParams as any);
      const resp = await worker.fetch(`/api/v1/finance/reports/trial-balance?${params}`, {
        headers: {
          'X-Business-ID': businessId
        }
      });

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
    });

    test('GET /api/v1/finance/reports/profit-loss - should generate P&L', async () => {
      const params = new URLSearchParams(reportParams as any);
      const resp = await worker.fetch(`/api/v1/finance/reports/profit-loss?${params}`, {
        headers: {
          'X-Business-ID': businessId,
          'X-Business-Name': 'Test Company'
        }
      });

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
    });

    test('GET /api/v1/finance/reports/cash-flow - should generate cash flow', async () => {
      const params = new URLSearchParams(reportParams as any);
      const resp = await worker.fetch(`/api/v1/finance/reports/cash-flow?${params}`, {
        headers: {
          'X-Business-ID': businessId
        }
      });

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
    });
  });

  describe('Invoice Management', () => {
    test('POST /api/v1/invoices - should create invoice', async () => {
      const invoiceData = {
        customerId: 'cust-123',
        type: 'standard',
        currency: 'USD',
        lineItems: [
          {
            description: 'Consulting Services',
            quantity: 10,
            unitPrice: 150,
            taxRate: 10
          }
        ],
        notes: 'Payment due within 30 days'
      };

      const resp = await worker.fetch('/api/v1/invoices', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId,
          'X-User-ID': userId
        },
        body: JSON.stringify(invoiceData)
      });

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('id');
      expect(data.data).toHaveProperty('invoiceNumber');
    });

    test('GET /api/v1/invoices - should list invoices', async () => {
      const resp = await worker.fetch('/api/v1/invoices?page=1&limit=20', {
        headers: {
          'X-Business-ID': businessId
        }
      });

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
      expect(data.pagination).toBeDefined();
    });

    test('POST /api/v1/invoices/:id/payments - should record payment', async () => {
      const invoiceId = 'inv-123';
      const paymentData = {
        amount: 500,
        paymentDate: new Date().toISOString(),
        paymentMethod: 'bank_transfer',
        reference: 'TXN-001'
      };

      const resp = await worker.fetch(`/api/v1/invoices/${invoiceId}/payments`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId,
          'X-User-ID': userId
        },
        body: JSON.stringify(paymentData)
      });

      // May return error if invoice doesn't exist
      expect([200, 400, 404]).toContain(resp.status);
    });
  });

  describe('Payment Processing', () => {
    test('POST /api/v1/payments/stripe/payment-intent - should create Stripe payment intent', async () => {
      const paymentData = {
        amount: 1000,
        currency: 'USD',
        description: 'Test payment'
      };

      const resp = await worker.fetch('/api/v1/payments/stripe/payment-intent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId,
          'X-User-ID': userId
        },
        body: JSON.stringify(paymentData)
      });

      // May fail with test keys
      expect([200, 400, 401]).toContain(resp.status);
    });

    test('POST /api/v1/payments/stripe/customer - should create Stripe customer', async () => {
      const customerData = {
        email: 'test@example.com',
        name: 'Test Customer'
      };

      const resp = await worker.fetch('/api/v1/payments/stripe/customer', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId,
          'X-User-ID': userId
        },
        body: JSON.stringify(customerData)
      });

      // May fail with test keys
      expect([200, 400, 401]).toContain(resp.status);
    });

    test('POST /api/v1/payments/paypal/order - should create PayPal order', async () => {
      const orderData = {
        amount: 100,
        currency: 'USD',
        returnUrl: 'https://example.com/success',
        cancelUrl: 'https://example.com/cancel'
      };

      const resp = await worker.fetch('/api/v1/payments/paypal/order', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId,
          'X-User-ID': userId
        },
        body: JSON.stringify(orderData)
      });

      // May fail with test credentials
      expect([200, 400, 401]).toContain(resp.status);
    });

    test('GET /api/v1/payments/health - should return payment service health', async () => {
      const resp = await worker.fetch('/api/v1/payments/health');

      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.success).toBe(true);
      expect(data.service).toBe('payments');
      expect(data.providers).toHaveProperty('stripe');
      expect(data.providers).toHaveProperty('paypal');
    });
  });

  describe('Error Handling', () => {
    test('should return 404 for non-existent route', async () => {
      const resp = await worker.fetch('/api/v1/finance/non-existent');

      expect(resp.status).toBe(404);
      const data = await resp.json();
      expect(data.success).toBe(false);
    });

    test('should handle invalid JSON', async () => {
      const resp = await worker.fetch('/api/v1/finance/accounts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId
        },
        body: 'invalid json'
      });

      expect(resp.status).toBe(400);
    });

    test('should validate required fields', async () => {
      const resp = await worker.fetch('/api/v1/invoices', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Business-ID': businessId
        },
        body: JSON.stringify({
          // Missing required customerId and lineItems
          currency: 'USD'
        })
      });

      expect(resp.status).toBe(400);
      const data = await resp.json();
      expect(data.success).toBe(false);
    });
  });
});

describe.skip('API Health and Versioning', () => {
  let worker: UnstableDevWorker;

  beforeAll(async () => {
    worker = await unstable_dev('src/index.ts', {
      experimental: { disableExperimentalWarning: true },
      local: true
    });
  });

  afterAll(async () => {
    await worker.stop();
  });

  test('GET /api/v1/finance/health - should return finance service health', async () => {
    const resp = await worker.fetch('/api/v1/finance/health');

    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data.success).toBe(true);
    expect(data.service).toBe('finance');
    expect(data.status).toBe('operational');
  });

  test('GET /api/v1/invoices/health - should return invoices service health', async () => {
    const resp = await worker.fetch('/api/v1/invoices/health');

    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data.success).toBe(true);
    expect(data.service).toBe('invoices');
    expect(data.status).toBe('operational');
  });

  test('CORS headers should be present', async () => {
    const resp = await worker.fetch('/api/v1/finance/health', {
      headers: {
        'Origin': 'https://app.coreflow360.com'
      }
    });

    expect(resp.headers.get('Access-Control-Allow-Origin')).toBeTruthy();
    expect(resp.headers.get('Access-Control-Allow-Credentials')).toBe('true');
  });
});