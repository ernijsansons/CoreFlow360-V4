import { describe, it, expect, beforeEach, afterEach, vi, MockedFunction } from 'vitest';
import { InvoiceManager } from '../../../modules/finance/invoice-manager';
import { JournalEntryManager } from '../../../modules/finance/journal-entry-manager';
import { FinanceAuditLogger } from '../../../modules/finance/audit-logger';
import { CurrencyManager } from '../../../modules/finance/currency-manager';
import { Logger } from '../../../shared/logger';
import {
  Invoice,
  InvoiceStatus,
  ApprovalStatus,
  CreateInvoiceRequest,
  UpdateInvoiceRequest,
  JournalEntryType,
  PaymentTermType
} from '../../../modules/finance/types';
import type { D1Database, KVNamespace } from '@cloudflare/workers-types';

// Mock dependencies
const mockD1Database = {
  prepare: vi.fn(),
  batch: vi.fn(),
  exec: vi.fn(),
};

const mockPreparedStatement = {
  bind: vi.fn(),
  first: vi.fn(),
  all: vi.fn(),
  run: vi.fn(),
};

const mockKV: Partial<KVNamespace> = {
  get: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
};

// Mock Logger
vi.mock('../../../shared/logger', () => ({
  Logger: vi.fn().mockImplementation(() => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  })),
}));

// Mock utility functions
vi.mock('../../../modules/finance/utils', () => ({
  validateBusinessId: vi.fn().mockImplementation((id) => id),
  generateInvoiceNumber: vi.fn().mockResolvedValue('INV-2024-001'),
  roundToCurrency: vi.fn().mockImplementation((amount) => Math.round(amount * 100) / 100),
}));

describe('InvoiceManager', () => {
  let invoiceManager: InvoiceManager;
  let mockJournalManager: any;
  let mockAuditLogger: any;
  let mockCurrencyManager: any;

  const mockCustomer = {
    id: 'customer123',
    name: 'Test Customer',
    email: 'test@customer.com',
    currency: 'USD',
    paymentTerms: { type: PaymentTermType.NET, days: 30 },
    billingAddress: {
      street: '123 Main St',
      city: 'Test City',
      state: 'TS',
      zipCode: '12345',
      country: 'US'
    },
    shippingAddress: {
      street: '123 Main St',
      city: 'Test City',
      state: 'TS',
      zipCode: '12345',
      country: 'US'
    },
    isActive: true,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    businessId: 'business123'
  };

  const mockInvoiceRequest: CreateInvoiceRequest = {
    customerId: 'customer123',
    issueDate: Date.now(),
    dueDate: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
    currency: 'USD',
    lines: [
      {
        description: 'Product 1',
        quantity: 2,
        unitPrice: 100.00,
        accountId: 'acc_revenue',
        taxRateId: 'tax_rate_1'
      },
      {
        description: 'Service 1',
        quantity: 1,
        unitPrice: 50.00,
        accountId: 'acc_service',
        discount: 10,
        discountType: 'percentage'
      }
    ],
    terms: { type: PaymentTermType.NET, netDays: 30, description: 'Net 30 days' },
    notes: 'Test invoice',
    referenceNumber: 'REF123'
  };

  beforeEach(() => {
    vi.clearAllMocks();

    // Reset database mocks
    mockD1Database.prepare.mockReturnValue(mockPreparedStatement);
    mockPreparedStatement.bind.mockReturnValue(mockPreparedStatement);
    mockPreparedStatement.first.mockResolvedValue(null);
    mockPreparedStatement.all.mockResolvedValue({ results: [] });
    mockPreparedStatement.run.mockResolvedValue({ success: true, meta: { changes: 1 } });

    // Mock dependencies
    mockJournalManager = {
      createJournalEntry: vi.fn().mockResolvedValue({
        id: 'journal_entry_123',
        entryNumber: 'JE-001'
      }),
      postJournalEntry: vi.fn().mockResolvedValue(true)
    };

    mockAuditLogger = {
      logAction: vi.fn().mockResolvedValue(true)
    };

    mockCurrencyManager = {
      getBaseCurrency: vi.fn().mockResolvedValue('USD'),
      getExchangeRate: vi.fn().mockResolvedValue(1.0)
    };

    invoiceManager = new InvoiceManager(
      mockD1Database as any,
      mockJournalManager,
      mockAuditLogger,
      mockCurrencyManager,
      mockKV as KVNamespace
    );
  });

  describe('Constructor', () => {
    it('should initialize with required dependencies', () => {
      expect(invoiceManager).toBeInstanceOf(InvoiceManager);
      expect(Logger).toHaveBeenCalled();
    });
  });

  describe('createInvoice', () => {
    beforeEach(() => {
      // Mock customer lookup
      mockPreparedStatement.first
        .mockResolvedValueOnce(mockCustomer) // Customer lookup
        .mockResolvedValueOnce({ approval_threshold: 1000 }); // Approval threshold

      // Mock tax calculation
      vi.spyOn(invoiceManager as any, 'taxEngine', 'get').mockReturnValue({
        calculateInvoiceTaxes: vi.fn().mockResolvedValue({
          totalTax: 15.00,
          taxLines: [
            {
              id: 'tax_line_1',
              taxName: 'Sales Tax',
              taxRate: 0.10,
              taxAmount: 15.00,
              accountId: 'acc_tax'
            }
          ],
          lineTaxes: [
            { lineId: 'line_inv_123_1', taxAmount: 10.00 },
            { lineId: 'line_inv_123_2', taxAmount: 5.00 }
          ]
        })
      });
    });

    it('should create invoice with valid data', async () => {
      const invoice = await invoiceManager.createInvoice(
        mockInvoiceRequest,
        'user123',
        'business123'
      );

      expect(invoice).toBeDefined();
      expect(invoice.invoiceNumber).toBe('INV-2024-001');
      expect(invoice.customerId).toBe('customer123');
      expect(invoice.customerName).toBe('Test Customer');
      expect(invoice.status).toBe(InvoiceStatus.DRAFT);
      expect(invoice.lines).toHaveLength(2);
      expect(invoice.subtotal).toBe(245.00); // 200 + 45 (50 - 10% discount)
      expect(invoice.taxTotal).toBe(15.00);
      expect(invoice.total).toBe(260.00);
      expect(mockAuditLogger.logAction).toHaveBeenCalledWith(
        'invoice',
        expect.any(String),
        'CREATE',
        'business123',
        'user123',
        expect.any(Object)
      );
    });

    it('should calculate line discounts correctly', async () => {
      const invoice = await invoiceManager.createInvoice(
        mockInvoiceRequest,
        'user123',
        'business123'
      );

      const discountedLine = invoice.lines.find(line =>
        line.description === 'Service 1'
      );
      expect(discountedLine?.lineTotal).toBe(45.00); // 50 - 10% = 45
    });

    it('should handle invoice-level discounts', async () => {
      const requestWithDiscounts = {
        ...mockInvoiceRequest,
        discounts: [
          {
            description: 'Early payment discount',
            type: 'percentage' as const,
            value: 5
          }
        ]
      };

      const invoice = await invoiceManager.createInvoice(
        requestWithDiscounts,
        'user123',
        'business123'
      );

      expect(invoice.discounts).toBeDefined();
      expect(invoice.discounts![0].amount).toBe(12.25); // 5% of 245
      expect(invoice.discountTotal).toBe(12.25);
    });

    it('should require approval for high-value invoices', async () => {
      // Set low approval threshold
      mockPreparedStatement.first
        .mockResolvedValueOnce(mockCustomer)
        .mockResolvedValueOnce({ approval_threshold: 100 });

      const invoice = await invoiceManager.createInvoice(
        mockInvoiceRequest,
        'user123',
        'business123'
      );

      expect(invoice.approvalRequired).toBe(true);
      expect(invoice.status).toBe(InvoiceStatus.PENDING_APPROVAL);
      expect(invoice.approvalStatus).toBe(ApprovalStatus.PENDING);
    });

    it('should handle multi-currency invoices', async () => {
      const eurRequest = {
        ...mockInvoiceRequest,
        currency: 'EUR'
      };

      mockCurrencyManager.getExchangeRate.mockResolvedValue(0.85);

      const invoice = await invoiceManager.createInvoice(
        eurRequest,
        'user123',
        'business123'
      );

      expect(invoice.currency).toBe('EUR');
      expect(invoice.exchangeRate).toBe(0.85);
      expect(mockCurrencyManager.getExchangeRate).toHaveBeenCalledWith(
        'EUR',
        'business123',
        eurRequest.issueDate
      );
    });

    it('should throw error when customer not found', async () => {
      mockPreparedStatement.first.mockResolvedValueOnce(null);

      await expect(
        invoiceManager.createInvoice(mockInvoiceRequest, 'user123', 'business123')
      ).rejects.toThrow('Customer not found');
    });

    it('should handle database errors gracefully', async () => {
      mockPreparedStatement.first.mockRejectedValue(new Error('Database error'));

      await expect(
        invoiceManager.createInvoice(mockInvoiceRequest, 'user123', 'business123')
      ).rejects.toThrow('Database error');
    });

    it('should generate unique invoice IDs', async () => {
      const invoice1 = await invoiceManager.createInvoice(
        mockInvoiceRequest,
        'user123',
        'business123'
      );

      const invoice2 = await invoiceManager.createInvoice(
        mockInvoiceRequest,
        'user123',
        'business123'
      );

      expect(invoice1.id).not.toBe(invoice2.id);
    });

    it('should save invoice to database', async () => {
      await invoiceManager.createInvoice(
        mockInvoiceRequest,
        'user123',
        'business123'
      );

      expect(mockPreparedStatement.run).toHaveBeenCalledWith();
      expect(mockD1Database.prepare).toHaveBeenCalledWith(
        expect.stringContaining('INSERT OR REPLACE INTO invoices')
      );
    });

    it('should handle missing optional fields', async () => {
      const minimalRequest = {
        customerId: 'customer123',
        issueDate: Date.now(),
        lines: [
          {
            description: 'Simple item',
            quantity: 1,
            unitPrice: 100,
            accountId: 'acc_revenue'
          }
        ]
      };

      const invoice = await invoiceManager.createInvoice(
        minimalRequest,
        'user123',
        'business123'
      );

      expect(invoice).toBeDefined();
      expect(invoice.notes).toBeUndefined();
      expect(invoice.referenceNumber).toBeUndefined();
    });
  });

  describe('updateInvoice', () => {
    const existingInvoice: Invoice = {
      id: 'invoice123',
      invoiceNumber: 'INV-2024-001',
      customerId: 'customer123',
      customerName: 'Test Customer',
      customerEmail: 'test@customer.com',
      issueDate: Date.now(),
      dueDate: Date.now() + (30 * 24 * 60 * 60 * 1000),
      currency: 'USD',
      exchangeRate: 1.0,
      subtotal: 200.00,
      taxTotal: 20.00,
      discountTotal: 0.00,
      total: 220.00,
      balanceDue: 220.00,
      status: InvoiceStatus.DRAFT,
      terms: { type: PaymentTermType.NET, netDays: 30, description: 'Net 30 days' },
      lines: [
        {
          id: 'line1',
          invoiceId: 'invoice123',
          description: 'Original item',
          quantity: 2,
          unitPrice: 100.00,
          lineTotal: 200.00,
          taxableAmount: 200.00,
          taxAmount: 20.00,
          accountId: 'acc_revenue'
        }
      ],
      taxLines: [],
      approvalRequired: false,
      createdAt: Date.now(),
      createdBy: 'user123',
      updatedAt: Date.now(),
      businessId: 'business123'
    };

    const updateRequest: UpdateInvoiceRequest = {
      notes: 'Updated notes',
      lines: [
        {
          id: 'line1',
          description: 'Updated item',
          quantity: 3,
          unitPrice: 150.00,
          accountId: 'acc_revenue'
        }
      ]
    };

    beforeEach(() => {
      // Mock existing invoice lookup
      mockPreparedStatement.first
        .mockResolvedValueOnce(existingInvoice) // getInvoice call
        .mockResolvedValueOnce(mockCustomer); // getCustomer call

      // Mock tax calculation
      vi.spyOn(invoiceManager as any, 'taxEngine', 'get').mockReturnValue({
        calculateInvoiceTaxes: vi.fn().mockResolvedValue({
          totalTax: 45.00,
          taxLines: [],
          lineTaxes: [{ lineId: 'line1', taxAmount: 45.00 }]
        })
      });
    });

    it('should update invoice successfully', async () => {
      const updatedInvoice = await invoiceManager.updateInvoice(
        'invoice123',
        updateRequest,
        'user456',
        'business123'
      );

      expect(updatedInvoice.notes).toBe('Updated notes');
      expect(updatedInvoice.lines[0].description).toBe('Updated item');
      expect(updatedInvoice.lines[0].quantity).toBe(3);
      expect(updatedInvoice.subtotal).toBe(450.00); // 3 * 150
      expect(updatedInvoice.updatedBy).toBe('user456');
    });

    it('should throw error for non-existent invoice', async () => {
      mockPreparedStatement.first.mockResolvedValueOnce(null);

      await expect(
        invoiceManager.updateInvoice('nonexistent', updateRequest, 'user456', 'business123')
      ).rejects.toThrow('Invoice not found');
    });

    it('should prevent updates to sent invoices', async () => {
      const sentInvoice = { ...existingInvoice, status: InvoiceStatus.SENT };
      mockPreparedStatement.first.mockResolvedValueOnce(sentInvoice);

      await expect(
        invoiceManager.updateInvoice('invoice123', updateRequest, 'user456', 'business123')
      ).rejects.toThrow('Invoice cannot be updated in current status');
    });

    it('should prevent updates to paid invoices', async () => {
      const paidInvoice = { ...existingInvoice, status: InvoiceStatus.PAID };
      mockPreparedStatement.first.mockResolvedValueOnce(paidInvoice);

      await expect(
        invoiceManager.updateInvoice('invoice123', updateRequest, 'user456', 'business123')
      ).rejects.toThrow('Invoice cannot be updated in current status');
    });

    it('should handle customer change', async () => {
      const newCustomer = { ...mockCustomer, id: 'customer456', name: 'New Customer' };
      const customerChangeRequest = { ...updateRequest, customerId: 'customer456' };

      mockPreparedStatement.first
        .mockResolvedValueOnce(existingInvoice)
        .mockResolvedValueOnce(mockCustomer) // Original customer
        .mockResolvedValueOnce(newCustomer); // New customer

      const updatedInvoice = await invoiceManager.updateInvoice(
        'invoice123',
        customerChangeRequest,
        'user456',
        'business123'
      );

      expect(updatedInvoice.customerId).toBe('customer456');
      expect(updatedInvoice.customerName).toBe('New Customer');
    });

    it('should recalculate totals when lines change', async () => {
      const updatedInvoice = await invoiceManager.updateInvoice(
        'invoice123',
        updateRequest,
        'user456',
        'business123'
      );

      expect(updatedInvoice.subtotal).toBe(450.00);
      expect(updatedInvoice.taxTotal).toBe(45.00);
      expect(updatedInvoice.total).toBe(495.00);
    });

    it('should log audit trail for updates', async () => {
      await invoiceManager.updateInvoice(
        'invoice123',
        updateRequest,
        'user456',
        'business123'
      );

      expect(mockAuditLogger.logAction).toHaveBeenCalledWith(
        'invoice',
        'invoice123',
        'UPDATE',
        'business123',
        'user456',
        expect.any(Object)
      );
    });
  });

  describe('postInvoice', () => {
    const invoiceToPost: Invoice = {
      id: 'invoice123',
      invoiceNumber: 'INV-2024-001',
      customerId: 'customer123',
      customerName: 'Test Customer',
      customerEmail: 'test@customer.com',
      issueDate: Date.now(),
      dueDate: Date.now() + (30 * 24 * 60 * 60 * 1000),
      currency: 'USD',
      exchangeRate: 1.0,
      subtotal: 200.00,
      taxTotal: 20.00,
      discountTotal: 0.00,
      total: 220.00,
      balanceDue: 220.00,
      status: InvoiceStatus.SENT,
      terms: { type: PaymentTermType.NET, netDays: 30, description: 'Net 30 days' },
      lines: [
        {
          id: 'line1',
          invoiceId: 'invoice123',
          description: 'Test item',
          quantity: 2,
          unitPrice: 100.00,
          lineTotal: 200.00,
          taxableAmount: 200.00,
          taxAmount: 20.00,
          accountId: 'acc_revenue'
        }
      ],
      taxLines: [
        {
          id: 'tax1',
          invoiceId: 'inv123',
          taxRateId: 'tax_rate_1',
          taxName: 'Sales Tax',
          taxRate: 0.10,
          taxableAmount: 200.00,
          taxAmount: 20.00,
          accountId: 'acc_tax'
        }
      ],
      approvalRequired: false,
      createdAt: Date.now(),
      createdBy: 'user123',
      updatedAt: Date.now(),
      businessId: 'business123'
    };

    beforeEach(() => {
      // Mock invoice lookup
      mockPreparedStatement.first
        .mockResolvedValueOnce(invoiceToPost) // getInvoice call
        .mockResolvedValueOnce({ // getAccountingConfiguration call
          accounts_receivable_id: 'acc_ar',
          sales_tax_payable_id: 'acc_tax_payable'
        });
    });

    it('should post invoice to journal successfully', async () => {
      const result = await invoiceManager.postInvoice(
        'invoice123',
        'user123',
        'business123'
      );

      expect(result.invoice.journalEntryId).toBe('journal_entry_123');
      expect(mockJournalManager.createJournalEntry).toHaveBeenCalledWith(
        {
          date: invoiceToPost.issueDate,
          description: `Invoice ${invoiceToPost.invoiceNumber} - ${invoiceToPost.customerName}`,
          reference: invoiceToPost.invoiceNumber,
          type: JournalEntryType.SYSTEM,
          lines: expect.arrayContaining([
            expect.objectContaining({
              accountId: 'acc_ar',
              debit: 220.00,
              credit: 0
            })
          ])
        },
        'user123',
        'business123'
      );
    });

    it('should create correct journal entries', async () => {
      await invoiceManager.postInvoice('invoice123', 'user123', 'business123');

      const journalCall = mockJournalManager.createJournalEntry.mock.calls[0][0];
      const lines = journalCall.lines;

      // Should have AR debit
      const arLine = lines.find((line: any) => line.accountId === 'acc_ar');
      expect(arLine).toBeDefined();
      expect(arLine.debit).toBe(220.00);
      expect(arLine.credit).toBe(0);

      // Should have revenue credit
      const revenueLine = lines.find((line: any) => line.accountId === 'acc_revenue');
      expect(revenueLine).toBeDefined();
      expect(revenueLine.debit).toBe(0);
      expect(revenueLine.credit).toBe(200.00);

      // Should have tax credit
      const taxLine = lines.find((line: any) => line.accountId === 'acc_tax');
      expect(taxLine).toBeDefined();
      expect(taxLine.debit).toBe(0);
      expect(taxLine.credit).toBe(20.00);
    });

    it('should throw error for non-existent invoice', async () => {
      mockPreparedStatement.first.mockResolvedValueOnce(null);

      await expect(
        invoiceManager.postInvoice('nonexistent', 'user123', 'business123')
      ).rejects.toThrow('Invoice not found');
    });

    it('should throw error for draft invoice', async () => {
      const draftInvoice = { ...invoiceToPost, status: InvoiceStatus.DRAFT };
      mockPreparedStatement.first.mockResolvedValueOnce(draftInvoice);

      await expect(
        invoiceManager.postInvoice('invoice123', 'user123', 'business123')
      ).rejects.toThrow('Invoice must be sent before posting');
    });

    it('should throw error for already posted invoice', async () => {
      const postedInvoice = { ...invoiceToPost, journalEntryId: 'existing_entry' };
      mockPreparedStatement.first.mockResolvedValueOnce(postedInvoice);

      await expect(
        invoiceManager.postInvoice('invoice123', 'user123', 'business123')
      ).rejects.toThrow('Invoice has already been posted');
    });

    it('should post journal entry after creation', async () => {
      await invoiceManager.postInvoice('invoice123', 'user123', 'business123');

      expect(mockJournalManager.postJournalEntry).toHaveBeenCalledWith(
        { journalEntryId: 'journal_entry_123' },
        'user123',
        'business123'
      );
    });

    it('should log audit trail for posting', async () => {
      await invoiceManager.postInvoice('invoice123', 'user123', 'business123');

      expect(mockAuditLogger.logAction).toHaveBeenCalledWith(
        'invoice',
        'invoice123',
        'POST',
        'business123',
        'user123',
        {
          journalEntryId: 'journal_entry_123',
          amount: 220.00
        }
      );
    });
  });

  describe('getInvoice', () => {
    const mockInvoiceRow = {
      id: 'invoice123',
      invoice_number: 'INV-2024-001',
      customer_id: 'customer123',
      customer_name: 'Test Customer',
      customer_email: 'test@customer.com',
      issue_date: Date.now(),
      due_date: Date.now() + (30 * 24 * 60 * 60 * 1000),
      currency: 'USD',
      exchange_rate: 1.0,
      subtotal: 200.00,
      tax_total: 20.00,
      discount_total: 0.00,
      total: 220.00,
      balance_due: 220.00,
      status: 'draft',
      terms: JSON.stringify({ type: 'net', days: 30 }),
      lines: JSON.stringify([]),
      tax_lines: JSON.stringify([]),
      approval_required: 0,
      created_at: Date.now(),
      created_by: 'user123',
      updated_at: Date.now(),
      business_id: 'business123'
    };

    it('should retrieve invoice successfully', async () => {
      mockPreparedStatement.first.mockResolvedValue(mockInvoiceRow);

      const invoice = await invoiceManager.getInvoice('invoice123', 'business123');

      expect(invoice).toBeDefined();
      expect(invoice!.id).toBe('invoice123');
      expect(invoice!.invoiceNumber).toBe('INV-2024-001');
      expect(invoice!.customerName).toBe('Test Customer');
      expect(mockPreparedStatement.bind).toHaveBeenCalledWith('invoice123', 'business123');
    });

    it('should return null for non-existent invoice', async () => {
      mockPreparedStatement.first.mockResolvedValue(null);

      const invoice = await invoiceManager.getInvoice('nonexistent', 'business123');

      expect(invoice).toBeNull();
    });

    it('should handle database errors', async () => {
      mockPreparedStatement.first.mockRejectedValue(new Error('Database error'));

      await expect(
        invoiceManager.getInvoice('invoice123', 'business123')
      ).rejects.toThrow('Database error');
    });

    it('should map database row to invoice object correctly', async () => {
      mockPreparedStatement.first.mockResolvedValue(mockInvoiceRow);

      const invoice = await invoiceManager.getInvoice('invoice123', 'business123');

      expect(invoice!.status).toBe(InvoiceStatus.DRAFT);
      expect(invoice!.approvalRequired).toBe(false);
      expect(invoice!.terms).toEqual({ type: 'net', days: 30 });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle invalid business ID', async () => {
      const validateBusinessId = require('../../../modules/finance/utils').validateBusinessId;
      validateBusinessId.mockImplementation(() => {
        throw new Error('Invalid business ID');
      });

      await expect(
        invoiceManager.createInvoice(mockInvoiceRequest, 'user123', 'invalid_id')
      ).rejects.toThrow('Invalid business ID');
    });

    it('should handle concurrent invoice creation', async () => {
      const promises = Array.from({ length: 5 }, () =>
        invoiceManager.createInvoice(mockInvoiceRequest, 'user123', 'business123')
      );

      const invoices = await Promise.all(promises);

      // All invoices should be created with unique IDs
      const ids = invoices.map(invoice => invoice.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(5);
    });

    it('should handle malformed line data', async () => {
      const invalidRequest = {
        ...mockInvoiceRequest,
        lines: [
          {
            description: '',
            quantity: -1,
            unitPrice: 'invalid' as any,
            accountId: 'acc_revenue'
          }
        ]
      };

      // Should be caught by validation before reaching invoice creation
      await expect(
        invoiceManager.createInvoice(invalidRequest, 'user123', 'business123')
      ).rejects.toThrow();
    });

    it('should handle tax calculation failures', async () => {
      vi.spyOn(invoiceManager as any, 'taxEngine', 'get').mockReturnValue({
        calculateInvoiceTaxes: vi.fn().mockRejectedValue(new Error('Tax calculation failed'))
      });

      await expect(
        invoiceManager.createInvoice(mockInvoiceRequest, 'user123', 'business123')
      ).rejects.toThrow('Tax calculation failed');
    });

    it('should handle currency conversion errors', async () => {
      mockCurrencyManager.getExchangeRate.mockRejectedValue(
        new Error('Exchange rate unavailable')
      );

      const eurRequest = { ...mockInvoiceRequest, currency: 'EUR' };

      await expect(
        invoiceManager.createInvoice(eurRequest, 'user123', 'business123')
      ).rejects.toThrow('Exchange rate unavailable');
    });

    it('should handle database transaction failures', async () => {
      mockPreparedStatement.run.mockRejectedValue(new Error('Transaction failed'));

      await expect(
        invoiceManager.createInvoice(mockInvoiceRequest, 'user123', 'business123')
      ).rejects.toThrow('Transaction failed');
    });
  });

  describe('Data Mapping and Conversion', () => {
    it('should correctly map customer data', async () => {
      const customerRow = {
        id: 'customer123',
        name: 'Test Customer',
        email: 'test@customer.com',
        currency: 'USD',
        payment_terms: JSON.stringify({ type: 'net', days: 30 }),
        billing_address: JSON.stringify({ street: '123 Main St' }),
        is_active: 1,
        created_at: Date.now(),
        updated_at: Date.now(),
        business_id: 'business123'
      };

      mockPreparedStatement.first.mockResolvedValue(customerRow);

      // Access private method through any type
      const customer = await (invoiceManager as any).getCustomer('customer123', 'business123');

      expect(customer.id).toBe('customer123');
      expect(customer.name).toBe('Test Customer');
      expect(customer.isActive).toBe(true);
      expect(customer.paymentTerms).toEqual({ type: 'net', days: 30 });
    });

    it('should handle null/undefined fields in mapping', async () => {
      const incompleteRow = {
        id: 'invoice123',
        invoice_number: 'INV-001',
        customer_id: 'customer123',
        customer_name: 'Test Customer',
        customer_email: null,
        issue_date: Date.now(),
        due_date: Date.now(),
        currency: 'USD',
        exchange_rate: 1.0,
        subtotal: 100.00,
        tax_total: 10.00,
        discount_total: 0.00,
        total: 110.00,
        balance_due: 110.00,
        status: 'draft',
        terms: JSON.stringify({ type: 'net', days: 30 }),
        lines: JSON.stringify([]),
        tax_lines: null,
        notes: null,
        approval_required: 0,
        created_at: Date.now(),
        created_by: 'user123',
        updated_at: Date.now(),
        business_id: 'business123'
      };

      mockPreparedStatement.first.mockResolvedValue(incompleteRow);

      const invoice = await invoiceManager.getInvoice('invoice123', 'business123');

      expect(invoice!.customerEmail).toBeUndefined();
      expect(invoice!.taxLines).toBeUndefined();
      expect(invoice!.notes).toBeUndefined();
    });
  });

  describe('Business Logic Validation', () => {
    it('should enforce business rules for invoice modification', async () => {
      const modifiedInvoice = {
        ...mockInvoiceRequest,
        status: InvoiceStatus.PAID
      };

      mockPreparedStatement.first.mockResolvedValueOnce(modifiedInvoice);

      await expect(
        invoiceManager.updateInvoice('invoice123', {}, 'user123', 'business123')
      ).rejects.toThrow('Invoice cannot be updated in current status');
    });

    it('should calculate due dates correctly', async () => {
      const issueDate = Date.now();
      const terms = { type: PaymentTermType.NET, days: 45 };

      // Mock payment terms manager
      const mockPaymentTermsManager = {
        calculateDueDate: vi.fn().mockReturnValue(issueDate + (45 * 24 * 60 * 60 * 1000))
      };

      vi.spyOn(invoiceManager as any, 'paymentTermsManager', 'get').mockReturnValue(
        mockPaymentTermsManager
      );

      const dueDate = (invoiceManager as any).calculateDueDate(issueDate, terms);

      expect(mockPaymentTermsManager.calculateDueDate).toHaveBeenCalledWith(issueDate, terms);
      expect(dueDate).toBe(issueDate + (45 * 24 * 60 * 60 * 1000));
    });
  });
});