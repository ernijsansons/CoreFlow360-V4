/**
 * Invoice Service Tests
 * Comprehensive test suite for invoice business logic
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { InvoiceService } from '@/modules/finance/invoice/service'
import { TaxCalculationEngine } from '@/modules/finance/invoice/tax-engine'
import { PDFGeneratorService } from '@/modules/finance/invoice/pdf-generator'
import { CurrencyService } from '@/modules/finance/invoice/currency-service'
import { AppError } from '@/shared/errors/app-error'
import type { CreateInvoiceRequest, Invoice } from '@/modules/finance/invoice/types'

// Mock dependencies
const mockDB = {
  prepare: vi.fn(),
  exec: vi.fn(),
  batch: vi.fn()
} as any

const mockAuditLogger = {
  log: vi.fn()
}

const mockTaxCalculator = {
  calculateTaxes: vi.fn().mockResolvedValue({
    lineItems: [],
    totalTax: 50.00,
    taxSummary: [],
    exemptionsApplied: []
  })
} as any

const mockPDFGenerator = {
  generateInvoicePDF: vi.fn().mockResolvedValue(Buffer.from('mock-pdf'))
} as any

const mockCurrencyService = {
  convertCurrency: vi.fn().mockResolvedValue({
    originalAmount: 100,
    convertedAmount: 100,
    exchangeRate: 1
  }),
  formatCurrency: vi.fn().mockImplementation((amount, currency) => `$${amount.toFixed(2)}`)
} as any

describe('InvoiceService', () => {
  let invoiceService: InvoiceService

  beforeEach(() => {
    vi.clearAllMocks()
    invoiceService = new InvoiceService(
      mockDB,
      mockAuditLogger,
      mockTaxCalculator,
      mockPDFGenerator,
      mockCurrencyService
    )
  })

  describe('createInvoice', () => {
    const validRequest: CreateInvoiceRequest = {
      customerId: 'customer-1',
      lineItems: [
        {
          description: 'Professional Services',
          quantity: 10,
          unitPrice: 100.00,
          discountAmount: 0,
          discountPercentage: 0
        }
      ],
      currency: 'USD',
      notes: 'Test invoice'
    }

    it('creates invoice successfully with valid data', async () => {
      const userId = 'user-1'

      // Mock successful creation
      const result = await invoiceService.createInvoice(validRequest, userId)

      expect(result).toBeDefined()
      expect(result.lineItems).toHaveLength(1)
      expect(result.lineItems[0].description).toBe('Professional Services')
      expect(result.createdBy).toBe(userId)
      expect(result.status).toBe('draft')

      // Should log audit events
      expect(mockAuditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'invoice_creation_started',
          userId
        })
      )
    })

    it('validates required fields', async () => {
      const invalidRequest = {
        ...validRequest,
        lineItems: []
      }

      await expect(
        invoiceService.createInvoice(invalidRequest, 'user-1')
      ).rejects.toThrow(AppError)
    })

    it('calculates totals correctly', async () => {
      const requestWithMultipleItems: CreateInvoiceRequest = {
        ...validRequest,
        lineItems: [
          {
            description: 'Item 1',
            quantity: 2,
            unitPrice: 100.00,
            discountAmount: 0,
            discountPercentage: 0
          },
          {
            description: 'Item 2',
            quantity: 1,
            unitPrice: 50.00,
            discountAmount: 5.00,
            discountPercentage: 0
          }
        ]
      }

      const result = await invoiceService.createInvoice(requestWithMultipleItems, 'user-1')

      // Item 1: 2 * 100 = 200
      // Item 2: 1 * 50 - 5 = 45
      // Subtotal: 245
      // Tax: 50 (mocked)
      // Total: 295
      expect(result.subtotal).toBe(245.00)
      expect(result.totalTax).toBe(50.00)
      expect(result.totalAmount).toBe(295.00)
    })

    it('applies discounts correctly', async () => {
      const requestWithDiscount: CreateInvoiceRequest = {
        ...validRequest,
        lineItems: [
          {
            description: 'Discounted Item',
            quantity: 1,
            unitPrice: 100.00,
            discountAmount: 0,
            discountPercentage: 10 // 10% discount
          }
        ]
      }

      const result = await invoiceService.createInvoice(requestWithDiscount, 'user-1')

      // Should apply 10% discount: 100 - 10 = 90
      expect(result.lineItems[0].lineTotal).toBe(90.00)
      expect(result.subtotal).toBe(90.00)
    })

    it('handles tax calculation integration', async () => {
      await invoiceService.createInvoice(validRequest, 'user-1')

      expect(mockTaxCalculator.calculateTaxes).toHaveBeenCalledWith(
        expect.objectContaining({
          lineItems: expect.any(Array)
        })
      )
    })

    it('generates unique invoice numbers', async () => {
      const result1 = await invoiceService.createInvoice(validRequest, 'user-1')
      const result2 = await invoiceService.createInvoice(validRequest, 'user-1')

      expect(result1.invoiceNumber).not.toBe(result2.invoiceNumber)
      expect(result1.id).not.toBe(result2.id)
    })
  })

  describe('updateInvoice', () => {
    const mockExistingInvoice: Invoice = {
      id: 'inv-1',
      businessId: 'business-1',
      invoiceNumber: 'INV-001',
      customerId: 'customer-1',
      customerDetails: {} as any,
      type: 'standard',
      status: 'draft',
      issueDate: new Date().toISOString(),
      dueDate: new Date().toISOString(),
      paymentTerms: 'net_30',
      currency: 'USD',
      exchangeRate: 1,
      lineItems: [],
      subtotal: 100,
      totalTax: 10,
      totalDiscount: 0,
      totalAmount: 110,
      amountPaid: 0,
      amountDue: 110,
      approvalStatus: 'pending',
      attachments: [],
      createdBy: 'user-1',
      createdAt: new Date().toISOString(),
      version: 1
    }

    it('updates invoice successfully', async () => {
      // Mock getInvoice to return existing invoice
      vi.spyOn(invoiceService, 'getInvoice').mockResolvedValue(mockExistingInvoice)

      const updateRequest = {
        notes: 'Updated notes',
        status: 'sent' as const
      }

      const result = await invoiceService.updateInvoice('inv-1', updateRequest, 'user-2')

      expect(result.notes).toBe('Updated notes')
      expect(result.status).toBe('sent')
      expect(result.updatedBy).toBe('user-2')
      expect(result.version).toBe(2)
    })

    it('throws error when invoice not found', async () => {
      vi.spyOn(invoiceService, 'getInvoice').mockResolvedValue(null)

      await expect(
        invoiceService.updateInvoice('invalid-id', {}, 'user-1')
      ).rejects.toThrow(AppError)
    })

    it('tracks price history when price changes', async () => {
      vi.spyOn(invoiceService, 'getInvoice').mockResolvedValue(mockExistingInvoice)

      const updateRequest = {
        pricing: {
          basePrice: 150.00
        }
      }

      const result = await invoiceService.updateInvoice('inv-1', updateRequest, 'user-1')

      expect(result.pricing.priceHistory).toHaveLength(2) // Original + new price
      expect(result.pricing.priceHistory[1].price).toBe(150.00)
    })
  })

  describe('search and filtering', () => {
    it('handles search parameters correctly', async () => {
      const searchParams = {
        page: 1,
        limit: 10,
        status: 'sent' as const,
        customerId: 'customer-1',
        search: 'INV-001'
      }

      const result = await invoiceService.searchInvoices(searchParams)

      expect(result).toBeDefined()
      expect(result.pagination.page).toBe(1)
      expect(result.pagination.limit).toBe(10)

      expect(mockAuditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'invoice_search_started'
        })
      )
    })

    it('normalizes search parameters', async () => {
      const invalidParams = {
        page: -1,
        limit: 1000, // Too high
        sortOrder: 'invalid' as any
      }

      const result = await invoiceService.searchInvoices(invalidParams)

      expect(result.pagination.page).toBe(1) // Should normalize to minimum
      expect(result.pagination.limit).toBeLessThanOrEqual(100) // Should cap at maximum
    })
  })

  describe('PDF generation', () => {
    it('generates PDF successfully', async () => {
      const mockInvoice = { ...mockExistingInvoice }
      vi.spyOn(invoiceService, 'getInvoice').mockResolvedValue(mockInvoice)

      const pdfBuffer = await invoiceService.generatePDF('inv-1')

      expect(pdfBuffer).toBeInstanceOf(Buffer)
      expect(mockPDFGenerator.generateInvoicePDF).toHaveBeenCalledWith(
        mockInvoice,
        expect.any(Object)
      )
    })

    it('throws error for invalid invoice', async () => {
      vi.spyOn(invoiceService, 'getInvoice').mockResolvedValue(null)

      await expect(
        invoiceService.generatePDF('invalid-id')
      ).rejects.toThrow(AppError)
    })
  })

  describe('currency handling', () => {
    it('handles multi-currency invoices', async () => {
      const eurRequest: CreateInvoiceRequest = {
        ...validRequest,
        currency: 'EUR'
      }

      const result = await invoiceService.createInvoice(eurRequest, 'user-1')

      expect(result.currency).toBe('EUR')
      expect(mockCurrencyService.formatCurrency).toHaveBeenCalledWith(
        expect.any(Number),
        'EUR'
      )
    })
  })

  describe('error handling', () => {
    it('handles database errors gracefully', async () => {
      mockDB.exec.mockRejectedValue(new Error('Database connection failed'))

      await expect(
        invoiceService.createInvoice(validRequest, 'user-1')
      ).rejects.toThrow(AppError)

      expect(mockAuditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'invoice_creation_failed'
        })
      )
    })

    it('handles validation errors', async () => {
      const invalidRequest = {
        customerId: '', // Invalid
        lineItems: []   // Invalid
      } as CreateInvoiceRequest

      await expect(
        invoiceService.createInvoice(invalidRequest, 'user-1')
      ).rejects.toThrow(AppError)
    })

    it('handles tax calculation errors', async () => {
      mockTaxCalculator.calculateTaxes.mockRejectedValue(new Error('Tax service unavailable'))

      await expect(
        invoiceService.createInvoice(validRequest, 'user-1')
      ).rejects.toThrow(AppError)
    })
  })

  describe('business rules validation', () => {
    it('prevents modification of paid invoices', async () => {
      const paidInvoice = { ...mockExistingInvoice, status: 'paid' as const }
      vi.spyOn(invoiceService, 'getInvoice').mockResolvedValue(paidInvoice)

      await expect(
        invoiceService.updateInvoice('inv-1', { notes: 'New notes' }, 'user-1')
      ).rejects.toThrow(AppError)
    })

    it('validates line item quantities', async () => {
      const invalidRequest: CreateInvoiceRequest = {
        ...validRequest,
        lineItems: [
          {
            description: 'Invalid Item',
            quantity: 0, // Invalid quantity
            unitPrice: 100.00,
            discountAmount: 0,
            discountPercentage: 0
          }
        ]
      }

      await expect(
        invoiceService.createInvoice(invalidRequest, 'user-1')
      ).rejects.toThrow(AppError)
    })

    it('validates discount amounts', async () => {
      const invalidRequest: CreateInvoiceRequest = {
        ...validRequest,
        lineItems: [
          {
            description: 'Over-discounted Item',
            quantity: 1,
            unitPrice: 100.00,
            discountAmount: 150.00, // Discount > unit price
            discountPercentage: 0
          }
        ]
      }

      await expect(
        invoiceService.createInvoice(invalidRequest, 'user-1')
      ).rejects.toThrow(AppError)
    })
  })
})