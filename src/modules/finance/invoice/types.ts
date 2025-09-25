/**
 * Invoice Management Types
 * Comprehensive type definitions for invoice generation and management
 */

import { z } from 'zod'

// Core Invoice Types
export enum InvoiceStatus {
  DRAFT = 'draft',
  PENDING_APPROVAL = 'pending_approval',
  APPROVED = 'approved',
  SENT = 'sent',
  VIEWED = 'viewed',
  PARTIALLY_PAID = 'partially_paid',
  PAID = 'paid',
  OVERDUE = 'overdue',
  CANCELLED = 'cancelled',
  REFUNDED = 'refunded',
  DISPUTED = 'disputed',
}

export enum InvoiceType {
  STANDARD = 'standard',
  RECURRING = 'recurring',
  CREDIT_NOTE = 'credit_note',
  DEBIT_NOTE = 'debit_note',
  PROFORMA = 'proforma',
  TAX_INVOICE = 'tax_invoice',
}

export enum PaymentTerms {
  NET_15 = 'net_15',
  NET_30 = 'net_30',
  NET_45 = 'net_45',
  NET_60 = 'net_60',
  NET_90 = 'net_90',
  DUE_ON_RECEIPT = 'due_on_receipt',
  CASH_ON_DELIVERY = 'cash_on_delivery',
  ADVANCE_PAYMENT = 'advance_payment',
}

// Address Schema
export const AddressSchema = z.object({
  street: z.string().min(1, 'Street address is required'),
  city: z.string().min(1, 'City is required'),
  state: z.string().min(1, 'State is required'),
  postalCode: z.string().min(1, 'Postal code is required'),
  country: z.string().min(2, 'Country code required').max(2),
})

// Customer Schema
export const CustomerSchema = z.object({
  id: z.string().uuid(),
  businessId: z.string().uuid(),
  name: z.string().min(1, 'Customer name is required'),
  email: z.string().email('Valid email required'),
  phone: z.string().optional(),
  taxId: z.string().optional(),
  billingAddress: AddressSchema,
  shippingAddress: AddressSchema.optional(),
  paymentTerms: z.nativeEnum(PaymentTerms).default(PaymentTerms.NET_30),
  creditLimit: z.number().nonnegative().optional(),
  currency: z.string().length(3, 'Currency must be 3 characters'),
  isActive: z.boolean().default(true),
})

// Tax Configuration Schema
export const TaxConfigSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1, 'Tax name required'),
  rate: z.number().min(0).max(1, 'Tax rate must be between 0 and 1'),
  isCompound: z.boolean().default(false),
  isInclusive: z.boolean().default(false),
  applicableCountries: z.array(z.string()).optional(),
  validFrom: z.string().datetime(),
  validTo: z.string().datetime().optional(),
})

// Invoice Line Item Schema
export const InvoiceLineItemSchema = z.object({
  id: z.string().uuid(),
  productId: z.string().uuid().optional(),
  description: z.string().min(1, 'Description is required'),
  quantity: z.number().positive('Quantity must be positive'),
  unitPrice: z.number().nonnegative('Unit price cannot be negative'),
  discountAmount: z.number().nonnegative().default(0),
  discountPercentage: z.number().min(0).max(100).default(0),
  taxConfigId: z.string().uuid().optional(),
  taxAmount: z.number().nonnegative().default(0),
  lineTotal: z.number().nonnegative(),
  notes: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
})

// Invoice Schema
export const InvoiceSchema = z.object({
  id: z.string().uuid(),
  businessId: z.string().uuid(),
  invoiceNumber: z.string().min(1, 'Invoice number required'),
  customerId: z.string().uuid(),
  customerDetails: CustomerSchema,
  type: z.nativeEnum(InvoiceType).default(InvoiceType.STANDARD),
  status: z.nativeEnum(InvoiceStatus).default(InvoiceStatus.DRAFT),
  issueDate: z.string().datetime(),
  dueDate: z.string().datetime(),
  paymentTerms: z.nativeEnum(PaymentTerms),
  currency: z.string().length(3),
  exchangeRate: z.number().positive().default(1),

  // Line items
  lineItems: z.array(InvoiceLineItemSchema).min(1, 'At least one line item required'),

  // Amounts
  subtotal: z.number().nonnegative(),
  totalTax: z.number().nonnegative(),
  totalDiscount: z.number().nonnegative(),
  shippingCost: z.number().nonnegative().default(0),
  adjustmentAmount: z.number().default(0),
  totalAmount: z.number().nonnegative(),

  // Payment information
  amountPaid: z.number().nonnegative().default(0),
  amountDue: z.number().nonnegative(),

  // Additional details
  notes: z.string().optional(),
  internalNotes: z.string().optional(),
  terms: z.string().optional(),
  footer: z.string().optional(),

  // References
  purchaseOrderNumber: z.string().optional(),
  salesOrderId: z.string().uuid().optional(),
  projectId: z.string().uuid().optional(),

  // Approval workflow
  approvalStatus: z.enum(['pending', 'approved', 'rejected']).default('pending'),
  approvedBy: z.string().uuid().optional(),
  approvedAt: z.string().datetime().optional(),
  rejectionReason: z.string().optional(),

  // Attachments
  attachments: z.array(z.object({
    id: z.string().uuid(),
    filename: z.string(),
    fileSize: z.number(),
    mimeType: z.string(),
    url: z.string().url(),
  })).default([]),

  // Audit fields
  createdBy: z.string().uuid(),
  updatedBy: z.string().uuid().optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime().optional(),
  version: z.number().positive().default(1),

  // Metadata
  metadata: z.record(z.unknown()).optional(),
})

// Create Invoice Request Schema
export const CreateInvoiceRequestSchema = z.object({
  customerId: z.string().uuid(),
  type: z.nativeEnum(InvoiceType).optional(),
  issueDate: z.string().datetime().optional(),
  dueDate: z.string().datetime().optional(),
  paymentTerms: z.nativeEnum(PaymentTerms).optional(),
  currency: z.string().length(3).optional(),
  lineItems: z.array(InvoiceLineItemSchema.omit({ id: true, lineTotal: true, taxAmount: true })),
  notes: z.string().optional(),
  terms: z.string().optional(),
  purchaseOrderNumber: z.string().optional(),
  projectId: z.string().uuid().optional(),
  metadata: z.record(z.unknown()).optional(),
})

// Update Invoice Request Schema
export const UpdateInvoiceRequestSchema = z.object({
  customerId: z.string().uuid().optional(),
  dueDate: z.string().datetime().optional(),
  paymentTerms: z.nativeEnum(PaymentTerms).optional(),
  lineItems: z.array(InvoiceLineItemSchema.omit({ id: true, lineTotal: true, taxAmount: true })).optional(),
  notes: z.string().optional(),
  terms: z.string().optional(),
  purchaseOrderNumber: z.string().optional(),
  projectId: z.string().uuid().optional(),
  metadata: z.record(z.unknown()).optional(),
})

// PDF Generation Options
export const PDFOptionsSchema = z.object({
  format: z.enum(['A4', 'Letter']).default('A4'),
  orientation: z.enum(['portrait', 'landscape']).default('portrait'),
  includePaymentInstructions: z.boolean().default(true),
  includeTermsAndConditions: z.boolean().default(true),
  watermark: z.string().optional(),
  customTemplate: z.string().optional(),
  locale: z.string().default('en-US'),
})

// Export TypeScript types
export type Address = z.infer<typeof AddressSchema>
export type Customer = z.infer<typeof CustomerSchema>
export type TaxConfig = z.infer<typeof TaxConfigSchema>
export type InvoiceLineItem = z.infer<typeof InvoiceLineItemSchema>
export type Invoice = z.infer<typeof InvoiceSchema>
export type CreateInvoiceRequest = z.infer<typeof CreateInvoiceRequestSchema>
export type UpdateInvoiceRequest = z.infer<typeof UpdateInvoiceRequestSchema>
export type PDFOptions = z.infer<typeof PDFOptionsSchema>

// API Response Types
export interface InvoiceSearchParams {
  page?: number
  limit?: number
  status?: InvoiceStatus
  customerId?: string
  startDate?: string
  endDate?: string
  minAmount?: number
  maxAmount?: number
  search?: string
  sortBy?: 'invoiceNumber' | 'issueDate' | 'dueDate' | 'totalAmount' | 'status'
  sortOrder?: 'asc' | 'desc'
}

export interface InvoiceListResponse {
  invoices: Invoice[]
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
    hasNext: boolean
    hasPrev: boolean
  }
  summary: {
    totalAmount: number
    paidAmount: number
    outstandingAmount: number
    overdueAmount: number
    currency: string
  }
}

// Email Configuration
export interface EmailConfig {
  to: string[]
  cc?: string[]
  bcc?: string[]
  subject?: string
  template?: string
  attachPdf: boolean
  sendReminder?: boolean
  reminderDays?: number[]
}

// Payment Link Configuration
export interface PaymentLinkConfig {
  provider: 'stripe' | 'paypal' | 'square'
  successUrl?: string
  cancelUrl?: string
  allowPartialPayment: boolean
  expiresAt?: string
  metadata?: Record<string, unknown>
}