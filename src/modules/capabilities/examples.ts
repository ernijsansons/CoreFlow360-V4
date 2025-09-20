/**
 * Example Capability Definitions
 * Demonstrates safe AI tool use for invoice creation and ledger posting
 */

import {
  CapabilitySpec,
  ParameterSpec,
  SqlOperationSpec,
  ApiOperationSpec,
  CostSpec,
  PermissionSpec,
  AuditSpec
} from './types';

/**
 * Invoice Creation Capability
 * Safely creates invoices with validation and cost tracking
 */
export const InvoiceCreationCapability: CapabilitySpec = {
  // Identity
  id: 'invoice:create',
  name: 'Create Invoice',
  description: 'Creates a new invoice with line items, tax calculations, and payment terms. Validates all business rules and maintains audit trail.',
  version: '1.2.0',
  category: 'database',

  // Parameters with comprehensive validation
  parameters: [
    {
      name: 'customerId',
      type: 'string',
      description: 'Unique identifier for the customer',
      validation: {
        required: true,
        pattern: '^[a-zA-Z0-9_-]+$',
        minLength: 3,
        maxLength: 50,
        format: 'uuid',
      },
      examples: ['cust_123e4567-e89b-12d3-a456-426614174000'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 10,
      },
    },
    {
      name: 'invoiceNumber',
      type: 'string',
      description: 'Human-readable invoice number',
      validation: {
        required: true,
        pattern: '^INV-[0-9]{4}-[0-9]+$',
        minLength: 8,
        maxLength: 20,
      },
      examples: ['INV-2024-001234'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 10,
      },
    },
    {
      name: 'issueDate',
      type: 'date',
      description: 'Invoice issue date in ISO 8601 format',
      validation: {
        required: true,
        format: 'iso8601',
      },
      examples: ['2024-03-15T00:00:00.000Z'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 15,
      },
    },
    {
      name: 'dueDate',
      type: 'date',
      description: 'Payment due date in ISO 8601 format',
      validation: {
        required: true,
        format: 'iso8601',
      },
      examples: ['2024-04-15T00:00:00.000Z'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 15,
      },
    },
    {
      name: 'lineItems',
      type: 'array',
      description: 'Array of invoice line items with descriptions, quantities, and pricing',
      validation: {
        required: true,
        minLength: 1,
        maxLength: 50,
        customValidator: 'validateInvoiceLineItems',
      },
      examples: [[
        {
          description: 'Professional Services - Q1 2024',
          quantity: 40,
          unitPrice: 125.00,
          taxRate: 0.08,
          lineTotal: 5000.00
        }
      ]],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 500,
      },
    },
    {
      name: 'currency',
      type: 'enum',
      description: 'Invoice currency code',
      validation: {
        required: true,
        enum: ['USD', 'EUR', 'GBP', 'CAD', 'AUD'],
      },
      examples: ['USD'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 5,
      },
    },
    {
      name: 'taxCalculationMode',
      type: 'enum',
      description: 'Method for calculating taxes',
      validation: {
        required: false,
        enum: ['inclusive', 'exclusive', 'exempt'],
      },
      examples: ['exclusive'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 10,
      },
    },
    {
      name: 'paymentTerms',
      type: 'object',
      description: 'Payment terms and conditions',
      validation: {
        required: false,
        customValidator: 'validatePaymentTerms',
      },
      examples: [{
        net: 30,
        discountPercentage: 2.0,
        discountDays: 10,
        lateFeePercentage: 1.5
      }],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 100,
      },
    },
    {
      name: 'notes',
      type: 'string',
      description: 'Additional notes or comments for the invoice',
      validation: {
        required: false,
        maxLength: 2000,
        customValidator: 'validateNoSQLInjection',
      },
      examples: ['Thank you for your business. Payment is due within 30 days.'],
      aiUsage: {
        includeInPrompt: false, // Don't include in AI prompts for security
        sanitize: true,
        maxTokens: 200,
      },
    },
    {
      name: 'internalReference',
      type: 'string',
      description: 'Internal reference or project code',
      validation: {
        required: false,
        maxLength: 100,
        pattern: '^[a-zA-Z0-9_-]*$',
      },
      examples: ['PROJECT-2024-Q1-ABC'],
      sensitive: true, // Mark as sensitive business data
      aiUsage: {
        includeInPrompt: false,
        sanitize: true,
        maxTokens: 20,
      },
    },
  ],

  // SQL Operation with safety constraints
  sqlOperation: {
    type: 'insert',
    table: 'invoices',
    allowedColumns: [
      'id', 'customer_id', 'invoice_number', 'issue_date', 'due_date',
      'currency', 'subtotal', 'tax_amount', 'total_amount', 'status',
      'payment_terms', 'notes', 'internal_reference', 'created_at', 'created_by'
    ],
    maxRows: 1, // Only insert one invoice at a time
    timeout: 30000, // 30 second timeout
    readOnly: false,
  },

  // Return type specification
  returnType: {
    type: 'object',
    schema: {
      type: 'object',
      properties: {
        invoiceId: { type: 'string' },
        invoiceNumber: { type: 'string' },
        totalAmount: { type: 'number' },
        taxAmount: { type: 'number' },
        status: { type: 'string' },
        createdAt: { type: 'string' },
        lineItemsCreated: { type: 'number' },
      },
      required: ['invoiceId', 'invoiceNumber', 'totalAmount'],
    },
    examples: [{
      invoiceId: 'inv_123e4567-e89b-12d3-a456-426614174000',
      invoiceNumber: 'INV-2024-001234',
      totalAmount: 5400.00,
      taxAmount: 400.00,
      status: 'draft',
      createdAt: '2024-03-15T10:30:00.000Z',
      lineItemsCreated: 1,
    }],
  },

  // Validation functions
  validation: {
    preExecution: [
      'validateCustomerExists',
      'validateInvoiceNumberUnique',
      'validateDateOrder',
      'validateLineItemTotals',
    ],
    postExecution: [
      'validateInvoiceCreated',
      'validateTaxCalculations',
    ],
    crossParameterValidation: 'validateInvoiceBusinessRules',
  },

  // Cost estimation
  costEstimation: {
    baseComputeUnits: 10, // Base cost for invoice creation
    perParameterUnits: 1,
    perRowUnits: 5, // Cost per line item
    customCostFactors: {
      lineItemCount: 2, // Additional cost per line item
      taxCalculation: 3, // Cost for tax calculations
    },
    maxCostUSD: 0.50, // Maximum $0.50 per invoice creation
  },

  // Permission requirements
  permissions: {
    requiredCapabilities: [
      'invoices:create',
      'customers:read',
      'financial:write',
    ],
    resourceTypes: ['invoice', 'customer'],
    businessContextRequired: true,
    userContextRequired: true,
    elevatedPrivileges: false,
  },

  // Audit configuration
  audit: {
    severity: 'high', // Financial operations are high severity
    eventType: 'invoice_creation',
    sensitiveDataHandling: {
      redactParameters: ['internalReference', 'notes'],
      redactResults: false,
      retentionDays: 2555, // 7 years for SOX compliance
    },
    complianceFlags: ['SOX', 'GAAP'],
    customMetadata: {
      category: 'financial_transaction',
      impactLevel: 'high',
    },
  },

  // Metadata
  tags: ['financial', 'invoice', 'accounting', 'high-value'],
  deprecated: false,
  owner: 'financial-systems-team',
  createdAt: 1710504000000, // 2024-03-15
  updatedAt: 1710504000000,

  // AI-specific configuration
  aiConfiguration: {
    promptTemplate: `Create an invoice with the following details:
- Customer: {customerId}
- Invoice Number: {invoiceNumber}
- Issue Date: {issueDate}
- Due Date: {dueDate}
- Line Items: {lineItems}
- Currency: {currency}

Validate all calculations and ensure compliance with tax regulations.`,
    responseProcessing: 'parseInvoiceCreationResult',
    fallbackBehavior: 'error',
    confidenceThreshold: 0.95, // High confidence required for financial operations
  },
};

/**
 * Ledger Posting Capability
 * Safely posts accounting entries to the general ledger
 */
export const LedgerPostingCapability: CapabilitySpec = {
  // Identity
  id: 'ledger:post',
  name: 'Post to General Ledger',
  description: 'Posts double-entry accounting transactions to the general ledger with automatic validation and balancing checks.',
  version: '1.1.0',
  category: 'database',

  // Parameters
  parameters: [
    {
      name: 'transactionId',
      type: 'string',
      description: 'Unique identifier for the transaction',
      validation: {
        required: true,
        format: 'uuid',
        minLength: 36,
        maxLength: 36,
      },
      examples: ['txn_123e4567-e89b-12d3-a456-426614174000'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 10,
      },
    },
    {
      name: 'journalEntries',
      type: 'array',
      description: 'Array of journal entries with account codes, amounts, and descriptions',
      validation: {
        required: true,
        minLength: 2, // Must have at least 2 entries (debit and credit)
        maxLength: 20, // Maximum 20 entries per transaction
        customValidator: 'validateJournalEntries',
      },
      examples: [[
        {
          accountCode: '1200', // Accounts Receivable
          debitAmount: 5400.00,
          creditAmount: 0,
          description: 'Invoice INV-2024-001234',
          referenceNumber: 'INV-2024-001234'
        },
        {
          accountCode: '4000', // Revenue
          debitAmount: 0,
          creditAmount: 5000.00,
          description: 'Professional Services Revenue',
          referenceNumber: 'INV-2024-001234'
        },
        {
          accountCode: '2200', // Sales Tax Payable
          debitAmount: 0,
          creditAmount: 400.00,
          description: 'Sales Tax on Invoice',
          referenceNumber: 'INV-2024-001234'
        }
      ]],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 800,
      },
    },
    {
      name: 'transactionDate',
      type: 'date',
      description: 'Date of the transaction for ledger posting',
      validation: {
        required: true,
        format: 'iso8601',
      },
      examples: ['2024-03-15T00:00:00.000Z'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 15,
      },
    },
    {
      name: 'description',
      type: 'string',
      description: 'General description of the transaction',
      validation: {
        required: true,
        minLength: 5,
        maxLength: 255,
        customValidator: 'validateNoSQLInjection',
      },
      examples: ['Invoice posting for customer services'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 50,
      },
    },
    {
      name: 'referenceType',
      type: 'enum',
      description: 'Type of source document',
      validation: {
        required: true,
        enum: ['invoice', 'payment', 'adjustment', 'accrual', 'reversal', 'transfer'],
      },
      examples: ['invoice'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 10,
      },
    },
    {
      name: 'referenceNumber',
      type: 'string',
      description: 'Reference number of the source document',
      validation: {
        required: true,
        minLength: 3,
        maxLength: 50,
        pattern: '^[a-zA-Z0-9_-]+$',
      },
      examples: ['INV-2024-001234'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 15,
      },
    },
    {
      name: 'fiscalPeriod',
      type: 'string',
      description: 'Fiscal period for the transaction (YYYY-MM format)',
      validation: {
        required: true,
        pattern: '^[0-9]{4}-[0-9]{2}$',
      },
      examples: ['2024-03'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 10,
      },
    },
    {
      name: 'autoBalance',
      type: 'boolean',
      description: 'Whether to automatically check that debits equal credits',
      validation: {
        required: false,
      },
      examples: [true],
      aiUsage: {
        includeInPrompt: false,
        sanitize: false,
      },
    },
    {
      name: 'approvalRequired',
      type: 'boolean',
      description: 'Whether this posting requires additional approval',
      validation: {
        required: false,
      },
      examples: [false],
      aiUsage: {
        includeInPrompt: false,
        sanitize: false,
      },
    },
    {
      name: 'metadata',
      type: 'object',
      description: 'Additional metadata for the ledger posting',
      validation: {
        required: false,
        customValidator: 'validateMetadataObject',
      },
      examples: [{
        department: 'sales',
        project: 'Q1-2024-initiatives',
        costCenter: 'CC-1001'
      }],
      sensitive: true, // Business-specific metadata
      aiUsage: {
        includeInPrompt: false,
        sanitize: true,
        maxTokens: 100,
      },
    },
  ],

  // SQL Operation for ledger posting
  sqlOperation: {
    type: 'insert',
    table: 'general_ledger',
    allowedColumns: [
      'id', 'transaction_id', 'account_code', 'debit_amount', 'credit_amount',
      'transaction_date', 'description', 'reference_type', 'reference_number',
      'fiscal_period', 'created_at', 'created_by', 'metadata'
    ],
    maxRows: 20, // Maximum 20 journal entries per transaction
    timeout: 45000, // 45 second timeout for complex transactions
    readOnly: false,
  },

  // Return type
  returnType: {
    type: 'object',
    schema: {
      type: 'object',
      properties: {
        transactionId: { type: 'string' },
        entriesPosted: { type: 'number' },
        totalDebits: { type: 'number' },
        totalCredits: { type: 'number' },
        balanced: { type: 'boolean' },
        fiscalPeriod: { type: 'string' },
        postedAt: { type: 'string' },
        ledgerEntryIds: { type: 'array', items: { type: 'string' } },
      },
      required: ['transactionId', 'entriesPosted', 'balanced'],
    },
    examples: [{
      transactionId: 'txn_123e4567-e89b-12d3-a456-426614174000',
      entriesPosted: 3,
      totalDebits: 5400.00,
      totalCredits: 5400.00,
      balanced: true,
      fiscalPeriod: '2024-03',
      postedAt: '2024-03-15T10:35:00.000Z',
      ledgerEntryIds: [
        'entry_001', 'entry_002', 'entry_003'
      ],
    }],
  },

  // Validation functions
  validation: {
    preExecution: [
      'validateAccountCodes',
      'validateFiscalPeriodOpen',
      'validateBalancingEntries',
      'validateTransactionLimits',
    ],
    postExecution: [
      'validateLedgerBalance',
      'validateTrialBalance',
      'validateAuditTrail',
    ],
    crossParameterValidation: 'validateLedgerPostingRules',
  },

  // Cost estimation
  costEstimation: {
    baseComputeUnits: 15, // Higher base cost for accounting operations
    perParameterUnits: 1,
    perRowUnits: 3, // Cost per journal entry
    customCostFactors: {
      entryCount: 2,
      balanceValidation: 5,
      auditTrail: 3,
    },
    maxCostUSD: 1.00, // Maximum $1.00 per ledger posting
  },

  // Permission requirements
  permissions: {
    requiredCapabilities: [
      'ledger:post',
      'accounting:write',
      'financial:transactions',
    ],
    resourceTypes: ['ledger', 'account'],
    businessContextRequired: true,
    userContextRequired: true,
    elevatedPrivileges: true, // Ledger posting requires elevated privileges
    approvalRequired: {
      minApprovers: 1,
      approverRoles: ['accounting_manager', 'controller'],
      timeoutMinutes: 60,
    },
  },

  // Audit configuration
  audit: {
    severity: 'critical', // Ledger operations are critical
    eventType: 'ledger_posting',
    sensitiveDataHandling: {
      redactParameters: ['metadata'],
      redactResults: false,
      retentionDays: 2555, // 7 years for SOX compliance
    },
    complianceFlags: ['SOX', 'GAAP', 'IFRS'],
    customMetadata: {
      category: 'accounting_transaction',
      impactLevel: 'critical',
      auditRequired: true,
    },
  },

  // Metadata
  tags: ['accounting', 'ledger', 'financial', 'critical', 'sox-compliance'],
  deprecated: false,
  owner: 'accounting-systems-team',
  createdAt: 1710504000000,
  updatedAt: 1710504000000,

  // AI configuration
  aiConfiguration: {
    promptTemplate: `Post the following journal entries to the general ledger:
- Transaction ID: {transactionId}
- Date: {transactionDate}
- Description: {description}
- Reference: {referenceType} {referenceNumber}
- Fiscal Period: {fiscalPeriod}

Journal Entries:
{journalEntries}

Ensure all entries are balanced and comply with accounting standards.`,
    responseProcessing: 'parseLedgerPostingResult',
    fallbackBehavior: 'error',
    confidenceThreshold: 0.99, // Very high confidence required for ledger operations
  },
};

/**
 * Customer Payment Processing Capability
 * Safely processes customer payments with fraud detection
 */
export const PaymentProcessingCapability: CapabilitySpec = {
  id: 'payment:process',
  name: 'Process Customer Payment',
  description: 'Processes customer payments with fraud detection, validation, and automatic ledger posting.',
  version: '1.0.0',
  category: 'api',

  parameters: [
    {
      name: 'paymentId',
      type: 'string',
      description: 'Unique payment identifier',
      validation: {
        required: true,
        format: 'uuid',
      },
      examples: ['pay_123e4567-e89b-12d3-a456-426614174000'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 10,
      },
    },
    {
      name: 'customerId',
      type: 'string',
      description: 'Customer making the payment',
      validation: {
        required: true,
        format: 'uuid',
      },
      examples: ['cust_123e4567-e89b-12d3-a456-426614174000'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 10,
      },
    },
    {
      name: 'amount',
      type: 'currency',
      description: 'Payment amount',
      validation: {
        required: true,
        min: 0.01,
        max: 100000.00,
      },
      examples: [1250.00],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 10,
      },
    },
    {
      name: 'currency',
      type: 'enum',
      description: 'Payment currency',
      validation: {
        required: true,
        enum: ['USD', 'EUR', 'GBP', 'CAD'],
      },
      examples: ['USD'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 5,
      },
    },
    {
      name: 'paymentMethod',
      type: 'enum',
      description: 'Method of payment',
      validation: {
        required: true,
        enum: ['credit_card', 'bank_transfer', 'ach', 'check', 'cash'],
      },
      examples: ['credit_card'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: false,
        maxTokens: 15,
      },
    },
    {
      name: 'paymentToken',
      type: 'string',
      description: 'Tokenized payment information',
      validation: {
        required: true,
        pattern: '^tok_[a-zA-Z0-9]{24}$',
      },
      examples: ['tok_1234567890abcdef12345678'],
      sensitive: true, // Payment tokens are sensitive
      aiUsage: {
        includeInPrompt: false, // Never include payment tokens in AI prompts
        sanitize: true,
      },
    },
    {
      name: 'invoiceIds',
      type: 'array',
      description: 'Invoices this payment applies to',
      validation: {
        required: false,
        maxLength: 10,
      },
      examples: [['INV-2024-001234', 'INV-2024-001235']],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 50,
      },
    },
  ],

  // API Operation for payment processing
  apiOperation: {
    method: 'POST',
    endpoint: '/payments/process',
    baseUrl: 'https://api.payments.coreflow360.com',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer {API_TOKEN}',
    },
    timeout: 30000,
    retries: 3,
    rateLimitPerMinute: 100,
  },

  returnType: {
    type: 'object',
    schema: {
      type: 'object',
      properties: {
        paymentId: { type: 'string' },
        status: { type: 'string' },
        transactionId: { type: 'string' },
        processedAmount: { type: 'number' },
        fees: { type: 'number' },
        fraudScore: { type: 'number' },
        processedAt: { type: 'string' },
      },
      required: ['paymentId', 'status', 'processedAmount'],
    },
  },

  validation: {
    preExecution: [
      'validateCustomerPaymentMethod',
      'validatePaymentLimits',
      'runFraudDetection',
      'validateInvoiceAmounts',
    ],
    postExecution: [
      'validateProcessingResult',
      'updateCustomerBalance',
    ],
  },

  costEstimation: {
    baseComputeUnits: 20,
    perRequestUnits: 10,
    customCostFactors: {
      fraudDetection: 5,
      paymentProcessing: 15,
    },
    maxCostUSD: 2.00,
  },

  permissions: {
    requiredCapabilities: [
      'payments:process',
      'customers:read',
      'financial:write',
    ],
    resourceTypes: ['payment', 'customer', 'invoice'],
    businessContextRequired: true,
    userContextRequired: true,
    elevatedPrivileges: true,
  },

  audit: {
    severity: 'critical',
    eventType: 'payment_processing',
    sensitiveDataHandling: {
      redactParameters: ['paymentToken'],
      redactResults: true,
      retentionDays: 2555,
    },
    complianceFlags: ['PCI-DSS', 'SOX', 'AML'],
  },

  tags: ['payment', 'financial', 'fraud-detection', 'pci-compliance'],
  owner: 'payments-team',
  createdAt: Date.now(),
  updatedAt: Date.now(),

  aiConfiguration: {
    promptTemplate: 'Process payment of {amount} {currency} for customer {customerId} using {paymentMethod}. Validate against invoices: {invoiceIds}',
    fallbackBehavior: 'error',
    confidenceThreshold: 0.98,
  },
};

/**
 * Example capability registry
 */
export const ExampleCapabilities = {
  invoice_create: InvoiceCreationCapability,
  ledger_post: LedgerPostingCapability,
  payment_process: PaymentProcessingCapability,
};

/**
 * Custom validation functions for the example capabilities
 */
export const ExampleValidators = {
  /**
   * Validate invoice line items structure and calculations
   */
  validateInvoiceLineItems: (lineItems: any[]): boolean => {
    if (!Array.isArray(lineItems) || lineItems.length === 0) {
      return false;
    }

    for (const item of lineItems) {
      // Validate required fields
      if (!item.description || !item.quantity || !item.unitPrice) {
        return false;
      }

      // Validate numeric values
      if (typeof item.quantity !== 'number' || item.quantity <= 0) {
        return false;
      }

      if (typeof item.unitPrice !== 'number' || item.unitPrice < 0) {
        return false;
      }

      // Validate calculated total
      const expectedTotal = item.quantity * item.unitPrice;
      if (item.lineTotal && Math.abs(item.lineTotal - expectedTotal) > 0.01) {
        return false;
      }
    }

    return true;
  },

  /**
   * Validate payment terms structure
   */
  validatePaymentTerms: (terms: any): boolean => {
    if (typeof terms !== 'object' || terms === null) {
      return false;
    }

    // Validate net days
    if (terms.net && (typeof terms.net !== 'number' || terms.net < 0 || terms.net > 365)) {
      return false;
    }

    // Validate discount percentage
    if (terms.discountPercentage && (typeof terms.discountPercentage !== 'number' || terms.discountPercentage < 0 || terms.discountPercentage > 100)) {
      return false;
    }

    return true;
  },

  /**
   * Validate journal entries for double-entry bookkeeping
   */
  validateJournalEntries: (entries: any[]): boolean => {
    if (!Array.isArray(entries) || entries.length < 2) {
      return false;
    }

    let totalDebits = 0;
    let totalCredits = 0;

    for (const entry of entries) {
      // Validate required fields
      if (!entry.accountCode || (!entry.debitAmount && !entry.creditAmount)) {
        return false;
      }

      // Validate account code format
      if (!/^[0-9]{4}$/.test(entry.accountCode)) {
        return false;
      }

      // Validate amounts
      const debit = entry.debitAmount || 0;
      const credit = entry.creditAmount || 0;

      if (typeof debit !== 'number' || typeof credit !== 'number') {
        return false;
      }

      if (debit < 0 || credit < 0) {
        return false;
      }

      // An entry should have either debit or credit, not both (or none)
      if ((debit > 0 && credit > 0) || (debit === 0 && credit === 0)) {
        return false;
      }

      totalDebits += debit;
      totalCredits += credit;
    }

    // Validate that debits equal credits (within 1 cent tolerance)
    return Math.abs(totalDebits - totalCredits) < 0.01;
  },

  /**
   * Cross-parameter validation for invoice business rules
   */
  validateInvoiceBusinessRules: (params: Record<string, unknown>): boolean => {
    const issueDate = new Date(params.issueDate as string);
    const dueDate = new Date(params.dueDate as string);

    // Due date must be after issue date
    if (dueDate <= issueDate) {
      return false;
    }

    // Due date shouldn't be more than 1 year in the future
    const oneYearFromNow = new Date();
    oneYearFromNow.setFullYear(oneYearFromNow.getFullYear() + 1);
    if (dueDate > oneYearFromNow) {
      return false;
    }

    return true;
  },

  /**
   * Validate ledger posting business rules
   */
  validateLedgerPostingRules: (params: Record<string, unknown>): boolean => {
    const entries = params.journalEntries as any[];
    const transactionDate = new Date(params.transactionDate as string);

    // Transaction date shouldn't be more than 30 days in the future
    const thirtyDaysFromNow = new Date();
    thirtyDaysFromNow.setDate(thirtyDaysFromNow.getDate() + 30);
    if (transactionDate > thirtyDaysFromNow) {
      return false;
    }

    // Validate fiscal period matches transaction date
    const fiscalPeriod = params.fiscalPeriod as string;
    const expectedPeriod = `${transactionDate.getFullYear()}-${String(transactionDate.getMonth() + 1).padStart(2, '0')}`;
    if (fiscalPeriod !== expectedPeriod) {
      return false;
    }

    return true;
  },

  /**
   * Validate metadata object structure
   */
  validateMetadataObject: (metadata: any): boolean => {
    if (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata)) {
      return false;
    }

    // Check for dangerous keys
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    for (const key of Object.keys(metadata)) {
      if (dangerousKeys.includes(key)) {
        return false;
      }
    }

    // Limit metadata size
    if (JSON.stringify(metadata).length > 10000) {
      return false;
    }

    return true;
  },
};