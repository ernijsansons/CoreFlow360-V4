/**
 * Example Capability Definitions
 * Demonstrates safe AI tool use for invoice creation and ledger posting
 */
import { CapabilitySpec } from './types';

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
  returnType: { type: 'object', schema: {}, examples: [] },
  validation: { preExecution: [], postExecution: [] },
  owner: 'system',
  createdAt: Date.now(),
  updatedAt: Date.now(),

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
      description: 'Unique invoice number',
      validation: {
        required: true,
        pattern: '^INV-[0-9]{6}$',
        minLength: 10,
        maxLength: 10,
      },
      examples: ['INV-123456'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 15,
      },
    },
    {
      name: 'lineItems',
      type: 'array',
      description: 'Array of invoice line items',
      validation: {
        required: true,
        minItems: 1,
        maxItems: 100,
        items: {
          required: true,
        },
      },
      examples: [
        [
          {
            description: 'Software License',
            quantity: 1,
            unitPrice: 1000.00,
            taxRate: 0.10,
          },
        ],
      ],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 200,
      },
    },
    {
      name: 'dueDate',
      type: 'string',
      description: 'Invoice due date in ISO format',
      validation: {
        required: true,
        format: 'date',
      },
      examples: ['2024-12-31'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 15,
      },
    },
    {
      name: 'paymentTerms',
      type: 'string',
      description: 'Payment terms description',
      validation: {
        required: false,
        maxLength: 200,
        enum: ['Net 30', 'Net 15', 'Due on Receipt', 'Custom'],
      },
      examples: ['Net 30'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 20,
      },
    },
  ],

  // SQL operations with safety checks
  // SQL operation with safety checks
  sqlOperation: {
    type: 'select' as const,
    table: 'customers',
    maxRows: 100,
    timeout: 5000,
    readOnly: true,
  },

  // Cost tracking
  costEstimation: {
    baseComputeUnits: 0.01, // $0.01 per invoice
    perRowUnits: 0.005, // $0.005 per line item
    maxCostUSD: 1.00, // Maximum $1.00 per operation
    
  },

  // Permission requirements
  permissions: {
    requiredCapabilities: ['invoices:create', 'customers:read'],
    businessContextRequired: true,
    userContextRequired: true,
    required: ['invoices:create', 'customers:read'],
    optional: ['invoices:approve', 'notifications:send'],
    businessRules: [
      'User must have access to customer data',
      'Invoice must be within business credit limits',
      'All line items must be valid and approved',
    ],
  },

  // Audit requirements
  audit: {
    severity: 'high' as const,
    eventType: 'invoice_creation',
    enabled: true,
    logLevel: 'info',
    requiredFields: ['userId', 'businessId', 'customerId', 'invoiceNumber'],
    retentionDays: 2555, // 7 years
    sensitiveDataHandling: {
      redactParameters: ['customerId', 'invoiceNumber'],
      redactResults: false,
      retentionDays: 2555
    },
  },

  // AI safety measures
  aiSafety: {
    maxTokens: 500,
    temperature: 0.1,
    topP: 0.9,
    frequencyPenalty: 0.1,
    presencePenalty: 0.1,
    stopSequences: ['<|endoftext|>', '<|stop|>'],
    contentFilter: true,
    biasDetection: true,
    hallucinationCheck: true,
  },



};

/**
 * Ledger Posting Capability
 * Safely posts transactions to the general ledger
 */
export const LedgerPostingCapability: CapabilitySpec = {
  // Identity
  id: 'ledger:post',
  name: 'Post to Ledger',
  description: 'Posts accounting transactions to the general ledger with double-entry validation and audit trail.',
  version: '1.1.0',
  category: 'database',
  returnType: { type: 'object', schema: {}, examples: [] },
  validation: { preExecution: [], postExecution: [] },
  owner: 'system',
  createdAt: Date.now(),
  updatedAt: Date.now(),

  // Parameters
  parameters: [
    {
      name: 'transactionId',
      type: 'string',
      description: 'Unique transaction identifier',
      validation: {
        required: true,
        pattern: '^TXN-[0-9]{8}$',
        minLength: 12,
        maxLength: 12,
      },
      examples: ['TXN-12345678'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 15,
      },
    },
    {
      name: 'entries',
      type: 'array',
      description: 'Array of ledger entries (must balance)',
      validation: {
        required: true,
        minItems: 2,
        maxItems: 50,
        items: {
          required: true,
        },
      },
      examples: [
        [
          {
            accountCode: '1000',
            description: 'Cash received from customer',
            debitAmount: 1000.00,
            creditAmount: 0.00,
          },
          {
            accountCode: '2000',
            description: 'Revenue from sales',
            debitAmount: 0.00,
            creditAmount: 1000.00,
          },
        ],
      ],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 300,
      },
    },
    {
      name: 'reference',
      type: 'string',
      description: 'Reference document (invoice, receipt, etc.)',
      validation: {
        required: false,
        maxLength: 100,
      },
      examples: ['INV-123456'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 20,
      },
    },
    {
      name: 'postingDate',
      type: 'string',
      description: 'Date of the transaction',
      validation: {
        required: true,
        format: 'date',
      },
      examples: ['2024-01-15'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 15,
      },
    },
  ],

  // SQL operation with safety checks
  sqlOperation: {
    type: 'select' as const,
    table: 'ledger_entries',
    maxRows: 100,
    timeout: 5000,
    readOnly: false,
  },

  // Cost tracking
  costEstimation: {
    baseComputeUnits: 0.02, // $0.02 per transaction
    perRowUnits: 0.01, // $0.01 per entry
    maxCostUSD: 2.00, // Maximum $2.00 per operation
    
  },

  // Permission requirements
  permissions: {
    requiredCapabilities: ['ledger:post', 'accounts:read'],
    businessContextRequired: true,
    userContextRequired: true,
    required: ['ledger:post', 'accounts:read'],
    optional: ['ledger:approve', 'accounts:write'],
    businessRules: [
      'All entries must balance (debits = credits)',
      'Account codes must exist in chart of accounts',
      'Posting date cannot be in the future',
      'Transaction must be approved before posting',
    ],
  },

  // Audit requirements
  audit: {
    severity: 'critical' as const,
    eventType: 'ledger_posting',
    enabled: true,
    logLevel: 'info',
    requiredFields: ['userId', 'businessId', 'transactionId', 'postingDate'],
    retentionDays: 2555, // 7 years
    sensitiveDataHandling: {
      redactParameters: ['transactionId', 'accountCode'],
      redactResults: false,
      retentionDays: 2555
    },
  },

  // AI safety measures
  aiSafety: {
    maxTokens: 400,
    temperature: 0.05,
    topP: 0.8,
    frequencyPenalty: 0.2,
    presencePenalty: 0.2,
    stopSequences: ['<|endoftext|>', '<|stop|>'],
    contentFilter: true,
    biasDetection: true,
    hallucinationCheck: true,
  },



};

/**
 * Customer Lookup Capability
 * Safely retrieves customer information
 */
export const CustomerLookupCapability: CapabilitySpec = {
  // Identity
  id: 'customer:lookup',
  name: 'Lookup Customer',
  description: 'Retrieves customer information with privacy controls and access logging.',
  version: '1.0.0',
  category: 'database',
  returnType: { type: 'object', schema: {}, examples: [] },
  validation: { preExecution: [], postExecution: [] },
  owner: 'system',
  createdAt: Date.now(),
  updatedAt: Date.now(),

  // Parameters
  parameters: [
    {
      name: 'customerId',
      type: 'string',
      description: 'Customer identifier',
      validation: {
        required: true,
        pattern: '^[a-zA-Z0-9_-]+$',
        minLength: 3,
        maxLength: 50,
      },
      examples: ['cust_123e4567-e89b-12d3-a456-426614174000'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 10,
      },
    },
    {
      name: 'fields',
      type: 'array',
      description: 'Specific fields to retrieve',
      validation: {
        required: false,
        items: {
          required: false,
          enum: ['id', 'name', 'email', 'phone', 'address', 'status', 'created_at'],
        },
      },
      examples: [['id', 'name', 'email']],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 50,
      },
    },
  ],

  // SQL operation with safety checks
  sqlOperation: {
    type: 'select' as const,
    table: 'customers',
    maxRows: 1,
    timeout: 5000,
    readOnly: true,
  },

  // Cost tracking
  costEstimation: {
    baseComputeUnits: 0.001, // $0.001 per lookup
    maxCostUSD: 0.10, // Maximum $0.10 per operation
    
  },

  // Permission requirements
  permissions: {
    requiredCapabilities: ['customers:read'],
    businessContextRequired: true,
    userContextRequired: true,
    required: ['customers:read'],
    optional: ['customers:read_sensitive'],
    businessRules: [
      'User must have customer access permissions',
      'Sensitive fields require additional permissions',
      'Customer must be active',
    ],
  },

  // Audit requirements
  audit: {
    severity: 'medium' as const,
    eventType: 'customer_lookup',
    enabled: true,
    logLevel: 'info',
    requiredFields: ['userId', 'businessId', 'customerId'],
    retentionDays: 365, // 1 year
    sensitiveDataHandling: {
      redactParameters: ['customerId'],
      redactResults: false,
      retentionDays: 365
    },
  },

  // AI safety measures
  aiSafety: {
    maxTokens: 200,
    temperature: 0.1,
    topP: 0.9,
    frequencyPenalty: 0.1,
    presencePenalty: 0.1,
    stopSequences: ['<|endoftext|>', '<|stop|>'],
    contentFilter: true,
    biasDetection: false,
    hallucinationCheck: false,
  },



};

