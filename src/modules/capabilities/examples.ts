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
          type: 'object',
          properties: {
            description: { type: 'string', minLength: 1, maxLength: 500 },
            quantity: { type: 'number', minimum: 0.01, maximum: 10000 },
            unitPrice: { type: 'number', minimum: 0, maximum: 1000000 },
            taxRate: { type: 'number', minimum: 0, maximum: 1 },
          },
          required: ['description', 'quantity', 'unitPrice', 'taxRate'],
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
        minDate: 'today',
        maxDate: '+1y',
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
  sqlOperations: [
    {
      id: 'validate_customer',
      description: 'Validate customer exists and is active',
      query: 'SELECT id, name, status FROM customers WHERE id = ? AND status = "active"',
      parameters: ['customerId'],
      timeout: 5000,
      retries: 3,
      validation: {
        requiredRows: 1,
        maxRows: 1,
      },
    },
    {
      id: 'check_invoice_number',
      description: 'Check if invoice number already exists',
      query: 'SELECT id FROM invoices WHERE invoice_number = ?',
      parameters: ['invoiceNumber'],
      timeout: 5000,
      retries: 3,
      validation: {
        requiredRows: 0,
        maxRows: 0,
      },
    },
    {
      id: 'create_invoice',
      description: 'Create the invoice record',
      query: `
        INSERT INTO invoices (
          id, customer_id, invoice_number, due_date, payment_terms,
          subtotal, tax_amount, total_amount, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?)
      `,
      parameters: [
        'invoiceId',
        'customerId',
        'invoiceNumber',
        'dueDate',
        'paymentTerms',
        'subtotal',
        'taxAmount',
        'totalAmount',
        'createdAt',
        'updatedAt',
      ],
      timeout: 10000,
      retries: 3,
      validation: {
        requiredRows: 1,
        maxRows: 1,
      },
    },
    {
      id: 'create_line_items',
      description: 'Create invoice line items',
      query: `
        INSERT INTO invoice_line_items (
          id, invoice_id, description, quantity, unit_price, tax_rate,
          line_total, tax_amount, total_amount, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      parameters: [
        'lineItemId',
        'invoiceId',
        'description',
        'quantity',
        'unitPrice',
        'taxRate',
        'lineTotal',
        'taxAmount',
        'totalAmount',
        'createdAt',
      ],
      timeout: 15000,
      retries: 3,
      validation: {
        requiredRows: 1,
        maxRows: 1,
      },
    },
  ],

  // API operations for external integrations
  apiOperations: [
    {
      id: 'notify_customer',
      description: 'Send invoice notification to customer',
      method: 'POST',
      url: 'https://api.example.com/notifications/invoice',
      headers: {
        'Authorization': 'Bearer ${apiKey}',
        'Content-Type': 'application/json',
      },
      body: {
        customerId: '${customerId}',
        invoiceNumber: '${invoiceNumber}',
        totalAmount: '${totalAmount}',
        dueDate: '${dueDate}',
      },
      timeout: 10000,
      retries: 2,
      validation: {
        successStatus: [200, 201],
        errorStatus: [400, 401, 403, 404, 500],
      },
    },
  ],

  // Cost tracking
  cost: {
    baseCost: 0.01, // $0.01 per invoice
    perLineItem: 0.005, // $0.005 per line item
    maxCost: 1.00, // Maximum $1.00 per operation
    currency: 'USD',
  },

  // Permission requirements
  permissions: {
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
    enabled: true,
    logLevel: 'info',
    requiredFields: ['userId', 'businessId', 'customerId', 'invoiceNumber'],
    retentionDays: 2555, // 7 years
    sensitiveFields: ['customerId', 'invoiceNumber'],
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

  // Rate limiting
  rateLimit: {
    requestsPerMinute: 60,
    requestsPerHour: 1000,
    requestsPerDay: 10000,
    burstLimit: 10,
  },

  // Error handling
  errorHandling: {
    retryableErrors: ['TIMEOUT', 'NETWORK_ERROR', 'RATE_LIMIT'],
    nonRetryableErrors: ['VALIDATION_ERROR', 'PERMISSION_DENIED', 'INVALID_CUSTOMER'],
    maxRetries: 3,
    backoffMultiplier: 2,
    maxBackoffMs: 30000,
  },

  // Monitoring and alerting
  monitoring: {
    enabled: true,
    metrics: ['success_rate', 'response_time', 'error_rate', 'cost_per_operation'],
    alerts: [
      {
        metric: 'error_rate',
        threshold: 0.05, // 5%
        severity: 'warning',
      },
      {
        metric: 'response_time',
        threshold: 5000, // 5 seconds
        severity: 'warning',
      },
    ],
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
          type: 'object',
          properties: {
            accountCode: { type: 'string', pattern: '^[0-9]{4}$' },
            description: { type: 'string', minLength: 1, maxLength: 200 },
            debitAmount: { type: 'number', minimum: 0 },
            creditAmount: { type: 'number', minimum: 0 },
          },
          required: ['accountCode', 'description', 'debitAmount', 'creditAmount'],
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
        maxDate: 'today',
      },
      examples: ['2024-01-15'],
      aiUsage: {
        includeInPrompt: true,
        sanitize: true,
        maxTokens: 15,
      },
    },
  ],

  // SQL operations
  sqlOperations: [
    {
      id: 'validate_accounts',
      description: 'Validate all account codes exist',
      query: 'SELECT code FROM chart_of_accounts WHERE code IN (?)',
      parameters: ['accountCodes'],
      timeout: 5000,
      retries: 3,
      validation: {
        requiredRows: 'all',
        maxRows: 50,
      },
    },
    {
      id: 'check_balance',
      description: 'Verify entries balance (debits = credits)',
      query: 'SELECT SUM(debit_amount) as total_debits, SUM(credit_amount) as total_credits FROM temp_entries',
      parameters: [],
      timeout: 5000,
      retries: 3,
      validation: {
        custom: 'total_debits === total_credits',
      },
    },
    {
      id: 'create_transaction',
      description: 'Create the transaction record',
      query: `
        INSERT INTO transactions (
          id, transaction_id, reference, posting_date, total_debits, total_credits,
          status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'posted', ?, ?)
      `,
      parameters: [
        'transactionUuid',
        'transactionId',
        'reference',
        'postingDate',
        'totalDebits',
        'totalCredits',
        'createdAt',
        'updatedAt',
      ],
      timeout: 10000,
      retries: 3,
      validation: {
        requiredRows: 1,
        maxRows: 1,
      },
    },
    {
      id: 'create_entries',
      description: 'Create ledger entries',
      query: `
        INSERT INTO ledger_entries (
          id, transaction_id, account_code, description, debit_amount, credit_amount,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      parameters: [
        'entryId',
        'transactionUuid',
        'accountCode',
        'description',
        'debitAmount',
        'creditAmount',
        'createdAt',
      ],
      timeout: 15000,
      retries: 3,
      validation: {
        requiredRows: 1,
        maxRows: 1,
      },
    },
  ],

  // Cost tracking
  cost: {
    baseCost: 0.02, // $0.02 per transaction
    perEntry: 0.01, // $0.01 per entry
    maxCost: 2.00, // Maximum $2.00 per operation
    currency: 'USD',
  },

  // Permission requirements
  permissions: {
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
    enabled: true,
    logLevel: 'info',
    requiredFields: ['userId', 'businessId', 'transactionId', 'postingDate'],
    retentionDays: 2555, // 7 years
    sensitiveFields: ['transactionId', 'accountCode'],
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

  // Rate limiting
  rateLimit: {
    requestsPerMinute: 30,
    requestsPerHour: 500,
    requestsPerDay: 5000,
    burstLimit: 5,
  },

  // Error handling
  errorHandling: {
    retryableErrors: ['TIMEOUT', 'NETWORK_ERROR', 'RATE_LIMIT'],
    nonRetryableErrors: ['VALIDATION_ERROR', 'PERMISSION_DENIED', 'UNBALANCED_ENTRIES'],
    maxRetries: 3,
    backoffMultiplier: 2,
    maxBackoffMs: 30000,
  },

  // Monitoring and alerting
  monitoring: {
    enabled: true,
    metrics: ['success_rate', 'response_time', 'error_rate', 'cost_per_operation'],
    alerts: [
      {
        metric: 'error_rate',
        threshold: 0.02, // 2%
        severity: 'critical',
      },
      {
        metric: 'response_time',
        threshold: 3000, // 3 seconds
        severity: 'warning',
      },
    ],
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
          type: 'string',
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

  // SQL operations
  sqlOperations: [
    {
      id: 'lookup_customer',
      description: 'Retrieve customer information',
      query: 'SELECT ${fields} FROM customers WHERE id = ? AND status = "active"',
      parameters: ['customerId'],
      timeout: 5000,
      retries: 3,
      validation: {
        requiredRows: 1,
        maxRows: 1,
      },
    },
  ],

  // Cost tracking
  cost: {
    baseCost: 0.001, // $0.001 per lookup
    maxCost: 0.10, // Maximum $0.10 per operation
    currency: 'USD',
  },

  // Permission requirements
  permissions: {
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
    enabled: true,
    logLevel: 'info',
    requiredFields: ['userId', 'businessId', 'customerId'],
    retentionDays: 365, // 1 year
    sensitiveFields: ['customerId'],
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

  // Rate limiting
  rateLimit: {
    requestsPerMinute: 120,
    requestsPerHour: 2000,
    requestsPerDay: 20000,
    burstLimit: 20,
  },

  // Error handling
  errorHandling: {
    retryableErrors: ['TIMEOUT', 'NETWORK_ERROR'],
    nonRetryableErrors: ['VALIDATION_ERROR', 'PERMISSION_DENIED', 'CUSTOMER_NOT_FOUND'],
    maxRetries: 2,
    backoffMultiplier: 1.5,
    maxBackoffMs: 5000,
  },

  // Monitoring and alerting
  monitoring: {
    enabled: true,
    metrics: ['success_rate', 'response_time', 'error_rate', 'cost_per_operation'],
    alerts: [
      {
        metric: 'error_rate',
        threshold: 0.10, // 10%
        severity: 'warning',
      },
      {
        metric: 'response_time',
        threshold: 2000, // 2 seconds
        severity: 'warning',
      },
    ],
  },
};

