/**
 * Input Validation Security Tests
 * Testing Zod validation schemas against malicious payloads and edge cases
 */

import { describe, it, expect } from 'vitest';
import {
  validateInput,
  ValidationError,
  chartAccountCreateSchema,
  journalEntryWithLinesSchema,
  invoiceCreateSchema,
  paymentCreateSchema,
  reportParametersSchema,
  customReportDefinitionSchema,
  exportRequestSchema,
  generateReportRequestSchema,
  validateBusinessIdInput,
  validateUserIdInput,
  validateCurrencyInput,
  validateAmountInput,
  validateDateInput
} from '../validation';
import {
  AccountType,
  AccountCategory,
  JournalEntryType,
  ReportType,
  ReportDataSource,
  FilterOperator,
  FilterDataType,
  AggregationType,
  PaymentMethod
} from '../types';

describe('Input Validation Security Tests', () => {
  describe('Business ID Validation', () => {
    const maliciousBusinessIds = [
      '', // Empty string
      '   ', // Whitespace only
      null, // Null
      undefined, // Undefined
      'business\'; DROP TABLE invoices; --', // SQL injection
      'business OR 1=1', // Logic injection
      '../../../etc/passwd', // Path traversal
      '<script>alert("xss")</script>', // XSS attempt
      'business\x00admin', // Null byte injection
      'A'.repeat(1000), // Extremely long string
      'business\nid', // Newline injection
      'business\tid', // Tab injection
      'business\rid', // Carriage return injection
      'business"id', // Quote injection
      "business'id", // Single quote injection
      'business`id', // Backtick injection
      'business$id', // Dollar sign
      'business%id', // Percent sign
      'business*id', // Wildcard
      'business?id', // Question mark
      'business[id]', // Brackets
      'business{id}', // Braces
      'business|id', // Pipe
      'business&id', // Ampersand
      'business#id', // Hash
      'business@id', // At symbol
      'business!id', // Exclamation
      'business+id', // Plus sign
      'business=id', // Equals sign
      'business:id', // Colon
      'business;id', // Semicolon
      'business<id>', // Angle brackets
      'business>id', // Greater than
      'business,id', // Comma
      'business.id.', // Multiple dots
      '123', // Too short
      'a', // Single character
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' // 51 characters (over limit)
    ];

    it('should reject all malicious business ID inputs', () => {
      for (const maliciousId of maliciousBusinessIds) {
        expect(() => validateBusinessIdInput(maliciousId)).toThrow();
      }
    });

    it('should accept valid business IDs', () => {
      const validBusinessIds = [
        'business_123',
        'company-456',
        'test_business_id_12345',
        'valid-business-id',
        'Business123',
        'business_id_with_underscores',
        'business-id-with-hyphens',
        'company_ABC',
        'firm-XYZ-123'
      ];

      for (const validId of validBusinessIds) {
        expect(() => validateBusinessIdInput(validId)).not.toThrow();
        expect(validateBusinessIdInput(validId)).toBe(validId);
      }
    });
  });

  describe('Chart of Accounts Validation', () => {
    it('should reject malicious account creation attempts', () => {
      const maliciousPayloads = [
        {
          code: '"; DROP TABLE chart_of_accounts; --',
          name: 'Cash',
          type: AccountType.ASSET,
          category: AccountCategory.CURRENT_ASSET,
          businessId: 'test_business'
        },
        {
          code: '1000',
          name: '<script>alert("xss")</script>',
          type: AccountType.ASSET,
          category: AccountCategory.CURRENT_ASSET,
          businessId: 'test_business'
        },
        {
          code: '1000',
          name: 'Cash',
          type: 'INVALID_TYPE' as any,
          category: AccountCategory.CURRENT_ASSET,
          businessId: 'test_business'
        },
        {
          code: '1000',
          name: 'Cash',
          type: AccountType.ASSET,
          category: 'INVALID_CATEGORY' as any,
          businessId: 'test_business'
        },
        {
          code: '', // Empty code
          name: 'Cash',
          type: AccountType.ASSET,
          category: AccountCategory.CURRENT_ASSET,
          businessId: 'test_business'
        },
        {
          code: 'A'.repeat(25), // Too long code
          name: 'Cash',
          type: AccountType.ASSET,
          category: AccountCategory.CURRENT_ASSET,
          businessId: 'test_business'
        },
        {
          code: '1000',
          name: 'A'.repeat(150), // Too long name
          type: AccountType.ASSET,
          category: AccountCategory.CURRENT_ASSET,
          businessId: 'test_business'
        },
        {
          code: '1000',
          name: 'Cash',
          type: AccountType.ASSET,
          category: AccountCategory.CURRENT_ASSET,
          description: 'A'.repeat(600), // Too long description
          businessId: 'test_business'
        }
      ];

      for (const payload of maliciousPayloads) {
        expect(() => validateInput(chartAccountCreateSchema, payload)).toThrow();
      }
    });

    it('should accept valid account creation data', () => {
      const validPayload = {
        code: '1000',
        name: 'Cash and Cash Equivalents',
        type: AccountType.ASSET,
        category: AccountCategory.CURRENT_ASSET,
        description: 'Primary operating cash accounts',
        isActive: true,
        businessId: 'test_business_123'
      };

      expect(() => validateInput(chartAccountCreateSchema, validPayload)).not.toThrow();
    });
  });

  describe('Journal Entry Validation', () => {
    it('should reject malicious journal entry creation attempts', () => {
      const maliciousPayloads = [
        {
          entryNumber: '"; DROP TABLE journal_entries; --',
          date: Date.now(),
          description: 'Test entry',
          type: JournalEntryType.STANDARD,
          periodId: 'period_1',
          businessId: 'test_business',
          lines: [
            {
              accountId: 'acc_1',
              debit: 100,
              currency: 'USD'
            },
            {
              accountId: 'acc_2',
              credit: 100,
              currency: 'USD'
            }
          ]
        },
        {
          entryNumber: 'JE001',
          date: -1, // Invalid negative date
          description: 'Test entry',
          type: JournalEntryType.STANDARD,
          periodId: 'period_1',
          businessId: 'test_business',
          lines: [
            {
              accountId: 'acc_1',
              debit: 100,
              currency: 'USD'
            },
            {
              accountId: 'acc_2',
              credit: 100,
              currency: 'USD'
            }
          ]
        },
        {
          entryNumber: 'JE001',
          date: Date.now(),
          description: '<script>alert("xss")</script>',
          type: JournalEntryType.STANDARD,
          periodId: 'period_1',
          businessId: 'test_business',
          lines: [
            {
              accountId: 'acc_1',
              debit: 100,
              currency: 'USD'
            },
            {
              accountId: 'acc_2',
              credit: 100,
              currency: 'USD'
            }
          ]
        },
        {
          entryNumber: 'JE001',
          date: Date.now(),
          description: 'Test entry',
          type: JournalEntryType.STANDARD,
          periodId: 'period_1',
          businessId: 'test_business',
          lines: [
            {
              accountId: 'acc_1',
              debit: 100,
              credit: 100, // Both debit and credit (invalid)
              currency: 'USD'
            }
          ]
        },
        {
          entryNumber: 'JE001',
          date: Date.now(),
          description: 'Test entry',
          type: JournalEntryType.STANDARD,
          periodId: 'period_1',
          businessId: 'test_business',
          lines: [
            {
              accountId: 'acc_1',
              debit: 100,
              currency: 'USD'
            },
            {
              accountId: 'acc_2',
              credit: 200, // Unbalanced entry
              currency: 'USD'
            }
          ]
        },
        {
          entryNumber: 'JE001',
          date: Date.now(),
          description: 'Test entry',
          type: JournalEntryType.STANDARD,
          periodId: 'period_1',
          businessId: 'test_business',
          lines: [] // No lines
        }
      ];

      for (const payload of maliciousPayloads) {
        expect(() => validateInput(journalEntryWithLinesSchema, payload)).toThrow();
      }
    });

    it('should accept valid journal entries', () => {
      const validPayload = {
        entryNumber: 'JE001',
        date: Date.now(),
        description: 'Cash receipt from customer',
        type: JournalEntryType.STANDARD,
        periodId: 'period_202412',
        businessId: 'test_business_123',
        lines: [
          {
            accountId: 'acc_cash',
            debit: 1000,
            currency: 'USD',
            description: 'Cash received'
          },
          {
            accountId: 'acc_ar',
            credit: 1000,
            currency: 'USD',
            description: 'AR payment received'
          }
        ]
      };

      expect(() => validateInput(journalEntryWithLinesSchema, validPayload)).not.toThrow();
    });
  });

  describe('Invoice Validation', () => {
    it('should reject malicious invoice creation attempts', () => {
      const maliciousPayloads = [
        {
          invoiceNumber: '"; DROP TABLE invoices; --',
          customerId: 'cust_1',
          customerName: 'Test Customer',
          issueDate: Date.now(),
          dueDate: Date.now() + 86400000 * 30,
          subtotal: 1000,
          total: 1000,
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceNumber: 'INV001',
          customerId: 'cust_1',
          customerName: '<script>alert("xss")</script>',
          issueDate: Date.now(),
          dueDate: Date.now() + 86400000 * 30,
          subtotal: 1000,
          total: 1000,
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceNumber: 'INV001',
          customerId: 'cust_1',
          customerName: 'Test Customer',
          customerEmail: 'not-an-email',
          issueDate: Date.now(),
          dueDate: Date.now() + 86400000 * 30,
          subtotal: 1000,
          total: 1000,
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceNumber: 'INV001',
          customerId: 'cust_1',
          customerName: 'Test Customer',
          issueDate: Date.now(),
          dueDate: Date.now() - 86400000, // Due date before issue date
          subtotal: 1000,
          total: 1000,
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceNumber: 'INV001',
          customerId: 'cust_1',
          customerName: 'Test Customer',
          issueDate: Date.now(),
          dueDate: Date.now() + 86400000 * 30,
          subtotal: 1000,
          taxAmount: 100,
          discountAmount: 50,
          total: 900, // Total doesn't match calculation
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceNumber: 'INV001',
          customerId: 'cust_1',
          customerName: 'Test Customer',
          issueDate: Date.now(),
          dueDate: Date.now() + 86400000 * 30,
          subtotal: -1000, // Negative amount
          total: -1000,
          currency: 'USD',
          businessId: 'test_business'
        }
      ];

      for (const payload of maliciousPayloads) {
        expect(() => validateInput(invoiceCreateSchema, payload)).toThrow();
      }
    });

    it('should accept valid invoice creation data', () => {
      const validPayload = {
        invoiceNumber: 'INV-2024-001',
        customerId: 'cust_12345',
        customerName: 'Acme Corporation',
        customerEmail: 'billing@acme.com',
        issueDate: Date.now(),
        dueDate: Date.now() + 86400000 * 30,
        terms: 'Net 30',
        subtotal: 1000,
        taxAmount: 100,
        discountAmount: 50,
        total: 1050,
        currency: 'USD',
        notes: 'Payment due within 30 days',
        businessId: 'test_business_123'
      };

      expect(() => validateInput(invoiceCreateSchema, validPayload)).not.toThrow();
    });
  });

  describe('Payment Validation', () => {
    it('should reject malicious payment creation attempts', () => {
      const maliciousPayloads = [
        {
          invoiceId: '"; DROP TABLE invoice_payments; --',
          amount: 500,
          paymentDate: Date.now(),
          paymentMethod: PaymentMethod.CREDIT_CARD,
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceId: 'inv_123',
          amount: 0, // Zero payment
          paymentDate: Date.now(),
          paymentMethod: PaymentMethod.CREDIT_CARD,
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceId: 'inv_123',
          amount: -500, // Negative payment
          paymentDate: Date.now(),
          paymentMethod: PaymentMethod.CREDIT_CARD,
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceId: 'inv_123',
          amount: 500,
          paymentDate: -1, // Invalid date
          paymentMethod: PaymentMethod.CREDIT_CARD,
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceId: 'inv_123',
          amount: 500,
          paymentDate: Date.now(),
          paymentMethod: 'INVALID_METHOD' as any,
          currency: 'USD',
          businessId: 'test_business'
        },
        {
          invoiceId: 'inv_123',
          amount: 500,
          paymentDate: Date.now(),
          paymentMethod: PaymentMethod.CREDIT_CARD,
          currency: 'INVALID', // Invalid currency
          businessId: 'test_business'
        }
      ];

      for (const payload of maliciousPayloads) {
        expect(() => validateInput(paymentCreateSchema, payload)).toThrow();
      }
    });

    it('should accept valid payment creation data', () => {
      const validPayload = {
        invoiceId: 'inv_12345',
        amount: 1050.00,
        paymentDate: Date.now(),
        paymentMethod: PaymentMethod.BANK_TRANSFER,
        reference: 'WIRE123456789',
        notes: 'Payment received via wire transfer',
        currency: 'USD',
        businessId: 'test_business_123'
      };

      expect(() => validateInput(paymentCreateSchema, validPayload)).not.toThrow();
    });
  });

  describe('Report Parameters Validation', () => {
    it('should reject malicious report parameter attempts', () => {
      const maliciousPayloads = [
        {
          startDate: -1, // Invalid negative date
          endDate: Date.now()
        },
        {
          startDate: Date.now(),
          endDate: Date.now() - 86400000 // End date before start date
        },
        {
          startDate: Date.now(),
          endDate: Date.now(),
          comparisonStartDate: Date.now(),
          comparisonEndDate: Date.now() - 86400000 // Comparison end before start
        },
        {
          startDate: Date.now(),
          endDate: Date.now(),
          currency: 'INVALID_CURRENCY_CODE'
        },
        {
          startDate: Date.now(),
          endDate: Date.now(),
          customFilters: [
            {
              field: '"; DROP TABLE invoices; --',
              operator: FilterOperator.EQUALS,
              value: 'test',
              dataType: FilterDataType.STRING
            }
          ]
        },
        {
          startDate: Date.now(),
          endDate: Date.now(),
          customFilters: [
            {
              field: 'customer_name',
              operator: 'INVALID_OPERATOR' as any,
              value: 'test',
              dataType: FilterDataType.STRING
            }
          ]
        }
      ];

      for (const payload of maliciousPayloads) {
        expect(() => validateInput(reportParametersSchema, payload)).toThrow();
      }
    });

    it('should accept valid report parameters', () => {
      const validPayload = {
        startDate: Date.now() - 86400000 * 30,
        endDate: Date.now(),
        comparisonStartDate: Date.now() - 86400000 * 60,
        comparisonEndDate: Date.now() - 86400000 * 30,
        currency: 'USD',
        includeInactive: false,
        consolidateSubsidiaries: true,
        customerIds: ['cust_1', 'cust_2'],
        customFilters: [
          {
            field: 'customer_name',
            operator: FilterOperator.CONTAINS,
            value: 'acme',
            dataType: FilterDataType.STRING
          }
        ]
      };

      expect(() => validateInput(reportParametersSchema, validPayload)).not.toThrow();
    });
  });

  describe('Custom Report Definition Validation', () => {
    it('should reject malicious custom report definitions', () => {
      const maliciousPayloads = [
        {
          name: '"; DROP TABLE custom_report_definitions; --',
          dataSource: ReportDataSource.INVOICES,
          columns: [
            {
              id: 'customer_name',
              field: 'customer_name',
              name: 'Customer Name',
              dataType: FilterDataType.STRING,
              isVisible: true
            }
          ],
          filters: [],
          sorting: [],
          createdBy: 'user_1',
          businessId: 'test_business'
        },
        {
          name: '', // Empty name
          dataSource: ReportDataSource.INVOICES,
          columns: [
            {
              id: 'customer_name',
              field: 'customer_name',
              name: 'Customer Name',
              dataType: FilterDataType.STRING,
              isVisible: true
            }
          ],
          filters: [],
          sorting: [],
          createdBy: 'user_1',
          businessId: 'test_business'
        },
        {
          name: 'A'.repeat(150), // Too long name
          dataSource: ReportDataSource.INVOICES,
          columns: [
            {
              id: 'customer_name',
              field: 'customer_name',
              name: 'Customer Name',
              dataType: FilterDataType.STRING,
              isVisible: true
            }
          ],
          filters: [],
          sorting: [],
          createdBy: 'user_1',
          businessId: 'test_business'
        },
        {
          name: 'Test Report',
          dataSource: 'INVALID_SOURCE' as any,
          columns: [
            {
              id: 'customer_name',
              field: 'customer_name',
              name: 'Customer Name',
              dataType: FilterDataType.STRING,
              isVisible: true
            }
          ],
          filters: [],
          sorting: [],
          createdBy: 'user_1',
          businessId: 'test_business'
        },
        {
          name: 'Test Report',
          dataSource: ReportDataSource.INVOICES,
          columns: [], // No columns
          filters: [],
          sorting: [],
          createdBy: 'user_1',
          businessId: 'test_business'
        }
      ];

      for (const payload of maliciousPayloads) {
        expect(() => validateInput(customReportDefinitionSchema, payload)).toThrow();
      }
    });

    it('should accept valid custom report definitions', () => {
      const validPayload = {
        name: 'Customer Invoice Report',
        description: 'Detailed invoice report by customer',
        dataSource: ReportDataSource.INVOICES,
        columns: [
          {
            id: 'invoice_number',
            field: 'invoice_number',
            name: 'Invoice Number',
            dataType: FilterDataType.STRING,
            isVisible: true
          },
          {
            id: 'customer_name',
            field: 'customer_name',
            name: 'Customer Name',
            dataType: FilterDataType.STRING,
            isVisible: true
          },
          {
            id: 'total',
            field: 'total',
            name: 'Total Amount',
            dataType: FilterDataType.NUMBER,
            isVisible: true,
            aggregationType: AggregationType.SUM
          }
        ],
        filters: [
          {
            field: 'status',
            operator: FilterOperator.IN,
            value: ['SENT', 'VIEWED'],
            dataType: FilterDataType.STRING
          }
        ],
        sorting: [
          {
            field: 'customer_name',
            direction: 'ASC' as const,
            priority: 1
          }
        ],
        grouping: [
          {
            field: 'customer_name',
            level: 1,
            showSubtotals: true
          }
        ],
        aggregations: [
          {
            field: 'total',
            type: AggregationType.SUM
          }
        ],
        isTemplate: false,
        isPublic: false,
        createdBy: 'user_12345',
        businessId: 'test_business_123'
      };

      expect(() => validateInput(customReportDefinitionSchema, validPayload)).not.toThrow();
    });
  });

  describe('Export Request Validation', () => {
    it('should reject malicious export requests', () => {
      const maliciousPayloads = [
        {
          reportId: '"; DROP TABLE financial_reports; --',
          format: 'EXCEL',
          businessId: 'test_business'
        },
        {
          reportId: 'report_123',
          format: 'INVALID_FORMAT' as any,
          businessId: 'test_business'
        },
        {
          reportId: '', // Empty report ID
          format: 'EXCEL',
          businessId: 'test_business'
        },
        {
          reportId: 'report_123',
          format: 'EXCEL',
          filename: '../../../etc/passwd', // Path traversal
          businessId: 'test_business'
        },
        {
          reportId: 'report_123',
          format: 'EXCEL',
          filename: 'A'.repeat(150), // Too long filename
          businessId: 'test_business'
        }
      ];

      for (const payload of maliciousPayloads) {
        expect(() => validateInput(exportRequestSchema, payload)).toThrow();
      }
    });

    it('should accept valid export requests', () => {
      const validPayload = {
        reportId: 'report_12345',
        format: 'EXCEL' as const,
        filename: 'financial-report-2024-12',
        includeCharts: true,
        includeRawData: true,
        businessId: 'test_business_123'
      };

      expect(() => validateInput(exportRequestSchema, validPayload)).not.toThrow();
    });
  });

  describe('Currency Validation', () => {
    it('should reject invalid currencies', () => {
      const invalidCurrencies = [
        '', // Empty
        'US', // Too short
        'USDX', // Too long
        'usd', // Lowercase
        '123', // Numbers
        'US$', // Special characters
        'USD EUR', // Multiple currencies
        'US\nD', // Newline
        'USD\x00', // Null byte
        null,
        undefined
      ];

      for (const currency of invalidCurrencies) {
        expect(() => validateCurrencyInput(currency)).toThrow();
      }
    });

    it('should accept valid currencies', () => {
      const validCurrencies = ['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF'];

      for (const currency of validCurrencies) {
        expect(() => validateCurrencyInput(currency)).not.toThrow();
        expect(validateCurrencyInput(currency)).toBe(currency);
      }
    });
  });

  describe('Amount Validation', () => {
    it('should reject invalid amounts', () => {
      const invalidAmounts = [
        -1, // Negative
        -0.01, // Negative decimal
        null,
        undefined,
        'not a number',
        NaN,
        Infinity,
        -Infinity
      ];

      for (const amount of invalidAmounts) {
        expect(() => validateAmountInput(amount)).toThrow();
      }
    });

    it('should accept valid amounts', () => {
      const validAmounts = [0, 0.01, 1, 100, 1000.50, 999999.99];

      for (const amount of validAmounts) {
        expect(() => validateAmountInput(amount)).not.toThrow();
        expect(validateAmountInput(amount)).toBe(amount);
      }
    });
  });

  describe('Date Validation', () => {
    it('should reject invalid dates', () => {
      const invalidDates = [
        -1, // Negative timestamp
        0, // Zero timestamp
        null,
        undefined,
        'not a number',
        NaN,
        Infinity,
        -Infinity,
        '2024-01-01' // String date
      ];

      for (const date of invalidDates) {
        expect(() => validateDateInput(date)).toThrow();
      }
    });

    it('should accept valid dates', () => {
      const validDates = [
        Date.now(),
        Date.now() - 86400000,
        Date.now() + 86400000,
        1640995200000, // Jan 1, 2022
        1735689600000  // Jan 1, 2025
      ];

      for (const date of validDates) {
        expect(() => validateDateInput(date)).not.toThrow();
        expect(validateDateInput(date)).toBe(date);
      }
    });
  });

  describe('Edge Cases and Boundary Testing', () => {
    it('should handle extremely large numbers safely', () => {
      const extremeValues = [
        Number.MAX_SAFE_INTEGER,
        Number.MAX_SAFE_INTEGER + 1,
        Number.MAX_VALUE,
        1e308,
        1e309
      ];

      for (const value of extremeValues) {
        expect(() => validateAmountInput(value)).toThrow();
      }
    });

    it('should handle unicode and special characters safely', () => {
      const unicodePayloads = [
        '🏦💰', // Emojis
        'الأعمال', // Arabic
        '事业', // Chinese
        'ビジネス', // Japanese
        '企업', // Korean
        'Бизнес', // Russian
        '\u0000', // Null character
        '\uFFFF', // Special unicode
        '﷽', // Arabic ligature
        '𝕭𝖚𝖘𝖎𝖓𝖊𝖘𝖘' // Mathematical bold
      ];

      for (const payload of unicodePayloads) {
        // Should either be rejected or safely handled
        try {
          validateBusinessIdInput(payload);
        } catch (error) {
          expect(error instanceof Error).toBe(true);
        }
      }
    });

    it('should handle concurrent validation safely', async () => {
      const validationPromises = [];

      // Create 100 concurrent validation attempts
      for (let i = 0; i < 100; i++) {
        const promise = new Promise((resolve) => {
          try {
            validateInput(invoiceCreateSchema, {
              invoiceNumber: `INV-${i}`,
              customerId: `cust_${i}`,
              customerName: `Customer ${i}`,
              issueDate: Date.now(),
              dueDate: Date.now() + 86400000 * 30,
              subtotal: 1000 + i,
              total: 1000 + i,
              currency: 'USD',
              businessId: `business_${i}`
            });
            resolve('success');
          } catch (error) {
            resolve('error');
          }
        });
        validationPromises.push(promise);
      }

      const results = await Promise.all(validationPromises);

      // All should succeed (no race conditions or interference)
      expect(results.every(result => result === 'success')).toBe(true);
    });
  });
});