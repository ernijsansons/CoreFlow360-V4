/**
 * SMB Accounting Correctness & Financial Validation Test Suite
 *
 * This test suite acts as an automated internal audit to ensure the integrity
 * of the core accounting logic. It validates fundamental accounting principles
 * required for SMB financial reporting.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock services and data types
// In a real test, these would be imported from the actual implementation.

// --- Mock Data & Types ---
enum AccountType {
  ASSET = 'ASSET',
  LIABILITY = 'LIABILITY',
  EQUITY = 'EQUITY',
  REVENUE = 'REVENUE',
  EXPENSE = 'EXPENSE',
}

interface Account {
  id: string;
  name: string;
  type: AccountType;
  balance: number;
}

interface JournalEntry {
  id: string;
  date: Date;
  description: string;
  lines: { accountId: string; debit?: number; credit?: number }[];
}

// --- Mock Services ---
const mockChartOfAccounts = {
  'acc_cash': { id: 'acc_cash', name: 'Cash', type: AccountType.ASSET, balance: 0 },
  'acc_ar': { id: 'acc_ar', name: 'Accounts Receivable', type: AccountType.ASSET, balance: 0 },
  'acc_sales': { id: 'acc_sales', name: 'Sales Revenue', type: AccountType.REVENUE, balance: 0 },
  'acc_expense': { id: 'acc_expense', name: 'Office Expense', type: AccountType.EXPENSE, balance: 0 },
};

// A mock service to manage journal entries and update account balances
const JournalService = {
  postEntry: vi.fn(async (entry: Omit<JournalEntry, 'id'>): Promise<JournalEntry> => {
    const debits = entry.lines.reduce((sum, line) => sum + (line.debit || 0), 0);
    const credits = entry.lines.reduce((sum, line) => sum + (line.credit || 0), 0);

    // Core double-entry validation
    if (Math.abs(debits - credits) > 0.001) {
      throw new Error('Unbalanced journal entry: Debits do not equal credits.');
    }

    // Simulate posting to the ledger
    entry.lines.forEach(line => {
      const account = mockChartOfAccounts[line.accountId];
      if (account) {
        if (line.debit) {
          // Debits increase Assets and Expenses
          if (account.type === AccountType.ASSET || account.type === AccountType.EXPENSE) {
            account.balance += line.debit;
          } else {
            account.balance -= line.debit;
          }
        }
        if (line.credit) {
          // Credits increase Liabilities, Equity, and Revenue
          if ([AccountType.LIABILITY, AccountType.EQUITY, AccountType.REVENUE].includes(account.type)) {
            account.balance += line.credit;
          } else {
            account.balance -= line.credit;
          }
        }
      }
    });

    return { id: `je_${Math.random()}`, ...entry };
  }),
};

// A mock service for high-level business transactions like creating an invoice
const InvoiceService = {
  createAndPostSale: vi.fn(async (amount: number) => {
    const entry = {
      date: new Date(),
      description: 'Sale of goods',
      lines: [
        { accountId: 'acc_ar', debit: amount },      // Debit Accounts Receivable
        { accountId: 'acc_sales', credit: amount },   // Credit Sales Revenue
      ],
    };
    return JournalService.postEntry(entry);
  }),
  receivePayment: vi.fn(async (amount: number) => {
    const entry = {
      date: new Date(),
      description: 'Payment received for sale',
      lines: [
        { accountId: 'acc_cash', debit: amount },     // Debit Cash
        { accountId: 'acc_ar', credit: amount },    // Credit Accounts Receivable
      ],
    };
    return JournalService.postEntry(entry);
  }),
};

// A mock reporting service to generate a trial balance
const ReportingService = {
  getTrialBalance: vi.fn(async () => {
    let totalDebits = 0;
    let totalCredits = 0;

    Object.values(mockChartOfAccounts).forEach(account => {
      if (account.balance > 0) {
        if (account.type === AccountType.ASSET || account.type === AccountType.EXPENSE) {
          totalDebits += account.balance;
        } else {
          totalCredits += account.balance;
        }
      } else if (account.balance < 0) {
        if ([AccountType.LIABILITY, AccountType.EQUITY, AccountType.REVENUE].includes(account.type)) {
          totalDebits += -account.balance;
        } else {
          totalCredits += -account.balance;
        }
      }
    });
    return { totalDebits, totalCredits };
  }),
};


describe('SMB Accounting Correctness & Financial Validation', () => {

  // Reset mock data before each test
  beforeEach(() => {
    vi.clearAllMocks();
    for (const accId in mockChartOfAccounts) {
      mockChartOfAccounts[accId].balance = 0;
    }
  });

  // --- Test Suite 1: Double-Entry Principle ---
  describe('Double-Entry Principle Validation', () => {
    it('should successfully post a balanced journal entry', async () => {
      const entry = {
        date: new Date(),
        description: 'Purchase office supplies',
        lines: [
          { accountId: 'acc_expense', debit: 150 },
          { accountId: 'acc_cash', credit: 150 },
        ],
      };
      await expect(JournalService.postEntry(entry)).resolves.toBeDefined();
    });

    it('should REJECT an unbalanced journal entry where debits > credits', async () => {
      const unbalancedEntry = {
        date: new Date(),
        description: 'Unbalanced entry',
        lines: [
          { accountId: 'acc_expense', debit: 200 },
          { accountId: 'acc_cash', credit: 150 },
        ],
      };
      await expect(JournalService.postEntry(unbalancedEntry)).rejects.toThrow(
        'Unbalanced journal entry: Debits do not equal credits.'
      );
    });

    it('should REJECT an unbalanced journal entry where credits > debits', async () => {
      const unbalancedEntry = {
        date: new Date(),
        description: 'Unbalanced entry',
        lines: [
          { accountId: 'acc_expense', debit: 100 },
          { accountId: 'acc_cash', credit: 150 },
        ],
      };
      await expect(JournalService.postEntry(unbalancedEntry)).rejects.toThrow(
        'Unbalanced journal entry: Debits do not equal credits.'
      );
    });
  });

  // --- Test Suite 2: Invoice-to-Cash Lifecycle ---
  describe('Invoice-to-Cash Lifecycle Validation', () => {
    it('should correctly update ledger accounts through a full sales cycle', async () => {
      const saleAmount = 5000;

      // Step 1: Initial state check
      expect(mockChartOfAccounts.acc_ar.balance).toBe(0);
      expect(mockChartOfAccounts.acc_sales.balance).toBe(0);
      expect(mockChartOfAccounts.acc_cash.balance).toBe(0);

      // Step 2: Create a new sale invoice
      await InvoiceService.createAndPostSale(saleAmount);

      // Verification 2: A/R should be debited, Sales should be credited
      // A/R is an asset, so its balance increases. Sales is revenue, so its balance increases.
      expect(mockChartOfAccounts.acc_ar.balance).toBe(saleAmount);
      expect(mockChartOfAccounts.acc_sales.balance).toBe(saleAmount);
      expect(mockChartOfAccounts.acc_cash.balance).toBe(0); // Cash not yet received

      // Step 3: Receive payment for the invoice
      await InvoiceService.receivePayment(saleAmount);

      // Verification 3: Cash should be debited, A/R should be credited
      // Cash balance increases. A/R balance decreases back to 0.
      expect(mockChartOfAccounts.acc_cash.balance).toBe(saleAmount);
      expect(mockChartOfAccounts.acc_ar.balance).toBe(0); // A/R is now settled
      expect(mockChartOfAccounts.acc_sales.balance).toBe(saleAmount); // Sales balance remains
    });
  });

  // --- Test Suite 3: Trial Balance Integrity ---
  describe('Trial Balance Integrity Validation', () => {
    it('should produce a balanced trial balance after multiple transactions', async () => {
      // Transaction 1: A sale
      await InvoiceService.createAndPostSale(1000);
      // Transaction 2: Another sale
      await InvoiceService.createAndPostSale(500);
      // Transaction 3: Receive payment for the first sale
      await InvoiceService.receivePayment(1000);
      // Transaction 4: Record an expense
      await JournalService.postEntry({
        date: new Date(),
        description: 'Internet bill',
        lines: [
          { accountId: 'acc_expense', debit: 100 },
          { accountId: 'acc_cash', credit: 100 },
        ],
      });

      // Final Balances Check:
      // Cash: 1000 (payment) - 100 (expense) = 900
      // A/R: 1000 (sale1) + 500 (sale2) - 1000 (payment) = 500
      // Sales: 1000 (sale1) + 500 (sale2) = 1500
      // Expense: 100
      expect(mockChartOfAccounts.acc_cash.balance).toBe(900);
      expect(mockChartOfAccounts.acc_ar.balance).toBe(500);
      expect(mockChartOfAccounts.acc_sales.balance).toBe(1500);
      expect(mockChartOfAccounts.acc_expense.balance).toBe(100);

      // Step 4: Generate the Trial Balance
      const trialBalance = await ReportingService.getTrialBalance();

      // Verification: Total debits must equal total credits
      expect(trialBalance.totalDebits).toBeGreaterThan(0);
      expect(trialBalance.totalCredits).toBeGreaterThan(0);
      expect(trialBalance.totalDebits).toBe(trialBalance.totalCredits);

      // Explicitly check the balance calculation
      // Debit balances: Cash (Asset) 900 + A/R (Asset) 500 + Office Expense (Expense) 100 = 1500
      // Credit balances: Sales (Revenue) 1500
      expect(trialBalance.totalDebits).toBe(1500);
      expect(trialBalance.totalCredits).toBe(1500);
    });
  });
});
