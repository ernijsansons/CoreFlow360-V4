/**
 * Finance Type Definitions
 * Comprehensive types for financial operations
 */

// Invoice Types
export interface InvoiceLineItem {
  id: string
  description: string
  quantity: number
  unitPrice: number
  amount: number
  taxRate?: number
}

export interface Invoice {
  id: string
  number: string
  customerId: string
  customerName: string
  date: string
  dueDate: string
  status: 'draft' | 'sent' | 'paid' | 'overdue' | 'voided'
  items: InvoiceLineItem[]
  subtotal: number
  taxAmount: number
  total: number
  paidAmount: number
  currency: string
  notes?: string
  createdAt: string
  updatedAt: string
}

export interface InvoiceFormData {
  customerId: string
  date: string
  dueDate: string
  items: Omit<InvoiceLineItem, 'id' | 'amount'>[]
  currency: string
  notes?: string
}

export interface InvoiceUpdateData extends Partial<InvoiceFormData> {
  status?: Invoice['status']
}

// Payment Types
export interface Payment {
  id: string
  invoiceId?: string
  customerId: string
  amount: number
  currency: string
  method: 'cash' | 'check' | 'credit_card' | 'bank_transfer' | 'other'
  reference?: string
  date: string
  status: 'pending' | 'completed' | 'failed' | 'refunded'
  notes?: string
  createdAt: string
  updatedAt: string
}

export interface PaymentFormData {
  invoiceId?: string
  customerId: string
  amount: number
  currency: string
  method: Payment['method']
  reference?: string
  date: string
  notes?: string
}

export interface RefundData {
  amount: number
  reason: string
}

// Account Types
export interface Account {
  id: string
  code: string
  name: string
  type: 'asset' | 'liability' | 'equity' | 'revenue' | 'expense'
  subtype?: string
  balance: number
  currency: string
  active: boolean
  description?: string
  createdAt: string
  updatedAt: string
}

export interface AccountFormData {
  code: string
  name: string
  type: Account['type']
  subtype?: string
  currency: string
  description?: string
}

// Journal Entry Types
export interface JournalEntryLine {
  id: string
  accountId: string
  accountName: string
  debit: number
  credit: number
  description?: string
}

export interface JournalEntry {
  id: string
  date: string
  reference: string
  description: string
  lines: JournalEntryLine[]
  totalDebit: number
  totalCredit: number
  status: 'draft' | 'posted' | 'voided'
  createdAt: string
  updatedAt: string
}

export interface JournalEntryFormData {
  date: string
  reference: string
  description: string
  lines: Omit<JournalEntryLine, 'id' | 'accountName'>[]
}

// Financial Report Types
export interface BalanceSheetData {
  assets: {
    current: Account[]
    fixed: Account[]
    other: Account[]
    total: number
  }
  liabilities: {
    current: Account[]
    longTerm: Account[]
    other: Account[]
    total: number
  }
  equity: {
    capital: Account[]
    retained: Account[]
    other: Account[]
    total: number
  }
}

export interface IncomeStatementData {
  revenue: {
    items: Account[]
    total: number
  }
  expenses: {
    items: Account[]
    total: number
  }
  netIncome: number
  period: {
    start: string
    end: string
  }
}

export interface CashFlowData {
  operating: {
    items: Account[]
    total: number
  }
  investing: {
    items: Account[]
    total: number
  }
  financing: {
    items: Account[]
    total: number
  }
  netCashFlow: number
  period: {
    start: string
    end: string
  }
}

export interface TrialBalanceData {
  accounts: Array<{
    code: string
    name: string
    debit: number
    credit: number
  }>
  totalDebit: number
  totalCredit: number
  balanced: boolean
}

export type FinancialReportType = 'balance-sheet' | 'income-statement' | 'cash-flow' | 'trial-balance'

export interface FinancialReportParams {
  startDate?: string
  endDate?: string
  comparePeriod?: boolean
}

// Transaction Types
export interface Transaction {
  id: string
  accountId: string
  date: string
  description: string
  type: 'debit' | 'credit'
  amount: number
  balance: number
  reference?: string
  createdAt: string
}

// Budget Types
export interface Budget {
  id: string
  name: string
  period: string
  departmentId?: string
  accountId: string
  amount: number
  spent: number
  remaining: number
  status: 'active' | 'exceeded' | 'completed'
  createdAt: string
  updatedAt: string
}

export interface BudgetFormData {
  name: string
  period: string
  departmentId?: string
  accountId: string
  amount: number
}

// Subscription Types
export interface Subscription {
  id: string
  customerId: string
  planId: string
  status: 'active' | 'canceled' | 'past_due' | 'trialing'
  amount: number
  currency: string
  interval: 'monthly' | 'yearly'
  currentPeriodStart: string
  currentPeriodEnd: string
  canceledAt?: string
  createdAt: string
  updatedAt: string
}

export interface SubscriptionFormData {
  customerId: string
  planId: string
  amount: number
  currency: string
  interval: Subscription['interval']
}

// Financial Metrics Types
export interface FinancialMetrics {
  revenue: {
    total: number
    recurring: number
    growth: number
  }
  expenses: {
    total: number
    breakdown: Record<string, number>
  }
  profit: {
    gross: number
    net: number
    margin: number
  }
  cashFlow: {
    operating: number
    investing: number
    financing: number
  }
  accounts: {
    receivable: number
    payable: number
  }
}

// Payment Intent Types (Stripe)
export interface PaymentIntentData {
  amount: number
  currency: string
  metadata?: Record<string, unknown>
}

export interface PaymentIntent {
  id: string
  amount: number
  currency: string
  status: string
  clientSecret: string
}

// Export Types
export interface ExportParams {
  format: 'csv' | 'excel' | 'pdf'
  filters?: Record<string, unknown>
}
