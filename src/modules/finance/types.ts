/**
 * Finance Module Type Definitions
 * Core types for double-entry bookkeeping system
 */

export enum AccountType {
  ASSET = 'ASSET',
  LIABILITY = 'LIABILITY',
  EQUITY = 'EQUITY',
  REVENUE = 'REVENUE',
  EXPENSE = 'EXPENSE',
  CONTRA_ASSET = 'CONTRA_ASSET',
  CONTRA_LIABILITY = 'CONTRA_LIABILITY',
  CONTRA_EQUITY = 'CONTRA_EQUITY',
  CONTRA_REVENUE = 'CONTRA_REVENUE',
  CONTRA_EXPENSE = 'CONTRA_EXPENSE'
}

export enum AccountCategory {
  // Assets
  CURRENT_ASSET = 'CURRENT_ASSET',
  FIXED_ASSET = 'FIXED_ASSET',
  INTANGIBLE_ASSET = 'INTANGIBLE_ASSET',
  INVESTMENT = 'INVESTMENT',

  // Liabilities
  CURRENT_LIABILITY = 'CURRENT_LIABILITY',
  LONG_TERM_LIABILITY = 'LONG_TERM_LIABILITY',

  // Equity
  OWNERS_EQUITY = 'OWNERS_EQUITY',
  RETAINED_EARNINGS = 'RETAINED_EARNINGS',

  // Revenue
  OPERATING_REVENUE = 'OPERATING_REVENUE',
  NON_OPERATING_REVENUE = 'NON_OPERATING_REVENUE',

  // Expenses
  COST_OF_GOODS_SOLD = 'COST_OF_GOODS_SOLD',
  OPERATING_EXPENSE = 'OPERATING_EXPENSE',
  NON_OPERATING_EXPENSE = 'NON_OPERATING_EXPENSE',
  TAX_EXPENSE = 'TAX_EXPENSE'
}

export interface ChartAccount {
  id: string;
  code: string; // e.g., "1000", "1010"
  name: string;
  type: AccountType;
  category: AccountCategory;
  parentId?: string;
  description?: string;
  currency: string; // Default currency
  normalBalance: 'debit' | 'credit';
  isActive: boolean;
  isSystemAccount: boolean; // Protected from deletion
  isReconcilable: boolean;
  isCashAccount: boolean;
  metadata?: Record<string, any>;
  createdAt: number;
  updatedAt: number;
  businessId: string;
}

export interface JournalEntry {
  id: string;
  entryNumber: string; // Sequential number
  date: number;
  description: string;
  reference?: string; // External reference
  type: JournalEntryType;
  status: JournalEntryStatus;
  lines: JournalLine[];
  attachments?: string[];
  reversalOf?: string; // ID of reversed entry
  reversedBy?: string; // ID of reversing entry
  periodId: string;
  postedAt?: number;
  postedBy?: string;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy?: string;
  businessId: string;
  metadata?: Record<string, any>;
}

export interface JournalLine {
  id: string;
  journalEntryId: string;
  accountId: string;
  accountCode: string;
  accountName: string;
  debit: number;
  credit: number;
  currency: string;
  exchangeRate: number;
  baseDebit: number; // In base currency
  baseCredit: number; // In base currency
  description?: string;
  departmentId?: string;
  projectId?: string;
  customerId?: string;
  vendorId?: string;
  employeeId?: string;
  metadata?: Record<string, any>;
}

export enum JournalEntryType {
  STANDARD = 'STANDARD',
  ADJUSTING = 'ADJUSTING',
  CLOSING = 'CLOSING',
  REVERSING = 'REVERSING',
  OPENING = 'OPENING',
  SYSTEM = 'SYSTEM' // Auto-generated
}

export enum JournalEntryStatus {
  DRAFT = 'DRAFT',
  PENDING_APPROVAL = 'PENDING_APPROVAL',
  APPROVED = 'APPROVED',
  POSTED = 'POSTED',
  REVERSED = 'REVERSED',
  VOIDED = 'VOIDED'
}

export interface AccountingPeriod {
  id: string;
  name: string; // e.g., "January 2024"
  startDate: number;
  endDate: number;
  fiscalYear: number;
  fiscalPeriod: number; // 1-12 for monthly, 1-4 for quarterly
  status: PeriodStatus;
  closedAt?: number;
  closedBy?: string;
  lockedAt?: number;
  lockedBy?: string;
  businessId: string;
}

export enum PeriodStatus {
  FUTURE = 'FUTURE',
  OPEN = 'OPEN',
  CLOSING = 'CLOSING',
  CLOSED = 'CLOSED',
  LOCKED = 'LOCKED'
}

export interface GeneralLedger {
  id: string;
  accountId: string;
  periodId: string;
  openingBalance: number;
  debits: number;
  credits: number;
  closingBalance: number;
  currency: string;
  transactionCount: number;
  lastTransactionDate?: number;
  businessId: string;
}

export interface TrialBalance {
  periodId: string;
  date: number;
  accounts: TrialBalanceAccount[];
  totalDebits: number;
  totalCredits: number;
  isBalanced: boolean;
  currency: string;
  businessId: string;
}

export interface TrialBalanceAccount {
  accountId: string;
  accountCode: string;
  accountName: string;
  accountType: AccountType;
  openingDebit: number;
  openingCredit: number;
  periodDebit: number;
  periodCredit: number;
  closingDebit: number;
  closingCredit: number;
}

export interface Currency {
  code: string; // ISO 4217
  name: string;
  symbol: string;
  decimalPlaces: number;
  isBaseCurrency: boolean;
}

export interface ExchangeRate {
  id: string;
  fromCurrency: string;
  toCurrency: string;
  rate: number;
  effectiveDate: number;
  expiryDate?: number;
  source: string;
  isAutomatic: boolean;
  businessId: string;
}

export interface LedgerTransaction {
  id: string;
  journalEntryId: string;
  accountId: string;
  date: number;
  debit: number;
  credit: number;
  balance: number; // Running balance
  currency: string;
  exchangeRate: number;
  baseDebit: number;
  baseCredit: number;
  baseBalance: number;
  description: string;
  reference?: string;
  reconciled: boolean;
  reconciledDate?: number;
  businessId: string;
}

export interface FinancialStatement {
  type: StatementType;
  periodId: string;
  startDate: number;
  endDate: number;
  currency: string;
  data: any; // Specific to statement type
  generatedAt: number;
  businessId: string;
}

export enum StatementType {
  BALANCE_SHEET = 'BALANCE_SHEET',
  INCOME_STATEMENT = 'INCOME_STATEMENT',
  CASH_FLOW = 'CASH_FLOW',
  EQUITY_STATEMENT = 'EQUITY_STATEMENT'
}

export interface AccountBalance {
  accountId: string;
  periodId: string;
  debit: number;
  credit: number;
  balance: number;
  currency: string;
  asOfDate: number;
}

export interface ClosingEntry {
  id: string;
  periodId: string;
  type: 'revenue' | 'expense' | 'dividend' | 'summary';
  sourceAccounts: string[];
  targetAccount: string;
  amount: number;
  journalEntryId: string;
  createdAt: number;
  businessId: string;
}

export interface AuditTrail {
  id: string;
  entityType: 'account' | 'journal' | 'period' | 'ledger';
  entityId: string;
  action: AuditAction;
  changes?: Record<string, any>;
  performedBy: string;
  performedAt: number;
  ipAddress?: string;
  userAgent?: string;
  businessId: string;
}

export enum AuditAction {
  CREATE = 'CREATE',
  UPDATE = 'UPDATE',
  DELETE = 'DELETE',
  POST = 'POST',
  REVERSE = 'REVERSE',
  VOID = 'VOID',
  APPROVE = 'APPROVE',
  REJECT = 'REJECT',
  CLOSE_PERIOD = 'CLOSE_PERIOD',
  LOCK_PERIOD = 'LOCK_PERIOD',
  UNLOCK_PERIOD = 'UNLOCK_PERIOD'
}

export interface ReconciliationItem {
  id: string;
  accountId: string;
  transactionId: string;
  statementDate: number;
  statementAmount: number;
  bookAmount: number;
  difference: number;
  status: 'matched' | 'unmatched' | 'partial';
  reconciledBy?: string;
  reconciledAt?: number;
  notes?: string;
  businessId: string;
}

export interface ValidationRule {
  id: string;
  name: string;
  type: 'account' | 'journal' | 'period';
  condition: string; // Expression to evaluate
  errorMessage: string;
  severity: 'error' | 'warning';
  isActive: boolean;
}

export interface FinanceConfig {
  businessId: string;
  baseCurrency: string;
  fiscalYearStart: number; // Month (1-12)
  periodType: 'monthly' | 'quarterly' | 'yearly';
  allowNegativeInventory: boolean;
  requireApproval: boolean;
  approvalThreshold: number;
  retainedEarningsAccountId?: string;
  incomeSummaryAccountId?: string;
  roundingAccountId?: string;
  currencyGainLossAccountId?: string;
  openingBalanceAccountId?: string;
}

export interface BudgetLine {
  id: string;
  accountId: string;
  periodId: string;
  budgetAmount: number;
  actualAmount: number;
  variance: number;
  variancePercentage: number;
  notes?: string;
  businessId: string;
}

// Request/Response types for API
export interface CreateJournalEntryRequest {
  date: number;
  description: string;
  reference?: string;
  type?: JournalEntryType;
  lines: Array<{
    accountId: string;
    debit?: number;
    credit?: number;
    currency?: string;
    description?: string;
    departmentId?: string;
    projectId?: string;
  }>;
}

export interface PostJournalEntryRequest {
  journalEntryId: string;
  postDate?: number;
}

export interface ClosePeriodRequest {
  periodId: string;
  adjustingEntries?: CreateJournalEntryRequest[];
}

export interface GenerateTrialBalanceRequest {
  periodId: string;
  asOfDate?: number;
  includeZeroBalances?: boolean;
  groupByType?: boolean;
}

export interface AccountBalanceRequest {
  accountIds?: string[];
  periodId: string;
  asOfDate?: number;
  includeSummary?: boolean;
}

// Invoice System Types
export interface Invoice {
  id: string;
  invoiceNumber: string;
  customerId: string;
  customerName: string;
  customerEmail?: string;
  customerAddress?: InvoiceAddress;
  billToAddress?: InvoiceAddress;
  shipToAddress?: InvoiceAddress;
  issueDate: number;
  dueDate: number;
  currency: string;
  exchangeRate: number;
  subtotal: number;
  taxTotal: number;
  discountTotal: number;
  total: number;
  balanceDue: number;
  status: InvoiceStatus;
  terms: PaymentTerms;
  lines: InvoiceLine[];
  taxLines?: TaxLine[];
  discounts?: InvoiceDiscount[];
  notes?: string;
  internalNotes?: string;
  referenceNumber?: string;
  poNumber?: string;
  journalEntryId?: string;
  approvalRequired: boolean;
  approvalStatus?: ApprovalStatus;
  approvals?: InvoiceApproval[];
  pdfUrl?: string;
  sentAt?: number;
  sentBy?: string;
  lastReminderSent?: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy?: string;
  businessId: string;
  metadata?: Record<string, any>;
}

export interface InvoiceLine {
  id: string;
  invoiceId: string;
  productId?: string;
  description: string;
  quantity: number;
  unitPrice: number;
  discount?: number;
  discountType?: 'percentage' | 'fixed';
  lineTotal: number;
  taxableAmount: number;
  taxAmount: number;
  taxRateId?: string;
  accountId?: string;
  departmentId?: string;
  projectId?: string;
  metadata?: Record<string, any>;
}

export interface TaxLine {
  id: string;
  invoiceId: string;
  taxRateId: string;
  taxName: string;
  taxRate: number;
  taxableAmount: number;
  taxAmount: number;
  accountId: string;
}

export interface InvoiceDiscount {
  id: string;
  invoiceId: string;
  description: string;
  type: 'percentage' | 'fixed';
  value: number;
  amount: number;
}

export interface InvoiceAddress {
  name?: string;
  line1: string;
  line2?: string;
  city: string;
  state?: string;
  postalCode: string;
  country: string;
}

export enum InvoiceStatus {
  DRAFT = 'DRAFT',
  PENDING_APPROVAL = 'PENDING_APPROVAL',
  SENT = 'SENT',
  VIEWED = 'VIEWED',
  PARTIALLY_PAID = 'PARTIALLY_PAID',
  PAID = 'PAID',
  OVERDUE = 'OVERDUE',
  CANCELLED = 'CANCELLED',
  VOIDED = 'VOIDED'
}

export enum ApprovalStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED'
}

export interface InvoiceApproval {
  id: string;
  invoiceId: string;
  approverUserId: string;
  approverName: string;
  status: ApprovalStatus;
  comments?: string;
  approvedAt?: number;
  rejectedAt?: number;
  level: number;
}

export interface PaymentTerms {
  type: PaymentTermType;
  netDays?: number;
  discountDays?: number;
  discountPercentage?: number;
  description: string;
}

export enum PaymentTermType {
  NET = 'NET',
  DUE_ON_RECEIPT = 'DUE_ON_RECEIPT',
  END_OF_MONTH = 'END_OF_MONTH',
  CASH_ON_DELIVERY = 'CASH_ON_DELIVERY',
  CUSTOM = 'CUSTOM'
}

export interface TaxRate {
  id: string;
  name: string;
  rate: number;
  type: TaxType;
  jurisdiction: string;
  accountId: string;
  isActive: boolean;
  effectiveDate: number;
  expiryDate?: number;
  businessId: string;
}

export enum TaxType {
  SALES_TAX = 'SALES_TAX',
  VAT = 'VAT',
  GST = 'GST',
  EXCISE_TAX = 'EXCISE_TAX',
  CUSTOM = 'CUSTOM'
}

export interface Customer {
  id: string;
  name: string;
  email?: string;
  phone?: string;
  website?: string;
  taxId?: string;
  currency: string;
  paymentTerms: PaymentTerms;
  creditLimit?: number;
  billingAddress?: InvoiceAddress;
  shippingAddress?: InvoiceAddress;
  contacts?: CustomerContact[];
  isActive: boolean;
  createdAt: number;
  updatedAt: number;
  businessId: string;
  metadata?: Record<string, any>;
}

export interface CustomerContact {
  id: string;
  name: string;
  email?: string;
  phone?: string;
  title?: string;
  isPrimary: boolean;
}

export interface InvoicePayment {
  id: string;
  invoiceId: string;
  paymentDate: number;
  amount: number;
  currency: string;
  exchangeRate: number;
  baseAmount: number;
  paymentMethod: PaymentMethod;
  reference?: string;
  notes?: string;
  journalEntryId?: string;
  createdAt: number;
  createdBy: string;
  businessId: string;
}

export enum PaymentMethod {
  CASH = 'CASH',
  CHECK = 'CHECK',
  CREDIT_CARD = 'CREDIT_CARD',
  BANK_TRANSFER = 'BANK_TRANSFER',
  ACH = 'ACH',
  WIRE_TRANSFER = 'WIRE_TRANSFER',
  PAYPAL = 'PAYPAL',
  OTHER = 'OTHER'
}

export interface AgingReport {
  customerId: string;
  customerName: string;
  current: number;
  days1to30: number;
  days31to60: number;
  days61to90: number;
  over90Days: number;
  total: number;
  currency: string;
}

export interface InvoiceTemplate {
  id: string;
  name: string;
  isDefault: boolean;
  logoUrl?: string;
  colors?: {
    primary: string;
    secondary: string;
    accent: string;
  };
  layout: 'standard' | 'modern' | 'minimal';
  showTaxColumn: boolean;
  showDiscountColumn: boolean;
  footerText?: string;
  businessId: string;
}

// Request/Response types for Invoice API
export interface CreateInvoiceRequest {
  customerId: string;
  issueDate: number;
  dueDate?: number;
  currency?: string;
  lines: Array<{
    description: string;
    quantity: number;
    unitPrice: number;
    discount?: number;
    discountType?: 'percentage' | 'fixed';
    taxRateId?: string;
    accountId?: string;
    departmentId?: string;
    projectId?: string;
  }>;
  discounts?: Array<{
    description: string;
    type: 'percentage' | 'fixed';
    value: number;
  }>;
  notes?: string;
  internalNotes?: string;
  referenceNumber?: string;
  poNumber?: string;
  terms?: PaymentTerms;
  billToAddress?: InvoiceAddress;
  shipToAddress?: InvoiceAddress;
}

export interface UpdateInvoiceRequest {
  customerId?: string;
  issueDate?: number;
  dueDate?: number;
  lines?: Array<{
    id?: string;
    description: string;
    quantity: number;
    unitPrice: number;
    discount?: number;
    discountType?: 'percentage' | 'fixed';
    taxRateId?: string;
    accountId?: string;
  }>;
  notes?: string;
  internalNotes?: string;
  referenceNumber?: string;
  poNumber?: string;
  terms?: PaymentTerms;
}

export interface SendInvoiceRequest {
  invoiceId: string;
  email?: string;
  subject?: string;
  message?: string;
  copyToSender?: boolean;
}

export interface RecordPaymentRequest {
  invoiceId: string;
  amount: number;
  paymentDate: number;
  paymentMethod: PaymentMethod;
  reference?: string;
  notes?: string;
  accountId?: string;
}

export interface ApproveInvoiceRequest {
  invoiceId: string;
  comments?: string;
}

export interface RejectInvoiceRequest {
  invoiceId: string;
  comments: string;
}

// Financial Reporting Types
export interface FinancialReport {
  id: string;
  type: FinancialReportType;
  name: string;
  description?: string;
  parameters: ReportParameters;
  generatedAt: number;
  generatedBy: string;
  status: ReportStatus;
  data: any; // Report-specific data structure
  exportUrls?: {
    excel?: string;
    csv?: string;
    pdf?: string;
  };
  businessId: string;
}

export enum FinancialReportType {
  PROFIT_AND_LOSS = 'PROFIT_AND_LOSS',
  BALANCE_SHEET = 'BALANCE_SHEET',
  CASH_FLOW = 'CASH_FLOW',
  AGING_RECEIVABLES = 'AGING_RECEIVABLES',
  AGING_PAYABLES = 'AGING_PAYABLES',
  TRIAL_BALANCE = 'TRIAL_BALANCE',
  GENERAL_LEDGER = 'GENERAL_LEDGER',
  CUSTOM = 'CUSTOM'
}

export enum ReportStatus {
  GENERATING = 'GENERATING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED'
}

export interface ReportParameters {
  startDate: number;
  endDate: number;
  periodType?: PeriodType;
  currency?: string;
  accountIds?: string[];
  customerIds?: string[];
  vendorIds?: string[];
  departmentIds?: string[];
  projectIds?: string[];
  includeInactive?: boolean;
  includeZeroBalances?: boolean;
  consolidateSubaccounts?: boolean;
  comparisonPeriod?: {
    startDate: number;
    endDate: number;
  };
  customFilters?: ReportFilter[];
}

export enum PeriodType {
  MONTHLY = 'MONTHLY',
  QUARTERLY = 'QUARTERLY',
  YEARLY = 'YEARLY',
  CUSTOM = 'CUSTOM'
}

export interface ReportFilter {
  field: string;
  operator: FilterOperator;
  value: any;
  dataType: FilterDataType;
}

export enum FilterOperator {
  EQUALS = 'EQUALS',
  NOT_EQUALS = 'NOT_EQUALS',
  GREATER_THAN = 'GREATER_THAN',
  LESS_THAN = 'LESS_THAN',
  GREATER_THAN_OR_EQUAL = 'GREATER_THAN_OR_EQUAL',
  LESS_THAN_OR_EQUAL = 'LESS_THAN_OR_EQUAL',
  CONTAINS = 'CONTAINS',
  NOT_CONTAINS = 'NOT_CONTAINS',
  STARTS_WITH = 'STARTS_WITH',
  ENDS_WITH = 'ENDS_WITH',
  IN = 'IN',
  NOT_IN = 'NOT_IN',
  IS_NULL = 'IS_NULL',
  IS_NOT_NULL = 'IS_NOT_NULL'
}

export enum FilterDataType {
  STRING = 'STRING',
  NUMBER = 'NUMBER',
  DATE = 'DATE',
  BOOLEAN = 'BOOLEAN',
  ARRAY = 'ARRAY'
}

// Profit & Loss Statement
export interface ProfitLossStatement {
  reportInfo: ReportInfo;
  revenue: ReportSection;
  costOfGoodsSold: ReportSection;
  grossProfit: ReportLine;
  operatingExpenses: ReportSection;
  operatingIncome: ReportLine;
  otherIncome: ReportSection;
  otherExpenses: ReportSection;
  incomeBeforeTaxes: ReportLine;
  taxes: ReportSection;
  netIncome: ReportLine;
  comparison?: ProfitLossComparison;
}

export interface ProfitLossComparison {
  previousPeriod: {
    netIncome: number;
    changeAmount: number;
    changePercentage: number;
  };
  budgetComparison?: {
    budgetedNetIncome: number;
    variance: number;
    variancePercentage: number;
  };
}

// Balance Sheet
export interface BalanceSheet {
  reportInfo: ReportInfo;
  assets: AssetSection;
  liabilities: LiabilitySection;
  equity: EquitySection;
  totalAssets: ReportLine;
  totalLiabilitiesAndEquity: ReportLine;
  isBalanced: boolean;
  comparison?: BalanceSheetComparison;
}

export interface AssetSection {
  currentAssets: ReportSection;
  fixedAssets: ReportSection;
  intangibleAssets: ReportSection;
  otherAssets: ReportSection;
  totalAssets: ReportLine;
}

export interface LiabilitySection {
  currentLiabilities: ReportSection;
  longTermLiabilities: ReportSection;
  totalLiabilities: ReportLine;
}

export interface EquitySection {
  ownersEquity: ReportSection;
  retainedEarnings: ReportLine;
  totalEquity: ReportLine;
}

export interface BalanceSheetComparison {
  previousPeriod: {
    totalAssets: number;
    totalLiabilities: number;
    totalEquity: number;
    assetChange: number;
    liabilityChange: number;
    equityChange: number;
  };
}

// Cash Flow Statement
export interface CashFlowStatement {
  reportInfo: ReportInfo;
  operatingActivities: CashFlowSection;
  investingActivities: CashFlowSection;
  financingActivities: CashFlowSection;
  netCashFlow: ReportLine;
  beginningCash: ReportLine;
  endingCash: ReportLine;
  comparison?: CashFlowComparison;
}

export interface CashFlowSection {
  title: string;
  items: ReportLine[];
  subtotal: ReportLine;
}

export interface CashFlowComparison {
  previousPeriod: {
    netCashFlow: number;
    operatingCashFlow: number;
    investingCashFlow: number;
    financingCashFlow: number;
  };
}

// Common Report Structures
export interface ReportInfo {
  title: string;
  subtitle?: string;
  businessName: string;
  periodDescription: string;
  startDate: number;
  endDate: number;
  generatedAt: number;
  currency: string;
  baseCurrency?: string;
  exchangeRate?: number;
}

export interface ReportSection {
  title: string;
  accounts: ReportLine[];
  subtotal: ReportLine;
  includeInTotal?: boolean;
}

export interface ReportLine {
  id?: string;
  accountId?: string;
  accountCode?: string;
  accountName?: string;
  description: string;
  amount: number;
  percentage?: number;
  level: number;
  isSubtotal?: boolean;
  isTotal?: boolean;
  parentId?: string;
  children?: ReportLine[];
  metadata?: Record<string, any>;
}

// Aging Reports
export interface AgingReportSummary {
  reportInfo: ReportInfo;
  summary: AgingSummary;
  details: AgingDetail[];
  totals: AgingBuckets;
}

export interface AgingSummary {
  totalOutstanding: number;
  totalCustomers: number;
  averageDaysOutstanding: number;
  largestOutstanding: {
    customerId: string;
    customerName: string;
    amount: number;
  };
}

export interface AgingDetail {
  entityId: string;
  entityName: string;
  entityType: 'customer' | 'vendor';
  contactInfo?: {
    email?: string;
    phone?: string;
  };
  creditLimit?: number;
  buckets: AgingBuckets;
  invoices: AgingInvoice[];
}

export interface AgingBuckets {
  current: number;
  days1to30: number;
  days31to60: number;
  days61to90: number;
  over90Days: number;
  total: number;
}

export interface AgingInvoice {
  invoiceId: string;
  invoiceNumber: string;
  date: number;
  dueDate: number;
  originalAmount: number;
  balanceAmount: number;
  daysPastDue: number;
  agingBucket: AgingBucket;
}

export enum AgingBucket {
  CURRENT = 'CURRENT',
  DAYS_1_30 = 'DAYS_1_30',
  DAYS_31_60 = 'DAYS_31_60',
  DAYS_61_90 = 'DAYS_61_90',
  OVER_90_DAYS = 'OVER_90_DAYS'
}

// Custom Report Builder
export interface CustomReportDefinition {
  id: string;
  name: string;
  description?: string;
  dataSource: ReportDataSource;
  columns: ReportColumn[];
  filters: ReportFilter[];
  sorting: ReportSort[];
  grouping?: ReportGrouping[];
  aggregations?: ReportAggregation[];
  formatting?: ReportFormatting;
  isTemplate?: boolean;
  isPublic?: boolean;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
  businessId: string;
}

export enum ReportDataSource {
  CHART_OF_ACCOUNTS = 'CHART_OF_ACCOUNTS',
  JOURNAL_ENTRIES = 'JOURNAL_ENTRIES',
  JOURNAL_LINES = 'JOURNAL_LINES',
  GENERAL_LEDGER = 'GENERAL_LEDGER',
  TRIAL_BALANCE = 'TRIAL_BALANCE',
  INVOICES = 'INVOICES',
  PAYMENTS = 'PAYMENTS',
  CUSTOMERS = 'CUSTOMERS',
  VENDORS = 'VENDORS',
  CUSTOM_SQL = 'CUSTOM_SQL'
}

export interface ReportColumn {
  id: string;
  name: string;
  field: string;
  dataType: FilterDataType;
  format?: ColumnFormat;
  width?: number;
  isVisible: boolean;
  sortOrder?: number;
  aggregationType?: AggregationType;
}

export interface ColumnFormat {
  type: 'currency' | 'percentage' | 'number' | 'date' | 'text';
  decimalPlaces?: number;
  currencySymbol?: string;
  dateFormat?: string;
  thousandsSeparator?: boolean;
}

export enum AggregationType {
  SUM = 'SUM',
  AVERAGE = 'AVERAGE',
  COUNT = 'COUNT',
  MIN = 'MIN',
  MAX = 'MAX',
  MEDIAN = 'MEDIAN'
}

export interface ReportSort {
  field: string;
  direction: 'ASC' | 'DESC';
  priority: number;
}

export interface ReportGrouping {
  field: string;
  level: number;
  showSubtotals: boolean;
  showGrandTotal: boolean;
}

export interface ReportAggregation {
  field: string;
  type: AggregationType;
  label?: string;
}

export interface ReportFormatting {
  headerStyle?: {
    backgroundColor?: string;
    textColor?: string;
    fontWeight?: string;
  };
  alternateRowColors?: boolean;
  showGridLines?: boolean;
  fontSize?: number;
  fontFamily?: string;
}

// Export Configuration
export interface ExportConfiguration {
  format: ExportFormat;
  filename?: string;
  includeHeaders?: boolean;
  includeFooters?: boolean;
  includeMetadata?: boolean;
  compression?: boolean;
  password?: string;
}

export enum ExportFormat {
  EXCEL = 'EXCEL',
  CSV = 'CSV',
  PDF = 'PDF',
  JSON = 'JSON'
}

// Report Generation Requests
export interface GenerateReportRequest {
  type: FinancialReportType;
  parameters: ReportParameters;
  exportFormats?: ExportFormat[];
  saveToHistory?: boolean;
}

export interface GenerateCustomReportRequest {
  definitionId: string;
  parameters: ReportParameters;
  exportFormats?: ExportFormat[];
  saveToHistory?: boolean;
}

export interface ReportExportRequest {
  reportId: string;
  format: ExportFormat;
  configuration?: ExportConfiguration;
}