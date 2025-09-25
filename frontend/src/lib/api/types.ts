// Auto-generated types from backend schemas
// These should be generated from the backend OpenAPI spec or database schemas

export interface User {
  id: string
  email: string
  name: string
  role: string
  businessId: string
  departmentId?: string
  createdAt: string
  updatedAt: string
  emailVerified: boolean
  mfaEnabled: boolean
  profilePicture?: string
  settings?: Record<string, any>
}

export interface Business {
  id: string
  name: string
  domain?: string
  industry?: string
  size?: string
  taxId?: string
  address?: Address
  phone?: string
  email?: string
  website?: string
  logo?: string
  settings?: BusinessSettings
  subscription?: Subscription
  createdAt: string
  updatedAt: string
  isActive: boolean
}

export interface Address {
  street: string
  city: string
  state: string
  postalCode: string
  country: string
}

export interface BusinessSettings {
  timezone?: string
  currency?: string
  fiscalYearStart?: string
  dateFormat?: string
  numberFormat?: string
  features?: string[]
}

export interface Subscription {
  plan: 'trial' | 'starter' | 'professional' | 'enterprise'
  status: 'active' | 'cancelled' | 'suspended' | 'expired'
  startDate: string
  endDate?: string
  seats: number
  features: string[]
}

export interface Department {
  id: string
  businessId: string
  name: string
  code: string
  parentId?: string
  managerId?: string
  description?: string
  createdAt: string
  updatedAt: string
}

export interface Role {
  id: string
  name: string
  description?: string
  permissions: string[]
  isSystem: boolean
  createdAt: string
  updatedAt: string
}

export interface Permission {
  id: string
  resource: string
  action: string
  description?: string
  conditions?: Record<string, any>
}

// CRM Types
export interface Lead {
  id: string
  businessId: string
  companyName: string
  contactName: string
  email: string
  phone?: string
  source: string
  status: LeadStatus
  score?: number
  assignedTo?: string
  tags?: string[]
  notes?: string
  metadata?: Record<string, any>
  createdAt: string
  updatedAt: string
}

export enum LeadStatus {
  NEW = 'new',
  CONTACTED = 'contacted',
  QUALIFIED = 'qualified',
  PROPOSAL = 'proposal',
  NEGOTIATION = 'negotiation',
  CLOSED_WON = 'closed_won',
  CLOSED_LOST = 'closed_lost',
}

export interface Contact {
  id: string
  businessId: string
  companyId?: string
  firstName: string
  lastName: string
  email: string
  phone?: string
  mobile?: string
  title?: string
  department?: string
  address?: Address
  tags?: string[]
  socialMedia?: Record<string, string>
  notes?: string
  createdAt: string
  updatedAt: string
}

export interface Company {
  id: string
  businessId: string
  name: string
  domain?: string
  industry?: string
  size?: string
  revenue?: number
  address?: Address
  phone?: string
  website?: string
  socialMedia?: Record<string, string>
  tags?: string[]
  notes?: string
  createdAt: string
  updatedAt: string
}

// Finance Types
export interface Invoice {
  id: string
  businessId: string
  invoiceNumber: string
  customerId: string
  issueDate: string
  dueDate: string
  status: InvoiceStatus
  items: InvoiceItem[]
  subtotal: number
  tax: number
  discount?: number
  total: number
  currency: string
  notes?: string
  terms?: string
  attachments?: string[]
  createdAt: string
  updatedAt: string
}

export enum InvoiceStatus {
  DRAFT = 'draft',
  SENT = 'sent',
  VIEWED = 'viewed',
  PARTIALLY_PAID = 'partially_paid',
  PAID = 'paid',
  OVERDUE = 'overdue',
  CANCELLED = 'cancelled',
}

export interface InvoiceItem {
  id: string
  description: string
  quantity: number
  unitPrice: number
  tax?: number
  discount?: number
  total: number
}

export interface Payment {
  id: string
  businessId: string
  invoiceId: string
  amount: number
  currency: string
  method: PaymentMethod
  status: PaymentStatus
  reference?: string
  notes?: string
  processedAt?: string
  createdAt: string
  updatedAt: string
}

export enum PaymentMethod {
  CASH = 'cash',
  CHECK = 'check',
  CREDIT_CARD = 'credit_card',
  BANK_TRANSFER = 'bank_transfer',
  PAYPAL = 'paypal',
  STRIPE = 'stripe',
  OTHER = 'other',
}

export enum PaymentStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  COMPLETED = 'completed',
  FAILED = 'failed',
  REFUNDED = 'refunded',
  CANCELLED = 'cancelled',
}

// Accounting Types
export interface Account {
  id: string
  businessId: string
  code: string
  name: string
  type: AccountType
  subtype?: string
  parentId?: string
  balance: number
  currency: string
  description?: string
  isActive: boolean
  isSystem: boolean
  createdAt: string
  updatedAt: string
}

export enum AccountType {
  ASSET = 'asset',
  LIABILITY = 'liability',
  EQUITY = 'equity',
  REVENUE = 'revenue',
  EXPENSE = 'expense',
}

export interface JournalEntry {
  id: string
  businessId: string
  entryNumber: string
  date: string
  description: string
  reference?: string
  lines: JournalLine[]
  status: 'draft' | 'posted' | 'cancelled'
  attachments?: string[]
  createdBy: string
  approvedBy?: string
  createdAt: string
  updatedAt: string
}

export interface JournalLine {
  id: string
  accountId: string
  accountCode: string
  accountName: string
  debit?: number
  credit?: number
  description?: string
  projectId?: string
  departmentId?: string
}

// Workflow Types
export interface Workflow {
  id: string
  businessId: string
  name: string
  description?: string
  trigger: WorkflowTrigger
  conditions?: WorkflowCondition[]
  actions: WorkflowAction[]
  status: 'active' | 'inactive' | 'draft'
  createdAt: string
  updatedAt: string
}

export interface WorkflowTrigger {
  type: 'event' | 'schedule' | 'manual'
  event?: string
  schedule?: string
  config?: Record<string, any>
}

export interface WorkflowCondition {
  field: string
  operator: string
  value: any
  logic?: 'and' | 'or'
}

export interface WorkflowAction {
  type: string
  config: Record<string, any>
  order: number
}

// Audit Types
export interface AuditLog {
  id: string
  businessId: string
  userId: string
  action: string
  resource: string
  resourceId?: string
  changes?: Record<string, any>
  metadata?: Record<string, any>
  ipAddress?: string
  userAgent?: string
  createdAt: string
}

// Notification Types
export interface Notification {
  id: string
  userId: string
  type: string
  title: string
  message: string
  data?: Record<string, any>
  read: boolean
  createdAt: string
  readAt?: string
}

// File Types
export interface FileMetadata {
  id: string
  businessId: string
  name: string
  path: string
  size: number
  mimeType: string
  uploadedBy: string
  tags?: string[]
  metadata?: Record<string, any>
  createdAt: string
  updatedAt: string
}

// Report Types
export interface Report {
  id: string
  businessId: string
  name: string
  description?: string
  type: string
  query?: string
  filters?: Record<string, any>
  columns?: ReportColumn[]
  schedule?: string
  recipients?: string[]
  format?: 'pdf' | 'excel' | 'csv'
  createdBy: string
  createdAt: string
  updatedAt: string
}

export interface ReportColumn {
  field: string
  label: string
  type: string
  format?: string
  aggregate?: string
  visible: boolean
  order: number
}