/**
 * Core Component Type Definitions
 *
 * Replaces 342+ instances of `any` types across the codebase
 * Created as part of ESLint warning remediation
 *
 * @see ESLINT-AUDIT-AND-FIX-PLAN.md
 */

import type React from 'react'

// ============================================================================
// React Core Types (Re-exports for convenience)
// ============================================================================

export type {
  ReactNode,
  ReactElement,
  FC,
  ComponentProps,
  CSSProperties,
  HTMLAttributes,
  RefObject
} from 'react'

// ============================================================================
// Base Component Props
// ============================================================================

/**
 * Base props for all components
 */
export interface BaseProps {
  /** Optional CSS class name */
  className?: string
  /** Optional element ID */
  id?: string
  /** Optional inline styles */
  style?: React.CSSProperties
}

/**
 * Props for components that accept children
 */
export interface ChildrenProps {
  /** Child elements */
  children: React.ReactNode
}

/**
 * Props for components that accept data
 */
export interface DataProps<T = unknown> {
  /** Data to render */
  data: T
}

/**
 * Combined base props with children
 */
export interface BaseComponentProps extends BaseProps, ChildrenProps {}

// ============================================================================
// Event Handler Types
// ============================================================================

/**
 * Mouse event handler for any HTML element
 */
export type MouseEventHandler<T extends HTMLElement = HTMLElement> =
  (event: React.MouseEvent<T>) => void

/**
 * Click event handler for buttons
 */
export type ClickHandler = MouseEventHandler<HTMLButtonElement>

/**
 * Change event handler for inputs
 */
export type ChangeEventHandler<T extends HTMLElement = HTMLInputElement> =
  (event: React.ChangeEvent<T>) => void

/**
 * Input change handler
 */
export type InputChangeHandler = ChangeEventHandler<HTMLInputElement>

/**
 * Form submit handler
 */
export type FormSubmitHandler<T extends HTMLElement = HTMLFormElement> =
  (event: React.FormEvent<T>) => void

/**
 * Keyboard event handler
 */
export type KeyboardEventHandler<T extends HTMLElement = HTMLElement> =
  (event: React.KeyboardEvent<T>) => void

/**
 * Focus event handler
 */
export type FocusEventHandler<T extends HTMLElement = HTMLElement> =
  (event: React.FocusEvent<T>) => void

/**
 * Drag event handler
 */
export type DragEventHandler<T extends HTMLElement = HTMLElement> =
  (event: React.DragEvent<T>) => void

// ============================================================================
// Widget & Dashboard Types
// ============================================================================

/**
 * Base widget interface
 */
export interface WidgetBase {
  /** Unique widget ID */
  id: string
  /** Widget type identifier */
  type: string
  /** Display title */
  title: string
  /** Optional description */
  description?: string
}

/**
 * Widget position
 */
export interface WidgetPosition {
  /** X coordinate */
  x: number
  /** Y coordinate */
  y: number
}

/**
 * Widget size
 */
export interface WidgetSize {
  /** Width in grid units */
  width: number
  /** Height in grid units */
  height: number
}

/**
 * Complete widget configuration
 */
export interface WidgetConfig<TData = unknown> extends WidgetBase {
  /** Widget position */
  position: WidgetPosition
  /** Widget size */
  size: WidgetSize
  /** Widget-specific data */
  data?: TData
  /** Visibility flag */
  visible?: boolean
  /** Whether widget can be moved */
  draggable?: boolean
  /** Whether widget can be resized */
  resizable?: boolean
}

// ============================================================================
// Data Structure Types
// ============================================================================

/**
 * Invoice data structure
 */
export interface InvoiceData {
  /** Invoice number */
  number: string
  /** Invoice status */
  status: 'paid' | 'pending' | 'overdue' | 'draft' | 'cancelled'
  /** Customer name */
  customer: string
  /** Customer ID */
  customerId: string
  /** Total amount */
  amount: number
  /** Currency code */
  currency?: string
  /** Due date */
  dueDate: string
  /** Issue date */
  issueDate: string
  /** Line items */
  items: InvoiceLineItem[]
  /** Tax amount */
  tax?: number
  /** Notes */
  notes?: string
}

/**
 * Invoice line item
 */
export interface InvoiceLineItem {
  /** Item description */
  description: string
  /** Quantity */
  quantity: number
  /** Unit price */
  price: number
  /** Tax rate */
  taxRate?: number
  /** Total amount */
  total?: number
}

/**
 * Metric item for dashboard display
 */
export interface MetricItem {
  /** Metric value */
  value: string | number
  /** Metric label */
  label: string
  /** Change percentage */
  change?: number
  /** Trend direction */
  trend?: 'up' | 'down' | 'stable'
  /** Icon name (lucide-react) */
  icon?: string
  /** Color theme */
  color?: 'primary' | 'secondary' | 'success' | 'warning' | 'danger'
}

/**
 * Metrics data collection
 */
export interface MetricsData {
  /** Array of metrics */
  metrics: MetricItem[]
  /** Optional period label */
  period?: string
  /** Optional comparison period */
  comparisonPeriod?: string
}

// ============================================================================
// Table Types
// ============================================================================

/**
 * Base table row (extend this for specific row types)
 */
export interface TableRow {
  /** Unique row ID */
  id: string
  /** Additional row properties */
  [key: string]: unknown
}

/**
 * Table column definition
 */
export interface TableColumn<T = TableRow> {
  /** Column key (must match data property) */
  key: string
  /** Column header text */
  header: string
  /** Cell renderer function */
  accessor: (row: T) => React.ReactNode
  /** Whether column is sortable */
  sortable?: boolean
  /** Column width */
  width?: string | number
  /** Column alignment */
  align?: 'left' | 'center' | 'right'
  /** Whether column is hidden */
  hidden?: boolean
}

/**
 * Sort configuration
 */
export interface SortConfig {
  /** Property key to sort by */
  key: string
  /** Sort direction */
  direction: 'asc' | 'desc'
}

/**
 * Filter configuration
 */
export interface FilterConfig {
  /** Filter key-value pairs */
  [key: string]: unknown
}

/**
 * Pagination configuration
 */
export interface PaginationConfig {
  /** Current page number (1-indexed) */
  page: number
  /** Items per page */
  pageSize: number
  /** Total number of items */
  total: number
}

/**
 * Complete table configuration
 */
export interface TableConfig<T = TableRow> {
  /** Column definitions */
  columns: TableColumn<T>[]
  /** Table data */
  data: T[]
  /** Sort configuration */
  sort?: SortConfig
  /** Filter configuration */
  filters?: FilterConfig
  /** Pagination configuration */
  pagination?: PaginationConfig
  /** Row click handler */
  onRowClick?: (row: T) => void
  /** Row selection handler */
  onRowSelect?: (rows: T[]) => void
  /** Whether rows are selectable */
  selectable?: boolean
  /** Selected row IDs */
  selectedIds?: string[]
}

// ============================================================================
// Paginated Data
// ============================================================================

/**
 * Paginated data response
 */
export interface PaginatedData<T> {
  /** Data items */
  items: T[]
  /** Total number of items */
  total: number
  /** Current page */
  page: number
  /** Items per page */
  pageSize: number
  /** Total pages */
  totalPages: number
  /** Whether there's a next page */
  hasNext: boolean
  /** Whether there's a previous page */
  hasPrevious: boolean
}

// ============================================================================
// API Response Types
// ============================================================================

/**
 * Generic API response
 */
export interface ApiResponse<T = unknown> {
  /** Whether request was successful */
  success: boolean
  /** Response data */
  data?: T
  /** Error message */
  error?: string
  /** Additional message */
  message?: string
  /** Response metadata */
  meta?: Record<string, unknown>
}

/**
 * API error details
 */
export interface ApiError {
  /** Error code */
  code: string
  /** Error message */
  message: string
  /** Additional error details */
  details?: unknown
  /** Field-specific errors */
  fieldErrors?: Record<string, string[]>
}

// ============================================================================
// Async State Types
// ============================================================================

/**
 * Status of an async operation
 */
export type AsyncStatus = 'idle' | 'loading' | 'success' | 'error'

/**
 * Async state discriminated union
 */
export type AsyncState<T, E = Error> =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: T }
  | { status: 'error'; error: E }

/**
 * Async state with data
 */
export interface AsyncStateWithData<T, E = Error> {
  /** Current status */
  status: AsyncStatus
  /** Data (if successful) */
  data?: T
  /** Error (if failed) */
  error?: E
  /** Whether currently loading */
  isLoading: boolean
  /** Whether successful */
  isSuccess: boolean
  /** Whether errored */
  isError: boolean
  /** Whether idle */
  isIdle: boolean
}

// ============================================================================
// Form Types
// ============================================================================

/**
 * Form field value type
 */
export type FormFieldValue = string | number | boolean | null | undefined

/**
 * Form values object
 */
export type FormValues = Record<string, FormFieldValue>

/**
 * Form errors object
 */
export type FormErrors = Record<string, string | string[]>

/**
 * Form validation result
 */
export interface ValidationResult {
  /** Whether validation passed */
  valid: boolean
  /** Validation errors */
  errors?: FormErrors
}

// ============================================================================
// Select/Dropdown Types
// ============================================================================

/**
 * Option for select/dropdown components
 */
export interface SelectOption<T = string> {
  /** Option value */
  value: T
  /** Display label */
  label: string
  /** Whether option is disabled */
  disabled?: boolean
  /** Optional icon */
  icon?: string
  /** Optional description */
  description?: string
}

/**
 * Grouped select options
 */
export interface SelectOptionGroup<T = string> {
  /** Group label */
  label: string
  /** Options in group */
  options: SelectOption<T>[]
}

// ============================================================================
// File Upload Types
// ============================================================================

/**
 * File upload progress
 */
export interface UploadProgress {
  /** File being uploaded */
  file: File
  /** Upload percentage (0-100) */
  progress: number
  /** Upload status */
  status: 'pending' | 'uploading' | 'success' | 'error'
  /** Error message (if failed) */
  error?: string
  /** Uploaded file URL */
  url?: string
}

/**
 * File with preview
 */
export interface FileWithPreview extends File {
  /** Preview URL */
  preview?: string
}

// ============================================================================
// Modal/Dialog Types
// ============================================================================

/**
 * Modal props
 */
export interface ModalProps {
  /** Whether modal is open */
  open: boolean
  /** Close handler */
  onClose: () => void
  /** Modal title */
  title?: string
  /** Modal size */
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full'
  /** Whether to show close button */
  showClose?: boolean
  /** Whether clicking overlay closes modal */
  closeOnOverlayClick?: boolean
}

// ============================================================================
// Toast/Notification Types
// ============================================================================

/**
 * Toast type
 */
export type ToastType = 'info' | 'success' | 'warning' | 'error'

/**
 * Toast notification
 */
export interface Toast {
  /** Toast ID */
  id: string
  /** Toast type */
  type: ToastType
  /** Toast title */
  title: string
  /** Toast message */
  message?: string
  /** Duration in ms (0 = never auto-dismiss) */
  duration?: number
  /** Action button */
  action?: {
    label: string
    onClick: () => void
  }
}

// ============================================================================
// Chart/Visualization Types
// ============================================================================

/**
 * Chart data point
 */
export interface ChartDataPoint {
  /** Data label */
  label: string
  /** Data value */
  value: number
  /** Optional additional data */
  [key: string]: unknown
}

/**
 * Chart configuration
 */
export interface ChartConfig {
  /** Chart type */
  type: 'line' | 'bar' | 'pie' | 'area' | 'scatter'
  /** Chart data */
  data: ChartDataPoint[]
  /** X-axis label */
  xLabel?: string
  /** Y-axis label */
  yLabel?: string
  /** Show legend */
  showLegend?: boolean
  /** Show grid */
  showGrid?: boolean
  /** Chart colors */
  colors?: string[]
}

// ============================================================================
// Export all types
// ============================================================================

// This file is now the single source of truth for component types
// Import from here instead of using `any` types!
