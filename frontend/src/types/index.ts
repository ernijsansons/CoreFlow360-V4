export interface User {
  id: string
  email: string
  firstName: string
  lastName: string
  avatar?: string
  role: UserRole
  permissions: Permission[]
  createdAt: string
  updatedAt: string
}

export interface Entity {
  id: string
  name: string
  domain?: string
  type: EntityType
  status: EntityStatus
  settings: EntitySettings
  subscription: Subscription
  createdAt: string
  updatedAt: string
}

export interface EntitySettings {
  timezone: string
  currency: string
  dateFormat: string
  theme: 'light' | 'dark' | 'system'
  features: string[]
}

export interface Subscription {
  plan: 'trial' | 'starter' | 'professional' | 'enterprise'
  status: 'active' | 'cancelled' | 'expired' | 'trial'
  expiresAt?: string
  limits: {
    users: number
    storage: number
    apiCalls: number
  }
}

export type EntityType = 'business' | 'organization' | 'team'
export type EntityStatus = 'active' | 'inactive' | 'suspended'

export type UserRole = 'owner' | 'admin' | 'manager' | 'user' | 'viewer'

export interface Permission {
  id: string
  name: string
  resource: string
  action: string
  scope: PermissionScope
}

export type PermissionScope = 'global' | 'entity' | 'self'

export interface AuthState {
  user: User | null
  token: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  isLoading: boolean
}

export interface EntitySwitcherItem {
  id: string
  name: string
  type: EntityType
  status: EntityStatus
  subscription: Subscription
  avatar?: string
  role: UserRole
}

export interface NotificationItem {
  id: string
  type: NotificationType
  title: string
  message: string
  timestamp: string
  read: boolean
  actions?: NotificationAction[]
}

export type NotificationType = 'info' | 'success' | 'warning' | 'error'

export interface NotificationAction {
  label: string
  url?: string
  action?: () => void
}

export interface ApiResponse<T = any> {
  data: T
  success: boolean
  message?: string
  errors?: Record<string, string[]>
  meta?: {
    page: number
    limit: number
    total: number
    totalPages: number
  }
}

export interface PaginationParams {
  page?: number
  limit?: number
  sort?: string
  order?: 'asc' | 'desc'
  search?: string
  filters?: Record<string, any>
}

export interface TableColumn<T = any> {
  key: keyof T | string
  label: string
  sortable?: boolean
  width?: string
  align?: 'left' | 'center' | 'right'
  render?: (value: any, row: T) => React.ReactNode
}

export interface FormField {
  name: string
  label: string
  type: FormFieldType
  required?: boolean
  placeholder?: string
  options?: { label: string; value: string }[]
  validation?: any
}

export type FormFieldType =
  | 'text'
  | 'email'
  | 'password'
  | 'number'
  | 'tel'
  | 'url'
  | 'textarea'
  | 'select'
  | 'checkbox'
  | 'radio'
  | 'date'
  | 'datetime-local'
  | 'file'

export interface RouteConfig {
  path: string
  component: React.ComponentType
  title?: string
  breadcrumb?: string
  permissions?: string[]
  preload?: boolean
}

export interface SidebarItem {
  id: string
  label: string
  icon?: React.ComponentType<{ className?: string }>
  href?: string
  children?: SidebarItem[]
  permissions?: string[]
  badge?: string | number
}

export interface Theme {
  colors: {
    primary: string
    secondary: string
    accent: string
    background: string
    foreground: string
    muted: string
    border: string
  }
  fonts: {
    sans: string
    mono: string
  }
  spacing: Record<string, string>
  borderRadius: Record<string, string>
}

export interface CacheItem<T = any> {
  data: T
  timestamp: number
  ttl: number
}

export interface SyncQueueItem {
  id: string
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'
  url: string
  data?: any
  headers?: Record<string, string>
  timestamp: number
  retries: number
  maxRetries: number
}

export interface ConnectivityStatus {
  online: boolean
  connectionType?: 'wifi' | 'cellular' | 'ethernet' | 'other'
  effectiveType?: '2g' | '3g' | '4g'
  downlink?: number
  rtt?: number
}

export interface WebVitals {
  fcp?: number
  lcp?: number
  cls?: number
  fid?: number
  ttfb?: number
}

export interface ErrorBoundaryState {
  hasError: boolean
  error?: Error
  errorInfo?: React.ErrorInfo
}

export interface LoadingState {
  isLoading: boolean
  progress?: number
  message?: string
}

export interface ModalState {
  isOpen: boolean
  title?: string
  content?: React.ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full'
  onClose?: () => void
}

export interface ToastMessage {
  id: string
  type: NotificationType
  title?: string
  message: string
  duration?: number
  action?: {
    label: string
    onClick: () => void
  }
}

export interface Command {
  id: string
  label: string
  description?: string
  icon?: React.ComponentType<{ className?: string }>
  shortcut?: string[]
  action: () => void
  keywords?: string[]
}

export interface SearchResult {
  id: string
  type: 'page' | 'action' | 'entity' | 'user' | 'document'
  title: string
  description?: string
  url?: string
  icon?: React.ComponentType<{ className?: string }>
  action?: () => void
}

export interface FileUpload {
  id: string
  file: File
  progress: number
  status: 'pending' | 'uploading' | 'completed' | 'error'
  url?: string
  error?: string
}