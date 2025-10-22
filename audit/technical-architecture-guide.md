# Technical Architecture Guide - Backend-to-UI Integration

**Created**: 2025-10-22
**Purpose**: Architectural patterns and best practices for integration implementation
**Audience**: Senior engineers, tech leads, architects

---

## Overview

This document defines the technical architecture and patterns for implementing backend-to-UI integration features. Following these patterns ensures consistency, maintainability, and scalability.

---

## Table of Contents

1. [Architecture Principles](#architecture-principles)
2. [Frontend Architecture](#frontend-architecture)
3. [Backend Integration Patterns](#backend-integration-patterns)
4. [State Management Strategy](#state-management-strategy)
5. [Error Handling Architecture](#error-handling-architecture)
6. [Caching Strategy](#caching-strategy)
7. [Real-time Updates](#real-time-updates)
8. [Security Architecture](#security-architecture)
9. [Performance Optimization](#performance-optimization)
10. [Testing Architecture](#testing-architecture)

---

## Architecture Principles

### 1. Separation of Concerns

**Layers**:
```
┌─────────────────────────────────────┐
│   Presentation Layer (Components)   │  ← UI logic only
├─────────────────────────────────────┤
│   Business Logic Layer (Hooks)      │  ← Data fetching, state
├─────────────────────────────────────┤
│   Data Access Layer (Services)      │  ← API calls
├─────────────────────────────────────┤
│   Network Layer (API Client)        │  ← HTTP, auth, errors
└─────────────────────────────────────┘
```

**Implementation**:
```typescript
// ❌ BAD: Business logic in component
export function GuidelinesPage() {
  const [data, setData] = useState([])

  useEffect(() => {
    fetch('/api/compliance/guidelines')
      .then(res => res.json())
      .then(setData)
  }, [])

  return <Table data={data} />
}

// ✅ GOOD: Proper separation
export function GuidelinesPage() {
  const { data, isLoading } = useGuidelines() // Hook handles logic
  return <GuidelinesTable data={data} isLoading={isLoading} />
}
```

---

### 2. Single Responsibility Principle

**Component Types**:

```typescript
// Container Component (Smart) - Manages state and logic
export function GuidelinesPageContainer() {
  const [filters, setFilters] = useState({})
  const { data, isLoading } = useGuidelines(filters)
  const createMutation = useCreateGuideline()

  return (
    <GuidelinesPageView
      data={data}
      isLoading={isLoading}
      filters={filters}
      onFiltersChange={setFilters}
      onCreate={createMutation.mutate}
    />
  )
}

// Presentation Component (Dumb) - Pure rendering
export function GuidelinesPageView({
  data,
  isLoading,
  filters,
  onFiltersChange,
  onCreate
}: GuidelinesPageViewProps) {
  return (
    <div>
      <Filters value={filters} onChange={onFiltersChange} />
      <Table data={data} isLoading={isLoading} />
      <CreateButton onClick={onCreate} />
    </div>
  )
}
```

---

### 3. Composition Over Inheritance

```typescript
// ✅ GOOD: Composition with hooks
export function useResourceManager<T>(
  resourceName: string,
  schema: z.ZodType<T>
) {
  const listQuery = useQuery({
    queryKey: [resourceName],
    queryFn: () => fetchResource(resourceName),
  })

  const createMutation = useMutation({
    mutationFn: (data) => createResource(resourceName, data),
  })

  return {
    items: listQuery.data,
    isLoading: listQuery.isLoading,
    create: createMutation.mutate,
  }
}

// Usage
export function GuidelinesPage() {
  const guidelines = useResourceManager('guidelines', guidelineSchema)
  const policies = useResourceManager('policies', policySchema)

  return <div>...</div>
}
```

---

## Frontend Architecture

### Directory Structure

```
frontend/src/
├── pages/                          # Route-level components
│   ├── admin/
│   │   └── compliance/
│   │       ├── GuidelinesPage.tsx          # Container
│   │       ├── GuidelinesTable.tsx         # Presentation
│   │       ├── GuidelinesToolbar.tsx       # Presentation
│   │       └── GuidelineModal.tsx          # Presentation
│   │
├── components/                     # Reusable components
│   ├── ui/                        # Primitives (Button, Input, etc.)
│   ├── layout/                    # Layout components
│   └── shared/                    # Shared business components
│
├── hooks/                         # Custom React hooks
│   ├── useCompliance.ts          # Feature-specific hooks
│   ├── usePagination.ts          # Utility hooks
│   └── useAuth.ts                # Auth hooks
│
├── services/                      # API client services
│   ├── compliance.service.ts     # CRUD operations
│   ├── finance.service.ts
│   └── crm.service.ts
│
├── stores/                        # Zustand stores (client state)
│   ├── auth.store.ts
│   └── ui.store.ts
│
├── lib/                           # Utilities
│   ├── api-client.ts             # Axios instance
│   ├── utils.ts                  # Helper functions
│   └── constants.ts              # App constants
│
├── types/                         # TypeScript types
│   ├── api.types.ts
│   └── models.types.ts
│
└── routes.tsx                     # Route configuration
```

---

### Component Architecture Pattern

**Standard Page Structure**:

```typescript
// pages/admin/compliance/GuidelinesPage.tsx
export function GuidelinesPage() {
  // 1. Local state
  const [modalOpen, setModalOpen] = useState(false)
  const [selectedItem, setSelectedItem] = useState<Guideline | null>(null)

  // 2. Router
  const navigate = useNavigate()
  const { id } = useParams()

  // 3. Global state
  const user = useAuthStore((state) => state.user)

  // 4. Data queries
  const { data, isLoading, error } = useGuidelines()

  // 5. Mutations
  const createMutation = useCreateGuideline()
  const updateMutation = useUpdateGuideline()
  const deleteMutation = useDeleteGuideline()

  // 6. Effects
  useEffect(() => {
    // Side effects here
  }, [dependencies])

  // 7. Handlers
  const handleCreate = () => {
    setSelectedItem(null)
    setModalOpen(true)
  }

  const handleEdit = (item: Guideline) => {
    setSelectedItem(item)
    setModalOpen(true)
  }

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure?')) {
      await deleteMutation.mutateAsync(id)
    }
  }

  // 8. Render
  return (
    <PageLayout>
      <PageHeader
        title="Compliance Guidelines"
        actions={<Button onClick={handleCreate}>Create</Button>}
      />

      <PageContent>
        <GuidelinesTable
          data={data}
          isLoading={isLoading}
          onEdit={handleEdit}
          onDelete={handleDelete}
        />
      </PageContent>

      <GuidelineModal
        open={modalOpen}
        guideline={selectedItem}
        onClose={() => setModalOpen(false)}
        onSave={selectedItem ? updateMutation.mutate : createMutation.mutate}
      />
    </PageLayout>
  )
}
```

---

## Backend Integration Patterns

### API Client Configuration

```typescript
// lib/api-client.ts
import axios from 'axios'
import { z } from 'zod'

// Base configuration
export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8787',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor: Add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor: Handle errors
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    // Handle 401: Refresh token or redirect to login
    if (error.response?.status === 401) {
      const refreshed = await refreshAuthToken()
      if (refreshed) {
        // Retry original request
        return apiClient.request(error.config)
      } else {
        // Redirect to login
        window.location.href = '/login'
      }
    }

    // Handle 403: Permission denied
    if (error.response?.status === 403) {
      toast.error('You do not have permission to perform this action')
    }

    // Handle 500: Server error
    if (error.response?.status >= 500) {
      toast.error('Server error. Please try again later.')
      // Log to Sentry
      captureException(error)
    }

    return Promise.reject(error)
  }
)

// Typed request wrapper
export async function apiRequest<T>(
  schema: z.ZodType<T>,
  request: Promise<any>
): Promise<T> {
  try {
    const response = await request
    return schema.parse(response.data)
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.error('API response validation failed:', error)
      throw new Error('Invalid API response')
    }
    throw error
  }
}
```

---

### Service Layer Pattern

```typescript
// services/base.service.ts
import { z } from 'zod'
import { apiClient, apiRequest } from '@/lib/api-client'

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export function createCRUDService<T>(
  basePath: string,
  schema: z.ZodType<T>,
  listSchema?: z.ZodType<PaginatedResponse<T>>
) {
  return {
    list: async (params?: Record<string, any>) => {
      return apiRequest(
        listSchema ?? z.object({ items: z.array(schema), total: z.number() }),
        apiClient.get(basePath, { params })
      )
    },

    get: async (id: string) => {
      return apiRequest(
        schema,
        apiClient.get(`${basePath}/${id}`)
      )
    },

    create: async (data: Omit<T, 'id'>) => {
      return apiRequest(
        schema,
        apiClient.post(basePath, data)
      )
    },

    update: async (id: string, data: Partial<T>) => {
      return apiRequest(
        schema,
        apiClient.put(`${basePath}/${id}`, data)
      )
    },

    delete: async (id: string) => {
      await apiClient.delete(`${basePath}/${id}`)
    },
  }
}
```

---

## State Management Strategy

### Server State (React Query)

**Use for**: Data from APIs, cached responses

```typescript
// Query keys factory pattern
export const queryKeys = {
  compliance: {
    all: ['compliance'] as const,
    guidelines: () => [...queryKeys.compliance.all, 'guidelines'] as const,
    guidelinesList: (filters: GuidelineFilters) =>
      [...queryKeys.compliance.guidelines(), 'list', filters] as const,
    guideline: (id: string) =>
      [...queryKeys.compliance.guidelines(), 'detail', id] as const,
  },
  finance: {
    all: ['finance'] as const,
    accounts: () => [...queryKeys.finance.all, 'accounts'] as const,
    // ...
  },
}

// Query configuration
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      retry: 3,
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
      refetchOnWindowFocus: false,
      refetchOnReconnect: true,
    },
    mutations: {
      retry: 0, // Don't retry mutations
    },
  },
})
```

---

### Client State (Zustand)

**Use for**: UI state, user preferences, global app state

```typescript
// stores/ui.store.ts
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface UIState {
  sidebarOpen: boolean
  theme: 'light' | 'dark'
  setSidebarOpen: (open: boolean) => void
  setTheme: (theme: 'light' | 'dark') => void
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarOpen: true,
      theme: 'light',
      setSidebarOpen: (open) => set({ sidebarOpen: open }),
      setTheme: (theme) => set({ theme }),
    }),
    {
      name: 'ui-storage', // LocalStorage key
    }
  )
)

// Usage
const sidebarOpen = useUIStore((state) => state.sidebarOpen)
const setSidebarOpen = useUIStore((state) => state.setSidebarOpen)
```

---

### Form State (React Hook Form)

**Use for**: Form validation and submission

```typescript
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'

const formSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().max(5000),
  category: z.enum(['POLICY', 'PROCEDURE']),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
})

type FormData = z.infer<typeof formSchema>

export function GuidelineForm({ guideline, onSubmit }: Props) {
  const form = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: guideline ?? {
      title: '',
      description: '',
      category: 'POLICY',
      severity: 'MEDIUM',
    },
  })

  return (
    <form onSubmit={form.handleSubmit(onSubmit)}>
      <Input {...form.register('title')} />
      {form.formState.errors.title && (
        <ErrorMessage>{form.formState.errors.title.message}</ErrorMessage>
      )}
      {/* ... other fields */}
    </form>
  )
}
```

---

## Error Handling Architecture

### Error Boundary Pattern

```typescript
// components/ErrorBoundary.tsx
import { Component, ErrorInfo, ReactNode } from 'react'
import { captureException } from '@/lib/sentry'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Error boundary caught:', error, errorInfo)
    captureException(error, { extra: errorInfo })
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback ?? (
        <div className="error-boundary">
          <h2>Something went wrong</h2>
          <p>{this.state.error?.message}</p>
          <button onClick={() => this.setState({ hasError: false, error: null })}>
            Try again
          </button>
        </div>
      )
    }

    return this.props.children
  }
}

// Usage
<ErrorBoundary fallback={<ErrorFallback />}>
  <GuidelinesPage />
</ErrorBoundary>
```

---

### API Error Handling Pattern

```typescript
// lib/errors.ts
export class APIError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public code?: string,
    public details?: any
  ) {
    super(message)
    this.name = 'APIError'
  }
}

export function handleAPIError(error: any): never {
  if (axios.isAxiosError(error)) {
    const statusCode = error.response?.status ?? 500
    const message = error.response?.data?.message ?? error.message
    const code = error.response?.data?.code
    const details = error.response?.data?.details

    throw new APIError(message, statusCode, code, details)
  }

  throw error
}

// Usage in service
export async function createGuideline(data: CreateGuidelineData) {
  try {
    const response = await apiClient.post('/api/compliance/guidelines', data)
    return guidelineSchema.parse(response.data)
  } catch (error) {
    handleAPIError(error)
  }
}

// Usage in component
const createMutation = useMutation({
  mutationFn: createGuideline,
  onError: (error: APIError) => {
    if (error.statusCode === 400) {
      toast.error('Validation error', { description: error.message })
    } else if (error.statusCode === 403) {
      toast.error('Permission denied')
    } else {
      toast.error('Something went wrong')
      captureException(error)
    }
  },
})
```

---

## Caching Strategy

### Cache Levels

```
┌─────────────────────────────────────────┐
│  Level 1: React Query Cache (5-30 min)  │
├─────────────────────────────────────────┤
│  Level 2: Service Worker Cache (1 hour) │
├─────────────────────────────────────────┤
│  Level 3: CDN Cache (Backend, 5 min)    │
├─────────────────────────────────────────┤
│  Level 4: Redis Cache (Backend, 10 min) │
└─────────────────────────────────────────┘
```

### Cache Invalidation Strategy

```typescript
// hooks/useCompliance.ts
export function useCreateGuideline() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: complianceService.createGuideline,
    onSuccess: (newGuideline) => {
      // Strategy 1: Invalidate and refetch
      queryClient.invalidateQueries({
        queryKey: queryKeys.compliance.guidelines(),
      })

      // Strategy 2: Optimistic update (faster UX)
      queryClient.setQueryData(
        queryKeys.compliance.guidelinesList({}),
        (old: PaginatedResponse<Guideline> | undefined) => {
          if (!old) return old
          return {
            ...old,
            items: [newGuideline, ...old.items],
            total: old.total + 1,
          }
        }
      )

      // Strategy 3: Set individual item cache
      queryClient.setQueryData(
        queryKeys.compliance.guideline(newGuideline.id),
        newGuideline
      )
    },
  })
}
```

---

## Real-time Updates

### WebSocket Architecture

```typescript
// lib/websocket.ts
class WebSocketManager {
  private ws: WebSocket | null = null
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectDelay = 1000

  connect(url: string) {
    this.ws = new WebSocket(url)

    this.ws.onopen = () => {
      console.log('WebSocket connected')
      this.reconnectAttempts = 0
    }

    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data)
      this.handleMessage(message)
    }

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    this.ws.onclose = () => {
      console.log('WebSocket disconnected')
      this.reconnect(url)
    }
  }

  private reconnect(url: string) {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached')
      return
    }

    this.reconnectAttempts++
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts)

    setTimeout(() => {
      console.log(`Reconnecting... (attempt ${this.reconnectAttempts})`)
      this.connect(url)
    }, delay)
  }

  private handleMessage(message: any) {
    // Emit event for subscribers
    window.dispatchEvent(
      new CustomEvent('ws-message', { detail: message })
    )
  }

  send(data: any) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    }
  }

  disconnect() {
    this.ws?.close()
    this.ws = null
  }
}

export const wsManager = new WebSocketManager()

// Hook for real-time updates
export function useWebSocket<T>(
  url: string,
  onMessage: (data: T) => void
) {
  useEffect(() => {
    wsManager.connect(url)

    const handler = (event: CustomEvent) => {
      onMessage(event.detail)
    }

    window.addEventListener('ws-message', handler as EventListener)

    return () => {
      window.removeEventListener('ws-message', handler as EventListener)
      wsManager.disconnect()
    }
  }, [url, onMessage])
}
```

---

## Security Architecture

### Authentication Flow

```typescript
// stores/auth.store.ts
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AuthState {
  token: string | null
  user: User | null
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  refreshToken: () => Promise<void>
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      token: null,
      user: null,
      isAuthenticated: false,

      login: async (email, password) => {
        const response = await apiClient.post('/api/auth/login', {
          email,
          password,
        })

        const { token, user } = response.data

        set({
          token,
          user,
          isAuthenticated: true,
        })

        localStorage.setItem('auth_token', token)
      },

      logout: () => {
        set({
          token: null,
          user: null,
          isAuthenticated: false,
        })

        localStorage.removeItem('auth_token')
      },

      refreshToken: async () => {
        try {
          const response = await apiClient.post('/api/auth/refresh')
          const { token } = response.data

          set({ token })
          localStorage.setItem('auth_token', token)
        } catch (error) {
          // Refresh failed, logout
          get().logout()
        }
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ token: state.token, user: state.user }),
    }
  )
)
```

### Permission Checking

```typescript
// hooks/usePermission.ts
export function usePermission(permission: string) {
  const user = useAuthStore((state) => state.user)

  return useMemo(() => {
    if (!user) return false

    // Check if user has permission
    return user.permissions.includes(permission)
  }, [user, permission])
}

// Component usage
export function DeleteButton({ itemId }: Props) {
  const canDelete = usePermission('compliance:guidelines:delete')
  const deleteMutation = useDeleteGuideline()

  if (!canDelete) return null

  return (
    <Button onClick={() => deleteMutation.mutate(itemId)}>
      Delete
    </Button>
  )
}
```

---

## Performance Optimization

### Code Splitting

```typescript
// routes.tsx
import { lazy, Suspense } from 'react'

// Lazy load pages
const GuidelinesPage = lazy(() => import('@/pages/admin/compliance/GuidelinesPage'))
const PoliciesPage = lazy(() => import('@/pages/admin/compliance/PoliciesPage'))

export const routes = [
  {
    path: '/admin/compliance/guidelines',
    element: (
      <Suspense fallback={<PageSkeleton />}>
        <GuidelinesPage />
      </Suspense>
    ),
  },
  {
    path: '/admin/compliance/policies',
    element: (
      <Suspense fallback={<PageSkeleton />}>
        <PoliciesPage />
      </Suspense>
    ),
  },
]
```

### Memoization

```typescript
// Memoize expensive computations
export function AccountsTree({ accounts }: Props) {
  const tree = useMemo(() => {
    return buildAccountTree(accounts) // Expensive operation
  }, [accounts])

  return <TreeView data={tree} />
}

// Memoize callbacks
export function GuidelinesTable({ data, onEdit }: Props) {
  const handleEdit = useCallback(
    (guideline: Guideline) => {
      onEdit(guideline)
    },
    [onEdit]
  )

  return (
    <Table>
      {data.map((item) => (
        <Row key={item.id} onEdit={handleEdit} />
      ))}
    </Table>
  )
}
```

---

## Testing Architecture

### Test Organization

```
frontend/src/
├── __tests__/
│   ├── unit/                    # Unit tests
│   │   ├── services/
│   │   ├── hooks/
│   │   └── utils/
│   ├── integration/             # Integration tests
│   │   └── api/
│   └── e2e/                     # E2E tests (Playwright)
│       ├── compliance/
│       ├── finance/
│       └── crm/
```

### Test Utilities

```typescript
// __tests__/utils/test-utils.tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { ReactNode } from 'react'

export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
}

export function renderWithProviders(ui: ReactNode) {
  const testQueryClient = createTestQueryClient()

  return render(
    <QueryClientProvider client={testQueryClient}>
      {ui}
    </QueryClientProvider>
  )
}

// Mock API responses
export function mockAPIResponse<T>(data: T) {
  return Promise.resolve({ data })
}
```

---

## Architecture Decision Records (ADRs)

### ADR-001: React Query for Server State

**Status**: Accepted
**Date**: 2025-10-22

**Context**: Need to manage server state (API data) efficiently with caching and synchronization.

**Decision**: Use React Query for all server state management.

**Consequences**:
- ✅ Built-in caching and automatic refetching
- ✅ Optimistic updates out of the box
- ✅ DevTools for debugging
- ❌ Additional dependency (but well worth it)

---

### ADR-002: Zod for Runtime Validation

**Status**: Accepted
**Date**: 2025-10-22

**Context**: TypeScript provides compile-time type safety, but we need runtime validation for API responses.

**Decision**: Use Zod schemas for runtime validation of all API responses.

**Consequences**:
- ✅ Catches API contract violations at runtime
- ✅ Single source of truth for types
- ✅ Great error messages
- ❌ Additional parsing overhead (minimal)

---

### ADR-003: Feature Flags for Gradual Rollout

**Status**: Accepted
**Date**: 2025-10-22

**Context**: New features need to be deployed safely with ability to rollback instantly.

**Decision**: All new features must be behind feature flags.

**Consequences**:
- ✅ Deploy to production with features OFF
- ✅ Enable for internal users first (beta testing)
- ✅ Gradual rollout (10% → 50% → 100%)
- ✅ Instant rollback without redeployment
- ❌ Additional complexity in code

---

## Quick Reference

### File Naming Conventions
- **Components**: `PascalCase.tsx` (e.g., `GuidelinesPage.tsx`)
- **Hooks**: `camelCase.ts` with `use` prefix (e.g., `useCompliance.ts`)
- **Services**: `camelCase.service.ts` (e.g., `compliance.service.ts`)
- **Stores**: `camelCase.store.ts` (e.g., `auth.store.ts`)
- **Utils**: `kebab-case.ts` (e.g., `format-date.ts`)

### Import Order
```typescript
// 1. React/external libraries
import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'

// 2. Internal libraries
import { apiClient } from '@/lib/api-client'
import { formatDate } from '@/lib/utils'

// 3. Components
import { Button } from '@/components/ui/button'
import { Table } from '@/components/ui/table'

// 4. Hooks
import { useGuidelines } from '@/hooks/useCompliance'

// 5. Types
import type { Guideline } from '@/types/compliance'
```

---

**Technical Architecture Guide Complete** ✅

**Next Steps**:
1. Review with tech lead and architects
2. Incorporate feedback and finalize patterns
3. Create code templates based on these patterns
4. Train team on architectural decisions

