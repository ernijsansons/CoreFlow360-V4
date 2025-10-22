# API Integration Cookbook - Code Examples

**Created**: 2025-10-22
**Purpose**: Ready-to-use code snippets for integrating backend APIs
**Format**: Copy-paste patterns for common integration scenarios

---

## Table of Contents

1. [Core Patterns](#core-patterns)
2. [Compliance Module](#compliance-module)
3. [Finance Module](#finance-module)
4. [CRM Module](#crm-module)
5. [Agent System](#agent-system)
6. [Workflow Engine](#workflow-engine)
7. [Advanced Patterns](#advanced-patterns)

---

## Core Patterns

### Pattern 1: Basic CRUD Service

```typescript
// services/base-crud.service.ts
import { apiClient } from '@/lib/api-client'
import { z } from 'zod'

export function createCRUDService<T extends z.ZodType>(
  resourcePath: string,
  schema: T
) {
  type Item = z.infer<T>

  return {
    async list(params?: Record<string, unknown>) {
      const response = await apiClient.get(resourcePath, { params })
      return z.array(schema).parse(response.data)
    },

    async get(id: string) {
      const response = await apiClient.get(`${resourcePath}/${id}`)
      return schema.parse(response.data)
    },

    async create(data: Omit<Item, 'id' | 'created_at'>) {
      const response = await apiClient.post(resourcePath, data)
      return schema.parse(response.data)
    },

    async update(id: string, data: Partial<Item>) {
      const response = await apiClient.put(`${resourcePath}/${id}`, data)
      return schema.parse(response.data)
    },

    async delete(id: string) {
      await apiClient.delete(`${resourcePath}/${id}`)
    },
  }
}

// Usage:
const guidelineSchema = z.object({
  id: z.string().uuid(),
  title: z.string(),
  // ... other fields
})

export const guidelinesService = createCRUDService(
  '/api/compliance/guidelines',
  guidelineSchema
)
```

---

### Pattern 2: Paginated List Hook

```typescript
// hooks/usePaginatedList.ts
import { useQuery } from '@tanstack/react-query'
import { useState, useMemo } from 'react'

export function usePaginatedList<T>(
  queryKey: unknown[],
  fetchFn: (params: { page: number; page_size: number; [key: string]: unknown }) => Promise<{
    items: T[]
    total: number
  }>,
  options?: {
    initialPageSize?: number
    additionalFilters?: Record<string, unknown>
  }
) {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(options?.initialPageSize ?? 20)

  const params = useMemo(
    () => ({
      page,
      page_size: pageSize,
      ...options?.additionalFilters,
    }),
    [page, pageSize, options?.additionalFilters]
  )

  const query = useQuery({
    queryKey: [...queryKey, params],
    queryFn: () => fetchFn(params),
    keepPreviousData: true,
  })

  return {
    ...query,
    page,
    pageSize,
    setPage,
    setPageSize,
    totalPages: Math.ceil((query.data?.total ?? 0) / pageSize),
  }
}

// Usage:
const { data, isLoading, page, setPage, totalPages } = usePaginatedList(
  ['guidelines'],
  complianceService.listGuidelines,
  { initialPageSize: 20 }
)
```

---

### Pattern 3: Optimistic Updates

```typescript
// hooks/useOptimisticUpdate.ts
import { useMutation, useQueryClient } from '@tanstack/react-query'

export function useOptimisticUpdate<TData, TVariables>(
  queryKey: unknown[],
  mutateFn: (variables: TVariables) => Promise<TData>,
  options?: {
    onSuccess?: (data: TData, variables: TVariables) => void
    onError?: (error: Error, variables: TVariables, context: unknown) => void
  }
) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: mutateFn,
    onMutate: async (variables) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey })

      // Snapshot previous value
      const previousData = queryClient.getQueryData(queryKey)

      // Optimistically update cache
      queryClient.setQueryData(queryKey, (old: TData[] | undefined) => {
        if (!old) return old
        // Update logic here
        return old
      })

      return { previousData }
    },
    onError: (error, variables, context) => {
      // Rollback to previous value
      if (context?.previousData) {
        queryClient.setQueryData(queryKey, context.previousData)
      }
      options?.onError?.(error, variables, context)
    },
    onSuccess: options?.onSuccess,
    onSettled: () => {
      // Always refetch after mutation
      queryClient.invalidateQueries({ queryKey })
    },
  })
}

// Usage:
const updateGuideline = useOptimisticUpdate(
  ['guidelines'],
  ({ id, data }) => complianceService.updateGuideline(id, data),
  {
    onSuccess: () => toast.success('Updated successfully'),
    onError: () => toast.error('Update failed'),
  }
)
```

---

## Compliance Module

### Example 1: List Guidelines with Filters

```typescript
// services/compliance.service.ts
import { apiClient } from '@/lib/api-client'
import { z } from 'zod'

const guidelineSchema = z.object({
  id: z.string().uuid(),
  business_id: z.string().uuid(),
  title: z.string(),
  description: z.string(),
  category: z.enum(['POLICY', 'PROCEDURE', 'STANDARD', 'REGULATION']),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  effective_date: z.string().datetime(),
  created_at: z.string().datetime(),
})

export async function listGuidelines(filters?: {
  page?: number
  page_size?: number
  category?: string
  severity?: string
  search?: string
}) {
  const response = await apiClient.get('/api/compliance/guidelines', {
    params: filters,
  })

  return z
    .object({
      items: z.array(guidelineSchema),
      total: z.number(),
      page: z.number(),
      page_size: z.number(),
    })
    .parse(response.data)
}

// Hook
export function useGuidelines(filters: Parameters<typeof listGuidelines>[0]) {
  return useQuery({
    queryKey: ['guidelines', filters],
    queryFn: () => listGuidelines(filters),
  })
}

// Component
export function GuidelinesPage() {
  const [filters, setFilters] = useState({ page: 1, page_size: 20 })
  const { data, isLoading } = useGuidelines(filters)

  return (
    <div>
      <GuidelinesTable data={data?.items ?? []} isLoading={isLoading} />
      <Pagination
        page={filters.page}
        total={data?.total ?? 0}
        onPageChange={(page) => setFilters({ ...filters, page })}
      />
    </div>
  )
}
```

---

### Example 2: Create Policy with Validation

```typescript
// services/compliance.service.ts
const policyRuleSchema = z.object({
  field: z.string(),
  operator: z.enum(['equals', 'not_equals', 'contains', 'greater_than', 'less_than']),
  value: z.unknown(),
  logic: z.enum(['AND', 'OR']).optional(),
})

const policySchema = z.object({
  id: z.string().uuid(),
  business_id: z.string().uuid(),
  name: z.string().min(1).max(100),
  policy_rules: z.array(policyRuleSchema),
  agent_types: z.array(z.string()),
  is_active: z.boolean(),
})

export type Policy = z.infer<typeof policySchema>

export async function createPolicy(data: {
  name: string
  policy_rules: z.infer<typeof policyRuleSchema>[]
  agent_types: string[]
}) {
  const response = await apiClient.post('/api/compliance/policies', data)
  return policySchema.parse(response.data)
}

// Form Component
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'

const formSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100),
  policy_rules: z
    .array(policyRuleSchema)
    .min(1, 'At least one rule is required'),
  agent_types: z.array(z.string()).min(1, 'Select at least one agent type'),
})

export function PolicyForm() {
  const createMutation = useMutation({
    mutationFn: createPolicy,
    onSuccess: () => toast.success('Policy created'),
  })

  const form = useForm({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: '',
      policy_rules: [],
      agent_types: [],
    },
  })

  const onSubmit = (data: z.infer<typeof formSchema>) => {
    createMutation.mutate(data)
  }

  return (
    <form onSubmit={form.handleSubmit(onSubmit)}>
      <Input {...form.register('name')} />
      {form.formState.errors.name && <p>{form.formState.errors.name.message}</p>}

      <RuleBuilder
        rules={form.watch('policy_rules')}
        onChange={(rules) => form.setValue('policy_rules', rules)}
      />

      <Button type="submit" disabled={createMutation.isLoading}>
        {createMutation.isLoading ? 'Creating...' : 'Create Policy'}
      </Button>
    </form>
  )
}
```

---

## Finance Module

### Example 3: Chart of Accounts Tree

```typescript
// services/finance.service.ts
const accountSchema = z.object({
  id: z.string().uuid(),
  code: z.string().regex(/^\d{4,}$/), // 4+ digits
  name: z.string(),
  type: z.enum(['ASSET', 'LIABILITY', 'EQUITY', 'REVENUE', 'EXPENSE']),
  category: z.string(),
  parent_id: z.string().uuid().nullable(),
  normal_balance: z.enum(['DEBIT', 'CREDIT']),
  is_active: z.boolean(),
  balance: z.number().optional(),
})

export type Account = z.infer<typeof accountSchema>

// Fetch all accounts (backend returns flat list)
export async function listAccounts() {
  const response = await apiClient.get('/api/finance/accounts')
  return z.array(accountSchema).parse(response.data)
}

// Build tree structure client-side
export function buildAccountTree(accounts: Account[]) {
  const accountMap = new Map<string, Account & { children: Account[] }>()

  // First pass: create map with children array
  accounts.forEach((account) => {
    accountMap.set(account.id, { ...account, children: [] })
  })

  // Second pass: build tree
  const roots: (Account & { children: Account[] })[] = []

  accountMap.forEach((account) => {
    if (account.parent_id) {
      const parent = accountMap.get(account.parent_id)
      parent?.children.push(account)
    } else {
      roots.push(account)
    }
  })

  // Sort by code
  const sortByCode = (a: Account, b: Account) =>
    a.code.localeCompare(b.code, undefined, { numeric: true })

  roots.sort(sortByCode)
  accountMap.forEach((account) => {
    account.children.sort(sortByCode)
  })

  return roots
}

// Component
export function ChartOfAccountsTree() {
  const { data: accounts, isLoading } = useQuery({
    queryKey: ['accounts'],
    queryFn: listAccounts,
  })

  const tree = useMemo(() => buildAccountTree(accounts ?? []), [accounts])

  if (isLoading) return <Skeleton />

  return (
    <Tree data={tree}>
      {(account) => (
        <TreeNode key={account.id}>
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm">{account.code}</span>
            <span>{account.name}</span>
            {account.balance !== undefined && (
              <span className="ml-auto font-medium">
                {formatCurrency(account.balance)}
              </span>
            )}
          </div>
        </TreeNode>
      )}
    </Tree>
  )
}
```

---

### Example 4: Journal Entry with Validation

```typescript
// services/finance.service.ts
const journalLineSchema = z.object({
  account_id: z.string().uuid(),
  description: z.string().optional(),
  debit_amount: z.number().min(0),
  credit_amount: z.number().min(0),
})

const journalEntrySchema = z.object({
  id: z.string().uuid(),
  entry_number: z.string(),
  date: z.string().datetime(),
  description: z.string(),
  reference: z.string().optional(),
  status: z.enum(['DRAFT', 'POSTED']),
  lines: z.array(journalLineSchema).min(2),
})

// Custom validation: ensure entry is balanced
const balancedJournalEntrySchema = journalEntrySchema
  .refine(
    (entry) => {
      const totalDebits = entry.lines.reduce((sum, line) => sum + line.debit_amount, 0)
      const totalCredits = entry.lines.reduce((sum, line) => sum + line.credit_amount, 0)
      return Math.abs(totalDebits - totalCredits) < 0.01 // Allow 1 cent rounding difference
    },
    { message: 'Entry must be balanced (debits = credits)' }
  )
  .refine(
    (entry) => {
      // Each line must have EITHER debit OR credit (not both, not neither)
      return entry.lines.every(
        (line) =>
          (line.debit_amount > 0 && line.credit_amount === 0) ||
          (line.credit_amount > 0 && line.debit_amount === 0)
      )
    },
    { message: 'Each line must have either debit or credit amount (not both)' }
  )

export async function createJournalEntry(
  data: Omit<z.infer<typeof journalEntrySchema>, 'id' | 'entry_number' | 'status'>
) {
  // Validate before sending
  balancedJournalEntrySchema.parse({ ...data, id: '', entry_number: '', status: 'DRAFT' })

  const response = await apiClient.post('/api/finance/journal-entries', data)
  return journalEntrySchema.parse(response.data)
}

// Hook with real-time balance calculation
export function useJournalEntryForm() {
  const [lines, setLines] = useState<z.infer<typeof journalLineSchema>[]>([
    { account_id: '', description: '', debit_amount: 0, credit_amount: 0 },
    { account_id: '', description: '', debit_amount: 0, credit_amount: 0 },
  ])

  const balance = useMemo(() => {
    const totalDebits = lines.reduce((sum, line) => sum + line.debit_amount, 0)
    const totalCredits = lines.reduce((sum, line) => sum + line.credit_amount, 0)
    return totalDebits - totalCredits
  }, [lines])

  const isBalanced = Math.abs(balance) < 0.01

  return {
    lines,
    setLines,
    balance,
    isBalanced,
    addLine: () => setLines([...lines, { account_id: '', description: '', debit_amount: 0, credit_amount: 0 }]),
    removeLine: (index: number) => setLines(lines.filter((_, i) => i !== index)),
  }
}
```

---

## CRM Module

### Example 5: AI-Powered Lead Enrichment

```typescript
// services/crm.service.ts
const enrichmentResultSchema = z.object({
  job_title: z.string().optional(),
  company_size: z.number().optional(),
  industry: z.string().optional(),
  linkedin_url: z.string().url().optional(),
  phone: z.string().optional(),
  confidence: z.number().min(0).max(1),
  source: z.enum(['CLEARBIT', 'LINKEDIN', 'MANUAL']),
})

export async function enrichLead(leadId: string, options?: {
  sources?: string[]
  autoApply?: boolean
}) {
  const response = await apiClient.post(`/api/crm/enrichment/enrich`, {
    entity_type: 'lead',
    entity_id: leadId,
    ...options,
  })

  return enrichmentResultSchema.parse(response.data)
}

// Batch enrichment
export async function batchEnrichLeads(leadIds: string[]) {
  const response = await apiClient.post('/api/crm/enrichment/batch', {
    entity_type: 'lead',
    entity_ids: leadIds,
  })

  return z.object({
    job_id: z.string().uuid(),
    status: z.enum(['PENDING', 'PROCESSING', 'COMPLETED', 'FAILED']),
    total: z.number(),
    completed: z.number(),
  }).parse(response.data)
}

// Poll for job status
export function useBatchEnrichmentStatus(jobId: string | null) {
  return useQuery({
    queryKey: ['enrichment-job', jobId],
    queryFn: async () => {
      const response = await apiClient.get(`/api/crm/enrichment/status/${jobId}`)
      return z.object({
        status: z.enum(['PENDING', 'PROCESSING', 'COMPLETED', 'FAILED']),
        completed: z.number(),
        total: z.number(),
        results: z.array(enrichmentResultSchema).optional(),
      }).parse(response.data)
    },
    enabled: !!jobId,
    refetchInterval: (data) => {
      // Poll every 2s while processing
      if (data?.status === 'PROCESSING') return 2000
      // Stop polling when completed
      if (data?.status === 'COMPLETED' || data?.status === 'FAILED') return false
      return 5000
    },
  })
}

// Component with progress
export function BatchEnrichmentDialog({ selectedLeadIds }: { selectedLeadIds: string[] }) {
  const [jobId, setJobId] = useState<string | null>(null)
  const enrichMutation = useMutation({ mutationFn: batchEnrichLeads })
  const { data: status } = useBatchEnrichmentStatus(jobId)

  const handleStart = async () => {
    const result = await enrichMutation.mutateAsync(selectedLeadIds)
    setJobId(result.job_id)
  }

  const progress = status ? (status.completed / status.total) * 100 : 0

  return (
    <Dialog>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Enrich {selectedLeadIds.length} Leads</DialogTitle>
        </DialogHeader>

        {!jobId ? (
          <Button onClick={handleStart} disabled={enrichMutation.isLoading}>
            Start Enrichment
          </Button>
        ) : (
          <div>
            <ProgressBar value={progress} />
            <p className="mt-2 text-sm text-gray-600">
              {status?.completed} of {status?.total} leads enriched
            </p>
            {status?.status === 'COMPLETED' && (
              <Alert className="mt-4">
                <Check className="h-4 w-4" />
                <AlertTitle>Enrichment Complete!</AlertTitle>
                <AlertDescription>
                  Successfully enriched {status.completed} leads.
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
```

---

## Agent System

### Example 6: Real-time Agent Activity Stream

```typescript
// hooks/useAgentActivity.ts
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api-client'

interface AgentActivity {
  id: string
  agent_id: string
  agent_name: string
  action: string
  timestamp: string
  status: 'SUCCESS' | 'FAILED'
  metadata: Record<string, unknown>
}

// WebSocket connection for real-time updates
export function useAgentActivityStream() {
  const [activities, setActivities] = useState<AgentActivity[]>([])
  const [isConnected, setIsConnected] = useState(false)

  useEffect(() => {
    // Connect to WebSocket
    const ws = new WebSocket('wss://api.coreflow360.com/agents/activity')

    ws.onopen = () => {
      setIsConnected(true)
      console.log('Connected to agent activity stream')
    }

    ws.onmessage = (event) => {
      const activity = JSON.parse(event.data) as AgentActivity
      setActivities((prev) => [activity, ...prev].slice(0, 100)) // Keep last 100
    }

    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
      setIsConnected(false)
    }

    ws.onclose = () => {
      setIsConnected(false)
      console.log('Disconnected from agent activity stream')
    }

    return () => {
      ws.close()
    }
  }, [])

  return {
    activities,
    isConnected,
  }
}

// Fallback: polling if WebSocket unavailable
export function useAgentActivityPolling(intervalMs = 5000) {
  return useQuery({
    queryKey: ['agent-activity'],
    queryFn: async () => {
      const response = await apiClient.get('/api/agents/activity', {
        params: { limit: 100 },
      })
      return response.data as AgentActivity[]
    },
    refetchInterval: intervalMs,
  })
}

// Component
export function AgentActivityFeed() {
  const { activities, isConnected } = useAgentActivityStream()

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <div className={`h-2 w-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-gray-400'}`} />
        <span className="text-sm text-gray-600">
          {isConnected ? 'Live' : 'Disconnected'}
        </span>
      </div>

      <div className="space-y-2">
        {activities.map((activity) => (
          <div
            key={activity.id}
            className="rounded-lg border p-3 animate-fade-in"
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="font-medium">{activity.agent_name}</p>
                <p className="text-sm text-gray-600">{activity.action}</p>
              </div>
              <Badge variant={activity.status === 'SUCCESS' ? 'success' : 'error'}>
                {activity.status}
              </Badge>
            </div>
            <p className="mt-1 text-xs text-gray-500">
              {formatDistanceToNow(new Date(activity.timestamp))} ago
            </p>
          </div>
        ))}
      </div>
    </div>
  )
}
```

---

## Advanced Patterns

### Pattern 7: Infinite Scroll with React Query

```typescript
// hooks/useInfiniteScroll.ts
import { useInfiniteQuery } from '@tanstack/react-query'
import { useInView } from 'react-intersection-observer'
import { useEffect } from 'react'

export function useInfiniteScroll<T>(
  queryKey: unknown[],
  fetchFn: (params: { page: number; page_size: number }) => Promise<{
    items: T[]
    next_page: number | null
  }>,
  options?: {
    pageSize?: number
  }
) {
  const { ref, inView } = useInView()
  const pageSize = options?.pageSize ?? 20

  const query = useInfiniteQuery({
    queryKey,
    queryFn: ({ pageParam = 1 }) =>
      fetchFn({ page: pageParam, page_size: pageSize }),
    getNextPageParam: (lastPage) => lastPage.next_page,
  })

  // Auto-fetch next page when sentinel is in view
  useEffect(() => {
    if (inView && query.hasNextPage && !query.isFetchingNextPage) {
      query.fetchNextPage()
    }
  }, [inView, query])

  const allItems = query.data?.pages.flatMap((page) => page.items) ?? []

  return {
    ...query,
    items: allItems,
    sentinelRef: ref, // Attach to element at bottom of list
  }
}

// Usage:
export function AuditLogInfiniteList() {
  const { items, isLoading, isFetchingNextPage, sentinelRef } = useInfiniteScroll(
    ['audit-log'],
    fetchAuditLog
  )

  return (
    <div className="space-y-2">
      {items.map((item) => (
        <AuditLogItem key={item.id} item={item} />
      ))}

      {/* Sentinel element triggers loading next page */}
      <div ref={sentinelRef} className="h-10">
        {isFetchingNextPage && <Spinner />}
      </div>
    </div>
  )
}
```

---

### Pattern 8: File Upload with Progress

```typescript
// services/upload.service.ts
export async function uploadFile(
  file: File,
  onProgress?: (progress: number) => void
) {
  const formData = new FormData()
  formData.append('file', file)

  return apiClient.post('/api/files/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      const progress = progressEvent.total
        ? (progressEvent.loaded / progressEvent.total) * 100
        : 0
      onProgress?.(progress)
    },
  })
}

// Hook
export function useFileUpload() {
  const [progress, setProgress] = useState(0)

  const mutation = useMutation({
    mutationFn: (file: File) => uploadFile(file, setProgress),
    onSuccess: () => {
      toast.success('File uploaded successfully')
      setProgress(0)
    },
    onError: () => {
      toast.error('File upload failed')
      setProgress(0)
    },
  })

  return {
    upload: mutation.mutate,
    isUploading: mutation.isLoading,
    progress,
  }
}

// Component
export function FileUploader() {
  const { upload, isUploading, progress } = useFileUpload()

  const handleDrop = (files: File[]) => {
    files.forEach((file) => upload(file))
  }

  return (
    <Dropzone onDrop={handleDrop} disabled={isUploading}>
      {isUploading ? (
        <div className="space-y-2">
          <ProgressBar value={progress} />
          <p className="text-sm">Uploading... {Math.round(progress)}%</p>
        </div>
      ) : (
        <p>Drop files here or click to upload</p>
      )}
    </Dropzone>
  )
}
```

---

### Pattern 9: Debounced Search

```typescript
// hooks/useDebouncedSearch.ts
import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'

export function useDebouncedSearch<T>(
  searchFn: (query: string) => Promise<T[]>,
  options?: {
    debounceMs?: number
    minQueryLength?: number
  }
) {
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')

  const debounceMs = options?.debounceMs ?? 300
  const minLength = options?.minQueryLength ?? 2

  // Debounce logic
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query)
    }, debounceMs)

    return () => clearTimeout(timer)
  }, [query, debounceMs])

  const searchQuery = useQuery({
    queryKey: ['search', debouncedQuery],
    queryFn: () => searchFn(debouncedQuery),
    enabled: debouncedQuery.length >= minLength,
  })

  return {
    query,
    setQuery,
    results: searchQuery.data ?? [],
    isSearching: searchQuery.isFetching,
  }
}

// Usage:
export function SearchableLeadPicker() {
  const { query, setQuery, results, isSearching } = useDebouncedSearch(
    (query) => crmService.searchLeads({ search: query }),
    { debounceMs: 300, minQueryLength: 2 }
  )

  return (
    <div>
      <Input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search leads..."
      />

      {isSearching && <Spinner className="mt-2" />}

      <ul className="mt-2 space-y-1">
        {results.map((lead) => (
          <li key={lead.id}>
            <button onClick={() => handleSelect(lead)}>
              {lead.name}
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}
```

---

## Quick Reference

### HTTP Methods
- **GET** - Fetch data (list, detail)
- **POST** - Create new resource
- **PUT** - Update entire resource
- **PATCH** - Update partial resource
- **DELETE** - Delete resource

### Common Status Codes
- **200** - OK (successful GET, PUT, PATCH)
- **201** - Created (successful POST)
- **204** - No Content (successful DELETE)
- **400** - Bad Request (validation error)
- **401** - Unauthorized (missing/invalid auth)
- **403** - Forbidden (insufficient permissions)
- **404** - Not Found
- **500** - Server Error

### Error Handling Pattern

```typescript
try {
  const result = await apiCall()
  // Success
} catch (error) {
  if (error.response?.status === 401) {
    // Redirect to login
    router.push('/login')
  } else if (error.response?.status === 403) {
    // Show permission denied
    toast.error('You don't have permission to perform this action')
  } else if (error.response?.status === 400) {
    // Show validation errors
    toast.error(error.response.data.message)
  } else {
    // Generic error
    toast.error('Something went wrong. Please try again.')
  }
}
```

---

**API Integration Cookbook Complete** ✅

**Next Steps**:
1. Copy relevant patterns into your feature implementation
2. Adapt schemas to match your specific API responses
3. Add feature-specific business logic
4. Test error scenarios

**Questions?** Check `audit/backend-routes.md` for complete API documentation.

