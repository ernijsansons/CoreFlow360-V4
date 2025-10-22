# Developer Quick Start Guide - Backend-to-UI Integration

**Created**: 2025-10-22
**Purpose**: Get developers productive on Day 1 of Sprint 34
**Audience**: Frontend engineers joining the integration project

---

## Welcome! 🚀

You're joining the backend-to-UI integration project that will unlock $2M+ in hidden product value. This guide will get you productive in **30 minutes**.

---

## What You're Building

We're building UIs for **50% of backend features** that currently have no user interface. You'll be working on:

- **Sprint 34-35** (Your first 2 weeks): Compliance Guidelines Management
- **Next 6-8 sprints**: 20 features across Compliance, Finance, CRM, Agents, Workflow

---

## Quick Setup (30 Minutes)

### 1. Clone & Install (5 min)

```bash
# Clone repository (if not already)
git clone https://github.com/your-org/coreflow360-v4.git
cd coreflow360-v4

# Verify Node.js version
node --version  # Must be 20.0.0+

# Install dependencies
npm ci

# Install frontend dependencies
cd frontend && npm ci && cd ..
```

### 2. Environment Setup (5 min)

```bash
# Copy environment template
cp .env.example .env.local

# Set required variables (ask team lead for actual values)
ANTHROPIC_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
JWT_SECRET=your_secret_here
```

### 3. Database Setup (5 min)

```bash
# Run local D1 migrations
wrangler d1 migrations apply coreflow360-main --local

# Seed database with test data (optional)
npm run db:seed
```

### 4. Start Development Server (5 min)

```bash
# Terminal 1: Backend (Cloudflare Workers)
npm run dev

# Terminal 2: Frontend (Vite)
cd frontend && npm run dev
```

**Access**: http://localhost:5173

### 5. Verify Setup (10 min)

```bash
# Run type check
npm run type-check

# Run tests
npm test

# Check linting
npm run lint
```

✅ **You're ready!** If all commands passed, proceed to "Your First Task" below.

---

## Project Structure Overview

```
CoreFlow360-V4/
├── src/                          # Backend (Cloudflare Workers)
│   ├── modules/                  # Business logic modules
│   │   ├── compliance/          # ← Compliance backend (Sprint 34)
│   │   ├── finance/             # Finance backend
│   │   ├── crm/                 # CRM backend
│   │   └── agents/              # AI agents
│   ├── routes/                   # API endpoints
│   │   ├── admin/               # Admin routes
│   │   │   └── compliance-admin.ts  # ← Your Sprint 34 APIs
│   │   └── finance/             # Finance routes
│   └── shared/                   # Shared utilities
│
├── frontend/                     # React Frontend
│   ├── src/
│   │   ├── pages/               # Page components
│   │   │   └── admin/           # Admin pages
│   │   │       └── compliance/  # ← You'll create this
│   │   ├── components/          # Reusable components
│   │   │   ├── ui/              # UI primitives (buttons, inputs)
│   │   │   └── layout/          # Layout components
│   │   ├── services/            # API client services
│   │   │   └── compliance.service.ts  # ← Create this
│   │   ├── hooks/               # Custom React hooks
│   │   │   └── useCompliance.ts       # ← Create this
│   │   ├── stores/              # Zustand state stores
│   │   └── lib/                 # Utilities
│   │
├── audit/                        # ← THIS IS YOUR GUIDE
│   ├── user-stories.md          # Detailed requirements
│   ├── e2e-test-plan.md         # Test specifications
│   ├── github-issues-template.md # Issue tickets
│   └── component-library-audit.md # UI components needed
│
└── database/
    └── migrations/               # Database schema
```

---

## Your First Task: Compliance Guidelines Page

**Ticket**: Issue #1 - Compliance Guidelines Management
**Story Points**: 8
**Timeline**: 5-8 days
**Pair**: You + Sarah (frontend lead)

### What You're Building

A page where admins can create, edit, and manage compliance guidelines.

**Visual**: [See mockups in Figma - link TBD]

**Key Features**:
- Table with pagination (20 guidelines per page)
- Search and filter (by category, severity)
- Create/Edit modal with form validation
- Delete with confirmation
- Real-time table updates after changes

---

## Step-by-Step Implementation

### Day 1 Morning: API Integration (2-3 hours)

#### 1. Create API Service

Create `frontend/src/services/compliance.service.ts`:

```typescript
import { apiClient } from '@/lib/api-client'
import { z } from 'zod'

// Schema matching backend
const guidelineSchema = z.object({
  id: z.string().uuid(),
  business_id: z.string().uuid(),
  title: z.string().min(1).max(200),
  description: z.string().max(5000),
  category: z.enum(['POLICY', 'PROCEDURE', 'STANDARD', 'REGULATION']),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  effective_date: z.string().datetime(),
  created_at: z.string().datetime(),
  created_by: z.string().uuid(),
})

export type Guideline = z.infer<typeof guidelineSchema>

const listSchema = z.object({
  items: z.array(guidelineSchema),
  total: z.number(),
  page: z.number(),
  page_size: z.number(),
})

export const complianceService = {
  // List guidelines with pagination
  async listGuidelines(params: {
    page?: number
    page_size?: number
    category?: string
    severity?: string
    search?: string
  }) {
    const response = await apiClient.get('/api/compliance/guidelines', {
      params,
    })
    return listSchema.parse(response.data)
  },

  // Get single guideline
  async getGuideline(id: string) {
    const response = await apiClient.get(`/api/compliance/guidelines/${id}`)
    return guidelineSchema.parse(response.data)
  },

  // Create guideline
  async createGuideline(data: Omit<Guideline, 'id' | 'created_at' | 'created_by' | 'business_id'>) {
    const response = await apiClient.post('/api/compliance/guidelines', data)
    return guidelineSchema.parse(response.data)
  },

  // Update guideline
  async updateGuideline(id: string, data: Partial<Guideline>) {
    const response = await apiClient.put(`/api/compliance/guidelines/${id}`, data)
    return guidelineSchema.parse(response.data)
  },

  // Delete guideline
  async deleteGuideline(id: string) {
    await apiClient.delete(`/api/compliance/guidelines/${id}`)
  },
}
```

**Key Points**:
- ✅ Use Zod for runtime validation (matches backend schema)
- ✅ Export TypeScript types from Zod schemas
- ✅ Use existing `apiClient` (handles auth, errors)
- ✅ Keep service thin - just API calls, no business logic

---

#### 2. Create React Query Hooks

Create `frontend/src/hooks/useCompliance.ts`:

```typescript
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { complianceService, type Guideline } from '@/services/compliance.service'
import { toast } from '@/components/ui/toast'

// Query keys for caching
export const complianceKeys = {
  all: ['compliance'] as const,
  guidelines: () => [...complianceKeys.all, 'guidelines'] as const,
  guidelinesList: (filters: Record<string, unknown>) =>
    [...complianceKeys.guidelines(), 'list', filters] as const,
  guideline: (id: string) => [...complianceKeys.guidelines(), 'detail', id] as const,
}

// List guidelines with filters
export function useGuidelines(params: Parameters<typeof complianceService.listGuidelines>[0]) {
  return useQuery({
    queryKey: complianceKeys.guidelinesList(params),
    queryFn: () => complianceService.listGuidelines(params),
    staleTime: 5 * 60 * 1000, // 5 minutes
  })
}

// Get single guideline
export function useGuideline(id: string) {
  return useQuery({
    queryKey: complianceKeys.guideline(id),
    queryFn: () => complianceService.getGuideline(id),
    enabled: !!id,
  })
}

// Create guideline mutation
export function useCreateGuideline() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: complianceService.createGuideline,
    onSuccess: () => {
      // Invalidate and refetch
      queryClient.invalidateQueries({ queryKey: complianceKeys.guidelines() })
      toast.success('Guideline created successfully')
    },
    onError: (error) => {
      toast.error('Failed to create guideline', {
        description: error.message,
      })
    },
  })
}

// Update guideline mutation
export function useUpdateGuideline() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Guideline> }) =>
      complianceService.updateGuideline(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: complianceKeys.guideline(variables.id) })
      queryClient.invalidateQueries({ queryKey: complianceKeys.guidelines() })
      toast.success('Guideline updated successfully')
    },
    onError: (error) => {
      toast.error('Failed to update guideline', {
        description: error.message,
      })
    },
  })
}

// Delete guideline mutation
export function useDeleteGuideline() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: complianceService.deleteGuideline,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: complianceKeys.guidelines() })
      toast.success('Guideline deleted successfully')
    },
    onError: (error) => {
      toast.error('Failed to delete guideline', {
        description: error.message,
      })
    },
  })
}
```

**Key Points**:
- ✅ Use React Query for caching and state management
- ✅ Centralized query keys for cache invalidation
- ✅ Optimistic updates with invalidation
- ✅ Toast notifications for user feedback
- ✅ Error handling built-in

---

### Day 1 Afternoon: Page Structure (3-4 hours)

#### 3. Create Page Component

Create `frontend/src/pages/admin/compliance/GuidelinesPage.tsx`:

```typescript
import { useState } from 'react'
import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useGuidelines } from '@/hooks/useCompliance'
import { GuidelinesTable } from './GuidelinesTable'
import { GuidelinesToolbar } from './GuidelinesToolbar'
import { GuidelineModal } from './GuidelineModal'
import type { Guideline } from '@/services/compliance.service'

export function GuidelinesPage() {
  // State
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [search, setSearch] = useState('')
  const [categoryFilter, setCategoryFilter] = useState<string>()
  const [severityFilter, setSeverityFilter] = useState<string>()
  const [modalOpen, setModalOpen] = useState(false)
  const [editingGuideline, setEditingGuideline] = useState<Guideline | null>(null)

  // Data
  const { data, isLoading, error } = useGuidelines({
    page,
    page_size: pageSize,
    search,
    category: categoryFilter,
    severity: severityFilter,
  })

  // Handlers
  const handleCreate = () => {
    setEditingGuideline(null)
    setModalOpen(true)
  }

  const handleEdit = (guideline: Guideline) => {
    setEditingGuideline(guideline)
    setModalOpen(true)
  }

  const handleModalClose = () => {
    setModalOpen(false)
    setEditingGuideline(null)
  }

  return (
    <div className="flex h-full flex-col">
      {/* Page Header */}
      <div className="border-b border-gray-200 px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-gray-900">
              Compliance Guidelines
            </h1>
            <p className="mt-1 text-sm text-gray-500">
              Manage organizational compliance requirements
            </p>
          </div>
          <Button onClick={handleCreate}>
            <Plus className="mr-2 h-4 w-4" />
            Create Guideline
          </Button>
        </div>
      </div>

      {/* Toolbar (Search + Filters) */}
      <GuidelinesToolbar
        search={search}
        onSearchChange={setSearch}
        categoryFilter={categoryFilter}
        onCategoryChange={setCategoryFilter}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
      />

      {/* Table */}
      <div className="flex-1 overflow-auto px-6 py-4">
        <GuidelinesTable
          data={data?.items ?? []}
          total={data?.total ?? 0}
          page={page}
          pageSize={pageSize}
          isLoading={isLoading}
          error={error}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
          onEdit={handleEdit}
        />
      </div>

      {/* Create/Edit Modal */}
      <GuidelineModal
        open={modalOpen}
        guideline={editingGuideline}
        onClose={handleModalClose}
      />
    </div>
  )
}
```

**Key Points**:
- ✅ Container component (smart) - manages state and data
- ✅ Delegates rendering to child components (dumb)
- ✅ Use hooks for data fetching
- ✅ Clear separation of concerns

---

### Day 2: Build Table Component (Full Day)

#### 4. Create GuidelinesTable Component

Create `frontend/src/pages/admin/compliance/GuidelinesTable.tsx`:

```typescript
import { useMemo } from 'react'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import { MoreHorizontal, Pencil, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { DataTable } from '@/components/ui/data-table'
import { Pagination } from '@/components/ui/pagination'
import { useDeleteGuideline } from '@/hooks/useCompliance'
import { formatDate } from '@/lib/utils'
import type { Guideline } from '@/services/compliance.service'

interface GuidelinesTableProps {
  data: Guideline[]
  total: number
  page: number
  pageSize: number
  isLoading: boolean
  error: Error | null
  onPageChange: (page: number) => void
  onPageSizeChange: (pageSize: number) => void
  onEdit: (guideline: Guideline) => void
}

export function GuidelinesTable({
  data,
  total,
  page,
  pageSize,
  isLoading,
  error,
  onPageChange,
  onPageSizeChange,
  onEdit,
}: GuidelinesTableProps) {
  const deleteGuideline = useDeleteGuideline()

  // Define columns
  const columns = useMemo<ColumnDef<Guideline>[]>(
    () => [
      {
        accessorKey: 'title',
        header: 'Title',
        cell: ({ row }) => (
          <div className="max-w-md">
            <div className="font-medium text-gray-900">{row.original.title}</div>
            <div className="mt-1 truncate text-sm text-gray-500">
              {row.original.description}
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'category',
        header: 'Category',
        cell: ({ row }) => (
          <Badge variant="outline">{row.original.category}</Badge>
        ),
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => {
          const severityColors = {
            LOW: 'bg-gray-100 text-gray-800',
            MEDIUM: 'bg-yellow-100 text-yellow-800',
            HIGH: 'bg-orange-100 text-orange-800',
            CRITICAL: 'bg-red-100 text-red-800',
          }
          return (
            <Badge className={severityColors[row.original.severity]}>
              {row.original.severity}
            </Badge>
          )
        },
      },
      {
        accessorKey: 'effective_date',
        header: 'Effective Date',
        cell: ({ row }) => formatDate(row.original.effective_date),
      },
      {
        id: 'actions',
        cell: ({ row }) => (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => onEdit(row.original)}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-red-600"
                onClick={() => {
                  if (confirm('Are you sure you want to delete this guideline?')) {
                    deleteGuideline.mutate(row.original.id)
                  }
                }}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ),
      },
    ],
    [onEdit, deleteGuideline]
  )

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    manualPagination: true,
    pageCount: Math.ceil(total / pageSize),
  })

  if (error) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-4">
        <p className="text-sm text-red-800">Error loading guidelines: {error.message}</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <DataTable table={table} isLoading={isLoading} />

      <Pagination
        page={page}
        pageSize={pageSize}
        total={total}
        onPageChange={onPageChange}
        onPageSizeChange={onPageSizeChange}
      />
    </div>
  )
}
```

**Key Points**:
- ✅ Use TanStack Table for table functionality
- ✅ Memoize columns definition
- ✅ Color-coded severity badges
- ✅ Actions dropdown with edit/delete
- ✅ Error and loading states
- ✅ Pagination built-in

---

### Days 3-4: Build Form Modal

#### 5. Create GuidelineModal Component

[See full implementation in audit/user-stories.md - Story #1]

**Key Components**:
- React Hook Form for form state
- Zod schema for validation
- Field-level error messages
- Submit with loading state
- Cancel with confirmation if dirty

---

## Testing Your Work

### Manual Testing Checklist

Sprint 34 - Day 5, run through this checklist:

- [ ] **Create Guideline**
  - [ ] Open modal, fill form, submit
  - [ ] Verify guideline appears in table immediately
  - [ ] Verify success toast appears
  - [ ] Check browser console for errors (should be none)

- [ ] **Validation**
  - [ ] Try submitting empty form - should show errors
  - [ ] Try title > 200 characters - should show error
  - [ ] Try invalid date - should show error

- [ ] **Edit Guideline**
  - [ ] Click edit, verify form pre-fills
  - [ ] Change title, save
  - [ ] Verify table updates immediately

- [ ] **Delete Guideline**
  - [ ] Click delete, verify confirmation appears
  - [ ] Confirm, verify guideline removed from table
  - [ ] Verify success toast

- [ ] **Search & Filter**
  - [ ] Type in search, verify results filter
  - [ ] Select category filter, verify results filter
  - [ ] Select severity filter, verify results filter
  - [ ] Clear filters, verify all results return

- [ ] **Pagination**
  - [ ] If > 20 guidelines, verify pagination works
  - [ ] Change page size, verify results update
  - [ ] Navigate to page 2, then back to page 1

### Automated Testing

Run E2E tests from `audit/e2e-test-plan.md`:

```bash
# Run Playwright tests for Compliance Guidelines
npx playwright test compliance-guidelines
```

---

## Common Pitfalls & Solutions

### ❌ Problem: "Type errors in service.ts"
**Solution**: Make sure your Zod schemas exactly match the backend API response. Check `src/routes/admin/compliance-admin.ts` for the actual structure.

### ❌ Problem: "Table not refreshing after create/edit"
**Solution**: Ensure you're calling `queryClient.invalidateQueries()` in your mutations. Check `useCompliance.ts` hooks.

### ❌ Problem: "CORS errors in console"
**Solution**: Backend should already handle CORS. If not, check `src/shared/cors.ts` configuration.

### ❌ Problem: "401 Unauthorized"
**Solution**: Make sure you're logged in. Check `localStorage` for auth token. If missing, log in through `/login`.

### ❌ Problem: "Form validation not working"
**Solution**: Verify Zod schema matches form fields. Check React Hook Form `resolver` is properly connected.

---

## Code Review Checklist

Before creating PR, verify:

- [ ] **TypeScript**: No `any` types, no `@ts-ignore` comments
- [ ] **Testing**: E2E tests pass, manual testing complete
- [ ] **Accessibility**: Keyboard navigation works, ARIA labels present
- [ ] **Performance**: No unnecessary re-renders (use React DevTools)
- [ ] **Styling**: Matches Figma designs, responsive on mobile
- [ ] **Error Handling**: All API calls have error handling
- [ ] **Loading States**: Show loading indicators during async operations
- [ ] **Linting**: `npm run lint` passes with no errors

---

## Getting Help

### Quick Questions
- **Slack**: #sprint-34 channel
- **Pair Programming**: Ping Sarah or Alex

### Debugging
- **Backend Issues**: Tag Michael in Slack
- **Design Questions**: Tag Lisa in #compliance-feature
- **Blocked**: Post in #sprint-34 immediately

### Resources
- **User Story**: `audit/user-stories.md` - Story #1
- **API Docs**: `audit/backend-routes.md` - Compliance section
- **Test Plan**: `audit/e2e-test-plan.md` - Test Suite 1
- **Component Specs**: `audit/component-library-audit.md`

---

## Next Features (After Guidelines)

Once you complete Guidelines (Story #1), you'll move to:

1. **Agent Policy Management** (Story #2) - Rule builder component
2. **Compliance Violation Tracker** (Story #3) - Dashboard with charts
3. **Compliance Audit Trail** (Story #4) - Timeline component

---

## Success Criteria

You've succeeded when:

✅ Guidelines page deployed to staging
✅ All E2E tests passing
✅ Acceptance criteria met (all checkboxes in user story)
✅ Code reviewed and approved
✅ Demo-ready for Sprint Review

---

**Welcome to the team! Let's build something amazing.** 🚀

**Questions?** Post in #sprint-34 or DM your tech lead.

