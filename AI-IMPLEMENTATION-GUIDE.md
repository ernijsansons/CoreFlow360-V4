# AI Agent Implementation Guide
## Systematic Development Plan for Autonomous AI Execution

**Purpose:** This guide enables AI agents to autonomously implement all 8 critical features with complete backend + frontend + tests.

**Status:** Feature 1 (Account Reconciliation) - 60% complete
- ✅ Database schema created
- ✅ Backend services implemented
- ✅ API routes created
- ✅ ReconciliationDashboard component created
- ⏳ Remaining frontend components needed
- ⏳ Tests needed

---

## 🤖 AI Agent Logic & Capabilities

### What AI Can Do Autonomously

1. **Create Database Schemas** ✅
   - Write SQL migrations
   - Create tables, indexes, foreign keys
   - Sample data for testing

2. **Implement Backend Services** ✅
   - TypeScript service classes
   - Business logic implementation
   - Algorithm implementations (matching, scoring)
   - Database queries

3. **Create API Endpoints** ✅
   - Hono route definitions
   - Request validation
   - Error handling
   - Response formatting

4. **Build Frontend Components** ✅
   - React components with TypeScript
   - TanStack Query hooks
   - Form handling
   - State management

5. **Write Tests** ✅
   - Unit tests (Vitest)
   - Integration tests
   - Component tests
   - E2E test specs

6. **Create Documentation** ✅
   - API documentation
   - Component documentation
   - Usage examples

### Implementation Pattern (Per Feature)

```typescript
// Step 1: Database Schema
// File: database/migrations/03X_feature_name.sql
CREATE TABLE feature_table (...);
CREATE INDEX idx_...;

// Step 2: Backend Service
// File: src/services/feature/feature-service.ts
export class FeatureService {
  constructor(private env: Env) {}
  async createFeature(...) {}
  async getFeature(...) {}
}

// Step 3: API Routes
// File: src/routes/feature.ts
const feature = new Hono<{ Bindings: Env }>();
feature.post('/', async (c) => { /* implementation */ });
feature.get('/:id', async (c) => { /* implementation */ });

// Step 4: Frontend Service
// File: frontend/src/lib/api/services/feature.service.ts
export const featureService = {
  create: (data) => apiClient.post('/api/v1/feature', { json: data }),
  get: (id) => apiClient.get(`/api/v1/feature/${id}`),
};

// Step 5: Frontend Components
// File: frontend/src/components/feature/FeatureComponent.tsx
export function FeatureComponent() {
  const { data, isLoading } = useQuery({
    queryKey: ['feature'],
    queryFn: () => featureService.get(id),
  });
  return <div>...</div>;
}

// Step 6: Page Route
// File: frontend/src/routes/feature/index.tsx
export const Route = createFileRoute('/feature/')({
  component: FeaturePage,
});

// Step 7: Tests
// File: src/services/feature/feature-service.test.ts
describe('FeatureService', () => {
  test('should create feature', async () => { /* test */ });
});
```

---

## 📋 Feature 1: Account Reconciliation - Completion Tasks

### Remaining Components to Create

#### 1. Statement Uploader Component
**File:** `frontend/src/components/reconciliation/StatementUploader.tsx`

```typescript
/**
 * Statement Uploader Component
 * Upload CSV/OFX/QFX bank statements
 */

import { useState, useRef } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Upload, FileText, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { apiClient } from '@/lib/api/client';

export function StatementUploader({ reconciliationId, onSuccess }: {
  reconciliationId: string;
  onSuccess?: (result: any) => void;
}) {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append('file', file);

      const response = await apiClient.post(
        `/api/v1/reconciliation/${reconciliationId}/upload-statement`,
        { body: formData }
      );

      if (!response.ok) throw new Error('Upload failed');
      return response.json();
    },
    onSuccess: (data) => {
      const event = new CustomEvent('show-toast', {
        detail: { message: `${data.data.imported_count} transactions imported`, type: 'success' }
      });
      window.dispatchEvent(event);
      if (onSuccess) onSuccess(data);
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) uploadMutation.mutate(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) uploadMutation.mutate(file);
  };

  return (
    <Card className="p-8">
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={(e) => { e.preventDefault(); setIsDragging(false); }}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
          isDragging ? 'border-brand-primary bg-brand-primary/5' : 'border-gray-300 hover:border-brand-primary'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".csv,.ofx,.qfx"
          onChange={handleFileChange}
          className="hidden"
        />

        {uploadMutation.isPending ? (
          <div className="flex flex-col items-center">
            <Loader2 className="w-12 h-12 text-brand-primary animate-spin mb-4" />
            <p className="text-lg font-semibold">Uploading statement...</p>
          </div>
        ) : (
          <div className="flex flex-col items-center">
            <Upload className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-lg font-semibold mb-2">Upload Bank Statement</p>
            <p className="text-sm text-muted-foreground">Drag & drop or click to browse</p>
            <p className="text-xs text-muted-foreground mt-2">Supported: CSV, OFX, QFX</p>
          </div>
        )}
      </div>

      {uploadMutation.isError && (
        <div className="mt-4 p-4 bg-destructive/10 border border-destructive rounded-lg flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-destructive" />
          <p className="text-sm text-destructive">Upload failed. Please try again.</p>
        </div>
      )}

      {uploadMutation.isSuccess && (
        <div className="mt-4 p-4 bg-green-100 dark:bg-green-900/20 border border-green-600 rounded-lg flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400" />
          <p className="text-sm text-green-600 dark:text-green-400">
            Statement uploaded successfully!
          </p>
        </div>
      )}
    </Card>
  );
}
```

#### 2. Transaction Matcher Component
**File:** `frontend/src/components/reconciliation/TransactionMatcher.tsx`

```typescript
/**
 * Transaction Matcher Component
 * Match statement transactions with book transactions
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { CheckCircle2, Sparkles, TrendingUp } from 'lucide-react';
import { apiClient } from '@/lib/api/client';

export function TransactionMatcher({ reconciliationId }: { reconciliationId: string }) {
  const queryClient = useQueryClient();

  const { data } = useQuery({
    queryKey: ['reconciliation-transactions', reconciliationId],
    queryFn: async () => {
      const response = await apiClient.get(`/api/v1/reconciliation/${reconciliationId}/transactions`);
      return response.json();
    },
  });

  const autoMatchMutation = useMutation({
    mutationFn: async () => {
      const response = await apiClient.post(`/api/v1/reconciliation/${reconciliationId}/auto-match`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reconciliation-transactions', reconciliationId] });
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Auto-matching completed', type: 'success' }
      });
      window.dispatchEvent(event);
    },
  });

  const transactions = data?.data?.statement_transactions || [];
  const unmatchedCount = transactions.filter((t: any) => !t.matched).length;

  return (
    <Card className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold">Transaction Matching</h2>
        <Button
          onClick={() => autoMatchMutation.mutate()}
          disabled={autoMatchMutation.isPending}
        >
          <Sparkles className="w-4 h-4 mr-2" />
          Auto-Match
        </Button>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="p-4 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
          <p className="text-sm text-muted-foreground">Total Transactions</p>
          <p className="text-2xl font-bold">{transactions.length}</p>
        </div>
        <div className="p-4 bg-green-100 dark:bg-green-900/20 rounded-lg">
          <p className="text-sm text-muted-foreground">Matched</p>
          <p className="text-2xl font-bold text-green-600 dark:text-green-400">
            {transactions.length - unmatchedCount}
          </p>
        </div>
        <div className="p-4 bg-orange-100 dark:bg-orange-900/20 rounded-lg">
          <p className="text-sm text-muted-foreground">Unmatched</p>
          <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">
            {unmatchedCount}
          </p>
        </div>
      </div>

      {/* Transaction list would go here */}
      {/* Implement transaction table with match actions */}
    </Card>
  );
}
```

#### 3. Reconciliation Page Route
**File:** `frontend/src/routes/finance/reconciliation.tsx`

```typescript
import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { ReconciliationDashboard } from '@/components/reconciliation/ReconciliationDashboard';

export const Route = createFileRoute('/finance/reconciliation')({
  component: ReconciliationPage,
});

function ReconciliationPage() {
  return (
    <MainLayout>
      <ReconciliationDashboard />
    </MainLayout>
  );
}
```

---

## 🚀 Systematic Implementation for Remaining Features

### Feature 2: Plaid Bank Integration

**Files to Create (in order):**

1. **Database Migration**
   - `database/migrations/032_plaid_integration.sql`
   - Tables: plaid_connections, plaid_accounts, plaid_sync_log

2. **Backend Service**
   - `src/services/plaid/plaid-client.ts`
   - `src/services/plaid/plaid-sync-service.ts`
   - Functions: createLinkToken(), exchangePublicToken(), syncTransactions()

3. **API Routes**
   - `src/routes/plaid.ts`
   - Endpoints: POST /create-link-token, POST /exchange-public-token, GET /connections

4. **Frontend Components**
   - `frontend/src/components/plaid/PlaidLink.tsx`
   - `frontend/src/components/plaid/BankConnectionList.tsx`
   - `frontend/src/routes/finance/banking/connections.tsx`

5. **Integration**
   - Add `import plaidRoutes from './plaid'` to `src/routes/index.ts`
   - Add `v1.route('/plaid', plaidRoutes)` to routes

---

### Feature 3: Multi-Currency Accounting

**Files to Create:**

1. **Database Migration**
   - `database/migrations/033_multi_currency.sql`
   - Tables: currencies, exchange_rates, multi_currency_transactions, currency_gain_loss

2. **Backend Services**
   - `src/services/currency/exchange-rate-service.ts`
   - `src/services/currency/currency-converter.ts`
   - `src/services/currency/gain-loss-calculator.ts`

3. **API Routes**
   - `src/routes/currency.ts`
   - Endpoints: GET /currencies, GET /rates, POST /convert

4. **Frontend Components**
   - `frontend/src/components/currency/CurrencySelector.tsx`
   - `frontend/src/components/currency/ExchangeRateDisplay.tsx`
   - `frontend/src/routes/finance/currency.tsx`

---

### Feature 4: Subscription Billing

**Files to Create:**

1. **Database Migration**
   - `database/migrations/034_subscription_billing.sql`
   - Tables: subscription_plans, subscriptions, subscription_items, subscription_invoices

2. **Backend Services**
   - `src/services/subscriptions/subscription-service.ts`
   - `src/services/subscriptions/billing-scheduler.ts`
   - `src/services/subscriptions/mrr-calculator.ts`

3. **API Routes**
   - `src/routes/subscriptions.ts`

4. **Frontend Components**
   - `frontend/src/components/subscriptions/SubscriptionPlanList.tsx`
   - `frontend/src/components/subscriptions/MRRDashboard.tsx`

---

### Feature 5: Revenue Recognition

**Files to Create:**

1. **Database Migration**
   - `database/migrations/035_revenue_recognition.sql`
   - Tables: revenue_contracts, performance_obligations, revenue_schedule

2. **Backend Services**
   - `src/services/revenue/revenue-recognition-service.ts`
   - `src/services/revenue/contract-manager.ts`

3. **API Routes**
   - `src/routes/revenue-recognition.ts`

4. **Frontend Components**
   - `frontend/src/components/revenue/ContractList.tsx`
   - `frontend/src/components/revenue/RevenueWaterfall.tsx`

---

## ✅ Testing Checklist (Per Feature)

### 1. Unit Tests
```bash
# Create test file
touch src/services/feature/feature-service.test.ts

# Template:
import { describe, test, expect } from 'vitest';
import { FeatureService } from './feature-service';

describe('FeatureService', () => {
  test('should create feature', async () => {
    // Arrange
    const mockEnv = { DB: mockDatabase };
    const service = new FeatureService(mockEnv);

    // Act
    const result = await service.createFeature(...);

    // Assert
    expect(result).toBeDefined();
  });
});
```

### 2. Integration Tests
- Test API endpoints with real database
- Test service layer with database
- Test external API integrations (mocked)

### 3. E2E Tests
- Test complete user workflows
- Test error handling
- Test edge cases

### 4. Manual QA
- Test UI in browser
- Test mobile responsiveness
- Test dark mode
- Test accessibility

---

## 📝 Implementation Checklist Template

For each feature, follow this checklist:

```markdown
## Feature X: [Name]

### Backend (3-5 days)
- [ ] Create database migration
- [ ] Implement service layer
- [ ] Write unit tests for services
- [ ] Create API routes
- [ ] Test API endpoints
- [ ] Integrate into main API

### Frontend (4-5 days)
- [ ] Create API service
- [ ] Build main dashboard component
- [ ] Build detail/form components
- [ ] Create page routes
- [ ] Write component tests
- [ ] Test in browser

### Testing & Documentation (1-2 days)
- [ ] Write E2E tests
- [ ] Manual QA
- [ ] API documentation
- [ ] User guide
- [ ] Deploy to staging
- [ ] Production deployment

### Acceptance Criteria
- [ ] All unit tests passing (95%+ coverage)
- [ ] All E2E tests passing
- [ ] API response time <200ms P95
- [ ] UI loads in <3s
- [ ] No console errors
- [ ] Accessibility score 100/100
- [ ] Works on mobile
- [ ] Dark mode working
```

---

## 🎯 Next Steps for AI Agent

To continue implementation:

1. **Complete Feature 1** (2-3 hours)
   - Create StatementUploader component
   - Create TransactionMatcher component
   - Create Reconciliation page route
   - Write tests

2. **Start Feature 2: Plaid Integration** (8 hours)
   - Follow systematic pattern above
   - Create all files in order
   - Test each component

3. **Continue with Features 3-8**
   - Use same systematic approach
   - Each feature takes 8-12 hours
   - Total remaining time: 60-90 hours

---

## 💡 Key Principles for AI Implementation

1. **Always create files in order:**
   - Database schema first
   - Backend services second
   - API routes third
   - Frontend components last

2. **Test as you go:**
   - Write tests immediately after implementation
   - Don't wait until the end

3. **Follow existing patterns:**
   - Copy structure from Feature 1
   - Maintain consistency
   - Reuse components where possible

4. **Document everything:**
   - Add JSDoc comments
   - Create README files
   - Update API documentation

5. **Handle errors gracefully:**
   - Always include try/catch
   - Provide helpful error messages
   - Log errors for debugging

---

**AI Agent Status:** Ready to autonomously implement all remaining features following this systematic guide.

**Estimated Completion:** 60-90 hours for Features 2-8
**Current Progress:** Feature 1 = 60% complete

---

*This guide enables any AI agent (Claude, GPT-4, etc.) to continue implementation autonomously with complete context and patterns.*
