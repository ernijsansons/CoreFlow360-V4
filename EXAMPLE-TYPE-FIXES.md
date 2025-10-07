# Example Type Fixes - Before & After

This document shows concrete examples of fixing `any` types and other ESLint warnings.
Use these patterns when fixing the remaining 785 warnings.

## Example 1: MessageRenderer Component

### BEFORE (15+ any types)

```typescript
// src/components/chat/MessageRenderer.tsx

import { oneLight } from 'react-syntax-highlighter/dist/esm/styles/prism'  // ❌ UNUSED
import { Download } from 'lucide-react'  // ❌ UNUSED

// ❌ BAD: any type for data prop
const InvoiceRenderer: React.FC<{ data: any }> = ({ data }) => (
  <div>
    <h4>Invoice {data.number}</h4>
    <Badge variant={data.status === 'paid' ? 'default' : 'secondary'}>
      {data.status}
    </Badge>
    <span>{data.customer}</span>
    <span>${data.amount.toLocaleString()}</span>
  </div>
)

// ❌ BAD: any type for data prop
const MetricRenderer: React.FC<{ data: any }> = ({ data }) => (
  <div>
    {data.metrics.map((metric: any, index: number) => (  // ❌ BAD: any in map
      <div key={index}>
        <div>{metric.value}</div>
        <div>{metric.label}</div>
        {metric.change && (
          <div>{metric.change > 0 ? '+' : ''}{metric.change}%</div>
        )}
      </div>
    ))}
  </div>
)

const components = {
  ul: ({ children }: any) => <ListRenderer>{children}</ListRenderer>,  // ❌ BAD
  ol: ({ children }: any) => <ListRenderer ordered>{children}</ListRenderer>,  // ❌ BAD
  h1: ({ children }: any) => <HeadingRenderer level={1}>{children}</HeadingRenderer>,  // ❌ BAD
  // ... more any types
}
```

### AFTER (0 any types)

```typescript
// src/components/chat/MessageRenderer.tsx

// ✅ GOOD: Remove unused imports (auto-fixed by lint:fix)
// import { oneLight } from ... // REMOVED
// import { Download } from ... // REMOVED

// ✅ GOOD: Import proper types
import type { InvoiceData, MetricsData, ChildrenProps } from '@/types/components'

// ✅ GOOD: Properly typed data prop
const InvoiceRenderer: React.FC<{ data: InvoiceData }> = ({ data }) => (
  <div>
    <h4>Invoice {data.number}</h4>
    <Badge variant={data.status === 'paid' ? 'default' : 'secondary'}>
      {data.status}
    </Badge>
    <span>{data.customer}</span>
    <span>${data.amount.toLocaleString()}</span>
  </div>
)

// ✅ GOOD: Properly typed data prop
const MetricRenderer: React.FC<{ data: MetricsData }> = ({ data }) => (
  <div>
    {data.metrics.map((metric, index) => (  // ✅ GOOD: type inferred from MetricsData
      <div key={index}>
        <div>{metric.value}</div>
        <div>{metric.label}</div>
        {metric.change && (
          <div>{metric.change > 0 ? '+' : ''}{metric.change}%</div>
        )}
      </div>
    ))}
  </div>
)

// ✅ GOOD: Properly typed children
const components = {
  ul: ({ children }: ChildrenProps) => <ListRenderer>{children}</ListRenderer>,
  ol: ({ children }: ChildrenProps) => <ListRenderer ordered>{children}</ListRenderer>,
  h1: ({ children }: ChildrenProps) => <HeadingRenderer level={1}>{children}</HeadingRenderer>,
  // ... properly typed
}
```

**Warnings Fixed**: 15 `@typescript-eslint/no-explicit-any`, 2 `@typescript-eslint/no-unused-vars`

---

## Example 2: AIAgentInterface Component

### BEFORE (15+ unused imports)

```typescript
// src/components/ai-agents/AIAgentInterface.tsx

import React, { useState, useEffect, useCallback } from 'react';  // ❌ useEffect, useCallback unused
import { motion, AnimatePresence } from 'framer-motion';
import {
  Bot,
  Brain,
  Cpu,        // ❌ UNUSED
  MessageSquare,
  Zap,
  Play,       // ❌ UNUSED
  Pause,      // ❌ UNUSED
  Settings,
  CheckCircle,   // ❌ UNUSED
  AlertCircle,   // ❌ UNUSED
  Info,          // ❌ UNUSED
  TrendingUp,
  Activity,
  Clock,
  BarChart3,     // ❌ UNUSED
  Send,
  Mic,
  Paperclip,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Download,      // ❌ UNUSED
  Upload,        // ❌ UNUSED
  Shield,
  AlertTriangle, // ❌ UNUSED
  Command,
  Sparkles
} from 'lucide-react';

export const AIAgentInterface: React.FC = () => {
  const [selectedAgent, setSelectedAgent] = useState<AIAgent | null>(null);
  const [activeConversation, setActiveConversation] = useState<Conversation | null>(null);  // ❌ UNUSED
  const [message, setMessage] = useState('');
  // ... component code that doesn't use many of the imports
}
```

### AFTER (0 unused imports)

```typescript
// src/components/ai-agents/AIAgentInterface.tsx

// ✅ GOOD: Only import what you use
import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Bot,
  Brain,
  MessageSquare,
  Zap,
  Settings,
  TrendingUp,
  Activity,
  Clock,
  Send,
  Mic,
  Paperclip,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Shield,
  Command,
  Sparkles
} from 'lucide-react'

export const AIAgentInterface: React.FC = () => {
  const [selectedAgent, setSelectedAgent] = useState<AIAgent | null>(null)
  const [message, setMessage] = useState('')
  // ✅ GOOD: Removed unused activeConversation state
  // ... component code
}
```

**Warnings Fixed**: 15 `@typescript-eslint/no-unused-vars`

---

## Example 3: Badge Component (React Refresh Violation)

### BEFORE (react-refresh warning)

```typescript
// @/components/ui/badge.tsx

import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs...",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary...",
        secondary: "border-transparent bg-secondary...",
        // ... more variants
      },
    },
    defaultVariants: { variant: "default" },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

// ❌ BAD: Exporting non-component (badgeVariants) with component
export { Badge, badgeVariants }
```

**ESLint Error**:
```
36:17  error  Fast refresh only works when a file only exports components.
               Use a new file to share constants or functions between components
               react-refresh/only-export-components
```

### AFTER (0 warnings)

**Step 1**: Create directory structure

```bash
mkdir -p @/components/ui/badge
```

**Step 2**: Split into separate files

```typescript
// @/components/ui/badge/badge-variants.ts
// ✅ GOOD: Constants in separate file

import { cva } from "class-variance-authority"

export const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs...",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary...",
        secondary: "border-transparent bg-secondary...",
        // ... more variants
      },
    },
    defaultVariants: { variant: "default" },
  }
)
```

```typescript
// @/components/ui/badge/Badge.tsx
// ✅ GOOD: Component in separate file, only exports component

import * as React from "react"
import type { VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"
import { badgeVariants } from "./badge-variants"

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}
```

```typescript
// @/components/ui/badge/index.ts
// ✅ GOOD: Barrel export file

export { Badge, type BadgeProps } from './Badge'
export { badgeVariants } from './badge-variants'
```

**Step 3**: Update imports across codebase

```typescript
// Other files that import Badge
// BEFORE:
import { Badge, badgeVariants } from '@/components/ui/badge'

// AFTER (no change needed if using index.ts):
import { Badge, badgeVariants } from '@/components/ui/badge'
```

**Warnings Fixed**: 1 `react-refresh/only-export-components`

---

## Example 4: React Hooks Dependencies

### BEFORE (exhaustive-deps warning)

```typescript
// src/components/agents/AgentDashboard.tsx

const initializeAgentSystem = () => {
  // ... initialization logic
}

const refreshAgentStatus = () => {
  // ... refresh logic
}

useEffect(() => {
  initializeAgentSystem()  // ❌ Function not in deps
  refreshAgentStatus()     // ❌ Function not in deps
}, [])  // ❌ BAD: Missing dependencies
```

**ESLint Warning**:
```
41:6  warning  React Hook useEffect has missing dependencies:
              'initializeAgentSystem' and 'refreshAgentStatus'.
              Either include them or remove the dependency array
              react-hooks/exhaustive-deps
```

### AFTER (0 warnings)

**Option 1**: Wrap functions in useCallback (if they depend on props/state)

```typescript
// ✅ GOOD: Wrap functions in useCallback
const initializeAgentSystem = useCallback(() => {
  // ... initialization logic
}, [/* dependencies */])

const refreshAgentStatus = useCallback(() => {
  // ... refresh logic
}, [/* dependencies */])

useEffect(() => {
  initializeAgentSystem()
  refreshAgentStatus()
}, [initializeAgentSystem, refreshAgentStatus])  // ✅ GOOD: All deps included
```

**Option 2**: Move functions inside useEffect (if they don't need to be external)

```typescript
// ✅ GOOD: Functions inside effect
useEffect(() => {
  const initializeAgentSystem = () => {
    // ... initialization logic
  }

  const refreshAgentStatus = () => {
    // ... refresh logic
  }

  initializeAgentSystem()
  refreshAgentStatus()
}, [])  // ✅ GOOD: No external dependencies
```

**Option 3**: Use ESLint disable (only if you know it's safe)

```typescript
// ⚠️ USE SPARINGLY: Only if you're 100% sure it's safe
useEffect(() => {
  initializeAgentSystem()
  refreshAgentStatus()
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [])
```

**Warnings Fixed**: 1 `react-hooks/exhaustive-deps`

---

## Example 5: Case Declarations

### BEFORE (no-case-declarations error)

```typescript
// src/components/dashboard/widgets/DataTable.tsx

switch (sortType) {
  case 'string':
    const stringCompare = (a: string, b: string) => a.localeCompare(b)  // ❌ BAD
    result = stringCompare(valA, valB)
    break
  case 'number':
    const numCompare = (a: number, b: number) => a - b  // ❌ BAD
    result = numCompare(valA, valB)
    break
}
```

**ESLint Error**:
```
94:7  error  Unexpected lexical declaration in case block  no-case-declarations
```

### AFTER (0 errors)

```typescript
// ✅ GOOD: Wrap case blocks in braces
switch (sortType) {
  case 'string': {
    const stringCompare = (a: string, b: string) => a.localeCompare(b)
    result = stringCompare(valA, valB)
    break
  }
  case 'number': {
    const numCompare = (a: number, b: number) => a - b
    result = numCompare(valA, valB)
    break
  }
}
```

**Warnings Fixed**: 2 `no-case-declarations`

---

## Example 6: Require Imports

### BEFORE (no-require-imports error)

```typescript
// src/__tests__/critical-paths.test.tsx

test('some test', () => {
  const mockModule = require('./mock-data')  // ❌ BAD: require in ESM
  // ... test code
})
```

**ESLint Error**:
```
312:15  error  A `require()` style import is forbidden  @typescript-eslint/no-require-imports
```

### AFTER (0 errors)

```typescript
// ✅ GOOD: Use import instead
import mockModule from './mock-data'

test('some test', () => {
  // ... test code using mockModule
})
```

**Or if dynamic import needed**:

```typescript
// ✅ GOOD: Use dynamic import
test('some test', async () => {
  const mockModule = await import('./mock-data')
  // ... test code
})
```

**Warnings Fixed**: 1 `@typescript-eslint/no-require-imports`

---

## Example 7: Empty Object Types

### BEFORE (no-empty-object-type error)

```typescript
// src/components/ui/some-component.tsx

interface ComponentProps {}  // ❌ BAD: Empty interface

export const Component: React.FC<ComponentProps> = () => {
  // ... component
}
```

**ESLint Error**:
```
8:18  error  An interface declaring no members is equivalent to its supertype
             @typescript-eslint/no-empty-object-type
```

### AFTER (0 errors)

**Option 1**: Remove the interface if not needed

```typescript
// ✅ GOOD: No props needed
export const Component: React.FC = () => {
  // ... component
}
```

**Option 2**: Use Record<string, never>

```typescript
// ✅ GOOD: Explicitly empty
type ComponentProps = Record<string, never>

export const Component: React.FC<ComponentProps> = () => {
  // ... component
}
```

**Option 3**: Add a comment explaining why empty

```typescript
// ✅ GOOD: Document intention
interface ComponentProps {
  // Intentionally empty - reserved for future props
}

export const Component: React.FC<ComponentProps> = () => {
  // ... component
}
```

**Warnings Fixed**: 1 `@typescript-eslint/no-empty-object-type`

---

## Quick Reference: Fix Patterns

| Warning Type | Auto-Fix? | Fix Method |
|--------------|-----------|------------|
| `no-unused-vars` | ✅ Yes | `npm run lint:fix` |
| `no-useless-escape` | ✅ Yes | `npm run lint:fix` |
| `no-explicit-any` | ❌ No | Create proper types (see Example 1) |
| `react-refresh/only-export-components` | ❌ No | Split file (see Example 3) |
| `exhaustive-deps` | ⚠️ Partial | Add deps or wrap in useCallback (see Example 4) |
| `no-case-declarations` | ❌ No | Wrap in braces (see Example 5) |
| `no-require-imports` | ❌ No | Convert to import (see Example 6) |
| `no-empty-object-type` | ❌ No | Remove or document (see Example 7) |

---

## Step-by-Step Workflow

1. **Run lint to see current state**
   ```bash
   npm run lint
   ```

2. **Auto-fix what you can**
   ```bash
   npm run lint:fix
   ```

3. **For each remaining file with warnings**:
   - Read the file
   - Identify warning patterns
   - Apply appropriate fix from examples above
   - Test the component still works
   - Run `npm run typecheck` to verify types
   - Commit the fix

4. **Verify zero warnings**
   ```bash
   npm run lint
   # Should show: 0 problems
   ```

---

## Testing After Fixes

```bash
# Type check
npm run typecheck

# Build
npm run build

# Run tests
npm test

# Start dev server and verify Fast Refresh
npm run dev
# Edit a component and verify it hot-reloads
```

---

**Remember**: Grug say fix one file at a time, test each fix, commit often. No rush, no break things! 🦴
