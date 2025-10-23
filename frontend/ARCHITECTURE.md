# Frontend Architecture

## Dependency Flow Rules

This document defines the dependency flow rules to prevent circular dependencies that can break production builds.

---

## Dependency Flow

```
core/ → No dependencies
  ↓
stores/ → Depends only on core
  ↓
hooks/ → Depends on core, stores
  ↓
components/ → Can use everything
```

---

## Import Rules

The following ESLint rules enforce one-way dependency flow:

- **Stores cannot import from hooks** - Prevents circular dependency risk
- **Stores cannot import from components** - Prevents circular dependency risk  
- **Hooks cannot import from components** - Prevents circular dependency risk

---

## Examples

### ✅ Good Imports

```typescript
// components/UserProfile.tsx
import { useAuthStore } from '@/stores'        // ✅ Components can import stores
import { useEntityStore } from '@/stores'      // ✅ Components can import stores

// hooks/useUserData.ts
import { useAuthStore } from '@/stores'        // ✅ Hooks can import stores

// stores/authStore.ts
import { apiClient } from '@/core/api'          // ✅ Stores can import core
```

### ❌ Bad Imports

```typescript
// stores/authStore.ts
import { useUserData } from '@/hooks'          // ❌ Stores cannot import hooks
import { UserProfile } from '@/components'     // ❌ Stores cannot import components

// hooks/useUserData.ts
import { UserProfile } from '@/components'     // ❌ Hooks cannot import components
```

---

## Testing

### Check for Circular Dependencies

```bash
# Check for circular dependencies
npm run check:circular

# Strict mode (fails if found)
npm run check:circular:strict

# Safe build (checks before building)
npm run build:safe
```

### Pre-commit Hook

The pre-commit hook automatically runs circular dependency checks before every commit. If circular dependencies are detected, the commit will be blocked with a clear error message.

---

## References

- **Recovery Plan**: `../RECOVERY_PLAN.md`
- **Session Status**: `../SESSION_STATUS.md`
- **ESLint Config**: `eslint.config.js`
- **Package Scripts**: `package.json`

---

**Last Updated**: October 23, 2025
**Phase**: 1.5 - Architecture Documentation
