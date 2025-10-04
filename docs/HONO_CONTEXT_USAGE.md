# Hono Context Usage Guide

## Quick Reference

### Import Types
```typescript
import type { AppContext, Next } from '../types/hono-context';
```

### Middleware Pattern
```typescript
app.use('*', async (c: AppContext, next: Next) => {
  // Set context variables
  c.set('correlationId', crypto.randomUUID());
  c.set('requestId', crypto.randomUUID());

  await next();
});
```

### Route Handler Pattern
```typescript
app.get('/api/resource', async (c: AppContext) => {
  // Get context variables with optional chaining
  const userId = c.get('userId');
  const businessId = c.get('businessId');

  // Use variables safely
  if (!userId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  return c.json({ userId, businessId });
});
```

### Authentication Middleware Pattern
```typescript
const authMiddleware = async (c: AppContext, next: Next) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return c.json({ error: 'Missing token' }, 401);
  }

  // Verify token and set context
  const payload = await verifyToken(token);
  c.set('userId', payload.sub);
  c.set('businessId', payload.businessId);
  c.set('roles', payload.roles || []);

  await next();
};
```

## Available Context Variables

| Variable | Type | When Available | Usage |
|----------|------|----------------|-------|
| `correlationId` | `string?` | Request tracking middleware | Trace requests across services |
| `requestId` | `string?` | Request tracking middleware | Unique request identifier |
| `env` | `Env?` | Environment setup middleware | Access Cloudflare bindings |
| `userId` | `string?` | After authentication | Identify authenticated user |
| `businessId` | `string?` | After authentication | Multi-tenant isolation |
| `sessionId` | `string?` | After session creation | Session management |
| `roles` | `string[]?` | After authentication | Authorization checks |
| `tokenVersion` | `string\|number?` | After JWT verification | Token rotation support |
| `sanitizedBody` | `any?` | After input sanitization | XSS-safe request body |
| `startTime` | `number?` | Performance middleware | Request timing |
| `dbQueryCount` | `number?` | Database middleware | Query performance tracking |
| `cacheHitCount` | `number?` | Cache middleware | Cache performance |
| `cacheMissCount` | `number?` | Cache middleware | Cache performance |

## Common Patterns

### 1. Request Tracking
```typescript
app.use('*', async (c: AppContext, next: Next) => {
  const correlationId = c.req.header('X-Correlation-ID') || crypto.randomUUID();
  const requestId = crypto.randomUUID();

  c.set('correlationId', correlationId);
  c.set('requestId', requestId);

  c.header('X-Correlation-ID', correlationId);
  c.header('X-Request-ID', requestId);

  await next();
});
```

### 2. Protected Routes
```typescript
app.get('/api/protected/resource', authMiddleware, async (c: AppContext) => {
  const userId = c.get('userId');
  const businessId = c.get('businessId');

  // Both are guaranteed to exist after authMiddleware
  // But TypeScript doesn't know that, so check anyway
  if (!userId || !businessId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const data = await fetchData(userId, businessId);
  return c.json(data);
});
```

### 3. Role-Based Access Control
```typescript
const requireRole = (requiredRole: string) => {
  return async (c: AppContext, next: Next) => {
    const roles = c.get('roles') || [];

    if (!roles.includes(requiredRole)) {
      return c.json({ error: 'Insufficient permissions' }, 403);
    }

    await next();
  };
};

app.delete('/api/admin/users/:id',
  authMiddleware,
  requireRole('admin'),
  async (c: AppContext) => {
    // Handle admin-only deletion
  }
);
```

### 4. Multi-Tenant Data Isolation
```typescript
app.get('/api/data', authMiddleware, async (c: AppContext) => {
  const businessId = c.get('businessId');

  // Always filter by businessId to prevent cross-tenant access
  const data = await db
    .select()
    .from('data')
    .where('business_id', businessId);

  return c.json(data);
});
```

### 5. Performance Tracking
```typescript
app.use('*', async (c: AppContext, next: Next) => {
  c.set('startTime', Date.now());
  c.set('dbQueryCount', 0);

  await next();

  const duration = Date.now() - (c.get('startTime') || Date.now());
  const queries = c.get('dbQueryCount') || 0;

  console.log(`Request completed in ${duration}ms with ${queries} queries`);
});
```

### 6. Input Sanitization
```typescript
app.use('*', async (c: AppContext, next: Next) => {
  if (['POST', 'PUT', 'PATCH'].includes(c.req.method)) {
    try {
      const body = await c.req.json();
      const sanitized = sanitizeInput(body);
      c.set('sanitizedBody', sanitized);
    } catch (error) {
      return c.json({ error: 'Invalid JSON' }, 400);
    }
  }

  await next();
});

app.post('/api/resource', async (c: AppContext) => {
  // Use sanitized body instead of raw input
  const body = c.get('sanitizedBody');

  // Process safely...
});
```

## Type Safety Tips

### 1. Always Import Types
```typescript
// ✅ Good
import type { AppContext, Next } from '../types/hono-context';

// ❌ Bad - loses type safety
import { Context } from 'hono';
```

### 2. Handle Optional Values
```typescript
// ✅ Good - checks for undefined
const userId = c.get('userId');
if (!userId) {
  return c.json({ error: 'Unauthorized' }, 401);
}

// ❌ Bad - assumes value exists
const userId = c.get('userId')!; // Dangerous!
```

### 3. Use Type Guards
```typescript
// ✅ Good - validates type
const roles = c.get('roles');
if (Array.isArray(roles) && roles.length > 0) {
  // Safe to use roles
}

// ❌ Bad - assumes type
const roles = c.get('roles') as string[];
```

### 4. Provide Defaults
```typescript
// ✅ Good - safe fallback
const correlationId = c.get('correlationId') || 'unknown';

// ✅ Also good - explicit handling
const correlationId = c.get('correlationId');
if (!correlationId) {
  // Handle missing correlation ID
}
```

## Debugging Tips

### 1. Log Context State
```typescript
app.use('*', async (c: AppContext, next: Next) => {
  console.log('Context variables:', {
    correlationId: c.get('correlationId'),
    requestId: c.get('requestId'),
    userId: c.get('userId'),
    businessId: c.get('businessId')
  });

  await next();
});
```

### 2. Validate Critical Variables
```typescript
const validateContext = (c: AppContext): boolean => {
  const required = ['userId', 'businessId'] as const;

  for (const key of required) {
    if (!c.get(key)) {
      console.error(`Missing required context variable: ${key}`);
      return false;
    }
  }

  return true;
};
```

### 3. Trace Variable Flow
```typescript
app.use('*', async (c: AppContext, next: Next) => {
  const before = { userId: c.get('userId'), businessId: c.get('businessId') };

  await next();

  const after = { userId: c.get('userId'), businessId: c.get('businessId') };

  if (before.userId !== after.userId) {
    console.log('userId changed during request processing');
  }
});
```

## Migration Checklist

When updating existing files to use typed context:

- [ ] Import `AppContext` and `Next` types
- [ ] Update all middleware signatures to use `AppContext`
- [ ] Update all route handlers to use `AppContext`
- [ ] Replace `Context` imports with typed imports
- [ ] Add null checks for optional variables
- [ ] Test all context variable usage
- [ ] Verify TypeScript compilation passes
- [ ] Run test suite to ensure functionality

## Common Errors and Solutions

### Error: "Argument of type 'X' is not assignable to parameter of type 'never'"
**Solution**: Import and use `AppContext` instead of generic `Context`

### Error: "Property 'X' does not exist on type 'AppContext'"
**Solution**: Ensure variable is defined in `AppVariables` type in `src/types/hono-context.ts`

### Error: "Type 'undefined' is not assignable to type 'X'"
**Solution**: Variables are optional. Add null checks or provide defaults.

## Resources

- Type definitions: `src/types/hono-context.ts`
- Example usage: `src/index.secure.ts`
- Test suite: `src/tests/types/hono-context.test.ts`
- Hono documentation: https://hono.dev/
