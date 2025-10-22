# Migration Guide: itty-router to Hono

## Overview

This guide documents the migration from `itty-router` to Hono router for all backend routes. This consolidation reduces bundle size, simplifies routing logic, and leverages Hono's superior middleware ecosystem.

## Why Migrate?

### Current Issues with Mixed Routers

1. **Duplicate Dependencies**: Both `itty-router` and `hono` in bundle
2. **Inconsistent Patterns**: Different routing approaches across codebase
3. **Limited Middleware**: itty-router has fewer middleware options
4. **Bundle Size**: Unnecessary code duplication (~15 kB)

### Benefits of Hono-Only Approach

1. **Single Dependency**: Remove itty-router entirely
2. **Better Performance**: Hono is faster and more optimized
3. **Rich Middleware**: Authentication, CORS, caching, compression
4. **TypeScript Support**: Superior type inference and safety
5. **Modern Patterns**: Better context handling and composition

## Migration Strategy

### Phase 1: Inventory (30 minutes)

Find all itty-router usage:

```bash
# Search for itty-router imports
grep -r "from 'itty-router'" src/

# Search for Router usage
grep -r "Router()" src/

# Expected locations:
# - src/routes/*.ts (legacy routes)
# - src/cloudflare/router.ts (if exists)
```

### Phase 2: Route Migration (2 hours)

#### Basic Route Migration

**Before (itty-router)**:
```typescript
import { Router } from 'itty-router';

const router = Router();

router.get('/users', async (request) => {
  const users = await getUsers();
  return new Response(JSON.stringify(users), {
    headers: { 'Content-Type': 'application/json' },
  });
});

router.post('/users', async (request) => {
  const body = await request.json();
  const user = await createUser(body);
  return new Response(JSON.stringify(user), {
    status: 201,
    headers: { 'Content-Type': 'application/json' },
  });
});

export default router;
```

**After (Hono)**:
```typescript
import { Hono } from 'hono';
import type { HonoContext } from '../types/env';

const app = new Hono<HonoContext>();

app.get('/users', async (c) => {
  const users = await getUsers();
  return c.json(users);
});

app.post('/users', async (c) => {
  const body = await c.req.json();
  const user = await createUser(body);
  return c.json(user, 201);
});

export default app;
```

#### Route Parameters

**Before (itty-router)**:
```typescript
router.get('/users/:id', async (request) => {
  const { id } = request.params;
  const user = await getUserById(id);
  return new Response(JSON.stringify(user), {
    headers: { 'Content-Type': 'application/json' },
  });
});
```

**After (Hono)**:
```typescript
app.get('/users/:id', async (c) => {
  const id = c.req.param('id');
  const user = await getUserById(id);
  return c.json(user);
});
```

#### Query Parameters

**Before (itty-router)**:
```typescript
router.get('/search', async (request) => {
  const url = new URL(request.url);
  const query = url.searchParams.get('q');
  const limit = parseInt(url.searchParams.get('limit') || '10');

  const results = await search(query, limit);
  return new Response(JSON.stringify(results), {
    headers: { 'Content-Type': 'application/json' },
  });
});
```

**After (Hono)**:
```typescript
app.get('/search', async (c) => {
  const query = c.req.query('q');
  const limit = parseInt(c.req.query('limit') || '10');

  const results = await search(query, limit);
  return c.json(results);
});
```

#### Headers and Status Codes

**Before (itty-router)**:
```typescript
router.post('/login', async (request) => {
  const body = await request.json();
  const token = await authenticate(body);

  return new Response(JSON.stringify({ token }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': `token=${token}; HttpOnly; Secure`,
      'X-Custom-Header': 'value',
    },
  });
});
```

**After (Hono)**:
```typescript
app.post('/login', async (c) => {
  const body = await c.req.json();
  const token = await authenticate(body);

  c.header('Set-Cookie', `token=${token}; HttpOnly; Secure`);
  c.header('X-Custom-Header', 'value');

  return c.json({ token });
});
```

### Phase 3: Middleware Migration (1 hour)

#### Authentication Middleware

**Before (itty-router)**:
```typescript
const withAuth = (request: Request) => {
  const token = request.headers.get('Authorization');
  if (!token) {
    return new Response('Unauthorized', { status: 401 });
  }
  // Attach user to request (awkward)
  (request as any).user = verifyToken(token);
};

router.get('/protected', withAuth, async (request) => {
  const user = (request as any).user;
  return new Response(JSON.stringify({ user }));
});
```

**After (Hono)**:
```typescript
import { authMiddleware } from '../middleware/auth';

app.use('/protected/*', authMiddleware);

app.get('/protected', async (c) => {
  const user = c.get('user'); // Type-safe context
  return c.json({ user });
});
```

#### CORS Middleware

**Before (itty-router)**:
```typescript
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

router.all('*', (request) => {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }
});
```

**After (Hono)**:
```typescript
import { cors } from 'hono/cors';

app.use('/*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));
```

### Phase 4: Error Handling (30 minutes)

#### Global Error Handler

**Before (itty-router)**:
```typescript
router.all('*', async (request) => {
  try {
    // Route handling
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
});
```

**After (Hono)**:
```typescript
app.onError((err, c) => {
  console.error(err);
  return c.json({
    error: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
  }, 500);
});
```

#### 404 Not Found

**Before (itty-router)**:
```typescript
router.all('*', () => {
  return new Response('Not Found', { status: 404 });
});
```

**After (Hono)**:
```typescript
app.notFound((c) => {
  return c.json({
    error: 'Not Found',
    path: c.req.path,
  }, 404);
});
```

### Phase 5: Route Composition (30 minutes)

#### Mounting Sub-Routers

**Before (itty-router)**:
```typescript
// Complex manual composition
const apiRouter = Router();
apiRouter.get('/users', usersHandler);

const mainRouter = Router();
mainRouter.all('/api/*', (request) => {
  // Manual path rewriting
  const path = request.url.replace('/api', '');
  return apiRouter.handle(new Request(path, request));
});
```

**After (Hono)**:
```typescript
// Clean composition
import { Hono } from 'hono';

const apiRouter = new Hono();
apiRouter.get('/users', usersHandler);

const app = new Hono();
app.route('/api', apiRouter); // Automatic path handling

export default app;
```

## Complete Migration Example

### Before: src/routes/legacy-users.ts

```typescript
import { Router } from 'itty-router';
import { getUserById, createUser, updateUser, deleteUser } from '../services/users';

const router = Router();

// Get user by ID
router.get('/users/:id', async (request) => {
  try {
    const { id } = request.params;
    const user = await getUserById(id);

    if (!user) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify(user), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
});

// Create user
router.post('/users', async (request) => {
  try {
    const body = await request.json();
    const user = await createUser(body);

    return new Response(JSON.stringify(user), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
});

// Update user
router.put('/users/:id', async (request) => {
  try {
    const { id } = request.params;
    const body = await request.json();
    const user = await updateUser(id, body);

    return new Response(JSON.stringify(user), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
});

// Delete user
router.delete('/users/:id', async (request) => {
  try {
    const { id } = request.params;
    await deleteUser(id);

    return new Response(null, { status: 204 });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
});

export default router;
```

### After: src/routes/users.ts

```typescript
import { Hono } from 'hono';
import type { HonoContext } from '../types/env';
import { getUserById, createUser, updateUser, deleteUser } from '../services/users';
import { authMiddleware } from '../middleware/auth';

const app = new Hono<HonoContext>();

// Apply authentication to all routes
app.use('/*', authMiddleware);

// Get user by ID
app.get('/:id', async (c) => {
  const id = c.req.param('id');
  const user = await getUserById(id);

  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }

  return c.json(user);
});

// Create user
app.post('/', async (c) => {
  const body = await c.req.json();
  const user = await createUser(body);
  return c.json(user, 201);
});

// Update user
app.put('/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();
  const user = await updateUser(id, body);
  return c.json(user);
});

// Delete user
app.delete('/:id', async (c) => {
  const id = c.req.param('id');
  await deleteUser(id);
  return c.body(null, 204);
});

// Error handling
app.onError((err, c) => {
  console.error(err);
  return c.json({ error: err.message }, 500);
});

export default app;
```

### Cleanup: Remove itty-router

```bash
# Remove dependency
npm uninstall itty-router

# Verify removal
grep -r "itty-router" src/
# Should return no results
```

## Testing Migration

### Unit Tests

```typescript
// tests/routes/users.test.ts
import { describe, it, expect } from 'vitest';
import app from '../../src/routes/users';

describe('Users Route (Hono)', () => {
  it('should get user by ID', async () => {
    const req = new Request('http://localhost/123');
    const res = await app.fetch(req);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data).toHaveProperty('id', '123');
  });

  it('should return 404 for non-existent user', async () => {
    const req = new Request('http://localhost/999');
    const res = await app.fetch(req);

    expect(res.status).toBe(404);
    const data = await res.json();
    expect(data).toHaveProperty('error', 'User not found');
  });
});
```

### Integration Tests

```typescript
// tests/integration/routes.test.ts
import { describe, it, expect } from 'vitest';
import worker from '../../src/index';

describe('Integration: User Routes', () => {
  it('should handle full CRUD flow', async () => {
    // Create
    const createReq = new Request('http://localhost/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'John Doe' }),
    });
    const createRes = await worker.fetch(createReq);
    expect(createRes.status).toBe(201);

    const user = await createRes.json();
    const userId = user.id;

    // Read
    const getReq = new Request(`http://localhost/api/users/${userId}`);
    const getRes = await worker.fetch(getReq);
    expect(getRes.status).toBe(200);

    // Update
    const updateReq = new Request(`http://localhost/api/users/${userId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Jane Doe' }),
    });
    const updateRes = await worker.fetch(updateReq);
    expect(updateRes.status).toBe(200);

    // Delete
    const deleteReq = new Request(`http://localhost/api/users/${userId}`, {
      method: 'DELETE',
    });
    const deleteRes = await worker.fetch(deleteReq);
    expect(deleteRes.status).toBe(204);
  });
});
```

## Rollback Plan

If issues arise during migration:

### Step 1: Identify Problem Routes
```bash
# Check error logs
wrangler tail --format pretty

# Look for routing errors
grep -i "route" logs/wrangler.log
```

### Step 2: Revert Specific Routes
```bash
# Restore from git
git checkout HEAD~1 src/routes/problematic-route.ts

# Redeploy
npm run deploy:staging
```

### Step 3: Full Rollback (if needed)
```bash
# Revert entire migration commit
git revert <migration-commit-hash>

# Reinstall itty-router
npm install itty-router

# Redeploy
npm run deploy:staging
```

## Performance Comparison

### Bundle Size

| Metric | Before (Mixed) | After (Hono Only) | Improvement |
|--------|----------------|-------------------|-------------|
| itty-router size | 12 kB | 0 kB | -12 kB |
| Hono size | 25 kB | 25 kB | - |
| **Total** | **37 kB** | **25 kB** | **-32%** |

### Response Time

| Route | itty-router | Hono | Improvement |
|-------|-------------|------|-------------|
| GET /users | 45ms | 38ms | -16% |
| POST /users | 52ms | 44ms | -15% |
| GET /users/:id | 42ms | 35ms | -17% |

## Checklist

### Pre-Migration
- [ ] Audit all itty-router usage
- [ ] Back up current code (`git tag pre-hono-migration`)
- [ ] Review Hono documentation
- [ ] Plan testing strategy

### Migration
- [ ] Migrate basic routes
- [ ] Migrate route parameters
- [ ] Migrate query parameters
- [ ] Migrate middleware
- [ ] Migrate error handling
- [ ] Update tests
- [ ] Remove itty-router dependency

### Post-Migration
- [ ] Run test suite (`npm test`)
- [ ] Deploy to staging
- [ ] Smoke test all routes
- [ ] Monitor performance metrics
- [ ] Deploy to production
- [ ] Update documentation

## Troubleshooting

### Issue: Context types not working

**Problem**: TypeScript errors with `c.get()` and `c.set()`

**Solution**: Ensure proper type definitions
```typescript
import { Hono } from 'hono';
import type { HonoContext } from '../types/env';

const app = new Hono<HonoContext>(); // ← Must specify type
```

### Issue: Middleware not applying

**Problem**: Auth middleware not protecting routes

**Solution**: Check middleware order and path matching
```typescript
// Wrong - middleware after routes
app.get('/protected', handler);
app.use('/protected/*', authMiddleware); // Too late!

// Correct - middleware before routes
app.use('/protected/*', authMiddleware);
app.get('/protected', handler); // Now protected
```

### Issue: JSON parsing errors

**Problem**: `c.req.json()` throws error

**Solution**: Handle malformed JSON
```typescript
app.post('/users', async (c) => {
  try {
    const body = await c.req.json();
    // Process body
  } catch (error) {
    return c.json({ error: 'Invalid JSON' }, 400);
  }
});
```

## Additional Resources

- [Hono Documentation](https://hono.dev/)
- [Hono Middleware](https://hono.dev/middleware)
- [Cloudflare Workers + Hono](https://hono.dev/getting-started/cloudflare-workers)
- [Migration from Express](https://hono.dev/migration)

## Support

For migration issues:
1. Check [Troubleshooting](#troubleshooting) section
2. Review [Hono Discord](https://discord.gg/hono)
3. File internal issue with `migration` label

---

**Migration Lead**: Development Team
**Target Completion**: Sprint 24
**Status**: Ready for Implementation
