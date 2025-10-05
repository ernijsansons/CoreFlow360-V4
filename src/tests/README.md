# CoreFlow360 V4 - Test Utilities Guide

## 📚 Quick Reference for Test Mocks

### Available Test Mocks

#### 1. KV Namespace Mock
**File:** `src/tests/mocks/kv-namespace-mock.ts`

**Usage:**
```typescript
import { createMockKV, MockKVNamespace } from './mocks/kv-namespace-mock';

// Option 1: Factory function
const kv = createMockKV();

// Option 2: Direct instantiation
const mockKV = new MockKVNamespace();
const kv = mockKV.asKVNamespace();

// Use in tests
await kv.put('key', 'value');
const value = await kv.get('key');
const { value, metadata } = await kv.getWithMetadata('key');
```

**Features:**
- ✅ All get() overloads (text, json, arrayBuffer, stream)
- ✅ getWithMetadata() support
- ✅ put(), delete(), list() operations
- ✅ Batch operations
- ✅ Helper methods: clear(), size(), has()

#### 2. D1 Database Mock
**File:** `src/tests/mocks/d1-database-mock.ts`

**Usage:**
```typescript
import { createMockD1, MockD1Database } from './mocks/d1-database-mock';

// Option 1: Factory function
const db = createMockD1();

// Option 2: Direct instantiation
const mockDB = new MockD1Database();

// Set mock results
mockDB.setMockResults('SELECT', [
  { id: 1, name: 'Test' }
], { rows_read: 1 });

// Use in tests
const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
const result = await stmt.bind(1).first();
```

**Features:**
- ✅ Complete D1PreparedStatement implementation
- ✅ prepare(), batch(), exec() support
- ✅ withSession() for transactions
- ✅ Mock result injection
- ✅ Helper methods: clear(), setMockResults()

### Test Patterns

#### Pattern 1: Simple KV Test
```typescript
import { describe, it, expect } from 'vitest';
import { createMockKV } from '../mocks/kv-namespace-mock';

describe('My Feature', () => {
  it('should store and retrieve data', async () => {
    const kv = createMockKV();

    await kv.put('user:1', JSON.stringify({ name: 'John' }));
    const data = await kv.get('user:1', 'json');

    expect(data).toEqual({ name: 'John' });
  });
});
```

#### Pattern 2: D1 Database Test
```typescript
import { describe, it, expect } from 'vitest';
import { createMockD1 } from '../mocks/d1-database-mock';

describe('Database Operations', () => {
  it('should query users', async () => {
    const db = createMockD1();
    db.setMockResults('users', [{ id: 1, email: 'test@example.com' }]);

    const result = await db.prepare('SELECT * FROM users').first();

    expect(result).toEqual({ id: 1, email: 'test@example.com' });
  });
});
```

#### Pattern 3: Combined Mocks
```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { createMockKV } from '../mocks/kv-namespace-mock';
import { createMockD1 } from '../mocks/d1-database-mock';
import { MyService } from '../../services/my-service';

describe('MyService', () => {
  let kv: KVNamespace;
  let db: D1Database;
  let service: MyService;

  beforeEach(() => {
    kv = createMockKV().asKVNamespace();
    db = createMockD1();
    service = new MyService(db, kv);
  });

  it('should work with both mocks', async () => {
    // Test implementation
  });
});
```

### Common Test Utilities

#### Assertion Helpers
```typescript
// Correct Vitest assertions
expect(value).toBe(expected);
expect(array.length).toBeGreaterThan(0);
expect.fail('Should not reach here');

// Incorrect (don't use)
// expect(array).toHaveLength.greaterThan(0); ❌
// fail('message'); ❌
```

#### Mock Request Creation
```typescript
function createMockRequest(
  headers: Record<string, string> = {},
  method: string = 'GET',
  url: string = 'https://api.example.com/test'
): Request {
  const headersObj = new Headers();
  Object.entries(headers).forEach(([key, value]) => {
    headersObj.set(key, value);
  });

  return new Request(url, {
    method,
    headers: headersObj
  });
}
```

### Best Practices

1. **Use Centralized Mocks**
   - ✅ Import from `./mocks/` directory
   - ❌ Don't create inline mocks

2. **Type Safety**
   - ✅ Use TypeScript types from `@cloudflare/workers-types`
   - ✅ Add type annotations for complex types

3. **Clean Tests**
   - ✅ Use `beforeEach()` for setup
   - ✅ Use `afterEach()` for cleanup
   - ✅ Clear mocks between tests

4. **Descriptive Test Names**
   - ✅ Use "should..." pattern
   - ✅ Include context in describe blocks

### Troubleshooting

#### Issue: "Cannot set property crypto"
**Solution:** Mock the crypto API properly
```typescript
import { vi } from 'vitest';

vi.stubGlobal('crypto', {
  randomUUID: () => '123e4567-e89b-12d3-a456-426614174000',
  subtle: {
    digest: async () => new ArrayBuffer(32)
  }
});
```

#### Issue: "KVNamespace type mismatch"
**Solution:** Use `.asKVNamespace()` method
```typescript
const mock = new MockKVNamespace();
const kv: KVNamespace = mock.asKVNamespace(); // ✅
```

#### Issue: "D1PreparedStatement error"
**Solution:** Use factory or set mock results
```typescript
const db = createMockD1();
db.setMockResults('pattern', [results]);
```

### Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test -- security.test.ts

# Run with coverage
npm run test:coverage

# Run in watch mode
npm test -- --watch

# Run with verbose output
npm test -- --reporter=verbose
```

### Test Coverage Goals

- **Unit Tests:** 95%+ coverage
- **Integration Tests:** Key workflows covered
- **Security Tests:** All vulnerability scenarios
- **Edge Cases:** Fuzz testing for boundaries

---

## 📝 Quick Checklist

Before writing a test:
- [ ] Import correct mock from `./mocks/`
- [ ] Use proper Vitest assertions
- [ ] Add type annotations for complex types
- [ ] Include both success and failure cases
- [ ] Test edge cases and boundaries

---

*For detailed implementation, see:*
- `src/tests/mocks/kv-namespace-mock.ts`
- `src/tests/mocks/d1-database-mock.ts`
- `TEST_COMPILATION_REPORT.md`
