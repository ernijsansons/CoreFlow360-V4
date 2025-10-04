/**
 * Hono Context Type Safety Tests
 * Validates that all context variable mappings are type-safe
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import type { AppContext, AppVariables } from '../../types/hono-context';
import type { Env } from '../../types/environment';

describe('Hono Context Type Safety', () => {
  let app: Hono<{ Bindings: Env; Variables: AppVariables }>;

  beforeEach(() => {
    app = new Hono<{ Bindings: Env; Variables: AppVariables }>();
  });

  it('should allow setting and getting correlationId', async () => {
    app.get('/test', (c: AppContext) => {
      c.set('correlationId', 'test-correlation-id');
      const correlationId = c.get('correlationId');
      return c.json({ correlationId });
    });

    const res = await app.request('/test');
    const json = await res.json();

    expect(json).toEqual({ correlationId: 'test-correlation-id' });
  });

  it('should allow setting and getting requestId', async () => {
    app.get('/test', (c: AppContext) => {
      c.set('requestId', 'test-request-id');
      const requestId = c.get('requestId');
      return c.json({ requestId });
    });

    const res = await app.request('/test');
    const json = await res.json();

    expect(json).toEqual({ requestId: 'test-request-id' });
  });

  it('should allow setting and getting userId', async () => {
    app.get('/test', (c: AppContext) => {
      c.set('userId', 'user-123');
      const userId = c.get('userId');
      return c.json({ userId });
    });

    const res = await app.request('/test');
    const json = await res.json();

    expect(json).toEqual({ userId: 'user-123' });
  });

  it('should allow setting and getting businessId', async () => {
    app.get('/test', (c: AppContext) => {
      c.set('businessId', 'business-456');
      const businessId = c.get('businessId');
      return c.json({ businessId });
    });

    const res = await app.request('/test');
    const json = await res.json();

    expect(json).toEqual({ businessId: 'business-456' });
  });

  it('should allow setting and getting roles array', async () => {
    app.get('/test', (c: AppContext) => {
      c.set('roles', ['admin', 'user']);
      const roles = c.get('roles');
      return c.json({ roles });
    });

    const res = await app.request('/test');
    const json = await res.json();

    expect(json).toEqual({ roles: ['admin', 'user'] });
  });

  it('should allow setting and getting tokenVersion', async () => {
    app.get('/test', (c: AppContext) => {
      c.set('tokenVersion', 1);
      const tokenVersion = c.get('tokenVersion');
      return c.json({ tokenVersion });
    });

    const res = await app.request('/test');
    const json = await res.json();

    expect(json).toEqual({ tokenVersion: 1 });
  });

  it('should allow setting and getting sanitizedBody', async () => {
    app.post('/test', (c: AppContext) => {
      c.set('sanitizedBody', { test: 'data' });
      const body = c.get('sanitizedBody');
      return c.json({ body });
    });

    const res = await app.request('/test', { method: 'POST' });
    const json = await res.json();

    expect(json).toEqual({ body: { test: 'data' } });
  });

  it('should handle multiple context variables in middleware chain', async () => {
    app.use('*', async (c: AppContext, next) => {
      c.set('correlationId', 'test-correlation');
      c.set('requestId', 'test-request');
      await next();
    });

    app.use('*', async (c: AppContext, next) => {
      c.set('userId', 'user-123');
      c.set('businessId', 'business-456');
      await next();
    });

    app.get('/test', (c: AppContext) => {
      return c.json({
        correlationId: c.get('correlationId'),
        requestId: c.get('requestId'),
        userId: c.get('userId'),
        businessId: c.get('businessId')
      });
    });

    const res = await app.request('/test');
    const json = await res.json();

    expect(json).toEqual({
      correlationId: 'test-correlation',
      requestId: 'test-request',
      userId: 'user-123',
      businessId: 'business-456'
    });
  });

  it('should work with authentication middleware pattern', async () => {
    const authMiddleware = async (c: AppContext, next: () => Promise<void>) => {
      // Simulate JWT verification
      c.set('userId', 'verified-user');
      c.set('businessId', 'verified-business');
      c.set('roles', ['admin']);
      c.set('tokenVersion', 1);
      await next();
    };

    app.use('/protected/*', authMiddleware);

    app.get('/protected/resource', (c: AppContext) => {
      const userId = c.get('userId');
      const businessId = c.get('businessId');
      const roles = c.get('roles');

      return c.json({ userId, businessId, roles });
    });

    const res = await app.request('/protected/resource');
    const json = await res.json();

    expect(json).toEqual({
      userId: 'verified-user',
      businessId: 'verified-business',
      roles: ['admin']
    });
  });

  it('should handle optional variables correctly', async () => {
    app.get('/test', (c: AppContext) => {
      // Should work with undefined values
      const userId = c.get('userId'); // May be undefined
      const correlationId = c.get('correlationId') || 'default-id';

      return c.json({
        hasUserId: userId !== undefined,
        correlationId
      });
    });

    const res = await app.request('/test');
    const json = await res.json();

    expect(json).toEqual({
      hasUserId: false,
      correlationId: 'default-id'
    });
  });
});
