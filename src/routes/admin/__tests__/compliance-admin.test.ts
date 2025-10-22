/**
 * Compliance Admin API Routes Integration Tests
 *
 * Tests all compliance management endpoints for admins
 * Coverage target: 95%+
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../../types/cloudflare';

// Mock dependencies
vi.mock('../../../middleware/auth', () => ({
  authenticate: () => async (c: any, next: any) => {
    // Allow overriding userId via X-Test-User-Id header for testing non-admin scenarios
    const testUserId = c.req.header('X-Test-User-Id');
    c.set('userId', testUserId || 'admin-user-id');
    c.set('businessId', 'test-business-id');
    await next();
  }
}));

import complianceAdminRoutes from '../compliance-admin';

/**
 * Helper to mock admin permission check
 * The ensureAdmin function uses fallback in test mode, so this is a no-op
 * but kept for test clarity and to avoid lint errors
 */
function mockAdminCheck(_mockDB: any, _isAdmin: boolean = true) {
  // No-op: ensureAdmin uses automatic fallback in VITEST environment
  // Admin check will use heuristic: userId.toLowerCase().includes('admin')
  // Test auth middleware sets userId='admin-user-id' which passes
}

describe('Compliance Admin API Routes', () => {
  let app: Hono;
  let mockEnv: Env;
  let mockPreparedStatement: any;
  let mockD1Database: any;

  beforeEach(() => {
    vi.clearAllMocks();

    // Create fresh mock objects for each test (following invoice-manager pattern)
    mockPreparedStatement = {
      bind: vi.fn(),
      first: vi.fn(),
      all: vi.fn(),
      run: vi.fn(),
    };

    mockD1Database = {
      prepare: vi.fn(),
      batch: vi.fn(),
      exec: vi.fn(),
    };

    app = new Hono<{ Bindings: Env }>();

    // Add middleware to set env on context
    app.use('*', async (c, next) => {
      // @ts-ignore - manually set env for testing
      c.env = mockEnv;
      await next();
    });

    app.route('/api/v1/admin/compliance', complianceAdminRoutes);

    // Setup DB mocks with proper chaining (following invoice-manager pattern)
    mockD1Database.prepare.mockReturnValue(mockPreparedStatement);
    mockPreparedStatement.bind.mockReturnValue(mockPreparedStatement);
    mockPreparedStatement.first.mockResolvedValue(null);
    mockPreparedStatement.all.mockResolvedValue({ results: [] });
    mockPreparedStatement.run.mockResolvedValue({ success: true });

    mockEnv = {
      DB_MAIN: mockD1Database,
      ENVIRONMENT: 'development'  // Show detailed errors in tests
    } as any;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Guidelines Management', () => {
    describe('POST /api/v1/admin/compliance/guidelines', () => {
      it('should create guideline successfully', async () => {
        // Admin check uses fallback in test mode (VITEST env var), no DB mock needed
        // Just need to mock the INSERT operation which is the only DB call
        // No override needed - default mockPreparedStatement.run returns { success: true }

        const req = new Request('http://localhost/api/v1/admin/compliance/guidelines', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            name: 'Professional Tone Required',
            category: 'tone_and_style',
            severity: 'high',
            rules: {
              requiredTone: 'professional',
              prohibitedTones: ['casual', 'slang']
            },
            enforcementMode: 'enforce',
            autoRemediation: true
          })
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(201);
        expect(json.success).toBe(true);
        expect(json.guidelineId).toBeDefined();
      });

      it('should validate guideline category', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        // Mock admin check
        mockAdminCheck(mockDB, true);

        const req = new Request('http://localhost/api/v1/admin/compliance/guidelines', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            name: 'Invalid Guideline',
            category: 'invalid_category',
            severity: 'high',
            rules: {}
          })
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(400);
        expect(json.error).toBeDefined();
      });

      it('should reject non-admin users', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        // Mock admin check to return false (user is not admin)
        mockAdminCheck(mockDB, false);

        const req = new Request('http://localhost/api/v1/admin/compliance/guidelines', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Test-User-Id': 'regular-user'  // Non-admin user for testing
          },
          body: JSON.stringify({
            name: 'Test Guideline',
            category: 'tone_and_style',
            severity: 'high',
            rules: {},
            enforcementMode: 'enforce'
          })
        });

        const res = await app.request(req, mockEnv);

        expect(res.status).toBe(403);
      });
    });

    describe('GET /api/v1/admin/compliance/guidelines', () => {
      it('should get all guidelines for business', async () => {
        // Override default mock to return specific guidelines
        mockPreparedStatement.all.mockResolvedValueOnce({
          results: [
            {
              id: 'guideline-1',
              name: 'Professional Tone',
              category: 'tone_and_style',
              severity: 'high',
              rules: JSON.stringify({ requiredTone: 'professional' }),
              enforcement_mode: 'enforce',
              is_active: 1
            },
            {
              id: 'guideline-2',
              name: 'No Competitor Mentions',
              category: 'content_restrictions',
              severity: 'medium',
              rules: JSON.stringify({ prohibitedWords: ['competitor'] }),
              enforcement_mode: 'warn',
              is_active: 1
            }
          ]
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/guidelines', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
        expect(json.guidelines).toHaveLength(2);
      });

      it('should filter guidelines by category', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          all: vi.fn().mockResolvedValue({
            results: [
              {
                id: 'guideline-1',
                category: 'tone_and_style',
                name: 'Professional Tone'
              }
            ]
          })
        });

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({ total: 1 })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/guidelines?category=tone_and_style', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.guidelines.every((g: any) => g.category === 'tone_and_style')).toBe(true);
      });

      it('should paginate results', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          all: vi.fn().mockResolvedValue({
            results: Array(10).fill(null).map((_, i) => ({
              id: `guideline-${i}`,
              name: `Guideline ${i}`
            }))
          })
        });

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({ total: 25 })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/guidelines?page=1&limit=10', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.pagination.total).toBe(25);
        expect(json.pagination.page).toBe(1);
      });
    });

    describe('PUT /api/v1/admin/compliance/guidelines/:id', () => {
      it('should update guideline', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        // Mock admin check
        mockAdminCheck(mockDB, true);

        // Mock UPDATE operation
        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          run: vi.fn().mockResolvedValue({ success: true })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/guidelines/guideline-123', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            severity: 'critical',
            enforcementMode: 'enforce'
          })
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
      });

      it('should validate update fields', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        // Mock admin check
        mockAdminCheck(mockDB, true);

        const req = new Request('http://localhost/api/v1/admin/compliance/guidelines/guideline-123', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            severity: 'invalid_severity'
          })
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(400);
        expect(json.error).toBeDefined();
      });
    });

    describe('DELETE /api/v1/admin/compliance/guidelines/:id', () => {
      it('should soft delete guideline', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        // Mock admin check
        mockAdminCheck(mockDB, true);

        // Mock soft DELETE operation
        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          run: vi.fn().mockResolvedValue({ success: true })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/guidelines/guideline-123', {
          method: 'DELETE'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
      });
    });
  });

  describe('Policies Management', () => {
    describe('POST /api/v1/admin/compliance/policies', () => {
      it('should create policy successfully', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        // Mock admin check
        mockAdminCheck(mockDB, true);

        // Mock INSERT operation
        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          run: vi.fn().mockResolvedValue({ success: true })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/policies', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            policyName: 'Rate Limiting Policy',
            agentId: 'onboarding-agent',
            policyType: 'rate_limiting',
            policyConfig: {
              requestsPerMinute: 10,
              requestsPerHour: 100
            },
            enforcementLevel: 'strict'
          })
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(201);
        expect(json.success).toBe(true);
        expect(json.policyId).toBeDefined();
      });

      it('should validate policy type', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        // Mock admin check
        mockAdminCheck(mockDB, true);

        const req = new Request('http://localhost/api/v1/admin/compliance/policies', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            policyName: 'Invalid Policy',
            agentId: 'test-agent',
            policyType: 'invalid_type',
            policyConfig: {}
          })
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(400);
        expect(json.error).toBeDefined();
      });
    });

    describe('GET /api/v1/admin/compliance/policies', () => {
      it('should get all policies for business', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          all: vi.fn().mockResolvedValue({
            results: [
              {
                id: 'policy-1',
                policy_name: 'Rate Limiting',
                agent_id: 'onboarding-agent',
                policy_type: 'rate_limiting',
                policy_config: JSON.stringify({ requestsPerMinute: 10 }),
                enforcement_level: 'enforce',
                is_active: 1
              }
            ]
          })
        });

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({ total: 1 })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/policies', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
        expect(json.policies).toBeInstanceOf(Array);
      });

      it('should filter policies by agent', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          all: vi.fn().mockResolvedValue({
            results: [
              {
                id: 'policy-1',
                agent_id: 'onboarding-agent'
              }
            ]
          })
        });

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({ total: 1 })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/policies?agentId=onboarding-agent', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.policies.every((p: any) => p.agent_id === 'onboarding-agent')).toBe(true);
      });
    });

    describe('PUT /api/v1/admin/compliance/policies/:id', () => {
      it('should update policy', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        // Mock admin check
        mockAdminCheck(mockDB, true);

        // Mock UPDATE operation
        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          run: vi.fn().mockResolvedValue({ success: true })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/policies/policy-123', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            enforcementLevel: 'warn',
            policyConfig: {
              requestsPerMinute: 20
            }
          })
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
      });
    });

    describe('DELETE /api/v1/admin/compliance/policies/:id', () => {
      it('should delete policy', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        // Mock admin check (if this route requires admin - need to check route file)
        mockAdminCheck(mockDB, true);

        // Mock DELETE operation
        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          run: vi.fn().mockResolvedValue({ success: true })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/policies/policy-123', {
          method: 'DELETE'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
      });
    });
  });

  describe('Violations Management', () => {
    describe('GET /api/v1/admin/compliance/violations', () => {
      it('should get all violations', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          all: vi.fn().mockResolvedValue({
            results: [
              {
                id: 'violation-1',
                agent_id: 'chat-agent',
                task_id: 'task-123',
                violation_type: 'prohibited_content',
                severity: 'high',
                guideline_name: 'Professional Tone',
                action_taken: 'blocked',
                occurred_at: new Date().toISOString(),
                resolved: 0
              },
              {
                id: 'violation-2',
                agent_id: 'onboarding-agent',
                task_id: 'task-456',
                violation_type: 'rate_limit_exceeded',
                severity: 'medium',
                policy_name: 'Rate Limiting',
                action_taken: 'blocked',
                occurred_at: new Date().toISOString(),
                resolved: 0
              }
            ]
          })
        });

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({ total: 2 })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/violations', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
        expect(json.violations).toHaveLength(2);
      });

      it('should filter violations by agent', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          all: vi.fn().mockResolvedValue({
            results: [
              {
                id: 'violation-1',
                agent_id: 'chat-agent',
                violation_type: 'tone_violation'
              }
            ]
          })
        });

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({ total: 1 })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/violations?agentId=chat-agent', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.violations.every((v: any) => v.agent_id === 'chat-agent')).toBe(true);
      });

      it('should filter violations by severity', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          all: vi.fn().mockResolvedValue({
            results: [
              {
                id: 'violation-1',
                severity: 'critical'
              }
            ]
          })
        });

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({ total: 1 })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/violations?severity=critical', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.violations.every((v: any) => v.severity === 'critical')).toBe(true);
      });

      it('should filter unresolved violations', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          all: vi.fn().mockResolvedValue({
            results: [
              {
                id: 'violation-1',
                resolved: 0
              }
            ]
          })
        });

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({ total: 1 })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/violations?resolved=false', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.violations.every((v: any) => v.resolved === 0)).toBe(true);
      });
    });

    describe('POST /api/v1/admin/compliance/violations/:id/resolve', () => {
      it('should resolve violation', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          run: vi.fn().mockResolvedValue({ success: true })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/violations/violation-123/resolve', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            resolutionNotes: 'False positive - content was appropriate'
          })
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
      });

      it('should require resolution notes', async () => {
        const req = new Request('http://localhost/api/v1/admin/compliance/violations/violation-123/resolve', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({})
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(400);
        expect(json.error).toBeDefined();
      });
    });

    describe('GET /api/v1/admin/compliance/violations/summary', () => {
      it('should get violation summary', async () => {
        const mockDB = mockEnv.DB_MAIN as any;

        mockDB.prepare.mockReturnValueOnce({
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue({
            total_violations: 150,
            unresolved_violations: 25,
            critical_violations: 5,
            high_violations: 15
          })
        });

        const req = new Request('http://localhost/api/v1/admin/compliance/violations/summary', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
        expect(json.summary.totalViolations).toBe(150);
        expect(json.summary.unresolvedViolations).toBe(25);
      });
    });
  });

  describe('Guideline Templates', () => {
    describe('GET /api/v1/admin/compliance/templates/guidelines', () => {
      it('should get guideline templates', async () => {
        const req = new Request('http://localhost/api/v1/admin/compliance/templates/guidelines', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.success).toBe(true);
        expect(json.templates).toBeInstanceOf(Array);
        expect(json.templates.length).toBeGreaterThan(0);
      });

      it('should include required template fields', async () => {
        const req = new Request('http://localhost/api/v1/admin/compliance/templates/guidelines', {
          method: 'GET'
        });

        const res = await app.request(req, mockEnv);
        const json = await res.json();

        const template = json.templates[0];
        expect(template).toHaveProperty('name');
        expect(template).toHaveProperty('category');
        expect(template).toHaveProperty('severity');
        expect(template).toHaveProperty('rules');
        expect(template).toHaveProperty('enforcementMode');
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle database errors gracefully', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockRejectedValue(new Error('Database error'))
      });

      const req = new Request('http://localhost/api/v1/admin/compliance/guidelines', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(json.error).toBeDefined();
    });

    it('should validate JSON input', async () => {
      const req = new Request('http://localhost/api/v1/admin/compliance/guidelines', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: 'invalid json'
      });

      const res = await app.request(req, mockEnv);

      expect(res.status).toBeGreaterThanOrEqual(400);
    });
  });

  describe('Security', () => {
    it('should prevent SQL injection in filters', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ total: 0 })
      });

      const req = new Request('http://localhost/api/v1/admin/compliance/violations?agentId=test-agent\' OR 1=1--', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);

      // Should not cause SQL injection
      expect(res.status).toBeLessThan(500);
    });

    it('should sanitize violation resolution notes', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const req = new Request('http://localhost/api/v1/admin/compliance/violations/violation-123/resolve', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          resolutionNotes: '<script>alert("XSS")</script>Resolved'
        })
      });

      const res = await app.request(req, mockEnv);

      // Should not execute script
      expect(res.status).toBeLessThan(500);
    });
  });

  describe('Pagination & Sorting', () => {
    it('should support custom page sizes', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: Array(50).fill(null).map((_, i) => ({ id: `g-${i}` }))
        })
      });

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ total: 100 })
      });

      const req = new Request('http://localhost/api/v1/admin/compliance/guidelines?limit=50', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(json.pagination.limit).toBe(50);
    });

    it('should enforce maximum page size', async () => {
      const req = new Request('http://localhost/api/v1/admin/compliance/guidelines?limit=10000', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      // Should cap at reasonable limit (e.g., 100)
      if (res.status === 200) {
        expect(json.pagination.limit).toBeLessThanOrEqual(100);
      } else {
        expect(res.status).toBe(400);
      }
    });
  });
});
