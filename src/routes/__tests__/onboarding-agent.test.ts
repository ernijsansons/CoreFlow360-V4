/**
 * Onboarding Agent API Routes Integration Tests
 *
 * Tests all onboarding endpoints with realistic scenarios
 * Coverage target: 95%+
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../types/cloudflare';

// Mock dependencies
vi.mock('../../middleware/auth', () => ({
  authenticate: () => async (c: any, next: any) => {
    c.set('userId', 'test-user-id');
    c.set('businessId', 'test-business-id');
    await next();
  }
}));

vi.mock('../../modules/agents/orchestrator', () => ({
  AgentOrchestrator: class MockOrchestrator {
    async executeTask(task: any, context: any) {
      // Simulate successful execution based on capability
      switch (task.capability) {
        case 'data_import':
          return {
            taskId: task.id,
            agentId: 'onboarding-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                rowsImported: 100,
                errors: [],
                importId: 'import-123'
              }
            },
            metrics: {
              executionTime: 1500,
              tokensUsed: 500,
              cost: 0.05
            },
            timestamp: new Date().toISOString()
          };

        case 'progress_tracking':
          return {
            taskId: task.id,
            agentId: 'onboarding-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                completionPercentage: 40,
                currentStep: 'data_import',
                stepsCompleted: ['account_setup', 'team_onboarding'],
                stepsRemaining: ['integration_wizard', 'validation_checks']
              }
            },
            metrics: {
              executionTime: 200,
              tokensUsed: 100,
              cost: 0.01
            },
            timestamp: new Date().toISOString()
          };

        case 'validation_checks':
          return {
            taskId: task.id,
            agentId: 'onboarding-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                allChecksPassed: true,
                checks: [
                  { name: 'Business Configured', passed: true },
                  { name: 'Data Imported', passed: true },
                  { name: 'Team Members Added', passed: true }
                ],
                failedChecks: []
              }
            },
            metrics: {
              executionTime: 800,
              tokensUsed: 200,
              cost: 0.02
            },
            timestamp: new Date().toISOString()
          };

        default:
          return {
            taskId: task.id,
            agentId: 'onboarding-agent',
            status: 'completed',
            result: {
              success: true,
              data: {}
            },
            metrics: {
              executionTime: 500,
              tokensUsed: 150,
              cost: 0.015
            },
            timestamp: new Date().toISOString()
          };
      }
    }
  }
}));

// Import the actual route handler
import onboardingRoutes from '../onboarding-agent';

describe('Onboarding Agent API Routes', () => {
  let app: Hono;
  let mockEnv: Env;

  beforeEach(() => {
    app = new Hono();
    app.route('/api/v1/onboarding', onboardingRoutes);

    mockEnv = {
      DB_MAIN: {
        prepare: vi.fn().mockReturnThis(),
        bind: vi.fn().mockReturnThis(),
        first: vi.fn(),
        all: vi.fn(),
        run: vi.fn()
      },
      ANTHROPIC_API_KEY: 'test-key',
      CLOUDFLARE_ACCOUNT_ID: 'test-account'
    } as any;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('POST /api/v1/onboarding/start', () => {
    it('should start onboarding flow successfully', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      // Mock configuration creation
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      // Mock progress creation
      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const req = new Request('http://localhost/api/v1/onboarding/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          flowType: 'full',
          businessInfo: {
            name: 'Test Business',
            industry: 'Technology'
          }
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.configurationId).toBeDefined();
      expect(json.progressId).toBeDefined();
      expect(json.nextStep).toBeDefined();
    });

    it('should reject invalid flow type', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          flowType: 'invalid_type'
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toBeDefined();
    });
  });

  describe('POST /api/v1/onboarding/import-data', () => {
    it('should import CSV data successfully', async () => {
      const csvData = 'name,email\nJohn,john@example.com\nJane,jane@example.com';
      const base64Data = Buffer.from(csvData).toString('base64');

      const req = new Request('http://localhost/api/v1/onboarding/import-data', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123',
          fileData: base64Data,
          format: 'csv',
          dataType: 'customers',
          fieldMapping: {
            name: 'full_name',
            email: 'email_address'
          }
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.rowsImported).toBeGreaterThan(0);
      expect(json.importId).toBeDefined();
    });

    it('should require file data and format', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/import-data', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123',
          dataType: 'customers'
          // Missing fileData and format
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toBeDefined();
    });
  });

  describe('POST /api/v1/onboarding/setup-account', () => {
    it('should set up account with configuration', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/setup-account', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123',
          businessConfig: {
            currency: 'USD',
            timezone: 'America/New_York',
            fiscalYearStart: '01-01'
          }
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
    });

    it('should validate currency format', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/setup-account', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123',
          businessConfig: {
            currency: 'INVALID', // Invalid currency code
            timezone: 'America/New_York'
          }
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toBeDefined();
    });
  });

  describe('POST /api/v1/onboarding/setup-integration', () => {
    it('should test integration successfully', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/setup-integration', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123',
          integrationType: 'stripe',
          credentials: {
            apiKey: 'sk_test_123'
          }
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
    });

    it('should validate integration type', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/setup-integration', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123',
          integrationType: 'invalid_integration',
          credentials: {}
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toBeDefined();
    });
  });

  describe('POST /api/v1/onboarding/team-members', () => {
    it('should add team members successfully', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/team-members', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123',
          teamMembers: [
            {
              email: 'member1@example.com',
              role: 'admin',
              name: 'Member 1'
            },
            {
              email: 'member2@example.com',
              role: 'user',
              name: 'Member 2'
            }
          ],
          sendInvitations: true
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
    });

    it('should validate email addresses', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/team-members', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123',
          teamMembers: [
            {
              email: 'invalid-email',
              role: 'admin',
              name: 'Test User'
            }
          ]
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toBeDefined();
    });
  });

  describe('GET /api/v1/onboarding/progress/:businessId', () => {
    it('should get onboarding progress', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/progress/biz-123', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.progress).toBeDefined();
      expect(json.progress.completionPercentage).toBeDefined();
    });
  });

  describe('POST /api/v1/onboarding/validate', () => {
    it('should validate onboarding readiness', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/validate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123'
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.allChecksPassed).toBeDefined();
      expect(json.checks).toBeInstanceOf(Array);
    });

    it('should require configuration ID', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/validate', {
        method: 'POST',
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

  describe('POST /api/v1/onboarding/complete', () => {
    it('should mark onboarding as complete', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const req = new Request('http://localhost/api/v1/onboarding/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          configurationId: 'config-123'
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
    });
  });

  describe('GET /api/v1/onboarding/analytics/:businessId', () => {
    it('should get onboarding analytics', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/analytics/biz-123?start=2025-01-01&end=2025-01-31', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
    });
  });

  describe('GET /api/v1/onboarding/templates', () => {
    it('should get onboarding templates', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/templates?industry=technology', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.templates).toBeInstanceOf(Array);
    });

    it('should filter templates by industry', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/templates?industry=retail', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.templates.every((t: any) => t.industry === 'retail' || t.industry === 'all')).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle agent execution errors', async () => {
      vi.mock('../../modules/agents/orchestrator', () => ({
        AgentOrchestrator: class MockOrchestrator {
          async executeTask() {
            throw new Error('Agent execution failed');
          }
        }
      }));

      const req = new Request('http://localhost/api/v1/onboarding/progress/biz-123', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(json.error).toBeDefined();
    });

    it('should handle missing authentication', async () => {
      vi.mock('../../middleware/auth', () => ({
        authenticate: () => async () => {
          throw new Error('Unauthorized');
        }
      }));

      const req = new Request('http://localhost/api/v1/onboarding/start', {
        method: 'POST',
        body: JSON.stringify({})
      });

      const res = await app.request(req, mockEnv);

      expect(res.status).toBeGreaterThanOrEqual(400);
    });
  });

  describe('Rate Limiting & Security', () => {
    it('should respect rate limits', async () => {
      const requests = [];
      for (let i = 0; i < 150; i++) {
        requests.push(
          app.request(
            new Request('http://localhost/api/v1/onboarding/progress/biz-123', {
              method: 'GET'
            }),
            mockEnv
          )
        );
      }

      const responses = await Promise.all(requests);
      const tooManyRequests = responses.filter(r => r.status === 429);

      // Some requests should be rate limited
      expect(tooManyRequests.length).toBeGreaterThan(0);
    });

    it('should sanitize user input', async () => {
      const req = new Request('http://localhost/api/v1/onboarding/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          flowType: 'full',
          businessInfo: {
            name: '<script>alert("XSS")</script>',
            industry: 'Technology'
          }
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      // Should either reject or sanitize
      if (res.status === 200) {
        expect(json.businessInfo?.name).not.toContain('<script>');
      } else {
        expect(res.status).toBe(400);
      }
    });
  });
});
