/**
 * Company Knowledge API Routes Integration Tests
 *
 * Tests all knowledge management endpoints
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
      switch (task.capability) {
        case 'website_scraping':
          return {
            taskId: task.id,
            agentId: 'company-knowledge-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                pagesScraped: 5,
                sourceId: 'source-123',
                url: task.input.data.url
              }
            },
            metrics: {
              executionTime: 5000,
              tokensUsed: 1000,
              cost: 0.10
            },
            timestamp: new Date().toISOString()
          };

        case 'product_learning':
          return {
            taskId: task.id,
            agentId: 'company-knowledge-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                productsAnalyzed: 3,
                insights: ['Product A targets enterprises', 'Product B for SMBs']
              }
            },
            metrics: {
              executionTime: 3000,
              tokensUsed: 800,
              cost: 0.08
            },
            timestamp: new Date().toISOString()
          };

        case 'brand_voice_analysis':
          return {
            taskId: task.id,
            agentId: 'company-knowledge-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                tone: 'professional',
                characteristics: ['helpful', 'expert'],
                guidelineCreated: task.input.data.createGuideline || false
              }
            },
            metrics: {
              executionTime: 2000,
              tokensUsed: 600,
              cost: 0.06
            },
            timestamp: new Date().toISOString()
          };

        case 'faq_generation':
          return {
            taskId: task.id,
            agentId: 'company-knowledge-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                faqsGenerated: 10,
                faqs: [
                  { question: 'What is the pricing?', answer: '$99/month', category: 'pricing' }
                ]
              }
            },
            metrics: {
              executionTime: 2500,
              tokensUsed: 700,
              cost: 0.07
            },
            timestamp: new Date().toISOString()
          };

        case 'content_recommendation':
          return {
            taskId: task.id,
            agentId: 'company-knowledge-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                recommendations: [
                  {
                    id: 'content-1',
                    title: 'Product Features',
                    contentType: 'product',
                    relevanceScore: 0.92
                  }
                ]
              }
            },
            metrics: {
              executionTime: 800,
              tokensUsed: 200,
              cost: 0.02
            },
            timestamp: new Date().toISOString()
          };

        case 'knowledge_validation':
          return {
            taskId: task.id,
            agentId: 'company-knowledge-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                validatedCount: 5,
                issuesFound: 1,
                accuracyScores: [0.95, 0.92, 0.88, 0.75, 0.90]
              }
            },
            metrics: {
              executionTime: 3000,
              tokensUsed: 900,
              cost: 0.09
            },
            timestamp: new Date().toISOString()
          };

        case 'knowledge_refresh':
          return {
            taskId: task.id,
            agentId: 'company-knowledge-agent',
            status: 'completed',
            result: {
              success: true,
              data: {
                contentsScheduled: 15,
                refreshStrategy: task.input.data.refreshStrategy
              }
            },
            metrics: {
              executionTime: 1000,
              tokensUsed: 300,
              cost: 0.03
            },
            timestamp: new Date().toISOString()
          };

        default:
          return {
            taskId: task.id,
            agentId: 'company-knowledge-agent',
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

import knowledgeRoutes from '../company-knowledge';

describe('Company Knowledge API Routes', () => {
  let app: Hono;
  let mockEnv: Env;

  beforeEach(() => {
    app = new Hono();
    app.route('/api/v1/knowledge', knowledgeRoutes);

    mockEnv = {
      DB_MAIN: {
        prepare: vi.fn().mockReturnThis(),
        bind: vi.fn().mockReturnThis(),
        first: vi.fn(),
        all: vi.fn(),
        run: vi.fn()
      },
      ANTHROPIC_API_KEY: 'test-key',
      OPENAI_API_KEY: 'test-openai-key',
      VECTORIZE_INDEX: {
        query: vi.fn(),
        insert: vi.fn()
      }
    } as any;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('POST /api/v1/knowledge/scrape', () => {
    it('should scrape website successfully', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/scrape', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: 'https://testcompany.com',
          maxDepth: 2,
          maxPages: 10
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.pagesScraped).toBeGreaterThan(0);
      expect(json.sourceId).toBeDefined();
    });

    it('should validate URL format', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/scrape', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: 'not-a-valid-url',
          maxDepth: 1
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toBeDefined();
    });

    it('should limit maxDepth and maxPages', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/scrape', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: 'https://testcompany.com',
          maxDepth: 100, // Too high
          maxPages: 10000 // Too high
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toContain('maxDepth');
    });
  });

  describe('GET /api/v1/knowledge/content/:businessId', () => {
    it('should get all content for business', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'content-1',
              content_type: 'product',
              title: 'Product A',
              summary: 'Great product',
              verified: 1,
              accuracy_score: 0.95
            },
            {
              id: 'content-2',
              content_type: 'faq',
              title: 'FAQ 1',
              summary: 'Common question',
              verified: 1,
              accuracy_score: 0.92
            }
          ]
        })
      });

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ total: 2 })
      });

      const req = new Request('http://localhost/api/v1/knowledge/content/biz-123', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.content).toHaveLength(2);
    });

    it('should filter by content type', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'content-1',
              content_type: 'pricing',
              title: 'Pricing Plans'
            }
          ]
        })
      });

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ total: 1 })
      });

      const req = new Request('http://localhost/api/v1/knowledge/content/biz-123?contentType=pricing', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.content.every((c: any) => c.content_type === 'pricing')).toBe(true);
    });

    it('should paginate results', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: Array(10).fill(null).map((_, i) => ({
            id: `content-${i}`,
            content_type: 'product',
            title: `Product ${i}`
          }))
        })
      });

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ total: 25 })
      });

      const req = new Request('http://localhost/api/v1/knowledge/content/biz-123?page=1&limit=10', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.pagination).toBeDefined();
      expect(json.pagination.total).toBe(25);
      expect(json.pagination.page).toBe(1);
      expect(json.pagination.limit).toBe(10);
    });
  });

  describe('POST /api/v1/knowledge/learn-products', () => {
    it('should learn products from scraped content', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/learn-products', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sourceId: 'source-123'
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.productsAnalyzed).toBeGreaterThan(0);
    });

    it('should require source ID', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/learn-products', {
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

  describe('POST /api/v1/knowledge/analyze-brand-voice', () => {
    it('should analyze brand voice and create guideline', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/analyze-brand-voice', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sourceId: 'source-123',
          createGuideline: true
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.tone).toBeDefined();
      expect(json.guidelineCreated).toBe(true);
    });

    it('should analyze without creating guideline', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/analyze-brand-voice', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sourceId: 'source-123',
          createGuideline: false
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.guidelineCreated).toBe(false);
    });
  });

  describe('POST /api/v1/knowledge/generate-faqs', () => {
    it('should generate FAQs from content', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/generate-faqs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sourceId: 'source-123',
          maxFaqs: 10
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.faqsGenerated).toBeGreaterThan(0);
    });

    it('should limit FAQ generation', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/generate-faqs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sourceId: 'source-123',
          maxFaqs: 1000 // Too many
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toBeDefined();
    });
  });

  describe('POST /api/v1/knowledge/search', () => {
    it('should perform semantic search', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          query: 'enterprise software features',
          limit: 5
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.results).toBeInstanceOf(Array);
    });

    it('should filter search by content type', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          query: 'pricing information',
          contentType: 'pricing',
          limit: 5
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.results).toBeInstanceOf(Array);
    });

    it('should require search query', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          limit: 5
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toBeDefined();
    });
  });

  describe('POST /api/v1/knowledge/validate', () => {
    it('should validate knowledge content', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/validate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          contentIds: ['content-1', 'content-2', 'content-3']
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.validatedCount).toBeGreaterThan(0);
    });

    it('should require content IDs', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/validate', {
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

  describe('POST /api/v1/knowledge/refresh', () => {
    it('should schedule content refresh', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refreshStrategy: 'stale_content',
          daysOld: 7
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.contentsScheduled).toBeGreaterThan(0);
    });

    it('should validate refresh strategy', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refreshStrategy: 'invalid_strategy'
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(400);
      expect(json.error).toBeDefined();
    });
  });

  describe('Knowledge Sources CRUD', () => {
    it('should create knowledge source', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const req = new Request('http://localhost/api/v1/knowledge/sources', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sourceType: 'website',
          sourceUrl: 'https://testcompany.com',
          configuration: {
            maxDepth: 2,
            refreshInterval: 86400
          }
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.sourceId).toBeDefined();
    });

    it('should get all sources for business', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'source-1',
              source_type: 'website',
              source_url: 'https://testcompany.com',
              status: 'active'
            }
          ]
        })
      });

      const req = new Request('http://localhost/api/v1/knowledge/sources', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.sources).toBeInstanceOf(Array);
    });

    it('should update source configuration', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const req = new Request('http://localhost/api/v1/knowledge/sources/source-123', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          status: 'paused',
          configuration: {
            maxDepth: 3
          }
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
    });

    it('should delete knowledge source', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const req = new Request('http://localhost/api/v1/knowledge/sources/source-123', {
        method: 'DELETE'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
    });
  });

  describe('GET /api/v1/knowledge/stats/:businessId', () => {
    it('should get knowledge statistics', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          total_content: 150,
          verified_content: 120,
          avg_accuracy: 0.92,
          last_updated: new Date().toISOString()
        })
      });

      const req = new Request('http://localhost/api/v1/knowledge/stats/biz-123', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.success).toBe(true);
      expect(json.stats.totalContent).toBe(150);
      expect(json.stats.verifiedContent).toBe(120);
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

      const req = new Request('http://localhost/api/v1/knowledge/scrape', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: 'https://testcompany.com'
        })
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(json.error).toBeDefined();
    });

    it('should handle database errors gracefully', async () => {
      const mockDB = mockEnv.DB_MAIN as any;

      mockDB.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockRejectedValue(new Error('Database error'))
      });

      const req = new Request('http://localhost/api/v1/knowledge/content/biz-123', {
        method: 'GET'
      });

      const res = await app.request(req, mockEnv);
      const json = await res.json();

      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(json.error).toBeDefined();
    });
  });

  describe('Rate Limiting & Security', () => {
    it('should enforce rate limits on expensive operations', async () => {
      const requests = [];
      for (let i = 0; i < 20; i++) {
        requests.push(
          app.request(
            new Request('http://localhost/api/v1/knowledge/scrape', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                url: 'https://testcompany.com',
                maxDepth: 2
              })
            }),
            mockEnv
          )
        );
      }

      const responses = await Promise.all(requests);
      const rateLimited = responses.filter(r => r.status === 429);

      expect(rateLimited.length).toBeGreaterThan(0);
    });

    it('should sanitize URLs', async () => {
      const req = new Request('http://localhost/api/v1/knowledge/scrape', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: 'javascript:alert("XSS")',
          maxDepth: 1
        })
      });

      const res = await app.request(req, mockEnv);

      expect(res.status).toBe(400);
    });
  });
});
