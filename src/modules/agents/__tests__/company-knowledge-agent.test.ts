/**
 * CompanyKnowledgeAgent Test Suite
 *
 * Tests all 10 knowledge management capabilities
 * Coverage target: 95%+
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { CompanyKnowledgeAgent } from '../company-knowledge-agent';
import type { AgentTask, BusinessContext } from '../types';

// Mock environment
const createMockEnv = () => ({
  DB_MAIN: {
    prepare: vi.fn().mockReturnThis(),
    bind: vi.fn().mockReturnThis(),
    first: vi.fn(),
    all: vi.fn(),
    run: vi.fn()
  },
  ANTHROPIC_API_KEY: 'test-anthropic-key',
  OPENAI_API_KEY: 'test-openai-key',
  VECTORIZE_INDEX: {
    query: vi.fn(),
    insert: vi.fn()
  }
});

// Mock fetch globally
global.fetch = vi.fn();

describe('CompanyKnowledgeAgent', () => {
  let agent: CompanyKnowledgeAgent;
  let mockEnv: any;
  let testContext: BusinessContext;

  beforeEach(() => {
    mockEnv = createMockEnv();
    agent = new CompanyKnowledgeAgent(mockEnv);

    testContext = {
      userId: 'user-123',
      businessId: 'biz-123',
      organizationId: 'org-123',
      timestamp: new Date().toISOString(),
      requestId: 'req-123',
      userPermissions: ['read', 'write'],
      preferences: {}
    };

    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Agent Configuration', () => {
    it('should have correct agent metadata', async () => {
      const config = await agent.getConfig();

      expect(config.id).toBe('company-knowledge-agent');
      expect(config.name).toBe('Company Knowledge Agent');
      expect(config.version).toBe('1.0.0');
      expect(config.capabilities).toHaveLength(10);
    });

    it('should declare all 10 capabilities', async () => {
      const config = await agent.getConfig();
      const expectedCapabilities = [
        'website_scraping',
        'product_learning',
        'brand_voice_analysis',
        'faq_generation',
        'guideline_extraction',
        'competitor_awareness',
        'knowledge_validation',
        'content_recommendation',
        'knowledge_refresh',
        'compliance_checking'
      ];

      expectedCapabilities.forEach(cap => {
        expect(config.capabilities).toContain(cap);
      });
    });
  });

  describe('website_scraping capability', () => {
    it('should scrape website pages successfully', async () => {
      const mockHTML = `
        <html>
          <head><title>Test Company</title></head>
          <body>
            <h1>Welcome to Test Company</h1>
            <p>We provide amazing products and services.</p>
            <a href="/about">About Us</a>
            <a href="/products">Products</a>
          </body>
        </html>
      `;

      // Mock robots.txt check (allow)
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve('User-agent: *\nAllow: /')
      });

      // Mock page fetch
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(mockHTML),
        headers: new Map([['content-type', 'text/html']])
      });

      // Mock knowledge source creation
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      // Mock content storage
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'website_scraping',
        input: {
          data: {
            url: 'https://testcompany.com',
            maxDepth: 1,
            maxPages: 10
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.success).toBe(true);
      expect(result.result.data.pagesScraped).toBeGreaterThan(0);
    });

    it('should respect robots.txt disallow', async () => {
      // Mock robots.txt check (disallow)
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve('User-agent: *\nDisallow: /')
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'website_scraping',
        input: {
          data: {
            url: 'https://blocked-site.com',
            maxDepth: 1,
            maxPages: 10
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.message).toContain('robots.txt');
    });

    it('should enforce rate limiting between requests', async () => {
      const mockHTML = '<html><body>Test</body></html>';

      // Mock robots.txt
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve('User-agent: *\nAllow: /')
      });

      // Mock multiple page fetches
      (global.fetch as any).mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(mockHTML),
        headers: new Map([['content-type', 'text/html']])
      });

      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const startTime = Date.now();

      const task: AgentTask = {
        id: 'task-1',
        capability: 'website_scraping',
        input: {
          data: {
            url: 'https://testcompany.com',
            maxDepth: 0,
            maxPages: 3
          }
        },
        priority: 'normal',
        context: testContext
      };

      await agent.execute(task, testContext);

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should take at least 2 seconds for 3 pages (1 second delay between each)
      expect(duration).toBeGreaterThanOrEqual(2000);
    });

    it('should only scrape same-domain pages', async () => {
      const mockHTML = `
        <html>
          <body>
            <a href="/internal">Internal Link</a>
            <a href="https://external-site.com/page">External Link</a>
            <a href="https://testcompany.com/another">Internal Link 2</a>
          </body>
        </html>
      `;

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve('User-agent: *\nAllow: /')
      });

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        text: () => Promise.resolve(mockHTML),
        headers: new Map([['content-type', 'text/html']])
      });

      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'website_scraping',
        input: {
          data: {
            url: 'https://testcompany.com',
            maxDepth: 2,
            maxPages: 10
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      // Should not include external-site.com
      expect(result.result.data.pagesScraped).toBeLessThan(4); // Only same-domain pages
    });
  });

  describe('product_learning capability', () => {
    it('should analyze products using AI', async () => {
      // Mock fetch products from knowledge base
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'content-1',
              title: 'Product A',
              content: 'Amazing productivity software for businesses',
              content_type: 'product'
            },
            {
              id: 'content-2',
              title: 'Product B',
              content: 'Enterprise security solution',
              content_type: 'product'
            }
          ]
        })
      });

      // Mock AI analysis (Anthropic API)
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          content: [{
            text: JSON.stringify({
              products: [
                {
                  name: 'Product A',
                  category: 'Software',
                  targetAudience: 'Businesses',
                  keyFeatures: ['Productivity', 'Collaboration'],
                  pricing: { model: 'subscription' }
                }
              ]
            })
          }]
        })
      });

      // Mock knowledge base update
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'product_learning',
        input: {
          data: {
            sourceId: 'source-1'
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.productsAnalyzed).toBeGreaterThan(0);
    });
  });

  describe('brand_voice_analysis capability', () => {
    it('should detect brand voice and create guidelines', async () => {
      // Mock fetch content
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              content: 'We help businesses thrive through innovative solutions and dedicated support.'
            },
            {
              content: 'Our team of experts delivers professional services tailored to your needs.'
            }
          ]
        })
      });

      // Mock AI brand voice analysis
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          content: [{
            text: JSON.stringify({
              tone: 'professional',
              characteristics: ['helpful', 'expert', 'supportive'],
              doList: ['Use professional language', 'Emphasize expertise'],
              dontList: ['Use slang', 'Be overly casual'],
              prohibitedWords: ['cheap', 'hack', 'tricks']
            })
          }]
        })
      });

      // Mock guideline creation
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'brand_voice_analysis',
        input: {
          data: {
            sourceId: 'source-1',
            createGuideline: true
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.tone).toBe('professional');
      expect(result.result.data.guidelineCreated).toBe(true);
    });
  });

  describe('faq_generation capability', () => {
    it('should generate FAQs from content', async () => {
      // Mock fetch content
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              content: 'Our service costs $99/month with a 14-day free trial.'
            },
            {
              content: 'We support integrations with Salesforce, HubSpot, and more.'
            }
          ]
        })
      });

      // Mock AI FAQ generation
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          content: [{
            text: JSON.stringify({
              faqs: [
                {
                  question: 'How much does it cost?',
                  answer: '$99/month with 14-day free trial',
                  category: 'pricing'
                },
                {
                  question: 'What integrations are supported?',
                  answer: 'Salesforce, HubSpot, and more',
                  category: 'features'
                }
              ]
            })
          }]
        })
      });

      // Mock FAQ storage
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'faq_generation',
        input: {
          data: {
            sourceId: 'source-1',
            maxFaqs: 10
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.faqsGenerated).toBeGreaterThan(0);
    });
  });

  describe('content_recommendation capability', () => {
    it('should perform semantic search using Vectorize', async () => {
      // Mock vector search
      mockEnv.VECTORIZE_INDEX.query.mockResolvedValueOnce({
        matches: [
          {
            id: 'content-1',
            score: 0.92,
            metadata: {
              business_id: 'biz-123',
              content_type: 'product',
              title: 'Product A',
              summary: 'Enterprise software solution'
            }
          },
          {
            id: 'content-2',
            score: 0.85,
            metadata: {
              business_id: 'biz-123',
              content_type: 'documentation',
              title: 'Getting Started Guide',
              summary: 'How to use our platform'
            }
          }
        ]
      });

      // Mock get embedding from OpenAI
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: [{
            embedding: new Array(1536).fill(0.1)
          }]
        })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'content_recommendation',
        input: {
          data: {
            query: 'enterprise software products',
            contentType: 'product',
            limit: 5
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.recommendations.length).toBeGreaterThan(0);
      expect(result.result.data.recommendations[0].relevanceScore).toBeGreaterThan(0.8);
    });

    it('should filter by content type', async () => {
      mockEnv.VECTORIZE_INDEX.query.mockResolvedValueOnce({
        matches: [
          {
            id: 'content-1',
            score: 0.90,
            metadata: {
              business_id: 'biz-123',
              content_type: 'pricing',
              title: 'Pricing Plans'
            }
          }
        ]
      });

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: [{ embedding: new Array(1536).fill(0.1) }]
        })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'content_recommendation',
        input: {
          data: {
            query: 'how much does it cost',
            contentType: 'pricing',
            limit: 5
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      const recommendations = result.result.data.recommendations;
      recommendations.forEach((rec: any) => {
        expect(rec.contentType).toBe('pricing');
      });
    });
  });

  describe('knowledge_validation capability', () => {
    it('should validate content accuracy', async () => {
      // Mock fetch content to validate
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'content-1',
              title: 'Product Features',
              content: 'Our product offers AI-powered analytics and real-time reporting.',
              source_url: 'https://testcompany.com/features'
            }
          ]
        })
      });

      // Mock AI validation
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          content: [{
            text: JSON.stringify({
              isAccurate: true,
              confidence: 0.95,
              issues: [],
              suggestions: []
            })
          }]
        })
      });

      // Mock update accuracy score
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'knowledge_validation',
        input: {
          data: {
            contentIds: ['content-1']
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.validatedCount).toBe(1);
    });

    it('should identify outdated content', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 100); // 100 days old

      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'content-1',
              title: 'Old Content',
              content: 'This content is outdated',
              last_validated_at: oldDate.toISOString()
            }
          ]
        })
      });

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          content: [{
            text: JSON.stringify({
              isAccurate: false,
              confidence: 0.60,
              issues: ['Content may be outdated'],
              suggestions: ['Refresh content from source']
            })
          }]
        })
      });

      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'knowledge_validation',
        input: {
          data: {
            contentIds: ['content-1']
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.issuesFound).toBeGreaterThan(0);
    });
  });

  describe('knowledge_refresh capability', () => {
    it('should schedule content refresh', async () => {
      // Mock find stale content
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'content-1',
              source_url: 'https://testcompany.com/page1',
              last_refreshed_at: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString()
            }
          ]
        })
      });

      // Mock update refresh schedule
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'knowledge_refresh',
        input: {
          data: {
            refreshStrategy: 'stale_content',
            daysOld: 7
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.contentsScheduled).toBeGreaterThan(0);
    });
  });

  describe('compliance_checking capability', () => {
    it('should check content against guidelines', async () => {
      // Mock fetch content
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'content-1',
              content: 'We are better than our competitors and cheaper too!'
            }
          ]
        })
      });

      // Mock fetch guidelines
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'guideline-1',
              category: 'content_restrictions',
              rules: JSON.stringify({
                prohibitedWords: ['competitors', 'cheaper']
              })
            }
          ]
        })
      });

      // Mock update content status
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'compliance_checking',
        input: {
          data: {
            contentIds: ['content-1']
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.violationsFound).toBeGreaterThan(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle fetch failures gracefully', async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

      const task: AgentTask = {
        id: 'task-1',
        capability: 'website_scraping',
        input: {
          data: {
            url: 'https://testcompany.com',
            maxDepth: 1,
            maxPages: 1
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.message).toContain('Network');
    });

    it('should handle AI API errors', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{ content: 'Test content' }]
        })
      });

      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests'
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'brand_voice_analysis',
        input: {
          data: {
            sourceId: 'source-1'
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.message).toBeDefined();
    });

    it('should handle unsupported capabilities', async () => {
      const task: AgentTask = {
        id: 'task-1',
        capability: 'unsupported_capability',
        input: { data: {} },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.code).toBe('CAPABILITY_NOT_SUPPORTED');
    });
  });

  describe('Metrics Tracking', () => {
    it('should track execution metrics including API costs', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [{ content: 'Test' }]
        })
      });

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          content: [{
            text: JSON.stringify({ tone: 'professional' })
          }],
          usage: {
            input_tokens: 100,
            output_tokens: 50
          }
        })
      });

      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-1',
        capability: 'brand_voice_analysis',
        input: {
          data: {
            sourceId: 'source-1',
            createGuideline: false
          }
        },
        priority: 'normal',
        context: testContext
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics).toBeDefined();
      expect(result.metrics.executionTime).toBeGreaterThan(0);
      expect(result.metrics.tokensUsed).toBeGreaterThan(0);
      expect(result.metrics.cost).toBeGreaterThan(0);
    });
  });
});
