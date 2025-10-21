/**
 * Knowledge Base Agent Test Suite
 * Comprehensive tests for all 10 capabilities
 * Target: 95%+ test coverage
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { KnowledgeBaseAgent } from '../knowledge-base-agent';
import type { AgentTask, BusinessContext } from '../types';

describe('KnowledgeBaseAgent', () => {
  let agent: KnowledgeBaseAgent;
  let mockEnv: any;
  let testContext: BusinessContext;

  beforeEach(() => {
    mockEnv = {
      DB_MAIN: {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnThis(),
          run: vi.fn().mockResolvedValue({ success: true }),
          first: vi.fn().mockResolvedValue(null),
          all: vi.fn().mockResolvedValue({ results: [] })
        })
      },
      ANTHROPIC_API_KEY: 'test-anthropic-key',
      OPENAI_API_KEY: 'test-openai-key',
      VECTORIZE_INDEX: {
        query: vi.fn().mockResolvedValue({ matches: [] }),
        insert: vi.fn().mockResolvedValue({ success: true }),
        upsert: vi.fn().mockResolvedValue({ success: true })
      }
    };

    agent = new KnowledgeBaseAgent(mockEnv);

    testContext = {
      userId: 'user-123',
      businessId: 'biz-123',
      organizationId: 'org-123',
      timestamp: new Date().toISOString(),
      requestId: 'req-123',
      userPermissions: ['read', 'write'],
      preferences: {},
      businessData: {
        companyName: 'Test Company',
        industry: 'Technology'
      }
    };
  });

  describe('Agent Configuration', () => {
    it('should have correct agent metadata', async () => {
      const config = await agent.getConfig();

      expect(config.id).toBe('knowledge-base-agent');
      expect(config.name).toBe('Knowledge Base Agent');
      expect(config.type).toBe('specialized');
    });

    it('should have all 10 capabilities', async () => {
      const config = await agent.getConfig();

      expect(config.capabilities).toHaveLength(10);
      expect(config.capabilities).toContain('semantic_search');
      expect(config.capabilities).toContain('article_creation');
      expect(config.capabilities).toContain('article_update');
      expect(config.capabilities).toContain('article_recommendation');
      expect(config.capabilities).toContain('content_generation');
      expect(config.capabilities).toContain('knowledge_gap_detection');
      expect(config.capabilities).toContain('article_optimization');
      expect(config.capabilities).toContain('multi_language_search');
      expect(config.capabilities).toContain('auto_categorization');
      expect(config.capabilities).toContain('related_content_linking');
    });

    it('should support multiple departments', async () => {
      const config = await agent.getConfig();

      expect(config.departments).toContain('support');
      expect(config.departments).toContain('customer_success');
    });

    it('should have reasonable cost per call', async () => {
      const config = await agent.getConfig();

      expect(config.costPerCall).toBe(0.002);
    });

    it('should estimate task cost correctly', async () => {
      const task: AgentTask = {
        id: 'task-001',
        capability: 'semantic_search',
        input: { data: { query: 'test' } },
        priority: 'normal'
      };

      const cost = await agent.estimateCost(task);
      expect(cost).toBe(0.002);
    });
  });

  describe('semantic_search capability', () => {
    it('should perform keyword search when vectorize not available', async () => {
      const noVectorEnv = { ...mockEnv, VECTORIZE_INDEX: undefined };
      const agentNoVector = new KnowledgeBaseAgent(noVectorEnv);

      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: [
            {
              id: 'art-1',
              business_id: 'biz-123',
              title: 'How to reset password',
              content: 'Step 1: Click forgot password...',
              summary: 'Password reset guide',
              category: 'account',
              tags: '["authentication","password"]',
              helpfulness: 0.9,
              views: 100,
              successful_resolutions: 50,
              language: 'en',
              status: 'published',
              visibility: 'public',
              author: 'user-123',
              metadata: '{"difficulty":"beginner","estimatedReadingTime":3,"prerequisites":[],"relatedProducts":[],"attachments":[]}',
              seo_metadata: '{"keywords":["password","reset"]}',
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z'
            }
          ]
        })
      });

      const task: AgentTask = {
        id: 'task-search-001',
        capability: 'semantic_search',
        input: {
          data: {
            query: 'reset password',
            maxResults: 10,
            minRelevance: 0.7
          }
        },
        priority: 'normal'
      };

      const result = await agentNoVector.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
    });

    it('should perform vector search when vectorize available', async () => {
      mockEnv.VECTORIZE_INDEX.query.mockResolvedValue({
        matches: [
          {
            id: 'art-1',
            score: 0.92,
            metadata: { title: 'Password Reset Guide' }
          }
        ]
      });

      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          id: 'art-1',
          business_id: 'biz-123',
          title: 'Password Reset Guide',
          content: 'Full guide...',
          summary: 'How to reset your password',
          category: 'account',
          tags: '["password"]',
          helpfulness: 0.9,
          views: 100,
          successful_resolutions: 50,
          language: 'en',
          status: 'published',
          visibility: 'public',
          author: 'user-123',
          metadata: '{}',
          seo_metadata: '{}',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z'
        })
      });

      const task: AgentTask = {
        id: 'task-vector-001',
        capability: 'semantic_search',
        input: {
          data: {
            query: 'forgot my password',
            maxResults: 5,
            minRelevance: 0.8
          }
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(mockEnv.VECTORIZE_INDEX.query).toHaveBeenCalled();
    });

    it('should filter by category', async () => {
      // Use agent without vectorize to test keyword search path
      const noVectorEnv = { ...mockEnv, VECTORIZE_INDEX: undefined };
      const agentNoVector = new KnowledgeBaseAgent(noVectorEnv);

      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-filter-001',
        capability: 'semantic_search',
        input: {
          data: {
            query: 'billing',
            category: 'billing',
            maxResults: 10
          }
        },
        priority: 'normal'
      };

      await agentNoVector.execute(task, testContext);

      expect(mockEnv.DB_MAIN.prepare).toHaveBeenCalled();
    });

    it('should respect language preference', async () => {
      // Use agent without vectorize to test keyword search path
      const noVectorEnv = { ...mockEnv, VECTORIZE_INDEX: undefined };
      const agentNoVector = new KnowledgeBaseAgent(noVectorEnv);

      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-lang-001',
        capability: 'semantic_search',
        input: {
          data: {
            query: 'help',
            language: 'es',
            maxResults: 5
          }
        },
        priority: 'normal'
      };

      await agentNoVector.execute(task, testContext);

      expect(mockEnv.DB_MAIN.prepare).toHaveBeenCalled();
    });
  });

  describe('article_creation capability', () => {
    it('should create a new article', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-create-001',
        capability: 'article_creation',
        input: {
          data: {
            title: 'Getting Started Guide',
            content: 'Welcome to our platform! Here is how to get started...',
            category: 'getting_started',
            tags: ['onboarding', 'beginner'],
            visibility: 'public',
            difficulty: 'beginner'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data).toBeDefined();
      expect(result.result.data.title).toBe('Getting Started Guide');
      expect(result.result.data.status).toBe('draft');
    });

    it('should generate slug from title', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-slug-001',
        capability: 'article_creation',
        input: {
          data: {
            title: 'How to Reset Your Password?',
            content: 'Password reset instructions...',
            category: 'account'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.slug).toBe('how-to-reset-your-password');
    });

    it('should calculate reading time from content', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const longContent = new Array(600).fill('word').join(' ');

      const task: AgentTask = {
        id: 'task-time-001',
        capability: 'article_creation',
        input: {
          data: {
            title: 'Long Article',
            content: longContent,
            category: 'advanced'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.metadata.estimatedReadingTime).toBeGreaterThan(0);
    });

    it('should generate vector embedding when vectorize available', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-embed-001',
        capability: 'article_creation',
        input: {
          data: {
            title: 'Test Article',
            content: 'Content for embedding...',
            category: 'technical'
          }
        },
        priority: 'normal'
      };

      await agent.execute(task, testContext);

      expect(mockEnv.VECTORIZE_INDEX.insert).toHaveBeenCalled();
    });
  });

  describe('article_update capability', () => {
    it('should update existing article', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          id: 'art-1',
          business_id: 'biz-123',
          title: 'Old Title',
          content: 'Old content',
          summary: 'Old summary',
          category: 'technical',
          tags: '[]',
          helpfulness: 0.5,
          views: 10,
          successful_resolutions: 5,
          language: 'en',
          status: 'published',
          visibility: 'public',
          author: 'user-123',
          metadata: '{}',
          seo_metadata: '{}',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z'
        })
      }).mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-update-001',
        capability: 'article_update',
        input: {
          data: {
            articleId: 'art-1',
            updates: {
              title: 'New Title',
              content: 'Updated content'
            }
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.title).toBe('New Title');
      expect(result.result.data.updatedAt).toBeDefined();
    });

    it('should regenerate embedding when content changes', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          id: 'art-1',
          business_id: 'biz-123',
          title: 'Title',
          content: 'Old content',
          summary: 'Summary',
          category: 'technical',
          tags: '[]',
          helpfulness: 0.5,
          views: 10,
          successful_resolutions: 5,
          language: 'en',
          status: 'published',
          visibility: 'public',
          author: 'user-123',
          metadata: '{}',
          seo_metadata: '{}',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z'
        })
      }).mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({ success: true })
      });

      const task: AgentTask = {
        id: 'task-embed-update-001',
        capability: 'article_update',
        input: {
          data: {
            articleId: 'art-1',
            updates: {
              content: 'Brand new content that needs new embedding'
            }
          }
        },
        priority: 'normal'
      };

      await agent.execute(task, testContext);

      expect(mockEnv.VECTORIZE_INDEX.upsert).toHaveBeenCalled();
    });

    it('should throw error if article not found', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue(null)
      });

      const task: AgentTask = {
        id: 'task-not-found-001',
        capability: 'article_update',
        input: {
          data: {
            articleId: 'nonexistent',
            updates: { title: 'New' }
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.message).toContain('not found');
    });
  });

  describe('article_recommendation capability', () => {
    it('should recommend articles based on ticket', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          subject: 'Cannot login',
          description: 'I forgot my password'
        })
      }).mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-recommend-001',
        capability: 'article_recommendation',
        input: {
          data: {
            ticketId: 'ticket-123',
            maxResults: 5
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
    });

    it('should recommend articles based on custom query', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-custom-001',
        capability: 'article_recommendation',
        input: {
          data: {
            customQuery: 'billing issues',
            maxResults: 3
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
    });
  });

  describe('content_generation capability', () => {
    it('should generate article content using AI', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [
            {
              text: '# How to Set Up Two-Factor Authentication\n\nTwo-factor authentication (2FA) adds an extra layer of security...'
            }
          ]
        })
      });

      const task: AgentTask = {
        id: 'task-gen-001',
        capability: 'content_generation',
        input: {
          data: {
            topic: 'Two-factor authentication setup',
            tone: 'professional',
            length: 'medium'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.content).toBeDefined();
      expect(result.result.data.summary).toBeDefined();
    });

    it('should throw error if no AI key configured', async () => {
      const noAIEnv = { ...mockEnv, ANTHROPIC_API_KEY: undefined };
      const agentNoAI = new KnowledgeBaseAgent(noAIEnv);

      const task: AgentTask = {
        id: 'task-no-ai-001',
        capability: 'content_generation',
        input: {
          data: {
            topic: 'Test topic'
          }
        },
        priority: 'normal'
      };

      const result = await agentNoAI.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.message).toContain('requires Anthropic API key');
    });

    it('should respect tone parameter', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [{ text: 'Generated content' }]
        })
      });

      const task: AgentTask = {
        id: 'task-tone-001',
        capability: 'content_generation',
        input: {
          data: {
            topic: 'API Documentation',
            tone: 'technical',
            length: 'long'
          }
        },
        priority: 'normal'
      };

      await agent.execute(task, testContext);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.anthropic.com/v1/messages',
        expect.objectContaining({
          method: 'POST'
        })
      );
    });
  });

  describe('knowledge_gap_detection capability', () => {
    it('should detect knowledge gaps', async () => {
      const task: AgentTask = {
        id: 'task-gap-001',
        capability: 'knowledge_gap_detection',
        input: {
          data: {}
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.gaps).toBeDefined();
      expect(result.result.data.suggestedArticles).toBeDefined();
    });

    it('should suggest articles based on unresolved queries', async () => {
      const task: AgentTask = {
        id: 'task-suggest-001',
        capability: 'knowledge_gap_detection',
        input: {
          data: {}
        },
        priority: 'high'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.data.suggestedArticles).toBeInstanceOf(Array);
    });
  });

  describe('article_optimization capability', () => {
    it('should optimize article with AI suggestions', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          id: 'art-1',
          business_id: 'biz-123',
          title: 'Article Title',
          content: 'Article content...',
          summary: 'Summary',
          category: 'technical',
          tags: '[]',
          helpfulness: 0.6,
          views: 50,
          successful_resolutions: 20,
          language: 'en',
          status: 'published',
          visibility: 'public',
          author: 'user-123',
          metadata: '{}',
          seo_metadata: '{}',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z'
        })
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [
            {
              text: '{"titleSuggestion": "Better Title", "contentImprovements": ["Add examples"]}'
            }
          ]
        })
      });

      const task: AgentTask = {
        id: 'task-optimize-001',
        capability: 'article_optimization',
        input: {
          data: {
            articleId: 'art-1'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.articleId).toBe('art-1');
      expect(result.result.data.suggestions).toBeDefined();
    });
  });

  describe('multi_language_search capability', () => {
    it('should perform multi-language search', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-multi-lang-001',
        capability: 'multi_language_search',
        input: {
          data: {
            query: 'ayuda',
            language: 'es'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
    });
  });

  describe('auto_categorization capability', () => {
    it('should auto-categorize content', async () => {
      const task: AgentTask = {
        id: 'task-cat-001',
        capability: 'auto_categorization',
        input: {
          data: {
            content: 'This article explains how to troubleshoot connection errors...'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.category).toBeDefined();
      expect(result.result.data.confidence).toBeGreaterThan(0);
      expect(result.result.data.suggestedTags).toBeDefined();
    });
  });

  describe('related_content_linking capability', () => {
    it('should find related articles', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValueOnce({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({
          id: 'art-1',
          business_id: 'biz-123',
          title: 'Password Reset',
          content: 'How to reset...',
          summary: 'Reset guide',
          category: 'account',
          tags: '[]',
          helpfulness: 0.8,
          views: 100,
          successful_resolutions: 50,
          language: 'en',
          status: 'published',
          visibility: 'public',
          author: 'user-123',
          metadata: '{}',
          seo_metadata: '{}',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z'
        })
      }).mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-related-001',
        capability: 'related_content_linking',
        input: {
          data: {
            articleId: 'art-1'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('completed');
      expect(result.result.data.articleId).toBe('art-1');
      expect(result.result.data.relatedArticles).toBeDefined();
    });

    it('should throw error if article not found', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue(null)
      });

      const task: AgentTask = {
        id: 'task-404-001',
        capability: 'related_content_linking',
        input: {
          data: {
            articleId: 'nonexistent'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.message).toContain('not found');
    });
  });

  describe('Error Handling', () => {
    it('should handle unsupported capability', async () => {
      const task: AgentTask = {
        id: 'task-unsupported-001',
        capability: 'invalid_capability' as any,
        input: { data: {} },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.code).toBe('EXECUTION_FAILED');
      expect(result.error?.message).toContain('Unsupported capability');
    });

    it('should include execution time in error response', async () => {
      const task: AgentTask = {
        id: 'task-error-001',
        capability: 'invalid' as any,
        input: { data: {} },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics.executionTime).toBeGreaterThanOrEqual(0);
      expect(result.metrics).toHaveProperty('executionTime');
    });

    it('should handle database errors gracefully', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockRejectedValue(new Error('Database connection failed'))
      });

      const task: AgentTask = {
        id: 'task-db-error-001',
        capability: 'article_creation',
        input: {
          data: {
            title: 'Test',
            content: 'Content',
            category: 'technical'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.status).toBe('failed');
      expect(result.error?.retryable).toBe(true);
    });
  });

  describe('Performance', () => {
    it('should complete semantic search quickly', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-perf-001',
        capability: 'semantic_search',
        input: {
          data: {
            query: 'test',
            maxResults: 5
          }
        },
        priority: 'normal'
      };

      const startTime = Date.now();
      const result = await agent.execute(task, testContext);
      const duration = Date.now() - startTime;

      expect(result.status).toBe('completed');
      expect(duration).toBeLessThan(5000); // Should complete in under 5 seconds
    });
  });

  describe('Metrics', () => {
    it('should track execution metrics', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-metrics-001',
        capability: 'semantic_search',
        input: {
          data: {
            query: 'test'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.metrics).toBeDefined();
      expect(result.metrics.executionTime).toBeGreaterThanOrEqual(0);
      expect(result.metrics).toHaveProperty('costUSD');
      expect(result.metrics.costUSD).toBe(0.002);
      expect(result.metrics.retryCount).toBe(0);
    });

    it('should include confidence and reasoning in result', async () => {
      mockEnv.DB_MAIN.prepare.mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      const task: AgentTask = {
        id: 'task-conf-001',
        capability: 'semantic_search',
        input: {
          data: {
            query: 'test'
          }
        },
        priority: 'normal'
      };

      const result = await agent.execute(task, testContext);

      expect(result.result.confidence).toBeGreaterThan(0);
      expect(result.result.reasoning).toBeDefined();
    });
  });
});
