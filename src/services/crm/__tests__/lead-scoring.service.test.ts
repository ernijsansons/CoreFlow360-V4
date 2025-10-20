/**
 * Lead Scoring Service Unit Tests
 * Tests for ML-powered lead scoring functionality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { LeadScoringService } from '../lead-scoring.service';

describe('LeadScoringService', () => {
  let service: LeadScoringService;
  let mockEnv: any;

  beforeEach(() => {
    // Mock Cloudflare environment
    mockEnv = {
      DB_MAIN: {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'model-001',
              model_name: 'Default Model',
              model_type: 'ml_regression',
              feature_weights: JSON.stringify({
                seniority: 0.3,
                company_size: 0.25,
                engagement: 0.3,
                data_quality: 0.15
              }),
              conversion_threshold: 70,
              status: 'active',
              workers_ai_model: '@cf/meta/llama-3-8b-instruct'
            }),
            run: vi.fn().mockResolvedValue({ success: true }),
            all: vi.fn().mockResolvedValue({ results: [] })
          })
        })
      },
      AI: {
        run: vi.fn().mockResolvedValue({
          response: JSON.stringify({
            score: 85,
            reasoning: 'High score due to C-level title',
            primary_drivers: ['C-level executive', 'Large company'],
            negative_factors: []
          })
        })
      }
    };

    service = new LeadScoringService(mockEnv);
  });

  describe('calculateLeadScore', () => {
    it('should calculate lead score successfully', async () => {
      const result = await service.calculateLeadScore(
        'business-001',
        'contact-001',
        'contact'
      );

      expect(result).toBeDefined();
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
      expect(result.confidence_level).toMatch(/low|medium|high|very_high/);
    });

    it('should throw error if no active model found', async () => {
      mockEnv.DB_MAIN.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue(null)
        })
      });

      await expect(
        service.calculateLeadScore('business-001', 'contact-001', 'contact')
      ).rejects.toThrow('No active scoring model found');
    });
  });

  describe('scoreSeniority', () => {
    it('should score C-level as 100', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore - accessing private method for testing
      const score = service.scoreSeniority('c_level');
      expect(score).toBe(100);
    });

    it('should score VP as 85', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const score = service.scoreSeniority('vp');
      expect(score).toBe(85);
    });

    it('should score manager as 55', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const score = service.scoreSeniority('manager');
      expect(score).toBe(55);
    });

    it('should default to 50 for unknown seniority', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const score = service.scoreSeniority('unknown');
      expect(score).toBe(50);
    });
  });

  describe('scoreCompanySize', () => {
    it('should score 10000+ employees as 100', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const score = service.scoreCompanySize(15000);
      expect(score).toBe(100);
    });

    it('should score 1000+ employees as 85', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const score = service.scoreCompanySize(2500);
      expect(score).toBe(85);
    });

    it('should score 200+ employees as 70', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const score = service.scoreCompanySize(500);
      expect(score).toBe(70);
    });

    it('should score small companies lower', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const score = service.scoreCompanySize(5);
      expect(score).toBeLessThan(50);
    });
  });

  describe('scoreToConversionProbability', () => {
    it('should convert high score (80) to high probability', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const prob = service.scoreToConversionProbability(80);
      expect(prob).toBeGreaterThan(0.7);
      expect(prob).toBeLessThanOrEqual(1.0);
    });

    it('should convert medium score (50) to medium probability', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const prob = service.scoreToConversionProbability(50);
      expect(prob).toBeGreaterThan(0.4);
      expect(prob).toBeLessThan(0.7);
    });

    it('should convert low score (20) to low probability', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      const prob = service.scoreToConversionProbability(20);
      expect(prob).toBeLessThan(0.4);
    });
  });

  describe('evaluateRule', () => {
    it('should evaluate equals operator correctly', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      expect(service.evaluateRule('test', 'equals', 'test')).toBe(true);
      // @ts-ignore
      expect(service.evaluateRule('test', 'equals', 'other')).toBe(false);
    });

    it('should evaluate contains operator correctly', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      expect(service.evaluateRule('Software Engineer', 'contains', 'Engineer')).toBe(true);
      // @ts-ignore
      expect(service.evaluateRule('Manager', 'contains', 'Engineer')).toBe(false);
    });

    it('should evaluate greater_than operator correctly', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      expect(service.evaluateRule(100, 'greater_than', '50')).toBe(true);
      // @ts-ignore
      expect(service.evaluateRule(25, 'greater_than', '50')).toBe(false);
    });

    it('should evaluate in_list operator correctly', () => {
      const service = new LeadScoringService(mockEnv);
      // @ts-ignore
      expect(service.evaluateRule('VP', 'in_list', 'CEO, VP, Director')).toBe(true);
      // @ts-ignore
      expect(service.evaluateRule('Manager', 'in_list', 'CEO, VP, Director')).toBe(false);
    });
  });
});
