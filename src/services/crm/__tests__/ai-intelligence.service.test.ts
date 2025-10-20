/**
 * AI Intelligence Service Unit Tests
 * Tests for sentiment analysis, next actions, forecasting, validation, and duplicate detection
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AIIntelligenceService } from '../ai-intelligence.service';

describe('AIIntelligenceService', () => {
  let service: AIIntelligenceService;
  let mockEnv: any;

  beforeEach(() => {
    mockEnv = {
      DB_MAIN: {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'contact-001',
              email: 'test@example.com',
              phone: '+1-555-0100',
              name: 'John Doe'
            }),
            run: vi.fn().mockResolvedValue({ success: true }),
            all: vi.fn().mockResolvedValue({ results: [] })
          })
        })
      },
      ANTHROPIC_API_KEY: 'test-key'
    };

    service = new AIIntelligenceService(mockEnv);
  });

  describe('isValidEmail', () => {
    it('should validate correct email addresses', () => {
      // @ts-ignore - testing private method
      expect(service.isValidEmail('test@example.com')).toBe(true);
      // @ts-ignore
      expect(service.isValidEmail('user.name+tag@example.co.uk')).toBe(true);
    });

    it('should reject invalid email addresses', () => {
      // @ts-ignore
      expect(service.isValidEmail('invalid')).toBe(false);
      // @ts-ignore
      expect(service.isValidEmail('no@domain')).toBe(false);
      // @ts-ignore
      expect(service.isValidEmail('@example.com')).toBe(false);
      // @ts-ignore
      expect(service.isValidEmail('test@')).toBe(false);
    });
  });

  describe('isValidPhone', () => {
    it('should validate phone numbers with various formats', () => {
      // @ts-ignore
      expect(service.isValidPhone('+1-555-0100')).toBe(true);
      // @ts-ignore
      expect(service.isValidPhone('555-0100')).toBe(false); // Too short
      // @ts-ignore
      expect(service.isValidPhone('+1 (555) 010-0100')).toBe(true);
      // @ts-ignore
      expect(service.isValidPhone('15550100100')).toBe(true);
    });

    it('should reject invalid phone numbers', () => {
      // @ts-ignore
      expect(service.isValidPhone('123')).toBe(false);
      // @ts-ignore
      expect(service.isValidPhone('abc')).toBe(false);
      // @ts-ignore
      expect(service.isValidPhone('')).toBe(false);
    });
  });

  describe('stringSimilarity', () => {
    it('should return 1.0 for identical strings', () => {
      // @ts-ignore
      const similarity = service.stringSimilarity('test', 'test');
      expect(similarity).toBe(1.0);
    });

    it('should return 0 for completely different strings', () => {
      // @ts-ignore
      const similarity = service.stringSimilarity('abc', 'xyz');
      expect(similarity).toBeLessThan(0.5);
    });

    it('should return high similarity for similar strings', () => {
      // @ts-ignore
      const similarity = service.stringSimilarity('John Smith', 'Jon Smith');
      expect(similarity).toBeGreaterThan(0.8);
    });

    it('should be case insensitive', () => {
      // @ts-ignore
      const similarity = service.stringSimilarity('TEST', 'test');
      expect(similarity).toBe(1.0);
    });

    it('should return 0 for empty strings', () => {
      // @ts-ignore
      const similarity = service.stringSimilarity('', 'test');
      expect(similarity).toBe(0);
    });
  });

  describe('levenshteinDistance', () => {
    it('should return 0 for identical strings', () => {
      // @ts-ignore
      const distance = service.levenshteinDistance('test', 'test');
      expect(distance).toBe(0);
    });

    it('should calculate single character difference', () => {
      // @ts-ignore
      const distance = service.levenshteinDistance('test', 'text');
      expect(distance).toBe(1);
    });

    it('should calculate multiple character differences', () => {
      // @ts-ignore
      const distance = service.levenshteinDistance('kitten', 'sitting');
      expect(distance).toBe(3);
    });

    it('should handle empty strings', () => {
      // @ts-ignore
      const distance = service.levenshteinDistance('', 'test');
      expect(distance).toBe(4);
    });
  });

  describe('validateData', () => {
    it('should detect invalid email format', async () => {
      mockEnv.DB_MAIN.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue({
            email: 'invalid-email',
            phone: '+1-555-0100'
          }),
          run: vi.fn().mockResolvedValue({ success: true })
        })
      });

      const issues = await service.validateData('business-001', 'contact', 'contact-001');

      expect(issues).toContainEqual(
        expect.objectContaining({
          field_name: 'email',
          issue_type: 'invalid_format'
        })
      );
    });

    it('should detect invalid phone format', async () => {
      mockEnv.DB_MAIN.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue({
            email: 'test@example.com',
            phone: '123' // Too short
          }),
          run: vi.fn().mockResolvedValue({ success: true })
        })
      });

      const issues = await service.validateData('business-001', 'contact', 'contact-001');

      expect(issues).toContainEqual(
        expect.objectContaining({
          field_name: 'phone',
          issue_type: 'invalid_format'
        })
      );
    });

    it('should detect missing contact info', async () => {
      mockEnv.DB_MAIN.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue({
            email: null,
            phone: null
          }),
          run: vi.fn().mockResolvedValue({ success: true })
        })
      });

      const issues = await service.validateData('business-001', 'contact', 'contact-001');

      expect(issues).toContainEqual(
        expect.objectContaining({
          field_name: 'contact_info',
          issue_type: 'missing_required'
        })
      );
    });

    it('should return empty array for valid data', async () => {
      mockEnv.DB_MAIN.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue({
            email: 'test@example.com',
            phone: '+1-555-0100'
          }),
          run: vi.fn().mockResolvedValue({ success: true })
        })
      });

      const issues = await service.validateData('business-001', 'contact', 'contact-001');

      expect(issues).toHaveLength(0);
    });
  });

  describe('detectDuplicates', () => {
    it('should detect duplicates with high similarity', async () => {
      mockEnv.DB_MAIN.prepare = vi.fn()
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'contact-001',
              name: 'John Smith',
              email: 'john@example.com',
              phone: '+1-555-0100'
            })
          })
        })
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({
              results: [
                {
                  id: 'contact-002',
                  name: 'Jon Smith', // Very similar
                  email: 'john@example.com',
                  phone: '+1-555-0100'
                }
              ]
            })
          })
        })
        .mockReturnValue({
          bind: vi.fn().mockReturnValue({
            run: vi.fn().mockResolvedValue({ success: true })
          })
        });

      const duplicates = await service.detectDuplicates('business-001', 'contact', 'contact-001');

      expect(duplicates.length).toBeGreaterThan(0);
      expect(duplicates[0].confidence).toBeGreaterThan(0.7);
    });

    it('should not flag contacts with low similarity', async () => {
      mockEnv.DB_MAIN.prepare = vi.fn()
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'contact-001',
              name: 'John Smith',
              email: 'john@example.com',
              phone: '+1-555-0100'
            })
          })
        })
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({
              results: [
                {
                  id: 'contact-002',
                  name: 'Jane Doe', // Completely different
                  email: 'jane@different.com',
                  phone: '+1-555-9999'
                }
              ]
            })
          })
        });

      const duplicates = await service.detectDuplicates('business-001', 'contact', 'contact-001');

      expect(duplicates).toHaveLength(0);
    });
  });
});
