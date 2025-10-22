/**
 * CRM API Integration Tests
 * End-to-end tests for all CRM API endpoints
 */

import { describe, it, expect, beforeAll } from 'vitest';

const API_BASE_URL = process.env.TEST_API_URL || 'http://localhost:8790/api/v1';
const BUSINESS_ID = 'business-test-001';
const USER_ID = 'user-test-001';

describe('CRM API Integration Tests', () => {
  const headers = {
    'Content-Type': 'application/json',
    'X-Business-ID': BUSINESS_ID,
    'X-User-ID': USER_ID
  };

  describe('Lead Scoring API', () => {
    it('should create a scoring model', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/lead-scoring/models`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model_name: 'Test Model',
          model_type: 'rule_based',
          feature_weights: {
            seniority: 0.3,
            company_size: 0.3,
            engagement: 0.4
          },
          conversion_threshold: 70
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('id');
    });

    it('should list all scoring models', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/lead-scoring/models`, {
        method: 'GET',
        headers
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(Array.isArray(data.data)).toBe(true);
    });

    it('should add a scoring rule', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/lead-scoring/rules`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model_id: 'model-test-001',
          rule_name: 'C-Level Boost',
          rule_type: 'demographic',
          field_name: 'job_title',
          operator: 'contains',
          field_value: 'CEO',
          points_if_match: 30,
          weight: 1.0
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
    });
  });

  describe('Enrichment API', () => {
    it('should queue contact for enrichment', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/enrichment/queue`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          contact_id: 'contact-test-001',
          priority: 80,
          preferred_sources: ['hunter', 'clearbit']
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
    });

    it('should get queue status', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/enrichment/queue/status`, {
        method: 'GET',
        headers
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('pending_count');
    });

    it('should save enrichment credentials', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/enrichment/credentials`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          data_source: 'hunter',
          api_key: 'test_hunter_api_key',
          monthly_quota: 1000
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
    });
  });

  describe('Deal Health API', () => {
    it('should track engagement event', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/deal-health/deal-test-001/events`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          event_type: 'meeting_completed',
          stakeholder_id: 'contact-test-001',
          sales_rep_id: USER_ID,
          engagement_value: 10
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
    });

    it('should calculate deal health', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/deal-health/deal-test-001/calculate`, {
        method: 'POST',
        headers
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('health_score');
      expect(data.data).toHaveProperty('win_probability');
    });

    it('should get at-risk deals', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/deal-health/at-risk`, {
        method: 'GET',
        headers
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(Array.isArray(data.data)).toBe(true);
    });
  });

  describe('AI Intelligence API', () => {
    it('should analyze sentiment', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/ai/sentiment`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          activity_id: 'activity-test-001',
          text: 'I am very excited about this opportunity and looking forward to working together!'
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('sentiment');
    });

    it('should generate next best actions', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/ai/next-actions`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          entity_type: 'deal',
          entity_id: 'deal-test-001'
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(Array.isArray(data.data)).toBe(true);
    });

    it('should generate revenue forecast', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/ai/forecast`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          period: 'Q1-2025',
          forecast_type: 'quarterly'
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('forecasted_revenue');
    });

    it('should validate data quality', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/ai/validate/contact/contact-test-001`, {
        method: 'POST',
        headers
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('issues');
    });

    it('should detect duplicates', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/ai/duplicates/contact/contact-test-001`, {
        method: 'POST',
        headers
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(Array.isArray(data.data)).toBe(true);
    });
  });

  describe('Relationship Graph API', () => {
    it('should create a relationship', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/relationships`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          source_id: 'contact-001',
          source_type: 'contact',
          target_id: 'contact-002',
          target_type: 'contact',
          relationship_type: 'peer_of',
          strength_score: 75
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
    });

    it('should find warm intro path', async () => {
      const response = await fetch(
        `${API_BASE_URL}/crm/relationships/path/contact-001/contact-003?maxHops=3`,
        {
          method: 'GET',
          headers
        }
      );

      const data = await response.json();
      // May return 404 if no path found - that's OK for test
      expect([200, 404]).toContain(response.status);
    });
  });

  describe('Job Change & Intent Signals API', () => {
    it('should check for job changes', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/job-changes/check/contact-test-001`, {
        method: 'POST',
        headers
      });

      const data = await response.json();
      expect(data).toHaveProperty('success');
    });

    it('should get recent job changes', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/job-changes/recent?days=30`, {
        method: 'GET',
        headers
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(Array.isArray(data.data)).toBe(true);
    });

    it('should track intent signal', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/intent-signals`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          entity_type: 'company',
          entity_id: 'company-test-001',
          signal_type: 'pricing_page_view',
          signal_source: 'website_analytics',
          intent_score: 85,
          topic: 'CRM Software',
          url: 'https://example.com/pricing'
        })
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
    });

    it('should get high intent signals', async () => {
      const response = await fetch(`${API_BASE_URL}/crm/intent-signals/high-intent`, {
        method: 'GET',
        headers
      });

      const data = await response.json();
      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(Array.isArray(data.data)).toBe(true);
    });
  });
});
