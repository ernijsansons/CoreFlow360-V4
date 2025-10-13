import { describe, it, expect, vi, beforeEach } from 'vitest'
import { crmDataQualityService } from '../crm-data-quality.service'
import apiClient from '../../client'

vi.mock('../../client')

describe('CRM Data Quality Service', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('findDuplicates', () => {
    it('should find duplicates for a specific entity', async () => {
      const mockResponse = {
        data: {
          matches: [
            {
              id: 'match-1',
              entity_type: 'contact',
              primary_id: 'contact-1',
              duplicate_ids: ['contact-2', 'contact-3'],
              confidence_score: 95,
            },
          ],
          count: 1,
          high_confidence: 1,
          auto_merge_eligible: 1,
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await crmDataQualityService.findDuplicates({
        entity_type: 'contact',
        entity_id: 'contact-1',
        threshold: 80,
      })

      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/crm/data-quality/duplicates/find',
        {
          entity_type: 'contact',
          entity_id: 'contact-1',
          threshold: 80,
        }
      )
      expect(result.data.matches).toHaveLength(1)
      expect(result.data.matches[0].confidence_score).toBe(95)
    })
  })

  describe('mergeDuplicates', () => {
    it('should merge duplicate entities', async () => {
      const mockResponse = {
        data: { success: true, merged_id: 'contact-1' },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await crmDataQualityService.mergeDuplicates({
        entity_type: 'contact',
        primary_id: 'contact-1',
        duplicate_ids: ['contact-2', 'contact-3'],
        merge_strategy: 'most_complete',
      })

      expect(apiClient.post).toHaveBeenCalledWith('/api/crm/data-quality/duplicates/merge', {
        entity_type: 'contact',
        primary_id: 'contact-1',
        duplicate_ids: ['contact-2', 'contact-3'],
        merge_strategy: 'most_complete',
      })
      expect(result.data.success).toBe(true)
    })
  })

  describe('validateEntity', () => {
    it('should validate entity data quality', async () => {
      const mockResponse = {
        data: {
          quality_score: {
            overall_score: 85,
            completeness_score: 90,
            accuracy_score: 85,
            freshness_score: 80,
            consistency_score: 85,
            issues_count: 1,
            critical_issues_count: 0,
          },
          issues: [
            {
              id: 'issue-1',
              entity_type: 'contact',
              entity_id: 'contact-1',
              field_name: 'email',
              severity: 'medium',
              issue_type: 'invalid_format',
              description: 'Email format is invalid',
              auto_fixable: true,
              resolved: false,
              detected_at: '2025-10-12T10:00:00Z',
            },
          ],
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await crmDataQualityService.validateEntity({
        entity_type: 'contact',
        entity_id: 'contact-1',
      })

      expect(apiClient.post).toHaveBeenCalledWith('/api/crm/data-quality/validate', {
        entity_type: 'contact',
        entity_id: 'contact-1',
      })
      expect(result.data.quality_score.overall_score).toBe(85)
      expect(result.data.issues).toHaveLength(1)
    })
  })

  describe('autoFixIssues', () => {
    it('should auto-fix data quality issues', async () => {
      const mockResponse = {
        data: {
          fixed_count: 5,
          message: 'Successfully fixed 5 issues',
        },
        success: true,
      }

      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await crmDataQualityService.autoFixIssues({
        entity_type: 'contact',
        entity_id: 'contact-1',
      })

      expect(apiClient.post).toHaveBeenCalledWith('/api/crm/data-quality/auto-fix', {
        entity_type: 'contact',
        entity_id: 'contact-1',
      })
      expect(result.data.fixed_count).toBe(5)
      expect(result.data.message).toBe('Successfully fixed 5 issues')
    })
  })

  describe('getDashboard', () => {
    it('should get dashboard summary', async () => {
      const mockResponse = {
        data: {
          quality_summary: [
            {
              entity_type: 'contact',
              overall_score: 82,
              total_issues: 45,
              critical_issues: 3,
            },
          ],
          duplicate_summary: [
            {
              entity_type: 'contact',
              pending_duplicates: 12,
              auto_merge_eligible: 8,
            },
          ],
          recent_issues: [],
        },
        success: true,
      }

      vi.mocked(apiClient.get).mockResolvedValue(mockResponse)

      const result = await crmDataQualityService.getDashboard()

      expect(apiClient.get).toHaveBeenCalledWith('/api/crm/data-quality/dashboard')
      expect(result.data.quality_summary).toHaveLength(1)
      expect(result.data.duplicate_summary).toHaveLength(1)
    })
  })
})
