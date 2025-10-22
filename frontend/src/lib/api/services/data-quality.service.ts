/**
 * CRM Data Quality API Service
 * Handles duplicate detection, validation, and auto-fix operations
 */

import { apiClient } from '../client';

export interface QualityIssue {
  id: string;
  type: 'duplicate' | 'missing_field' | 'invalid_format' | 'outdated';
  entity_type: 'contact' | 'company' | 'deal' | 'lead';
  entity_id: string;
  entity_name: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  auto_fixable: boolean;
  created_at: string;
}

export interface DuplicateMatch {
  id: string;
  primary_id: string;
  duplicate_id: string;
  primary_name: string;
  duplicate_name: string;
  match_score: number;
  confidence: 'high' | 'medium' | 'low';
  match_reasons: string[];
  auto_merge_eligible: boolean;
}

export interface QualityScore {
  overall: number;
  contacts: number;
  companies: number;
  deals: number;
  leads: number;
  trend: string;
}

export interface FindDuplicatesRequest {
  entity_type: 'contact' | 'company';
  entity_id?: string;
  threshold?: number;
}

export interface MergeDuplicatesRequest {
  entity_type: 'contact' | 'company';
  primary_id: string;
  duplicate_ids: string[];
  field_resolution: Record<string, 'primary' | 'duplicate' | 'merge'>;
  preserve_history?: boolean;
}

export interface ValidateEntityRequest {
  entity_type: 'contact' | 'company' | 'lead' | 'deal';
  entity_id: string;
}

export interface AutoFixRequest {
  entity_type: 'contact' | 'company' | 'lead' | 'deal';
  entity_id: string;
}

export const dataQualityService = {
  /**
   * Get overall data quality score
   */
  async getQualityScore(): Promise<QualityScore> {
    const response = await apiClient.get<QualityScore>('/api/crm/data-quality/score');
    return response;
  },

  /**
   * Find duplicate records
   */
  async findDuplicates(request: FindDuplicatesRequest) {
    const response = await apiClient.post('/api/crm/data-quality/duplicates/find', request);
    return response.data;
  },

  /**
   * Scan all records for duplicates
   */
  async scanForDuplicates(entity_type: 'contact' | 'company') {
    const response = await apiClient.post('/api/crm/data-quality/duplicates/scan', {
      entity_type
    });
    return response.data;
  },

  /**
   * Merge duplicate records
   */
  async mergeDuplicates(request: MergeDuplicatesRequest) {
    const response = await apiClient.post('/api/crm/data-quality/duplicates/merge', request);
    return response.data;
  },

  /**
   * Dismiss a duplicate match
   */
  async dismissDuplicate(matchId: string) {
    const response = await apiClient.post(`/api/crm/data-quality/duplicates/${matchId}/dismiss`);
    return response.data;
  },

  /**
   * Get all duplicate matches
   */
  async getDuplicates(entity_type?: 'contact' | 'company'): Promise<DuplicateMatch[]> {
    const params = entity_type ? { entity_type } : {};
    const response = await apiClient.get<DuplicateMatch[]>('/api/crm/data-quality/duplicates', { params });
    return response;
  },

  /**
   * Validate entity data
   */
  async validateEntity(request: ValidateEntityRequest) {
    const response = await apiClient.post('/api/crm/data-quality/validate', request);
    return response.data;
  },

  /**
   * Auto-fix entity issues
   */
  async autoFix(request: AutoFixRequest) {
    const response = await apiClient.post('/api/crm/data-quality/auto-fix', request);
    return response.data;
  },

  /**
   * Get all quality issues
   */
  async getIssues(filters?: {
    severity?: 'high' | 'medium' | 'low';
    type?: 'duplicate' | 'missing_field' | 'invalid_format' | 'outdated';
    entity_type?: 'contact' | 'company' | 'deal' | 'lead';
  }): Promise<QualityIssue[]> {
    const response = await apiClient.get<QualityIssue[]>('/api/crm/data-quality/issues', { params: filters });
    return response;
  },

  /**
   * Resolve a quality issue
   */
  async resolveIssue(issueId: string, resolution: {
    action: 'fix' | 'dismiss' | 'manual';
    notes?: string;
  }) {
    const response = await apiClient.post(`/api/crm/data-quality/issues/${issueId}/resolve`, resolution);
    return response.data;
  },

  /**
   * Get data quality statistics
   */
  async getStatistics() {
    const response = await apiClient.get('/api/crm/data-quality/statistics');
    return response.data;
  },

  /**
   * Run bulk data quality check
   */
  async runBulkCheck(entity_type: 'contact' | 'company' | 'all') {
    const response = await apiClient.post('/api/crm/data-quality/bulk-check', {
      entity_type
    });
    return response.data;
  }
};
