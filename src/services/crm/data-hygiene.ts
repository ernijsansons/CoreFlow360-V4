// @ts-nocheck
/**
 * CRM Data Hygiene & Anomaly Detection Engine
 * Automated data validation, cleansing, and quality monitoring
 * Inspired by Salesforce Data Quality Management
 */

import type { D1Database } from '@cloudflare/workers-types';
import type { Contact, Company, Lead, Deal } from '../../types/crm';

// ============================================================
// TYPES
// ============================================================

export interface DataQualityIssue {
  id: string;
  entity_type: 'contact' | 'company' | 'lead' | 'deal';
  entity_id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  issue_type: DataQualityIssueType;
  field_name?: string;
  current_value?: any;
  suggested_value?: any;
  description: string;
  auto_fixable: boolean;
  detected_at: string;
  resolved_at?: string;
}

export type DataQualityIssueType =
  | 'missing_required_field'
  | 'invalid_format'
  | 'stale_data'
  | 'invalid_email'
  | 'invalid_phone'
  | 'invalid_domain'
  | 'orphaned_record'
  | 'low_score_anomaly'
  | 'duplicate_suspected'
  | 'inconsistent_data'
  | 'missing_activity'
  | 'data_decay';

export interface ValidationRule {
  field: string;
  rule_type: 'required' | 'format' | 'range' | 'custom';
  validator: (value: any, entity: any) => boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  error_message: string;
  auto_fix?: (value: any) => any;
}

export interface DataQualityScore {
  entity_type: 'contact' | 'company' | 'lead' | 'deal';
  entity_id: string;
  overall_score: number; // 0-100
  completeness_score: number;
  accuracy_score: number;
  freshness_score: number;
  consistency_score: number;
  issues_count: number;
  critical_issues_count: number;
}

export interface DataQualityReport {
  business_id: string;
  total_records: number;
  healthy_records: number;
  at_risk_records: number;
  critical_records: number;
  avg_quality_score: number;
  issues_by_type: Record<DataQualityIssueType, number>;
  trends: {
    period: string;
    score: number;
    issues: number;
  }[];
}

// ============================================================
// DATA HYGIENE ENGINE
// ============================================================

export class DataHygieneEngine {
  private validationRules: Map<string, ValidationRule[]> = new Map();

  constructor(
    private db: D1Database,
    private businessId: string
  ) {
    this.initializeValidationRules();
  }

  // ============================================================
  // VALIDATION RULES
  // ============================================================

  private initializeValidationRules() {
    // Contact validation rules
    this.validationRules.set('contact', [
      {
        field: 'email',
        rule_type: 'required',
        validator: (value) => !!value && value.length > 0,
        severity: 'critical',
        error_message: 'Email is required for contacts'
      },
      {
        field: 'email',
        rule_type: 'format',
        validator: (value) => this.isValidEmail(value),
        severity: 'high',
        error_message: 'Invalid email format',
        auto_fix: (value) => value?.toLowerCase().trim()
      },
      {
        field: 'first_name',
        rule_type: 'required',
        validator: (value) => !!value && value.length > 0,
        severity: 'high',
        error_message: 'First name is required'
      },
      {
        field: 'last_name',
        rule_type: 'required',
        validator: (value) => !!value && value.length > 0,
        severity: 'high',
        error_message: 'Last name is required'
      },
      {
        field: 'phone',
        rule_type: 'format',
        validator: (value) => !value || this.isValidPhone(value),
        severity: 'medium',
        error_message: 'Invalid phone format',
        auto_fix: (value) => this.normalizePhone(value)
      },
      {
        field: 'job_title',
        rule_type: 'required',
        validator: (value) => !!value,
        severity: 'medium',
        error_message: 'Job title helps with qualification'
      },
      {
        field: 'company_id',
        rule_type: 'required',
        validator: (value) => !!value,
        severity: 'medium',
        error_message: 'Contact should be linked to a company'
      }
    ]);

    // Company validation rules
    this.validationRules.set('company', [
      {
        field: 'name',
        rule_type: 'required',
        validator: (value) => !!value && value.length > 0,
        severity: 'critical',
        error_message: 'Company name is required'
      },
      {
        field: 'domain',
        rule_type: 'format',
        validator: (value) => !value || this.isValidDomain(value),
        severity: 'high',
        error_message: 'Invalid domain format',
        auto_fix: (value) => value?.toLowerCase().trim()
      },
      {
        field: 'website',
        rule_type: 'format',
        validator: (value) => !value || this.isValidUrl(value),
        severity: 'low',
        error_message: 'Invalid website URL'
      },
      {
        field: 'email',
        rule_type: 'format',
        validator: (value) => !value || this.isValidEmail(value),
        severity: 'medium',
        error_message: 'Invalid company email'
      },
      {
        field: 'industry',
        rule_type: 'required',
        validator: (value) => !!value,
        severity: 'medium',
        error_message: 'Industry helps with segmentation'
      },
      {
        field: 'company_size',
        rule_type: 'required',
        validator: (value) => !!value,
        severity: 'medium',
        error_message: 'Company size needed for qualification'
      }
    ]);

    // Lead validation rules
    this.validationRules.set('lead', [
      {
        field: 'title',
        rule_type: 'required',
        validator: (value) => !!value && value.length > 0,
        severity: 'critical',
        error_message: 'Lead title is required'
      },
      {
        field: 'source',
        rule_type: 'required',
        validator: (value) => !!value,
        severity: 'high',
        error_message: 'Lead source tracking is critical'
      },
      {
        field: 'owner_id',
        rule_type: 'required',
        validator: (value) => !!value,
        severity: 'high',
        error_message: 'Lead must be assigned to an owner'
      }
    ]);

    // Deal validation rules
    this.validationRules.set('deal', [
      {
        field: 'name',
        rule_type: 'required',
        validator: (value) => !!value && value.length > 0,
        severity: 'critical',
        error_message: 'Deal name is required'
      },
      {
        field: 'amount',
        rule_type: 'required',
        validator: (value) => value !== null && value >= 0,
        severity: 'high',
        error_message: 'Deal amount must be specified'
      },
      {
        field: 'company_id',
        rule_type: 'required',
        validator: (value) => !!value,
        severity: 'critical',
        error_message: 'Deal must be linked to a company'
      },
      {
        field: 'owner_id',
        rule_type: 'required',
        validator: (value) => !!value,
        severity: 'high',
        error_message: 'Deal must have an owner'
      },
      {
        field: 'expected_close_date',
        rule_type: 'required',
        validator: (value) => !!value,
        severity: 'medium',
        error_message: 'Expected close date helps with forecasting'
      }
    ]);
  }

  // ============================================================
  // DATA VALIDATION
  // ============================================================

  async validateEntity(
    entityType: 'contact' | 'company' | 'lead' | 'deal',
    entity: any
  ): Promise<DataQualityIssue[]> {
    const issues: DataQualityIssue[] = [];
    const rules = this.validationRules.get(entityType) || [];

    for (const rule of rules) {
      const value = entity[rule.field];
      if (!rule.validator(value, entity)) {
        issues.push({
          id: crypto.randomUUID(),
          entity_type: entityType,
          entity_id: entity.id,
          severity: rule.severity,
          issue_type: rule.rule_type === 'required' ? 'missing_required_field' : 'invalid_format',
          field_name: rule.field,
          current_value: value,
          suggested_value: rule.auto_fix ? rule.auto_fix(value) : undefined,
          description: rule.error_message,
          auto_fixable: !!rule.auto_fix,
          detected_at: new Date().toISOString()
        });
      }
    }

    // Additional context-specific checks
    issues.push(...await this.checkStaleData(entityType, entity));
    issues.push(...await this.checkOrphanedRecords(entityType, entity));
    issues.push(...await this.checkMissingActivity(entityType, entity));

    return issues;
  }

  // ============================================================
  // STALE DATA DETECTION
  // ============================================================

  private async checkStaleData(
    entityType: 'contact' | 'company' | 'lead' | 'deal',
    entity: any
  ): Promise<DataQualityIssue[]> {
    const issues: DataQualityIssue[] = [];
    const now = new Date();
    const updatedAt = new Date(entity.updated_at);
    const daysSinceUpdate = (now.getTime() - updatedAt.getTime()) / (1000 * 60 * 60 * 24);

    // Define staleness thresholds by entity type
    const thresholds: Record<typeof entityType, number> = {
      contact: 180, // 6 months
      company: 365, // 1 year
      lead: 90,     // 3 months
      deal: 30      // 1 month
    };

    if (daysSinceUpdate > thresholds[entityType]) {
      issues.push({
        id: crypto.randomUUID(),
        entity_type: entityType,
        entity_id: entity.id,
        severity: daysSinceUpdate > thresholds[entityType] * 2 ? 'high' : 'medium',
        issue_type: 'stale_data',
        description: `Record hasn't been updated in ${Math.floor(daysSinceUpdate)} days`,
        auto_fixable: false,
        detected_at: new Date().toISOString()
      });
    }

    return issues;
  }

  // ============================================================
  // ORPHANED RECORD DETECTION
  // ============================================================

  private async checkOrphanedRecords(
    entityType: 'contact' | 'company' | 'lead' | 'deal',
    entity: any
  ): Promise<DataQualityIssue[]> {
    const issues: DataQualityIssue[] = [];

    // Check for broken relationships
    if (entityType === 'contact' && entity.company_id) {
      const company = await this.db
        .prepare('SELECT id FROM crm_companies WHERE id = ? AND deleted_at IS NULL')
        .bind(entity.company_id)
        .first() as any;

      if (!company) {
        issues.push({
          id: crypto.randomUUID(),
          entity_type: 'contact',
          entity_id: entity.id,
          severity: 'high',
          issue_type: 'orphaned_record',
          field_name: 'company_id',
          current_value: entity.company_id,
          description: 'Contact linked to non-existent company',
          auto_fixable: true,
          detected_at: new Date().toISOString()
        });
      }
    }

    if (entityType === 'lead' && entity.company_id) {
      const company = await this.db
        .prepare('SELECT id FROM crm_companies WHERE id = ? AND deleted_at IS NULL')
        .bind(entity.company_id)
        .first() as any;

      if (!company) {
        issues.push({
          id: crypto.randomUUID(),
          entity_type: 'lead',
          entity_id: entity.id,
          severity: 'high',
          issue_type: 'orphaned_record',
          field_name: 'company_id',
          description: 'Lead linked to non-existent company',
          auto_fixable: true,
          detected_at: new Date().toISOString()
        });
      }
    }

    if (entityType === 'deal') {
      if (entity.company_id) {
        const company = await this.db
          .prepare('SELECT id FROM crm_companies WHERE id = ? AND deleted_at IS NULL')
          .bind(entity.company_id)
          .first() as any;

        if (!company) {
          issues.push({
            id: crypto.randomUUID(),
            entity_type: 'deal',
            entity_id: entity.id,
            severity: 'critical',
            issue_type: 'orphaned_record',
            field_name: 'company_id',
            description: 'Deal linked to non-existent company',
            auto_fixable: false,
            detected_at: new Date().toISOString()
          });
        }
      }

      if (entity.primary_contact_id) {
        const contact = await this.db
          .prepare('SELECT id FROM crm_contacts WHERE id = ? AND deleted_at IS NULL')
          .bind(entity.primary_contact_id)
          .first() as any;

        if (!contact) {
          issues.push({
            id: crypto.randomUUID(),
            entity_type: 'deal',
            entity_id: entity.id,
            severity: 'medium',
            issue_type: 'orphaned_record',
            field_name: 'primary_contact_id',
            description: 'Deal linked to non-existent contact',
            auto_fixable: true,
            detected_at: new Date().toISOString()
          });
        }
      }
    }

    return issues;
  }

  // ============================================================
  // MISSING ACTIVITY DETECTION
  // ============================================================

  private async checkMissingActivity(
    entityType: 'contact' | 'company' | 'lead' | 'deal',
    entity: any
  ): Promise<DataQualityIssue[]> {
    const issues: DataQualityIssue[] = [];

    // Check for entities without recent activity
    let activityCount = 0;

    if (entityType === 'contact') {
      const result = await this.db
        .prepare(`
          SELECT COUNT(*) as count FROM crm_activities
          WHERE contact_id = ? AND deleted_at IS NULL
            AND completed_at >= datetime('now', '-30 days')
        `)
        .bind(entity.id)
        .first<{ count: number }>();

      activityCount = result?.count || 0;
    } else if (entityType === 'company') {
      const result = await this.db
        .prepare(`
          SELECT COUNT(*) as count FROM crm_activities
          WHERE company_id = ? AND deleted_at IS NULL
            AND completed_at >= datetime('now', '-30 days')
        `)
        .bind(entity.id)
        .first<{ count: number }>();

      activityCount = result?.count || 0;
    } else if (entityType === 'deal' && entity.status === 'open') {
      const result = await this.db
        .prepare(`
          SELECT COUNT(*) as count FROM crm_activities
          WHERE deal_id = ? AND deleted_at IS NULL
            AND completed_at >= datetime('now', '-7 days')
        `)
        .bind(entity.id)
        .first<{ count: number }>();

      activityCount = result?.count || 0;
    }

    if (activityCount === 0 && entityType === 'deal' && entity.status === 'open') {
      issues.push({
        id: crypto.randomUUID(),
        entity_type: entityType,
        entity_id: entity.id,
        severity: 'high',
        issue_type: 'missing_activity',
        description: 'Open deal has no recent activity (may be stalled)',
        auto_fixable: false,
        detected_at: new Date().toISOString()
      });
    }

    return issues;
  }

  // ============================================================
  // DATA QUALITY SCORING
  // ============================================================

  async calculateQualityScore(
    entityType: 'contact' | 'company' | 'lead' | 'deal',
    entity: any
  ): Promise<DataQualityScore> {
    const issues = await this.validateEntity(entityType, entity);

    // Calculate sub-scores
    const completenessScore = this.calculateCompletenessScore(entityType, entity);
    const accuracyScore = this.calculateAccuracyScore(issues);
    const freshnessScore = this.calculateFreshnessScore(entity);
    const consistencyScore = this.calculateConsistencyScore(issues);

    // Weighted overall score
    const overallScore = Math.round(
      completenessScore * 0.3 +
      accuracyScore * 0.3 +
      freshnessScore * 0.2 +
      consistencyScore * 0.2
    );

    return {
      entity_type: entityType,
      entity_id: entity.id,
      overall_score: overallScore,
      completeness_score: completenessScore,
      accuracy_score: accuracyScore,
      freshness_score: freshnessScore,
      consistency_score: consistencyScore,
      issues_count: issues.length,
      critical_issues_count: issues.filter(i => i.severity === 'critical').length
    };
  }

  private calculateCompletenessScore(entityType: string, entity: any): number {
    const importantFields: Record<string, string[]> = {
      contact: ['email', 'first_name', 'last_name', 'phone', 'job_title', 'company_id'],
      company: ['name', 'domain', 'industry', 'company_size', 'website', 'phone'],
      lead: ['title', 'source', 'owner_id', 'contact_id', 'company_id'],
      deal: ['name', 'amount', 'company_id', 'owner_id', 'expected_close_date', 'stage']
    };

    const fields = importantFields[entityType] || [];
    const filledFields = fields.filter(f => entity[f] !== null && entity[f] !== undefined && entity[f] !== '');

    return Math.round((filledFields.length / fields.length) * 100);
  }

  private calculateAccuracyScore(issues: DataQualityIssue[]): number {
    const formatIssues = issues.filter(i => i.issue_type === 'invalid_format' || i.issue_type === 'invalid_email' || i.issue_type === 'invalid_phone');
    return Math.max(0, 100 - (formatIssues.length * 20));
  }

  private calculateFreshnessScore(entity: any): number {
    const now = new Date();
    const updatedAt = new Date(entity.updated_at);
    const daysSinceUpdate = (now.getTime() - updatedAt.getTime()) / (1000 * 60 * 60 * 24);

    if (daysSinceUpdate <= 30) return 100;
    if (daysSinceUpdate <= 90) return 80;
    if (daysSinceUpdate <= 180) return 60;
    if (daysSinceUpdate <= 365) return 40;
    return 20;
  }

  private calculateConsistencyScore(issues: DataQualityIssue[]): number {
    const consistencyIssues = issues.filter(i => i.issue_type === 'orphaned_record' || i.issue_type === 'inconsistent_data');
    return Math.max(0, 100 - (consistencyIssues.length * 25));
  }

  // ============================================================
  // AUTO-FIX
  // ============================================================

  async autoFixIssues(entityType: 'contact' | 'company' | 'lead' | 'deal', entityId: string): Promise<number> {
    const entity = await this.getEntity(entityType, entityId);
    if (!entity) return 0;

    const issues = await this.validateEntity(entityType, entity);
    const fixableIssues = issues.filter(i => i.auto_fixable);

    let fixedCount = 0;

    for (const issue of fixableIssues) {
      if (issue.suggested_value && issue.field_name) {
        await this.db
          .prepare(`UPDATE crm_${entityType}s SET ${issue.field_name} = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
          .bind(issue.suggested_value, entityId)
          .run();

        fixedCount++;
      } else if (issue.issue_type === 'orphaned_record' && issue.field_name) {
        // Set orphaned references to null
        await this.db
          .prepare(`UPDATE crm_${entityType}s SET ${issue.field_name} = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
          .bind(entityId)
          .run();

        fixedCount++;
      }
    }

    return fixedCount;
  }

  // ============================================================
  // BATCH SCANNING
  // ============================================================

  async scanAllRecords(): Promise<DataQualityReport> {
    const [contacts, companies, leads, deals] = await Promise.all([
      this.db.prepare('SELECT * FROM crm_contacts WHERE business_id = ? AND deleted_at IS NULL').bind(this.businessId).all(),
      this.db.prepare('SELECT * FROM crm_companies WHERE business_id = ? AND deleted_at IS NULL').bind(this.businessId).all(),
      this.db.prepare('SELECT * FROM crm_leads WHERE business_id = ? AND deleted_at IS NULL').bind(this.businessId).all(),
      this.db.prepare('SELECT * FROM crm_deals WHERE business_id = ? AND deleted_at IS NULL').bind(this.businessId).all()
    ]);

    const allRecords = [
      ...(contacts.results || []).map(r => ({ type: 'contact' as const, data: r })),
      ...(companies.results || []).map(r => ({ type: 'company' as const, data: r })),
      ...(leads.results || []).map(r => ({ type: 'lead' as const, data: r })),
      ...(deals.results || []).map(r => ({ type: 'deal' as const, data: r }))
    ];

    let totalRecords = 0;
    let healthyRecords = 0;
    let atRiskRecords = 0;
    let criticalRecords = 0;
    let totalScore = 0;
    const issuesByType: Record<string, number> = {};

    for (const record of allRecords) {
      totalRecords++;
      const score = await this.calculateQualityScore(record.type, record.data);
      totalScore += score.overall_score;

      if (score.overall_score >= 80) {
        healthyRecords++;
      } else if (score.overall_score >= 60) {
        atRiskRecords++;
      } else {
        criticalRecords++;
      }

      const issues = await this.validateEntity(record.type, record.data);
      for (const issue of issues) {
        issuesByType[issue.issue_type] = (issuesByType[issue.issue_type] || 0) + 1;
      }
    }

    return {
      business_id: this.businessId,
      total_records: totalRecords,
      healthy_records: healthyRecords,
      at_risk_records: atRiskRecords,
      critical_records: criticalRecords,
      avg_quality_score: totalRecords > 0 ? Math.round(totalScore / totalRecords) : 0,
      issues_by_type: issuesByType as any,
      trends: []
    };
  }

  // ============================================================
  // UTILITY METHODS
  // ============================================================

  private async getEntity(entityType: string, entityId: string): Promise<any> {
    return this.db
      .prepare(`SELECT * FROM crm_${entityType}s WHERE id = ?`)
      .bind(entityId)
      .first() as any;
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  private isValidPhone(phone: string): boolean {
    const normalized = phone.replace(/[^0-9]/g, '');
    return normalized.length >= 10 && normalized.length <= 15;
  }

  private isValidDomain(domain: string): boolean {
    const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i;
    return domainRegex.test(domain);
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  private normalizePhone(phone: string): string {
    return phone.replace(/[^0-9]/g, '');
  }
}
