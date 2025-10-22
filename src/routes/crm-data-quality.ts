// @ts-nocheck
/**
 * CRM Data Quality & Duplicate Detection API Routes
 */

import { Hono } from 'hono';
import { Logger } from '../shared/logger';
const logger = new Logger({ component: 'crm-data-quality' });
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { DuplicateDetectionEngine } from '../services/crm/duplicate-detection';
import { DataHygieneEngine } from '../services/crm/data-hygiene';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

// ============================================================
// REQUEST VALIDATION SCHEMAS
// ============================================================

const FindDuplicatesSchema = z.object({
  entity_type: z.enum(['contact', 'company']),
  entity_id: z.string().optional(),
  threshold: z.number().min(0).max(100).default(70)
});

const MergeEntitiesSchema = z.object({
  entity_type: z.enum(['contact', 'company']),
  primary_id: z.string(),
  duplicate_ids: z.array(z.string()),
  field_resolution: z.record(z.enum(['primary', 'duplicate', 'merge'])),
  preserve_history: z.boolean().default(true)
});

const ValidateEntitySchema = z.object({
  entity_type: z.enum(['contact', 'company', 'lead', 'deal']),
  entity_id: z.string()
});

const AutoFixSchema = z.object({
  entity_type: z.enum(['contact', 'company', 'lead', 'deal']),
  entity_id: z.string()
});

// ============================================================
// DUPLICATE DETECTION ENDPOINTS
// ============================================================

/**
 * Find duplicates for a specific entity
 * POST /api/crm/data-quality/duplicates/find
 */
app.post('/duplicates/find', zValidator('json', FindDuplicatesSchema), async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const { entity_type, entity_id, threshold } = c.get('validatedData');

    const engine = new DuplicateDetectionEngine(c.env.DB_MAIN, businessId);

    let entity;
    if (entity_id) {
      // Find duplicates for specific entity
      const tableName = entity_type === 'contact' ? 'crm_contacts' : 'crm_companies';
      entity = await c.env.DB_MAIN
        .prepare(`SELECT * FROM ${tableName} WHERE id = ? AND business_id = ?`)
        .bind(entity_id, businessId)
        .first();

      if (!entity) {
        return c.json({ success: false, error: 'Entity not found' }, 404);
      }
    }

    const matches = entity_type === 'contact'
      ? await engine.findContactDuplicates(entity || {}, threshold)
      : await engine.findCompanyDuplicates(entity || {}, threshold);

    // Store matches in database for tracking
    for (const match of matches) {
      await c.env.DB_MAIN
        .prepare(`
          INSERT OR IGNORE INTO crm_duplicate_matches (
            business_id, entity_type, primary_id, duplicate_id,
            match_score, confidence, match_reasons, auto_merge_eligible
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          businessId,
          entity_type,
          match.primary_id,
          match.duplicate_id,
          match.match_score,
          match.confidence,
          JSON.stringify(match.match_reasons),
          match.auto_merge_eligible ? 1 : 0
        )
        .run();
    }

    return c.json({
      success: true,
      data: {
        matches,
        count: matches.length,
        high_confidence: matches.filter(m => m.confidence === 'high').length,
        auto_merge_eligible: matches.filter(m => m.auto_merge_eligible).length
      }
    });
  } catch (error: any) {
    logger.error('Duplicate detection error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Scan all records for duplicates
 * POST /api/crm/data-quality/duplicates/scan
 */
app.post('/duplicates/scan', async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const { entity_type } = await c.req.json();

    if (!entity_type || !['contact', 'company'].includes(entity_type)) {
      return c.json({ success: false, error: 'Invalid entity_type' }, 400);
    }

    const engine = new DuplicateDetectionEngine(c.env.DB_MAIN, businessId);

    const matches = entity_type === 'contact'
      ? await engine.scanAllContactsForDuplicates()
      : await engine.scanAllCompaniesForDuplicates();

    // Store all matches
    for (const match of matches) {
      await c.env.DB_MAIN
        .prepare(`
          INSERT OR IGNORE INTO crm_duplicate_matches (
            business_id, entity_type, primary_id, duplicate_id,
            match_score, confidence, match_reasons, auto_merge_eligible
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          businessId,
          entity_type,
          match.primary_id,
          match.duplicate_id,
          match.match_score,
          match.confidence,
          JSON.stringify(match.match_reasons),
          match.auto_merge_eligible ? 1 : 0
        )
        .run();
    }

    return c.json({
      success: true,
      data: {
        total_matches: matches.length,
        high_confidence: matches.filter(m => m.confidence === 'high').length,
        auto_merge_eligible: matches.filter(m => m.auto_merge_eligible).length,
        scan_completed_at: new Date().toISOString()
      }
    });
  } catch (error: any) {
    logger.error('Batch duplicate scan error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Get pending duplicate matches
 * GET /api/crm/data-quality/duplicates/pending
 */
app.get('/duplicates/pending', async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const entity_type = c.req.query('entity_type');
    const confidence = c.req.query('confidence');

    let query = `
      SELECT * FROM crm_duplicate_matches
      WHERE business_id = ? AND status = 'pending'
    `;
    const params: any[] = [businessId];

    if (entity_type && ['contact', 'company'].includes(entity_type)) {
      query += ' AND entity_type = ?';
      params.push(entity_type);
    }

    if (confidence && ['low', 'medium', 'high'].includes(confidence)) {
      query += ' AND confidence = ?';
      params.push(confidence);
    }

    query += ' ORDER BY match_score DESC, detected_at DESC';

    const result = await c.env.DB_MAIN
      .prepare(query)
      .bind(...params)
      .all();

    return c.json({
      success: true,
      data: result.results || []
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Merge duplicate entities
 * POST /api/crm/data-quality/duplicates/merge
 */
app.post('/duplicates/merge', zValidator('json', MergeEntitiesSchema), async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const strategy = c.get('validatedData');

    const engine = new DuplicateDetectionEngine(c.env.DB_MAIN, businessId);

    const result = strategy.entity_type === 'contact'
      ? await engine.mergeContacts(strategy)
      : await engine.mergeCompanies(strategy);

    // Update match status
    await c.env.DB_MAIN
      .prepare(`
        UPDATE crm_duplicate_matches
        SET status = 'merged',
            merged_into = ?,
            merged_at = CURRENT_TIMESTAMP,
            merge_strategy = ?
        WHERE business_id = ?
          AND primary_id = ?
          AND duplicate_id IN (${strategy.duplicate_ids.map(() => '?').join(',')})
      `)
      .bind(
        strategy.primary_id,
        JSON.stringify(strategy),
        businessId,
        strategy.primary_id,
        ...strategy.duplicate_ids
      )
      .run();

    return c.json({
      success: true,
      data: result
    });
  } catch (error: any) {
    logger.error('Merge error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Dismiss duplicate match
 * POST /api/crm/data-quality/duplicates/:matchId/dismiss
 */
app.post('/duplicates/:matchId/dismiss', async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const userId = c.get('userId');
    const matchId = c.req.param('matchId');

    await c.env.DB_MAIN
      .prepare(`
        UPDATE crm_duplicate_matches
        SET status = 'dismissed',
            reviewed_by = ?,
            reviewed_at = CURRENT_TIMESTAMP
        WHERE id = ? AND business_id = ?
      `)
      .bind(userId, matchId, businessId)
      .run();

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ============================================================
// DATA QUALITY ENDPOINTS
// ============================================================

/**
 * Validate entity data quality
 * POST /api/crm/data-quality/validate
 */
app.post('/validate', zValidator('json', ValidateEntitySchema), async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const { entity_type, entity_id } = c.get('validatedData');

    const engine = new DataHygieneEngine(c.env.DB_MAIN, businessId);

    // Fetch entity
    const tableName = `crm_${entity_type}s`;
    const entity = await c.env.DB_MAIN
      .prepare(`SELECT * FROM ${tableName} WHERE id = ? AND business_id = ?`)
      .bind(entity_id, businessId)
      .first();

    if (!entity) {
      return c.json({ success: false, error: 'Entity not found' }, 404);
    }

    const issues = await engine.validateEntity(entity_type, entity);
    const qualityScore = await engine.calculateQualityScore(entity_type, entity);

    // Store issues
    for (const issue of issues) {
      await c.env.DB_MAIN
        .prepare(`
          INSERT INTO crm_data_quality_issues (
            business_id, entity_type, entity_id, severity, issue_type,
            field_name, current_value, suggested_value, description, auto_fixable
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          businessId,
          issue.entity_type,
          issue.entity_id,
          issue.severity,
          issue.issue_type,
          issue.field_name || null,
          issue.current_value || null,
          issue.suggested_value || null,
          issue.description,
          issue.auto_fixable ? 1 : 0
        )
        .run();
    }

    // Cache quality score
    await c.env.DB_MAIN
      .prepare(`
        INSERT OR REPLACE INTO crm_data_quality_scores (
          business_id, entity_type, entity_id,
          overall_score, completeness_score, accuracy_score,
          freshness_score, consistency_score,
          issues_count, critical_issues_count,
          expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+24 hours'))
      `)
      .bind(
        businessId,
        entity_type,
        entity_id,
        qualityScore.overall_score,
        qualityScore.completeness_score,
        qualityScore.accuracy_score,
        qualityScore.freshness_score,
        qualityScore.consistency_score,
        qualityScore.issues_count,
        qualityScore.critical_issues_count
      )
      .run();

    return c.json({
      success: true,
      data: {
        quality_score: qualityScore,
        issues
      }
    });
  } catch (error: any) {
    logger.error('Validation error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Get data quality report for business
 * GET /api/crm/data-quality/report
 */
app.get('/report', async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const engine = new DataHygieneEngine(c.env.DB_MAIN, businessId);

    const report = await engine.scanAllRecords();

    return c.json({
      success: true,
      data: report
    });
  } catch (error: any) {
    logger.error('Report generation error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Get data quality issues
 * GET /api/crm/data-quality/issues
 */
app.get('/issues', async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const entity_type = c.req.query('entity_type');
    const severity = c.req.query('severity');
    const resolved = c.req.query('resolved') === 'true';

    let query = 'SELECT * FROM crm_data_quality_issues WHERE business_id = ? AND resolved = ?';
    const params: any[] = [businessId, resolved ? 1 : 0];

    if (entity_type) {
      query += ' AND entity_type = ?';
      params.push(entity_type);
    }

    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }

    query += ' ORDER BY severity DESC, detected_at DESC LIMIT 100';

    const result = await c.env.DB_MAIN
      .prepare(query)
      .bind(...params)
      .all();

    return c.json({
      success: true,
      data: result.results || []
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Auto-fix data quality issues
 * POST /api/crm/data-quality/auto-fix
 */
app.post('/auto-fix', zValidator('json', AutoFixSchema), async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const { entity_type, entity_id } = c.get('validatedData');

    const engine = new DataHygieneEngine(c.env.DB_MAIN, businessId);

    const fixedCount = await engine.autoFixIssues(entity_type, entity_id);

    // Mark issues as resolved
    await c.env.DB_MAIN
      .prepare(`
        UPDATE crm_data_quality_issues
        SET resolved = TRUE,
            resolved_at = CURRENT_TIMESTAMP,
            resolution_method = 'auto'
        WHERE business_id = ?
          AND entity_type = ?
          AND entity_id = ?
          AND auto_fixable = TRUE
          AND resolved = FALSE
      `)
      .bind(businessId, entity_type, entity_id)
      .run();

    return c.json({
      success: true,
      data: {
        fixed_count: fixedCount,
        message: `Auto-fixed ${fixedCount} issues`
      }
    });
  } catch (error: any) {
    logger.error('Auto-fix error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Resolve data quality issue manually
 * POST /api/crm/data-quality/issues/:issueId/resolve
 */
app.post('/issues/:issueId/resolve', async (c: any) => {
  try {
    const businessId = c.get('businessId');
    const userId = c.get('userId');
    const issueId = c.req.param('issueId');

    await c.env.DB_MAIN
      .prepare(`
        UPDATE crm_data_quality_issues
        SET resolved = TRUE,
            resolved_at = CURRENT_TIMESTAMP,
            resolved_by = ?,
            resolution_method = 'manual'
        WHERE id = ? AND business_id = ?
      `)
      .bind(userId, issueId, businessId)
      .run();

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Get data quality dashboard summary
 * GET /api/crm/data-quality/dashboard
 */
app.get('/dashboard', async (c: any) => {
  try {
    const businessId = c.get('businessId');

    // Get summary from view
    const summary = await c.env.DB_MAIN
      .prepare('SELECT * FROM v_crm_data_quality_summary WHERE business_id = ?')
      .bind(businessId)
      .all();

    // Get duplicate summary
    const duplicates = await c.env.DB_MAIN
      .prepare('SELECT * FROM v_crm_duplicate_detection_summary WHERE business_id = ?')
      .bind(businessId)
      .all();

    // Get recent issues
    const recentIssues = await c.env.DB_MAIN
      .prepare(`
        SELECT * FROM crm_data_quality_issues
        WHERE business_id = ? AND resolved = FALSE
        ORDER BY severity DESC, detected_at DESC
        LIMIT 10
      `)
      .bind(businessId)
      .all();

    return c.json({
      success: true,
      data: {
        quality_summary: summary.results || [],
        duplicate_summary: duplicates.results || [],
        recent_issues: recentIssues.results || []
      }
    });
  } catch (error: any) {
    logger.error('Dashboard error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

export default app;
