/**
 * Unified AI Intelligence Service
 * Combines sentiment analysis, next best actions, and revenue forecasting
 * Features #7, #8, #10 - Phase 1 Sprint 1
 */

import type { Env } from '../../types/env';

export class AIIntelligenceService {
  constructor(private env: Env) {}

  /**
   * Analyze sentiment using Claude API (Feature #7)
   */
  async analyzeSentiment(businessId: string, activityId: string, text: string): Promise<any> {
    const prompt = `Analyze the sentiment of this communication and return JSON only:

Text: """
${text}
"""

Return format:
{
  "sentiment": "positive",
  "sentiment_score": 0.7,
  "confidence": 0.9,
  "key_phrases": ["looking forward", "excited about"],
  "emotions": {"excitement": 0.7, "optimism": 0.6},
  "tone": "professional"
}`;

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': this.env.ANTHROPIC_API_KEY || '',
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-3-sonnet-20240229',
          max_tokens: 300,
          messages: [{ role: 'user', content: prompt }]
        })
      });

      const data = await response.json() as any;
      const content = data.content?.[0]?.text || '{}';
      const result = JSON.parse(content.match(/\{[\s\S]*\}/)?.[0] || '{}');

      // Save to database
      const id = crypto.randomUUID().replace(/-/g, '');
      await this.env.DB_MAIN.prepare(`
        INSERT INTO crm_sentiment_scores (
          id, business_id, activity_id, sentiment, sentiment_score,
          confidence, key_phrases, emotions_detected, tone
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, businessId, activityId,
        result.sentiment || 'neutral',
        result.sentiment_score || 0,
        result.confidence || 0.5,
        JSON.stringify(result.key_phrases || []),
        JSON.stringify(result.emotions || {}),
        result.tone || 'neutral'
      ).run();

      return { id, ...result };
    } catch (error) {
      console.error('Sentiment analysis error:', error);
      return { sentiment: 'neutral', sentiment_score: 0, confidence: 0 };
    }
  }

  /**
   * Generate next best actions using AI (Feature #8)
   */
  async generateNextActions(businessId: string, entityType: string, entityId: string, userId: string): Promise<any[]> {
    // Get entity context
    const entity = await this.getEntityContext(entityType, entityId, businessId);

    const prompt = `As a sales AI assistant, recommend the top 3 next best actions for this ${entityType}:

Context: ${JSON.stringify(entity, null, 2)}

Return JSON array only:
[
  {
    "action_type": "send_email",
    "priority": 90,
    "title": "Send ROI calculator",
    "description": "Share customized ROI calculator based on their company size",
    "reasoning": "Contact is C-level at large company, showing budget authority"
  }
]`;

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': this.env.ANTHROPIC_API_KEY || '',
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-3-sonnet-20240229',
          max_tokens: 500,
          messages: [{ role: 'user', content: prompt }]
        })
      });

      const data = await response.json() as any;
      const content = data.content?.[0]?.text || '[]';
      const actions = JSON.parse(content.match(/\[[\s\S]*\]/)?.[0] || '[]');

      // Save to database
      const savedActions = [];
      for (const action of actions) {
        const id = crypto.randomUUID().replace(/-/g, '');
        await this.env.DB_MAIN.prepare(`
          INSERT INTO crm_next_actions (
            id, business_id, entity_type, entity_id, user_id,
            action_type, priority, action_title, action_description, reasoning,
            expires_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          id, businessId, entityType, entityId, userId,
          action.action_type, action.priority, action.title,
          action.description, action.reasoning,
          new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
        ).run();

        savedActions.push({ id, ...action });
      }

      return savedActions;
    } catch (error) {
      console.error('Next actions generation error:', error);
      return [];
    }
  }

  /**
   * Generate revenue forecast using AI (Feature #10)
   */
  async generateRevenueForecast(businessId: string, period: string, forecastType: string): Promise<any> {
    // Get pipeline data
    const pipeline = await this.env.DB_MAIN.prepare(`
      SELECT
        COUNT(*) as deals_count,
        SUM(deal_value) as pipeline_value,
        SUM(deal_value * CASE stage
          WHEN 'prospecting' THEN 0.1
          WHEN 'qualification' THEN 0.2
          WHEN 'proposal' THEN 0.5
          WHEN 'negotiation' THEN 0.75
          ELSE 0.9
        END) as weighted_pipeline,
        AVG(deal_value) as avg_deal_size
      FROM crm_deals
      WHERE business_id = ? AND stage NOT IN ('won', 'lost')
    `).bind(businessId).first() as any;

    // Calculate forecast using simple weighted pipeline method
    // (In production, this would use ML model)
    const forecasted = (pipeline?.weighted_pipeline || 0) * 0.8; // 80% of weighted pipeline
    const confidence = pipeline?.deals_count > 10 ? 0.85 : 0.65;
    const variance = forecasted * 0.15; // ±15% confidence interval

    const id = crypto.randomUUID().replace(/-/g, '');
    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_revenue_forecasts (
        id, business_id, forecast_period, forecast_type,
        forecasted_revenue, confidence_interval_low, confidence_interval_high,
        confidence_level, pipeline_value, weighted_pipeline, deals_count,
        model_version, forecasted_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id, businessId, period, forecastType,
      forecasted,
      forecasted - variance,
      forecasted + variance,
      confidence,
      pipeline?.pipeline_value || 0,
      pipeline?.weighted_pipeline || 0,
      pipeline?.deals_count || 0,
      'v1.0-weighted-pipeline',
      'ai_agent'
    ).run();

    return {
      id,
      forecasted_revenue: forecasted,
      confidence_interval: [forecasted - variance, forecasted + variance],
      confidence_level: confidence,
      pipeline_analysis: pipeline
    };
  }

  /**
   * Validate data quality (Feature #11)
   */
  async validateData(businessId: string, entityType: string, entityId: string): Promise<any[]> {
    const entity = await this.getEntityContext(entityType, entityId, businessId);
    const issues: any[] = [];

    // Email validation
    if (entity.email && !this.isValidEmail(entity.email)) {
      issues.push({
        field_name: 'email',
        issue_type: 'invalid_format',
        description: 'Email format is invalid'
      });
    }

    // Phone validation
    if (entity.phone && !this.isValidPhone(entity.phone)) {
      issues.push({
        field_name: 'phone',
        issue_type: 'invalid_format',
        description: 'Phone number format is invalid'
      });
    }

    // Required fields
    if (!entity.email && !entity.phone) {
      issues.push({
        field_name: 'contact_info',
        issue_type: 'missing_required',
        description: 'Missing email and phone number'
      });
    }

    // Save issues to database
    for (const issue of issues) {
      const id = crypto.randomUUID().replace(/-/g, '');
      await this.env.DB_MAIN.prepare(`
        INSERT INTO crm_data_quality_issues (
          id, business_id, entity_type, entity_id,
          field_name, issue_type, issue_description
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, businessId, entityType, entityId,
        issue.field_name, issue.issue_type, issue.description
      ).run();
    }

    return issues;
  }

  /**
   * Detect duplicates using fuzzy matching (Feature #12)
   */
  async detectDuplicates(businessId: string, entityType: string, entityId: string): Promise<any[]> {
    // Get entity data
    const entity = await this.getEntityContext(entityType, entityId, businessId);

    // Find potential duplicates
    const table = entityType === 'contact' ? 'crm_contacts' : 'crm_companies';
    const candidates = await this.env.DB_MAIN.prepare(`
      SELECT * FROM ${table}
      WHERE business_id = ? AND id != ?
      LIMIT 100
    `).bind(businessId, entityId).all();

    const duplicates: any[] = [];

    for (const candidate of (candidates.results || []) as any[]) {
      const nameSim = this.stringSimilarity(entity.name || '', candidate.name || '');
      const emailSim = this.stringSimilarity(entity.email || '', candidate.email || '');
      const phoneSim = this.stringSimilarity(entity.phone || '', candidate.phone || '');

      const overall = (nameSim * 0.5 + emailSim * 0.3 + phoneSim * 0.2);

      if (overall > 0.7) { // 70% similarity threshold
        const id = crypto.randomUUID().replace(/-/g, '');
        await this.env.DB_MAIN.prepare(`
          INSERT OR IGNORE INTO crm_duplicate_pairs (
            id, business_id, entity_type, entity_1_id, entity_2_id,
            overall_confidence, name_similarity, email_similarity, phone_similarity,
            matching_fields, differing_fields
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          id, businessId, entityType, entityId, candidate.id,
          overall, nameSim, emailSim, phoneSim,
          JSON.stringify(['name']),
          JSON.stringify([])
        ).run();

        duplicates.push({
          id,
          candidate_id: candidate.id,
          confidence: overall,
          name_similarity: nameSim
        });
      }
    }

    return duplicates;
  }

  /**
   * Helper methods
   */
  private async getEntityContext(entityType: string, entityId: string, businessId: string): Promise<any> {
    const table = entityType === 'contact' ? 'crm_contacts' :
                  entityType === 'deal' ? 'crm_deals' : 'crm_companies';

    return await this.env.DB_MAIN.prepare(`
      SELECT * FROM ${table} WHERE id = ? AND business_id = ?
    `).bind(entityId, businessId).first() || {};
  }

  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  private isValidPhone(phone: string): boolean {
    return /^[\d\s\-\+\(\)]{10,}$/.test(phone);
  }

  private stringSimilarity(str1: string, str2: string): number {
    if (!str1 || !str2) return 0;
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    if (longer.length === 0) return 1.0;

    const editDistance = this.levenshteinDistance(longer.toLowerCase(), shorter.toLowerCase());
    return (longer.length - editDistance) / longer.length;
  }

  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }
}
