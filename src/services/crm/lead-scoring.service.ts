/**
 * Predictive Lead Scoring Service
 * ML-powered lead scoring using Cloudflare Workers AI
 * Feature #4 - Phase 1 Sprint 1
 */

import type { Env } from '../../types/env';

export interface LeadScore {
  id: string;
  entity_id: string;
  entity_type: 'contact' | 'lead' | 'company';
  score: number; // 0-100
  confidence_level: 'low' | 'medium' | 'high' | 'very_high';
  conversion_probability: number; // 0.0-1.0
  predicted_deal_size?: number;
  predicted_time_to_close?: number; // days
  primary_drivers: string[];
  negative_factors: string[];
  ai_reasoning?: string;
  recommended_actions: string[];
  scored_at: string;
}

export interface ScoringModel {
  id: string;
  model_name: string;
  model_type: 'ml_regression' | 'rule_based' | 'hybrid' | 'custom';
  feature_weights: Record<string, number>;
  conversion_threshold: number;
  accuracy_rate?: number;
  status: 'draft' | 'training' | 'active' | 'archived';
  workers_ai_model?: string;
}

export interface ScoringFeatures {
  // Demographic
  job_title?: string;
  seniority_level?: string;
  department?: string;
  location?: string;

  // Firmographic
  company_size?: number;
  company_revenue?: number;
  industry?: string;
  company_growth_rate?: number;

  // Behavioral
  website_visits?: number;
  email_opens?: number;
  email_clicks?: number;
  content_downloads?: number;
  webinar_attendance?: number;

  // Engagement
  meeting_count?: number;
  response_rate?: number;
  last_interaction_days?: number;
  engagement_frequency?: number;

  // Data Quality
  data_completeness?: number;
  profile_enriched?: boolean;
  linkedin_connected?: boolean;
}

export class LeadScoringService {
  constructor(private env: Env) {}

  /**
   * Calculate lead score using active model
   */
  async calculateLeadScore(
    businessId: string,
    entityId: string,
    entityType: 'contact' | 'lead' | 'company'
  ): Promise<LeadScore> {
    // Get default active model
    const model = await this.getDefaultModel(businessId);
    if (!model) {
      throw new Error('No active scoring model found');
    }

    // Fetch entity data and extract features
    const features = await this.extractFeatures(businessId, entityId, entityType);

    // Calculate score based on model type
    let score: number;
    let aiReasoning: string | undefined;
    let primaryDrivers: string[] = [];
    let negativeFactors: string[] = [];

    switch (model.model_type) {
      case 'ml_regression':
        const mlResult = await this.calculateMLScore(model, features);
        score = mlResult.score;
        aiReasoning = mlResult.reasoning;
        primaryDrivers = mlResult.primary_drivers;
        negativeFactors = mlResult.negative_factors;
        break;

      case 'rule_based':
        const ruleResult = await this.calculateRuleBasedScore(businessId, model.id, features);
        score = ruleResult.score;
        primaryDrivers = ruleResult.primary_drivers;
        negativeFactors = ruleResult.negative_factors;
        break;

      case 'hybrid':
        // Combine ML and rules
        const mlScore = await this.calculateMLScore(model, features);
        const ruleScore = await this.calculateRuleBasedScore(businessId, model.id, features);
        score = Math.round((mlScore.score * 0.7) + (ruleScore.score * 0.3));
        aiReasoning = mlScore.reasoning;
        primaryDrivers = [...mlScore.primary_drivers, ...ruleScore.primary_drivers].slice(0, 5);
        negativeFactors = [...mlScore.negative_factors, ...ruleScore.negative_factors].slice(0, 5);
        break;

      default:
        throw new Error(`Unsupported model type: ${model.model_type}`);
    }

    // Calculate conversion probability
    const conversionProbability = this.scoreToConversionProbability(score);

    // Get previous score for trend analysis
    const previousScore = await this.getPreviousScore(entityId, entityType);

    // Generate recommended actions
    const recommendedActions = this.generateRecommendedActions(score, features, primaryDrivers);

    // Predict deal metrics
    const { dealSize, daysToClose } = await this.predictDealMetrics(features, score);

    // Determine confidence level
    const confidenceLevel = this.determineConfidence(features, score);

    // Save score to database
    const scoreId = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_lead_scores (
        id, business_id, entity_id, entity_type, model_id, score,
        confidence_level, feature_scores, primary_drivers, negative_factors,
        conversion_probability, predicted_deal_size, predicted_time_to_close,
        ai_reasoning, recommended_actions, previous_score,
        score_trend, scored_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      scoreId,
      businessId,
      entityId,
      entityType,
      model.id,
      score,
      confidenceLevel,
      JSON.stringify(this.calculateFeatureScores(features, model.feature_weights)),
      JSON.stringify(primaryDrivers),
      JSON.stringify(negativeFactors),
      conversionProbability,
      dealSize,
      daysToClose,
      aiReasoning,
      JSON.stringify(recommendedActions),
      previousScore,
      this.calculateScoreTrend(score, previousScore),
      now,
      new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days expiry
    ).run();

    return {
      id: scoreId,
      entity_id: entityId,
      entity_type: entityType,
      score,
      confidence_level: confidenceLevel,
      conversion_probability: conversionProbability,
      predicted_deal_size: dealSize,
      predicted_time_to_close: daysToClose,
      primary_drivers: primaryDrivers,
      negative_factors: negativeFactors,
      ai_reasoning: aiReasoning,
      recommended_actions: recommendedActions,
      scored_at: now
    };
  }

  /**
   * Calculate ML-powered score using Cloudflare Workers AI
   */
  private async calculateMLScore(
    model: ScoringModel,
    features: ScoringFeatures
  ): Promise<{ score: number; reasoning: string; primary_drivers: string[]; negative_factors: string[] }> {
    // Build prompt for Workers AI
    const prompt = this.buildScoringPrompt(features, model.feature_weights);

    try {
      // Call Cloudflare Workers AI
      const response = await this.env.AI?.run((model.workers_ai_model || '@cf/meta/llama-3-8b-instruct') as any, {
        prompt,
        max_tokens: 512,
        temperature: 0.1,
      }) as any;

      // Parse AI response
      const aiOutput = response.response || response.text || '';
      const parsedResult = this.parseAIResponse(aiOutput);

      return {
        score: parsedResult.score,
        reasoning: parsedResult.reasoning,
        primary_drivers: parsedResult.primary_drivers,
        negative_factors: parsedResult.negative_factors
      };
    } catch (error) {
      console.error('Workers AI scoring error:', error);
      // Fallback to simple weighted scoring
      return this.calculateWeightedScore(features, model.feature_weights);
    }
  }

  /**
   * Build prompt for Workers AI lead scoring
   */
  private buildScoringPrompt(features: ScoringFeatures, weights: Record<string, number>): string {
    return `You are a B2B lead scoring AI. Score this lead from 0-100 based on conversion likelihood.

Lead Profile:
${Object.entries(features).map(([key, value]) => `- ${key}: ${value}`).join('\n')}

Feature Importance Weights:
${Object.entries(weights).map(([key, weight]) => `- ${key}: ${(weight * 100).toFixed(0)}%`).join('\n')}

Provide your analysis in this EXACT JSON format:
{
  "score": 85,
  "reasoning": "High score due to C-level title and large company size",
  "primary_drivers": ["C-level executive", "Fortune 500 company", "High engagement"],
  "negative_factors": ["Limited budget information", "No recent interaction"]
}

Response (JSON only):`;
  }

  /**
   * Parse AI response to extract score and insights
   */
  private parseAIResponse(aiOutput: string): {
    score: number;
    reasoning: string;
    primary_drivers: string[];
    negative_factors: string[];
  } {
    try {
      // Extract JSON from response
      const jsonMatch = aiOutput.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('No JSON found in AI response');
      }

      const parsed = JSON.parse(jsonMatch[0]);
      return {
        score: Math.min(100, Math.max(0, parsed.score || 50)),
        reasoning: parsed.reasoning || 'AI scoring completed',
        primary_drivers: parsed.primary_drivers || [],
        negative_factors: parsed.negative_factors || []
      };
    } catch (error) {
      console.error('Failed to parse AI response:', error);
      return {
        score: 50,
        reasoning: 'Unable to parse AI response',
        primary_drivers: [],
        negative_factors: []
      };
    }
  }

  /**
   * Calculate weighted score (fallback method)
   */
  private calculateWeightedScore(
    features: ScoringFeatures,
    weights: Record<string, number>
  ): { score: number; reasoning: string; primary_drivers: string[]; negative_factors: string[] } {
    let totalScore = 0;
    let totalWeight = 0;
    const drivers: Array<{ text: string; score: number }> = [];

    // Seniority scoring
    if (features.seniority_level && weights.seniority) {
      const seniorityScore = this.scoreSeniority(features.seniority_level);
      totalScore += seniorityScore * weights.seniority;
      totalWeight += weights.seniority;
      if (seniorityScore >= 80) {
        drivers.push({ text: `${features.seniority_level} seniority level`, score: seniorityScore });
      }
    }

    // Company size scoring
    if (features.company_size && weights.company_size) {
      const sizeScore = this.scoreCompanySize(features.company_size);
      totalScore += sizeScore * weights.company_size;
      totalWeight += weights.company_size;
      if (sizeScore >= 80) {
        drivers.push({ text: `${features.company_size}+ employees`, score: sizeScore });
      }
    }

    // Engagement scoring
    if (weights.engagement) {
      const engagementScore = this.scoreEngagement(features);
      totalScore += engagementScore * weights.engagement;
      totalWeight += weights.engagement;
      if (engagementScore >= 70) {
        drivers.push({ text: 'High engagement activity', score: engagementScore });
      }
    }

    // Data completeness scoring
    if (features.data_completeness && weights.data_quality) {
      const qualityScore = features.data_completeness;
      totalScore += qualityScore * weights.data_quality;
      totalWeight += weights.data_quality;
    }

    const finalScore = totalWeight > 0 ? Math.round(totalScore / totalWeight) : 50;

    // Sort drivers by score and take top 3
    const primaryDrivers = drivers
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map(d => d.text);

    // Identify negative factors
    const negativeFactors: string[] = [];
    if (features.last_interaction_days && features.last_interaction_days > 30) {
      negativeFactors.push('No recent interaction (30+ days)');
    }
    if (features.data_completeness && features.data_completeness < 50) {
      negativeFactors.push('Low data completeness');
    }
    if (!features.linkedin_connected) {
      negativeFactors.push('Not connected on LinkedIn');
    }

    return {
      score: finalScore,
      reasoning: `Weighted score based on ${primaryDrivers.length} key factors`,
      primary_drivers: primaryDrivers,
      negative_factors: negativeFactors
    };
  }

  /**
   * Calculate rule-based score
   */
  private async calculateRuleBasedScore(
    businessId: string,
    modelId: string,
    features: ScoringFeatures
  ): Promise<{ score: number; primary_drivers: string[]; negative_factors: string[] }> {
    // Get active rules for model
    const rulesResult = await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_scoring_rules
      WHERE business_id = ? AND model_id = ? AND is_active = 1
      ORDER BY priority DESC
    `).bind(businessId, modelId).all();

    const rules = (rulesResult.results || []) as any[];

    let totalPoints = 0;
    const matchedRules: string[] = [];

    for (const rule of rules) {
      const fieldValue = (features as any)[rule.field_name];
      const ruleMatches = this.evaluateRule(
        fieldValue,
        rule.operator,
        rule.field_value
      );

      if (ruleMatches) {
        totalPoints += rule.points_if_match * rule.weight;
        matchedRules.push(rule.rule_name);
      }
    }

    // Normalize to 0-100
    const score = Math.min(100, Math.max(0, totalPoints));

    return {
      score: Math.round(score),
      primary_drivers: matchedRules.slice(0, 5),
      negative_factors: []
    };
  }

  /**
   * Evaluate a single scoring rule
   */
  private evaluateRule(fieldValue: any, operator: string, expectedValue: string): boolean {
    switch (operator) {
      case 'equals':
        return String(fieldValue) === expectedValue;
      case 'not_equals':
        return String(fieldValue) !== expectedValue;
      case 'contains':
        return String(fieldValue).toLowerCase().includes(expectedValue.toLowerCase());
      case 'not_contains':
        return !String(fieldValue).toLowerCase().includes(expectedValue.toLowerCase());
      case 'greater_than':
        return Number(fieldValue) > Number(expectedValue);
      case 'less_than':
        return Number(fieldValue) < Number(expectedValue);
      case 'in_list':
        const list = expectedValue.split(',').map(v => v.trim());
        return list.includes(String(fieldValue));
      case 'matches_regex':
        return new RegExp(expectedValue).test(String(fieldValue));
      default:
        return false;
    }
  }

  /**
   * Extract features from entity data
   */
  private async extractFeatures(
    businessId: string,
    entityId: string,
    entityType: string
  ): Promise<ScoringFeatures> {
    // Get entity data with enrichment
    const entity = await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_contacts
      WHERE id = ? AND business_id = ?
    `).bind(entityId, businessId).first() as any;

    if (!entity) {
      throw new Error('Entity not found');
    }

    // Get data completeness
    const completeness = await this.env.DB_MAIN.prepare(`
      SELECT completeness_percentage FROM crm_data_completeness
      WHERE entity_id = ? AND entity_type = ?
    `).bind(entityId, entityType).first() as any;

    return {
      job_title: entity.job_title,
      seniority_level: entity.seniority_level,
      department: entity.department,
      location: entity.location,
      company_size: entity.company_employee_count,
      industry: entity.company_industry,
      data_completeness: completeness?.completeness_percentage || 0,
      profile_enriched: entity.last_enriched_at != null,
      linkedin_connected: entity.linkedin_url != null,
      // Add more features as needed
    };
  }

  /**
   * Helper scoring functions
   */
  private scoreSeniority(level: string): number {
    const scores: Record<string, number> = {
      'c_level': 100,
      'vp': 85,
      'director': 70,
      'manager': 55,
      'individual_contributor': 40,
      'entry_level': 25
    };
    return scores[level] || 50;
  }

  private scoreCompanySize(size: number): number {
    if (size >= 10000) return 100;
    if (size >= 1000) return 85;
    if (size >= 200) return 70;
    if (size >= 50) return 55;
    if (size >= 10) return 40;
    return 25;
  }

  private scoreEngagement(features: ScoringFeatures): number {
    let score = 0;
    if (features.meeting_count && features.meeting_count > 0) score += 30;
    if (features.email_opens && features.email_opens > 3) score += 25;
    if (features.website_visits && features.website_visits > 5) score += 25;
    if (features.content_downloads && features.content_downloads > 0) score += 20;
    return Math.min(100, score);
  }

  private scoreToConversionProbability(score: number): number {
    // Sigmoid-like curve: score 70+ = 70%+ probability
    return 1 / (1 + Math.exp(-0.08 * (score - 50)));
  }

  private calculateFeatureScores(features: ScoringFeatures, weights: Record<string, number>): Record<string, number> {
    // Return individual feature scores for transparency
    return {
      seniority: features.seniority_level ? this.scoreSeniority(features.seniority_level) : 0,
      company_size: features.company_size ? this.scoreCompanySize(features.company_size) : 0,
      engagement: this.scoreEngagement(features),
      data_quality: features.data_completeness || 0
    };
  }

  private determineConfidence(features: ScoringFeatures, score: number): 'low' | 'medium' | 'high' | 'very_high' {
    const dataCompleteness = features.data_completeness || 0;
    if (dataCompleteness >= 80 && (score >= 70 || score <= 30)) return 'very_high';
    if (dataCompleteness >= 60) return 'high';
    if (dataCompleteness >= 40) return 'medium';
    return 'low';
  }

  private generateRecommendedActions(score: number, features: ScoringFeatures, drivers: string[]): string[] {
    const actions: string[] = [];

    if (score >= 80) {
      actions.push('Schedule demo call immediately');
      actions.push('Assign to senior sales rep');
      if (!features.meeting_count) {
        actions.push('Send personalized outreach via LinkedIn');
      }
    } else if (score >= 60) {
      actions.push('Add to nurture campaign');
      actions.push('Send relevant case study');
      actions.push('Invite to upcoming webinar');
    } else if (score >= 40) {
      actions.push('Continue email drip campaign');
      actions.push('Share educational content');
    } else {
      actions.push('Place in long-term nurture');
      actions.push('Monitor for engagement signals');
    }

    return actions.slice(0, 4);
  }

  private async predictDealMetrics(features: ScoringFeatures, score: number): Promise<{ dealSize: number | undefined; daysToClose: number | undefined }> {
    // Simple heuristic prediction (can be enhanced with ML later)
    let dealSize: number | undefined;
    let daysToClose: number | undefined;

    if (features.company_size) {
      // Rough correlation: larger companies = larger deals
      if (features.company_size >= 1000) dealSize = 50000;
      else if (features.company_size >= 200) dealSize = 25000;
      else if (features.company_size >= 50) dealSize = 10000;
      else dealSize = 5000;
    }

    // Time to close inversely proportional to score
    if (score >= 80) daysToClose = 30;
    else if (score >= 60) daysToClose = 60;
    else if (score >= 40) daysToClose = 90;
    else daysToClose = 120;

    return { dealSize, daysToClose };
  }

  private async getPreviousScore(entityId: string, entityType: string): Promise<number | null> {
    const previous = await this.env.DB_MAIN.prepare(`
      SELECT score FROM crm_lead_scores
      WHERE entity_id = ? AND entity_type = ?
      ORDER BY scored_at DESC
      LIMIT 1 OFFSET 1
    `).bind(entityId, entityType).first() as any;

    return previous?.score || null;
  }

  private calculateScoreTrend(currentScore: number, previousScore: number | null): 'improving' | 'declining' | 'stable' | null {
    if (!previousScore) return null;
    const delta = currentScore - previousScore;
    if (delta > 5) return 'improving';
    if (delta < -5) return 'declining';
    return 'stable';
  }

  /**
   * Get default active model for business
   */
  private async getDefaultModel(businessId: string): Promise<ScoringModel | null> {
    const result = await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_lead_scoring_models
      WHERE business_id = ? AND status = 'active' AND is_default = 1
      LIMIT 1
    `).bind(businessId).first() as any;

    if (!result) return null;

    return {
      id: result.id,
      model_name: result.model_name,
      model_type: result.model_type,
      feature_weights: JSON.parse(result.feature_weights || '{}'),
      conversion_threshold: result.conversion_threshold,
      accuracy_rate: result.accuracy_rate,
      status: result.status,
      workers_ai_model: result.workers_ai_model
    } as any;
  }
}
