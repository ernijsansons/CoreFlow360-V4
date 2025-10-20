/**
 * Deal Health Scoring Service
 * AI-powered deal health analysis with engagement velocity tracking
 * Feature #5 - Phase 1 Sprint 1
 */

import type { Env } from '../../types/env';

export interface DealHealthScore {
  id: string;
  deal_id: string;
  health_score: number;
  health_status: 'critical' | 'at_risk' | 'healthy' | 'excellent';
  win_probability: number;
  predicted_outcome: 'win' | 'loss' | 'uncertain';
  engagement_score: number;
  velocity_score: number;
  stakeholder_score: number;
  risk_factors: string[];
  recommended_actions: string[];
  coaching_tips: string[];
  scored_at: string;
}

export interface EngagementEvent {
  event_type: string;
  event_timestamp: string;
  stakeholder_id?: string;
  engagement_value: number;
}

export class DealHealthService {
  constructor(private env: Env) {}

  /**
   * Calculate comprehensive deal health score
   */
  async calculateDealHealth(businessId: string, dealId: string): Promise<DealHealthScore> {
    // Get deal details
    const deal = await this.getDeal(businessId, dealId);
    if (!deal) {
      throw new Error('Deal not found');
    }

    // Calculate component scores
    const engagementScore = await this.calculateEngagementScore(dealId);
    const velocityScore = await this.calculateVelocityScore(dealId, deal);
    const stakeholderScore = await this.calculateStakeholderScore(dealId);
    const budgetScore = this.calculateBudgetScore(deal);
    const timelineScore = this.calculateTimelineScore(deal);

    // Weighted overall health score
    const weights = {
      engagement: 0.30,
      velocity: 0.25,
      stakeholder: 0.25,
      budget: 0.10,
      timeline: 0.10
    };

    const healthScore = Math.round(
      engagementScore * weights.engagement +
      velocityScore * weights.velocity +
      stakeholderScore * weights.stakeholder +
      budgetScore * weights.budget +
      timelineScore * weights.timeline
    );

    // Determine health status
    const healthStatus = this.getHealthStatus(healthScore);

    // Calculate win probability using AI
    const winProbability = await this.calculateWinProbability(
      deal,
      healthScore,
      engagementScore,
      stakeholderScore
    );

    // Identify risk factors
    const riskFactors = await this.identifyRiskFactors(dealId, deal, {
      engagement: engagementScore,
      velocity: velocityScore,
      stakeholder: stakeholderScore
    });

    // Generate AI recommendations
    const { recommendedActions, coachingTips } = await this.generateRecommendations(
      deal,
      healthScore,
      riskFactors
    );

    // Get previous score for trend
    const previousScore = await this.getPreviousHealthScore(dealId);

    // Save to database
    const id = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_deal_health_scores (
        id, business_id, deal_id, health_score, health_status, trend,
        win_probability, predicted_outcome, confidence_level,
        engagement_score, velocity_score, stakeholder_score, budget_score, timeline_score,
        days_since_last_activity, risk_factors, recommended_actions, coaching_tips,
        previous_health_score, scored_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id, businessId, dealId, healthScore, healthStatus,
      this.calculateTrend(healthScore, previousScore),
      winProbability,
      winProbability > 0.6 ? 'win' : winProbability < 0.4 ? 'loss' : 'uncertain',
      this.determineConfidence(engagementScore, stakeholderScore),
      engagementScore, velocityScore, stakeholderScore, budgetScore, timelineScore,
      await this.getDaysSinceLastActivity(dealId),
      JSON.stringify(riskFactors),
      JSON.stringify(recommendedActions),
      JSON.stringify(coachingTips),
      previousScore,
      now
    ).run();

    return {
      id,
      deal_id: dealId,
      health_score: healthScore,
      health_status: healthStatus,
      win_probability: winProbability,
      predicted_outcome: winProbability > 0.6 ? 'win' : winProbability < 0.4 ? 'loss' : 'uncertain',
      engagement_score: engagementScore,
      velocity_score: velocityScore,
      stakeholder_score: stakeholderScore,
      risk_factors: riskFactors,
      recommended_actions: recommendedActions,
      coaching_tips: coachingTips,
      scored_at: now
    };
  }

  /**
   * Track engagement event
   */
  async trackEngagementEvent(
    businessId: string,
    dealId: string,
    eventType: string,
    metadata: {
      stakeholder_id?: string;
      sales_rep_id?: string;
      engagement_value?: number;
    }
  ): Promise<void> {
    const id = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();

    // Calculate engagement value if not provided
    const engagementValue = metadata.engagement_value ?? this.getEventEngagementValue(eventType);

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_deal_engagement_events (
        id, business_id, deal_id, event_type, event_timestamp,
        stakeholder_id, sales_rep_id, engagement_value, event_metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id, businessId, dealId, eventType, now,
      metadata.stakeholder_id || null,
      metadata.sales_rep_id || null,
      engagementValue,
      JSON.stringify(metadata)
    ).run();

    // Auto-recalculate health score on significant events
    if (Math.abs(engagementValue) >= 5) {
      await this.calculateDealHealth(businessId, dealId);
    }
  }

  /**
   * Calculate engagement score (0-100)
   */
  private async calculateEngagementScore(dealId: string): Promise<number> {
    const metrics = await this.env.DB_MAIN.prepare(`
      SELECT
        COUNT(*) as total_events,
        COUNT(CASE WHEN event_type LIKE 'email_opened%' THEN 1 END) as email_opens,
        COUNT(CASE WHEN event_type LIKE 'email_clicked%' THEN 1 END) as email_clicks,
        COUNT(CASE WHEN event_type LIKE 'meeting_completed%' THEN 1 END) as meetings,
        COUNT(CASE WHEN event_type LIKE 'document_viewed%' THEN 1 END) as doc_views,
        AVG(engagement_value) as avg_engagement,
        julianday('now') - julianday(MAX(event_timestamp)) as days_since_last
      FROM crm_deal_engagement_events
      WHERE deal_id = ?
        AND event_timestamp >= datetime('now', '-30 days')
    `).bind(dealId).first() as any;

    if (!metrics || !metrics.total_events) return 20; // Low score if no activity

    let score = 0;

    // Activity volume (0-40 points)
    if (metrics.total_events >= 20) score += 40;
    else if (metrics.total_events >= 10) score += 30;
    else if (metrics.total_events >= 5) score += 20;
    else score += 10;

    // Meeting engagement (0-30 points)
    if (metrics.meetings >= 4) score += 30;
    else if (metrics.meetings >= 2) score += 20;
    else if (metrics.meetings >= 1) score += 10;

    // Email engagement (0-20 points)
    const emailEngagement = (metrics.email_opens || 0) + (metrics.email_clicks || 0) * 2;
    score += Math.min(20, emailEngagement * 2);

    // Recency penalty (0-10 points deduction)
    if (metrics.days_since_last > 14) score -= 10;
    else if (metrics.days_since_last > 7) score -= 5;

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Calculate velocity score (0-100)
   */
  private async calculateVelocityScore(dealId: string, deal: any): Promise<number> {
    const events = await this.env.DB_MAIN.prepare(`
      SELECT event_type, event_timestamp
      FROM crm_deal_engagement_events
      WHERE deal_id = ?
      ORDER BY event_timestamp ASC
    `).bind(dealId).all();

    if (!events.results || events.results.length < 2) return 50;

    const eventList = events.results as any[];
    const firstEvent = new Date(eventList[0].event_timestamp);
    const lastEvent = new Date(eventList[eventList.length - 1].event_timestamp);
    const dealAgeDays = (lastEvent.getTime() - firstEvent.getTime()) / (1000 * 60 * 60 * 24);

    // Count stage advancements
    const stageAdvancements = eventList.filter((e: any) => e.event_type === 'stage_advanced').length;

    // Calculate velocity (stages per 30 days)
    const velocityRate = dealAgeDays > 0 ? (stageAdvancements / dealAgeDays) * 30 : 0;

    // Score based on velocity
    let score = 50; // Baseline

    if (velocityRate >= 2) score = 100;       // 2+ stages per month = excellent
    else if (velocityRate >= 1) score = 85;   // 1 stage per month = good
    else if (velocityRate >= 0.5) score = 70; // 1 stage per 2 months = okay
    else if (velocityRate >= 0.25) score = 50;// 1 stage per 4 months = slow
    else score = 30;                           // Slower = concerning

    // Penalty for stalled deals
    const daysSinceLastAdvancement = await this.getDaysSinceEvent(dealId, 'stage_advanced');
    if (daysSinceLastAdvancement > 60) score -= 30;
    else if (daysSinceLastAdvancement > 30) score -= 15;

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Calculate stakeholder score (0-100)
   */
  private async calculateStakeholderScore(dealId: string): Promise<number> {
    const stakeholders = await this.env.DB_MAIN.prepare(`
      SELECT
        COUNT(*) as total,
        COUNT(CASE WHEN role = 'champion' THEN 1 END) as champions,
        COUNT(CASE WHEN role = 'decision_maker' THEN 1 END) as decision_makers,
        COUNT(CASE WHEN engagement_level IN ('high', 'very_high') THEN 1 END) as highly_engaged,
        COUNT(CASE WHEN sentiment IN ('positive', 'very_positive') THEN 1 END) as positive_sentiment
      FROM crm_deal_stakeholders
      WHERE deal_id = ? AND status = 'active'
    `).bind(dealId).first() as any;

    if (!stakeholders || stakeholders.total === 0) return 10; // Very low if no stakeholders

    let score = 0;

    // Champion presence (0-30 points)
    if (stakeholders.champions >= 1) score += 30;

    // Decision maker engagement (0-30 points)
    if (stakeholders.decision_makers >= 1) score += 30;
    else score -= 20; // Penalty for no decision maker

    // Multi-threading (0-25 points)
    if (stakeholders.total >= 5) score += 25;
    else if (stakeholders.total >= 3) score += 20;
    else if (stakeholders.total >= 2) score += 10;

    // Engagement level (0-15 points)
    const engagementRate = stakeholders.total > 0 ? stakeholders.highly_engaged / stakeholders.total : 0;
    score += Math.round(engagementRate * 15);

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Calculate budget score (0-100)
   */
  private calculateBudgetScore(deal: any): number {
    if (!deal.deal_value) return 50; // Neutral if no value

    // Check if budget is confirmed
    if (deal.budget_confirmed) return 100;

    // Check if deal value is reasonable
    if (deal.deal_value > 0) return 70;

    return 40; // Low score if budget unclear
  }

  /**
   * Calculate timeline score (0-100)
   */
  private calculateTimelineScore(deal: any): number {
    if (!deal.expected_close_date) return 50;

    const closeDate = new Date(deal.expected_close_date);
    const now = new Date();
    const daysToClose = (closeDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

    // Score based on realistic timeline
    if (daysToClose < 0) return 20;              // Overdue = bad
    if (daysToClose <= 30) return 100;           // Closing soon = excellent
    if (daysToClose <= 60) return 85;            // < 2 months = good
    if (daysToClose <= 90) return 70;            // < 3 months = okay
    if (daysToClose <= 180) return 55;           // < 6 months = acceptable
    return 40;                                    // > 6 months = concerning
  }

  /**
   * Calculate win probability using AI
   */
  private async calculateWinProbability(
    deal: any,
    healthScore: number,
    engagementScore: number,
    stakeholderScore: number
  ): Promise<number> {
    // Simple formula (can enhance with ML later)
    const baseProb = healthScore / 100;
    const engagementBoost = (engagementScore - 50) / 200; // -0.25 to +0.25
    const stakeholderBoost = (stakeholderScore - 50) / 200;

    const winProb = baseProb + engagementBoost + stakeholderBoost;

    return Math.max(0, Math.min(1, winProb));
  }

  /**
   * Identify risk factors
   */
  private async identifyRiskFactors(
    dealId: string,
    deal: any,
    scores: { engagement: number; velocity: number; stakeholder: number }
  ): Promise<string[]> {
    const risks: string[] = [];

    // Check for low engagement
    if (scores.engagement < 40) {
      risks.push('Low customer engagement - minimal activity in past 30 days');
    }

    // Check for slow velocity
    if (scores.velocity < 40) {
      risks.push('Deal velocity below target - stages not progressing');
    }

    // Check stakeholder coverage
    if (scores.stakeholder < 40) {
      risks.push('Insufficient stakeholder engagement - missing champion or decision maker');
    }

    // Check for no recent activity
    const daysSince = await this.getDaysSinceLastActivity(dealId);
    if (daysSince > 14) {
      risks.push(`No activity in ${daysSince} days - deal may be stalled`);
    }

    // Check for competitive threats
    const competitorMentions = await this.env.DB_MAIN.prepare(`
      SELECT COUNT(*) as count
      FROM crm_deal_engagement_events
      WHERE deal_id = ? AND event_type = 'competitor_mentioned'
    `).bind(dealId).first() as any;

    if (competitorMentions?.count > 0) {
      risks.push(`Competitive threat detected (${competitorMentions.count} mentions)`);
    }

    return risks;
  }

  /**
   * Generate AI-powered recommendations
   */
  private async generateRecommendations(
    deal: any,
    healthScore: number,
    riskFactors: string[]
  ): Promise<{ recommendedActions: string[]; coachingTips: string[] }> {
    const actions: string[] = [];
    const tips: string[] = [];

    if (healthScore < 40) {
      actions.push('Schedule immediate call with champion to assess deal status');
      actions.push('Review and address all open objections');
      tips.push('Focus on re-engaging decision makers with value proposition');
    } else if (healthScore < 60) {
      actions.push('Increase touchpoint frequency with key stakeholders');
      actions.push('Provide ROI calculator or business case document');
      tips.push('Identify and nurture additional champions within account');
    } else if (healthScore >= 80) {
      actions.push('Prepare proposal and pricing for presentation');
      actions.push('Schedule final decision meeting with economic buyer');
      tips.push('Maintain momentum - avoid delays in contracting');
    }

    // Risk-specific actions
    for (const risk of riskFactors) {
      if (risk.includes('engagement')) {
        actions.push('Send personalized email with relevant case study');
      }
      if (risk.includes('stakeholder')) {
        actions.push('Map stakeholder relationships and identify missing connections');
      }
      if (risk.includes('stalled')) {
        actions.push('Run discovery call to uncover blockers');
      }
    }

    return {
      recommendedActions: actions.slice(0, 5),
      coachingTips: tips.slice(0, 3)
    };
  }

  /**
   * Helper methods
   */
  private getHealthStatus(score: number): 'critical' | 'at_risk' | 'healthy' | 'excellent' {
    if (score >= 80) return 'excellent';
    if (score >= 60) return 'healthy';
    if (score >= 40) return 'at_risk';
    return 'critical';
  }

  private calculateTrend(current: number, previous: number | null): 'improving' | 'stable' | 'declining' | null {
    if (!previous) return null;
    const delta = current - previous;
    if (delta > 10) return 'improving';
    if (delta < -10) return 'declining';
    return 'stable';
  }

  private determineConfidence(engagementScore: number, stakeholderScore: number): string {
    const avgScore = (engagementScore + stakeholderScore) / 2;
    if (avgScore >= 80) return 'very_high';
    if (avgScore >= 60) return 'high';
    if (avgScore >= 40) return 'medium';
    return 'low';
  }

  private getEventEngagementValue(eventType: string): number {
    const values: Record<string, number> = {
      'meeting_completed': 10,
      'proposal_signed': 10,
      'demo_completed': 8,
      'email_replied': 5,
      'document_viewed': 3,
      'email_opened': 1,
      'meeting_no_show': -5,
      'objection_raised': -3,
      'competitor_mentioned': -2
    };
    return values[eventType] || 0;
  }

  private async getDeal(businessId: string, dealId: string): Promise<any> {
    return await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_deals
      WHERE id = ? AND business_id = ?
    `).bind(dealId, businessId).first();
  }

  private async getPreviousHealthScore(dealId: string): Promise<number | null> {
    const result = await this.env.DB_MAIN.prepare(`
      SELECT health_score FROM crm_deal_health_scores
      WHERE deal_id = ?
      ORDER BY scored_at DESC
      LIMIT 1 OFFSET 1
    `).bind(dealId).first() as any;

    return result?.health_score || null;
  }

  private async getDaysSinceLastActivity(dealId: string): Promise<number> {
    const result = await this.env.DB_MAIN.prepare(`
      SELECT julianday('now') - julianday(MAX(event_timestamp)) as days
      FROM crm_deal_engagement_events
      WHERE deal_id = ?
    `).bind(dealId).first() as any;

    return Math.round(result?.days || 0);
  }

  private async getDaysSinceEvent(dealId: string, eventType: string): Promise<number> {
    const result = await this.env.DB_MAIN.prepare(`
      SELECT julianday('now') - julianday(MAX(event_timestamp)) as days
      FROM crm_deal_engagement_events
      WHERE deal_id = ? AND event_type = ?
    `).bind(dealId, eventType).first() as any;

    return Math.round(result?.days || 999);
  }
}
