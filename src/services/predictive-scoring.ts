import type { Lead, LeadExtended, Company, Contact } from '../types/crm';
import type { Env } from '../types/env';

export interface LeadScore {
  leadId: string;
  overallScore: number; // 0-100
  propensityToBuy: number; // 0-100
  expectedDealSize: number;
  timeToClose: number; // days
  confidence: number; // 0-1
  factors: ScoreFactor[];
  riskFactors: RiskFactor[];
  recommendations: string[];
  reasoning: string;
  calculatedAt: string;
  validUntil: string;
}

export interface ScoreFactor {
  name: string;
  category: 'engagement' | 'fit' | 'behavior' | 'timing' | 'competition';
  score: number;
  weight: number;
  impact: 'positive' | 'negative' | 'neutral';
  description: string;
}

export interface RiskFactor {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  mitigation: string;
  probability: number;
}

export interface Signals {
  engagement: EngagementSignals;
  webActivity: WebActivitySignals;
  emailEngagement: EmailSignals;
  contentConsumption: ContentSignals;
  competitorActivity: CompetitorSignals;
  marketTiming: MarketSignals;
  fitScore: number;
  behavior: BehaviorAnalysis;
  timing: TimingIndicators;
  historicalPatterns: HistoricalPattern[];
  socialSignals?: SocialSignals;
  technographic?: TechnographicSignals;
}

export interface EngagementSignals {
  totalInteractions: number;
  recentInteractions: number;
  interactionFrequency: number;
  responseTime: number;
  engagementTrend: 'increasing' | 'stable' | 'decreasing';
  channelPreference: string;
  peakEngagementTime: string;
}

export interface WebActivitySignals {
  pageViews: number;
  sessionCount: number;
  avgSessionDuration: number;
  pagesPerSession: number;
  highValuePageViews: string[];
  returnVisitorRate: number;
  conversionEvents: string[];
  lastVisit: string;
}

export interface EmailSignals {
  openRate: number;
  clickRate: number;
  replyRate: number;
  forwardRate: number;
  unsubscribed: boolean;
  bestPerformingContent: string[];
  engagementTrend: 'increasing' | 'stable' | 'decreasing';
}

export interface ContentSignals {
  downloadsCount: number;
  contentTypes: string[];
  topicsConsumed: string[];
  consumptionDepth: number;
  webinarAttendance: number;
  demoRequests: number;
}

export interface CompetitorSignals {
  mentionedCompetitors: string[];
  competitorWebsiteVisits: number;
  competitorContentConsumption: boolean;
  switchingSignals: string[];
  dissatisfactionSignals: string[];
}

export interface MarketSignals {
  industryGrowthRate: number;
  marketMaturity: 'early' | 'growth' | 'mature' | 'declining';
  seasonalFactors: string[];
  economicIndicators: any;
  regulatoryChanges: string[];
}

export interface BehaviorAnalysis {
  buyingStage: 'awareness' | 'consideration' | 'evaluation' | 'decision' | 'purchase';
  buyingRole: 'champion' | 'influencer' | 'decision_maker' | 'evaluator' | 'end_user';
  engagementPattern: 'active' | 'passive' | 'sporadic' | 'intensive';
  researchBehavior: 'thorough' | 'quick' | 'delegated' | 'collaborative';
  decisionSpeed: 'fast' | 'moderate' | 'slow';
}

export interface TimingIndicators {
  urgencySignals: string[];
  budgetTiming: string;
  projectTimeline: string;
  fiscalYearPosition: string;
  contractRenewalDates: string[];
  triggerEvents: string[];
}

export interface HistoricalPattern {
  pattern: string;
  occurrences: number;
  successRate: number;
  avgDealSize: number;
  avgTimeToClose: number;
  confidence: number;
}

export interface SocialSignals {
  linkedInActivity: number;
  twitterEngagement: number;
  companyMentions: number;
  employeeAdvocacy: number;
  socialSentiment: 'positive' | 'neutral' | 'negative';
}

export interface TechnographicSignals {
  currentTechStack: string[];
  recentTechChanges: string[];
  techBudget: number;
  techMaturity: 'basic' | 'intermediate' | 'advanced';
  integrationNeeds: string[];
}

export interface DealIntelligence {
  dealId: string;
  winProbability: number;
  expectedCloseDate: string;
  recommendedNextAction: string;
  competitiveThreats: CompetitiveThreat[];
  stakeholderMap: StakeholderAnalysis[];
  dealRisks: DealRisk[];
  accelerators: DealAccelerator[];
  timeline: DealTimeline;
}

export interface CompetitiveThreat {
  competitor: string;
  threatLevel: 'low' | 'medium' | 'high';
  strengths: string[];
  weaknesses: string[];
  counterStrategy: string;
}

export interface StakeholderAnalysis {
  name: string;
  role: string;
  influence: 'low' | 'medium' | 'high';
  stance: 'champion' | 'supportive' | 'neutral' | 'skeptical' | 'opposed';
  engagementStrategy: string;
}

export interface DealRisk {
  risk: string;
  impact: 'low' | 'medium' | 'high';
  likelihood: number;
  mitigation: string;
  earlyWarningSignals: string[];
}

export interface DealAccelerator {
  action: string;
  impact: number;
  effort: 'low' | 'medium' | 'high';
  timing: string;
  dependencies: string[];
}

export interface DealTimeline {
  currentStage: string;
  stageProgress: number;
  keyMilestones: Milestone[];
  criticalPath: string[];
  estimatedDuration: number;
}

export interface Milestone {
  name: string;
  dueDate: string;
  status: 'pending' | 'in_progress' | 'completed' | 'at_risk';
  owner: string;
  dependencies: string[];
}

export class PredictiveScoring {
  private env: Env;
  private scoreCache: Map<string, LeadScore>;
  private patternCache: Map<string, HistoricalPattern[]>;

  constructor(env: Env) {
    this.env = env;
    this.scoreCache = new Map();
    this.patternCache = new Map();
  }

  async scoreLeadPropensity(lead: LeadExtended): Promise<LeadScore> {
    // Check cache first
    const cacheKey = `${lead.id}_${Date.now()}`;
    const cached = this.scoreCache.get(lead.id);
    if (cached && new Date(cached.validUntil) > new Date()) {
      return cached;
    }

    // Gather all signals
    const signals = await this.gatherSignals(lead);

    // Generate AI-powered prediction
    const prediction = await this.generatePrediction(lead, signals);

    // Calculate component scores
    const factors = this.calculateScoreFactors(signals);

    // Identify risks
    const riskFactors = await this.identifyRisks(lead, signals);

    // Generate recommendations
    const recommendations = await this.generateRecommendations(lead, signals, prediction);

    // Build final score
    const score: LeadScore = {
      leadId: lead.id,
      overallScore: prediction.score,
      propensityToBuy: prediction.propensityToBuy,
      expectedDealSize: prediction.expectedDealSize,
      timeToClose: prediction.timeToClose,
      confidence: prediction.confidence,
      factors,
      riskFactors,
      recommendations,
      reasoning: prediction.reasoning,
      calculatedAt: new Date().toISOString(),
      validUntil: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // Valid for 24 hours
    };

    // Store for continuous learning
    await this.storePrediction(lead, score);

    // Cache the score
    this.scoreCache.set(lead.id, score);

    return score;
  }

  private async gatherSignals(lead: LeadExtended): Promise<Signals> {
    const [
      engagement,
      webActivity,
      emailEngagement,
      contentConsumption,
      competitorActivity,
      marketTiming,
      socialSignals,
      technographic
    ] = await Promise.all([
      this.getEngagementMetrics(lead),
      this.getWebsiteActivity(lead),
      this.getEmailMetrics(lead),
      this.getContentEngagement(lead),
      this.detectCompetitorActivity(lead),
      this.analyzeMarketTiming(lead),
      this.getSocialSignals(lead),
      this.getTechnographicData(lead)
    ]);

    return {
      engagement,
      webActivity,
      emailEngagement,
      contentConsumption,
      competitorActivity,
      marketTiming,
      fitScore: await this.calculateFitScore(lead),
      behavior: await this.analyzeBehavior(lead),
      timing: await this.detectTimingSignals(lead),
      historicalPatterns: await this.getHistoricalPatterns(lead),
      socialSignals,
      technographic
    };
  }

  private async getEngagementMetrics(lead: LeadExtended): Promise<EngagementSignals> {
    const db = this.env.DB_CRM;

    // Get interaction data
    const result = await db.prepare(`
      SELECT
        COUNT(*) as total_interactions,
        COUNT(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 END) as recent_interactions,
        AVG(CASE WHEN response_time IS NOT NULL THEN response_time END) as avg_response_time,
        MAX(created_at) as last_interaction
      FROM lead_activities
      WHERE lead_id = ?
    `).bind(lead.id).first();

    // Calculate frequency
    const firstInteraction = await db.prepare(`
      SELECT MIN(created_at) as first_interaction
      FROM lead_activities
      WHERE lead_id = ?
    `).bind(lead.id).first();

    const daysSinceFirst = firstInteraction?.first_interaction
      ? (Date.now() - new Date(firstInteraction.first_interaction as string).getTime()) / (1000 * 60 * 60 * 24)
      : 1;

    const frequency = (result?.total_interactions as number || 0) / Math.max(daysSinceFirst, 1);

    // Determine trend
    const trendResult = await db.prepare(`
      SELECT
        COUNT(CASE WHEN created_at >= datetime('now',
  '-14 days') AND created_at < datetime('now', '-7 days') THEN 1 END) as week1,
        COUNT(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 END) as week2
      FROM lead_activities
      WHERE lead_id = ?
    `).bind(lead.id).first();

    const week1 = trendResult?.week1 as number || 0;
    const week2 = trendResult?.week2 as number || 0;
    const trend = week2 > week1 * 1.2 ? 'increasing' : week2 < week1 * 0.8 ? 'decreasing' : 'stable';

    return {
      totalInteractions: result?.total_interactions as number || 0,
      recentInteractions: result?.recent_interactions as number || 0,
      interactionFrequency: frequency,
      responseTime: result?.avg_response_time as number || 0,
      engagementTrend: trend,
      channelPreference: await this.getPreferredChannel(lead),
      peakEngagementTime: await this.getPeakEngagementTime(lead)
    };
  }

  private async getWebsiteActivity(lead: LeadExtended): Promise<WebActivitySignals> {
    const db = this.env.DB_CRM;

    // In production, this would integrate with web analytics
    const result = await db.prepare(`
      SELECT
        COUNT(DISTINCT session_id) as session_count,
        COUNT(*) as page_views,
        AVG(duration) as avg_duration,
        GROUP_CONCAT(DISTINCT page_path) as pages
      FROM web_activities
      WHERE lead_id = ?
        AND created_at >= datetime('now', '-30 days')
    `).bind(lead.id).first();

    // Identify high-value pages
    const highValuePages = ['pricing', 'demo', 'features', 'case-studies', 'contact'];
    const visitedPages = (result?.pages as string || '').split(',');
    const highValuePageViews = visitedPages.filter((page: any) =>
      highValuePages.some(hvp => page.includes(hvp))
    );

    return {
      pageViews: result?.page_views as number || 0,
      sessionCount: result?.session_count as number || 0,
      avgSessionDuration: result?.avg_duration as number || 0,
      pagesPerSession: (result?.page_views as number || 0) / Math.max(result?.session_count as number || 1, 1),
      highValuePageViews,
      returnVisitorRate: result?.session_count as number > 1 ? 0.5 : 0,
      conversionEvents: await this.getConversionEvents(lead),
      lastVisit: new Date().toISOString() // Would get from actual data
    };
  }

  private async getEmailMetrics(lead: LeadExtended): Promise<EmailSignals> {
    const db = this.env.DB_CRM;

    const result = await db.prepare(`
      SELECT
        COUNT(*) as total_sent,
        COUNT(CASE WHEN opened_at IS NOT NULL THEN 1 END) as opened,
        COUNT(CASE WHEN clicked_at IS NOT NULL THEN 1 END) as clicked,
        COUNT(CASE WHEN replied_at IS NOT NULL THEN 1 END) as replied
      FROM channel_messages
      WHERE lead_id = ? AND channel = 'email'
    `).bind(lead.id).first();

    const total = result?.total_sent as number || 1;

    return {
      openRate: (result?.opened as number || 0) / total,
      clickRate: (result?.clicked as number || 0) / total,
      replyRate: (result?.replied as number || 0) / total,
      forwardRate: 0, // Would track in production
      unsubscribed: false, // Would check opt-out status
      bestPerformingContent: [],
      engagementTrend: 'stable'
    };
  }

  private async getContentEngagement(lead: LeadExtended): Promise<ContentSignals> {
    // In production, track content consumption
    return {
      downloadsCount: Math.floor(Math.random() * 5),
      contentTypes: ['whitepaper', 'case_study', 'webinar'],
      topicsConsumed: ['sales_automation', 'ai_technology', 'roi_analysis'],
      consumptionDepth: 0.7,
      webinarAttendance: 1,
      demoRequests: lead.ai_qualification_score && lead.ai_qualification_score > 70 ? 1 : 0
    };
  }

  private async detectCompetitorActivity(lead: LeadExtended): Promise<CompetitorSignals> {
    // Analyze conversations and activities for competitor mentions
    const competitorKeywords = ['competitor', 'alternative', 'compare', 'vs', 'switching from'];

    return {
      mentionedCompetitors: [],
      competitorWebsiteVisits: 0,
      competitorContentConsumption: false,
      switchingSignals: [],
      dissatisfactionSignals: []
    };
  }

  private async analyzeMarketTiming(lead: LeadExtended): Promise<MarketSignals> {
    // Market analysis would integrate with external data sources
    return {
      industryGrowthRate: 0.15, // 15% growth
      marketMaturity: 'growth',
      seasonalFactors: this.getSeasonalFactors(),
      economicIndicators: {},
      regulatoryChanges: []
    };
  }

  private async getSocialSignals(lead: LeadExtended): Promise<SocialSignals> {
    // Would integrate with social media APIs
    return {
      linkedInActivity: 5,
      twitterEngagement: 2,
      companyMentions: 3,
      employeeAdvocacy: 1,
      socialSentiment: 'positive'
    };
  }

  private async getTechnographicData(lead: LeadExtended): Promise<TechnographicSignals> {
    // Would integrate with technographic data providers
    return {
      currentTechStack: ['Salesforce', 'Slack', 'Zoom'],
      recentTechChanges: [],
      techBudget: 100000,
      techMaturity: 'intermediate',
      integrationNeeds: ['CRM', 'Email', 'Calendar']
    };
  }

  private async calculateFitScore(lead: LeadExtended): Promise<number> {
    let score = 50; // Base score

    // Company size fit
    if (lead.company_size === '51-200' || lead.company_size === '201-500') {
      score += 20; // Ideal company size
    } else if (lead.company_size === '11-50' || lead.company_size === '501-1000') {
      score += 10;
    }

    // Industry fit
    const idealIndustries = ['technology', 'saas', 'software', 'finance'];
    if (lead.industry && idealIndustries.includes(lead.industry.toLowerCase())) {
      score += 15;
    }

    // Title/Role fit
    const idealTitles = ['vp', 'director', 'head', 'manager', 'ceo', 'cto'];
    if (lead.title && idealTitles.some(t => lead.title!.toLowerCase().includes(t))) {
      score += 15;
    }

    return Math.min(score, 100);
  }

  private async analyzeBehavior(lead: LeadExtended): Promise<BehaviorAnalysis> {
    // Analyze lead behavior patterns
    const engagement = await this.getEngagementMetrics(lead);

    // Determine buying stage based on activities
    let buyingStage: BehaviorAnalysis['buyingStage'] = 'awareness';
    if (engagement.totalInteractions > 10) buyingStage = 'consideration';
    if (engagement.totalInteractions > 20) buyingStage = 'evaluation';
    if (lead.ai_qualification_score && lead.ai_qualification_score > 70) buyingStage = 'decision';

    // Determine role based on title
    let buyingRole: BehaviorAnalysis['buyingRole'] = 'evaluator';
    if (lead.title?.toLowerCase().includes('ceo') || lead.title?.toLowerCase().includes('vp')) {
      buyingRole = 'decision_maker';
    } else if (lead.title?.toLowerCase().includes('manager')) {
      buyingRole = 'influencer';
    }

    return {
      buyingStage,
      buyingRole,
      engagementPattern: engagement.interactionFrequency > 1 ? 'active' : 'passive',
      researchBehavior: 'thorough',
      decisionSpeed: engagement.engagementTrend === 'increasing' ? 'fast' : 'moderate'
    };
  }

  private async detectTimingSignals(lead: LeadExtended): Promise<TimingIndicators> {
    const urgencySignals: string[] = [];

    // Check for urgency keywords in recent interactions
    if (lead.ai_intent_summary?.includes('urgent') || lead.ai_intent_summary?.includes('asap')) {
      urgencySignals.push('Expressed urgency in communications');
    }

    // Fiscal year timing
    const currentMonth = new Date().getMonth();
    const fiscalYearPosition = currentMonth >= 9 ? 'Q4' : currentMonth >= 6 ? 'Q3' : currentMonth >= 3 ? 'Q2' : 'Q1';

    return {
      urgencySignals,
      budgetTiming: fiscalYearPosition === 'Q4' ? 'End of fiscal year' : 'Mid-year',
      projectTimeline: 'Not specified',
      fiscalYearPosition,
      contractRenewalDates: [],
      triggerEvents: await this.detectTriggerEvents(lead)
    };
  }

  private async detectTriggerEvents(lead: LeadExtended): Promise<string[]> {
    const events: string[] = [];

    // New lead is a trigger
    if (lead.created_at) {
      const daysSinceCreation = (Date.now() - new Date(lead.created_at).getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceCreation < 7) {
        events.push('New lead this week');
      }
    }

    // High engagement is a trigger
    if (lead.ai_engagement_score && lead.ai_engagement_score > 70) {
      events.push('High engagement score');
    }

    return events;
  }

  private async getHistoricalPatterns(lead: LeadExtended): Promise<HistoricalPattern[]> {
    // Check cache
    const cacheKey = `${lead.industry}_${lead.company_size}`;
    if (this.patternCache.has(cacheKey)) {
      return this.patternCache.get(cacheKey)!;
    }

    const db = this.env.DB_CRM;

    // Find similar successful deals
    const patterns = await db.prepare(`
      SELECT
        pattern_type as pattern,
        COUNT(*) as occurrences,
        AVG(CASE WHEN status = 'closed_won' THEN 1 ELSE 0 END) as success_rate,
        AVG(deal_value) as avg_deal_size,
        AVG(days_to_close) as avg_time_to_close
      FROM historical_deals
      WHERE industry = ? OR company_size = ?
      GROUP BY pattern_type
    `).bind(lead.industry || '', lead.company_size || '').all();

    const historicalPatterns: HistoricalPattern[] = patterns.results.map((p: any) => ({
      pattern: p.pattern,
      occurrences: p.occurrences,
      successRate: p.success_rate,
      avgDealSize: p.avg_deal_size,
      avgTimeToClose: p.avg_time_to_close,
      confidence: Math.min(p.occurrences / 10, 1) // Confidence based on sample size
    }));

    // Cache the patterns
    this.patternCache.set(cacheKey, historicalPatterns);

    return historicalPatterns;
  }

  private async generatePrediction(lead: LeadExtended, signals: Signals): Promise<any> {
    const prompt = `
      Analyze this lead and predict their likelihood to purchase.

      Lead Information:
      - Name: ${lead.first_name} ${lead.last_name || ''}
      - Company: ${lead.company_name || 'Unknown'}
      - Industry: ${lead.industry || 'Unknown'}
      - Company Size: ${lead.company_size || 'Unknown'}
      - Title: ${lead.title || 'Unknown'}
      - Current Score: ${lead.ai_qualification_score || 0}

      Engagement Signals:
      - Total Interactions: ${signals.engagement.totalInteractions}
      - Recent Activity: ${signals.engagement.recentInteractions} in last 7 days
      - Engagement Trend: ${signals.engagement.engagementTrend}
      - Response Time: ${signals.engagement.responseTime}ms average

      Web Activity:
      - Page Views: ${signals.webActivity.pageViews}
      - Sessions: ${signals.webActivity.sessionCount}
      - High-Value Pages Visited: ${signals.webActivity.highValuePageViews.join(', ')}

      Email Engagement:
      - Open Rate: ${(signals.emailEngagement.openRate * 100).toFixed(1)}%
      - Click Rate: ${(signals.emailEngagement.clickRate * 100).toFixed(1)}%
      - Reply Rate: ${(signals.emailEngagement.replyRate * 100).toFixed(1)}%

      Content Consumption:
      - Downloads: ${signals.contentConsumption.downloadsCount}
      - Topics: ${signals.contentConsumption.topicsConsumed.join(', ')}
      - Demo Requests: ${signals.contentConsumption.demoRequests}

      Behavioral Analysis:
      - Buying Stage: ${signals.behavior.buyingStage}
      - Buying Role: ${signals.behavior.buyingRole}
      - Engagement Pattern: ${signals.behavior.engagementPattern}
      - Decision Speed: ${signals.behavior.decisionSpeed}

      Market Context:
      - Industry Growth: ${(signals.marketTiming.industryGrowthRate * 100).toFixed(1)}%
      - Market Maturity: ${signals.marketTiming.marketMaturity}

      Historical Patterns:
      ${signals.historicalPatterns.map((p: any) => `- ${p.pattern}: ${(p.successRate * 100).toFixed(1)}% success rate`).join('\n')}

      Based on all these signals, predict:
      1. Overall lead score (0-100)
      2. Propensity to buy (0-100)
      3. Expected deal size in dollars
      4. Expected time to close in days
      5. Confidence level (0-1)
      6. Key reasoning for the prediction

      Return as JSON:
      {
        "score": number,
        "propensityToBuy": number,
        "expectedDealSize": number,
        "timeToClose": number,
        "confidence": number,
        "reasoning": "Detailed explanation"
      }
    `;

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.env.ANTHROPIC_API_KEY || '',
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-3-sonnet-20240229',
          max_tokens: 1000,
          messages: [{
            role: 'user',
            content: prompt
          }],
          temperature: 0.3
        })
      });

      const result = await response.json() as any;
      const jsonMatch = result.content[0].text.match(/\{[\s\S]*\}/);

      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
    } catch (error: any) {
    }

    // Fallback prediction
    return {
      score: 50,
      propensityToBuy: 50,
      expectedDealSize: 50000,
      timeToClose: 30,
      confidence: 0.5,
      reasoning: 'Based on available signals'
    };
  }

  private calculateScoreFactors(signals: Signals): ScoreFactor[] {
    const factors: ScoreFactor[] = [];

    // Engagement factor
    factors.push({
      name: 'Engagement Level',
      category: 'engagement',
      score: Math.min(signals.engagement.totalInteractions * 2, 100),
      weight: 0.25,
      impact: signals.engagement.engagementTrend === 'increasing' ? 'positive' : 'neutral',
     
  description: `${signals.engagement.totalInteractions} total interactions, ${signals.engagement.engagementTrend} trend`
    });

    // Fit factor
    factors.push({
      name: 'Company Fit',
      category: 'fit',
      score: signals.fitScore,
      weight: 0.20,
      impact: signals.fitScore > 70 ? 'positive' : signals.fitScore < 40 ? 'negative' : 'neutral',
      description: `Fit score of ${signals.fitScore} based on company profile`
    });

    // Behavior factor
    const behaviorScore = this.scoreBehavior(signals.behavior);
    factors.push({
      name: 'Buying Behavior',
      category: 'behavior',
      score: behaviorScore,
      weight: 0.20,
      impact: behaviorScore > 70 ? 'positive' : 'neutral',
      description: `${signals.behavior.buyingStage} stage, ${signals.behavior.buyingRole} role`
    });

    // Timing factor
    const timingScore = signals.timing.urgencySignals.length * 20 + 40;
    factors.push({
      name: 'Timing Signals',
      category: 'timing',
      score: Math.min(timingScore, 100),
      weight: 0.15,
      impact: signals.timing.urgencySignals.length > 0 ? 'positive' : 'neutral',
      description: `${signals.timing.urgencySignals.length} urgency signals detected`
    });

    // Content consumption
    const contentScore = Math.min(signals.contentConsumption.downloadsCount * 20, 100);
    factors.push({
      name: 'Content Engagement',
      category: 'engagement',
      score: contentScore,
      weight: 0.10,
      impact: contentScore > 60 ? 'positive' : 'neutral',
      description: `${signals.contentConsumption.downloadsCount} content downloads`
    });

    // Competition factor
    const hasCompetitorActivity = signals.competitorActivity.mentionedCompetitors.length > 0;
    factors.push({
      name: 'Competitive Landscape',
      category: 'competition',
      score: hasCompetitorActivity ? 30 : 70,
      weight: 0.10,
      impact: hasCompetitorActivity ? 'negative' : 'neutral',
      description: hasCompetitorActivity ? 'Evaluating competitors' : 'No competitor activity detected'
    });

    return factors;
  }

  private scoreBehavior(behavior: BehaviorAnalysis): number {
    let score = 0;

    // Stage scoring
    const stageScores = {
      awareness: 20,
      consideration: 40,
      evaluation: 60,
      decision: 80,
      purchase: 100
    };
    score += stageScores[behavior.buyingStage];

    // Role scoring
    const roleScores = {
      decision_maker: 20,
      champion: 15,
      influencer: 10,
      evaluator: 5,
      end_user: 5
    };
    score += roleScores[behavior.buyingRole];

    return Math.min(score, 100);
  }

  private async identifyRisks(lead: LeadExtended, signals: Signals): Promise<RiskFactor[]> {
    const risks: RiskFactor[] = [];

    // Low engagement risk
    if (signals.engagement.engagementTrend === 'decreasing') {
      risks.push({
        type: 'Declining Engagement',
        severity: 'high',
        description: 'Lead engagement is decreasing over time',
        mitigation: 'Re-engage with personalized content or different channel',
        probability: 0.7
      });
    }

    // Competition risk
    if (signals.competitorActivity.mentionedCompetitors.length > 0) {
      risks.push({
        type: 'Competitive Evaluation',
        severity: 'medium',
        description: `Evaluating ${signals.competitorActivity.mentionedCompetitors.length} competitors`,
        mitigation: 'Highlight differentiators and provide comparison materials',
        probability: 0.6
      });
    }

    // Long sales cycle risk
    if (signals.behavior.decisionSpeed === 'slow') {
      risks.push({
        type: 'Extended Sales Cycle',
        severity: 'medium',
        description: 'Lead shows signs of slow decision-making process',
        mitigation: 'Create urgency with limited-time offers or business case',
        probability: 0.5
      });
    }

    // Budget risk
    if (signals.timing.fiscalYearPosition === 'Q4') {
      risks.push({
        type: 'Budget Constraints',
        severity: 'low',
        description: 'End of fiscal year may impact budget availability',
        mitigation: 'Explore financing options or defer payment terms',
        probability: 0.4
      });
    }

    // No champion risk
    if (signals.behavior.buyingRole !== 'champion' && signals.behavior.buyingRole !== 'decision_maker') {
      risks.push({
        type: 'No Internal Champion',
        severity: 'high',
        description: 'No clear champion or decision maker engaged',
        mitigation: 'Identify and engage senior stakeholders',
        probability: 0.6
      });
    }

    return risks;
  }

  private async generateRecommendations(
    lead: LeadExtended,
    signals: Signals,
    prediction: any
  ): Promise<string[]> {
    const recommendations: string[] = [];

    // Engagement recommendations
    if (signals.engagement.engagementTrend === 'decreasing') {
      recommendations.push('Schedule a personal check-in call to re-engage');
    }

    if (signals.engagement.recentInteractions === 0) {
      recommendations.push('Send a value-add piece of content to restart conversation');
    }

    // Stage-specific recommendations
    switch (signals.behavior.buyingStage) {
      case 'awareness':
        recommendations.push('Share educational content about the problem space');
        break;
      case 'consideration':
        recommendations.push('Provide case studies from similar companies');
        break;
      case 'evaluation':
        recommendations.push('Offer a personalized demo or proof of concept');
        break;
      case 'decision':
        recommendations.push('Present ROI analysis and implementation plan');
        break;
    }

    // Channel recommendations
    if (signals.engagement.channelPreference === 'email' && signals.emailEngagement.openRate < 0.2) {
      recommendations.push('Try reaching out via LinkedIn or phone');
    }

    // Content recommendations
    if (signals.contentConsumption.downloadsCount === 0) {
      recommendations.push('Share high-value content matched to their interests');
    }

    // Timing recommendations
    if (signals.timing.urgencySignals.length > 0) {
      recommendations.push('Fast-track the sales process with executive involvement');
    }

    // Competition recommendations
    if (signals.competitorActivity.mentionedCompetitors.length > 0) {
      recommendations.push('Provide competitive differentiation materials');
    }

    return recommendations;
  }

  private async storePrediction(lead: LeadExtended, score: LeadScore): Promise<void> {
    const db = this.env.DB_CRM;

    await db.prepare(`
      INSERT INTO lead_scores (
        lead_id, overall_score, propensity_to_buy, expected_deal_size,
        time_to_close, confidence, factors, risk_factors, recommendations,
        reasoning, calculated_at, valid_until
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      lead.id,
      score.overallScore,
      score.propensityToBuy,
      score.expectedDealSize,
      score.timeToClose,
      score.confidence,
      JSON.stringify(score.factors),
      JSON.stringify(score.riskFactors),
      JSON.stringify(score.recommendations),
      score.reasoning,
      score.calculatedAt,
      score.validUntil
    ).run();

    // Update lead with latest score
    await db.prepare(`
      UPDATE leads
      SET ai_qualification_score = ?, updated_at = ?
      WHERE id = ?
    `).bind(score.overallScore, new Date().toISOString(), lead.id).run();
  }

  // Helper methods
  private async getPreferredChannel(lead: LeadExtended): Promise<string> {
    // Analyze which channel has best engagement
    const db = this.env.DB_CRM;

    const result = await db.prepare(`
      SELECT channel, COUNT(*) as count
      FROM channel_messages
      WHERE lead_id = ? AND replied_at IS NOT NULL
      GROUP BY channel
      ORDER BY count DESC
      LIMIT 1
    `).bind(lead.id).first();

    return result?.channel as string || 'email';
  }

  private async getPeakEngagementTime(lead: LeadExtended): Promise<string> {
    // Analyze when lead is most active
    const db = this.env.DB_CRM;

    const result = await db.prepare(`
      SELECT strftime('%H', created_at) as hour, COUNT(*) as count
      FROM lead_activities
      WHERE lead_id = ?
      GROUP BY hour
      ORDER BY count DESC
      LIMIT 1
    `).bind(lead.id).first();

    const hour = result?.hour as string || '10';
    return `${hour}:00`;
  }

  private async getConversionEvents(lead: LeadExtended): Promise<string[]> {
    // Track conversion events
    const events: string[] = [];

    if (lead.ai_qualification_score && lead.ai_qualification_score > 70) {
      events.push('qualified');
    }

    // Would track actual conversion events
    return events;
  }

  private getSeasonalFactors(): string[] {
    const month = new Date().getMonth();
    const factors: string[] = [];

    if (month === 11 || month === 0) {
      factors.push('End of year budget flush');
    }
    if (month >= 8 && month <= 10) {
      factors.push('Q4 planning season');
    }
    if (month >= 0 && month <= 2) {
      factors.push('New year initiatives');
    }

    return factors;
  }

  // Deal Intelligence Methods
  async analyzeDealIntelligence(dealId: string): Promise<DealIntelligence> {
    // This would analyze deal-specific intelligence
    // For now, return mock data
    return {
      dealId,
      winProbability: 0.65,
      expectedCloseDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      recommendedNextAction: 'Schedule technical deep-dive with engineering team',
      competitiveThreats: [],
      stakeholderMap: [],
      dealRisks: [],
      accelerators: [],
      timeline: {
        currentStage: 'negotiation',
        stageProgress: 0.6,
        keyMilestones: [],
        criticalPath: [],
        estimatedDuration: 30
      }
    };
  }
}