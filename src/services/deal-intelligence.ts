import type { Lead, Company } from '../types/crm';
import type { Env } from '../types/env';
import { PredictiveScoring } from './predictive-scoring';

export interface Opportunity {
  id: string;
  name: string;
  leadId: string;
  companyId: string;
  value: number;
  stage: OpportunityStage;
  closeDate: string;
  probability: number;
  owner: string;
  createdAt: string;
  updatedAt: string;
  daysInStage: number;
  totalAge: number;
  lastActivity: string;
  nextStep?: string;
  stakeholderEngagement: StakeholderEngagement;
  knownCompetitors: string[];
  contractValue?: number;
  recurringRevenue?: number;
  dealType: 'new' | 'expansion' | 'renewal';
  source: string;
  champion?: string;
  decisionCriteria?: string[];
  painPoints?: string[];
  businessCase?: string;
  notes?: string;
}

export type OpportunityStage =
  | 'prospecting'
  | 'qualification'
  | 'needs_analysis'
  | 'value_proposition'
  | 'decision_maker_identification'
  | 'perception_analysis'
  | 'proposal'
  | 'negotiation'
  | 'closed_won'
  | 'closed_lost';

export interface StakeholderEngagement {
  totalStakeholders: number;
  engagedStakeholders: number;
  decisionMakersEngaged: number;
  lastEngagement: string;
  engagementLevel: 'low' | 'medium' | 'high';
}

export interface DealIntelligence {
  opportunity: Opportunity;
  scoring: DealScoring;
  insights: DealInsights;
  recommendations: DealRecommendation[];
  riskFactors: RiskFactor[];
  nextActions: NextAction[];
  competitiveAnalysis: CompetitiveAnalysis;
  timeline: DealTimeline;
  forecast: DealForecast;
}

export interface DealScoring {
  overall: number;
  breakdown: {
    engagement: number;
    momentum: number;
    fit: number;
    urgency: number;
    budget: number;
    authority: number;
    need: number;
  };
  trend: 'improving' | 'declining' | 'stable';
  confidence: number;
  lastUpdated: string;
}

export interface DealInsights {
  keyInsights: string[];
  strengths: string[];
  weaknesses: string[];
  opportunities: string[];
  threats: string[];
  criticalSuccessFactors: string[];
  dealDrivers: string[];
  potentialBlockers: string[];
}

export interface DealRecommendation {
  id: string;
  type: 'action' | 'strategy' | 'tactical' | 'relationship';
  priority: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  rationale: string;
  expectedImpact: string;
  effort: 'low' | 'medium' | 'high';
  timeline: string;
  owner?: string;
  status: 'pending' | 'in_progress' | 'completed' | 'cancelled';
}

export interface RiskFactor {
  id: string;
  type: 'competitive' | 'budget' | 'timeline' | 'stakeholder' | 'technical' | 'compliance';
  severity: 'low' | 'medium' | 'high' | 'critical';
  probability: number;
  impact: string;
  mitigation: string;
  owner?: string;
  status: 'identified' | 'monitoring' | 'mitigating' | 'resolved';
}

export interface NextAction {
  id: string;
  type: 'call' | 'email' | 'meeting' | 'demo' | 'proposal' | 'follow_up';
  title: string;
  description: string;
  dueDate: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  owner: string;
  status: 'pending' | 'in_progress' | 'completed' | 'cancelled';
  outcome?: string;
}

export interface CompetitiveAnalysis {
  competitors: CompetitorInfo[];
  ourPosition: CompetitivePosition;
  winRate: number;
  differentiators: string[];
  threats: string[];
  opportunities: string[];
}

export interface CompetitorInfo {
  name: string;
  strength: number;
  weakness: string[];
  pricing: 'higher' | 'similar' | 'lower';
  lastEncountered: string;
  winRate: number;
}

export interface CompetitivePosition {
  overall: 'leading' | 'competitive' | 'behind' | 'unknown';
  pricing: 'premium' | 'competitive' | 'discount';
  features: 'superior' | 'comparable' | 'inferior';
  relationship: 'strong' | 'moderate' | 'weak' | 'none';
}

export interface DealTimeline {
  stages: TimelineStage[];
  currentStage: string;
  estimatedClose: string;
  confidence: number;
  milestones: Milestone[];
}

export interface TimelineStage {
  name: string;
  startDate: string;
  endDate: string;
  duration: number;
  status: 'completed' | 'current' | 'upcoming';
  probability: number;
}

export interface Milestone {
  name: string;
  date: string;
  status: 'completed' | 'pending' | 'overdue';
  critical: boolean;
}

export interface DealForecast {
  probability: number;
  expectedValue: number;
  bestCase: number;
  worstCase: number;
  confidence: number;
  factors: ForecastFactor[];
  scenarios: ForecastScenario[];
}

export interface ForecastFactor {
  name: string;
  impact: number;
  probability: number;
  description: string;
}

export interface ForecastScenario {
  name: string;
  probability: number;
  value: number;
  description: string;
}

export class DealIntelligenceService {
  private env: Env;
  private predictiveScoring: PredictiveScoring;

  constructor(env: Env) {
    this.env = env;
    this.predictiveScoring = new PredictiveScoring(env);
  }

  async analyzeDeal(opportunity: Opportunity): Promise<DealIntelligence> {
    const startTime = Date.now();

    // Perform comprehensive deal analysis
    const [
      scoring,
      insights,
      recommendations,
      riskFactors,
      nextActions,
      competitiveAnalysis,
      timeline,
      forecast
    ] = await Promise.all([
      this.calculateDealScoring(opportunity),
      this.generateDealInsights(opportunity),
      this.generateRecommendations(opportunity),
      this.identifyRiskFactors(opportunity),
      this.generateNextActions(opportunity),
      this.analyzeCompetition(opportunity),
      this.buildDealTimeline(opportunity),
      this.generateForecast(opportunity)
    ]);

    return {
      opportunity,
      scoring,
      insights,
      recommendations,
      riskFactors,
      nextActions,
      competitiveAnalysis,
      timeline,
      forecast
    };
  }

  private async calculateDealScoring(opportunity: Opportunity): Promise<DealScoring> {
    const breakdown = {
      engagement: this.calculateEngagementScore(opportunity),
      momentum: this.calculateMomentumScore(opportunity),
      fit: this.calculateFitScore(opportunity),
      urgency: this.calculateUrgencyScore(opportunity),
      budget: this.calculateBudgetScore(opportunity),
      authority: this.calculateAuthorityScore(opportunity),
      need: this.calculateNeedScore(opportunity)
    };

    const overall = Object.values(breakdown).reduce((sum, score) => sum + score, 0) / Object.keys(breakdown).length;
    const trend = this.calculateScoreTrend(opportunity);
    const confidence = this.calculateScoreConfidence(opportunity);

    return {
      overall: Math.round(overall),
      breakdown,
      trend,
      confidence,
      lastUpdated: new Date().toISOString()
    };
  }

  private calculateEngagementScore(opportunity: Opportunity): number {
    const engagement = opportunity.stakeholderEngagement;
    const engagementRatio = engagement.totalStakeholders > 0 
      ? engagement.engagedStakeholders / engagement.totalStakeholders 
      : 0;

    let score = engagementRatio * 50; // Base score from engagement ratio

    // Bonus for decision maker engagement
    if (engagement.decisionMakersEngaged > 0) {
      score += 20;
    }

    // Bonus for high engagement level
    if (engagement.engagementLevel === 'high') {
      score += 20;
    } else if (engagement.engagementLevel === 'medium') {
      score += 10;
    }

    // Penalty for stale engagement
    const daysSinceLastEngagement = this.calculateDaysSince(engagement.lastEngagement);
    if (daysSinceLastEngagement > 30) {
      score -= 20;
    } else if (daysSinceLastEngagement > 14) {
      score -= 10;
    }

    return Math.max(0, Math.min(100, score));
  }

  private calculateMomentumScore(opportunity: Opportunity): number {
    let score = 50; // Base score

    // Days in current stage
    if (opportunity.daysInStage < 7) {
      score += 20; // Fresh momentum
    } else if (opportunity.daysInStage > 30) {
      score -= 30; // Stale
    }

    // Recent activity
    const daysSinceActivity = this.calculateDaysSince(opportunity.lastActivity);
    if (daysSinceActivity < 3) {
      score += 20;
    } else if (daysSinceActivity > 14) {
      score -= 20;
    }

    // Stage progression
    const stageScore = this.getStageScore(opportunity.stage);
    score += stageScore;

    return Math.max(0, Math.min(100, score));
  }

  private calculateFitScore(opportunity: Opportunity): number {
    let score = 50; // Base score

    // Deal type
    if (opportunity.dealType === 'expansion') {
      score += 20; // Existing customer
    } else if (opportunity.dealType === 'renewal') {
      score += 30; // High fit for renewals
    }

    // Value alignment
    if (opportunity.value > 100000) {
      score += 15; // Large deal
    } else if (opportunity.value < 10000) {
      score -= 10; // Small deal
    }

    // Source quality
    if (opportunity.source === 'referral') {
      score += 20;
    } else if (opportunity.source === 'inbound') {
      score += 10;
    }

    return Math.max(0, Math.min(100, score));
  }

  private calculateUrgencyScore(opportunity: Opportunity): number {
    let score = 50; // Base score

    // Close date proximity
    const daysToClose = this.calculateDaysUntil(opportunity.closeDate);
    if (daysToClose < 30) {
      score += 30; // High urgency
    } else if (daysToClose < 90) {
      score += 15; // Medium urgency
    } else if (daysToClose > 180) {
      score -= 20; // Low urgency
    }

    // Stage urgency
    const urgentStages = ['proposal', 'negotiation'];
    if (urgentStages.includes(opportunity.stage)) {
      score += 20;
    }

    return Math.max(0, Math.min(100, score));
  }

  private calculateBudgetScore(opportunity: Opportunity): number {
    let score = 50; // Base score

    // Contract value
    if (opportunity.contractValue) {
      if (opportunity.contractValue > opportunity.value) {
        score += 20; // Budget confirmed
      } else if (opportunity.contractValue < opportunity.value * 0.8) {
        score -= 20; // Budget concerns
      }
    }

    // Deal size
    if (opportunity.value > 50000) {
      score += 15; // Substantial budget
    }

    return Math.max(0, Math.min(100, score));
  }

  private calculateAuthorityScore(opportunity: Opportunity): number {
    let score = 50; // Base score

    // Champion presence
    if (opportunity.champion) {
      score += 25;
    }

    // Decision maker engagement
    const decisionMakers = opportunity.stakeholderEngagement.decisionMakersEngaged;
    if (decisionMakers > 0) {
      score += decisionMakers * 10;
    }

    // Decision criteria
    if (opportunity.decisionCriteria && opportunity.decisionCriteria.length > 0) {
      score += 15;
    }

    return Math.max(0, Math.min(100, score));
  }

  private calculateNeedScore(opportunity: Opportunity): number {
    let score = 50; // Base score

    // Pain points identified
    if (opportunity.painPoints && opportunity.painPoints.length > 0) {
      score += opportunity.painPoints.length * 10;
    }

    // Business case
    if (opportunity.businessCase) {
      score += 20;
    }

    // Stage indicates need validation
    const needStages = ['needs_analysis', 'value_proposition'];
    if (needStages.includes(opportunity.stage)) {
      score += 15;
    }

    return Math.max(0, Math.min(100, score));
  }

  private getStageScore(stage: OpportunityStage): number {
    const stageScores: Record<OpportunityStage, number> = {
      'prospecting': 10,
      'qualification': 20,
      'needs_analysis': 30,
      'value_proposition': 40,
      'decision_maker_identification': 50,
      'perception_analysis': 60,
      'proposal': 70,
      'negotiation': 80,
      'closed_won': 100,
      'closed_lost': 0
    };

    return stageScores[stage] || 0;
  }

  private calculateScoreTrend(opportunity: Opportunity): 'improving' | 'declining' | 'stable' {
    // This would typically compare with historical data
    // For now, return based on recent activity
    const daysSinceActivity = this.calculateDaysSince(opportunity.lastActivity);
    
    if (daysSinceActivity < 7) {
      return 'improving';
    } else if (daysSinceActivity > 21) {
      return 'declining';
    }
    
    return 'stable';
  }

  private calculateScoreConfidence(opportunity: Opportunity): number {
    let confidence = 0.5; // Base confidence

    // More data points increase confidence
    if (opportunity.stakeholderEngagement.totalStakeholders > 3) {
      confidence += 0.2;
    }

    if (opportunity.decisionCriteria && opportunity.decisionCriteria.length > 2) {
      confidence += 0.1;
    }

    if (opportunity.painPoints && opportunity.painPoints.length > 1) {
      confidence += 0.1;
    }

    if (opportunity.businessCase) {
      confidence += 0.1;
    }

    return Math.min(1.0, confidence);
  }

  private async generateDealInsights(opportunity: Opportunity): Promise<DealInsights> {
    const keyInsights: string[] = [];
    const strengths: string[] = [];
    const weaknesses: string[] = [];
    const opportunities: string[] = [];
    const threats: string[] = [];
    const criticalSuccessFactors: string[] = [];
    const dealDrivers: string[] = [];
    const potentialBlockers: string[] = [];

    // Analyze engagement
    const engagement = opportunity.stakeholderEngagement;
    if (engagement.engagementLevel === 'high') {
      strengths.push('High stakeholder engagement');
      dealDrivers.push('Strong relationship building');
    } else if (engagement.engagementLevel === 'low') {
      weaknesses.push('Low stakeholder engagement');
      potentialBlockers.push('Limited stakeholder buy-in');
    }

    // Analyze stage progression
    if (opportunity.daysInStage > 30) {
      weaknesses.push('Deal stalled in current stage');
      potentialBlockers.push('Stage progression delay');
    } else if (opportunity.daysInStage < 7) {
      strengths.push('Recent stage progression');
    }

    // Analyze budget
    if (opportunity.contractValue && opportunity.contractValue >= opportunity.value) {
      strengths.push('Budget confirmed');
      criticalSuccessFactors.push('Budget alignment');
    } else if (opportunity.contractValue && opportunity.contractValue < opportunity.value * 0.8) {
      weaknesses.push('Budget gap identified');
      potentialBlockers.push('Budget constraints');
    }

    // Analyze competition
    if (opportunity.knownCompetitors.length > 0) {
      threats.push('Competitive pressure');
      opportunities.push('Differentiation opportunity');
    }

    // Analyze timeline
    const daysToClose = this.calculateDaysUntil(opportunity.closeDate);
    if (daysToClose < 30) {
      opportunities.push('Imminent close opportunity');
      criticalSuccessFactors.push('Timeline management');
    } else if (daysToClose > 180) {
      potentialBlockers.push('Extended sales cycle');
    }

    // Analyze deal type
    if (opportunity.dealType === 'expansion') {
      strengths.push('Existing customer relationship');
      dealDrivers.push('Customer expansion');
    } else if (opportunity.dealType === 'renewal') {
      strengths.push('Renewal opportunity');
      criticalSuccessFactors.push('Customer satisfaction');
    }

    return {
      keyInsights,
      strengths,
      weaknesses,
      opportunities,
      threats,
      criticalSuccessFactors,
      dealDrivers,
      potentialBlockers
    };
  }

  private async generateRecommendations(opportunity: Opportunity): Promise<DealRecommendation[]> {
    const recommendations: DealRecommendation[] = [];

    // Engagement recommendations
    if (opportunity.stakeholderEngagement.engagementLevel === 'low') {
      recommendations.push({
        id: `rec_${Date.now()}_1`,
        type: 'relationship',
        priority: 'high',
        title: 'Increase stakeholder engagement',
        description: 'Schedule meetings with key stakeholders to build relationships',
        rationale: 'Low engagement level indicates relationship building needed',
        expectedImpact: 'Improved deal momentum and stakeholder buy-in',
        effort: 'medium',
        timeline: '1-2 weeks',
        status: 'pending'
      });
    }

    // Stage progression recommendations
    if (opportunity.daysInStage > 30) {
      recommendations.push({
        id: `rec_${Date.now()}_2`,
        type: 'action',
        priority: 'high',
        title: 'Advance deal stage',
        description: 'Take specific actions to move deal to next stage',
        rationale: 'Deal has been in current stage too long',
        expectedImpact: 'Improved deal velocity',
        effort: 'high',
        timeline: '1 week',
        status: 'pending'
      });
    }

    // Budget recommendations
    if (!opportunity.contractValue || opportunity.contractValue < opportunity.value) {
      recommendations.push({
        id: `rec_${Date.now()}_3`,
        type: 'strategy',
        priority: 'medium',
        title: 'Validate budget and value',
        description: 'Work with stakeholders to align budget with deal value',
        rationale: 'Budget gap may prevent deal closure',
        expectedImpact: 'Budget alignment and deal closure',
        effort: 'medium',
        timeline: '2-3 weeks',
        status: 'pending'
      });
    }

    // Competition recommendations
    if (opportunity.knownCompetitors.length > 0) {
      recommendations.push({
        id: `rec_${Date.now()}_4`,
        type: 'tactical',
        priority: 'medium',
        title: 'Address competitive threats',
        description: 'Develop competitive differentiation strategy',
        rationale: 'Competitive pressure identified',
        expectedImpact: 'Improved competitive positioning',
        effort: 'high',
        timeline: '2-4 weeks',
        status: 'pending'
      });
    }

    return recommendations;
  }

  private async identifyRiskFactors(opportunity: Opportunity): Promise<RiskFactor[]> {
    const risks: RiskFactor[] = [];

    // Timeline risks
    const daysToClose = this.calculateDaysUntil(opportunity.closeDate);
    if (daysToClose < 30 && opportunity.stage !== 'closed_won') {
      risks.push({
        id: `risk_${Date.now()}_1`,
        type: 'timeline',
        severity: 'high',
        probability: 0.7,
        impact: 'Deal may not close on time',
        mitigation: 'Accelerate decision-making process',
        status: 'identified'
      });
    }

    // Engagement risks
    if (opportunity.stakeholderEngagement.engagementLevel === 'low') {
      risks.push({
        id: `risk_${Date.now()}_2`,
        type: 'stakeholder',
        severity: 'medium',
        probability: 0.6,
        impact: 'Low stakeholder buy-in may prevent closure',
        mitigation: 'Increase stakeholder engagement activities',
        status: 'identified'
      });
    }

    // Budget risks
    if (opportunity.contractValue && opportunity.contractValue < opportunity.value * 0.8) {
      risks.push({
        id: `risk_${Date.now()}_3`,
        type: 'budget',
        severity: 'high',
        probability: 0.8,
        impact: 'Budget gap may prevent deal closure',
        mitigation: 'Work with stakeholders to increase budget or reduce scope',
        status: 'identified'
      });
    }

    // Competition risks
    if (opportunity.knownCompetitors.length > 0) {
      risks.push({
        id: `risk_${Date.now()}_4`,
        type: 'competitive',
        severity: 'medium',
        probability: 0.5,
        impact: 'Competitive pressure may result in deal loss',
        mitigation: 'Strengthen competitive differentiation',
        status: 'identified'
      });
    }

    return risks;
  }

  private async generateNextActions(opportunity: Opportunity): Promise<NextAction[]> {
    const actions: NextAction[] = [];

    // Follow-up actions based on stage
    const daysSinceActivity = this.calculateDaysSince(opportunity.lastActivity);
    if (daysSinceActivity > 7) {
      actions.push({
        id: `action_${Date.now()}_1`,
        type: 'follow_up',
        title: 'Follow up on recent activity',
        description: 'Check in with stakeholders on recent progress',
        dueDate: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString(),
        priority: 'high',
        owner: opportunity.owner,
        status: 'pending'
      });
    }

    // Stage-specific actions
    if (opportunity.stage === 'needs_analysis') {
      actions.push({
        id: `action_${Date.now()}_2`,
        type: 'meeting',
        title: 'Conduct needs analysis meeting',
        description: 'Deep dive into customer requirements and pain points',
        dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        priority: 'high',
        owner: opportunity.owner,
        status: 'pending'
      });
    } else if (opportunity.stage === 'proposal') {
      actions.push({
        id: `action_${Date.now()}_3`,
        type: 'proposal',
        title: 'Prepare and deliver proposal',
        description: 'Create comprehensive proposal addressing customer needs',
        dueDate: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(),
        priority: 'critical',
        owner: opportunity.owner,
        status: 'pending'
      });
    }

    // Engagement actions
    if (opportunity.stakeholderEngagement.engagementLevel === 'low') {
      actions.push({
        id: `action_${Date.now()}_4`,
        type: 'meeting',
        title: 'Schedule stakeholder meetings',
        description: 'Meet with key stakeholders to build relationships',
        dueDate: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString(),
        priority: 'medium',
        owner: opportunity.owner,
        status: 'pending'
      });
    }

    return actions;
  }

  private async analyzeCompetition(opportunity: Opportunity): Promise<CompetitiveAnalysis> {
    const competitors: CompetitorInfo[] = [];
    
    // Analyze known competitors
    for (const competitorName of opportunity.knownCompetitors) {
      competitors.push({
        name: competitorName,
        strength: this.calculateCompetitorStrength(competitorName),
        weakness: this.identifyCompetitorWeaknesses(competitorName),
        pricing: this.assessCompetitorPricing(competitorName),
        lastEncountered: new Date().toISOString(),
        winRate: this.calculateWinRateAgainst(competitorName)
      });
    }

    const ourPosition = this.assessOurPosition(competitors);
    const winRate = this.calculateOverallWinRate(competitors);
    const differentiators = this.identifyDifferentiators();
    const threats = this.identifyCompetitiveThreats(competitors);
    const opportunities = this.identifyCompetitiveOpportunities(competitors);

    return {
      competitors,
      ourPosition,
      winRate,
      differentiators,
      threats,
      opportunities
    };
  }

  private calculateCompetitorStrength(competitorName: string): number {
    // Mock competitor strength calculation
    const strengths: Record<string, number> = {
      'salesforce': 85,
      'hubspot': 80,
      'pipedrive': 75,
      'zoho': 70,
      'monday.com': 75
    };

    return strengths[competitorName.toLowerCase()] || 60;
  }

  private identifyCompetitorWeaknesses(competitorName: string): string[] {
    // Mock competitor weakness identification
    const weaknesses: Record<string, string[]> = {
      'salesforce': ['Complex setup', 'High cost', 'Steep learning curve'],
      'hubspot': ['Limited customization', 'Pricing complexity'],
      'pipedrive': ['Limited features', 'Basic reporting'],
      'zoho': ['Integration issues', 'Support quality'],
      'monday.com': ['Limited CRM features', 'Pricing tiers']
    };

    return weaknesses[competitorName.toLowerCase()] || ['Unknown weaknesses'];
  }

  private assessCompetitorPricing(competitorName: string): 'higher' | 'similar' | 'lower' {
    // Mock pricing assessment
    const pricing: Record<string, 'higher' | 'similar' | 'lower'> = {
      'salesforce': 'higher',
      'hubspot': 'similar',
      'pipedrive': 'lower',
      'zoho': 'lower',
      'monday.com': 'similar'
    };

    return pricing[competitorName.toLowerCase()] || 'similar';
  }

  private calculateWinRateAgainst(competitorName: string): number {
    // Mock win rate calculation
    const winRates: Record<string, number> = {
      'salesforce': 0.6,
      'hubspot': 0.7,
      'pipedrive': 0.8,
      'zoho': 0.75,
      'monday.com': 0.65
    };

    return winRates[competitorName.toLowerCase()] || 0.5;
  }

  private assessOurPosition(competitors: CompetitorInfo[]): CompetitivePosition {
    if (competitors.length === 0) {
      return {
        overall: 'unknown',
        pricing: 'competitive',
        features: 'comparable',
        relationship: 'moderate'
      };
    }

    const avgStrength = competitors.reduce((sum, comp) => sum + comp.strength, 0) / competitors.length;
    const avgWinRate = competitors.reduce((sum, comp) => sum + comp.winRate, 0) / competitors.length;

    let overall: 'leading' | 'competitive' | 'behind' | 'unknown';
    if (avgWinRate > 0.7) {
      overall = 'leading';
    } else if (avgWinRate > 0.5) {
      overall = 'competitive';
    } else {
      overall = 'behind';
    }

    return {
      overall,
      pricing: 'competitive',
      features: avgStrength > 75 ? 'superior' : 'comparable',
      relationship: 'moderate'
    };
  }

  private calculateOverallWinRate(competitors: CompetitorInfo[]): number {
    if (competitors.length === 0) return 0.5;
    
    return competitors.reduce((sum, comp) => sum + comp.winRate, 0) / competitors.length;
  }

  private identifyDifferentiators(): string[] {
    return [
      'Advanced AI capabilities',
      'Seamless integration',
      'Superior customer support',
      'Flexible pricing',
      'Easy implementation'
    ];
  }

  private identifyCompetitiveThreats(competitors: CompetitorInfo[]): string[] {
    const threats: string[] = [];

    for (const competitor of competitors) {
      if (competitor.strength > 80) {
        threats.push(`Strong competitor: ${competitor.name}`);
      }
      if (competitor.pricing === 'lower') {
        threats.push(`Price pressure from ${competitor.name}`);
      }
    }

    return threats;
  }

  private identifyCompetitiveOpportunities(competitors: CompetitorInfo[]): string[] {
    const opportunities: string[] = [];

    for (const competitor of competitors) {
      if (competitor.strength < 70) {
        opportunities.push(`Weak competitor: ${competitor.name}`);
      }
      if (competitor.pricing === 'higher') {
        opportunities.push(`Price advantage over ${competitor.name}`);
      }
    }

    return opportunities;
  }

  private async buildDealTimeline(opportunity: Opportunity): Promise<DealTimeline> {
    const stages = this.getStageProgression(opportunity.stage);
    const currentStage = opportunity.stage;
    const estimatedClose = opportunity.closeDate;
    const confidence = this.calculateTimelineConfidence(opportunity);
    const milestones = this.identifyMilestones(opportunity);

    return {
      stages,
      currentStage,
      estimatedClose,
      confidence,
      milestones
    };
  }

  private getStageProgression(currentStage: OpportunityStage): TimelineStage[] {
    const allStages: OpportunityStage[] = [
      'prospecting',
      'qualification',
      'needs_analysis',
      'value_proposition',
      'decision_maker_identification',
      'perception_analysis',
      'proposal',
      'negotiation',
      'closed_won'
    ];

    const currentIndex = allStages.indexOf(currentStage);
    const stages: TimelineStage[] = [];

    for (let i = 0; i < allStages.length; i++) {
      const stage = allStages[i];
      const isCompleted = i < currentIndex;
      const isCurrent = i === currentIndex;
      const isUpcoming = i > currentIndex;

      stages.push({
        name: stage,
        startDate: new Date(Date.now() - (currentIndex - i) * 7 * 24 * 60 * 60 * 1000).toISOString(),
        endDate: new Date(Date.now() + (i - currentIndex) * 7 * 24 * 60 * 60 * 1000).toISOString(),
        duration: 7,
        status: isCompleted ? 'completed' : isCurrent ? 'current' : 'upcoming',
        probability: this.calculateStageProbability(stage, i, currentIndex)
      });
    }

    return stages;
  }

  private calculateStageProbability(stage: OpportunityStage, stageIndex: number, currentIndex: number): number {
    if (stageIndex < currentIndex) return 1.0;
    if (stageIndex === currentIndex) return 0.8;
    
    // Decreasing probability for future stages
    const stagesAhead = stageIndex - currentIndex;
    return Math.max(0.1, 0.8 - (stagesAhead * 0.1));
  }

  private calculateTimelineConfidence(opportunity: Opportunity): number {
    let confidence = 0.5;

    // More data points increase confidence
    if (opportunity.stakeholderEngagement.totalStakeholders > 3) {
      confidence += 0.2;
    }

    if (opportunity.decisionCriteria && opportunity.decisionCriteria.length > 2) {
      confidence += 0.1;
    }

    if (opportunity.businessCase) {
      confidence += 0.1;
    }

    // Recent activity increases confidence
    const daysSinceActivity = this.calculateDaysSince(opportunity.lastActivity);
    if (daysSinceActivity < 7) {
      confidence += 0.1;
    }

    return Math.min(1.0, confidence);
  }

  private identifyMilestones(opportunity: Opportunity): Milestone[] {
    const milestones: Milestone[] = [];

    // Add key milestones based on stage
    if (opportunity.stage === 'proposal' || opportunity.stage === 'negotiation') {
      milestones.push({
        name: 'Proposal delivered',
        date: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(),
        status: 'pending',
        critical: true
      });
    }

    if (opportunity.stage === 'negotiation') {
      milestones.push({
        name: 'Contract signed',
        date: opportunity.closeDate,
        status: 'pending',
        critical: true
      });
    }

    // Add follow-up milestones
    milestones.push({
      name: 'Next stakeholder meeting',
      date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      status: 'pending',
      critical: false
    });

    return milestones;
  }

  private async generateForecast(opportunity: Opportunity): Promise<DealForecast> {
    const probability = opportunity.probability / 100;
    const expectedValue = opportunity.value * probability;
    const bestCase = opportunity.value * 1.2;
    const worstCase = opportunity.value * 0.3;
    const confidence = this.calculateForecastConfidence(opportunity);
    const factors = this.identifyForecastFactors(opportunity);
    const scenarios = this.generateForecastScenarios(opportunity);

    return {
      probability,
      expectedValue,
      bestCase,
      worstCase,
      confidence,
      factors,
      scenarios
    };
  }

  private calculateForecastConfidence(opportunity: Opportunity): number {
    let confidence = 0.5;

    // More data points increase confidence
    if (opportunity.stakeholderEngagement.totalStakeholders > 3) {
      confidence += 0.2;
    }

    if (opportunity.decisionCriteria && opportunity.decisionCriteria.length > 2) {
      confidence += 0.1;
    }

    if (opportunity.businessCase) {
      confidence += 0.1;
    }

    if (opportunity.contractValue) {
      confidence += 0.1;
    }

    return Math.min(1.0, confidence);
  }

  private identifyForecastFactors(opportunity: Opportunity): ForecastFactor[] {
    const factors: ForecastFactor[] = [];

    // Engagement factor
    factors.push({
      name: 'Stakeholder engagement',
      impact: opportunity.stakeholderEngagement.engagementLevel === 'high' ? 0.2 : -0.1,
      probability: 0.8,
      description: 'Level of stakeholder engagement affects deal closure'
    });

    // Timeline factor
    const daysToClose = this.calculateDaysUntil(opportunity.closeDate);
    factors.push({
      name: 'Timeline pressure',
      impact: daysToClose < 30 ? 0.1 : -0.05,
      probability: 0.7,
      description: 'Time pressure affects decision making'
    });

    // Competition factor
    if (opportunity.knownCompetitors.length > 0) {
      factors.push({
        name: 'Competitive pressure',
        impact: -0.15,
        probability: 0.6,
        description: 'Competitive alternatives may impact closure'
      });
    }

    return factors;
  }

  private generateForecastScenarios(opportunity: Opportunity): ForecastScenario[] {
    const scenarios: ForecastScenario[] = [];

    // Best case scenario
    scenarios.push({
      name: 'Best case',
      probability: 0.2,
      value: opportunity.value * 1.2,
      description: 'All factors align positively'
    });

    // Most likely scenario
    scenarios.push({
      name: 'Most likely',
      probability: 0.6,
      value: opportunity.value * (opportunity.probability / 100),
      description: 'Current trajectory continues'
    });

    // Worst case scenario
    scenarios.push({
      name: 'Worst case',
      probability: 0.2,
      value: opportunity.value * 0.3,
      description: 'Deal stalls or reduces in value'
    });

    return scenarios;
  }

  // Utility methods
  private calculateDaysSince(dateString: string): number {
    const date = new Date(dateString);
    const now = new Date();
    return Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));
  }

  private calculateDaysUntil(dateString: string): number {
    const date = new Date(dateString);
    const now = new Date();
    return Math.floor((date.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
  }

  // Public methods for real-time updates
  async updateDealIntelligence(opportunity: Opportunity): Promise<DealIntelligence> {
    return this.analyzeDeal(opportunity);
  }

  async getDealInsights(opportunityId: string): Promise<DealIntelligence | null> {
    // This would typically fetch from cache or database
    return null;
  }

  async trackDealProgress(opportunityId: string, updates: Partial<Opportunity>): Promise<void> {
    // This would typically update the deal in the database
    console.log(`Tracking deal progress for ${opportunityId}:`, updates);
  }
}

