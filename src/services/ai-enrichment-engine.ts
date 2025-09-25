import type { Env } from '../types/env';
import type {
  Lead,
  Contact,
  Company,
  CompanyEnrichment,
  ContactEnrichment,
  NewsEnrichment,
  SocialEnrichment,
  AIInsights,
  BudgetIndicator,
  AuthorityIndicator,
  NeedIndicator,
  TimelineIndicator,
  ApproachRecommendation,
  NextBestAction,
  PersonalizedMessage,
  RiskFactor
} from '../types/enrichment';

export interface EnrichmentData {
  lead: Lead;
  company?: CompanyEnrichment;
  contact?: ContactEnrichment;
  news?: NewsEnrichment;
  social?: SocialEnrichment;
}

export class AIEnrichmentEngine {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async analyzeEnrichmentData(data: EnrichmentData): Promise<AIInsights> {
    try {
      const [
        leadScoring,
        qualificationInsights,
        personalizationInsights,
        competitiveInsights,
        recommendations,
        riskAnalysis
      ] = await Promise.all([
        this.performLeadScoring(data),
        this.analyzeQualification(data),
        this.generatePersonalizationInsights(data),
        this.analyzeCompetitiveLandscape(data),
        this.generateRecommendations(data),
        this.analyzeRisks(data)
      ]);

      return {
        // Lead scoring
        icp_fit_score: leadScoring.icp_fit_score,
        buying_intent_score: leadScoring.buying_intent_score,
        engagement_propensity: leadScoring.engagement_propensity,
        conversion_probability: leadScoring.conversion_probability,

        // Qualification
        budget_indicators: qualificationInsights.budget_indicators,
        authority_indicators: qualificationInsights.authority_indicators,
        need_indicators: qualificationInsights.need_indicators,
        timeline_indicators: qualificationInsights.timeline_indicators,

        // Personalization
        pain_points: personalizationInsights.pain_points,
        value_propositions: personalizationInsights.value_propositions,
        communication_preferences: personalizationInsights.communication_preferences,
        meeting_best_times: personalizationInsights.meeting_best_times,

        // Competitive
        current_solutions: competitiveInsights.current_solutions,
        competitor_relationships: competitiveInsights.competitor_relationships,
        switching_probability: competitiveInsights.switching_probability,

        // Recommendations
        recommended_approach: recommendations.recommended_approach,
        next_best_actions: recommendations.next_best_actions,
        personalized_messaging: recommendations.personalized_messaging,

        // Risk factors
        risk_factors: riskAnalysis.risk_factors,
        churn_indicators: riskAnalysis.churn_indicators,

        // Opportunities (basic implementation)
        upsell_opportunities: [],
        cross_sell_opportunities: [],
        expansion_potential: {
          additional_seats: 0,
          new_departments: [],
          geographic_expansion: [],
          total_revenue_potential: 0,
          timeline: '6-12 months'
        }
      };
    } catch (error) {
      return this.getDefaultInsights();
    }
  }

  private async performLeadScoring(data: EnrichmentData): Promise<{
    icp_fit_score: number;
    buying_intent_score: number;
    engagement_propensity: number;
    conversion_probability: number;
  }> {
    const prompt = `
Analyze this lead data and provide scoring (0-100 for scores, 0-1 for probability):

LEAD DATA:
Company: ${data.company?.legal_name || 'Unknown'}
Industry: ${data.company?.industry || 'Unknown'}
Employee Count: ${data.company?.employee_count || 'Unknown'}
Revenue: ${data.company?.annual_revenue || 'Unknown'}
Founded: ${data.company?.founded_year || 'Unknown'}

Contact: ${data.contact?.full_name || 'Unknown'}
Title: ${data.contact?.title || 'Unknown'}
Seniority: ${data.contact?.seniority_level || 'Unknown'}
Department: ${data.contact?.department || 'Unknown'}

Recent News: ${data.news?.recent_news?.slice(0, 3).map(n => n.title).join('; ') || 'None'}
Tech Stack: ${data.company?.tech_stack?.tools?.slice(0, 5).join(', ') || 'Unknown'}

Based on this data, provide scores for:
1. ICP Fit Score (how well they match ideal customer profile)
2. Buying Intent Score (signals of purchase readiness)
3. Engagement Propensity (likelihood to respond)
4. Conversion Probability (likelihood to convert)

Consider factors like company size, industry fit, decision maker access, budget indicators, timing signals.
Respond with just the four numbers.
`;

    try {
      const response = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,
        max_tokens: 100,
        temperature: 0.1
      });

      const scores = this.parseScores(response.response);

      return {
        icp_fit_score: scores[0] || 50,
        buying_intent_score: scores[1] || 30,
        engagement_propensity: scores[2] || 60,
        conversion_probability: (scores[3] || 25) / 100
      };
    } catch (error) {
      return {
        icp_fit_score: 50,
        buying_intent_score: 30,
        engagement_propensity: 60,
        conversion_probability: 0.25
      };
    }
  }

  private async analyzeQualification(data: EnrichmentData): Promise<{
    budget_indicators: BudgetIndicator[];
    authority_indicators: AuthorityIndicator[];
    need_indicators: NeedIndicator[];
    timeline_indicators: TimelineIndicator[];
  }> {
    const prompt = `
Analyze this lead for BANT qualification signals:

Company: ${data.company?.legal_name || 'Unknown'}
Revenue: ${data.company?.annual_revenue || 'Unknown'}
Employee Count: ${data.company?.employee_count || 'Unknown'}
Funding: ${data.company?.funding_total || 'Unknown'}

Contact: ${data.contact?.full_name || 'Unknown'}
Title: ${data.contact?.title || 'Unknown'}
Seniority: ${data.contact?.seniority_level || 'Unknown'}

Recent News: ${data.news?.recent_news?.map(n => n.title).join('; ') || 'None'}
Job Openings: ${data.company?.job_openings?.map(j => j.title).join(', ') || 'None'}

Identify:
1. Budget indicators (funding, revenue, growth signals)
2. Authority indicators (title, seniority, decision making power)
3. Need indicators (pain points, problems, growth challenges)
4. Timeline indicators (urgency signals, project timelines)

Be specific about evidence found in the data.
`;

    try {
      const response = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,
        max_tokens: 512,
        temperature: 0.3
      });

      return this.parseQualificationInsights(response.response, data);
    } catch (error) {
      return this.getDefaultQualificationInsights(data);
    }
  }

  private async generatePersonalizationInsights(data: EnrichmentData): Promise<{
    pain_points: string[];
    value_propositions: string[];
    communication_preferences: any[];
    meeting_best_times: any[];
  }> {
    const prompt = `
Generate personalization insights for this lead:

Company: ${data.company?.legal_name || 'Unknown'}
Industry: ${data.company?.industry || 'Unknown'}
Size: ${data.company?.employee_count || 'Unknown'} employees

Contact: ${data.contact?.full_name || 'Unknown'}
Title: ${data.contact?.title || 'Unknown'}
Location: ${data.contact?.location?.city || 'Unknown'}, ${data.contact?.location?.country || 'Unknown'}

Recent News: ${data.news?.recent_news?.slice(0, 2).map(n => n.title).join('; ') || 'None'}
Technologies: ${data.company?.tech_stack?.tools?.slice(0, 5).join(', ') || 'Unknown'}

Based on their industry, role, and company situation:
1. What are their likely pain points and challenges?
2. What value propositions would resonate most?
3. What communication style would work best?
4. What time zones and schedules to consider?

Provide specific, actionable insights.
`;

    try {
      const response = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,
        max_tokens: 400,
        temperature: 0.4
      });

      return this.parsePersonalizationInsights(response.response, data);
    } catch (error) {
      return this.getDefaultPersonalizationInsights(data);
    }
  }

  private async analyzeCompetitiveLandscape(data: EnrichmentData): Promise<{
    current_solutions: any[];
    competitor_relationships: any[];
    switching_probability: number;
  }> {
    const techStack = data.company?.tech_stack?.tools || [];
    const competitors = this.identifyCompetitors(techStack, data.company?.industry);

    return {
      current_solutions: competitors.map(comp => ({
        vendor: comp,
        product: 'Unknown',
        satisfaction_level: 6,
        switching_cost: 'medium',
        pain_points: ['Integration complexity', 'Limited scalability']
      })),
      competitor_relationships: [],
      switching_probability: techStack.length > 0 ? 0.3 : 0.7
    };
  }

  private async generateRecommendations(data: EnrichmentData): Promise<{
    recommended_approach: ApproachRecommendation;
    next_best_actions: NextBestAction[];
    personalized_messaging: PersonalizedMessage[];
  }> {
    const prompt = `
Create sales recommendations for this lead:

Contact: ${data.contact?.title || 'Unknown'} at ${data.company?.legal_name || 'Unknown'}
Company Size: ${data.company?.employee_count || 'Unknown'} employees
Industry: ${data.company?.industry || 'Unknown'}
Recent News: ${data.news?.recent_news?.[0]?.title || 'None'}

Generate:
1. Best sales approach strategy
2. Top 3 immediate next actions
3. Personalized message for cold outreach

Consider their seniority, industry, company size, and recent developments.
Be specific and actionable.
`;

    try {
      const response = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,
        max_tokens: 500,
        temperature: 0.4
      });

      return this.parseRecommendations(response.response, data);
    } catch (error) {
      return this.getDefaultRecommendations(data);
    }
  }

  private async analyzeRisks(data: EnrichmentData): Promise<{
    risk_factors: RiskFactor[];
    churn_indicators: any[];
  }> {
    const riskFactors: RiskFactor[] = [];

    // Budget risk
    if (!data.company?.annual_revenue || data.company.annual_revenue < 1000000) {
      riskFactors.push({
        type: 'budget',
        risk: 'Low revenue may indicate budget constraints',
        severity: 'medium',
        mitigation_strategy: 'Focus on ROI and quick wins',
        probability: 0.6
      });
    }

    // Authority risk
    if (data.contact?.seniority_level === 'individual_contributor') {
      riskFactors.push({
        type: 'authority',
        risk: 'Contact may not have decision-making authority',
        severity: 'high',
        mitigation_strategy: 'Request introduction to decision maker',
        probability: 0.8
      });
    }

    // Competition risk
    if (data.company?.tech_stack?.tools?.length > 10) {
      riskFactors.push({
        type: 'competition',
        risk: 'Heavy tech stack may indicate existing vendor relationships',
        severity: 'medium',
        mitigation_strategy: 'Emphasize integration capabilities',
        probability: 0.5
      });
    }

    // Timing risk
    if (data.news?.recent_news?.some(n => n.sentiment === 'negative')) {
      riskFactors.push({
        type: 'timing',
        risk: 'Recent negative news may affect buying decisions',
        severity: 'medium',
        mitigation_strategy: 'Wait for better timing or address concerns',
        probability: 0.4
      });
    }

    return {
      risk_factors: riskFactors,
      churn_indicators: []
    };
  }

  // Helper methods for parsing AI responses
  private parseScores(response: string): number[] {
    const numbers = response.match(/\d+/g);
    return numbers ? numbers.map(n => parseInt(n)).slice(0, 4) : [];
  }

  private parseQualificationInsights(response: string, data: EnrichmentData): any {
    // Default implementation - in production, would use more sophisticated parsing
    return this.getDefaultQualificationInsights(data);
  }

  private parsePersonalizationInsights(response: string, data: EnrichmentData): any {
    return this.getDefaultPersonalizationInsights(data);
  }

  private parseRecommendations(response: string, data: EnrichmentData): any {
    return this.getDefaultRecommendations(data);
  }

  private identifyCompetitors(techStack: string[], industry?: string): string[] {
    const techCompetitors: Record<string, string[]> = {
      'Salesforce': ['HubSpot', 'Pipedrive', 'Zoho'],
      'Slack': ['Microsoft Teams', 'Discord', 'Zoom'],
      'AWS': ['Azure', 'Google Cloud', 'Digital Ocean'],
      'Stripe': ['PayPal', 'Square', 'Adyen'],
      'Zendesk': ['Intercom', 'Freshdesk', 'Help Scout']
    };

    const competitors: string[] = [];
    for (const tech of techStack) {
      if (techCompetitors[tech]) {
        competitors.push(...techCompetitors[tech]);
      }
    }

    return [...new Set(competitors)];
  }

  // Default implementations
  private getDefaultInsights(): AIInsights {
    return {
      icp_fit_score: 50,
      buying_intent_score: 30,
      engagement_propensity: 60,
      conversion_probability: 0.25,
      budget_indicators: [],
      authority_indicators: [],
      need_indicators: [],
      timeline_indicators: [],
      pain_points: [],
      value_propositions: [],
      communication_preferences: [],
      meeting_best_times: [],
      current_solutions: [],
      competitor_relationships: [],
      switching_probability: 0.5,
      recommended_approach: {
        strategy: 'consultative',
        messaging_angle: 'efficiency',
        value_props: ['cost_savings', 'productivity'],
        objection_handling: [],
        next_steps: ['discovery_call'],
        success_probability: 0.3
      },
      next_best_actions: [],
      personalized_messaging: [],
      risk_factors: [],
      churn_indicators: [],
      upsell_opportunities: [],
      cross_sell_opportunities: [],
      expansion_potential: {
        additional_seats: 0,
        new_departments: [],
        geographic_expansion: [],
        total_revenue_potential: 0,
        timeline: '6-12 months'
      }
    };
  }

  private getDefaultQualificationInsights(data: EnrichmentData): any {
    const budget_indicators: BudgetIndicator[] = [];
    const authority_indicators: AuthorityIndicator[] = [];
    const need_indicators: NeedIndicator[] = [];
    const timeline_indicators: TimelineIndicator[] = [];

    // Budget analysis
    if (data.company?.annual_revenue && data.company.annual_revenue > 10000000) {
      budget_indicators.push({
        type: 'explicit',
        indicator: `Annual revenue of $${data.company.annual_revenue}`,
        confidence: 0.8,
        estimated_budget: Math.floor(data.company.annual_revenue * 0.1),
        budget_range: '100K-1M'
      });
    }

    // Authority analysis
    if (data.contact?.seniority_level === 'c_level') {
      authority_indicators.push({
        type: 'title',
        indicator: `C-level executive: ${data.contact.title}`,
        confidence: 0.9,
        authority_level: 'high'
      });
    }

    // Need analysis from news
    if (data.news?.recent_news?.length > 0) {
      need_indicators.push({
        category: 'growth',
        pain_point: 'Company growth and scaling challenges',
        urgency: 'medium',
        evidence: data.news.recent_news.map(n => n.title),
        confidence: 0.6
      });
    }

    return {
      budget_indicators,
      authority_indicators,
      need_indicators,
      timeline_indicators
    };
  }

  private getDefaultPersonalizationInsights(data: EnrichmentData): any {
    const industry = data.company?.industry || 'Technology';
    const role = data.contact?.seniority_level || 'individual_contributor';

    const industryPainPoints: Record<string, string[]> = {
      'Technology': ['Scaling infrastructure', 'Talent acquisition', 'Security compliance'],
      'Healthcare': ['Regulatory compliance', 'Patient experience', 'Cost management'],
      'Finance': ['Risk management', 'Regulatory compliance', 'Digital transformation'],
      'Retail': ['Customer experience', 'Inventory management', 'Omnichannel integration']
    };

    const roleValueProps: Record<string, string[]> = {
      'c_level': ['Strategic advantage', 'Competitive differentiation', 'Market leadership'],
      'vp': ['Team productivity', 'Operational efficiency', 'Cost optimization'],
      'director': ['Process improvement', 'Team scalability', 'Performance metrics'],
      'manager': ['Workflow automation', 'Resource optimization', 'Team collaboration']
    };

    return {
      pain_points: industryPainPoints[industry] || industryPainPoints['Technology'],
      value_propositions: roleValueProps[role] || roleValueProps['manager'],
      communication_preferences: [{
        channel: 'email',
        preference_score: 0.8,
        best_times: ['9:00-11:00', '14:00-16:00'],
        avoid_times: ['before 8:00', 'after 18:00']
      }],
      meeting_best_times: [{
        day_of_week: 'Tuesday',
        time_range: '10:00-11:00',
        timezone: data.contact?.location?.timezone || 'UTC',
        confidence: 0.7
      }]
    };
  }

  private getDefaultRecommendations(data: EnrichmentData): any {
    const isExecutive = data.contact?.seniority_level === 'c_level' || data.contact?.seniority_level === 'vp';

    return {
      recommended_approach: {
        strategy: isExecutive ? 'executive_briefing' : 'consultative_selling',
        messaging_angle: isExecutive ? 'strategic_value' : 'operational_efficiency',
        value_props: isExecutive
          ? ['Competitive advantage', 'Market leadership', 'Strategic growth']
          : ['Productivity gains', 'Cost savings', 'Process optimization'],
        objection_handling: ['Budget concerns', 'Timeline challenges', 'Integration complexity'],
        next_steps: isExecutive ? ['Executive briefing', 'ROI analysis'] : ['Product demo', 'Pilot program'],
        success_probability: isExecutive ? 0.4 : 0.6
      },
      next_best_actions: [
        {
          action: 'Send personalized LinkedIn connection request',
          priority: 'high',
          timing: 'immediately',
          context: 'Build relationship foundation',
          expected_outcome: 'Connection acceptance',
          success_probability: 0.7
        },
        {
          action: 'Research recent company initiatives',
          priority: 'medium',
          timing: 'within 24 hours',
          context: 'Prepare for initial outreach',
          expected_outcome: 'Better conversation starters',
          success_probability: 0.9
        },
        {
          action: 'Prepare industry-specific use case',
          priority: 'medium',
          timing: 'before first call',
          context: 'Show relevant value',
          expected_outcome: 'Higher engagement',
          success_probability: 0.8
        }
      ],
      personalized_messaging: [
        {
          channel: 'email',
          message_type: 'cold_outreach',
          subject_line: `Quick question about ${data.company?.legal_name || 'your company'}'s growth`,
          message: `Hi ${data.contact?.first_name || 'there'},\n\nI noticed ${data.company?.legal_name || 'your company'} ${data.news?.recent_news?.[0] ? `recently ${data.news.recent_news[0].title.toLowerCase()}` : 'is growing rapidly'}. Given your
  role as ${data.contact?.title || 'a leader'}, I thought you might be interested in how similar companies are solving [specific challenge].\n\nWould you be open to a brief 15-minute conversation next week?\n\nBest regards`,
          personalization_score: 0.8,
          expected_response_rate: 0.15
        }
      ]
    };
  }
}