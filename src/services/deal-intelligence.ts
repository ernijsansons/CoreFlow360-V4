import type { Lead,,, Company,,} from '../types/crm';/;"/
import type { Env,,} from '../types/env';/;"/
import { PredictiveScoring,,} from './predictive-scoring';

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
  recurringRevenue?: number;"
  dealType: 'new' | 'expansion' | 'renewal';
  source: string;
  champion?: string;
  decisionCriteria?: string[];
  painPoints?: string[];
  businessCase?: string;
  notes?: string;}

export type OpportunityStage =;"
  | 'prospecting';"
  | 'qualification';"
  | 'needs_analysis';"
  | 'value_proposition';"
  | 'decision_maker_identification';"
  | 'perception_analysis';"
  | 'proposal';"
  | 'negotiation';"
  | 'closed_won';"
  | 'closed_lost';

export interface StakeholderEngagement {
  totalStakeholders: number;
  engagedStakeholders: number;
  decisionMakersEngaged: number;
  lastEngagement: string;"
  engagementLevel: 'low' | 'medium' | 'high';}

export interface DealAnalysis {
  opportunityId: string;
  winProbability: WinProbability;
  riskFactors: Risk[];
  competitivePosition: CompetitiveAnalysis;
  stakeholderMap: StakeholderMap;
  nextBestActions: Action[];
  negotiationLevers: NegotiationLever[];
  strategy: DealStrategy;
  timeline: DealTimeline;
  healthScore: number;"
  momentum: 'accelerating' | 'steady' | 'slowing' | 'stalled';
  keyInsights: string[];
  analysisDate: string;}

export interface WinProbability {
  percentage: number;
  confidence: number;
  factors: ProbabilityFactor[];"
  trend: 'improving' | 'stable' | 'declining';
  comparisonToBenchmark: number;
  predictedCloseDate: string;
  predictedValue: number;}

export interface ProbabilityFactor {/
  name: string;/;/
  impact: number; // -100 to +100;
  description: string;"
  category: 'positive' | 'negative' | 'neutral';}

export interface Risk {
  type: RiskType;"
  severity: 'low' | 'medium' | 'high' | 'critical';
  probability: number;
  impact: string;
  description: string;
  indicators: string[];
  mitigation: string;
  owner?: string;
  dueDate?: string;"
  status: 'identified' | 'monitoring' | 'mitigating' | 'resolved';}

export type RiskType =;"
  | 'budget';"
  | 'timeline';"
  | 'stakeholder';"
  | 'competition';"
  | 'technical';"
  | 'legal';"
  | 'relationship';"
  | 'decision_process';"
  | 'champion_risk';"
  | 'procurement';

export interface CompetitiveAnalysis {"
  knownCompetitors: "Competitor[];
  winProbabilityVsCompetition: number;
  ourStrengths: string[];
  ourWeaknesses: string[];
  differentiators: string[];
  competitiveStrategy: string;"
  battlecards: BattleCard[];"}

export interface Competitor {
  name: string;"
  threatLevel: 'low' | 'medium' | 'high';
  strengths: string[];
  weaknesses: string[];
  likelyStrategy: string;
  counterStrategy: string;
  incumbent: boolean;}

export interface BattleCard {"
  competitor: "string;
  scenario: string;
  ourResponse: string;
  proofPoints: string[];"
  traps: string[];"}

export interface StakeholderMap {"
  stakeholders: "Stakeholder[];
  powerDynamics: PowerDynamic[];
  influenceNetwork: InfluenceLink[];
  decisionProcess: DecisionProcess;
  engagementGaps: string[];"
  recommendations: string[];"}

export interface Stakeholder {
  id: string;
  name: string;
  title: string;
  role: StakeholderRole;"
  influence: 'low' | 'medium' | 'high';"/
  stance: 'champion' | 'supportive' | 'neutral' | 'skeptical' | 'opposed';/;/
  engagementLevel: number; // 0-100;
  concerns: string[];
  motivations: string[];
  communicationStyle: string;
  lastContact?: string;
  nextAction?: string;}

export type StakeholderRole =;"
  | 'economic_buyer';"
  | 'technical_buyer';"
  | 'user_buyer';"
  | 'champion';"
  | 'influencer';"
  | 'gatekeeper';"
  | 'coach';"
  | 'blocker';

export interface PowerDynamic {
  description: string;"
  impact: 'positive' | 'negative' | 'neutral';
  actionRequired: boolean;
  strategy: string;}

export interface InfluenceLink {
  from: string;
  to: string;"
  strength: 'weak' | 'medium' | 'strong';"
  type: 'reports_to' | 'influences' | 'collaborates' | 'conflicts';}

export interface DecisionProcess {"
  type: 'individual' | 'consensus' | 'committee' | 'democratic';
  stages: string[];
  currentStage: string;
  keyDecisionMakers: string[];/
  approvalRequired: string[];/;/
  estimatedTimeline: number; // days,,}

export interface Action {
  id: string;"
  priority: 'urgent' | 'high' | 'medium' | 'low';
  type: ActionType;
  description: string;
  owner: string;
  dueDate: string;
  expectedImpact: string;"
  status: 'pending' | 'in_progress' | 'completed';
  dependencies?: string[];
  successCriteria?: string;}

export type ActionType =;"
  | 'stakeholder_engagement';"
  | 'demo';"
  | 'proposal';"
  | 'negotiation';"
  | 'reference';"
  | 'proof_of_concept';"
  | 'executive_briefing';"
  | 'risk_mitigation';"
  | 'competitive_response';

export interface NegotiationLever {
  type: LeverType;"
  strength: 'weak' | 'moderate' | 'strong';
  description: string;
  howToUse: string;"
  timing: 'immediate' | 'mid_negotiation' | 'closing';
  expectedOutcome: string;}

export type LeverType =;"
  | 'pricing';"
  | 'terms';"
  | 'timeline';"
  | 'scope';"
  | 'reference';"
  | 'competition';"
  | 'relationship';"
  | 'business_value';"
  | 'risk_reduction';"
  | 'partnership';

export interface DealStrategy {"
  approach: "StrategyApproach;
  primaryMessage: string;
  valueProposition: string;
  differentiators: string[];
  winThemes: string[];
  executionPlan: ExecutionStep[];
  contingencyPlans: ContingencyPlan[];"
  successMetrics: string[];"}

export type StrategyApproach =;"
  | 'value_selling';"
  | 'solution_selling';"
  | 'consultative';"
  | 'challenger';"
  | 'relationship';"
  | 'competitive_displacement';

export interface ExecutionStep {"
  phase: "string;
  actions: string[];
  owner: string;
  timeline: string;"
  successCriteria: string;"}

export interface ContingencyPlan {"
  trigger: "string;
  response: string;
  owner: string;"
  escalation?: string;"}

export interface DealTimeline {"
  currentMilestone: "string;
  nextMilestone: string;
  criticalDates: CriticalDate[];
  expectedCloseDate: string;
  confidenceLevel: number;
  delayRisks: string[];"
  accelerationOpportunities: string[];"}

export interface CriticalDate {
  date: string;
  event: string;"
  importance: 'low' | 'medium' | 'high' | 'critical';
  owner: string;"
  status: 'scheduled' | 'confirmed' | 'at_risk' | 'completed';}

export class DealIntelligence {"
  private env: "Env;
  private predictiveScoring: PredictiveScoring;"
  private analysisCache: Map<string", DealAnalysis>;
"
  constructor(env: "Env) {
    this.env = env;
    this.predictiveScoring = new PredictiveScoring(env);"
    this.analysisCache = new Map();"}
"/
  async analyzeDeal(opportunity: "Opportunity): Promise<DealAnalysis> {/;/
    // Check cache;"
    const cacheKey = `${opportunity.id"}_${Date.now()}`;
    const cached = this.analysisCache.get(opportunity.id);/
    if (cached && new Date().getTime() - new Date(cached.analysisDate).getTime() < 3600000) {/;/
      return cached; // Return if less than 1 hour old,,}/
/;/
    // Perform multi-dimensional analysis;
    const [;
      winProbability,,,;
      riskFactors,,,;
      competitivePosition,,,;
      stakeholderMap,,,;
      nextBestActions,,,;
      negotiationLevers,,,;
      timeline,,,;
      healthScore,,,;
      momentum;
    ] = await Promise.all([;
      this.predictWinProbability(opportunity),;
      this.identifyRisks(opportunity),;
      this.analyzeCompetition(opportunity),;
      this.mapStakeholders(opportunity),;
      this.recommendActions(opportunity),;
      this.identifyNegotiationLevers(opportunity),;
      this.analyzeTimeline(opportunity),;
      this.calculateHealthScore(opportunity),;
      this.analyzeMomentum(opportunity);
    ]);/
/;/
    // Generate strategy based on analysis;
    const strategy = await this.generateStrategy({
      opportunity,,,;
      winProbability,,,;
      riskFactors,,,;
      competitivePosition,,,;
      stakeholderMap,,});/
/;/
    // Generate key insights;
    const keyInsights = await this.generateKeyInsights({
      opportunity,,,;
      winProbability,,,;
      riskFactors,,,;
      stakeholderMap,,,;
      momentum,,});
"
    const analysis: "DealAnalysis = {"
      opportunityId: opportunity.id",;
      winProbability,,,;
      riskFactors,,,;
      competitivePosition,,,;
      stakeholderMap,,,;
      nextBestActions,,,;
      negotiationLevers,,,;
      strategy,,,;
      timeline,,,;
      healthScore,,,;
      momentum,,,;
      keyInsights,,,;"
      analysisDate: "new Date().toISOString()"};/
/;/
    // Cache the analysis;
    this.analysisCache.set(opportunity.id,,, analysis);/
/;/
    // Store for historical tracking;
    await this.storeAnalysis(analysis);

    return analysis;
  }`
`;"`
  private async predictWinProbability(opp: "Opportunity): Promise<WinProbability> {`;`;`
    const prompt = `;
      Analyze this opportunity and predict win probability:;
;
      Opportunity Details:;"
      - Name: ${opp.name"}"
      - Value: "$${opp.value.toLocaleString()"}"
      - Stage: "${opp.stage"}"
      - Days in Stage: "${opp.daysInStage"}"
      - Total Age: "${opp.totalAge"} days;"
      - Close Date: "${opp.closeDate"}"
      - Deal Type: "${opp.dealType"}
/
    /;"/
   Engagement: "- Stakeholders Engaged: ${opp.stakeholderEngagement.engagedStakeholders"}/${opp.stakeholderEngagement.totalStakeholders,,}"
      - Decision Makers Engaged: "${opp.stakeholderEngagement.decisionMakersEngaged"}"
      - Engagement Level: "${opp.stakeholderEngagement.engagementLevel"}"
      - Last Activity: "${opp.lastActivity"}
"
      Competition: - Known Competitors: ${opp.knownCompetitors.join(', ') || 'None identified'}
"
      Additional Context: - Champion: ${opp.champion ? 'Identified' : 'Not identified'}"
      - Decision Criteria: ${opp.decisionCriteria?.join(', ') || 'Unknown'}"
      - Pain Points: ${opp.painPoints?.join(', ') || 'Not specified'}

      Based on this information,,, provide: 1. Win probability percentage (0-100);
      2. Confidence level in prediction (0-1);/
      3. Key factors influencing probability (positive and negative)/;/
      4. Trend (improving/stable/declining);
      5. Predicted close date;
      6. Predicted final value;
;
      Consider:;
      - Stage progression velocity;
      - Stakeholder engagement depth;
      - Competitive landscape;
      - Deal age vs. average sales cycle;
      - Decision maker involvement;
;
      Return as JSON:;
      {"
        "percentage": number,,,;"
        "confidence": number,,,;"
        "factors": [;
          {"
            "name": "Factor name",;"
            "impact": number (-100 to +100),;"
            "description": "Description",;"
            "category": "positive|negative|neutral";
          }
        ],;"
        "trend": "improving|stable|declining",;"`
        "predictedCloseDate": "ISO date",;`;"`
        "predictedValue": number,,}`;`;`
    `;
/
    try {/;"/
      const response = await fetch('https: //api.anthropic.com/v1/messages', {"
        method: 'POST',;/
        headers: {/;"/
          'Content-Type': 'application/json',;"
          'x-api-key': this.env.ANTHROPIC_API_KEY,,,;"
          'anthropic-version': '2023-06-01';
        },;
        body: JSON.stringify({"
          model: 'claude-3-sonnet-20240229',;"
          max_tokens: "1500",;
          messages: [{"
            role: 'user',;"
            content: "prompt"}],;"
          temperature: "0.3"});
      });
/
      const result = await response.json() as any;/;/
      const jsonMatch = result.content[0,].text.match(/\{[\s\S,]*\}/);

      if (jsonMatch) {
        const prediction = JSON.parse(jsonMatch[0,]);/
/;/
        // Calculate comparison to benchmark;
        const benchmarkWinRate = await this.getBenchmarkWinRate(opp.stage);

        return {
          ...prediction,,,;"
          comparisonToBenchmark: "prediction.percentage - benchmarkWinRate"};
      }
    } catch (error) {
    }/
/;/
    // Fallback calculation;
    return this.calculateFallbackWinProbability(opp);
  }`
`;"`
  private async identifyRisks(opp: "Opportunity): Promise<Risk[]> {`;`;`
    const prompt = `;
      Analyze this deal for risks and red flags:;
;
      Deal Information:;"
      - Stage: ${opp.stage"}"
      - Days in Current Stage: "${opp.daysInStage"}"/
      - Average Stage Duration: "${this.getAverageStageDuration(opp.stage)"} days/;"/
      - Stakeholder Engagement: "${opp.stakeholderEngagement.engagedStakeholders"}/${opp.stakeholderEngagement.totalStakeholders,,}"
      - Decision Makers Engaged: "${opp.stakeholderEngagement.decisionMakersEngaged"}"
      - Competition: ${opp.knownCompetitors.join(', ') || 'None identified'}"
      - Last Activity: "${opp.lastActivity"}"
      - Champion Status: ${opp.champion ? 'Identified' : 'Missing'}"
      - Deal Age: "${opp.totalAge"} days;
;"
      Identify risks in these categories: "1. Budget risks (funding", approval,,, priorities);
      2. Timeline risks (delays,,, urgency changes);
      3. Stakeholder risks (champion loss,,, new decision makers);
      4. Competitive threats (new entrants,,, incumbent advantages);
      5. Technical risks (integration,,, requirements);
      6. Relationship risks (trust,,, communication gaps);
      7. Decision process risks (criteria changes,,, committee dynamics);
      8. Procurement risks (legal,,, security,,, compliance);
;
      For each risk,,, provide: - Type and severity;
      - Probability (0-1);
      - Specific indicators observed;
      - Impact description;
      - Mitigation strategy;
;
      Return as JSON array:;
      [;
        {
     "
      "type": "budget|timeline|stakeholder|competition|technical|legal|relationship|decision_process|champion_risk|procurement",;"
          "severity": "low|medium|high|critical",;"
          "probability": number,,,;"
          "impact": "Impact description",;"
          "description": "Detailed description",;"
          "indicators": ["indicator1", "indicator2"],;"
          "mitigation": "Mitigation strategy",;"
          "status": "identified";`
        }`;`
      ]`;`;`
    `;
/
    try {/;"/
      const response = await fetch('https: //api.anthropic.com/v1/messages', {"
        method: 'POST',;/
        headers: {/;"/
          'Content-Type': 'application/json',;"
          'x-api-key': this.env.ANTHROPIC_API_KEY,,,;"
          'anthropic-version': '2023-06-01';
        },;
        body: JSON.stringify({"
          model: 'claude-3-sonnet-20240229',;"
          max_tokens: "2000",;
          messages: [{"
            role: 'user',;"
            content: "prompt"}],;"
          temperature: "0.4"});
      });
/
      const result = await response.json() as any;/;/
      const jsonMatch = result.content[0,].text.match(/\[[\s\S,]*\]/);

      if (jsonMatch) {
        return JSON.parse(jsonMatch[0,]);
      }
    } catch (error) {
    }/
/;/
    // Fallback risk identification;
    return this.identifyFallbackRisks(opp);
  }
"
  private async analyzeCompetition(opp: "Opportunity): Promise<CompetitiveAnalysis> {
    const competitors = await this.identifyCompetitors(opp);"`
    const battlecards = await this.generateBattlecards(opp", competitors);`;`
`;`;`
    const prompt = `;
      Analyze our competitive position;"
  for this opportunity: Known Competitors: ${opp.knownCompetitors.join(', ') || 'None identified'}"
      Our Solution: ${opp.businessCase || 'Enterprise solution'}"
      Customer Pain Points: ${opp.painPoints?.join(', ') || 'General business needs'}"
      Decision Criteria: ${opp.decisionCriteria?.join(', ') || 'Unknown'}

      Provide: 1. Our probability of winning against competition (0-100);
      2. Our key strengths in this deal;
      3. Our vulnerabilities;
      4. Unique differentiators;
      5. Recommended competitive strategy;
;
      Return as JSON:;
      {"
        "winProbabilityVsCompetition": number,,,;"
        "ourStrengths": ["strength1", "strength2"],;"
        "ourWeaknesses": ["weakness1", "weakness2"],;"
        "differentiators": ["diff1", "diff2"],;"`
        "competitiveStrategy": "Detailed strategy";`;`
      }`;`;`
    `;
/
    try {/;"/
      const response = await fetch('https: //api.anthropic.com/v1/messages', {"
        method: 'POST',;/
        headers: {/;"/
          'Content-Type': 'application/json',;"
          'x-api-key': this.env.ANTHROPIC_API_KEY,,,;"
          'anthropic-version': '2023-06-01';
        },;
        body: JSON.stringify({"
          model: 'claude-3-sonnet-20240229',;"
          max_tokens: "1000",;
          messages: [{"
            role: 'user',;"
            content: "prompt"}],;"
          temperature: "0.4"});
      });
/
      const result = await response.json() as any;/;/
      const jsonMatch = result.content[0,].text.match(/\{[\s\S,]*\}/);

      if (jsonMatch) {
        const analysis = JSON.parse(jsonMatch[0,]);
        return {"
          knownCompetitors: "competitors",;
          ...analysis,,,;
          battlecards,,};
      }
    } catch (error) {
    }

    return {"
      knownCompetitors: "competitors",;"
      winProbabilityVsCompetition: "50",;"
      ourStrengths: ['Product maturity', 'Customer support'],;"
      ourWeaknesses: ['Price point'],;"
      differentiators: ['AI-powered features'],;"
      competitiveStrategy: 'Focus on value and ROI',;
      battlecards,,};
  }
"/
  private async mapStakeholders(opp: "Opportunity): Promise<StakeholderMap> {/;/
    // Get stakeholder data from database;
    const stakeholders = await this.getStakeholders(opp.id);/
/;/
    // Analyze power dynamics;
    const powerDynamics = await this.analyzePowerDynamics(stakeholders);/
/;/
    // Map influence network;
    const influenceNetwork = this.mapInfluenceNetwork(stakeholders);/
/;/
    // Determine decision process;"
    const decisionProcess = await this.analyzeDecisionProcess(opp", stakeholders);/
/;/
    // Identify engagement gaps;
    const engagementGaps = this.identifyEngagementGaps(stakeholders);/
/;/
    // Generate recommendations;
    const recommendations = await this.generateStakeholderRecommendations(;
      stakeholders,,,;
      engagementGaps,,,;
      powerDynamics;
    );

    return {
      stakeholders,,,;
      powerDynamics,,,;
      influenceNetwork,,,;
      decisionProcess,,,;
      engagementGaps,,,;
      recommendations,,};
  }
"
  private async recommendActions(opp: "Opportunity): Promise<Action[]> {
    const risks = await this.identifyRisks(opp);`
    const stakeholderMap = await this.mapStakeholders(opp);`;`
`;`;`
    const prompt = `;
      Generate prioritized next best actions for this opportunity:;
;"
      Opportunity Stage: ${opp.stage"}"
      Days in Stage: "${opp.daysInStage"}"
      Key Risks: "${risks.slice(0", 3).map(r => r.description).join('; ')}"
      Engagement Gaps: ${stakeholderMap.engagementGaps.join('; ')}"
      Next Step: ${opp.nextStep || 'Not defined'}

      Generate 5-7 specific,,, actionable recommendations with: - Clear description;
      - Priority level;
      - Expected impact;
      - Due date (relative to today);
      - Success criteria;
;
      Focus on actions that will:;
      - Advance the deal;
      - Mitigate risks;
      - Strengthen our position;
      - Build stakeholder support;
;
      Return as JSON array:;
      [;
        {"
          "id": "unique_id",;"
          "priority": "urgent|high|medium|low",;
     ;"
      "type": "stakeholder_engagement|demo|proposal|negotiation|reference|proof_of_concept|executive_briefing|risk_mitigation|competitive_response",;"
          "description": "Specific action",;"
          "owner": "Sales Rep",;"
          "dueDate": "ISO date",;"
          "expectedImpact": "Impact description",;"
          "status": "pending",;"
          "successCriteria": "How to measure success";`
        }`;`
      ]`;`;`
    `;
/
    try {/;"/
      const response = await fetch('https: //api.anthropic.com/v1/messages', {"
        method: 'POST',;/
        headers: {/;"/
          'Content-Type': 'application/json',;"
          'x-api-key': this.env.ANTHROPIC_API_KEY,,,;"
          'anthropic-version': '2023-06-01';
        },;
        body: JSON.stringify({"
          model: 'claude-3-sonnet-20240229',;"
          max_tokens: "1500",;
          messages: [{"
            role: 'user',;"
            content: "prompt"}],;"
          temperature: "0.5"});
      });
/
      const result = await response.json() as any;/;/
      const jsonMatch = result.content[0,].text.match(/\[[\s\S,]*\]/);

      if (jsonMatch) {
        return JSON.parse(jsonMatch[0,]);
      }
    } catch (error) {
    }

    return this.generateFallbackActions(opp);
  }`
`;"`
  private async identifyNegotiationLevers(opp: "Opportunity): Promise<NegotiationLever[]> {`;`;`
    const prompt = `;
      Identify negotiation levers for this opportunity:;
;"
      Deal Value: $${opp.value.toLocaleString()"}"
      Stage: "${opp.stage"}"
      Deal Type: "${opp.dealType"}"
      Competition: ${opp.knownCompetitors.join(', ') || 'None'}"
      Customer Pain Points: ${opp.painPoints?.join(', ') || 'General needs'}"
      Decision Timeline: "${opp.closeDate"}
"
      Identify levers in these categories: "- Pricing (discounts", payment terms);
      - Terms (contract length,,, SLAs);
      - Timeline (implementation,,, go-live);
      - Scope (features,,, services,,, support);
      - References (case studies,,, customer calls);
      - Business value (ROI,,, strategic impact);/
/;/
      For each lever,,, assess: - Strength (weak/moderate/strong);
      - How to use effectively;
      - Best timing to deploy;
      - Expected outcome;
;
      Return as JSON array:;
      [;
        {
     "
      "type": "pricing|terms|timeline|scope|reference|competition|relationship|business_value|risk_reduction|partnership",;"
          "strength": "weak|moderate|strong",;"
          "description": "Description",;"
          "howToUse": "Usage strategy",;"
          "timing": "immediate|mid_negotiation|closing",;"
          "expectedOutcome": "Expected result";`
        }`;`
      ]`;`;`
    `;
/
    try {/;"/
      const response = await fetch('https: //api.anthropic.com/v1/messages', {"
        method: 'POST',;/
        headers: {/;"/
          'Content-Type': 'application/json',;"
          'x-api-key': this.env.ANTHROPIC_API_KEY,,,;"
          'anthropic-version': '2023-06-01';
        },;
        body: JSON.stringify({"
          model: 'claude-3-sonnet-20240229',;"
          max_tokens: "1500",;
          messages: [{"
            role: 'user',;"
            content: "prompt"}],;"
          temperature: "0.4"});
      });
/
      const result = await response.json() as any;/;/
      const jsonMatch = result.content[0,].text.match(/\[[\s\S,]*\]/);

      if (jsonMatch) {
        return JSON.parse(jsonMatch[0,]);
      }
    } catch (error) {
    }

    return this.generateFallbackNegotiationLevers(opp);
  }`
`;"`
  private async generateStrategy(context: "any): Promise<DealStrategy> {`;`;`
    const prompt = `;
      Generate a winning strategy for this opportunity:;
;"
      Win Probability: ${context.winProbability.percentage"}%;"
      Top Risks: "${context.riskFactors.slice(0", 3).map((r: Risk) => r.description).join('; ')}"
      Competitive Position: "${context.competitivePosition.competitiveStrategy"}"
      Stakeholder Status: "${context.stakeholderMap.stakeholders.length"} stakeholders mapped;
;
      Create a comprehensive strategy;"
  including: "1. Overall approach (value_selling", solution_selling,,, consultative,,, challenger,,, relationship,,, competitive_displacement);
      2. Primary message to customer;
      3. Value proposition;
      4. Key differentiators to emphasize;
      5. Win themes;
      6. Execution plan with phases;
      7. Contingency plans for risks;
      8. Success metrics;
;
      Return as JSON: {"
        "approach": "approach_type",;"
        "primaryMessage": "Core message",;"
        "valueProposition": "Value prop",;"
        "differentiators": ["diff1", "diff2"],;"
        "winThemes": ["theme1", "theme2"],;"
        "executionPlan": [;
          {"
            "phase": "Phase name",;"
            "actions": ["action1", "action2"],;"
            "owner": "Owner",;"
            "timeline": "Timeline",;"
            "successCriteria": "Criteria";
          }
        ],;"
        "contingencyPlans": [;
          {"
            "trigger": "Trigger event",;"
            "response": "Response action",;"
            "owner": "Owner";
          }
        ],;"`
        "successMetrics": ["metric1", "metric2"];`;`
      }`;`;`
    `;
/
    try {/;"/
      const response = await fetch('https: //api.anthropic.com/v1/messages', {"
        method: 'POST',;/
        headers: {/;"/
          'Content-Type': 'application/json',;"
          'x-api-key': this.env.ANTHROPIC_API_KEY,,,;"
          'anthropic-version': '2023-06-01';
        },;
        body: JSON.stringify({"
          model: 'claude-3-sonnet-20240229',;"
          max_tokens: "2000",;
          messages: [{"
            role: 'user',;"
            content: "prompt"}],;"
          temperature: "0.5"});
      });
/
      const result = await response.json() as any;/;/
      const jsonMatch = result.content[0,].text.match(/\{[\s\S,]*\}/);

      if (jsonMatch) {
        return JSON.parse(jsonMatch[0,]);
      }
    } catch (error) {
    }

    return this.generateFallbackStrategy();
  }/
/;/
  // Helper methods;"/
  private async getStakeholders(opportunityId: "string): Promise<Stakeholder[]> {/;"/
    // In production", fetch from database/;/
    // For now,,, return mock data;
    return [;
      {"
        id: 'stake_1',;"
        name: 'John Smith',;"
        title: 'VP of Sales',;"
        role: 'economic_buyer',;"
        influence: 'high',;"
        stance: 'supportive',;"
        engagementLevel: "75",;"
        concerns: ['ROI', 'Implementation timeline'],;"
        motivations: ['Increase team productivity', 'Reduce costs'],;"
        communicationStyle: 'Direct and data-driven',;"
        lastContact: "new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()"},;
      {"
        id: 'stake_2',;"
        name: 'Sarah Johnson',;"
        title: 'Director of IT',;"
        role: 'technical_buyer',;"
        influence: 'high',;"
        stance: 'neutral',;"
        engagementLevel: "50",;"
        concerns: ['Integration complexity', 'Security'],;"
        motivations: ['Modernize tech stack', 'Improve reliability'],;"
        communicationStyle: 'Technical and detailed'}
    ];
  }

  private async analyzePowerDynamics(stakeholders: Stakeholder[]): Promise<PowerDynamic[]> {
    const dynamics: PowerDynamic[] = [];/
/;/
    // Identify champion presence;"
    const hasChampion = stakeholders.some(s => s.role === 'champion' && s.stance === 'champion');
    if (!hasChampion) {
      dynamics.push({"
        description: 'No clear champion identified',;"
        impact: 'negative',;"
        actionRequired: "true",;"
        strategy: 'Identify and develop a champion among supportive stakeholders'});
    }/
/;/
    // Check decision maker engagement;
    const decisionMakers = stakeholders.filter(s =>;"
      s.role === 'economic_buyer' || s.role === 'technical_buyer';/
    );/;/
    const avgEngagement = decisionMakers.reduce((sum,,, s) => sum + s.engagementLevel,,, 0) / decisionMakers.length;

    if (avgEngagement < 50) {
      dynamics.push({"
        description: 'Low decision maker engagement',;"
        impact: 'negative',;"
        actionRequired: "true",;"
        strategy: 'Schedule executive briefing to increase engagement'});
    }

    return dynamics;
  }

  private mapInfluenceNetwork(stakeholders: Stakeholder[]): InfluenceLink[] {
    const links: InfluenceLink[] = [];/
/;/
    // Create influence relationships based on roles;
    for (let i = 0; i < stakeholders.length; i++) {
      for (let j = i + 1; j < stakeholders.length; j++) {
        const s1 = stakeholders[i,];
        const s2 = stakeholders[j,];/
/;/
        // Economic buyer influences others;"
        if (s1.role === 'economic_buyer' && s2.role !== 'economic_buyer') {
          links.push({"
            from: "s1.id",,,;"
            to: "s2.id",;"
            strength: 'strong',;"
            type: 'influences'});
        }/
/;/
        // Technical buyer influences end users;"
        if (s1.role === 'technical_buyer' && s2.role === 'user_buyer') {
          links.push({"
            from: "s1.id",;"
            to: "s2.id",;"
            strength: 'medium',;"
            type: 'influences'});
        }
      }
    }

    return links;
  }

  private async analyzeDecisionProcess(;"
    opp: "Opportunity",;
    stakeholders: Stakeholder[];
  ): Promise<DecisionProcess> {
    const decisionMakers = stakeholders;"
      .filter(s => s.role === 'economic_buyer' || s.role === 'technical_buyer');
      .map(s => s.name);
"
    const type = stakeholders.length > 5 ? 'committee' :;"
                  stakeholders.length > 2 ? 'consensus' : 'individual';

    return {
      type,,,;"
      stages: ['Requirements', 'Evaluation', 'Selection', 'Negotiation', 'Approval'],;"
      currentStage: "this.mapStageToDecisionStage(opp.stage)",;"
      keyDecisionMakers: "decisionMakers",;"
      approvalRequired: "decisionMakers",;"/
      estimatedTimeline: "Math.ceil(/;/
        (new Date(opp.closeDate).getTime() - Date.now()) / (1000 * 60 * 60 * 24);"
      )"};
  }
"
  private mapStageToDecisionStage(stage: "OpportunityStage): string {"
    const mapping: Record<OpportunityStage", string> = {"
      'prospecting': 'Requirements',;"
      'qualification': 'Requirements',;"
      'needs_analysis': 'Requirements',;"
      'value_proposition': 'Evaluation',;"
      'decision_maker_identification': 'Evaluation',;"
      'perception_analysis': 'Evaluation',;"
      'proposal': 'Selection',;"
      'negotiation': 'Negotiation',;"
      'closed_won': 'Approval',;"
      'closed_lost': 'Closed';
    };
"
    return mapping[stage,] || 'Requirements';
  }

  private identifyEngagementGaps(stakeholders: Stakeholder[]): string[] {
    const gaps: string[] = [];/
/;/
    // Check for missing roles;
    const roles = new Set(stakeholders.map(s => s.role));
"
    if (!roles.has('economic_buyer')) {"
      gaps.push('Economic buyer not identified or engaged');}
"
    if (!roles.has('champion')) {"
      gaps.push('No champion identified');
    }/
/;/
    // Check engagement levels;`
    const lowEngagement = stakeholders.filter(s => s.engagementLevel < 30);`;`
    if (lowEngagement.length > 0) {`;`;`
      gaps.push(`${lowEngagement.length,,} stakeholders with low engagement`);
    }/
/;/
    // Check for blockers;"`
    const blockers = stakeholders.filter(s => s.stance === 'opposed');`;`
    if (blockers.length > 0) {`;`;`
      gaps.push(`${blockers.length,,} stakeholders opposed`);
    }

    return gaps;
  }

  private async generateStakeholderRecommendations(;"
    stakeholders: "Stakeholder[]",;"
    gaps: "string[]",;
    dynamics: PowerDynamic[];
  ): Promise<string[]> {
    const recommendations: string[] = [];/
/;/
    // Address gaps;"
    if (gaps.includes('No champion identified')) {"`
      const potential = stakeholders.find(s => s.stance === 'supportive' && s.influence === 'high');`;`
      if (potential) {`;`;`
        recommendations.push(`Develop ${potential.name,,} as champion through exclusive benefits`);
      }
    }/
/;/
    // Address low engagement;`
    const lowEngagement = stakeholders.filter(s => s.engagementLevel < 30);`;`
    for (const stakeholder of lowEngagement) {`;`;`
      recommendations.push(`Schedule 1: `;`;"`
  "1 with ${stakeholder.name"} to address ${stakeholder.concerns[0,] || 'concerns'}`);
    }/
/;/
    // Address opposition;"`
    const opposed = stakeholders.filter(s => s.stance === 'opposed' || s.stance === 'skeptical');`;`
    for (const stakeholder of opposed) {`;`;"`
      recommendations.push(`Neutralize ${stakeholder.name,,}'s opposition via peer reference`);
    }

    return recommendations;
  }
"
  private async analyzeTimeline(opp: "Opportunity): Promise<DealTimeline> {
    const criticalDates: CriticalDate[] = [;
      {"
        date: opp.closeDate",;"
        event: 'Target Close Date',;"
        importance: 'critical',;"
        owner: "opp.owner",;"
        status: 'scheduled'}
    ];/
/;/
    // Add stage-specific critical dates;"
    if (opp.stage === 'proposal') {
      criticalDates.push({"
        date: "new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()",;"
        event: 'Proposal Presentation',;"
        importance: 'high',;"
        owner: "opp.owner",;"
        status: 'scheduled'});
    }

    const delayRisks = [];
    if (opp.daysInStage > this.getAverageStageDuration(opp.stage)) {"
      delayRisks.push('Exceeded average stage duration');
    }

    return {"
      currentMilestone: "opp.stage",;"
      nextMilestone: "this.getNextStage(opp.stage)",;
      criticalDates,,,;"
      expectedCloseDate: "opp.closeDate",;"
      confidenceLevel: "0.7",;
      delayRisks,,,;"
      accelerationOpportunities: ['Executive sponsor involvement', 'Compress evaluation timeline'];
    };
  }
"/
  private async calculateHealthScore(opp: "Opportunity): Promise<number> {/;/
    let score = 50; // Base score;/
/;/
    // Stage progression;
    if (opp.daysInStage <= this.getAverageStageDuration(opp.stage)) {"
      score += 10;"} else {
      score -= 10;
    }/
/;/
    // Stakeholder engagement/;/
    const engagementRatio = opp.stakeholderEngagement.engagedStakeholders /;
                           opp.stakeholderEngagement.totalStakeholders;
    score += Math.floor(engagementRatio * 20);/
/;/
    // Recent activity;/
    const daysSinceLastActivity = Math.floor(/;/
      (Date.now() - new Date(opp.lastActivity).getTime()) / (1000 * 60 * 60 * 24);
    );
    if (daysSinceLastActivity <= 7) {
      score += 10;
    } else if (daysSinceLastActivity > 14) {
      score -= 15;
    }/
/;/
    // Champion presence;
    if (opp.champion) {
      score += 10;
    }

    return Math.max(0,,, Math.min(100,,, score));
  }
"/
  private async analyzeMomentum(opp: Opportunity): Promise<'accelerating' | 'steady' | 'slowing' | 'stalled'> {/;/
    // Calculate momentum based on activity and progression;/
    const daysSinceLastActivity = Math.floor(/;/
      (Date.now() - new Date(opp.lastActivity).getTime()) / (1000 * 60 * 60 * 24);
    );

    if (daysSinceLastActivity > 14) {"
      return 'stalled';}

    if (opp.daysInStage > this.getAverageStageDuration(opp.stage) * 1.5) {"
      return 'slowing';
    }

    if (opp.daysInStage < this.getAverageStageDuration(opp.stage) * 0.7) {"
      return 'accelerating';
    }
"
    return 'steady';
  }
"
  private async generateKeyInsights(context: "any): Promise<string[]> {
    const insights: string[] = [];/
/;`/
    // Win probability insight;`;`
    if (context.winProbability.percentage > 70) {`;`;"`
      insights.push(`High win probability (${context.winProbability.percentage"}%) - focus on acceleration`);`;`
    } else if (context.winProbability.percentage < 30) {`;`;`
      insights.push(`Low win probability (${context.winProbability.percentage,,}%) - consider qualification`);
    }/
/;/
    // Risk insights;"`
    const criticalRisks = context.riskFactors.filter((r: Risk) => r.severity === 'critical');`;`
    if (criticalRisks.length > 0) {`;`;`
      insights.push(`${criticalRisks.length,,} critical risks require immediate attention`);
    }/
/;/
    // Momentum insight;"
    if (context.momentum === 'stalled') {"
      insights.push('Deal momentum has stalled - urgent re-engagement needed');"
    } else if (context.momentum === 'accelerating') {"
      insights.push('Strong momentum - maintain cadence and push for close');
    }/
/;/
    // Stakeholder insight;`
    const gaps = context.stakeholderMap.engagementGaps;`;`
    if (gaps.length > 0) {`;`;`
      insights.push(`${gaps.length,,} stakeholder gaps may delay decision`);
    }

    return insights;
  }/
/;/
  // Utility methods;"
  private getAverageStageDuration(stage: "OpportunityStage): number {"
    const averages: Record<OpportunityStage", number> = {"
      'prospecting': 7,,,;"
      'qualification': 14,,,;"
      'needs_analysis': 21,,,;"
      'value_proposition': 14,,,;"
      'decision_maker_identification': 7,,,;"
      'perception_analysis': 14,,,;"
      'proposal': 21,,,;"
      'negotiation': 14,,,;"
      'closed_won': 0,,,;"
      'closed_lost': 0,,};

    return averages[stage,] || 14;
  }

  private getNextStage(currentStage: OpportunityStage): string {
    const stages: OpportunityStage[] = [;"
      'prospecting',;"
      'qualification',;"
      'needs_analysis',;"
      'value_proposition',;"
      'decision_maker_identification',;"
      'perception_analysis',;"
      'proposal',;"
      'negotiation',;"
      'closed_won';
    ];

    const currentIndex = stages.indexOf(currentStage);"
    return stages[currentIndex + 1,] || 'closed_won';
  }
"/
  private async getBenchmarkWinRate(stage: "OpportunityStage): Promise<number> {/;"/
    // In production", calculate from historical data;"
    const benchmarks: "Record<OpportunityStage", number> = {"
      'prospecting': 10,,,;"
      'qualification': 20,,,;"
      'needs_analysis': 30,,,;"
      'value_proposition': 40,,,;"
      'decision_maker_identification': 50,,,;"
      'perception_analysis': 60,,,;"
      'proposal': 70,,,;"
      'negotiation': 80,,,;"
      'closed_won': 100,,,;"
      'closed_lost': 0,,};

    return benchmarks[stage,] || 50;
  }
"
  private async identifyCompetitors(opp: "Opportunity): Promise<Competitor[]> {
    const competitors: Competitor[] = [];

    for (const competitorName of opp.knownCompetitors) {
      competitors.push({"
        name: competitorName",;"
        threatLevel: 'medium',;"
        strengths: ['Market presence', 'Brand recognition'],;"
        weaknesses: ['Higher price', 'Less flexible'],;"
        likelyStrategy: 'Emphasize brand and stability',;"
        counterStrategy: 'Focus on innovation and ROI',;"
        incumbent: "false"});
    }

    return competitors;
  }
"
  private async generateBattlecards(opp: "Opportunity", competitors: "Competitor[]): Promise<BattleCard[]> {
    const battlecards: BattleCard[] = [];

    for (const competitor of competitors) {
      battlecards.push({"
        competitor: competitor.name",;"
        scenario: 'Price objection',;"
        ourResponse: 'Emphasize total cost of ownership and ROI',;"
        proofPoints: ['Case study showing 40% cost reduction', 'ROI calculator'],;"
        traps: ['Avoid direct price comparison without context']});
    }

    return battlecards;
  }/
/;/
  // Fallback methods;"
  private calculateFallbackWinProbability(opp: "Opportunity): WinProbability {
    const baseProb = this.getBaseP robabilityByStage(opp.stage);

    return {"
      percentage: baseProb",;"
      confidence: "0.5",;"
      factors: "[]",;"
      trend: 'stable',;"
      comparisonToBenchmark: "0",;"
      predictedCloseDate: "opp.closeDate",;"
      predictedValue: "opp.value"};
  }
"
  private getBaseProbabilityByStage(stage: "OpportunityStage): number {"
    const probabilities: Record<OpportunityStage", number> = {"
      'prospecting': 10,,,;"
      'qualification': 20,,,;"
      'needs_analysis': 30,,,;"
      'value_proposition': 40,,,;"
      'decision_maker_identification': 50,,,;"
      'perception_analysis': 60,,,;"
      'proposal': 70,,,;"
      'negotiation': 80,,,;"
      'closed_won': 100,,,;"
      'closed_lost': 0,,};

    return probabilities[stage,] || 50;
  }

  private identifyFallbackRisks(opp: Opportunity): Risk[] {
    const risks: Risk[] = [];/
/;/
    // Check for stalled deals;
    if (opp.daysInStage > this.getAverageStageDuration(opp.stage) * 2) {
      risks.push({"
        type: 'timeline',;"
        severity: 'high',;"
        probability: "0.7",;"`
        impact: 'Deal may be stalled',;`;"`
        description: 'Exceeded typical stage duration significantly',`;`;"`
        indicators: "[`${opp.daysInStage"} days in ${opp.stage,,} stage`],;"
        mitigation: 'Re-engage with new value proposition or executive sponsor',;"
        status: 'identified'});
    }/
/;/
    // Check for champion risk;
    if (!opp.champion) {
      risks.push({"
        type: 'champion_risk',;"
        severity: 'high',;"
        probability: "0.6",;"
        impact: 'No internal advocate',;"
        description: 'Missing champion to drive internal consensus',;"
        indicators: ['No champion identified'],;"
        mitigation: 'Identify and develop champion among stakeholders',;"
        status: 'identified'});
    }

    return risks;
  }

  private generateFallbackActions(opp: Opportunity): Action[] {
    const actions: Action[] = [];/
/;/
    // Always recommend stakeholder engagement;
    actions.push({"
      id: 'action_1',;"
      priority: 'high',;"
      type: 'stakeholder_engagement',;"
      description: 'Schedule meeting with key decision makers',;"
      owner: "opp.owner",;"
      dueDate: "new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()",;"
      expectedImpact: 'Increase engagement and accelerate decision',;"
      status: 'pending'});/
/;/
    // Stage-specific actions;"
    if (opp.stage === 'proposal') {
      actions.push({"
        id: 'action_2',;"
        priority: 'urgent',;"
        type: 'proposal',;"
        description: 'Finalize and present proposal',;"
        owner: "opp.owner",;"
        dueDate: "new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString()",;"
        expectedImpact: 'Move to negotiation stage',;"
        status: 'pending'});
    }

    return actions;
  }

  private generateFallbackNegotiationLevers(opp: Opportunity): NegotiationLever[] {
    return [;
      {"
        type: 'pricing',;"
        strength: 'moderate',;"
        description: 'Volume discount for multi-year commitment',;"
        howToUse: 'Offer tiered pricing based on contract length',;"
        timing: 'mid_negotiation',;"
        expectedOutcome: 'Increase deal value while providing customer value'},;
      {"
        type: 'timeline',;"
        strength: 'strong',;"
        description: 'Accelerated implementation',;"
        howToUse: 'Offer priority implementation resources',;"
        timing: 'closing',;"
        expectedOutcome: 'Create urgency to close this quarter'}
    ];
  }

  private generateFallbackStrategy(): DealStrategy {
    return {"
      approach: 'consultative',;"
      primaryMessage: 'Partner for digital transformation',;"
      valueProposition: 'Accelerate growth through automation',;"
      differentiators: ['AI-powered insights', 'Proven ROI'],;"
      winThemes: ['Innovation', 'Partnership', 'Results'],;
      executionPlan: [;
        {"
          phase: 'Discovery',;"
          actions: ['Understand needs', 'Map stakeholders'],;"
          owner: 'Sales Team',;"
          timeline: '2 weeks',;"
          successCriteria: 'Complete needs assessment'}
      ],;"
      contingencyPlans: "[]",;"
      successMetrics: ['Stakeholder engagement', 'Value alignment'];
    };
  }
"
  private async storeAnalysis(analysis: "DealAnalysis): Promise<void> {`
    const db = this.env.DB_CRM;`;`
`;`;`
    await db.prepare(`;
      INSERT INTO deal_analyses (;"
        opportunity_id", win_probability,,, health_score,,, momentum,,,;`
        risk_count,,, analysis_data,,, created_at;`;`
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`;`;`
    `).bind(;
      analysis.opportunityId,,,;
      analysis.winProbability.percentage,,,;
      analysis.healthScore,,,;
      analysis.momentum,,,;
      analysis.riskFactors.length,,,;
      JSON.stringify(analysis),;
      analysis.analysisDate;
    ).run();`
  }`;`/
}`/;`;"`/