import type { Env } from '../types/env';
import { DealIntelligenceService, type Opportunity } from './deal-intelligence';
import { PredictiveScoring } from './predictive-scoring';

export interface Forecast {
  period: ForecastPeriod;
  startDate: string;
  endDate: string;
  scenarios: {
    conservative: ScenarioForecast;
    likely: ScenarioForecast;
    optimistic: ScenarioForecast;
  };
  pipeline: PipelineAnalysis;
  assumptions: Assumption[];
  riskFactors: ForecastRisk[];
  recommendations: ForecastRecommendation[];
  confidence: ConfidenceAnalysis;
  visualization: ForecastVisualization;
  generatedAt: string;
}

export interface ForecastPeriod {
  type: 'month' | 'quarter' | 'year';
  name: string;
  number: number;
  year: number;
}

export interface ScenarioForecast {
  revenue: number;
  deals: number;
  averageDealSize: number;
  conversionRate: number;
  probability: number;
  breakdown: RevenueBreakdown;
  keyDrivers: string[];
  assumptions: string[];
}

export interface RevenueBreakdown {
  newBusiness: number;
  expansion: number;
  renewal: number;
  byStage: Record<string, number>;
  bySegment: Record<string, number>;
  byProduct: Record<string, number>;
  byRep: Record<string, number>;
  byRegion: Record<string, number>;
}

export interface PipelineAnalysis {
  totalValue: number;
  qualifiedValue: number;
  weightedValue: number;
  dealCount: number;
  averageDealSize: number;
  averageAge: number;
  velocity: PipelineVelocity;
  coverage: number; // Pipeline coverage ratio
  health: PipelineHealth;
  stages: StageAnalysis[];
  trends: PipelineTrend[];
}

export interface PipelineVelocity {
  averageCycleLength: number;
  stageConversion: Record<string, number>;
  velocityTrend: 'accelerating' | 'steady' | 'slowing';
  bottlenecks: Bottleneck[];
}

export interface Bottleneck {
  stage: string;
  averageDays: number;
  benchmark: number;
  impact: 'low' | 'medium' | 'high';
  recommendation: string;
}

export interface PipelineHealth {
  score: number; // 0-100
  indicators: HealthIndicator[];
  strengths: string[];
  weaknesses: string[];
  trend: 'improving' | 'stable' | 'declining';
}

export interface HealthIndicator {
  name: string;
  value: number;
  benchmark: number;
  status: 'good' | 'warning' | 'critical';
  description: string;
}

export interface StageAnalysis {
  stage: string;
  dealCount: number;
  totalValue: number;
  weightedValue: number;
  conversionRate: number;
  averageAge: number;
  velocity: number;
  forecast: number;
}

export interface PipelineTrend {
  metric: string;
  current: number;
  previous: number;
  change: number;
  changePercent: number;
  trend: 'up' | 'down' | 'flat';
}

export interface Assumption {
  category: 'conversion' | 'timing' | 'market' | 'execution' | 'external';
  description: string;
  confidence: number; // 0-1
  impact: 'low' | 'medium' | 'high';
  sensitivity: number; // How sensitive forecast is to this assumption
}

export interface ForecastRisk {
  type: string;
  description: string;
  probability: number;
  impact: number; // Revenue impact in dollars
  mitigation: string;
  owner?: string;
  timeline?: string;
}

export interface ForecastRecommendation {
  priority: 'critical' | 'high' | 'medium' | 'low';
  category: 'pipeline' | 'execution' | 'process' | 'resource' | 'strategy';
  action: string;
  impact: string;
  effort: 'low' | 'medium' | 'high';
  timeline: string;
  expectedOutcome: number; // Revenue impact
}

export interface ConfidenceAnalysis {
  overall: number; // 0-100
  byScenario: {
    conservative: number;
    likely: number;
    optimistic: number;
  };
  factors: ConfidenceFactor[];
  historicalAccuracy: number;
}

export interface ConfidenceFactor {
  name: string;
  impact: 'positive' | 'negative';
  weight: number;
  description: string;
}

export interface ForecastVisualization {
  waterfall: WaterfallChart;
  timeline: TimelineChart;
  funnel: FunnelChart;
  heatmap: HeatmapData;
  trends: TrendChart[];
}

export interface WaterfallChart {
  startingPoint: number;
  steps: WaterfallStep[];
  endingPoint: number;
}

export interface WaterfallStep {
  name: string;
  value: number;
  type: 'increase' | 'decrease';
  cumulative: number;
}

export interface TimelineChart {
  periods: TimePeriod[];
  milestones: ForecastMilestone[];
}

export interface TimePeriod {
  name: string;
  start: string;
  end: string;
  forecast: number;
  actual?: number;
}

export interface ForecastMilestone {
  date: string;
  event: string;
  impact: number;
}

export interface FunnelChart {
  stages: FunnelStage[];
  conversionRates: number[];
}

export interface FunnelStage {
  name: string;
  count: number;
  value: number;
  percentage: number;
}

export interface HeatmapData {
  dimensions: string[];
  data: HeatmapCell[];
}

export interface HeatmapCell {
  x: string;
  y: string;
  value: number;
  label: string;
}

export interface TrendChart {
  name: string;
  data: DataPoint[];
  forecast: DataPoint[];
}

export interface DataPoint {
  date: string;
  value: number;
  label?: string;
}

export interface HistoricalConversion {
  overall: number;
  byStage: Record<string, number>;
  bySegment: Record<string, number>;
  bySource: Record<string, number>;
  byRep: Record<string, number>;
  trend: 'improving' | 'stable' | 'declining';
  seasonalFactors: SeasonalFactor[];
}

export interface SeasonalFactor {
  period: string;
  factor: number; // Multiplier (1.0 = normal)
  description: string;
}

export interface MarketConditions {
  economicIndicators: EconomicIndicator[];
  competitiveLandscape: CompetitiveFactors;
  industryTrends: string[];
  externalRisks: string[];
  opportunities: string[];
}

export interface EconomicIndicator {
  name: string;
  value: number;
  trend: 'positive' | 'neutral' | 'negative';
  impact: string;
}

export interface CompetitiveFactors {
  marketShare: number;
  competitorActivity: string[];
  pricingPressure: 'low' | 'medium' | 'high';
  differentiation: number; // 0-100
}

export class RevenueForecast {
  private env: Env;
  private dealIntelligence: DealIntelligenceService;
  private predictiveScoring: PredictiveScoring;
  private forecastCache: Map<string, Forecast>;

  constructor(env: Env) {
    this.env = env;
    this.dealIntelligence = new DealIntelligenceService(env);
    this.predictiveScoring = new PredictiveScoring(env);
    this.forecastCache = new Map();
  }

  async generateForecast(
    period: 'month' | 'quarter' | 'year',
    targetRevenue?: number
  ): Promise<Forecast> {
    // Get time period details
    const periodDetails = this.getPeriodDetails(period);

    // Check cache
    const cacheKey = `${period}_${periodDetails.startDate}`;
    const cached = this.forecastCache.get(cacheKey);
    if (cached && new Date().getTime() - new Date(cached.generatedAt).getTime() < 3600000) {
      return cached; // Return if less than 1 hour old
    }

    // Gather all data
    const [pipeline, historicalRates, marketConditions] = await Promise.all([
      this.getPipelineData(periodDetails),
      this.getHistoricalConversion(period),
      this.getMarketConditions()
    ]);

    // Generate AI-powered forecast
    const scenarios = await this.generateScenarios(
      pipeline,
      historicalRates,
      marketConditions,
      periodDetails
    );

    // Identify assumptions
    const assumptions = await this.identifyAssumptions(
      pipeline,
      historicalRates,
      marketConditions
    );

    // Assess risks
    const riskFactors = await this.assessRisks(
      pipeline,
      scenarios,
      marketConditions
    );

    // Generate recommendations
    const recommendations = await this.generateRecommendations(
      pipeline,
      scenarios,
      targetRevenue,
      riskFactors
    );

    // Calculate confidence
    const confidence = this.calculateConfidence(
      pipeline,
      historicalRates,
      assumptions
    );

    // Create visualization data
    const visualization = this.createVisualization(
      pipeline,
      scenarios,
      periodDetails
    );

    const forecast: Forecast = {
      period: periodDetails,
      startDate: periodDetails.startDate,
      endDate: periodDetails.endDate,
      scenarios,
      pipeline,
      assumptions,
      riskFactors,
      recommendations,
      confidence,
      visualization,
      generatedAt: new Date().toISOString()
    };

    // Cache the forecast
    this.forecastCache.set(cacheKey, forecast);

    // Store for tracking
    await this.storeForecast(forecast);

    return forecast;
  }

  private getPeriodDetails(period: 'month' | 'quarter' | 'year'):
  ForecastPeriod & { startDate: string; endDate: string } {
    const now = new Date();
    let startDate: Date;
    let endDate: Date;
    let name: string;
    let number: number;

    switch (period) {
      case 'month':
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        name = now.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
        number = now.getMonth() + 1;
        break;

      case 'quarter':
        const quarter = Math.floor(now.getMonth() / 3);
        startDate = new Date(now.getFullYear(), quarter * 3, 1);
        endDate = new Date(now.getFullYear(), (quarter + 1) * 3, 0);
        name = `Q${quarter + 1} ${now.getFullYear()}`;
        number = quarter + 1;
        break;

      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        endDate = new Date(now.getFullYear(), 11, 31);
        name = now.getFullYear().toString();
        number = now.getFullYear();
        break;
    }

    return {
      type: period,
      name,
      number,
      year: now.getFullYear(),
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString()
    };
  }

  private async getPipelineData(period: any): Promise<PipelineAnalysis> {
    const db = this.env.DB_CRM;

    // Get all opportunities in pipeline
    const opportunities = await db.prepare(`
      SELECT * FROM opportunities
      WHERE status = 'open'
        AND close_date BETWEEN ? AND ?
      ORDER BY value DESC
    `).bind(period.startDate, period.endDate).all();

    // Calculate pipeline metrics
    const deals = opportunities.results as unknown as Opportunity[];
    const totalValue = deals.reduce((sum, d) => sum + d.value, 0);
    const qualifiedValue = deals
      .filter((d: any) => d.stage !== 'prospecting' && d.stage !== 'qualification')
      .reduce((sum, d) => sum + d.value, 0);

    // Calculate weighted value based on stage probability
    const weightedValue = deals.reduce((sum, d) => {
      const probability = this.getStageProbability(d.stage);
      return sum + (d.value * probability);
    }, 0);

    // Analyze velocity
    const velocity = await this.analyzeVelocity(deals);

    // Analyze pipeline health
    const health = await this.analyzePipelineHealth(deals, velocity);

    // Analyze by stage
    const stages = await this.analyzeByStage(deals);

    // Analyze trends
    const trends = await this.analyzeTrends(deals);

    return {
      totalValue,
      qualifiedValue,
      weightedValue,
      dealCount: deals.length,
      averageDealSize: deals.length > 0 ? totalValue / deals.length : 0,
      averageAge: this.calculateAverageAge(deals),
      velocity,
      coverage: totalValue / (period.target || totalValue * 0.3), // Pipeline coverage ratio
      health,
      stages,
      trends
    };
  }

  private async getHistoricalConversion(period: 'month' | 'quarter' | 'year'): Promise<HistoricalConversion> {
    const db = this.env.DB_CRM;

    // Get historical conversion data
    const historicalDeals = await db.prepare(`
      SELECT
        stage,
        COUNT(*) as total,
        COUNT(CASE WHEN status = 'closed_won' THEN 1 END) as won,
        AVG(value) as avg_value
      FROM opportunities
      WHERE close_date >= datetime('now', '-1 year')
      GROUP BY stage
    `).all();

    // Calculate conversion rates
    const byStage: Record<string, number> = {};
    for (const stage of historicalDeals.results) {
      byStage[stage.stage as string] = (stage.won as number) / (stage.total as number);
    }

    // Get overall conversion
    const overallResult = await db.prepare(`
      SELECT
        COUNT(*) as total,
        COUNT(CASE WHEN status = 'closed_won' THEN 1 END) as won
      FROM opportunities
      WHERE close_date >= datetime('now', '-1 year')
    `).first();

    const overall = (overallResult?.won as number || 0) / (overallResult?.total as number || 1);

    // Determine trend
    const recentConversion = await this.getRecentConversion();
    const trend = recentConversion > overall * 1.05 ? 'improving' :
                  recentConversion < overall * 0.95 ? 'declining' : 'stable';

    // Seasonal factors
    const seasonalFactors = this.getSeasonalFactors(period);

    return {
      overall,
      byStage,
      bySegment: await this.getConversionBySegment(),
      bySource: await this.getConversionBySource(),
      byRep: await this.getConversionByRep(),
      trend,
      seasonalFactors
    };
  }

  private async getMarketConditions(): Promise<MarketConditions> {
    // In production, this would integrate with external data sources
    return {
      economicIndicators: [
        {
          name: 'GDP Growth',
          value: 2.5,
          trend: 'positive',
          impact: 'Increased business investment'
        },
        {
          name: 'Interest Rates',
          value: 5.5,
          trend: 'neutral',
          impact: 'Stable financing costs'
        }
      ],
      competitiveLandscape: {
        marketShare: 15,
        competitorActivity: ['New competitor entered market', 'Price war in low-end segment'],
        pricingPressure: 'medium',
        differentiation: 75
      },
      industryTrends: [
        'AI adoption accelerating',
        'Digital transformation priority',
        'Remote work normalization'
      ],
      externalRisks: [
        'Economic uncertainty',
        'Supply chain disruptions'
      ],
      opportunities: [
        'New market segments opening',
        'Partnership opportunities'
      ]
    };
  }

  private async generateScenarios(
    pipeline: PipelineAnalysis,
    historicalRates: HistoricalConversion,
    marketConditions: MarketConditions,
    period: any
  ): Promise<{ conservative: ScenarioForecast; likely: ScenarioForecast; optimistic: ScenarioForecast }> {
    const prompt = `
      Generate revenue forecast scenarios based on this data:

      Pipeline Analysis:
      - Total Pipeline Value: $${pipeline.totalValue.toLocaleString()}
      - Weighted Pipeline: $${pipeline.weightedValue.toLocaleString()}
      - Deal Count: ${pipeline.dealCount}
      - Average Deal Size: $${pipeline.averageDealSize.toLocaleString()}
      - Pipeline Coverage: ${pipeline.coverage.toFixed(2)}x

      Historical Conversion:
      - Overall Rate: ${(historicalRates.overall * 100).toFixed(1)}%
      - Trend: ${historicalRates.trend}
      - Seasonal Factor: ${this.getCurrentSeasonalFactor(historicalRates.seasonalFactors)}

      Market Conditions:
      - Economic Growth: ${marketConditions.economicIndicators[0]?.value}%
      - Competition: ${marketConditions.competitiveLandscape.pricingPressure} pricing pressure
      - Market Share: ${marketConditions.competitiveLandscape.marketShare}%

      Period: ${period.type} (${period.name})

      Generate three scenarios:

      1. CONSERVATIVE (25% probability):
      - Lower conversion rates (historical - 20%)
      - Longer sales cycles
      - Deal slippage
      - Some deal losses to competition

      2. LIKELY (50% probability):
      - Historical conversion rates
      - Normal sales cycles
      - Expected close dates
      - Maintain win rate

      3. OPTIMISTIC (25% probability):
      - Higher conversion (historical + 20%)
      - Accelerated deals
      - Upside from new opportunities
      - Competitive wins

      For each scenario provide:
      - Total revenue forecast
      - Number of deals expected to close
      - Average deal size
      - Conversion rate used
      - Key drivers and assumptions

      Return as JSON:
      {
        "conservative": {
          "revenue": number,
          "deals": number,
          "averageDealSize": number,
          "conversionRate": number,
          "probability": 0.25,
          "keyDrivers": ["driver1", "driver2"],
          "assumptions": ["assumption1", "assumption2"]
        },
        "likely": { ... },
        "optimistic": { ... }
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
          max_tokens: 2000,
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
        const scenarios = JSON.parse(jsonMatch[0]);

        // Add breakdown for each scenario
        for (const scenario of Object.values(scenarios) as ScenarioForecast[]) {
          scenario.breakdown = await this.generateBreakdown(scenario, pipeline);
        }

        return scenarios;
      }
    } catch (error: any) {
    }

    // Fallback calculation
    return this.calculateFallbackScenarios(pipeline, historicalRates);
  }

  private async generateBreakdown(
    scenario: ScenarioForecast,
    pipeline: PipelineAnalysis
  ): Promise<RevenueBreakdown> {
    // Estimate breakdown based on pipeline composition
    const newBusinessRatio = 0.7;
    const expansionRatio = 0.2;
    const renewalRatio = 0.1;

    return {
      newBusiness: scenario.revenue * newBusinessRatio,
      expansion: scenario.revenue * expansionRatio,
      renewal: scenario.revenue * renewalRatio,
      byStage: this.calculateStageBreakdown(scenario, pipeline),
      bySegment: {},
      byProduct: {},
      byRep: {},
      byRegion: {}
    };
  }

  private calculateStageBreakdown(
    scenario: ScenarioForecast,
    pipeline: PipelineAnalysis
  ): Record<string, number> {
    const breakdown: Record<string, number> = {};

    for (const stage of pipeline.stages) {
      breakdown[stage.stage] = stage.weightedValue * scenario.conversionRate;
    }

    return breakdown;
  }

  private async identifyAssumptions(
    pipeline: PipelineAnalysis,
    historicalRates: HistoricalConversion,
    marketConditions: MarketConditions
  ): Promise<Assumption[]> {
    const assumptions: Assumption[] = [];

    // Conversion assumptions
    assumptions.push({
      category: 'conversion',
      description: `Conversion rates remain consistent with ${historicalRates.trend} trend`,
      confidence: 0.7,
      impact: 'high',
      sensitivity: 0.8
    });

    // Timing assumptions
    assumptions.push({
      category: 'timing',
      description: 'Deals close within expected timeframe',
      confidence: 0.6,
      impact: 'medium',
      sensitivity: 0.5
    });

    // Market assumptions
    if (marketConditions.economicIndicators[0]?.trend === 'positive') {
      assumptions.push({
        category: 'market',
        description: 'Economic growth continues supporting demand',
        confidence: 0.5,
        impact: 'medium',
        sensitivity: 0.6
      });
    }

    // Execution assumptions
    assumptions.push({
      category: 'execution',
      description: 'Sales team maintains current productivity',
      confidence: 0.8,
      impact: 'high',
      sensitivity: 0.7
    });

    // External assumptions
    assumptions.push({
      category: 'external',
      description: 'No major competitive disruptions',
      confidence: 0.6,
      impact: 'medium',
      sensitivity: 0.4
    });

    return assumptions;
  }

  private async assessRisks(
    pipeline: PipelineAnalysis,
    scenarios: any,
    marketConditions: MarketConditions
  ): Promise<ForecastRisk[]> {
    const risks: ForecastRisk[] = [];

    // Pipeline coverage risk
    if (pipeline.coverage < 3) {
      risks.push({
        type: 'Pipeline Coverage',
        description: 'Insufficient pipeline to meet forecast',
        probability: 0.6,
        impact: (scenarios.likely.revenue - scenarios.conservative.revenue) * 0.3,
        mitigation: 'Accelerate lead generation and qualification'
      });
    }

    // Conversion risk
    if (pipeline.health.trend === 'declining') {
      risks.push({
        type: 'Conversion Decline',
        description: 'Declining conversion rates may impact forecast',
        probability: 0.5,
        impact: scenarios.likely.revenue * 0.15,
        mitigation: 'Implement sales enablement and training'
      });
    }

    // Competition risk
    if (marketConditions.competitiveLandscape.pricingPressure === 'high') {
      risks.push({
        type: 'Competitive Pressure',
        description: 'Increased competition may reduce win rates',
        probability: 0.4,
        impact: scenarios.likely.revenue * 0.1,
        mitigation: 'Enhance value proposition and differentiation'
      });
    }

    // Timing risk
    if (pipeline.velocity.velocityTrend === 'slowing') {
      risks.push({
        type: 'Deal Slippage',
        description: 'Slowing velocity may push deals to next period',
        probability: 0.5,
        impact: scenarios.likely.revenue * 0.2,
        mitigation: 'Focus on deal acceleration tactics'
      });
    }

    // Large deal dependency
    const largeDeals = pipeline.stages
      .flatMap(s => [s])
      .filter((s: any) => s.totalValue > pipeline.averageDealSize * 3);

    if (largeDeals.length > 0) {
      risks.push({
        type: 'Large Deal Dependency',
        description: 'Forecast dependent on few large deals',
        probability: 0.3,
        impact: largeDeals.reduce((sum, d) => sum + d.totalValue, 0) * 0.5,
        mitigation: 'Increase deal count and diversification'
      });
    }

    return risks;
  }

  private async generateRecommendations(
    pipeline: PipelineAnalysis,
    scenarios: any,
    targetRevenue: number | undefined,
    risks: ForecastRisk[]
  ): Promise<ForecastRecommendation[]> {
    const recommendations: ForecastRecommendation[] = [];
    const gap = targetRevenue ? targetRevenue - scenarios.likely.revenue : 0;

    // Pipeline recommendations
    if (pipeline.coverage < 3) {
      recommendations.push({
        priority: 'critical',
        category: 'pipeline',
        action: 'Increase pipeline generation by 50%',
        impact: 'Add $' + (pipeline.totalValue * 0.5).toLocaleString() + ' to pipeline',
        effort: 'high',
        timeline: '30 days',
        expectedOutcome: scenarios.likely.revenue * 0.2
      });
    }

    // Execution recommendations
    if (pipeline.velocity.bottlenecks.length > 0) {
      const bottleneck = pipeline.velocity.bottlenecks[0];
      recommendations.push({
        priority: 'high',
        category: 'execution',
        action: `Address ${bottleneck.stage} bottleneck`,
        impact: `Reduce cycle time by ${bottleneck.averageDays - bottleneck.benchmark} days`,
        effort: 'medium',
        timeline: '14 days',
        expectedOutcome: scenarios.likely.revenue * 0.1
      });
    }

    // Process recommendations
    if (pipeline.health.score < 70) {
      recommendations.push({
        priority: 'high',
        category: 'process',
        action: 'Implement deal review cadence',
        impact: 'Improve forecast accuracy and deal progression',
        effort: 'low',
        timeline: '7 days',
        expectedOutcome: scenarios.likely.revenue * 0.05
      });
    }

    // Resource recommendations
    if (gap > scenarios.likely.revenue * 0.2) {
      recommendations.push({
        priority: 'critical',
        category: 'resource',
        action: 'Add sales capacity or accelerate hiring',
        impact: 'Increase deal capacity by 30%',
        effort: 'high',
        timeline: '60 days',
        expectedOutcome: gap * 0.4
      });
    }

    // Strategy recommendations
    for (const risk of risks.slice(0, 2)) {
      recommendations.push({
        priority: 'medium',
        category: 'strategy',
        action: risk.mitigation,
        impact: `Mitigate $${risk.impact.toLocaleString()} risk`,
        effort: 'medium',
        timeline: '30 days',
        expectedOutcome: risk.impact * (1 - risk.probability)
      });
    }

    return recommendations;
  }

  private calculateConfidence(
    pipeline: PipelineAnalysis,
    historicalRates: HistoricalConversion,
    assumptions: Assumption[]
  ): ConfidenceAnalysis {
    const factors: ConfidenceFactor[] = [];

    // Pipeline health factor
    if (pipeline.health.score > 70) {
      factors.push({
        name: 'Strong Pipeline Health',
        impact: 'positive',
        weight: 0.25,
        description: `Pipeline health score of ${pipeline.health.score}`
      });
    } else {
      factors.push({
        name: 'Weak Pipeline Health',
        impact: 'negative',
        weight: 0.25,
        description: `Pipeline health score of ${pipeline.health.score}`
      });
    }

    // Coverage factor
    if (pipeline.coverage >= 3) {
      factors.push({
        name: 'Good Pipeline Coverage',
        impact: 'positive',
        weight: 0.20,
        description: `${pipeline.coverage.toFixed(1)}x coverage ratio`
      });
    } else {
      factors.push({
        name: 'Insufficient Pipeline Coverage',
        impact: 'negative',
        weight: 0.20,
        description: `Only ${pipeline.coverage.toFixed(1)}x coverage`
      });
    }

    // Historical accuracy
    const historicalAccuracy = 0.75; // Would calculate from actual vs forecast
    if (historicalAccuracy > 0.8) {
      factors.push({
        name: 'High Historical Accuracy',
        impact: 'positive',
        weight: 0.30,
        description: `${(historicalAccuracy * 100).toFixed(0)}% historical forecast accuracy`
      });
    }

    // Calculate overall confidence
    const positiveFactors = factors.filter((f: any) => f.impact === 'positive');
    const negativeFactors = factors.filter((f: any) => f.impact === 'negative');

    const positiveWeight = positiveFactors.reduce((sum, f) => sum + f.weight, 0);
    const negativeWeight = negativeFactors.reduce((sum, f) => sum + f.weight, 0);

    const overall = Math.max(0, Math.min(100,
      50 + (positiveWeight * 50) - (negativeWeight * 50)
    ));

    return {
      overall,
      byScenario: {
        conservative: 85,
        likely: overall,
        optimistic: 40
      },
      factors,
      historicalAccuracy
    };
  }

  private createVisualization(
    pipeline: PipelineAnalysis,
    scenarios: any,
    period: any
  ): ForecastVisualization {
    return {
      waterfall: this.createWaterfall(pipeline, scenarios.likely),
      timeline: this.createTimeline(period, scenarios),
      funnel: this.createFunnel(pipeline),
      heatmap: this.createHeatmap(pipeline),
      trends: this.createTrends(pipeline)
    };
  }

  private createWaterfall(pipeline: PipelineAnalysis, scenario: ScenarioForecast): WaterfallChart {
    const steps: WaterfallStep[] = [];
    let cumulative = 0;

    // Starting pipeline
    steps.push({
      name: 'Starting Pipeline',
      value: pipeline.totalValue,
      type: 'increase',
      cumulative: pipeline.totalValue
    });
    cumulative = pipeline.totalValue;

    // Conversion
    const converted = pipeline.totalValue * scenario.conversionRate;
    const lost = pipeline.totalValue - converted;

    steps.push({
      name: 'Lost Deals',
      value: -lost,
      type: 'decrease',
      cumulative: cumulative - lost
    });
    cumulative -= lost;

    // New pipeline
    const newPipeline = scenario.revenue - converted;
    if (newPipeline > 0) {
      steps.push({
        name: 'New Opportunities',
        value: newPipeline,
        type: 'increase',
        cumulative: cumulative + newPipeline
      });
      cumulative += newPipeline;
    }

    return {
      startingPoint: 0,
      steps,
      endingPoint: scenario.revenue
    };
  }

  private createTimeline(period: any, scenarios: any): TimelineChart {
    const periods: TimePeriod[] = [];
    const milestones: ForecastMilestone[] = [];

    // Create monthly periods for the forecast period
    const start = new Date(period.startDate);
    const end = new Date(period.endDate);

    let current = new Date(start);
    while (current <= end) {
      const monthEnd = new Date(current.getFullYear(), current.getMonth() + 1, 0);
      periods.push({
        name: current.toLocaleDateString('en-US', { month: 'short' }),
        start: current.toISOString(),
        end: monthEnd.toISOString(),
        forecast: scenarios.likely.revenue / periods.length // Distribute evenly for now
      });

      current = new Date(current.getFullYear(), current.getMonth() + 1, 1);
    }

    return { periods, milestones };
  }

  private createFunnel(pipeline: PipelineAnalysis): FunnelChart {
    const stages: FunnelStage[] = [];
    let remainingCount = pipeline.dealCount;
    let remainingValue = pipeline.totalValue;

    for (const stage of pipeline.stages) {
      stages.push({
        name: stage.stage,
        count: stage.dealCount,
        value: stage.totalValue,
        percentage: (stage.dealCount / pipeline.dealCount) * 100
      });
    }

    const conversionRates = stages.map((s, i) => {
      if (i === 0) return 100;
      return (s.count / stages[i - 1].count) * 100;
    });

    return { stages, conversionRates };
  }

  private createHeatmap(pipeline: PipelineAnalysis): HeatmapData {
    const data: HeatmapCell[] = [];

    // Create heatmap of stage vs time
    const stages = ['Prospecting', 'Qualification', 'Proposal', 'Negotiation'];
    const months = ['Month 1', 'Month 2', 'Month 3'];

    for (const stage of stages) {
      for (const month of months) {
        data.push({
          x: month,
          y: stage,
          value: Math.random() * 100, // Would use actual data
          label: `${stage} - ${month}`
        });
      }
    }

    return {
      dimensions: ['Time', 'Stage'],
      data
    };
  }

  private createTrends(pipeline: PipelineAnalysis): TrendChart[] {
    return [
      {
        name: 'Pipeline Value',
        data: this.generateHistoricalTrend('pipeline', 12),
        forecast: this.generateForecastTrend('pipeline', 3)
      },
      {
        name: 'Win Rate',
        data: this.generateHistoricalTrend('winrate', 12),
        forecast: this.generateForecastTrend('winrate', 3)
      },
      {
        name: 'Average Deal Size',
        data: this.generateHistoricalTrend('dealsize', 12),
        forecast: this.generateForecastTrend('dealsize', 3)
      }
    ];
  }

  private generateHistoricalTrend(metric: string, months: number): DataPoint[] {
    const data: DataPoint[] = [];
    const now = new Date();

    for (let i = months; i > 0; i--) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
      data.push({
        date: date.toISOString(),
        value: Math.random() * 1000000 // Would use actual historical data
      });
    }

    return data;
  }

  private generateForecastTrend(metric: string, months: number): DataPoint[] {
    const data: DataPoint[] = [];
    const now = new Date();

    for (let i = 1; i <= months; i++) {
      const date = new Date(now.getFullYear(), now.getMonth() + i, 1);
      data.push({
        date: date.toISOString(),
        value: Math.random() * 1000000 // Would use forecast data
      });
    }

    return data;
  }

  // Helper methods
  private getStageProbability(stage: string): number {
    const probabilities: Record<string, number> = {
      'prospecting': 0.1,
      'qualification': 0.2,
      'needs_analysis': 0.3,
      'value_proposition': 0.4,
      'decision_maker_identification': 0.5,
      'perception_analysis': 0.6,
      'proposal': 0.7,
      'negotiation': 0.8,
      'closed_won': 1.0,
      'closed_lost': 0
    };

    return probabilities[stage] || 0.5;
  }

  private calculateAverageAge(deals: Opportunity[]): number {
    if (deals.length === 0) return 0;

    const totalAge = deals.reduce((sum, d) => sum + d.totalAge, 0);
    return totalAge / deals.length;
  }

  private async analyzeVelocity(deals: Opportunity[]): Promise<PipelineVelocity> {
    const stageConversion: Record<string, number> = {};
    const bottlenecks: Bottleneck[] = [];

    // Analyze each stage
    const stages = ['prospecting', 'qualification', 'proposal', 'negotiation'];
    for (const stage of stages) {
      const stageDeals = deals.filter((d: any) => d.stage === stage);
      if (stageDeals.length > 0) {
        const avgDays = stageDeals.reduce((sum, d) => sum + d.daysInStage, 0) / stageDeals.length;
        const benchmark = this.getStageBenchmark(stage);

        if (avgDays > benchmark * 1.5) {
          bottlenecks.push({
            stage,
            averageDays: avgDays,
            benchmark,
            impact: 'high',
            recommendation: `Reduce ${stage} duration by ${Math.round(avgDays - benchmark)} days`
          });
        }

        stageConversion[stage] = 0.7; // Would calculate actual conversion
      }
    }

    // Determine velocity trend
    const avgCycleLength = this.calculateAverageAge(deals);
    const historicalCycle = 60; // Would get from historical data
    const velocityTrend = avgCycleLength < historicalCycle * 0.9 ? 'accelerating' :
                         avgCycleLength > historicalCycle * 1.1 ? 'slowing' : 'steady';

    return {
      averageCycleLength: avgCycleLength,
      stageConversion,
      velocityTrend,
      bottlenecks
    };
  }

  private getStageBenchmark(stage: string): number {
    const benchmarks: Record<string, number> = {
      'prospecting': 7,
      'qualification': 14,
      'proposal': 21,
      'negotiation': 14
    };

    return benchmarks[stage] || 14;
  }

  private async analyzePipelineHealth(
    deals: Opportunity[],
    velocity: PipelineVelocity
  ): Promise<PipelineHealth> {
    const indicators: HealthIndicator[] = [];
    const strengths: string[] = [];
    const weaknesses: string[] = [];

    // Deal count indicator
    const dealCountBenchmark = 50;
    indicators.push({
      name: 'Deal Count',
      value: deals.length,
      benchmark: dealCountBenchmark,
      status: deals.length >= dealCountBenchmark ? 'good' :
              deals.length >= dealCountBenchmark * 0.7 ? 'warning' : 'critical',
      description: `${deals.length} deals in pipeline`
    });

    if (deals.length >= dealCountBenchmark) {
      strengths.push('Strong deal volume');
    } else {
      weaknesses.push('Insufficient deal count');
    }

    // Velocity indicator
    indicators.push({
      name: 'Sales Velocity',
      value: velocity.averageCycleLength,
      benchmark: 60,
      status: velocity.velocityTrend === 'accelerating' ? 'good' :
              velocity.velocityTrend === 'steady' ? 'warning' : 'critical',
      description: `${velocity.velocityTrend} velocity trend`
    });

    // Calculate health score
    const goodIndicators = indicators.filter((i: any) => i.status === 'good').length;
    const score = (goodIndicators / indicators.length) * 100;

    return {
      score,
      indicators,
      strengths,
      weaknesses,
      trend: score > 70 ? 'improving' : score < 50 ? 'declining' : 'stable'
    };
  }

  private async analyzeByStage(deals: Opportunity[]): Promise<StageAnalysis[]> {
    const stages = ['prospecting', 'qualification', 'proposal', 'negotiation'];
    const analysis: StageAnalysis[] = [];

    for (const stage of stages) {
      const stageDeals = deals.filter((d: any) => d.stage === stage);
      const totalValue = stageDeals.reduce((sum, d) => sum + d.value, 0);
      const probability = this.getStageProbability(stage);
      const weightedValue = totalValue * probability;

      analysis.push({
        stage,
        dealCount: stageDeals.length,
        totalValue,
        weightedValue,
        conversionRate: probability,
        averageAge: this.calculateAverageAge(stageDeals),
        velocity: 1, // Would calculate actual velocity
        forecast: weightedValue * 0.7 // Apply historical conversion
      });
    }

    return analysis;
  }

  private async analyzeTrends(deals: Opportunity[]): Promise<PipelineTrend[]> {
    // Would compare with previous period
    return [
      {
        metric: 'Total Pipeline Value',
        current: deals.reduce((sum, d) => sum + d.value, 0),
        previous: 5000000, // Would get from historical data
        change: 500000,
        changePercent: 10,
        trend: 'up'
      },
      {
        metric: 'Average Deal Size',
        current: deals.length > 0 ? deals.reduce((sum, d) => sum + d.value, 0) / deals.length : 0,
        previous: 45000,
        change: 5000,
        changePercent: 11,
        trend: 'up'
      }
    ];
  }

  private async getRecentConversion(): Promise<number> {
    // Would calculate from recent data
    return 0.25;
  }

  private getSeasonalFactors(period: 'month' | 'quarter' | 'year'): SeasonalFactor[] {
    const month = new Date().getMonth();
    const factors: SeasonalFactor[] = [];

    // Q4 typically stronger
    if (month >= 9 && month <= 11) {
      factors.push({
        period: 'Q4',
        factor: 1.2,
        description: 'End of year budget flush'
      });
    }

    // Q1 typically slower
    if (month >= 0 && month <= 2) {
      factors.push({
        period: 'Q1',
        factor: 0.9,
        description: 'New budget cycles'
      });
    }

    return factors;
  }

  private getCurrentSeasonalFactor(factors: SeasonalFactor[]): number {
    if (factors.length === 0) return 1.0;
    return factors[0].factor;
  }

  private async getConversionBySegment(): Promise<Record<string, number>> {
    return {
      'Enterprise': 0.35,
      'Mid-Market': 0.28,
      'SMB': 0.22
    };
  }

  private async getConversionBySource(): Promise<Record<string, number>> {
    return {
      'Inbound': 0.32,
      'Outbound': 0.18,
      'Partner': 0.28,
      'Referral': 0.45
    };
  }

  private async getConversionByRep(): Promise<Record<string, number>> {
    return {
      'Rep A': 0.30,
      'Rep B': 0.25,
      'Rep C': 0.35
    };
  }

  private calculateFallbackScenarios(
    pipeline: PipelineAnalysis,
    historicalRates: HistoricalConversion
  ): any {
    const baseRevenue = pipeline.weightedValue;

    return {
      conservative: {
        revenue: baseRevenue * 0.7,
        deals: Math.floor(pipeline.dealCount * 0.6),
        averageDealSize: pipeline.averageDealSize * 0.9,
        conversionRate: historicalRates.overall * 0.8,
        probability: 0.25,
        breakdown: this.generateBreakdown(
          { revenue: baseRevenue * 0.7 } as any,
          pipeline
        ),
        keyDrivers: ['Lower conversion', 'Deal slippage'],
        assumptions: ['Market headwinds', 'Competition']
      },
      likely: {
        revenue: baseRevenue,
        deals: Math.floor(pipeline.dealCount * 0.75),
        averageDealSize: pipeline.averageDealSize,
        conversionRate: historicalRates.overall,
        probability: 0.50,
        breakdown: this.generateBreakdown(
          { revenue: baseRevenue } as any,
          pipeline
        ),
        keyDrivers: ['Historical conversion', 'Normal execution'],
        assumptions: ['Stable market', 'Team performance']
      },
      optimistic: {
        revenue: baseRevenue * 1.3,
        deals: Math.floor(pipeline.dealCount * 0.9),
        averageDealSize: pipeline.averageDealSize * 1.1,
        conversionRate: historicalRates.overall * 1.2,
        probability: 0.25,
        breakdown: this.generateBreakdown(
          { revenue: baseRevenue * 1.3 } as any,
          pipeline
        ),
        keyDrivers: ['Accelerated deals', 'Higher conversion'],
        assumptions: ['Market growth', 'Strong execution']
      }
    };
  }

  private async storeForecast(forecast: Forecast): Promise<void> {
    const db = this.env.DB_CRM;

    await db.prepare(`
      INSERT INTO revenue_forecasts (
        period_type, period_name, start_date, end_date,
        conservative_revenue, likely_revenue, optimistic_revenue,
        confidence_score, forecast_data, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      forecast.period.type,
      forecast.period.name,
      forecast.startDate,
      forecast.endDate,
      forecast.scenarios.conservative.revenue,
      forecast.scenarios.likely.revenue,
      forecast.scenarios.optimistic.revenue,
      forecast.confidence.overall,
      JSON.stringify(forecast),
      forecast.generatedAt
    ).run();
  }

  // Public methods for analysis
  async compareToTarget(forecast: Forecast, target: number): Promise<{
    gap: number;
    gapPercent: number;
    achievable: boolean;
    requiredActions: string[];
  }> {
    const gap = target - forecast.scenarios.likely.revenue;
    const gapPercent = (gap / target) * 100;

    const requiredActions: string[] = [];
    if (gap > 0) {
      requiredActions.push(`Generate additional $${gap.toLocaleString()} in pipeline`);
      requiredActions.push(`Improve conversion rate by ${(gap / forecast.pipeline.totalValue * 100).toFixed(1)}%`);
      requiredActions.push(`Add ${Math.ceil(gap / forecast.pipeline.averageDealSize)} new deals`);
    }

    return {
      gap,
      gapPercent,
      achievable: gapPercent < 20,
      requiredActions
    };
  }

  async getHistoricalAccuracy(): Promise<{
    averageAccuracy: number;
    byPeriod: Record<string, number>;
    trend: string;
  }> {
    // Would calculate from historical forecasts vs actuals
    return {
      averageAccuracy: 0.82,
      byPeriod: {
        'Q1': 0.78,
        'Q2': 0.83,
        'Q3': 0.85,
        'Q4': 0.82
      },
      trend: 'improving'
    };
  }
}