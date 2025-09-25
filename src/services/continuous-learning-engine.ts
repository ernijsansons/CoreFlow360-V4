import type { Env } from '../types/env';
import type {
  Interaction,
  Outcome,
  Strategy,
  PromptVariant,
  Pattern,
  CustomerSegment,
  Playbook,
  Feedback,
  LearningMetrics,
  ExperimentResult,
  StrategyUpdate
} from '../types/crm';

export class ContinuousLearningEngine {
  private env: Env;
  private businessId: string;
  private strategies = new Map<string, Strategy>();
  private variants = new Map<string, PromptVariant>();
  private patterns = new Map<string, Pattern>();
  private segments = new Map<string, CustomerSegment>();
  private learningQueue: Array<{ interaction: Interaction; outcome: Outcome}> = [];
  private experimentTracker = new Map<string, ExperimentResult>();

  constructor(env: Env, businessId: string) {
    this.env = env;
    this.businessId = businessId;
    this.initializeLearning();
  }

  async learnFromOutcome(interaction: Interaction, outcome: Outcome): Promise<void> {
    // Add to learning queue for batch processing
    this.learningQueue.push({ interaction, outcome });
    
    // Immediate learning for critical outcomes
    if (this.isCriticalOutcome(outcome)) {
      await this.processLearning(interaction, outcome);
    }
    
    // Batch process if queue is full
    if (this.learningQueue.length >= 10) {
      await this.processBatchLearning();
    }
  }

  private async processLearning(interaction: Interaction, outcome: Outcome): Promise<void> {
    // Analyze what worked or didn't
    const analysis = await this.analyzeOutcome(interaction, outcome);
    
    // Update strategies based on analysis
    await this.updateStrategies(analysis);
    
    // Update patterns
    await this.updatePatterns(interaction, outcome);
    
    // Update customer segments
    await this.updateSegments(interaction, outcome);
  }

  private async processBatchLearning(): Promise<void> {
    const batch = this.learningQueue.splice(0, 10);
    
    for (const { interaction, outcome } of batch) {
      await this.processLearning(interaction, outcome);
    }
  }

  private async analyzeOutcome(interaction: Interaction, outcome: Outcome): Promise<{
    success: boolean;
    factors: string[];
    recommendations: string[];
  }> {
    // Mock analysis - would use real AI in production
    return {
      success: outcome.success,
      factors: ['timing', 'approach', 'personalization'],
      recommendations: ['adjust timing', 'refine approach', 'improve personalization']
    };
  }

  private async updateStrategies(analysis: any): Promise<void> {
    // Update strategy effectiveness based on analysis
    for (const [id, strategy] of this.strategies) {
      if (analysis.factors.includes(strategy.type)) {
        strategy.effectiveness = Math.min(1, strategy.effectiveness + 0.1);
      }
    }
  }

  private async updatePatterns(interaction: Interaction, outcome: Outcome): Promise<void> {
    // Identify and update patterns
    const patternKey = this.generatePatternKey(interaction);
    const existingPattern = this.patterns.get(patternKey);
    
    if (existingPattern) {
      existingPattern.frequency++;
      existingPattern.successRate = (existingPattern.successRate + (outcome.success ? 1 : 0)) / 2;
    } else {
      this.patterns.set(patternKey, {
        id: patternKey,
        type: 'interaction',
        frequency: 1,
        successRate: outcome.success ? 1 : 0,
        metadata: interaction
      });
    }
  }

  private async updateSegments(interaction: Interaction, outcome: Outcome): Promise<void> {
    // Update customer segment characteristics
    const segmentId = this.identifySegment(interaction);
    const segment = this.segments.get(segmentId);
    
    if (segment) {
      segment.interactionCount++;
      segment.successRate = (segment.successRate + (outcome.success ? 1 : 0)) / 2;
    }
  }

  private generatePatternKey(interaction: Interaction): string {
    return `${interaction.type}_${interaction.channel}_${interaction.context}`;
  }

  private identifySegment(interaction: Interaction): string {
    // Mock segment identification
    return 'segment_1';
  }

  private isCriticalOutcome(outcome: Outcome): boolean {
    return outcome.success && outcome.value > 1000;
  }

  async createExperiment(strategy: Strategy, variants: PromptVariant[]): Promise<string> {
    const experimentId = `exp_${Date.now()}`;
    
    const experiment: ExperimentResult = {
      id: experimentId,
      strategyId: strategy.id,
      variants: variants.map(v => ({ ...v, id: `var_${Date.now()}_${Math.random()}` })),
      startDate: new Date(),
      status: 'running',
      results: [],
      winner: null
    };
    
    this.experimentTracker.set(experimentId, experiment);
    return experimentId;
  }

  async recordExperimentResult(experimentId: string, variantId: string, outcome: Outcome): Promise<void> {
    const experiment = this.experimentTracker.get(experimentId);
    if (!experiment) return;
    
    experiment.results.push({
      variantId,
      outcome,
      timestamp: new Date()
    });
    
    // Check if experiment should conclude
    if (experiment.results.length >= 100) {
      await this.concludeExperiment(experimentId);
    }
  }

  private async concludeExperiment(experimentId: string): Promise<void> {
    const experiment = this.experimentTracker.get(experimentId);
    if (!experiment) return;
    
    // Find winning variant
    const variantResults = new Map<string, { count: number; successRate: number }>();
    
    for (const result of experiment.results) {
      const existing = variantResults.get(result.variantId) || { count: 0, successRate: 0 };
      existing.count++;
      existing.successRate = (existing.successRate + (result.outcome.success ? 1 : 0)) / 2;
      variantResults.set(result.variantId, existing);
    }
    
    let bestVariant = '';
    let bestScore = 0;
    
    for (const [variantId, stats] of variantResults) {
      const score = stats.successRate * Math.log(stats.count);
      if (score > bestScore) {
        bestScore = score;
        bestVariant = variantId;
      }
    }
    
    experiment.winner = bestVariant;
    experiment.status = 'completed';
    experiment.endDate = new Date();
  }

  async getLearningMetrics(): Promise<LearningMetrics> {
    const totalInteractions = this.learningQueue.length + Array.from(this.patterns.values()).reduce((sum, p) => sum + p.frequency, 0);
    const successfulInteractions = Array.from(this.patterns.values()).reduce((sum, p) => sum + (p.frequency * p.successRate), 0);
    
    return {
      totalInteractions,
      successfulInteractions,
      successRate: totalInteractions > 0 ? successfulInteractions / totalInteractions : 0,
      activeExperiments: Array.from(this.experimentTracker.values()).filter(e => e.status === 'running').length,
      completedExperiments: Array.from(this.experimentTracker.values()).filter(e => e.status === 'completed').length,
      patternsDiscovered: this.patterns.size,
      strategiesOptimized: this.strategies.size,
      lastLearningUpdate: new Date()
    };
  }

  async getRecommendations(): Promise<StrategyUpdate[]> {
    const recommendations: StrategyUpdate[] = [];
    
    // Analyze patterns for recommendations
    for (const [id, pattern] of this.patterns) {
      if (pattern.successRate > 0.8 && pattern.frequency > 5) {
        recommendations.push({
          strategyId: id,
          type: 'increase_usage',
          reason: 'High success rate pattern',
          confidence: pattern.successRate
        });
      }
    }
    
    return recommendations;
  }

  async exportLearningData(): Promise<{
    strategies: Strategy[];
    patterns: Pattern[];
    segments: CustomerSegment[];
    experiments: ExperimentResult[];
  }> {
    return {
      strategies: Array.from(this.strategies.values()),
      patterns: Array.from(this.patterns.values()),
      segments: Array.from(this.segments.values()),
      experiments: Array.from(this.experimentTracker.values())
    };
  }

  async importLearningData(data: {
    strategies: Strategy[];
    patterns: Pattern[];
    segments: CustomerSegment[];
    experiments: ExperimentResult[];
  }): Promise<void> {
    // Import strategies
    for (const strategy of data.strategies) {
      this.strategies.set(strategy.id, strategy);
    }
    
    // Import patterns
    for (const pattern of data.patterns) {
      this.patterns.set(pattern.id, pattern);
    }
    
    // Import segments
    for (const segment of data.segments) {
      this.segments.set(segment.id, segment);
    }
    
    // Import experiments
    for (const experiment of data.experiments) {
      this.experimentTracker.set(experiment.id, experiment);
    }
  }

  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      return {
        status: 'healthy',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      };
    }
  }
}

