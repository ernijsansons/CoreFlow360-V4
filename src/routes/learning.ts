import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '../types/env';
import { ContinuousLearningEngine } from '../services/continuous-learning-engine';
import { PatternRecognition } from '../services/pattern-recognition';
import { PlaybookGenerator } from '../services/playbook-generator';
import type {
  Interaction,
  Outcome,
  Pattern,
  Playbook,
  Feedback,
  CustomerSegment,
  ExperimentResult
} from '../types/crm';

const learningRoutes = new Hono<{ Bindings: Env }>();

// =====================================================
// LEARNING OUTCOMES
// =====================================================

// Record interaction outcome for learning
const recordOutcomeSchema = z.object({
  interactionId: z.string(),
  leadId: z.string(),
  type: z.string(),
  channel: z.string(),
  strategy: z.string(),
  variant: z.string().optional(),
  content: z.string(),
  context: z.record(z.any()).optional(),
  timing: z.string().optional(),
  outcome: z.object({
    success: z.boolean(),
    result: z.string(),
    responseTime: z.number().optional(),
    sentiment: z.string().optional(),
    qualityScore: z.number().optional(),
    notes: z.string().optional()
  })
});

learningRoutes.post('/outcomes', async (c: any) => {
  try {
    const body = await c.req.json();
    const data = recordOutcomeSchema.parse(body);

    const learningEngine = new ContinuousLearningEngine(c.env);

    const interaction: Interaction = {
      id: data.interactionId,
      leadId: data.leadId,
      type: data.type,
      channel: data.channel,
      strategy: data.strategy,
      variant: data.variant,
      content: data.content,
      context: data.context || {},
      timing: data.timing || 'immediate',
      timestamp: new Date().toISOString()
    };

    const outcome: Outcome = {
      success: data.outcome.success,
      result: data.outcome.result,
      responseTime: data.outcome.responseTime,
      sentiment: data.outcome.sentiment,
      qualityScore: data.outcome.qualityScore,
      notes: data.outcome.notes,
      timestamp: new Date().toISOString()
    };

    await learningEngine.learnFromOutcome(interaction, outcome);

    return c.json({
      success: true,
      message: 'Outcome recorded and learning initiated',
      interactionId: data.interactionId
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to record outcome'
    }, 400);
  }
});

// Get learning metrics
learningRoutes.get('/metrics', async (c: any) => {
  try {
    const timeframe = c.req.query('timeframe') || '30d';
    const learningEngine = new ContinuousLearningEngine(c.env);

    const metrics = await learningEngine.getMetrics(timeframe);

    return c.json({
      success: true,
      metrics,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve metrics'
    }, 500);
  }
});

// =====================================================
// PATTERN RECOGNITION
// =====================================================

// Analyze patterns
learningRoutes.post('/patterns/analyze', async (c: any) => {
  try {
    const body = await c.req.json();
    const type = body.type || 'all';

    const patternRecognition = new PatternRecognition(c.env);

    let patterns: Pattern[] = [];

    switch (type) {
      case 'winning':
        patterns = await patternRecognition.identifyWinningPatterns();
        break;
      case 'channel':
        patterns = await patternRecognition.identifyChannelPatterns();
        break;
      case 'timing':
        patterns = await patternRecognition.identifyTimingPatterns();
        break;
      case 'content':
        patterns = await patternRecognition.identifyContentPatterns();
        break;
      case 'objection':
        patterns = await patternRecognition.identifyObjectionPatterns();
        break;
      case 'sequence':
        patterns = await patternRecognition.identifySequencePatterns();
        break;
      case 'closing':
        patterns = await patternRecognition.identifyClosingPatterns();
        break;
      case 'all':
        const results = await patternRecognition.runComprehensivePatternAnalysis();
        patterns = [
          ...results.channelPatterns,
          ...results.timingPatterns,
          ...results.contentPatterns,
          ...results.objectionPatterns,
          ...results.sequencePatterns,
          ...results.closingPatterns
        ];
        break;
      default:
        throw new Error(`Invalid pattern type: ${type}`);
    }

    return c.json({
      success: true,
      patterns,
      count: patterns.length,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to analyze patterns'
    }, 500);
  }
});

// Get patterns by type
learningRoutes.get('/patterns/:type', async (c: any) => {
  try {
    const type = c.req.param('type');
    const patternRecognition = new PatternRecognition(c.env);

    const patterns = await patternRecognition.getPatternsByType(type);

    return c.json({
      success: true,
      patterns,
      count: patterns.length
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve patterns'
    }, 500);
  }
});

// Get top performing patterns
learningRoutes.get('/patterns/top/:limit?', async (c: any) => {
  try {
    const limit = parseInt(c.req.param('limit') || '10');
    const patternRecognition = new PatternRecognition(c.env);

    const patterns = await patternRecognition.getTopPerformingPatterns(limit);

    return c.json({
      success: true,
      patterns,
      count: patterns.length
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve top patterns'
    }, 500);
  }
});

// Validate pattern
learningRoutes.post('/patterns/:id/validate', async (c: any) => {
  try {
    const patternId = c.req.param('id');
    const patternRecognition = new PatternRecognition(c.env);

    const isValid = await patternRecognition.validatePattern(patternId);

    return c.json({
      success: true,
      patternId,
      isValid,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to validate pattern'
    }, 500);
  }
});

// Get pattern insights
learningRoutes.get('/patterns/insights', async (c: any) => {
  try {
    const patternRecognition = new PatternRecognition(c.env);
    const insights = await patternRecognition.getPatternInsights();

    return c.json({
      success: true,
      insights,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve pattern insights'
    }, 500);
  }
});

// =====================================================
// PLAYBOOK GENERATION
// =====================================================

// Generate playbook for segment
const generatePlaybookSchema = z.object({
  segmentId: z.string(),
  segmentName: z.string(),
  criteria: z.object({
    industry: z.array(z.string()).optional(),
    companySize: z.string().optional(),
    region: z.array(z.string()).optional(),
    technology: z.array(z.string()).optional(),
    budget: z.object({
      min: z.number().optional(),
      max: z.number().optional()
    }).optional()
  }),
  characteristics: z.object({
    typicalChallenges: z.array(z.string()),
    decisionMakers: z.array(z.string()),
    preferredChannels: z.array(z.string()),
    communicationStyle: z.string(),
    buyingCycle: z.string().optional()
  })
});

learningRoutes.post('/playbooks/generate', async (c: any) => {
  try {
    const body = await c.req.json();
    const data = generatePlaybookSchema.parse(body);

    const segment: CustomerSegment = {
      id: data.segmentId,
      name: data.segmentName,
      criteria: data.criteria,
      characteristics: data.characteristics,
      leadCount: 0,
      performance: {
        conversionRate: 0,
        averageDealSize: 0,
        salesCycle: 0,
        winRate: 0
      },
      strategies: [],
      patterns: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const playbookGenerator = new PlaybookGenerator(c.env);
    const playbook = await playbookGenerator.generatePlaybook(segment);

    return c.json({
      success: true,
      playbook,
      message: `Playbook generated for ${segment.name}`,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to generate playbook'
    }, 500);
  }
});

// Update playbook with feedback
const updatePlaybookSchema = z.object({
  feedback: z.array(z.object({
    type: z.enum(['usability', 'effectiveness', 'accuracy', 'suggestion']),
    rating: z.number().min(1).max(5),
    comment: z.string(),
    category: z.string().optional(),
    suggestions: z.array(z.string()).optional()
  }))
});

learningRoutes.put('/playbooks/:id', async (c: any) => {
  try {
    const playbookId = c.req.param('id');
    const body = await c.req.json();
    const data = updatePlaybookSchema.parse(body);

    const playbookGenerator = new PlaybookGenerator(c.env);
    const playbook = await playbookGenerator.getPlaybook(playbookId);

    if (!playbook) {
      return c.json({
        success: false,
        error: 'Playbook not found'
      }, 404);
    }

    const feedback: Feedback[] = data.feedback.map((f: any) => ({
      id: `feedback_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      playbookId,
      type: f.type,
      rating: f.rating,
      comment: f.comment,
      category: f.category,
      suggestions: f.suggestions,
      timestamp: new Date().toISOString()
    }));

    const updatedPlaybook = await playbookGenerator.updatePlaybook(playbook, feedback);

    return c.json({
      success: true,
      playbook: updatedPlaybook,
      message: 'Playbook updated successfully'
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to update playbook'
    }, 500);
  }
});

// Get playbook
learningRoutes.get('/playbooks/:id', async (c: any) => {
  try {
    const playbookId = c.req.param('id');
    const playbookGenerator = new PlaybookGenerator(c.env);

    const playbook = await playbookGenerator.getPlaybook(playbookId);

    if (!playbook) {
      return c.json({
        success: false,
        error: 'Playbook not found'
      }, 404);
    }

    return c.json({
      success: true,
      playbook
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve playbook'
    }, 500);
  }
});

// Get active playbooks
learningRoutes.get('/playbooks/active', async (c: any) => {
  try {
    const playbookGenerator = new PlaybookGenerator(c.env);
    const playbooks = await playbookGenerator.getActivePlaybooks();

    return c.json({
      success: true,
      playbooks,
      count: playbooks.length
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve active playbooks'
    }, 500);
  }
});

// Get playbook performance metrics
learningRoutes.get('/playbooks/performance', async (c: any) => {
  try {
    const playbookGenerator = new PlaybookGenerator(c.env);
    const performance = await playbookGenerator.getPlaybookPerformance();

    return c.json({
      success: true,
      performance,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve playbook performance'
    }, 500);
  }
});

// Record playbook usage
learningRoutes.post('/playbooks/:id/usage', async (c: any) => {
  try {
    const playbookId = c.req.param('id');
    const body = await c.req.json();

    const playbookGenerator = new PlaybookGenerator(c.env);
    await playbookGenerator.recordPlaybookUsage(
      playbookId,
      body.userId,
      body.leadId,
      body.section
    );

    return c.json({
      success: true,
      message: 'Usage recorded successfully'
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to record usage'
    }, 500);
  }
});

// Record playbook feedback
learningRoutes.post('/playbooks/:id/feedback', async (c: any) => {
  try {
    const playbookId = c.req.param('id');
    const body = await c.req.json();

    const playbookGenerator = new PlaybookGenerator(c.env);
    await playbookGenerator.recordPlaybookFeedback(
      playbookId,
      body.userId,
      body.section,
      body.rating,
      body.comment
    );

    return c.json({
      success: true,
      message: 'Feedback recorded successfully'
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to record feedback'
    }, 500);
  }
});

// =====================================================
// EXPERIMENTS
// =====================================================

// Get active experiments
learningRoutes.get('/experiments/active', async (c: any) => {
  try {
    const learningEngine = new ContinuousLearningEngine(c.env);
    const experiments = await learningEngine.getActiveExperiments();

    return c.json({
      success: true,
      experiments,
      count: experiments.length,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve active experiments'
    }, 500);
  }
});

// =====================================================
// STRATEGIES
// =====================================================

// Get strategy by ID
learningRoutes.get('/strategies/:id', async (c: any) => {
  try {
    const strategyId = c.req.param('id');
    const learningEngine = new ContinuousLearningEngine(c.env);

    const strategy = await learningEngine.getStrategy(strategyId);

    if (!strategy) {
      return c.json({
        success: false,
        error: 'Strategy not found'
      }, 404);
    }

    return c.json({
      success: true,
      strategy
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve strategy'
    }, 500);
  }
});

// Get active variants for strategy
learningRoutes.get('/strategies/:id/variants', async (c: any) => {
  try {
    const strategyId = c.req.param('id');
    const learningEngine = new ContinuousLearningEngine(c.env);

    const variants = await learningEngine.getActiveVariants(strategyId);

    return c.json({
      success: true,
      variants,
      count: variants.length
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve variants'
    }, 500);
  }
});

export { learningRoutes };