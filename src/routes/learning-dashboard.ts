import { Hono } from 'hono';
import type { Env } from '../types/env';
import { ContinuousLearningEngine } from '../services/continuous-learning-engine';
import { PatternRecognition } from '../services/pattern-recognition';
import { PlaybookGenerator } from '../services/playbook-generator';

const dashboardRoutes = new Hono<{ Bindings: Env }>();

// =====================================================
// DASHBOARD OVERVIEW
// =====================================================

dashboardRoutes.get('/overview', async (c: any) => {
  try {
    const learningEngine = new ContinuousLearningEngine(c.env);
    const patternRecognition = new PatternRecognition(c.env);
    const playbookGenerator = new PlaybookGenerator(c.env);
    const db = c.env.DB_CRM;

    // Get overall metrics
    const metrics = await learningEngine.getMetrics('30d');
    const patternInsights = await patternRecognition.getPatternInsights();
    const playbookPerformance = await playbookGenerator.getPlaybookPerformance();

    // Get recent activity
    const recentActivity = await db.prepare(`
      SELECT
        'interaction' as type,
        id,
        created_at,
        outcome_success as success
      FROM interactions
      WHERE created_at >= datetime('now', '-24 hours')
      UNION ALL
      SELECT
        'pattern' as type,
        id,
        discovered as created_at,
        1 as success
      FROM patterns
      WHERE discovered >= datetime('now', '-24 hours')
      UNION ALL
      SELECT
        'experiment' as type,
        id,
        start_date as created_at,
        CASE WHEN decision = 'adopt' THEN 1 ELSE 0 END as success
      FROM experiments
      WHERE start_date >= datetime('now', '-7 days')
      ORDER BY created_at DESC
      LIMIT 50
    `).all();

    // Get system health
    const systemHealth = await this.getSystemHealth(c.env);

    return c.json({
      success: true,
      overview: {
        metrics,
        patterns: patternInsights,
        playbooks: playbookPerformance,
        recentActivity: recentActivity.results,
        systemHealth
      },
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve dashboard data'
    }, 500);
  }
});

// =====================================================
// PERFORMANCE METRICS
// =====================================================

dashboardRoutes.get('/performance', async (c: any) => {
  try {
    const db = c.env.DB_CRM;
    const timeframe = c.req.query('timeframe') || '30d';

    // Parse timeframe
    let daysBack = 30;
    if (timeframe.endsWith('d')) {
      daysBack = parseInt(timeframe.slice(0, -1));
    } else if (timeframe.endsWith('w')) {
      daysBack = parseInt(timeframe.slice(0, -1)) * 7;
    } else if (timeframe.endsWith('m')) {
      daysBack = parseInt(timeframe.slice(0, -1)) * 30;
    }

    // Get performance trends
    const performanceTrends = await db.prepare(`
      SELECT
        date(created_at) as date,
        COUNT(*) as interactions,
        AVG(CASE WHEN outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
        AVG(response_time_minutes) as avg_response_time
      FROM interactions
      WHERE created_at >= datetime('now', '-${daysBack} days')
      GROUP BY date(created_at)
      ORDER BY date DESC
    `).all();

    // Get strategy performance
    const strategyPerformance = await db.prepare(`
      SELECT
        s.name as strategy_name,
        s.type as strategy_type,
        COUNT(i.id) as total_interactions,
        AVG(CASE WHEN i.outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
        AVG(i.response_time_minutes) as avg_response_time
      FROM strategies s
      LEFT JOIN interactions i ON s.id = i.strategy_id
      WHERE s.active = 1
        AND i.created_at >= datetime('now', '-${daysBack} days')
      GROUP BY s.id, s.name, s.type
      ORDER BY success_rate DESC
    `).all();

    // Get variant performance
    const variantPerformance = await db.prepare(`
      SELECT
        pv.name as variant_name,
        pv.strategy_id,
        COUNT(i.id) as interactions,
        AVG(CASE WHEN i.outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
        pv.traffic_split
      FROM prompt_variants pv
      LEFT JOIN interactions i ON pv.id = i.variant_id
      WHERE pv.active = 1
        AND i.created_at >= datetime('now', '-${daysBack} days')
      GROUP BY pv.id, pv.name
      HAVING interactions >= 10
      ORDER BY success_rate DESC
    `).all();

    // Get channel performance
    const channelPerformance = await db.prepare(`
      SELECT
        channel,
        COUNT(*) as interactions,
        AVG(CASE WHEN outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
        AVG(response_time_minutes) as avg_response_time
      FROM interactions
      WHERE created_at >= datetime('now', '-${daysBack} days')
        AND channel IS NOT NULL
      GROUP BY channel
      ORDER BY success_rate DESC
    `).all();

    return c.json({
      success: true,
      performance: {
        timeframe,
        trends: performanceTrends.results,
        strategies: strategyPerformance.results,
        variants: variantPerformance.results,
        channels: channelPerformance.results
      },
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve performance metrics'
    }, 500);
  }
});

// =====================================================
// LEARNING INSIGHTS
// =====================================================

dashboardRoutes.get('/insights', async (c: any) => {
  try {
    const db = c.env.DB_CRM;
    const learningEngine = new ContinuousLearningEngine(c.env);
    const patternRecognition = new PatternRecognition(c.env);

    // Get top patterns
    const topPatterns = await patternRecognition.getTopPerformingPatterns(10);

    // Get active experiments
    const activeExperiments = await learningEngine.getActiveExperiments();

    // Get recent learnings
    const recentLearnings = await db.prepare(`
      SELECT
        ld.*,
        i.channel,
        i.interaction_type
      FROM learning_data ld
      JOIN interactions i ON ld.interaction_id = i.id
      WHERE ld.created_at >= datetime('now', '-7 days')
        AND ld.analysis_data IS NOT NULL
      ORDER BY ld.created_at DESC
      LIMIT 20
    `).all();

    // Get improvement opportunities
    const improvements = await this.identifyImprovements(c.env);

    // Get anomalies
    const anomalies = await this.detectAnomalies(c.env);

    return c.json({
      success: true,
      insights: {
        topPatterns,
        activeExperiments,
        recentLearnings: recentLearnings.results,
        improvements,
        anomalies
      },
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve learning insights'
    }, 500);
  }
});

// =====================================================
// EXPERIMENT MONITORING
// =====================================================

dashboardRoutes.get('/experiments/monitoring', async (c: any) => {
  try {
    const db = c.env.DB_CRM;

    // Get all experiments with detailed stats
    const experiments = await db.prepare(`
      SELECT
        e.*,
        COUNT(DISTINCT i.id) as total_interactions,
        AVG(CASE WHEN i.outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
        MIN(i.created_at) as first_interaction,
        MAX(i.created_at) as last_interaction
      FROM experiments e
      LEFT JOIN interactions i ON i.created_at >= e.start_date
        AND (i.created_at <= e.end_date OR e.end_date IS NULL)
      GROUP BY e.id
      ORDER BY e.start_date DESC
    `).all();

    // Calculate experiment statistics
    const stats = {
      total: experiments.results.length,
      active: experiments.results.filter((e: any) => !e.end_date).length,
      completed: experiments.results.filter((e: any) => e.end_date).length,
      adopted: experiments.results.filter((e: any) => e.decision === 'adopt').length,
      rejected: experiments.results.filter((e: any) => e.decision === 'reject').length,
      avgDuration: 0,
      avgInteractions: 0,
      successRate: 0
    };

    if (experiments.results.length > 0) {
      const completedExperiments = experiments.results.filter((e: any) => e.end_date);
      if (completedExperiments.length > 0) {
        const durations = completedExperiments.map((e: any) => {
          const start = new Date(e.start_date);
          const end = new Date(e.end_date);
          return (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24); // Days
        });
        stats.avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length;
      }

      stats.avgInteractions = experiments.results.reduce((sum: number, e: any) =>
        sum + (e.total_interactions || 0), 0) / experiments.results.length;

      stats.successRate = stats.adopted / (stats.adopted + stats.rejected) || 0;
    }

    return c.json({
      success: true,
      experiments: {
        list: experiments.results,
        statistics: stats
      },
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve experiment data'
    }, 500);
  }
});

// =====================================================
// PATTERN ANALYTICS
// =====================================================

dashboardRoutes.get('/patterns/analytics', async (c: any) => {
  try {
    const db = c.env.DB_CRM;

    // Get pattern distribution
    const patternDistribution = await db.prepare(`
      SELECT
        type,
        COUNT(*) as count,
        AVG(confidence) as avg_confidence
      FROM patterns
      GROUP BY type
      ORDER BY count DESC
    `).all();

    // Get pattern validation history
    const validationHistory = await db.prepare(`
      SELECT
        date(last_validated) as date,
        COUNT(*) as patterns_validated,
        AVG(confidence) as avg_confidence
      FROM patterns
      WHERE last_validated >= datetime('now', '-30 days')
      GROUP BY date(last_validated)
      ORDER BY date DESC
    `).all();

    // Get pattern effectiveness
    const patternEffectiveness = await db.prepare(`
      SELECT
        p.name,
        p.type,
        p.confidence,
        COUNT(pr.id) as recommendations,
        AVG(pr.confidence) as avg_recommendation_confidence
      FROM patterns p
      LEFT JOIN pattern_recommendations pr ON p.id = pr.pattern_id
      GROUP BY p.id
      HAVING recommendations > 0
      ORDER BY p.confidence DESC
      LIMIT 20
    `).all();

    return c.json({
      success: true,
      analytics: {
        distribution: patternDistribution.results,
        validationHistory: validationHistory.results,
        effectiveness: patternEffectiveness.results
      },
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve pattern analytics'
    }, 500);
  }
});

// =====================================================
// PLAYBOOK ANALYTICS
// =====================================================

dashboardRoutes.get('/playbooks/analytics', async (c: any) => {
  try {
    const db = c.env.DB_CRM;

    // Get playbook usage statistics
    const usageStats = await db.prepare(`
      SELECT
        p.name as playbook_name,
        p.segment_id,
        COUNT(DISTINCT pu.user_id) as unique_users,
        COUNT(DISTINCT pu.lead_id) as unique_leads,
        COUNT(pu.id) as total_uses,
        GROUP_CONCAT(DISTINCT pu.section_used) as sections_used,
        MAX(pu.used_at) as last_used
      FROM playbooks p
      LEFT JOIN playbook_usage pu ON p.id = pu.playbook_id
      WHERE p.active = 1
      GROUP BY p.id
      ORDER BY total_uses DESC
    `).all();

    // Get feedback summary
    const feedbackSummary = await db.prepare(`
      SELECT
        p.name as playbook_name,
        COUNT(f.id) as feedback_count,
        AVG(f.rating) as avg_rating,
        COUNT(CASE WHEN f.rating >= 4 THEN 1 END) as positive_feedback,
        COUNT(CASE WHEN f.rating <= 2 THEN 1 END) as negative_feedback
      FROM playbooks p
      LEFT JOIN feedback f ON p.id = f.playbook_id
      GROUP BY p.id
      HAVING feedback_count > 0
      ORDER BY avg_rating DESC
    `).all();

    // Get section effectiveness
    const sectionEffectiveness = await db.prepare(`
      SELECT
        section_used,
        COUNT(*) as usage_count,
        COUNT(DISTINCT playbook_id) as playbooks_using
      FROM playbook_usage
      WHERE used_at >= datetime('now', '-30 days')
      GROUP BY section_used
      ORDER BY usage_count DESC
    `).all();

    return c.json({
      success: true,
      analytics: {
        usage: usageStats.results,
        feedback: feedbackSummary.results,
        sections: sectionEffectiveness.results
      },
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve playbook analytics'
    }, 500);
  }
});

// =====================================================
// HELPER FUNCTIONS
// =====================================================

async function getSystemHealth(this: any, env: Env): Promise<any> {
  const db = env.DB_CRM;

  try {
    // Check database connectivity
    const dbCheck = await db.prepare('SELECT 1').first();

    // Check table counts
    const tableCounts = await Promise.all([
      db.prepare('SELECT COUNT(*) as count FROM strategies').first(),
      db.prepare('SELECT COUNT(*) as count FROM patterns').first(),
      db.prepare('SELECT COUNT(*) as count FROM playbooks').first(),
      db.prepare('SELECT COUNT(*) as count FROM experiments').first()
    ]);

    // Check for recent activity
    const recentActivity = await db.prepare(`
      SELECT COUNT(*) as count
      FROM interactions
      WHERE created_at >= datetime('now', '-1 hour')
    `).first();

    return {
      status: 'healthy',
      database: dbCheck ? 'connected' : 'disconnected',
      tables: {
        strategies: tableCounts[0]?.count || 0,
        patterns: tableCounts[1]?.count || 0,
        playbooks: tableCounts[2]?.count || 0,
        experiments: tableCounts[3]?.count || 0
      },
      recentActivity: recentActivity?.count || 0,
      lastCheck: new Date().toISOString()
    };
  } catch (error: any) {
    return {
      status: 'degraded',
      error: error instanceof Error ? error.message : 'Unknown error',
      lastCheck: new Date().toISOString()
    };
  }
}

async function identifyImprovements(this: any, env: Env): Promise<any[]> {
  const db = env.DB_CRM;

  const improvements = [];

  try {
    // Find underperforming strategies
    const underperformingStrategies = await db.prepare(`
      SELECT
        s.name,
        s.type,
        COUNT(i.id) as interactions,
        AVG(CASE WHEN i.outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate
      FROM strategies s
      JOIN interactions i ON s.id = i.strategy_id
      WHERE s.active = 1
        AND i.created_at >= datetime('now', '-7 days')
      GROUP BY s.id
      HAVING success_rate < 0.3 AND interactions >= 10
    `).all();

    for (const strategy of underperformingStrategies.results) {
      improvements.push({
        type: 'strategy',
        target: strategy.name,
        issue: `Low success rate: ${((strategy.success_rate as number) * 100).toFixed(1)}%`,
        recommendation: 'Review and update strategy approach or create new variants for testing'
      });
    }

    // Find stale playbooks
    const stalePlaybooks = await db.prepare(`
      SELECT name, segment_id, updated_at
      FROM playbooks
      WHERE active = 1
        AND updated_at < datetime('now', '-30 days')
    `).all();

    for (const playbook of stalePlaybooks.results) {
      improvements.push({
        type: 'playbook',
        target: playbook.name,
        issue: 'Not updated in over 30 days',
        recommendation: 'Review recent feedback and update playbook content'
      });
    }

    // Find patterns needing validation
    const unvalidatedPatterns = await db.prepare(`
      SELECT name, type, confidence, last_validated
      FROM patterns
      WHERE last_validated < datetime('now', '-14 days')
        AND confidence < 0.7
    `).all();

    for (const pattern of unvalidatedPatterns.results) {
      improvements.push({
        type: 'pattern',
        target: pattern.name,
        issue: `Low confidence (${((pattern.confidence as number) * 100).toFixed(1)}%) and not recently validated`,
        recommendation: 'Validate pattern against recent data or consider retiring'
      });
    }

  } catch (error: any) {
  }

  return improvements;
}

async function detectAnomalies(this: any, env: Env): Promise<any[]> {
  const db = env.DB_CRM;
  const anomalies = [];

  try {
    // Detect sudden drops in success rate
    const successRateAnomaly = await db.prepare(`
      WITH daily_rates AS (
        SELECT
          date(created_at) as date,
          AVG(CASE WHEN outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate
        FROM interactions
        WHERE created_at >= datetime('now', '-14 days')
        GROUP BY date(created_at)
      ),
      avg_rate AS (
        SELECT AVG(success_rate) as baseline
        FROM daily_rates
      )
      SELECT
        date,
        success_rate,
        (SELECT baseline FROM avg_rate) as baseline
      FROM daily_rates
      WHERE success_rate < (SELECT baseline FROM avg_rate) * 0.7
      ORDER BY date DESC
    `).all();

    for (const anomaly of successRateAnomaly.results) {
      anomalies.push({
        type: 'performance_drop',
        date: anomaly.date,
        metric: 'success_rate',
        value: anomaly.success_rate,
        baseline: anomaly.baseline,
        severity: 'high',
        description: `Success rate dropped
  to ${((anomaly.success_rate as number) * 100).toFixed(1)}% (baseline: ${((anomaly.baseline as number) * 100).toFixed(1)}%)`
      });
    }

    // Detect unusual response times
    const responseTimeAnomaly = await db.prepare(`
      WITH hourly_times AS (
        SELECT
          strftime('%Y-%m-%d %H', created_at) as hour,
          AVG(response_time_minutes) as avg_response_time,
          COUNT(*) as interactions
        FROM interactions
        WHERE created_at >= datetime('now', '-24 hours')
          AND response_time_minutes IS NOT NULL
        GROUP BY hour
      ),
      baseline AS (
        SELECT
          AVG(avg_response_time) as avg_baseline,
          AVG(avg_response_time) + 2 * STDEV(avg_response_time) as upper_bound
        FROM hourly_times
      )
      SELECT
        hour,
        avg_response_time,
        interactions,
        (SELECT avg_baseline FROM baseline) as baseline,
        (SELECT upper_bound FROM baseline) as threshold
      FROM hourly_times
      WHERE avg_response_time > (SELECT upper_bound FROM baseline)
    `).all();

    for (const anomaly of responseTimeAnomaly.results) {
      anomalies.push({
        type: 'response_time_spike',
        date: anomaly.hour,
        metric: 'response_time',
        value: anomaly.avg_response_time,
        baseline: anomaly.baseline,
        severity: 'medium',
        description: `Response
  time spiked to ${anomaly.avg_response_time} minutes (baseline: ${Math.round(anomaly.baseline as number)} minutes)`
      });
    }

  } catch (error: any) {
  }

  return anomalies;
}

export { dashboardRoutes };