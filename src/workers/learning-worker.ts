import type { Env } from '../types/env';
import { ContinuousLearningEngine } from '../services/continuous-learning-engine';
import { PatternRecognition } from '../services/pattern-recognition';
import { PlaybookGenerator } from '../services/playbook-generator';

export interface LearningTask {
  id: string;
  type: 'learn_outcome' | 'analyze_patterns' | 'validate_patterns' | 'update_playbooks' | 'run_experiments';
  data: any;
  scheduledAt?: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
}

export class LearningWorker {
  private env: Env;
  private learningEngine: ContinuousLearningEngine;
  private patternRecognition: PatternRecognition;
  private playbookGenerator: PlaybookGenerator;
  private isProcessing = false;
  private taskQueue: LearningTask[] = [];

  constructor(env: Env) {
    this.env = env;
    this.learningEngine = new ContinuousLearningEngine(env);
    this.patternRecognition = new PatternRecognition(env);
    this.playbookGenerator = new PlaybookGenerator(env);
  }

  // Main worker loop
  async start(): Promise<void> {

    // Set up scheduled tasks
    await this.scheduleRecurringTasks();

    // Process task queue continuously
    while (true) {
      if (!this.isProcessing && this.taskQueue.length > 0) {
        await this.processNextTask();
      }

      // Wait before checking again
      await this.sleep(5000); // 5 seconds
    }
  }

  // Add task to queue
  async queueTask(task: LearningTask): Promise<void> {
    // Sort by priority
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

    this.taskQueue.push(task);
    this.taskQueue.sort((a, b) => {
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });

  }

  // Process next task in queue
  private async processNextTask(): Promise<void> {
    if (this.taskQueue.length === 0) return;

    this.isProcessing = true;
    const task = this.taskQueue.shift()!;


    try {
      switch (task.type) {
        case 'learn_outcome':
          await this.processLearningOutcome(task.data);
          break;
        case 'analyze_patterns':
          await this.analyzePatterns(task.data);
          break;
        case 'validate_patterns':
          await this.validatePatterns(task.data.businessId);
          break;
        case 'update_playbooks':
          await this.updatePlaybooks(task.data.businessId);
          break;
        case 'run_experiments':
          await this.runExperiments(task.data.businessId);
          break;
        default:
      }

    } catch (error) {

      // Re-queue with lower priority if critical
      if (task.priority === 'critical') {
        task.priority = 'high';
        await this.queueTask(task);
      }
    } finally {
      this.isProcessing = false;
    }
  }

  // Process learning outcome
  private async processLearningOutcome(data: any): Promise<void> {
    const { interaction, outcome } = data;
    await this.learningEngine.learnFromOutcome(interaction, outcome);

    // Queue pattern analysis if significant outcome
    if (outcome.success || outcome.result === 'meeting_booked' || outcome.result === 'deal_closed') {
      await this.queueTask({
        id: `pattern_${Date.now()}`,
        type: 'analyze_patterns',
        data: { trigger: 'significant_outcome', interaction, outcome },
        priority: 'medium'
      });
    }
  }

  // Analyze patterns
  private async analyzePatterns(data: any): Promise<void> {
    const { type = 'all' } = data;


    if (type === 'all' || type === 'comprehensive') {
      const results = await this.patternRecognition.runComprehensivePatternAnalysis();

      // Update playbooks if new patterns found
      const totalPatterns =
        results.channelPatterns.length +
        results.timingPatterns.length +
        results.contentPatterns.length +
        results.objectionPatterns.length +
        results.sequencePatterns.length +
        results.closingPatterns.length;

      if (totalPatterns > 0) {
        await this.queueTask({
          id: `playbook_update_${Date.now()}`,
          type: 'update_playbooks',
          data: { reason: 'new_patterns', patterns: results },
          priority: 'low'
        });
      }
    } else {
      // Analyze specific pattern type
      let patterns = [];
      switch (type) {
        case 'winning':
          patterns = await this.patternRecognition.identifyWinningPatterns();
          break;
        case 'channel':
          patterns = await this.patternRecognition.identifyChannelPatterns();
          break;
        case 'timing':
          patterns = await this.patternRecognition.identifyTimingPatterns();
          break;
        case 'content':
          patterns = await this.patternRecognition.identifyContentPatterns();
          break;
        case 'objection':
          patterns = await this.patternRecognition.identifyObjectionPatterns();
          break;
        case 'sequence':
          patterns = await this.patternRecognition.identifySequencePatterns();
          break;
        case 'closing':
          patterns = await this.patternRecognition.identifyClosingPatterns();
          break;
      }

    }
  }

  // Validate existing patterns
  private async validatePatterns(businessId: string): Promise<void> {
    const db = this.env.DB_CRM;

    // Get patterns that haven't been validated recently - CRITICAL: Include business_id filter
    const patternsToValidate = await db.prepare(`
      SELECT id FROM patterns
      WHERE business_id = ? AND last_validated < datetime('now', '-7 days')
      ORDER BY confidence DESC
      LIMIT 20
    `).bind(businessId).all();


    for (const row of patternsToValidate.results) {
      const patternId = row.id as string;
      const isValid = await this.patternRecognition.validatePattern(patternId);

      if (!isValid) {
      }
    }
  }

  // Update playbooks based on new data
  private async updatePlaybooks(businessId: string): Promise<void> {
    const db = this.env.DB_CRM;

    // Get active playbooks that need updating - CRITICAL: Include business_id filter
    const playbooksToUpdate = await db.prepare(`
      SELECT p.*,
        COUNT(f.id) as feedback_count,
        AVG(f.rating) as avg_rating
      FROM playbooks p
      LEFT JOIN feedback f ON p.id = f.playbook_id AND f.business_id = ?
      WHERE p.business_id = ? AND p.active = 1
        AND (
          p.updated_at < datetime('now', '-14 days')
          OR AVG(f.rating) < 3.5
        )
      GROUP BY p.id
      HAVING feedback_count > 5
      LIMIT 5
    `).bind(businessId, businessId).all();


    for (const row of playbooksToUpdate.results) {
      const playbookData = JSON.parse(row.playbook_data as string);

      // Get recent feedback - CRITICAL: Include business_id filter
      const feedback = await db.prepare(`
        SELECT * FROM feedback
        WHERE playbook_id = ? AND business_id = ?
        ORDER BY created_at DESC
        LIMIT 20
      `).bind(row.id, businessId).all();

      const feedbackData = feedback.results.map(f => ({
        id: f.id as string,
        type: f.type as any,
        rating: f.rating as number,
        comment: f.comment as string,
        category: f.category as string,
        timestamp: f.created_at as string
      }));

      // Update playbook
      await this.playbookGenerator.updatePlaybook(playbookData, feedbackData);
    }
  }

  // Run and monitor experiments
  private async runExperiments(businessId: string): Promise<void> {
    const experiments = await this.learningEngine.getActiveExperiments();


    for (const experiment of experiments) {
      // Check if experiment should end
      if (experiment.endDate && new Date(experiment.endDate) <= new Date()) {
        await this.concludeExperiment(experiment, businessId);
      } else {
        // Check interim results
        await this.checkExperimentProgress(experiment, businessId);
      }
    }
  }

  // Conclude an experiment
  private async concludeExperiment(experiment: any, businessId: string): Promise<void> {
    const db = this.env.DB_CRM;


    // Analyze results - CRITICAL: Include business_id filter
    const results = await db.prepare(`
      SELECT
        variant_id,
        COUNT(*) as interactions,
        AVG(CASE WHEN outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate
      FROM interactions
      WHERE business_id = ? AND created_at >= ?
        AND (variant_id IN (?, ?) OR strategy_id = ?)
      GROUP BY variant_id
    `).bind(
      businessId,
      experiment.startDate,
      experiment.variants.control?.id,
      experiment.variants.test?.id,
      experiment.strategyId
    ).all();

    // Determine winner
    const controlResult = results.results.find(r => r.variant_id === experiment.variants.control?.id);
    const testResult = results.results.find(r => r.variant_id === experiment.variants.test?.id);

    let decision = 'continue';
    if (testResult && controlResult) {
      const testRate = testResult.success_rate as number;
      const controlRate = controlResult.success_rate as number;

      if (testRate > controlRate * 1.1) { // 10% improvement threshold
        decision = 'adopt';
      } else if (testRate < controlRate * 0.9) {
        decision = 'reject';
      }
    }

    // Update experiment - CRITICAL: Include business_id filter
    await db.prepare(`
      UPDATE experiments
      SET decision = ?, end_date = CURRENT_TIMESTAMP
      WHERE id = ? AND business_id = ?
    `).bind(decision, experiment.id, businessId).run();


    // Apply decision
    if (decision === 'adopt' && experiment.variants.test) {
      await this.applyExperimentResults(experiment);
    }
  }

  // Apply successful experiment results
  private async applyExperimentResults(experiment: any): Promise<void> {

    // This would update strategies, prompts, or other components
    // based on the successful experiment
  }

  // Check experiment progress
  private async checkExperimentProgress(experiment: any, businessId: string): Promise<void> {
    // Monitor experiment progress and make adjustments if needed
    const db = this.env.DB_CRM;

    const stats = await db.prepare(`
      SELECT
        COUNT(*) as total_interactions,
        AVG(CASE WHEN outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate
      FROM interactions
      WHERE business_id = ? AND created_at >= ?
        AND (variant_id IN (?, ?) OR strategy_id = ?)
    `).bind(
      businessId,
      experiment.startDate,
      experiment.variants.control?.id,
      experiment.variants.test?.id,
      experiment.strategyId
    ).first();

    if ((stats?.total_interactions as number || 0) < 10) {
    } else {
    }
  }

  // Schedule recurring tasks
  private async scheduleRecurringTasks(): Promise<void> {
    // Pattern analysis - every 6 hours
    setInterval(async () => {
      await this.queueTask({
        id: `scheduled_patterns_${Date.now()}`,
        type: 'analyze_patterns',
        data: { type: 'comprehensive' },
        priority: 'low'
      });
    }, 6 * 60 * 60 * 1000);

    // Pattern validation - daily
    setInterval(async () => {
      await this.queueTask({
        id: `scheduled_validation_${Date.now()}`,
        type: 'validate_patterns',
        data: {},
        priority: 'low'
      });
    }, 24 * 60 * 60 * 1000);

    // Playbook updates - twice daily
    setInterval(async () => {
      await this.queueTask({
        id: `scheduled_playbooks_${Date.now()}`,
        type: 'update_playbooks',
        data: { reason: 'scheduled' },
        priority: 'low'
      });
    }, 12 * 60 * 60 * 1000);

    // Experiment monitoring - every hour
    setInterval(async () => {
      await this.queueTask({
        id: `scheduled_experiments_${Date.now()}`,
        type: 'run_experiments',
        data: {},
        priority: 'medium'
      });
    }, 60 * 60 * 1000);

  }

  // Utility function to sleep
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Get worker status
  async getStatus(): Promise<{
    isProcessing: boolean;
    queueLength: number;
    taskQueue: LearningTask[];
  }> {
    return {
      isProcessing: this.isProcessing,
      queueLength: this.taskQueue.length,
      taskQueue: this.taskQueue
    };
  }
}

// Export for Cloudflare Workers
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/worker/status') {
      const worker = new LearningWorker(env);
      const status = await worker.getStatus();

      return new Response(JSON.stringify(status), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (url.pathname === '/worker/queue' && request.method === 'POST') {
      const task = await request.json() as LearningTask;
      const worker = new LearningWorker(env);
      await worker.queueTask(task);

      return new Response(JSON.stringify({ success: true, message: 'Task queued' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Start worker if not already running
    if (url.pathname === '/worker/start') {
      const worker = new LearningWorker(env);
      worker.start().catch(error => {
      });

      return new Response(JSON.stringify({ success: true, message: 'Worker started' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Learning Worker', { status: 200 });
  },

  // Scheduled handler for Cloudflare Workers
  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    const worker = new LearningWorker(env);

    // Run scheduled pattern analysis
    await worker.queueTask({
      id: `cron_patterns_${Date.now()}`,
      type: 'analyze_patterns',
      data: { type: 'comprehensive' },
      priority: 'medium'
    });

    // Process queued tasks
    const status = await worker.getStatus();
    if (!status.isProcessing && status.queueLength > 0) {
      worker.start().catch(error => {
      });
    }
  }
};