/**
 * Task Queue Manager with Backpressure Control
 * Manages task execution with rate limiting and system protection
 */

import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { AgentTask, TaskPriority, BusinessContext } from './types';
import { generateSecureToken, sanitizeBusinessId } from './security-utils';
import { AuditLogger, AuditEventType } from './audit-logger';

export interface QueuedTask {
  id: string;
  task: AgentTask;
  priority: TaskPriority;
  businessId: string;
  userId: string;
  enqueuedAt: number;
  attempts: number;
  lastAttempt?: number;
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'deferred';
  error?: string;
  deferredUntil?: number;
}

export interface QueueConfig {
  maxQueueDepth: number;
  maxConcurrentTasks: number;
  maxTasksPerBusiness: number;
  maxTasksPerSecond: number;
  taskTimeout: number;
  retryDelay: number;
  maxRetries: number;
  enablePriorityQueue: boolean;
  backpressureThreshold: number;
}

export interface QueueMetrics {
  queueDepth: number;
  processingCount: number;
  completedCount: number;
  failedCount: number;
  deferredCount: number;
  avgWaitTime: number;
  avgProcessingTime: number;
  throughput: number;
  backpressure: boolean;
}

export interface BackpressureStrategy {
  shouldAccept(metrics: QueueMetrics, task: AgentTask): boolean;
  getDeferralTime(metrics: QueueMetrics): number;
  getPriorityBoost(task: AgentTask, waitTime: number): number;
}

export // TODO: Consider splitting TaskQueueManager into smaller, focused classes
class TaskQueueManager {
  private logger: Logger;
  private kv: KVNamespace;
  private db: D1Database;
  private auditLogger: AuditLogger;
  private config: QueueConfig;

  private queue: Map<string, QueuedTask> = new Map();
  private processingTasks: Map<string, QueuedTask> = new Map();
  private businessQueues: Map<string, Set<string>> = new Map();

  private metrics: QueueMetrics = {
    queueDepth: 0,
    processingCount: 0,
    completedCount: 0,
    failedCount: 0,
    deferredCount: 0,
    avgWaitTime: 0,
    avgProcessingTime: 0,
    throughput: 0,
    backpressure: false
  };

  private throughputWindow: number[] = [];
  private waitTimes: number[] = [];
  private processingTimes: number[] = [];

  private backpressureStrategy: BackpressureStrategy;
  private processingInterval?: NodeJS.Timeout;
  private metricsInterval?: NodeJS.Timeout;

  constructor(kv: KVNamespace, db: D1Database, config?: Partial<QueueConfig>) {
    this.logger = new Logger();
    this.kv = kv;
    this.db = db;
    this.auditLogger = AuditLogger.getInstance(db);

    this.config = {
      maxQueueDepth: 1000,
      maxConcurrentTasks: 50,
      maxTasksPerBusiness: 10,
      maxTasksPerSecond: 100,
      taskTimeout: 30000,
      retryDelay: 5000,
      maxRetries: 3,
      enablePriorityQueue: true,
      backpressureThreshold: 0.8,
      ...config
    };

    this.backpressureStrategy = new AdaptiveBackpressureStrategy(this.config);
    this.startProcessing();
    this.startMetricsCollection();
  }

  /**
   * Enqueue a task for processing
   */
  async enqueue(task: AgentTask): Promise<{
    accepted: boolean;
    queueId?: string;
    reason?: string;
    deferredUntil?: number;
  }> {
    try {
      const safeBusinessId = sanitizeBusinessId(task.context.businessId);

      // Check backpressure
      if (!this.backpressureStrategy.shouldAccept(this.metrics, task)) {
        const deferralTime = this.backpressureStrategy.getDeferralTime(this.metrics);

        await this.auditLogger.log(
          AuditEventType.TASK_REJECTED,
          'medium',
          safeBusinessId,
          task.context.userId,
          {
            reason: 'Backpressure active',
            queueDepth: this.metrics.queueDepth,
            deferredUntil: Date.now() + deferralTime
          },
          { taskId: task.id }
        );

        return {
          accepted: false,
          reason: 'System under high load, please retry later',
          deferredUntil: Date.now() + deferralTime
        };
      }

      // Check queue depth
      if (this.queue.size >= this.config.maxQueueDepth) {
        return {
          accepted: false,
          reason: 'Queue is full'
        };
      }

      // Check per-business limit
      const businessQueue = this.businessQueues.get(safeBusinessId) || new Set();
      if (businessQueue.size >= this.config.maxTasksPerBusiness) {
        return {
          accepted: false,
          reason: 'Business task limit exceeded'
        };
      }

      // Create queued task
      const queueId = generateSecureToken(16);
      const queuedTask: QueuedTask = {
        id: queueId,
        task,
        priority: task.priority,
        businessId: safeBusinessId,
        userId: task.context.userId,
        enqueuedAt: Date.now(),
        attempts: 0,
        status: 'pending'
      };

      // Add to queue
      this.queue.set(queueId, queuedTask);
      businessQueue.add(queueId);
      this.businessQueues.set(safeBusinessId, businessQueue);

      // Update metrics
      this.metrics.queueDepth = this.queue.size;

      // Persist to database
      await this.persistQueuedTask(queuedTask);

      this.logger.info('Task enqueued', {
        queueId,
        taskId: task.id,
        priority: task.priority,
        queueDepth: this.metrics.queueDepth
      });

      return {
        accepted: true,
        queueId
      };

    } catch (error) {
      this.logger.error('Failed to enqueue task', error, {
        taskId: task.id
      });

      return {
        accepted: false,
        reason: 'Failed to enqueue task'
      };
    }
  }

  /**
   * Process tasks from the queue
   */
  private async processTasks(): Promise<void> {
    // Check if we can process more tasks
    if (this.processingTasks.size >= this.config.maxConcurrentTasks) {
      return;
    }

    // Get next tasks to process
    const tasksToProcess = this.getNextTasks(
      this.config.maxConcurrentTasks - this.processingTasks.size
    );

    for (const queuedTask of tasksToProcess) {
      this.processTask(queuedTask).catch(error => {
        this.logger.error('Task processing failed', error, {
          queueId: queuedTask.id,
          taskId: queuedTask.task.id
        });
      });
    }
  }

  /**
   * Process a single task
   */
  private async processTask(queuedTask: QueuedTask): Promise<void> {
    const startTime = Date.now();

    try {
      // Move to processing
      this.queue.delete(queuedTask.id);
      this.processingTasks.set(queuedTask.id, queuedTask);
      queuedTask.status = 'processing';
      queuedTask.lastAttempt = startTime;
      queuedTask.attempts++;

      // Update metrics
      this.metrics.queueDepth = this.queue.size;
      this.metrics.processingCount = this.processingTasks.size;

      // Record wait time
      const waitTime = startTime - queuedTask.enqueuedAt;
      this.waitTimes.push(waitTime);
      if (this.waitTimes.length > 100) this.waitTimes.shift();

      // Execute task with timeout
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Task timeout')), this.config.taskTimeout);
      });

      // Note: Actual task execution would happen here
      // For now, we'll simulate it
      await Promise.race([
        this.executeTask(queuedTask.task),
        timeoutPromise
      ]);

      // Task completed successfully
      queuedTask.status = 'completed';
      this.metrics.completedCount++;

      // Record processing time
      const processingTime = Date.now() - startTime;
      this.processingTimes.push(processingTime);
      if (this.processingTimes.length > 100) this.processingTimes.shift();

      // Update throughput
      this.throughputWindow.push(Date.now());
      const cutoff = Date.now() - 60000; // Last minute
      this.throughputWindow = this.throughputWindow.filter(t => t > cutoff);

      this.logger.info('Task completed', {
        queueId: queuedTask.id,
        taskId: queuedTask.task.id,
        waitTime,
        processingTime
      });

    } catch (error) {
      queuedTask.status = 'failed';
      queuedTask.error = error instanceof Error ? error.message : 'Unknown error';
      this.metrics.failedCount++;

      // Check if we should retry
      if (queuedTask.attempts < this.config.maxRetries) {
        // Defer for retry
        queuedTask.status = 'deferred';
        queuedTask.deferredUntil = Date.now() + this.config.retryDelay;
        this.metrics.deferredCount++;

        // Re-add to queue
        this.queue.set(queuedTask.id, queuedTask);

        this.logger.warn('Task deferred for retry', {
          queueId: queuedTask.id,
          attempt: queuedTask.attempts,
          deferredUntil: queuedTask.deferredUntil
        });
      } else {
        this.logger.error('Task failed after max retries', error, {
          queueId: queuedTask.id,
          taskId: queuedTask.task.id,
          attempts: queuedTask.attempts
        });
      }

    } finally {
      // Remove from processing
      this.processingTasks.delete(queuedTask.id);
      this.metrics.processingCount = this.processingTasks.size;

      // Remove from business queue if completed or failed
      if (queuedTask.status === 'completed' ||
          (queuedTask.status === 'failed' && queuedTask.attempts >= this.config.maxRetries)) {
        const businessQueue = this.businessQueues.get(queuedTask.businessId);
        if (businessQueue) {
          businessQueue.delete(queuedTask.id);
          if (businessQueue.size === 0) {
            this.businessQueues.delete(queuedTask.businessId);
          }
        }
      }

      // Update database
      await this.updateQueuedTask(queuedTask);
    }
  }

  /**
   * Get next tasks to process based on priority
   */
  private getNextTasks(limit: number): QueuedTask[] {
    const now = Date.now();
    const tasks: QueuedTask[] = [];

    // Convert queue to array and sort by priority
    const sortedTasks = Array.from(this.queue.values())
      .filter(task => {
        // Skip deferred tasks
        if (task.status === 'deferred' && task.deferredUntil && task.deferredUntil > now) {
          return false;
        }
        return task.status === 'pending' || task.status === 'deferred';
      })
      .sort((a, b) => {
        if (!this.config.enablePriorityQueue) {
          return a.enqueuedAt - b.enqueuedAt; // FIFO
        }

        // Priority with age boost
        const aWaitTime = now - a.enqueuedAt;
        const bWaitTime = now - b.enqueuedAt;

        const aScore = this.getPriorityScore(a.priority) +
          this.backpressureStrategy.getPriorityBoost(a.task, aWaitTime);
        const bScore = this.getPriorityScore(b.priority) +
          this.backpressureStrategy.getPriorityBoost(b.task, bWaitTime);

        return bScore - aScore; // Higher score = higher priority
      });

    // Take up to limit
    for (const task of sortedTasks) {
      if (tasks.length >= limit) break;

      // Check rate limit
      if (this.throughputWindow.length >= this.config.maxTasksPerSecond) {
        const oldestAllowed = Date.now() - 1000;
        if (this.throughputWindow[0] > oldestAllowed) {
          break; // Rate limit reached
        }
      }

      tasks.push(task);
    }

    return tasks;
  }

  /**
   * Get priority score
   */
  private getPriorityScore(priority: TaskPriority): number {
    const scores = {
      critical: 1000,
      high: 100,
      medium: 10,
      low: 1
    };
    return scores[priority] || 1;
  }

  /**
   * Execute task (placeholder - actual execution handled by orchestrator)
   */
  private async executeTask(task: AgentTask): Promise<void> {
    // This would call the orchestrator's executeTask method
    // For now, simulate with a delay
    await new Promise(resolve => setTimeout(resolve, Math.random() * 1000 + 500));
  }

  /**
   * Update queue metrics
   */
  private updateMetrics(): void {
    // Calculate average wait time
    if (this.waitTimes.length > 0) {
      this.metrics.avgWaitTime = this.waitTimes.reduce((a, b) => a + b, 0) / this.waitTimes.length;
    }

    // Calculate average processing time
    if (this.processingTimes.length > 0) {
      this.metrics.avgProcessingTime = this.processingTimes.reduce((a, b) => a + b, 0) / this.processingTimes.length;
    }

    // Calculate throughput (tasks per minute)
    this.metrics.throughput = this.throughputWindow.length;

    // Check backpressure
    const utilizationRatio = this.metrics.queueDepth / this.config.maxQueueDepth;
    this.metrics.backpressure = utilizationRatio >= this.config.backpressureThreshold;

    if (this.metrics.backpressure) {
      this.logger.warn('Backpressure activated', {
        queueDepth: this.metrics.queueDepth,
        maxDepth: this.config.maxQueueDepth,
        utilizationRatio
      });
    }
  }

  /**
   * Persist queued task to database
   */
  private async persistQueuedTask(task: QueuedTask): Promise<void> {
    try {
      await this.db.prepare(`
        INSERT INTO agent_task_queue (
          id, task_id, business_id, user_id, priority,
          task_data, status, enqueued_at, attempts
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        task.id,
        task.task.id,
        task.businessId,
        task.userId,
        task.priority,
        JSON.stringify(task.task),
        task.status,
        task.enqueuedAt,
        task.attempts
      ).run();
    } catch (error) {
      this.logger.error('Failed to persist queued task', error, {
        queueId: task.id
      });
    }
  }

  /**
   * Update queued task in database
   */
  private async updateQueuedTask(task: QueuedTask): Promise<void> {
    try {
      await this.db.prepare(`
        UPDATE agent_task_queue
        SET status = ?, attempts = ?, last_attempt = ?,
            error = ?, deferred_until = ?, completed_at = ?
        WHERE id = ?
      `).bind(
        task.status,
        task.attempts,
        task.lastAttempt || null,
        task.error || null,
        task.deferredUntil || null,
        task.status === 'completed' ? Date.now() : null,
        task.id
      ).run();
    } catch (error) {
      this.logger.error('Failed to update queued task', error, {
        queueId: task.id
      });
    }
  }

  /**
   * Start processing loop
   */
  private startProcessing(): void {
    this.processingInterval = setInterval(() => {
      this.processTasks().catch(error => {
        this.logger.error('Processing loop error', error);
      });
    }, 100) as any; // Process every 100ms
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    this.metricsInterval = setInterval(() => {
      this.updateMetrics();
    }, 1000) as any; // Update metrics every second
  }

  /**
   * Get current queue metrics
   */
  getMetrics(): QueueMetrics {
    return { ...this.metrics };
  }

  /**
   * Get queue status for a business
   */
  async getBusinessQueueStatus(businessId: string): Promise<{
    queuedTasks: number;
    processingTasks: number;
    completedTasks: number;
    failedTasks: number;
  }> {
    const safeBusinessId = sanitizeBusinessId(businessId);
    const businessQueue = this.businessQueues.get(safeBusinessId) || new Set();

    let queued = 0;
    let processing = 0;

    for (const queueId of businessQueue) {
      if (this.queue.has(queueId)) queued++;
      if (this.processingTasks.has(queueId)) processing++;
    }

    // Get historical data from database
    const result = await this.db.prepare(`
      SELECT
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed
      FROM agent_task_queue
      WHERE business_id = ?
      AND enqueued_at > ?
    `).bind(safeBusinessId, Date.now() - 86400000).first(); // Last 24 hours

    return {
      queuedTasks: queued,
      processingTasks: processing,
      completedTasks: (result?.completed as number) || 0,
      failedTasks: (result?.failed as number) || 0
    };
  }

  /**
   * Recover queue from database on startup
   */
  async recoverQueue(): Promise<void> {
    try {
      const result = await this.db.prepare(`
        SELECT * FROM agent_task_queue
        WHERE status IN ('pending', 'processing', 'deferred')
        ORDER BY priority DESC, enqueued_at ASC
        LIMIT ?
      `).bind(this.config.maxQueueDepth).all();

      const tasks = result.results || [];

      for (const row of tasks) {
        const queuedTask: QueuedTask = {
          id: row.id as string,
          task: JSON.parse(row.task_data as string),
          priority: row.priority as TaskPriority,
          businessId: row.business_id as string,
          userId: row.user_id as string,
          enqueuedAt: row.enqueued_at as number,
          attempts: row.attempts as number,
          lastAttempt: row.last_attempt as number | undefined,
          status: row.status === 'processing' ? 'pending' : row.status as any,
          error: row.error as string | undefined,
          deferredUntil: row.deferred_until as number | undefined
        };

        // Re-add to queue
        this.queue.set(queuedTask.id, queuedTask);

        // Update business queues
        const businessQueue = this.businessQueues.get(queuedTask.businessId) || new Set();
        businessQueue.add(queuedTask.id);
        this.businessQueues.set(queuedTask.businessId, businessQueue);
      }

      this.metrics.queueDepth = this.queue.size;

      this.logger.info('Queue recovered from database', {
        recoveredTasks: tasks.length
      });

    } catch (error) {
      this.logger.error('Failed to recover queue', error);
    }
  }

  /**
   * Shutdown queue manager
   */
  async shutdown(): Promise<void> {
    if (this.processingInterval) {
      clearInterval(this.processingInterval);
    }
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }

    // Wait for processing tasks to complete
    const timeout = Date.now() + 10000; // 10 second shutdown timeout
    while (this.processingTasks.size > 0 && Date.now() < timeout) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    // Save queue state
    for (const task of this.queue.values()) {
      await this.updateQueuedTask(task);
    }

    this.logger.info('Task queue manager shutdown', {
      remainingTasks: this.queue.size,
      processingTasks: this.processingTasks.size
    });
  }
}

/**
 * Adaptive backpressure strategy
 */
class AdaptiveBackpressureStrategy implements BackpressureStrategy {
  private config: QueueConfig;

  constructor(config: QueueConfig) {
    this.config = config;
  }

  shouldAccept(metrics: QueueMetrics, task: AgentTask): boolean {
    // Always accept critical tasks
    if (task.priority === 'critical') {
      return true;
    }

    // Check if backpressure is active
    if (metrics.backpressure) {
      // Only accept high priority when under pressure
      return task.priority === 'high';
    }

    // Check utilization
    const utilization = metrics.queueDepth / this.config.maxQueueDepth;

    // Graduated acceptance based on priority and utilization
    if (task.priority === 'high') {
      return utilization < 0.95;
    } else if (task.priority === 'medium') {
      return utilization < 0.8;
    } else {
      return utilization < 0.6;
    }
  }

  getDeferralTime(metrics: QueueMetrics): number {
    // Calculate based on queue depth and processing rate
    const estimatedWait = metrics.queueDepth / Math.max(metrics.throughput / 60, 1);

    // Add buffer based on utilization
    const utilization = metrics.queueDepth / this.config.maxQueueDepth;
    const buffer = utilization * 10000; // Up to 10 seconds buffer

    return Math.min(estimatedWait * 1000 + buffer, 60000); // Max 1 minute deferral
  }

  getPriorityBoost(task: AgentTask, waitTime: number): number {
    // Boost priority for tasks that have been waiting
    // Prevents starvation of lower priority tasks

    const ageMinutes = waitTime / 60000;

    // Exponential boost after certain thresholds
    if (ageMinutes > 5) {
      return 500; // Major boost after 5 minutes
    } else if (ageMinutes > 2) {
      return 100; // Moderate boost after 2 minutes
    } else if (ageMinutes > 1) {
      return 50; // Small boost after 1 minute
    }

    return ageMinutes * 10; // Linear boost for first minute
  }
}