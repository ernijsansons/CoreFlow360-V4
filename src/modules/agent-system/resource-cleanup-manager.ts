/**
 * Resource Cleanup Manager
 * Prevents memory leaks through automatic resource disposal
 */

import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';

export interface CleanupTask {
  id: string;
  type: 'memory' | 'cache' | 'connection' | 'timer' | 'listener' | 'stream';
  resource: any;
  cleanup: () => Promise<void> | void;
  ttl?: number;
  createdAt: number;
  lastAccessed: number;
  accessCount: number;
  metadata?: Record<string, any>;
}

export interface CleanupConfig {
  maxMemoryUsage: number; // bytes
  maxCacheSize: number;
  cleanupInterval: number; // ms
  resourceTTL: number; // ms
  enableAutoCleanup: boolean;
  aggressiveCleanup: boolean;
}

export interface ResourceMetrics {
  totalResources: number;
  memoryUsage: number;
  cacheSize: number;
  activeTimers: number;
  activeListeners: number;
  cleanedCount: number;
  leaksSuspected: number;
}

export // TODO: Consider splitting ResourceCleanupManager into smaller, focused classes
class ResourceCleanupManager {
  private logger: Logger;
  private resources = new Map<string, CleanupTask>();
  private weakRefs = new WeakMap<object, CleanupTask>();
  private timers = new Set<NodeJS.Timeout>();
  private intervals = new Set<NodeJS.Timeout>();
  private listeners = new Map<string, { target: any; event: string; handler: Function }>();
  private streams = new Set<any>();

  private config: CleanupConfig;
  private cleanupInterval?: NodeJS.Timeout;
  private metrics: ResourceMetrics = {
    totalResources: 0,
    memoryUsage: 0,
    cacheSize: 0,
    activeTimers: 0,
    activeListeners: 0,
    cleanedCount: 0,
    leaksSuspected: 0
  };

  private memoryMonitor?: MemoryMonitor;
  private leakDetector?: LeakDetector;

  constructor(config?: Partial<CleanupConfig>) {
    this.logger = new Logger();
    this.config = {
      maxMemoryUsage: 500 * 1024 * 1024, // 500MB
      maxCacheSize: 10000,
      cleanupInterval: 60000, // 1 minute
      resourceTTL: 300000, // 5 minutes
      enableAutoCleanup: true,
      aggressiveCleanup: false,
      ...config
    };

    this.memoryMonitor = new MemoryMonitor(this);
    this.leakDetector = new LeakDetector(this);

    if (this.config.enableAutoCleanup) {
      this.startAutoCleanup();
    }
  }

  /**
   * Register a resource for tracking and cleanup
   */
  registerResource<T extends object>(
    id: string,
    resource: T,
    cleanup: () => Promise<void> | void,
    options?: {
      ttl?: number;
      metadata?: Record<string, any>;
      weak?: boolean;
    }
  ): T {
    const task: CleanupTask = {
      id,
      type: this.detectResourceType(resource),
      resource: options?.weak ? new WeakRef(resource) : resource,
      cleanup,
      ttl: options?.ttl || this.config.resourceTTL,
      createdAt: Date.now(),
      lastAccessed: Date.now(),
      accessCount: 0,
      metadata: options?.metadata
    };

    this.resources.set(id, task);

    if (options?.weak) {
      this.weakRefs.set(resource, task);
    }

    this.metrics.totalResources++;

    this.logger.debug('Resource registered', {
      id,
      type: task.type,
      ttl: task.ttl
    });

    // Return proxy to track access
    return this.createResourceProxy(resource, task);
  }

  /**
   * Register a timer for cleanup
   */
  registerTimer(timer: NodeJS.Timeout): void {
    this.timers.add(timer);
    this.metrics.activeTimers++;
  }

  /**
   * Register an interval for cleanup
   */
  registerInterval(interval: NodeJS.Timeout): void {
    this.intervals.add(interval);
    this.metrics.activeTimers++;
  }

  /**
   * Register an event listener for cleanup
   */
  registerListener(
    id: string,
    target: any,
    event: string,
    handler: Function
  ): void {
    this.listeners.set(id, { target, event, handler });
    this.metrics.activeListeners++;
  }

  /**
   * Register a stream for cleanup
   */
  registerStream(stream: any): void {
    this.streams.add(stream);

    // Auto-cleanup on stream end
    if (stream.on) {
      stream.on('end', () => this.unregisterStream(stream));
      stream.on('error', () => this.unregisterStream(stream));
    }
  }

  /**
   * Unregister a stream
   */
  private unregisterStream(stream: any): void {
    this.streams.delete(stream);
  }

  /**
   * Manual cleanup of a specific resource
   */
  async cleanupResource(id: string): Promise<void> {
    const task = this.resources.get(id);
    if (!task) return;

    try {
      await task.cleanup();
      this.resources.delete(id);
      this.metrics.cleanedCount++;

      this.logger.debug('Resource cleaned up', { id, type: task.type });

    } catch (error) {
      this.logger.error('Resource cleanup failed', error, { id });
    }
  }

  /**
   * Perform automatic cleanup
   */
  private async performCleanup(): Promise<void> {
    const startTime = Date.now();
    const now = Date.now();
    let cleanedCount = 0;

    try {
      // Check memory usage
      const memoryUsage = this.getMemoryUsage();
      const memoryPressure = memoryUsage > this.config.maxMemoryUsage;

      if (memoryPressure) {
        this.logger.warn('Memory pressure detected', {
          usage: memoryUsage,
          limit: this.config.maxMemoryUsage
        });
      }

      // Cleanup expired resources
      for (const [id, task] of this.resources) {
        const shouldClean = this.shouldCleanResource(task, now, memoryPressure);

        if (shouldClean) {
          await this.cleanupResource(id);
          cleanedCount++;
        }
      }

      // Cleanup weak references
      this.cleanupWeakReferences();

      // Check for memory leaks
      if (this.leakDetector) {
        const leaks = await this.leakDetector.detectLeaks();
        if (leaks.length > 0) {
          this.metrics.leaksSuspected = leaks.length;
          this.logger.warn('Potential memory leaks detected', { count: leaks.length });
        }
      }

      // Force garbage collection if available and under pressure
      if (memoryPressure && global.gc) {
        global.gc();
        this.logger.info('Forced garbage collection due to memory pressure');
      }

      const duration = Date.now() - startTime;
      this.logger.info('Cleanup completed', {
        cleanedCount,
        duration,
        totalResources: this.resources.size,
        memoryUsage
      });

    } catch (error) {
      this.logger.error('Cleanup failed', error);
    }
  }

  /**
   * Determine if resource should be cleaned
   */
  private shouldCleanResource(
    task: CleanupTask,
    now: number,
    memoryPressure: boolean
  ): boolean {
    // Always clean expired resources
    if (task.ttl && (now - task.lastAccessed) > task.ttl) {
      return true;
    }

    // Aggressive cleanup under memory pressure
    if (memoryPressure && this.config.aggressiveCleanup) {
      // Clean resources not accessed recently
      const idleTime = now - task.lastAccessed;
      if (idleTime > 60000) { // 1 minute idle
        return true;
      }

      // Clean low-priority resources
      if (task.metadata?.priority === 'low') {
        return true;
      }
    }

    // Check cache size limit
    if (task.type === 'cache' && this.resources.size > this.config.maxCacheSize) {
      // Clean oldest cache entries
      return task.accessCount < 2 && (now - task.createdAt) > 30000;
    }

    return false;
  }

  /**
   * Cleanup weak references
   */
  private cleanupWeakReferences(): void {
    const deadRefs: string[] = [];

    for (const [id, task] of this.resources) {
      if (task.resource instanceof WeakRef) {
        const deref = task.resource.deref();
        if (!deref) {
          deadRefs.push(id);
        }
      }
    }

    for (const id of deadRefs) {
      this.resources.delete(id);
      this.metrics.cleanedCount++;
    }

    if (deadRefs.length > 0) {
      this.logger.debug('Cleaned up dead weak references', { count: deadRefs.length });
    }
  }

  /**
   * Create resource proxy for access tracking
   */
  private createResourceProxy<T extends object>(resource: T, task: CleanupTask): T {
    if (typeof resource !== 'object' || resource === null) {
      return resource;
    }

    return new Proxy(resource, {
      get: (target, prop) => {
        task.lastAccessed = Date.now();
        task.accessCount++;
        return Reflect.get(target, prop);
      },
      set: (target, prop, value) => {
        task.lastAccessed = Date.now();
        task.accessCount++;
        return Reflect.set(target, prop, value);
      }
    });
  }

  /**
   * Detect resource type
   */
  private detectResourceType(resource: any): CleanupTask['type'] {
    if (resource instanceof Map || resource instanceof Set) {
      return 'cache';
    }
    if (resource.on && resource.emit) {
      return 'listener';
    }
    if (resource.pipe || resource.readable || resource.writable) {
      return 'stream';
    }
    if (resource.close || resource.end || resource.destroy) {
      return 'connection';
    }
    if (typeof resource === 'function' && resource.name?.includes('Timeout')) {
      return 'timer';
    }
    return 'memory';
  }

  /**
   * Get current memory usage
   */
  private getMemoryUsage(): number {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const usage = process.memoryUsage();
      return usage.heapUsed;
    }
    // Estimate based on resource count
    return this.resources.size * 1000; // Rough estimate
  }

  /**
   * Cleanup all timers
   */
  cleanupAllTimers(): void {
    for (const timer of this.timers) {
      clearTimeout(timer);
    }
    this.timers.clear();

    for (const interval of this.intervals) {
      clearInterval(interval);
    }
    this.intervals.clear();

    this.metrics.activeTimers = 0;
    this.logger.info('All timers cleaned up');
  }

  /**
   * Cleanup all listeners
   */
  cleanupAllListeners(): void {
    for (const [id, { target, event, handler }] of this.listeners) {
      if (target.removeEventListener) {
        target.removeEventListener(event, handler);
      } else if (target.off) {
        target.off(event, handler);
      }
    }
    this.listeners.clear();
    this.metrics.activeListeners = 0;
    this.logger.info('All listeners cleaned up');
  }

  /**
   * Cleanup all streams
   */
  async cleanupAllStreams(): Promise<void> {
    for (const stream of this.streams) {
      try {
        if (stream.destroy) {
          stream.destroy();
        } else if (stream.end) {
          stream.end();
        } else if (stream.close) {
          await stream.close();
        }
      } catch (error) {
        this.logger.error('Stream cleanup failed', error);
      }
    }
    this.streams.clear();
    this.logger.info('All streams cleaned up');
  }

  /**
   * Start automatic cleanup
   */
  private startAutoCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.performCleanup().catch(error => {
        this.logger.error('Auto cleanup failed', error);
      });
    }, this.config.cleanupInterval) as any;

    this.registerInterval(this.cleanupInterval);
  }

  /**
   * Get current metrics
   */
  getMetrics(): ResourceMetrics {
    return {
      ...this.metrics,
      totalResources: this.resources.size,
      memoryUsage: this.getMemoryUsage(),
      activeTimers: this.timers.size + this.intervals.size,
      activeListeners: this.listeners.size
    };
  }

  /**
   * Shutdown cleanup manager
   */
  async shutdown(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    // Cleanup all resources
    const cleanupPromises: Promise<void>[] = [];
    for (const [id, task] of this.resources) {
      cleanupPromises.push(this.cleanupResource(id));
    }

    await Promise.allSettled(cleanupPromises);

    // Cleanup system resources
    this.cleanupAllTimers();
    this.cleanupAllListeners();
    await this.cleanupAllStreams();

    this.logger.info('Resource cleanup manager shutdown', {
      cleanedResources: cleanupPromises.length
    });
  }
}

/**
 * Memory monitor for detecting pressure
 */
class MemoryMonitor {
  private manager: ResourceCleanupManager;
  private samples: number[] = [];
  private sampleInterval?: NodeJS.Timeout;

  constructor(manager: ResourceCleanupManager) {
    this.manager = manager;
    this.startMonitoring();
  }

  private startMonitoring(): void {
    this.sampleInterval = setInterval(() => {
      if (typeof process !== 'undefined' && process.memoryUsage) {
        const usage = process.memoryUsage();
        this.samples.push(usage.heapUsed);

        if (this.samples.length > 60) {
          this.samples.shift();
        }

        this.detectTrend();
      }
    }, 1000) as any; // Sample every second
  }

  private detectTrend(): void {
    if (this.samples.length < 10) return;

    const recent = this.samples.slice(-10);
    const older = this.samples.slice(-20, -10);

    const recentAvg = recent.reduce((a, b) => a + b, 0) / recent.length;
    const olderAvg = older.reduce((a, b) => a + b, 0) / older.length;

    const growthRate = (recentAvg - olderAvg) / olderAvg;

    if (growthRate > 0.2) { // 20% growth
      (this.manager as any).logger.warn('Rapid memory growth detected', {
        growthRate: `${(growthRate * 100).toFixed(2)}%`,
        recentAvg,
        olderAvg
      });
    }
  }

  stop(): void {
    if (this.sampleInterval) {
      clearInterval(this.sampleInterval);
    }
  }
}

/**
 * Leak detector for identifying memory leaks
 */
class LeakDetector {
  private manager: ResourceCleanupManager;
  private snapshots: Map<string, { count: number; size: number; time: number }> = new Map();

  constructor(manager: ResourceCleanupManager) {
    this.manager = manager;
  }

  async detectLeaks(): Promise<Array<{ id: string; reason: string }>> {
    const leaks: Array<{ id: string; reason: string }> = [];
    const now = Date.now();

    // Analyze resources
    const resources = (this.manager as any).resources as Map<string, CleanupTask>;

    for (const [id, task] of resources) {
      // Check for resources that should have been cleaned
      if (task.ttl && (now - task.lastAccessed) > task.ttl * 2) {
        leaks.push({
          id,
          reason: 'Resource exceeded TTL by 2x'
        });
      }

      // Check for resources with no recent access but high memory
      if (task.accessCount === 0 && (now - task.createdAt) > 60000) {
        leaks.push({
          id,
          reason: 'Unused resource for over 1 minute'
        });
      }

      // Check for growing resources
      const snapshot = this.snapshots.get(id);
      if (snapshot) {
        const currentSize = this.estimateSize(task.resource);
        if (currentSize > snapshot.size * 2) {
          leaks.push({
            id,
            reason: `Resource size doubled: ${snapshot.size} -> ${currentSize}`
          });
        }
      }

      // Update snapshot
      this.snapshots.set(id, {
        count: task.accessCount,
        size: this.estimateSize(task.resource),
        time: now
      });
    }

    // Clean old snapshots
    for (const [id, snapshot] of this.snapshots) {
      if (!resources.has(id) || (now - snapshot.time) > 300000) {
        this.snapshots.delete(id);
      }
    }

    return leaks;
  }

  private estimateSize(resource: any): number {
    if (resource instanceof WeakRef) {
      resource = resource.deref();
      if (!resource) return 0;
    }

    if (typeof resource === 'string') {
      return resource.length * 2; // UTF-16
    }
    if (resource instanceof ArrayBuffer) {
      return resource.byteLength;
    }
    if (Array.isArray(resource)) {
      return resource.length * 8; // Rough estimate
    }
    if (resource instanceof Map || resource instanceof Set) {
      return resource.size * 16; // Rough estimate
    }

    return 100; // Default estimate
  }
}