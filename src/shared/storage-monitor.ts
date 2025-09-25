/**
 * Storage Monitoring and Management System
 * Monitors Durable Object storage usage and prevents storage limit violations
 */

import { Logger } from './logger';

export interface StorageMetrics {
  totalSizeBytes: number;
  keyCount: number;
  averageKeySize: number;
  largestKeySize: number;
  utilizationPercentage: number;
  estimatedTimeToFull?: number;
}

export interface StorageAlert {
  level: 'warning' | 'critical';
  threshold: number;
  currentUsage: number;
  message: string;
  recommendedActions: string[];
}

export interface StorageCleanupResult {
  itemsRemoved: number;
  bytesFreed: number;
  success: boolean;
  errors?: string[];
}

export class StorageMonitor {
  private logger: Logger;
  private storage: DurableObjectStorage;

  // Storage limits for Cloudflare Workers Durable Objects
  private readonly MAX_STORAGE_SIZE = 128 * 1024 * 1024; // 128MB limit
  private readonly WARNING_THRESHOLD = 0.8; // 80% warning
  private readonly CRITICAL_THRESHOLD = 0.95; // 95% critical
  private readonly MAX_KEYS_COUNT = 16384; // 16K keys limit
  private readonly MAX_KEY_SIZE = 2048; // 2KB per key max recommended

  constructor(storage: DurableObjectStorage) {
    this.logger = new Logger();
    this.storage = storage;
  }

  /**
   * Get comprehensive storage metrics
   */
  async getStorageMetrics(): Promise<StorageMetrics> {
    try {
      const startTime = performance.now();

      // List all keys to calculate metrics
      const keys = await this.storage.list();
      const keyCount = keys.size;

      if (keyCount === 0) {
        return {
          totalSizeBytes: 0,
          keyCount: 0,
          averageKeySize: 0,
          largestKeySize: 0,
          utilizationPercentage: 0
        };
      }

      // Sample storage to estimate total size
      let totalSizeBytes = 0;
      let largestKeySize = 0;
      const sampleSize = Math.min(100, keyCount); // Sample up to 100 keys
      const sampleKeys = Array.from(keys.keys()).slice(0, sampleSize);

      for (const key of sampleKeys) {
        try {
          const value = await this.storage.get(key);
          if (value !== undefined) {
            const serialized = JSON.stringify(value);
            const keySize = new TextEncoder().encode(key + serialized).length;
            totalSizeBytes += keySize;
            largestKeySize = Math.max(largestKeySize, keySize);
          }
        } catch (error) {
          this.logger.warn('Failed to read storage key for metrics', { key, error });
        }
      }

      // Extrapolate to total size
      const averageKeySize = totalSizeBytes / sampleSize;
      const estimatedTotalSize = averageKeySize * keyCount;

      const utilizationPercentage = (estimatedTotalSize / this.MAX_STORAGE_SIZE) * 100;

      // Estimate time to full based on recent growth (simplified)
      let estimatedTimeToFull: number | undefined;
      if (utilizationPercentage > 50) {
        const remainingBytes = this.MAX_STORAGE_SIZE - estimatedTotalSize;
        const growthRate = this.estimateGrowthRate();
        if (growthRate > 0) {
          estimatedTimeToFull = remainingBytes / growthRate; // seconds to full
        }
      }

      const executionTime = performance.now() - startTime;
      this.logger.debug('Storage metrics calculated', {
        keyCount,
        estimatedTotalSize,
        utilizationPercentage,
        executionTimeMs: executionTime
      });

      return {
        totalSizeBytes: estimatedTotalSize,
        keyCount,
        averageKeySize,
        largestKeySize,
        utilizationPercentage,
        estimatedTimeToFull
      };

    } catch (error) {
      this.logger.error('Failed to calculate storage metrics', error);
      throw error;
    }
  }

  /**
   * Check for storage alerts and warnings
   */
  async checkStorageAlerts(): Promise<StorageAlert[]> {
    const alerts: StorageAlert[] = [];

    try {
      const metrics = await this.getStorageMetrics();

      // Check total storage utilization
      if (metrics.utilizationPercentage >= this.CRITICAL_THRESHOLD * 100) {
        alerts.push({
          level: 'critical',
          threshold: this.CRITICAL_THRESHOLD * 100,
          currentUsage: metrics.utilizationPercentage,
          message: `Storage usage at critical level: ${metrics.utilizationPercentage.toFixed(1)}%`,
          recommendedActions: [
            'Immediate cleanup of old data required',
            'Review data retention policies',
            'Consider data archival or migration',
            'Implement automatic cleanup jobs'
          ]
        });
      } else if (metrics.utilizationPercentage >= this.WARNING_THRESHOLD * 100) {
        alerts.push({
          level: 'warning',
          threshold: this.WARNING_THRESHOLD * 100,
          currentUsage: metrics.utilizationPercentage,
          message: `Storage usage approaching limit: ${metrics.utilizationPercentage.toFixed(1)}%`,
          recommendedActions: [
            'Schedule cleanup of old data',
            'Review and optimize data structures',
            'Consider implementing data compression',
            'Monitor growth trends closely'
          ]
        });
      }

      // Check key count limits
      if (metrics.keyCount >= this.MAX_KEYS_COUNT * 0.9) {
        alerts.push({
          level: metrics.keyCount >= this.MAX_KEYS_COUNT * 0.95 ? 'critical' : 'warning',
          threshold: this.MAX_KEYS_COUNT,
          currentUsage: metrics.keyCount,
          message: `Key count approaching limit: ${metrics.keyCount}/${this.MAX_KEYS_COUNT}`,
          recommendedActions: [
            'Consolidate related data into fewer keys',
            'Cleanup expired or unused keys',
            'Consider using composite keys',
            'Implement key lifecycle management'
          ]
        });
      }

      // Check for oversized keys
      if (metrics.largestKeySize > this.MAX_KEY_SIZE) {
        alerts.push({
          level: 'warning',
          threshold: this.MAX_KEY_SIZE,
          currentUsage: metrics.largestKeySize,
          message: `Large key detected: ${metrics.largestKeySize} bytes`,
          recommendedActions: [
            'Break down large data structures',
            'Implement data pagination',
            'Use compression for large values',
            'Consider external storage for large data'
          ]
        });
      }

      return alerts;

    } catch (error) {
      this.logger.error('Failed to check storage alerts', error);
      return [{
        level: 'critical',
        threshold: 0,
        currentUsage: 0,
        message: 'Storage monitoring system failure',
        recommendedActions: ['Check storage monitor logs', 'Restart monitoring system']
      }];
    }
  }

  /**
   * Perform automatic storage cleanup
   */
  async performCleanup(options: {
    maxAge?: number; // milliseconds
    maxItems?: number;
    keyPatterns?: string[];
    dryRun?: boolean;
  } = {}): Promise<StorageCleanupResult> {
    const {
      maxAge = 7 * 24 * 60 * 60 * 1000, // 7 days default
      maxItems = 100,
      keyPatterns = [],
      dryRun = false
    } = options;

    const errors: string[] = [];
    let itemsRemoved = 0;
    let bytesFreed = 0;

    try {
      const allKeys = await this.storage.list();
      const now = Date.now();
      const keysToRemove: string[] = [];

      for (const [key, metadata] of allKeys.entries()) {
        try {
          let shouldRemove = false;

          // Check age-based cleanup
          if (maxAge > 0) {
            // Try to extract timestamp from key or use metadata
            const keyAge = this.extractKeyAge(key, metadata);
            if (keyAge && (now - keyAge) > maxAge) {
              shouldRemove = true;
            }
          }

          // Check pattern-based cleanup
          if (keyPatterns.length > 0) {
            for (const pattern of keyPatterns) {
              if (key.includes(pattern)) {
                shouldRemove = true;
                break;
              }
            }
          }

          if (shouldRemove) {
            keysToRemove.push(key);
          }

          // Limit cleanup batch size
          if (keysToRemove.length >= maxItems) {
            break;
          }

        } catch (error) {
          errors.push(`Failed to evaluate key ${key}: ${error}`);
        }
      }

      // Perform actual cleanup
      if (!dryRun && keysToRemove.length > 0) {
        for (const key of keysToRemove) {
          try {
            const value = await this.storage.get(key);
            if (value !== undefined) {
              const keySize = new TextEncoder().encode(JSON.stringify(value)).length;
              await this.storage.delete(key);
              itemsRemoved++;
              bytesFreed += keySize;
            }
          } catch (error) {
            errors.push(`Failed to delete key ${key}: ${error}`);
          }
        }
      } else if (dryRun) {
        itemsRemoved = keysToRemove.length;
        // Estimate bytes that would be freed
        for (const key of keysToRemove.slice(0, 10)) { // Sample estimation
          try {
            const value = await this.storage.get(key);
            if (value !== undefined) {
              bytesFreed += new TextEncoder().encode(JSON.stringify(value)).length;
            }
          } catch (error) {
            // Ignore errors in dry run estimation
          }
        }
        bytesFreed = Math.round((bytesFreed / Math.min(10, keysToRemove.length)) * keysToRemove.length);
      }

      const result = {
        itemsRemoved,
        bytesFreed,
        success: errors.length === 0,
        errors: errors.length > 0 ? errors : undefined
      };

      this.logger.info('Storage cleanup completed', {
        ...result,
        dryRun,
        keysEvaluated: allKeys.size
      });

      return result;

    } catch (error) {
      this.logger.error('Storage cleanup failed', error);
      return {
        itemsRemoved: 0,
        bytesFreed: 0,
        success: false,
        errors: [error instanceof Error ? error.message : String(error)]
      };
    }
  }

  /**
   * Implement smart data compression for storage efficiency
   */
  async compressStorageValue(key: string, value: any): Promise<{ compressed: string; savings: number }> {
    try {
      const originalSerialized = JSON.stringify(value);
      const originalSize = new TextEncoder().encode(originalSerialized).length;

      // Simple compression using common patterns
      let compressed = originalSerialized;

      // Remove unnecessary whitespace
      compressed = compressed.replace(/\s+/g, ' ');

      // Common string replacements for business data
      const replacements = [
        ['business_id', 'bid'],
        ['user_id', 'uid'],
        ['created_at', 'cat'],
        ['updated_at', 'uat'],
        ['timestamp', 'ts'],
        ['description', 'desc'],
        ['metadata', 'meta']
      ];

      for (const [original, replacement] of replacements) {
        compressed = compressed.replace(new RegExp(`"${original}"`, 'g'), `"${replacement}"`);
      }

      const compressedSize = new TextEncoder().encode(compressed).length;
      const savings = originalSize - compressedSize;

      return {
        compressed,
        savings
      };

    } catch (error) {
      this.logger.warn('Failed to compress storage value', { key, error });
      return {
        compressed: JSON.stringify(value),
        savings: 0
      };
    }
  }

  /**
   * Set up automatic storage monitoring
   */
  setupAutomaticMonitoring(intervalMs: number = 60000): NodeJS.Timeout {
    const timer = setInterval(async () => {
      try {
        const alerts = await this.checkStorageAlerts();

        for (const alert of alerts) {
          if (alert.level === 'critical') {
            this.logger.error(`CRITICAL STORAGE ALERT: ${alert.message}`, {
              currentUsage: alert.currentUsage,
              threshold: alert.threshold,
              actions: alert.recommendedActions
            });

            // Automatic cleanup for critical alerts
            await this.performCleanup({ maxItems: 50 });

          } else if (alert.level === 'warning') {
            this.logger.warn(`Storage warning: ${alert.message}`, {
              currentUsage: alert.currentUsage,
              threshold: alert.threshold
            });
          }
        }

      } catch (error) {
        this.logger.error('Automatic storage monitoring failed', error);
      }
    }, intervalMs);

    this.logger.info('Automatic storage monitoring started', { intervalMs });
    return timer;
  }

  /**
   * Extract key age from key name or metadata
   */
  private extractKeyAge(key: string, metadata?: any): number | null {
    try {
      // Try to extract timestamp from key name patterns
      const timestampMatches = [
        /(\d{13})/, // 13-digit timestamp
        /(\d{10})/, // 10-digit timestamp
        /_(\d+)_/, // timestamp in middle
        /^(\d+)_/ // timestamp at start
      ];

      for (const pattern of timestampMatches) {
        const match = key.match(pattern);
        if (match) {
          const timestamp = parseInt(match[1]);
          // Validate timestamp is reasonable (between 2020-2030)
          if (timestamp > 1577836800000 && timestamp < 1893456000000) {
            return timestamp;
          }
        }
      }

      // If no timestamp in key, return null (can't determine age)
      return null;

    } catch (error) {
      return null;
    }
  }

  /**
   * Estimate storage growth rate (simplified implementation)
   */
  private estimateGrowthRate(): number {
    // This would need historical data to be accurate
    // For now, return a conservative estimate
    return 1024; // 1KB per second growth estimate
  }

  /**
   * Get storage statistics summary
   */
  async getStorageSummary(): Promise<{
    status: 'healthy' | 'warning' | 'critical';
    metrics: StorageMetrics;
    alerts: StorageAlert[];
    recommendations: string[];
  }> {
    const metrics = await this.getStorageMetrics();
    const alerts = await this.checkStorageAlerts();

    let status: 'healthy' | 'warning' | 'critical' = 'healthy';
    if (alerts.some(a => a.level === 'critical')) {
      status = 'critical';
    } else if (alerts.some(a => a.level === 'warning')) {
      status = 'warning';
    }

    const recommendations: string[] = [];
    if (metrics.utilizationPercentage > 70) {
      recommendations.push('Consider implementing data archival strategy');
    }
    if (metrics.keyCount > 1000) {
      recommendations.push('Review data structure optimization opportunities');
    }
    if (metrics.averageKeySize > 1024) {
      recommendations.push('Implement data compression for large values');
    }

    return {
      status,
      metrics,
      alerts,
      recommendations
    };
  }
}