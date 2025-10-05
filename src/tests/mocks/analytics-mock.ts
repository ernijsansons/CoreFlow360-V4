/**
 * Production-Quality MockAnalyticsEngine
 * Fully implements Cloudflare AnalyticsEngineDataset interface for testing
 *
 * Features:
 * - Complete AnalyticsEngineDataset implementation
 * - Event capture and querying
 * - Type-safe implementation
 *
 * @see @cloudflare/workers-types AnalyticsEngineDataset
 */

import type { AnalyticsEngineDataset } from '@cloudflare/workers-types';

interface AnalyticsEvent {
  timestamp: Date;
  indexes?: (string | number)[];
  blobs?: string[];
  doubles?: number[];
}

/**
 * MockAnalyticsEngine - Production-quality mock for Cloudflare AnalyticsEngineDataset
 */
export class MockAnalyticsEngine implements AnalyticsEngineDataset {
  private events: AnalyticsEvent[] = [];

  /**
   * Write analytics event
   */
  writeDataPoint(event?: {
    indexes?: (ArrayBuffer | string)[];
    blobs?: string[];
    doubles?: number[];
  }): void {
    this.events.push({
      timestamp: new Date(),
      indexes: event?.indexes as any,
      blobs: event?.blobs,
      doubles: event?.doubles,
    });
  }

  // ==========================================
  // TEST HELPER METHODS
  // ==========================================

  /**
   * Get all recorded events
   */
  getEvents(): AnalyticsEvent[] {
    return [...this.events];
  }

  /**
   * Get event count
   */
  getEventCount(): number {
    return this.events.length;
  }

  /**
   * Get events matching criteria
   */
  queryEvents(filter: {
    indexes?: (string | number)[];
    blobs?: string[];
    doubles?: number[];
  }): AnalyticsEvent[] {
    return this.events.filter((event) => {
      if (filter.indexes) {
        const hasAllIndexes = filter.indexes.every(
          (idx) => event.indexes?.includes(idx)
        );
        if (!hasAllIndexes) return false;
      }

      if (filter.blobs) {
        const hasAllBlobs = filter.blobs.every(
          (blob) => event.blobs?.includes(blob)
        );
        if (!hasAllBlobs) return false;
      }

      if (filter.doubles) {
        const hasAllDoubles = filter.doubles.every(
          (double) => event.doubles?.includes(double)
        );
        if (!hasAllDoubles) return false;
      }

      return true;
    });
  }

  /**
   * Get events in time range
   */
  getEventsByTimeRange(start: Date, end: Date): AnalyticsEvent[] {
    return this.events.filter(
      (event) => event.timestamp >= start && event.timestamp <= end
    );
  }

  /**
   * Get latest events
   */
  getLatestEvents(count: number): AnalyticsEvent[] {
    return this.events.slice(-count);
  }

  /**
   * Clear all events
   */
  clear(): void {
    this.events = [];
  }

  /**
   * Get event summary statistics
   */
  getStats(): {
    totalEvents: number;
    firstEvent?: Date;
    lastEvent?: Date;
    uniqueIndexes: Set<string | number>;
    uniqueBlobs: Set<string>;
  } {
    const uniqueIndexes = new Set<string | number>();
    const uniqueBlobs = new Set<string>();

    for (const event of this.events) {
      event.indexes?.forEach((idx) => uniqueIndexes.add(idx));
      event.blobs?.forEach((blob) => uniqueBlobs.add(blob));
    }

    return {
      totalEvents: this.events.length,
      firstEvent: this.events[0]?.timestamp,
      lastEvent: this.events[this.events.length - 1]?.timestamp,
      uniqueIndexes,
      uniqueBlobs,
    };
  }
}

/**
 * Factory function to create MockAnalyticsEngine instances
 */
export function createMockAnalytics(): MockAnalyticsEngine {
  return new MockAnalyticsEngine();
}
