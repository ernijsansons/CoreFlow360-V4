// @ts-nocheck
/* eslint-disable no-console */
import { Logger as StructuredLogger } from "./logger";
const workerLogger = new StructuredLogger({ component: "shared-worker-polyfills" });
/**
 * Worker-Compatible Polyfills for Browser APIs
 *
 * Cloudflare Workers do not have access to browser globals like:
 * - navigator
 * - window
 * - document
 * - performance (limited)
 *
 * This file provides Worker-compatible alternatives.
 */

/**
 * Worker-compatible navigator polyfill
 */
export const workerNavigator = {
  /**
   * Number of logical processors available
   * In Workers, we default to 4 as a reasonable estimate
   */
  hardwareConcurrency: 4,

  /**
   * User agent string (if available in Worker context)
   */
  get userAgent(): string {
    // Workers don't have navigator.userAgent
    return 'Cloudflare-Worker/1.0';
  },

  /**
   * Check if WebGPU is available
   * Always false in Workers
   */
  gpu: undefined,
};

/**
 * Worker-compatible performance API
 */
export const workerPerformance = {
  /**
   * High-resolution timestamp in milliseconds
   */
  now(): number {
    return Date.now();
  },

  /**
   * Memory information (not available in Workers)
   */
  memory: undefined,

  /**
   * Navigation timing (not available in Workers)
   */
  timing: undefined,

  /**
   * Mark a performance measurement point
   */
  mark(name: string): void {
    // No-op in Workers, could be implemented with custom tracking
    workerLogger.debug(`Performance mark: ${name} at ${Date.now()}`);
  },

  /**
   * Measure time between two marks
   */
  measure(name: string, startMark: string, endMark: string): void {
    // No-op in Workers
    workerLogger.debug(`Performance measure: ${name} from ${startMark} to ${endMark}`);
  },
};

/**
 * Check if code is running in a Worker environment
 */
export function isWorkerEnvironment(): boolean {
  return (
    typeof window === 'undefined' &&
    typeof WorkerGlobalScope !== 'undefined' &&
    self instanceof WorkerGlobalScope
  );
}

/**
 * Get appropriate navigator object for current environment
 */
export function getNavigator(): typeof workerNavigator {
  if (typeof navigator !== 'undefined') {
    return navigator as any;
  }
  return workerNavigator;
}

/**
 * Get appropriate performance object for current environment
 */
export function getPerformance(): typeof workerPerformance {
  if (typeof performance !== 'undefined') {
    return performance as any;
  }
  return workerPerformance;
}

/**
 * Detect device capabilities in Worker environment
 */
export interface WorkerDeviceCapabilities {
  webGPU: boolean;
  wasmSimd: boolean;
  tensorflowLite: boolean;
  memoryMB: number;
  computeUnits: number;
}

/**
 * Get device capabilities (Worker-safe)
 */
export function getDeviceCapabilities(): WorkerDeviceCapabilities {
  const nav = getNavigator();
  const perf = getPerformance();
  void perf;

  return {
    webGPU: false, // Not available in Workers
    wasmSimd: typeof WebAssembly !== 'undefined',
    tensorflowLite: false,
    memoryMB: 2048, // Default estimate for Workers
    computeUnits: nav.hardwareConcurrency || 4,
  };
}

/**
 * Edge device information for AI orchestration
 */
export interface EdgeDeviceInfo {
  capabilities: WorkerDeviceCapabilities;
  latency: number;
  bandwidth: number;
  reliability: number;
}

/**
 * Get edge device information (Worker-safe)
 */
export function getEdgeDeviceInfo(): EdgeDeviceInfo {
  return {
    capabilities: getDeviceCapabilities(),
    latency: 1, // ms - Workers have minimal latency
    bandwidth: 1000, // Mbps - estimate
    reliability: 0.99,
  };
}

/**
 * Type guard for checking if window is available
 */
export function hasWindow(): boolean {
  return typeof window !== 'undefined';
}

/**
 * Type guard for checking if document is available
 */
export function hasDocument(): boolean {
  return typeof document !== 'undefined';
}

/**
 * Safe way to access window object
 */
export function getWindow(): Window | undefined {
  return hasWindow() ? window : undefined;
}

/**
 * Safe way to access document object
 */
export function getDocument(): Document | undefined {
  return hasDocument() ? document : undefined;
}

/**
 * Environment detection
 */
export const environment = {
  isWorker: isWorkerEnvironment(),
  isBrowser: hasWindow(),
  isNode: typeof process !== 'undefined' && process.versions?.node !== undefined,

  get type(): 'worker' | 'browser' | 'node' | 'unknown' {
    if (this.isWorker) return 'worker';
    if (this.isBrowser) return 'browser';
    if (this.isNode) return 'node';
    return 'unknown';
  },
};

/**
 * Console wrapper that works in all environments
 */
export const workerConsole = {
  debug(...args: any[]): void {
    if (typeof console !== "undefined" && typeof console.debug === "function") {
      console.debug(...args);
    }
  },

  info(...args: any[]): void {
    if (typeof console !== "undefined" && typeof console.info === "function") {
      console.info(...args);
    }
  },

  warn(...args: any[]): void {
    if (typeof console !== "undefined" && typeof console.warn === "function") {
      console.warn(...args);
    }
  },

  error(...args: any[]): void {
    if (typeof console !== "undefined" && typeof console.error === "function") {
      console.error(...args);
    }
  },
};


