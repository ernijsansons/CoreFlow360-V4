// Database type extensions and helpers

import { D1Result, D1Database } from '@cloudflare/workers-types';

// Extended D1Result with changes property
export interface D1ResultWithChanges<T = unknown> extends D1Result<T> {
  changes?: number;
  duration?: number;
  lastRowId?: number;
}

// Helper type for batch operations
export type D1BatchResult<T = unknown> = D1Result<T>[];

// Memory interface for agent system
export interface Memory {
  id: string;
  type: 'short' | 'long' | 'episodic';
  content: string;
  timestamp: number;
  metadata?: Record<string, any>;
}

export interface MemoryWithMessages extends Memory {
  messages: Array<{
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp: number;
  }>;
}

// Audit event types
export enum AuditEventType {
  TASK_CREATED = 'TASK_CREATED',
  TASK_COMPLETED = 'TASK_COMPLETED',
  TASK_FAILED = 'TASK_FAILED',
  TASK_RETRIED = 'TASK_RETRIED',
  TASK_REJECTED = 'TASK_REJECTED',
  TASK_CANCELLED = 'TASK_CANCELLED',

  AGENT_REGISTERED = 'AGENT_REGISTERED',
  AGENT_UPDATED = 'AGENT_UPDATED',
  AGENT_REMOVED = 'AGENT_REMOVED',

  WORKFLOW_STARTED = 'WORKFLOW_STARTED',
  WORKFLOW_COMPLETED = 'WORKFLOW_COMPLETED',
  WORKFLOW_FAILED = 'WORKFLOW_FAILED',

  SECURITY_ALERT = 'SECURITY_ALERT',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',

  CONFIG_CHANGED = 'CONFIG_CHANGED',
  SYSTEM_ERROR = 'SYSTEM_ERROR'
}

// Helper functions
export function isD1ResultWithChanges<T>(result: D1Result<T> | D1ResultWithChanges<T>): result is D1ResultWithChanges<T> {
  return 'changes' in result;
}

export function getChangesCount<T>(result: D1Result<T> | D1ResultWithChanges<T>): number {
  if (isD1ResultWithChanges(result)) {
    return result.changes || 0;
  }
  return 0;
}