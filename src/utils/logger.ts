/**
 * Logger utility - Re-exports from shared logger
 */
import { Logger, type LoggerConfig } from '../shared/logger';

/**
 * Creates a logger instance with the specified configuration
 */
export function createLogger(component: string, config?: Partial<LoggerConfig>): Logger {
  return new Logger({
    component,
    ...config,
  });
}

// Re-export types and classes
export { Logger } from '../shared/logger';
export type { LoggerConfig } from '../shared/logger';
export { LogLevel } from '../shared/logger';
