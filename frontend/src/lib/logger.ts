// Logger utility for frontend
import type { CloudflareEnv } from './cloudflare';

export interface LoggerConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  env?: CloudflareEnv;
}

class Logger {
  private level: string;
  private env?: CloudflareEnv;

  constructor(config: LoggerConfig = { level: 'info' }) {
    this.level = config.level;
    this.env = config.env;
  }

  private shouldLog(level: string): boolean {
    const levels = ['debug', 'info', 'warn', 'error'];
    return levels.indexOf(level) >= levels.indexOf(this.level);
  }

  debug(message: string, ...args: any[]) {
    if (this.shouldLog('debug')) {
      console.debug(`[DEBUG] ${message}`, ...args);
    }
  }

  info(message: string, ...args: any[]) {
    if (this.shouldLog('info')) {
      console.info(`[INFO] ${message}`, ...args);
    }
  }

  warn(message: string, ...args: any[]) {
    if (this.shouldLog('warn')) {
      console.warn(`[WARN] ${message}`, ...args);
    }
  }

  error(message: string, ...args: any[]) {
    if (this.shouldLog('error')) {
      console.error(`[ERROR] ${message}`, ...args);
    }
  }
}

// Create default logger instance
export const logger = new Logger({
  level: process.env.NODE_ENV === 'development' ? 'debug' : 'info'
});

export default Logger;
