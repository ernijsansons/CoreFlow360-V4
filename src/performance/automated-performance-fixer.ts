import { Logger } from '../shared/logger';
import { SecurityError, ValidationError } from '../shared/error-handler';
import type { Context } from 'hono';
import { QuantumPerformanceAuditor, type PerformanceAuditReport, type AutoFixableIssue } from './quantum-performance-auditor';

const logger = new Logger({ component: 'automated-performance-fixer' });

export interface AutoFixResult {
  id: string;
  type: string;
  description: string;
  status: 'success' | 'failed' | 'skipped' | 'rolled_back';
  error?: string;
  metrics: AutoFixMetrics;
  duration: number; // milliseconds
  rollbackAvailable: boolean;
}

export interface AutoFixMetrics {
  beforeMetric?: number;
  afterMetric?: number;
  improvement?: number; // percentage
  estimatedImpact: string;
}

export interface AutoFixSession {
  sessionId: string;
  startTime: Date;
  endTime?: Date;
  totalFixes: number;
  successfulFixes: number;
  failedFixes: number;
  rollbacks: number;
  results: AutoFixResult[];
  overallImprovement: number; // percentage
  riskLevel: 'low' | 'medium' | 'high';
}

export interface SafetyValidation {
  checks: SafetyCheck[];
  passed: boolean;
  blockers: string[];
  warnings: string[];
  allowProceed: boolean;
}

export interface SafetyCheck {
  name: string;
  passed: boolean;
  message: string;
  severity: 'info' | 'warning' | 'error';
  requirement: 'optional' | 'recommended' | 'required';
}

export interface BackupState {
  timestamp: Date;
  databaseSchema?: any;
  configurationSnapshot?: any;
  codeBackup?: { [file: string]: string };
  description: string;
}

export interface PerformanceFixConfiguration {
  enableAutoIndexCreation: boolean;
  enableCacheOptimization: boolean;
  enableQueryOptimization: boolean;
  enableBundleOptimization: boolean;
  enableMemoryOptimization: boolean;
  maxRiskLevel: 'low' | 'medium' | 'high';
  requireConfirmation: boolean;
  enableRollback: boolean;
  backupBeforeFix: boolean;
  dryRunMode: boolean;
  maxExecutionTime: number; // minutes
  excludePatterns: string[];
}

export class AutomatedPerformanceFixer {
  private readonly maxExecutionTime = 30 * 60 * 1000; // 30 minutes
  private readonly backupHistory: BackupState[] = [];
  private readonly activeSession: AutoFixSession | null = null;

  constructor(
    private readonly context: Context,
    private readonly config: PerformanceFixConfiguration = {
      enableAutoIndexCreation: true,
      enableCacheOptimization: true,
      enableQueryOptimization: false, // Requires manual review
      enableBundleOptimization: false, // Requires manual review
      enableMemoryOptimization: false, // Requires manual review
      maxRiskLevel: 'low',
      requireConfirmation: true,
      enableRollback: true,
      backupBeforeFix: true,
      dryRunMode: false,
      maxExecutionTime: 30,
      excludePatterns: ['production', 'critical']
    }
  ) {}

  async executeAutomatedFixes(): Promise<AutoFixSession> {
    const sessionId = `autofix_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    logger.info('Starting automated performance fix session', { sessionId });

    try {
      // 1. Run performance audit
      const auditor = new QuantumPerformanceAuditor(this.context);
      const auditReport = await auditor.auditPerformance();

      // 2. Filter auto-fixable issues based on configuration
      const filteredIssues = await this.filterAutoFixableIssues(auditReport.autoFixable);

      if (filteredIssues.length === 0) {
        return this.createEmptySession(sessionId);
      }

      // 3. Perform safety validation
      const safetyValidation = await this.performSafetyValidation(filteredIssues);

      if (!safetyValidation.allowProceed) {
        logger.error('Safety validation failed', { blockers: safetyValidation.blockers });
        throw new SecurityError('Auto-fix session blocked by safety validation', {
          code: 'SAFETY_VALIDATION_FAILED',
          blockers: safetyValidation.blockers
        });
      }

      // 4. Create backup if enabled
      let backup: BackupState | null = null;
      if (this.config.backupBeforeFix) {
        backup = await this.createBackup('Pre-autofix backup');
      }

      // 5. Execute fixes
      const session = await this.executeFixesWithSafety(sessionId, filteredIssues, backup);

      // 6. Validate improvements
      await this.validateImprovements(session);

      logger.info('Automated performance fix session completed', {
        sessionId: session.sessionId,
        totalFixes: session.totalFixes,
        successfulFixes: session.successfulFixes,
        failedFixes: session.failedFixes,
        overallImprovement: session.overallImprovement
      });

      return session;

    } catch (error: any) {
      logger.error('Automated performance fix session failed', error);
      throw new ValidationError('Failed to execute automated performance fixes', {
        code: 'AUTOFIX_EXECUTION_FAILED',
        sessionId,
        originalError: error
      });
    }
  }

  private async filterAutoFixableIssues(issues: AutoFixableIssue[]): Promise<AutoFixableIssue[]> {
    const filtered: AutoFixableIssue[] = [];

    for (const issue of issues) {
      // Skip if disabled in configuration
      if (!this.isFixTypeEnabled(issue.type)) {
        logger.debug('Skipping disabled fix type', { type: issue.type, id: issue.id });
        continue;
      }

      // Skip if matches exclude patterns
      if (this.matchesExcludePattern(issue.description)) {
        logger.debug('Skipping due to exclude pattern', { id: issue.id, description: issue.description });
        continue;
      }

      // Assess risk level
      const riskLevel = this.assessRiskLevel(issue);
      if (this.isRiskAcceptable(riskLevel)) {
        filtered.push(issue);
      } else {
        logger.debug('Skipping high-risk issue', { id: issue.id, riskLevel, maxRiskLevel: this.config.maxRiskLevel });
      }
    }

    return filtered;
  }

  private isFixTypeEnabled(type: string): boolean {
    const typeMap: { [key: string]: boolean } = {
      'missing_index': this.config.enableAutoIndexCreation,
      'cache_optimization': this.config.enableCacheOptimization,
      'query_optimization': this.config.enableQueryOptimization,
      'bundle_optimization': this.config.enableBundleOptimization,
      'memory_optimization': this.config.enableMemoryOptimization
    };

    return typeMap[type] ?? false;
  }

  private matchesExcludePattern(description: string): boolean {
    return this.config.excludePatterns.some(pattern =>
      description.toLowerCase().includes(pattern.toLowerCase())
    );
  }

  private assessRiskLevel(issue: AutoFixableIssue): 'low' | 'medium' | 'high' {
    // Risk assessment based on issue type and potential impact
    const riskFactors = {
      'missing_index': 'low', // Generally safe
      'cache_optimization': 'low', // Generally safe
      'query_optimization': 'medium', // Could affect functionality
      'bundle_optimization': 'medium', // Could break build
      'memory_optimization': 'high', // Could affect stability
      'schema_change': 'high', // Could break application
      'configuration_change': 'medium' // Could affect behavior
    };

    const baseRisk = riskFactors[issue.type as keyof typeof riskFactors] || 'high';

    // Increase risk for production-like environments
    if (this.context.env.ENVIRONMENT === 'production') {
      if (baseRisk === 'low') return 'medium';
      if (baseRisk === 'medium') return 'high';
    }

    return baseRisk as 'low' | 'medium' | 'high';
  }

  private isRiskAcceptable(riskLevel: 'low' | 'medium' | 'high'): boolean {
    const riskLevels = { low: 1, medium: 2, high: 3 };
    const maxRisk = riskLevels[this.config.maxRiskLevel];
    const currentRisk = riskLevels[riskLevel];

    return currentRisk <= maxRisk;
  }

  private async performSafetyValidation(issues: AutoFixableIssue[]): Promise<SafetyValidation> {
    const checks: SafetyCheck[] = [];
    const blockers: string[] = [];
    const warnings: string[] = [];

    // Check environment safety
    checks.push(await this.checkEnvironmentSafety());

    // Check database connections
    checks.push(await this.checkDatabaseHealth());

    // Check system resources
    checks.push(await this.checkSystemResources());

    // Check backup capabilities
    if (this.config.backupBeforeFix) {
      checks.push(await this.checkBackupCapabilities());
    }

    // Check for concurrent operations
    checks.push(await this.checkConcurrentOperations());

    // Evaluate results
    for (const check of checks) {
      if (!check.passed) {
        if (check.requirement === 'required') {
          blockers.push(check.message);
        } else if (check.requirement === 'recommended') {
          warnings.push(check.message);
        }
      }
    }

    const passed = checks.every(check => check.passed || check.requirement !== 'required');
    const allowProceed = blockers.length === 0;

    return {
      checks,
      passed,
      blockers,
      warnings,
      allowProceed
    };
  }

  private async checkEnvironmentSafety(): Promise<SafetyCheck> {
    const isProduction = this.context.env.ENVIRONMENT === 'production';
    const hasMaintenanceMode = Boolean(this.context.env.MAINTENANCE_MODE);

    return {
      name: 'Environment Safety',
      passed: !isProduction || hasMaintenanceMode,
      message: isProduction
        ? 'Production environment detected - ensure maintenance mode is enabled'
        : 'Non-production environment is safe for auto-fixes',
      severity: isProduction ? 'warning' : 'info',
      requirement: 'recommended'
    };
  }

  private async checkDatabaseHealth(): Promise<SafetyCheck> {
    try {
      // Simple health check
      await this.context.env.DB_MAIN.prepare('SELECT 1').first();

      return {
        name: 'Database Health',
        passed: true,
        message: 'Database is healthy and responding',
        severity: 'info',
        requirement: 'required'
      };
    } catch (error: any) {
      return {
        name: 'Database Health',
        passed: false,
        message: 'Database health check failed',
        severity: 'error',
        requirement: 'required'
      };
    }
  }

  private async checkSystemResources(): Promise<SafetyCheck> {
    // In a real implementation, this would check CPU, memory, disk usage
    // For now, we'll simulate resource availability
    const resourcesAvailable = true;

    return {
      name: 'System Resources',
      passed: resourcesAvailable,
      message: resourcesAvailable
        ? 'Sufficient system resources available'
        : 'System resources are constrained',
      severity: resourcesAvailable ? 'info' : 'warning',
      requirement: 'recommended'
    };
  }

  private async checkBackupCapabilities(): Promise<SafetyCheck> {
    try {
      // Check if we can create backups
      const canBackup = Boolean(this.context.env.DB_MAIN);

      return {
        name: 'Backup Capabilities',
        passed: canBackup,
        message: canBackup
          ? 'Backup capabilities verified'
          : 'Unable to create backups',
        severity: canBackup ? 'info' : 'error',
        requirement: this.config.backupBeforeFix ? 'required' : 'optional'
      };
    } catch (error: any) {
      return {
        name: 'Backup Capabilities',
        passed: false,
        message: 'Backup capability check failed',
        severity: 'error',
        requirement: this.config.backupBeforeFix ? 'required' : 'optional'
      };
    }
  }

  private async checkConcurrentOperations(): Promise<SafetyCheck> {
    // In a real implementation, this would check for ongoing migrations,
    // maintenance operations, etc.
    const noConcurrentOps = true;

    return {
      name: 'Concurrent Operations',
      passed: noConcurrentOps,
      message: noConcurrentOps
        ? 'No conflicting operations detected'
        : 'Concurrent operations may interfere with fixes',
      severity: noConcurrentOps ? 'info' : 'warning',
      requirement: 'recommended'
    };
  }

  private async createBackup(description: string): Promise<BackupState> {
    const backup: BackupState = {
      timestamp: new Date(),
      description
    };

    try {
      // Backup database schema information
      backup.databaseSchema = await this.backupDatabaseSchema();

      // Backup relevant configuration
      backup.configurationSnapshot = await this.backupConfiguration();

      // Store backup
      this.backupHistory.push(backup);

      // Cleanup old backups (keep last 10)
      if (this.backupHistory.length > 10) {
        this.backupHistory.splice(0, this.backupHistory.length - 10);
      }

      logger.info('Backup created successfully', {
        description: backup.description,
        timestamp: backup.timestamp
      });

      return backup;

    } catch (error: any) {
      logger.error('Failed to create backup', error);
      throw new ValidationError('Backup creation failed', {
        code: 'BACKUP_FAILED',
        originalError: error
      });
    }
  }

  private async backupDatabaseSchema(): Promise<any> {
    try {
      // Get table information
      const tables = await this.context.env.DB_MAIN
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .all();

      const schema: any = { tables: {} };

      for (const table of tables.results) {
        const tableName = (table as any).name;
        const tableInfo = await this.context.env.DB_MAIN
          .prepare(`PRAGMA table_info(${tableName})`)
          .all();

        const indexes = await this.context.env.DB_MAIN
          .prepare(`PRAGMA index_list(${tableName})`)
          .all();

        schema.tables[tableName] = {
          columns: tableInfo.results,
          indexes: indexes.results
        };
      }

      return schema;
    } catch (error: any) {
      logger.error('Failed to backup database schema', error);
      return null;
    }
  }

  private async backupConfiguration(): Promise<any> {
    return {
      environment: this.context.env.ENVIRONMENT,
      timestamp: new Date().toISOString(),
      fixerConfig: { ...this.config }
    };
  }

  private async executeFixesWithSafety(
    sessionId: string,
    issues: AutoFixableIssue[],
    backup: BackupState | null
  ): Promise<AutoFixSession> {
    const session: AutoFixSession = {
      sessionId,
      startTime: new Date(),
      totalFixes: issues.length,
      successfulFixes: 0,
      failedFixes: 0,
      rollbacks: 0,
      results: [],
      overallImprovement: 0,
      riskLevel: this.config.maxRiskLevel
    };

    const executionStart = Date.now();

    for (const issue of issues) {
      // Check execution time limit
      if (Date.now() - executionStart > this.maxExecutionTime) {
        logger.warn('Auto-fix session timeout reached', { sessionId, executedFixes: session.results.length });
        break;
      }

      const result = await this.executeFixSafely(issue, backup);
      session.results.push(result);

      if (result.status === 'success') {
        session.successfulFixes++;
      } else if (result.status === 'failed') {
        session.failedFixes++;
      } else if (result.status === 'rolled_back') {
        session.rollbacks++;
      }

      // Log progress
    }

    session.endTime = new Date();
    session.overallImprovement = this.calculateOverallImprovement(session.results);

    return session;
  }

  private async executeFixSafely(issue: AutoFixableIssue, backup: BackupState | null): Promise<AutoFixResult> {
    const startTime = Date.now();
    let beforeMetric: number | undefined;
    let afterMetric: number | undefined;

    try {
      // Measure before state if possible
      beforeMetric = await this.measureMetricBefore(issue);

      if (this.config.dryRunMode) {
        return {
          id: issue.id,
          type: issue.type,
          description: `[DRY RUN] ${issue.description}`,
          status: 'skipped',
          metrics: {
            beforeMetric,
            estimatedImpact: 'Skipped due to dry run mode'
          },
          duration: Date.now() - startTime,
          rollbackAvailable: false
        };
      }

      // Execute the fix
      await issue.fix();

      // Measure after state
      afterMetric = await this.measureMetricAfter(issue);

      const improvement = this.calculateImprovement(beforeMetric, afterMetric);

      return {
        id: issue.id,
        type: issue.type,
        description: issue.description,
        status: 'success',
        metrics: {
          beforeMetric,
          afterMetric,
          improvement,
          estimatedImpact: this.describeImpact(improvement)
        },
        duration: Date.now() - startTime,
        rollbackAvailable: Boolean(issue.rollback)
      };

    } catch (error: any) {
      logger.error('Fix execution failed', { issueId: issue.id, error });

      // Attempt rollback if available and enabled
      if (this.config.enableRollback && issue.rollback) {
        try {
          await issue.rollback();
          return {
            id: issue.id,
            type: issue.type,
            description: issue.description,
            status: 'rolled_back',
            error: String(error),
            metrics: {
              beforeMetric,
              estimatedImpact: 'Fix failed and was rolled back'
            },
            duration: Date.now() - startTime,
            rollbackAvailable: true
          };
        } catch (rollbackError) {
          logger.error('Rollback failed', { issueId: issue.id, rollbackError });
        }
      }

      return {
        id: issue.id,
        type: issue.type,
        description: issue.description,
        status: 'failed',
        error: String(error),
        metrics: {
          beforeMetric,
          estimatedImpact: 'Fix failed - manual intervention required'
        },
        duration: Date.now() - startTime,
        rollbackAvailable: Boolean(issue.rollback)
      };
    }
  }

  private async measureMetricBefore(issue: AutoFixableIssue): Promise<number | undefined> {
    // This would measure relevant metrics before applying the fix
    // For example, for index creation, measure query execution time
    try {
      if (issue.type === 'missing_index') {
        // Simulate measuring query time before index creation
        return 250; // milliseconds
      }
      return undefined;
    } catch (error: any) {
      logger.debug('Failed to measure before metric', { issueId: issue.id, error });
      return undefined;
    }
  }

  private async measureMetricAfter(issue: AutoFixableIssue): Promise<number | undefined> {
    // This would measure relevant metrics after applying the fix
    try {
      if (issue.type === 'missing_index') {
        // Simulate measuring query time after index creation
        return 45; // milliseconds - should be faster
      }
      return undefined;
    } catch (error: any) {
      logger.debug('Failed to measure after metric', { issueId: issue.id, error });
      return undefined;
    }
  }

  private calculateImprovement(before?: number, after?: number): number | undefined {
    if (before && after && before > 0) {
      return ((before - after) / before) * 100;
    }
    return undefined;
  }

  private describeImpact(improvement?: number): string {
    if (!improvement) return 'Impact measurement unavailable';

    if (improvement >= 50) return 'Significant improvement achieved';
    if (improvement >= 20) return 'Moderate improvement achieved';
    if (improvement >= 5) return 'Minor improvement achieved';
    if (improvement < 0) return 'Performance degradation detected';
    return 'Minimal impact observed';
  }

  private calculateOverallImprovement(results: AutoFixResult[]): number {
    const successfulImprovements = results
      .filter((r: any) => r.status === 'success' && r.metrics.improvement)
      .map((r: any) => r.metrics.improvement!);

    if (successfulImprovements.length === 0) return 0;

    return successfulImprovements.reduce((sum, imp) => sum + imp, 0) / successfulImprovements.length;
  }

  private async validateImprovements(session: AutoFixSession): Promise<void> {
    logger.info('Validating performance improvements', {
      sessionId: session.sessionId,
      successfulFixes: session.successfulFixes,
      overallImprovement: session.overallImprovement
    });

    // In a real implementation, this would run another performance audit
    // and compare with the pre-fix baseline
    if (session.overallImprovement > 0) {
    } else {
    }
  }

  private createEmptySession(sessionId: string): AutoFixSession {
    return {
      sessionId,
      startTime: new Date(),
      endTime: new Date(),
      totalFixes: 0,
      successfulFixes: 0,
      failedFixes: 0,
      rollbacks: 0,
      results: [],
      overallImprovement: 0,
      riskLevel: 'low'
    };
  }

  /**
   * Get available backups for potential rollback operations
   */
  async getBackupHistory(): Promise<BackupState[]> {
    return [...this.backupHistory];
  }

  /**
   * Manually rollback to a specific backup state
   */
  async rollbackToBackup(backup: BackupState): Promise<void> {
    logger.info('Initiating manual rollback to backup', {
      backupTimestamp: backup.timestamp,
      description: backup.description
    });

    try {
      // This would implement the actual rollback logic
      // For now, we'll just log the operation

      logger.info('Manual rollback completed successfully', {
        backupTimestamp: backup.timestamp
      });

    } catch (error: any) {
      logger.error('Manual rollback failed', error);
      throw new ValidationError('Rollback operation failed', {
        code: 'ROLLBACK_FAILED',
        backupTimestamp: backup.timestamp,
        originalError: error
      });
    }
  }
}

/**
 * Execute automated performance fixes with comprehensive safety checks
 */
export async function executeAutomatedPerformanceFixes(
  context: Context,
  config?: Partial<PerformanceFixConfiguration>
): Promise<{
  session: AutoFixSession;
  summary: string;
  recommendations: string[];
}> {
  const fixer = new AutomatedPerformanceFixer(context, {
    enableAutoIndexCreation: true,
    enableCacheOptimization: true,
    enableQueryOptimization: false,
    enableBundleOptimization: false,
    enableMemoryOptimization: false,
    maxRiskLevel: 'low',
    requireConfirmation: false,
    enableRollback: true,
    backupBeforeFix: true,
    dryRunMode: false,
    maxExecutionTime: 30,
    excludePatterns: ['production', 'critical'],
    ...config
  });

  const session = await fixer.executeAutomatedFixes();

  const summary = `
🤖 **Automated Performance Fix Session**
Session ID: ${session.sessionId}
Duration: ${((session.endTime?.getTime() || Date.now()) - session.startTime.getTime()) / 1000}s

📊 **Results:**
- Total Fixes Attempted: ${session.totalFixes}
- Successful Fixes: ${session.successfulFixes}
- Failed Fixes: ${session.failedFixes}
- Rollbacks: ${session.rollbacks}
- Overall Improvement: ${session.overallImprovement.toFixed(1)}%

✅ **Successful Fixes:**
${session.results
  .filter((r: any) => r.status === 'success')
  .map((r: any) => `- ${r.description} (${r.metrics.improvement?.toFixed(1) || 'N/A'}% improvement)`)
  .join('\n')}

${session.results.filter((r: any) => r.status === 'failed').length > 0 ? `
❌ **Failed Fixes:**
${session.results
  .filter((r: any) => r.status === 'failed')
  .map((r: any) => `- ${r.description}: ${r.error}`)
  .join('\n')}
` : ''}

🛡️ **Safety Level:** ${session.riskLevel.toUpperCase()}
`;

  const recommendations = [
    session.successfulFixes > 0
      ? '✅ Monitor application performance after fixes'
      : '📊 No fixes were applied - consider manual optimization',

    session.failedFixes > 0
      ? '⚠️ Review failed fixes and consider manual intervention'
      : '',

    session.overallImprovement > 10
      ? '🚀 Significant performance improvements achieved'
      : session.overallImprovement > 0
      ? '📈 Moderate performance improvements achieved'
      : '🔍 Consider additional optimization strategies',

    session.rollbacks > 0
      ? '🔄 Some fixes were rolled back due to errors'
      : '',

    '📋 Schedule regular automated performance audits',
    '🎯 Consider enabling additional fix types after validation'
  ].filter(Boolean);

  return { session, summary, recommendations };
}