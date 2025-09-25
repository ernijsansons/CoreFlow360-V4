import * as fs from 'fs/promises';
import * as path from 'path';
import { DataIntegrityAuditResult, Issue } from '../types/index';

export class QuantumDataAuditor {
  async auditDataIntegrity(): Promise<DataIntegrityAuditResult> {

    const [
      validationIssues,
      consistencyIssues,
      backupIssues,
      retentionIssues
    ] = await Promise.all([
      this.checkValidation(),
      this.auditConsistency(),
      this.checkBackups(),
      this.auditRetention()
    ]);

    const allIssues = [
      ...validationIssues,
      ...consistencyIssues,
      ...backupIssues,
      ...retentionIssues
    ];

    const score = this.calculateDataIntegrityScore(allIssues);


    return {
      validationIssues,
      consistencyIssues,
      backupIssues,
      retentionIssues,
      score
    };
  }

  private async checkValidation(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for missing input validation
      if (content.includes('req.body') && !content.includes('validate')) {
        issues.push({
          id: `validation-${Date.now()}-missing-input`,
          category: 'data-integrity',
          severity: 'HIGH',
          description: 'API endpoints without input validation',
          file,
          autoFixable: true,
          impact: ['security', 'data-integrity'],
          recommendation: 'Add input validation middleware or schema validation'
        });
      }

      // Check for missing database constraints
      if (content.includes('CREATE TABLE') && !content.includes('NOT NULL')) {
        issues.push({
          id: `validation-${Date.now()}-missing-constraints`,
          category: 'data-integrity',
          severity: 'MEDIUM',
          description: 'Database tables without proper constraints',
          file,
          autoFixable: true,
          impact: ['data-integrity', 'consistency'],
          recommendation: 'Add NOT NULL, UNIQUE, and CHECK constraints'
        });
      }

      // Check for missing email validation
      if (content.includes('email') && !content.includes('@') && !content.includes('validate')) {
        issues.push({
          id: `validation-${Date.now()}-email`,
          category: 'data-integrity',
          severity: 'MEDIUM',
          description: 'Email fields without proper validation',
          file,
          autoFixable: true,
          impact: ['data-quality', 'user-experience'],
          recommendation: 'Add email format validation'
        });
      }

      // Check for missing data sanitization
      if (content.includes('innerHTML') || content.includes('html')) {
        if (!content.includes('sanitize') && !content.includes('escape')) {
          issues.push({
            id: `validation-${Date.now()}-sanitization`,
            category: 'data-integrity',
            severity: 'HIGH',
            description: 'HTML content without sanitization',
            file,
            autoFixable: true,
            impact: ['security', 'xss-prevention'],
            recommendation: 'Sanitize HTML content before rendering'
          });
        }
      }
    }

    return issues;
  }

  private async auditConsistency(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for inconsistent data formats
      const dateFormats = content.match(/\d{4}-\d{2}-\d{2}|\d{2}\/\d{2}\/\d{4}|\d{2}-\d{2}-\d{4}/g);
      if (dateFormats && new Set(dateFormats.map(d => d.replace(/\d/g, 'X'))).size > 1) {
        issues.push({
          id: `consistency-${Date.now()}-date-formats`,
          category: 'data-integrity',
          severity: 'MEDIUM',
          description: 'Inconsistent date formats detected',
          file,
          autoFixable: true,
          impact: ['data-consistency', 'user-experience'],
          recommendation: 'Standardize on a single date format (ISO 8601 recommended)'
        });
      }

      // Check for missing foreign key constraints
      if (content.includes('_id') && !content.includes('FOREIGN KEY')) {
        issues.push({
          id: `consistency-${Date.now()}-foreign-keys`,
          category: 'data-integrity',
          severity: 'HIGH',
          description: 'Foreign key references without constraints',
          file,
          autoFixable: false,
          impact: ['data-integrity', 'referential-integrity'],
          recommendation: 'Add foreign key constraints for referential integrity'
        });
      }

      // Check for missing transaction handling
      if (content.includes('INSERT') && content.includes('UPDATE') && !content.includes('transaction')) {
        issues.push({
          id: `consistency-${Date.now()}-transactions`,
          category: 'data-integrity',
          severity: 'HIGH',
          description: 'Multiple database operations without transaction handling',
          file,
          autoFixable: false,
          impact: ['data-consistency', 'atomicity'],
          recommendation: 'Wrap related database operations in transactions'
        });
      }

      // Check for race condition potential
      if (content.includes('async') && content.includes('await') && content.includes('UPDATE')) {
        if (!content.includes('lock') && !content.includes('version')) {
          issues.push({
            id: `consistency-${Date.now()}-race-conditions`,
            category: 'data-integrity',
            severity: 'MEDIUM',
            description: 'Potential race conditions in concurrent updates',
            file,
            autoFixable: false,
            impact: ['data-consistency', 'concurrency'],
            recommendation: 'Implement optimistic locking or database-level locks'
          });
        }
      }
    }

    return issues;
  }

  private async checkBackups(): Promise<Issue[]> {
    const issues: Issue[] = [];
    
    try {
      // Check for backup scripts
      const backupFiles = await this.findFiles(['**/backup**', '**/scripts/backup**']);
      
      if (backupFiles.length === 0) {
        issues.push({
          id: `backup-${Date.now()}-missing-scripts`,
          category: 'data-integrity',
          severity: 'CRITICAL',
          description: 'No backup scripts or procedures detected',
          autoFixable: false,
          impact: ['disaster-recovery', 'business-continuity'],
          recommendation: 'Implement automated backup procedures'
        });
      }

      // Check for backup configuration
      const configFiles = await this.findFiles(['**/config**', '**/.env**']);
      let hasBackupConfig = false;
      
      for (const file of configFiles) {
        const content = await fs.readFile(file, 'utf-8');
        if (content.includes('backup') || content.includes('BACKUP')) {
          hasBackupConfig = true;
          break;
        }
      }

      if (!hasBackupConfig) {
        issues.push({
          id: `backup-${Date.now()}-missing-config`,
          category: 'data-integrity',
          severity: 'HIGH',
          description: 'No backup configuration found',
          autoFixable: false,
          impact: ['disaster-recovery'],
          recommendation: 'Configure backup settings in environment variables'
        });
      }

      // Check for backup testing
      const testFiles = await this.findTestFiles();
      const hasBackupTests = testFiles.some(file => 
        file.includes('backup') || file.includes('restore')
      );

      if (!hasBackupTests) {
        issues.push({
          id: `backup-${Date.now()}-no-testing`,
          category: 'data-integrity',
          severity: 'HIGH',
          description: 'No backup/restore testing procedures',
          autoFixable: false,
          impact: ['disaster-recovery', 'reliability'],
          recommendation: 'Implement automated backup testing'
        });
      }
    } catch (error) {
      issues.push({
        id: `backup-${Date.now()}-audit-failed`,
        category: 'data-integrity',
        severity: 'MEDIUM',
        description: 'Unable to audit backup procedures',
        autoFixable: false,
        impact: ['disaster-recovery'],
        recommendation: 'Manually verify backup procedures'
      });
    }

    return issues;
  }

  private async auditRetention(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for data retention policies
      if (content.includes('DELETE') && !content.includes('retention')) {
        issues.push({
          id: `retention-${Date.now()}-no-policy`,
          category: 'data-integrity',
          severity: 'MEDIUM',
          description: 'Data deletion without retention policy',
          file,
          autoFixable: false,
          impact: ['compliance', 'data-governance'],
          recommendation: 'Implement data retention policies'
        });
      }

      // Check for audit logging
      if (content.includes('UPDATE') || content.includes('DELETE')) {
        if (!content.includes('audit') && !content.includes('log')) {
          issues.push({
            id: `retention-${Date.now()}-no-audit-log`,
            category: 'data-integrity',
            severity: 'HIGH',
            description: 'Data modifications without audit logging',
            file,
            autoFixable: true,
            impact: ['compliance', 'traceability'],
            recommendation: 'Add audit logging for all data modifications'
          });
        }
      }

      // Check for soft delete implementation
      if (content.includes('DELETE FROM') && !content.includes('deleted_at')) {
        issues.push({
          id: `retention-${Date.now()}-hard-delete`,
          category: 'data-integrity',
          severity: 'MEDIUM',
          description: 'Hard deletes without soft delete option',
          file,
          autoFixable: false,
          impact: ['data-recovery', 'compliance'],
          recommendation: 'Consider implementing soft deletes for important data'
        });
      }

      // Check for data archiving
      if (content.includes('old') || content.includes('archive')) {
        if (!content.includes('archive') && content.includes('DELETE')) {
          issues.push({
            id: `retention-${Date.now()}-no-archiving`,
            category: 'data-integrity',
            severity: 'LOW',
            description: 'Old data deletion without archiving',
            file,
            autoFixable: false,
            impact: ['data-recovery', 'analytics'],
            recommendation: 'Archive old data before deletion'
          });
        }
      }
    }

    return issues;
  }

  private calculateDataIntegrityScore(issues: Issue[]): number {
    let score = 100;

    for (const issue of issues) {
      switch (issue.severity) {
        case 'CRITICAL':
          score -= 25;
          break;
        case 'HIGH':
          score -= 15;
          break;
        case 'MEDIUM':
          score -= 8;
          break;
        case 'LOW':
          score -= 3;
          break;
      }
    }

    return Math.max(0, score);
  }

  private async findSourceFiles(): Promise<string[]> {
    const extensions = ['.ts', '.js', '.sql', '.tsx', '.jsx'];
    const files: string[] = [];

    async function scanDirectory(dir: string): Promise<void> {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
            await scanDirectory(fullPath);
          } else if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
            files.push(fullPath);
          }
        }
      } catch (error) {
        // Skip directories we can't read
      }
    }

    await scanDirectory('./src');
    await scanDirectory('./database');
    return files;
  }

  private async findFiles(patterns: string[]): Promise<string[]> {
    const files: string[] = [];

    async function scanDirectory(dir: string): Promise<void> {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
            await scanDirectory(fullPath);
          } else if (entry.isFile()) {
            const isMatch = patterns.some(pattern => {
              const regex = new RegExp(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'));
              return regex.test(fullPath);
            });
            if (isMatch) {
              files.push(fullPath);
            }
          }
        }
      } catch (error) {
        // Skip directories we can't read
      }
    }

    await scanDirectory('./');
    return files;
  }

  private async findTestFiles(): Promise<string[]> {
    const testExtensions = ['.test.ts', '.test.js', '.spec.ts', '.spec.js'];
    const files: string[] = [];

    async function scanDirectory(dir: string): Promise<void> {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
            await scanDirectory(fullPath);
          } else if (entry.isFile() && testExtensions.some(ext => entry.name.endsWith(ext))) {
            files.push(fullPath);
          }
        }
      } catch (error) {
        // Skip directories we can't read
      }
    }

    await scanDirectory('./');
    return files;
  }
}