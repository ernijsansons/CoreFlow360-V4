/**
 * SUPERNOVA Deep Code Audit System
 * Comprehensive line-by-line analysis with maximum detail and reasoning
 */

import { Logger } from '../shared/logger';
import * as fs from 'fs/promises';
import * as path from 'path';

const logger = new Logger({ component: 'supernova-deep-audit'});

// ============================================================================
// SUPERNOVA DEEP AUDIT ORCHESTRATOR
// ============================================================================

export class SupernovaDeepAuditor {
  private static instance: SupernovaDeepAuditor;
  private auditResults: Map<string, FileAuditResult> = new Map();
  private totalLinesAudited = 0;
  private criticalIssues = 0;
  private highIssues = 0;
  private mediumIssues = 0;
  private lowIssues = 0;

  static getInstance(): SupernovaDeepAuditor {
    if (!SupernovaDeepAuditor.instance) {
      SupernovaDeepAuditor.instance = new SupernovaDeepAuditor();
    }
    return SupernovaDeepAuditor.instance;
  }

  /**
   * SUPERNOVA Enhanced: Perform comprehensive line-by-line audit
   */
  async performDeepAudit(projectRoot: string): Promise<DeepAuditReport> {
    logger.info('SUPERNOVA: Starting comprehensive deep audit');
    
    const startTime = Date.now();
    const files = await this.discoverFiles(projectRoot);
    
    for (const file of files) {
      await this.auditFile(file);
    }
    
    const duration = Date.now() - startTime;
    
    return {
      summary: {
        totalFiles: files.length,
        totalLinesAudited: this.totalLinesAudited,
        criticalIssues: this.criticalIssues,
        highIssues: this.highIssues,
        mediumIssues: this.mediumIssues,
        lowIssues: this.lowIssues,
        auditDuration: duration
      },
      files: Array.from(this.auditResults.values()),
      recommendations: this.generateRecommendations()
    };
  }

  private async discoverFiles(projectRoot: string): Promise<string[]> {
    const files: string[] = [];
    const extensions = ['.ts', '.js', '.tsx', '.jsx'];
    
    async function scanDir(dir: string) {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          await scanDir(fullPath);
        } else if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
          files.push(fullPath);
        }
      }
    }
    
    await scanDir(projectRoot);
    return files;
  }

  private async auditFile(filePath: string): Promise<void> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const lines = content.split('\n');
      
      const issues: AuditIssue[] = [];
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNumber = i + 1;
        
        // Check for various issues
        const lineIssues = this.analyzeLine(line, lineNumber, filePath);
        issues.push(...lineIssues);
        
        this.totalLinesAudited++;
      }
      
      const result: FileAuditResult = {
        filePath,
        totalLines: lines.length,
        issues,
        complexity: this.calculateComplexity(content),
        maintainability: this.calculateMaintainability(content),
        security: this.analyzeSecurity(content),
        performance: this.analyzePerformance(content)
      };
      
      this.auditResults.set(filePath, result);
      this.updateIssueCounts(issues);
      
    } catch (error) {
      logger.error(`Failed to audit file ${filePath}:`, error);
    }
  }

  private analyzeLine(line: string, lineNumber: number, filePath: string): AuditIssue[] {
    const issues: AuditIssue[] = [];
    
    // Check for common issues
    if (line.includes('any')) {
      issues.push({
        type: 'type-safety',
        severity: 'medium',
        line: lineNumber,
        message: 'Use of "any" type reduces type safety',
        suggestion: 'Replace with specific type or interface'
      });
    }
    
    if (line.includes('console.log')) {
      issues.push({
        type: 'code-quality',
        severity: 'low',
        line: lineNumber,
        message: 'Console.log should be replaced with proper logging',
        suggestion: 'Use Logger service instead'
      });
    }
    
    if (line.includes('TODO') || line.includes('FIXME')) {
      issues.push({
        type: 'technical-debt',
        severity: 'medium',
        line: lineNumber,
        message: 'Technical debt marker found',
        suggestion: 'Address TODO/FIXME items'
      });
    }
    
    return issues;
  }

  private calculateComplexity(content: string): number {
    // Simple complexity calculation
    const complexityKeywords = ['if', 'else', 'for', 'while', 'switch', 'case', 'catch', 'try'];
    let complexity = 1;
    
    for (const keyword of complexityKeywords) {
      const matches = content.match(new RegExp(`\\b${keyword}\\b`, 'g'));
      if (matches) {
        complexity += matches.length;
      }
    }
    
    return complexity;
  }

  private calculateMaintainability(content: string): number {
    // Simple maintainability score (0-100)
    const lines = content.split('\n');
    const totalLines = lines.length;
    const commentLines = lines.filter(line => line.trim().startsWith('//') || line.trim().startsWith('/*')).length;
    const commentRatio = commentLines / totalLines;
    
    return Math.min(100, Math.max(0, commentRatio * 100));
  }

  private analyzeSecurity(content: string): SecurityAnalysis {
    const issues: string[] = [];
    
    if (content.includes('eval(')) {
      issues.push('Use of eval() is dangerous');
    }
    
    if (content.includes('innerHTML')) {
      issues.push('innerHTML can lead to XSS vulnerabilities');
    }
    
    return {
      score: Math.max(0, 100 - issues.length * 20),
      issues
    };
  }

  private analyzePerformance(content: string): PerformanceAnalysis {
    const issues: string[] = [];
    
    if (content.includes('for (let i = 0; i < array.length; i++)')) {
      issues.push('Consider using for...of or forEach for better performance');
    }
    
    return {
      score: Math.max(0, 100 - issues.length * 15),
      issues
    };
  }

  private updateIssueCounts(issues: AuditIssue[]): void {
    for (const issue of issues) {
      switch (issue.severity) {
        case 'critical':
          this.criticalIssues++;
          break;
        case 'high':
          this.highIssues++;
          break;
        case 'medium':
          this.mediumIssues++;
          break;
        case 'low':
          this.lowIssues++;
          break;
      }
    }
  }

  private generateRecommendations(): string[] {
    const recommendations: string[] = [];
    
    if (this.criticalIssues > 0) {
      recommendations.push('Address critical issues immediately');
    }
    
    if (this.highIssues > 0) {
      recommendations.push('Plan to address high-priority issues');
    }
    
    if (this.mediumIssues > 0) {
      recommendations.push('Schedule time for medium-priority issues');
    }
    
    return recommendations;
  }
}

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================

export interface DeepAuditReport {
  summary: AuditSummary;
  files: FileAuditResult[];
  recommendations: string[];
}

export interface AuditSummary {
  totalFiles: number;
  totalLinesAudited: number;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  auditDuration: number;
}

export interface FileAuditResult {
  filePath: string;
  totalLines: number;
  issues: AuditIssue[];
  complexity: number;
  maintainability: number;
  security: SecurityAnalysis;
  performance: PerformanceAnalysis;
}

export interface AuditIssue {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  line: number;
  message: string;
  suggestion: string;
}

export interface SecurityAnalysis {
  score: number;
  issues: string[];
}

export interface PerformanceAnalysis {
  score: number;
  issues: string[];
}

