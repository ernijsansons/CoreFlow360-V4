import * as fs from 'fs/promises';
import * as path from 'path';
import { PerformanceAuditResult, Issue } from '../types/index';

export class QuantumPerformanceAuditor {
  async auditPerformance(): Promise<PerformanceAuditResult> {

    const [
      bottlenecks,
      memoryLeaks,
      inefficientQueries,
      cachingIssues
    ] = await Promise.all([
      this.identifyBottlenecks(),
      this.detectMemoryLeaks(),
      this.auditQueries(),
      this.checkCaching()
    ]);

    const allIssues = [
      ...bottlenecks,
      ...memoryLeaks,
      ...inefficientQueries,
      ...cachingIssues
    ];

    const score = this.calculatePerformanceScore(allIssues);


    return {
      bottlenecks,
      memoryLeaks,
      inefficientQueries,
      cachingIssues,
      score
    };
  }

  private async identifyBottlenecks(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for synchronous blocking operations
      if (content.includes('fs.readFileSync') || content.includes('fs.writeFileSync')) {
        issues.push({
          id: `perf-${Date.now()}-sync-fs`,
          category: 'performance',
          severity: 'HIGH',
          description: 'Synchronous file operations detected - blocking event loop',
          file,
          autoFixable: true,
          impact: ['performance', 'user-experience'],
          recommendation: 'Use async file operations (fs.promises or fs.readFile with callbacks)'
        });
      }

      // Check for blocking JSON operations on large data
      if (content.includes('JSON.parse') && content.includes('stringify')) {
        issues.push({
          id: `perf-${Date.now()}-json-parse`,
          category: 'performance',
          severity: 'MEDIUM',
          description: 'Large JSON parsing operations may block event loop',
          file,
          autoFixable: false,
          impact: ['performance'],
          recommendation: 'Consider streaming JSON parser for large payloads'
        });
      }

      // Check for inefficient loops
      const nestedLoopPattern = /for\s*\([^}]*\{[^}]*for\s*\(/g;
      if (nestedLoopPattern.test(content)) {
        issues.push({
          id: `perf-${Date.now()}-nested-loops`,
          category: 'performance',
          severity: 'MEDIUM',
          description: 'Nested loops detected - potential O(n²) complexity',
          file,
          autoFixable: false,
          impact: ['performance', 'scalability'],
          recommendation: 'Consider optimizing algorithm complexity'
        });
      }

      // Check for missing pagination
      if (content.includes('SELECT') && !content.includes('LIMIT') && !content.includes('OFFSET')) {
        issues.push({
          id: `perf-${Date.now()}-no-pagination`,
          category: 'performance',
          severity: 'HIGH',
          description: 'Database queries without pagination detected',
          file,
          autoFixable: true,
          impact: ['performance', 'scalability'],
          recommendation: 'Implement pagination for database queries'
        });
      }

      // Check for inefficient array operations
      if (content.includes('.forEach(') && content.includes('.push(')) {
        issues.push({
          id: `perf-${Date.now()}-inefficient-array`,
          category: 'performance',
          severity: 'LOW',
          description: 'Inefficient array operations - forEach with push',
          file,
          autoFixable: true,
          impact: ['performance'],
          recommendation: 'Use map() instead of forEach with push'
        });
      }

      // Check for missing compression
      if (content.includes('express') && !content.includes('compression')) {
        issues.push({
          id: `perf-${Date.now()}-no-compression`,
          category: 'performance',
          severity: 'MEDIUM',
          description: 'Express server without compression middleware',
          file,
          autoFixable: true,
          impact: ['performance', 'bandwidth'],
          recommendation: 'Add compression middleware to Express'
        });
      }
    }

    return issues;
  }

  private async detectMemoryLeaks(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for event listeners without cleanup
      if (content.includes('addEventListener') && !content.includes('removeEventListener')) {
        issues.push({
          id: `memory-${Date.now()}-event-listeners`,
          category: 'performance',
          severity: 'HIGH',
          description: 'Event listeners added without cleanup - potential memory leak',
          file,
          autoFixable: false,
          impact: ['performance', 'memory'],
          recommendation: 'Always remove event listeners in cleanup functions'
        });
      }

      // Check for setInterval without clearInterval
      if (content.includes('setInterval') && !content.includes('clearInterval')) {
        issues.push({
          id: `memory-${Date.now()}-intervals`,
          category: 'performance',
          severity: 'HIGH',
          description: 'setInterval without clearInterval - potential memory leak',
          file,
          autoFixable: false,
          impact: ['performance', 'memory'],
          recommendation: 'Always clear intervals when component unmounts'
        });
      }

      // Check for global variables
      const globalVarPattern = /var\s+\w+\s*=|let\s+\w+\s*=|const\s+\w+\s*=/g;
      const matches = content.match(globalVarPattern);
      if (matches && matches.length > 10) {
        issues.push({
          id: `memory-${Date.now()}-global-vars`,
          category: 'performance',
          severity: 'MEDIUM',
          description: 'Excessive global variables detected',
          file,
          autoFixable: false,
          impact: ['performance', 'memory'],
          recommendation: 'Reduce global scope pollution'
        });
      }

      // Check for large object creation in loops
      if (content.includes('for') && content.includes('new ') && content.includes('{')) {
        issues.push({
          id: `memory-${Date.now()}-object-creation`,
          category: 'performance',
          severity: 'MEDIUM',
          description: 'Object creation inside loops - high memory allocation',
          file,
          autoFixable: false,
          impact: ['performance', 'memory', 'gc-pressure'],
          recommendation: 'Move object creation outside loops or use object pooling'
        });
      }
    }

    return issues;
  }

  private async auditQueries(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const queryFiles = await this.findFiles(['**/*service*.ts', '**/*repository*.ts', '**/*dao*.ts']);

    for (const file of queryFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for N+1 query patterns
      if (content.includes('forEach') && content.includes('SELECT')) {
        issues.push({
          id: `query-${Date.now()}-n-plus-one`,
          category: 'performance',
          severity: 'CRITICAL',
          description: 'Potential N+1 query problem detected',
          file,
          autoFixable: false,
          impact: ['performance', 'database'],
          recommendation: 'Use batch queries or eager loading to avoid N+1 problems'
        });
      }

      // Check for missing indexes
      if (content.includes('WHERE') && !content.includes('INDEX')) {
        issues.push({
          id: `query-${Date.now()}-missing-index`,
          category: 'performance',
          severity: 'HIGH',
          description: 'Queries on potentially unindexed columns',
          file,
          autoFixable: false,
          impact: ['performance', 'database'],
          recommendation: 'Add database indexes for frequently queried columns'
        });
      }

      // Check for SELECT *
      if (content.includes('SELECT *') || content.includes('select *')) {
        issues.push({
          id: `query-${Date.now()}-select-all`,
          category: 'performance',
          severity: 'MEDIUM',
          description: 'SELECT * queries detected - fetching unnecessary data',
          file,
          autoFixable: true,
          impact: ['performance', 'bandwidth'],
          recommendation: 'Specify only required columns in SELECT statements'
        });
      }

      // Check for missing query timeouts
      if (content.includes('query') && !content.includes('timeout')) {
        issues.push({
          id: `query-${Date.now()}-no-timeout`,
          category: 'performance',
          severity: 'MEDIUM',
          description: 'Database queries without timeout configuration',
          file,
          autoFixable: true,
          impact: ['performance', 'reliability'],
          recommendation: 'Add query timeouts to prevent hanging connections'
        });
      }

      // Check for lack of connection pooling
      if (content.includes('createConnection') && !content.includes('pool')) {
        issues.push({
          id: `query-${Date.now()}-no-pooling`,
          category: 'performance',
          severity: 'HIGH',
          description: 'Database connections without pooling',
          file,
          autoFixable: false,
          impact: ['performance', 'scalability'],
          recommendation: 'Implement connection pooling for database operations'
        });
      }
    }

    return issues;
  }

  private async checkCaching(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for API routes without caching
      if (content.includes('app.get') || content.includes('router.get')) {
        if (!content.includes('cache') && !content.includes('redis') && !content.includes('etag')) {
          issues.push({
            id: `cache-${Date.now()}-no-caching`,
            category: 'performance',
            severity: 'MEDIUM',
            description: 'API endpoints without caching strategy',
            file,
            autoFixable: true,
            impact: ['performance', 'scalability'],
            recommendation: 'Implement caching for frequently accessed endpoints'
          });
        }
      }

      // Check for static assets without caching headers
      if (content.includes('static') && !content.includes('maxAge') && !content.includes('cache-control')) {
        issues.push({
          id: `cache-${Date.now()}-static-no-cache`,
          category: 'performance',
          severity: 'MEDIUM',
          description: 'Static assets served without cache headers',
          file,
          autoFixable: true,
          impact: ['performance', 'bandwidth'],
          recommendation: 'Add appropriate cache headers for static assets'
        });
      }

      // Check for repeated expensive computations
      if (content.includes('crypto.') && !content.includes('memoize') && !content.includes('cache')) {
        issues.push({
          id: `cache-${Date.now()}-crypto-no-cache`,
          category: 'performance',
          severity: 'HIGH',
          description: 'Expensive cryptographic operations without caching',
          file,
          autoFixable: false,
          impact: ['performance', 'cpu'],
          recommendation: 'Cache results of expensive cryptographic operations'
        });
      }

      // Check for database queries without caching
      if (content.includes('SELECT') && !content.includes('cache') && !content.includes('redis')) {
        issues.push({
          id: `cache-${Date.now()}-query-no-cache`,
          category: 'performance',
          severity: 'MEDIUM',
          description: 'Database queries without result caching',
          file,
          autoFixable: false,
          impact: ['performance', 'database'],
          recommendation: 'Implement query result caching for frequently accessed data'
        });
      }
    }

    return issues;
  }

  private calculatePerformanceScore(issues: Issue[]): number {
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
    const extensions = ['.ts', '.js', '.tsx', '.jsx'];
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
      } catch (error: any) {
        // Skip directories we can't read
      }
    }

    await scanDirectory('./src');
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
      } catch (error: any) {
        // Skip directories we can't read
      }
    }

    await scanDirectory('./src');
    return files;
  }
}