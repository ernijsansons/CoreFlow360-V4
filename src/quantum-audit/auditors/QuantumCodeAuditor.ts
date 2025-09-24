import * as fs from 'fs/promises';
import * as path from 'path';
import { CodeQualityAuditResult, Issue } from '../types/index';

export class QuantumCodeAuditor {
  async auditCodeQuality(): Promise<CodeQualityAuditResult> {

    const [
      complexity,
      duplication,
      testCoverage,
      documentation
    ] = await Promise.all([
      this.analyzeComplexity(),
      this.detectDuplication(),
      this.checkTestCoverage(),
      this.auditDocumentation()
    ]);

    const allIssues = [
      ...complexity,
      ...duplication,
      ...testCoverage,
      ...documentation
    ];

    const score = this.calculateCodeQualityScore(allIssues);


    return {
      complexity,
      duplication,
      testCoverage,
      documentation,
      score
    };
  }

  private async analyzeComplexity(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');
      const lines = content.split('\n');

      // Check cyclomatic complexity
      let complexity = 1;
      const complexityKeywords = ['if', 'else if', 'for', 'while', 'switch', 'case', 'catch', '&&', '||'];
      
      for (const line of lines) {
        for (const keyword of complexityKeywords) {
          if (line.includes(keyword)) {
            complexity++;
          }
        }
      }

      if (complexity > 15) {
        issues.push({
          id: `complexity-${Date.now()}-high`,
          category: 'code-quality',
          severity: 'HIGH',
          description: `High cyclomatic complexity detected (${complexity})`,
          file,
          autoFixable: false,
          impact: ['maintainability', 'testability'],
          recommendation: 'Break down function into smaller, more focused functions'
        });
      }

      // Check function length
      const functionMatches = content.match(/function\s+\w+[^{]*\{[^}]*\}/gs) || [];
      for (const func of functionMatches) {
        const funcLines = func.split('\n').length;
        if (funcLines > 50) {
          issues.push({
            id: `complexity-${Date.now()}-long-function`,
            category: 'code-quality',
            severity: 'MEDIUM',
            description: `Function exceeds recommended length (${funcLines} lines)`,
            file,
            autoFixable: false,
            impact: ['maintainability', 'readability'],
            recommendation: 'Split function into smaller, more focused functions'
          });
        }
      }

      // Check nesting depth
      let maxNesting = 0;
      let currentNesting = 0;
      for (const line of lines) {
        const openBraces = (line.match(/\{/g) || []).length;
        const closeBraces = (line.match(/\}/g) || []).length;
        currentNesting += openBraces - closeBraces;
        maxNesting = Math.max(maxNesting, currentNesting);
      }

      if (maxNesting > 5) {
        issues.push({
          id: `complexity-${Date.now()}-deep-nesting`,
          category: 'code-quality',
          severity: 'MEDIUM',
          description: `Deep nesting detected (${maxNesting} levels)`,
          file,
          autoFixable: false,
          impact: ['readability', 'maintainability'],
          recommendation: 'Reduce nesting by using early returns or extracting functions'
        });
      }
    }

    return issues;
  }

  private async detectDuplication(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();
    const codeBlocks = new Map<string, string[]>();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');
      const lines = content.split('\n');

      // Look for duplicate code blocks (5+ lines)
      for (let i = 0; i < lines.length - 5; i++) {
        const block = lines.slice(i, i + 5).join('\n').trim();
        if (block.length > 50) { // Ignore very short blocks
          if (!codeBlocks.has(block)) {
            codeBlocks.set(block, []);
          }
          codeBlocks.get(block)!.push(file);
        }
      }
    }

    // Report duplicates
    for (const [block, files] of codeBlocks) {
      if (files.length > 1) {
        issues.push({
          id: `duplication-${Date.now()}-${files.length}`,
          category: 'code-quality',
          severity: 'MEDIUM',
          description: `Duplicate code found in ${files.length} files`,
          autoFixable: false,
          impact: ['maintainability', 'consistency'],
          recommendation: 'Extract common code into shared functions or modules'
        });
      }
    }

    return issues;
  }

  private async checkTestCoverage(): Promise<Issue[]> {
    const issues: Issue[] = [];
    
    try {
      // Look for test files
      const testFiles = await this.findTestFiles();
      const sourceFiles = await this.findSourceFiles();
      
      const coverage = (testFiles.length / sourceFiles.length) * 100;
      
      if (coverage < 80) {
        issues.push({
          id: `test-${Date.now()}-low-coverage`,
          category: 'code-quality',
          severity: 'HIGH',
          description: `Low test coverage (${coverage.toFixed(1)}%)`,
          autoFixable: false,
          impact: ['reliability', 'maintainability'],
          recommendation: 'Increase test coverage to at least 80%'
        });
      }

      // Check for missing test files for critical modules
      const criticalModules = ['auth', 'payment', 'security'];
      for (const module of criticalModules) {
        const hasTests = testFiles.some(file => file.includes(module));
        if (!hasTests) {
          issues.push({
            id: `test-${Date.now()}-missing-critical`,
            category: 'code-quality',
            severity: 'CRITICAL',
            description: `Missing tests for critical module: ${module}`,
            autoFixable: false,
            impact: ['reliability', 'security'],
            recommendation: `Add comprehensive tests for ${module} module`
          });
        }
      }
    } catch (error) {
      issues.push({
        id: `test-${Date.now()}-no-tests`,
        category: 'code-quality',
        severity: 'CRITICAL',
        description: 'No test framework or test files detected',
        autoFixable: false,
        impact: ['reliability', 'maintainability'],
        recommendation: 'Set up testing framework and write comprehensive tests'
      });
    }

    return issues;
  }

  private async auditDocumentation(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for missing JSDoc comments on functions
      const functionMatches = content.match(/(?:export\s+)?(?:async\s+)?function\s+\w+/g) || [];
      const jsdocMatches = content.match(/\/\*\*[\s\S]*?\*\//g) || [];
      
      if (functionMatches.length > jsdocMatches.length) {
        issues.push({
          id: `docs-${Date.now()}-missing-jsdoc`,
          category: 'code-quality',
          severity: 'LOW',
          description: 'Functions missing JSDoc documentation',
          file,
          autoFixable: true,
          impact: ['maintainability', 'developer-experience'],
          recommendation: 'Add JSDoc comments to all public functions'
        });
      }

      // Check for missing README
      if (file.includes('index.ts') && !content.includes('README')) {
        try {
          await fs.access(path.join(path.dirname(file), 'README.md'));
        } catch {
          issues.push({
            id: `docs-${Date.now()}-missing-readme`,
            category: 'code-quality',
            severity: 'MEDIUM',
            description: 'Module missing README documentation',
            file: path.dirname(file),
            autoFixable: true,
            impact: ['developer-experience', 'onboarding'],
            recommendation: 'Add README.md with module description and usage examples'
          });
        }
      }

      // Check for TODO comments
      const todoMatches = content.match(/\/\/ TODO|TODO:/gi);
      if (todoMatches && todoMatches.length > 5) {
        issues.push({
          id: `docs-${Date.now()}-excessive-todos`,
          category: 'code-quality',
          severity: 'LOW',
          description: `Excessive TODO comments (${todoMatches.length})`,
          file,
          autoFixable: false,
          impact: ['maintainability'],
          recommendation: 'Convert TODOs to GitHub issues or complete the tasks'
        });
      }
    }

    return issues;
  }

  private calculateCodeQualityScore(issues: Issue[]): number {
    let score = 100;

    for (const issue of issues) {
      switch (issue.severity) {
        case 'CRITICAL':
          score -= 20;
          break;
        case 'HIGH':
          score -= 12;
          break;
        case 'MEDIUM':
          score -= 6;
          break;
        case 'LOW':
          score -= 2;
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
      } catch (error) {
        // Skip directories we can't read
      }
    }

    await scanDirectory('./src');
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