import { Logger } from '../shared/logger';
import type { Context } from 'hono';
import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

const logger = new Logger({ component: 'complexity-analyzer' });

export interface ComplexityAnalyzerConfig {
  cyclomatic: {
    maxComplexity: number;
    checkPerFunction: boolean;
  };
  cognitive: {
    maxComplexity: number;
    checkNesting: boolean;
  };
  maintenance: {
    checkDuplication: boolean;
    maxFileLength: number;
    maxFunctionLength: number;
  };
}

export interface ComplexityAuditReport {
  score: number;
  cyclomaticComplexity: CyclomaticAnalysis;
  cognitiveComplexity: CognitiveAnalysis;
  maintainability: MaintainabilityAnalysis;
  hotspots: ComplexityHotspot[];
  recommendations: ComplexityRecommendation[];
}

export interface CyclomaticAnalysis {
  average: number;
  max: number;
  distribution: ComplexityDistribution[];
  violations: ComplexityViolation[];
}

export interface CognitiveAnalysis {
  average: number;
  max: number;
  nestingDepth: NestingAnalysis;
  violations: ComplexityViolation[];
}

export interface ComplexityDistribution {
  range: string;
  count: number;
  percentage: number;
}

export interface ComplexityViolation {
  function: string;
  file: string;
  complexity: number;
  threshold: number;
  recommendation: string;
}

export interface NestingAnalysis {
  maxDepth: number;
  averageDepth: number;
  violations: NestingViolation[];
}

export interface NestingViolation {
  location: string;
  depth: number;
  type: string;
  fix: string;
}

export interface MaintainabilityAnalysis {
  index: number;
  duplication: DuplicationAnalysis;
  fileMetrics: FileMetrics;
  functionMetrics: FunctionMetrics;
}

export interface DuplicationAnalysis {
  percentage: number;
  duplicates: CodeDuplicate[];
  totalLines: number;
  duplicatedLines: number;
}

export interface CodeDuplicate {
  locations: Array<{ file: string; line?: number }>;
  lines: number;
  tokens: number;
  recommendation: string;
}

export interface FileMetrics {
  averageLength: number;
  maxLength: number;
  violations: FileLengthViolation[];
}

export interface FileLengthViolation {
  file: string;
  lines: number;
  threshold: number;
  recommendation: string;
}

export interface FunctionMetrics {
  averageLength: number;
  maxLength: number;
  violations: FunctionLengthViolation[];
}

export interface FunctionLengthViolation {
  function: string;
  file: string;
  lines: number;
  threshold: number;
  recommendation: string;
}

export interface ComplexityHotspot {
  location: string;
  type: 'cyclomatic' | 'cognitive' | 'nesting';
  value: number;
  impact: string;
  refactoring: string;
}

export interface ComplexityRecommendation {
  target: string;
  issue: string;
  recommendation: string;
  complexity: number;
  improvement: number;
}

export class ComplexityAnalyzer {
  private logger: Logger;
  private config: ComplexityAnalyzerConfig;
  private sourceFiles: string[] = [];
  private complexityData: Map<string, FunctionComplexity[]> = new Map();

  constructor(private readonly context: Context) {
    this.logger = new Logger({ component: 'complexity-analyzer' });
    this.config = {
      cyclomatic: { maxComplexity: 10, checkPerFunction: true },
      cognitive: { maxComplexity: 15, checkNesting: true },
      maintenance: { checkDuplication: true, maxFileLength: 500, maxFunctionLength: 50 }
    };
  }

  async analyze(config: ComplexityAnalyzerConfig): Promise<ComplexityAuditReport> {
    this.config = config;
    this.logger.info('Starting complexity analysis');

    // Discover source files
    await this.discoverSourceFiles();

    // Analyze each file
    for (const file of this.sourceFiles) {
      await this.analyzeFile(file);
    }

    // Generate report
    const cyclomaticAnalysis = this.analyzeCyclomaticComplexity();
    const cognitiveAnalysis = this.analyzeCognitiveComplexity();
    const maintainabilityAnalysis = this.analyzeMaintainability();
    const hotspots = this.identifyHotspots();
    const recommendations = this.generateRecommendations();

    const score = this.calculateComplexityScore({
      cyclomaticAnalysis,
      cognitiveAnalysis,
      maintainabilityAnalysis
    });

    return {
      score,
      cyclomaticComplexity: cyclomaticAnalysis,
      cognitiveComplexity: cognitiveAnalysis,
      maintainability: maintainabilityAnalysis,
      hotspots,
      recommendations
    };
  }

  private async discoverSourceFiles(): Promise<void> {
    const srcPath = path.join(process.cwd(), 'src');

    // In production, this would recursively find all .ts/.js files
    // For now, we'll simulate with sample data
    this.sourceFiles = [
      'src/index.ts',
      'src/modules/auth/service.ts',
      'src/routes/auth.ts',
      'src/middleware/auth.ts'
    ];
  }

  private async analyzeFile(filePath: string): Promise<void> {
    try {
      // In production, we'd parse the actual file
      // For now, simulate complexity data
      const functions = this.simulateFunctionComplexity(filePath);
      this.complexityData.set(filePath, functions);
    } catch (error) {
      this.logger.error('Error analyzing file', { filePath, error });
    }
  }

  private simulateFunctionComplexity(filePath: string): FunctionComplexity[] {
    // Simulate realistic complexity data based on file type
    const isAuthFile = filePath.includes('auth');
    const isServiceFile = filePath.includes('service');

    return [
      {
        name: isAuthFile ? 'validateToken' : 'processRequest',
        cyclomatic: isServiceFile ? 12 : 6,
        cognitive: isServiceFile ? 18 : 8,
        nesting: isAuthFile ? 4 : 2,
        lines: isServiceFile ? 75 : 35
      },
      {
        name: isAuthFile ? 'refreshTokens' : 'handleError',
        cyclomatic: 8,
        cognitive: 10,
        nesting: 3,
        lines: 45
      }
    ];
  }

  private analyzeCyclomaticComplexity(): CyclomaticAnalysis {
    const allComplexities: number[] = [];
    const violations: ComplexityViolation[] = [];

    for (const [file, functions] of this.complexityData) {
      for (const func of functions) {
        allComplexities.push(func.cyclomatic);

        if (func.cyclomatic > this.config.cyclomatic.maxComplexity) {
          violations.push({
            function: func.name,
            file,
            complexity: func.cyclomatic,
            threshold: this.config.cyclomatic.maxComplexity,
            recommendation: this.getComplexityRecommendation(func.cyclomatic)
          });
        }
      }
    }

    const average = allComplexities.reduce((a, b) => a + b, 0) / allComplexities.length || 0;
    const max = Math.max(...allComplexities, 0);

    return {
      average: Math.round(average * 10) / 10,
      max,
      distribution: this.calculateDistribution(allComplexities),
      violations
    };
  }

  private analyzeCognitiveComplexity(): CognitiveAnalysis {
    const allComplexities: number[] = [];
    const violations: ComplexityViolation[] = [];
    const nestingDepths: number[] = [];

    for (const [file, functions] of this.complexityData) {
      for (const func of functions) {
        allComplexities.push(func.cognitive);
        nestingDepths.push(func.nesting);

        if (func.cognitive > this.config.cognitive.maxComplexity) {
          violations.push({
            function: func.name,
            file,
            complexity: func.cognitive,
            threshold: this.config.cognitive.maxComplexity,
            recommendation: 'Simplify logic, reduce nesting, extract helper functions'
          });
        }
      }
    }

    const average = allComplexities.reduce((a, b) => a + b, 0) / allComplexities.length || 0;
    const max = Math.max(...allComplexities, 0);
    const avgNesting = nestingDepths.reduce((a, b) => a + b, 0) / nestingDepths.length || 0;

    return {
      average: Math.round(average * 10) / 10,
      max,
      nestingDepth: {
        maxDepth: Math.max(...nestingDepths, 0),
        averageDepth: Math.round(avgNesting * 10) / 10,
        violations: this.findNestingViolations()
      },
      violations
    };
  }

  private analyzeMaintainability(): MaintainabilityAnalysis {
    const fileViolations: FileLengthViolation[] = [];
    const functionViolations: FunctionLengthViolation[] = [];
    const fileLengths: number[] = [];
    const functionLengths: number[] = [];

    // Simulate file and function metrics
    for (const [file, functions] of this.complexityData) {
      const fileLength = functions.reduce((sum, f) => sum + f.lines, 0) + 50; // Add overhead
      fileLengths.push(fileLength);

      if (fileLength > this.config.maintenance.maxFileLength) {
        fileViolations.push({
          file,
          lines: fileLength,
          threshold: this.config.maintenance.maxFileLength,
          recommendation: 'Split file into smaller modules'
        });
      }

      for (const func of functions) {
        functionLengths.push(func.lines);

        if (func.lines > this.config.maintenance.maxFunctionLength) {
          functionViolations.push({
            function: func.name,
            file,
            lines: func.lines,
            threshold: this.config.maintenance.maxFunctionLength,
            recommendation: 'Extract helper functions or split functionality'
          });
        }
      }
    }

    // Calculate maintainability index (simplified version)
    const avgComplexity = this.calculateAverageComplexity();
    const maintainabilityIndex = Math.max(0, 171 - 5.2 * Math.log(avgComplexity) - 0.23 * avgComplexity);

    return {
      index: Math.round(maintainabilityIndex),
      duplication: this.analyzeDuplication(),
      fileMetrics: {
        averageLength: Math.round(fileLengths.reduce((a, b) => a + b, 0) / fileLengths.length || 0),
        maxLength: Math.max(...fileLengths, 0),
        violations: fileViolations
      },
      functionMetrics: {
        averageLength: Math.round(functionLengths.reduce((a, b) => a + b, 0) / functionLengths.length || 0),
        maxLength: Math.max(...functionLengths, 0),
        violations: functionViolations
      }
    };
  }

  private analyzeDuplication(): DuplicationAnalysis {
    // Simulate duplication detection
    const duplicates: CodeDuplicate[] = [
      {
        locations: [
          { file: 'src/routes/auth.ts', line: 45 },
          { file: 'src/routes/users.ts', line: 67 }
        ],
        lines: 25,
        tokens: 150,
        recommendation: 'Extract common validation logic to shared utility'
      }
    ];

    const totalLines = 2500; // Simulated
    const duplicatedLines = duplicates.reduce((sum, d) => sum + d.lines, 0);

    return {
      percentage: Math.round((duplicatedLines / totalLines) * 100),
      duplicates,
      totalLines,
      duplicatedLines
    };
  }

  private identifyHotspots(): ComplexityHotspot[] {
    const hotspots: ComplexityHotspot[] = [];

    for (const [file, functions] of this.complexityData) {
      for (const func of functions) {
        if (func.cyclomatic > 15) {
          hotspots.push({
            location: `${file}:${func.name}`,
            type: 'cyclomatic',
            value: func.cyclomatic,
            impact: 'Difficult to test and maintain',
            refactoring: 'Apply Extract Method pattern'
          });
        }

        if (func.cognitive > 20) {
          hotspots.push({
            location: `${file}:${func.name}`,
            type: 'cognitive',
            value: func.cognitive,
            impact: 'Hard to understand and modify',
            refactoring: 'Simplify conditionals and reduce nesting'
          });
        }

        if (func.nesting > 4) {
          hotspots.push({
            location: `${file}:${func.name}`,
            type: 'nesting',
            value: func.nesting,
            impact: 'Deep nesting makes code hard to follow',
            refactoring: 'Use early returns and guard clauses'
          });
        }
      }
    }

    return hotspots.sort((a, b) => b.value - a.value).slice(0, 10);
  }

  private generateRecommendations(): ComplexityRecommendation[] {
    const recommendations: ComplexityRecommendation[] = [];

    // Analyze patterns and generate recommendations
    const avgCyclomatic = this.calculateAverageComplexity();

    if (avgCyclomatic > 8) {
      recommendations.push({
        target: 'Overall Codebase',
        issue: 'High average cyclomatic complexity',
        recommendation: 'Implement coding standards for max complexity per function',
        complexity: avgCyclomatic,
        improvement: 30 // percentage
      });
    }

    // Check for specific high-complexity patterns
    for (const [file, functions] of this.complexityData) {
      const highComplexityFuncs = functions.filter(f => f.cyclomatic > 15);
      if (highComplexityFuncs.length > 0) {
        recommendations.push({
          target: file,
          issue: `${highComplexityFuncs.length} functions with excessive complexity`,
          recommendation: 'Refactor using Strategy or Command patterns',
          complexity: Math.max(...highComplexityFuncs.map(f => f.cyclomatic)),
          improvement: 40
        });
      }
    }

    return recommendations;
  }

  private calculateDistribution(values: number[]): ComplexityDistribution[] {
    const ranges = [
      { min: 0, max: 5, label: '0-5 (Simple)' },
      { min: 6, max: 10, label: '6-10 (Moderate)' },
      { min: 11, max: 20, label: '11-20 (Complex)' },
      { min: 21, max: Infinity, label: '21+ (Very Complex)' }
    ];

    return ranges.map(range => {
      const count = values.filter(v => v >= range.min && v <= range.max).length;
      return {
        range: range.label,
        count,
        percentage: Math.round((count / values.length) * 100) || 0
      };
    });
  }

  private findNestingViolations(): NestingViolation[] {
    const violations: NestingViolation[] = [];

    for (const [file, functions] of this.complexityData) {
      for (const func of functions) {
        if (func.nesting > 3) {
          violations.push({
            location: `${file}:${func.name}`,
            depth: func.nesting,
            type: 'excessive_nesting',
            fix: 'Extract nested logic into separate functions'
          });
        }
      }
    }

    return violations;
  }

  private getComplexityRecommendation(complexity: number): string {
    if (complexity <= 10) return 'Consider simplifying if possible';
    if (complexity <= 20) return 'Extract methods to reduce complexity';
    if (complexity <= 30) return 'Urgent: Apply design patterns to simplify';
    return 'Critical: Major refactoring required';
  }

  private calculateAverageComplexity(): number {
    let total = 0;
    let count = 0;

    for (const functions of this.complexityData.values()) {
      for (const func of functions) {
        total += func.cyclomatic;
        count++;
      }
    }

    return count > 0 ? total / count : 0;
  }

  private calculateComplexityScore(analysis: {
    cyclomaticAnalysis: CyclomaticAnalysis;
    cognitiveAnalysis: CognitiveAnalysis;
    maintainabilityAnalysis: MaintainabilityAnalysis;
  }): number {
    // Score calculation based on thresholds and violations
    let score = 100;

    // Deduct for cyclomatic complexity
    score -= analysis.cyclomaticAnalysis.violations.length * 5;
    score -= Math.max(0, analysis.cyclomaticAnalysis.average - 5) * 2;

    // Deduct for cognitive complexity
    score -= analysis.cognitiveAnalysis.violations.length * 4;
    score -= Math.max(0, analysis.cognitiveAnalysis.average - 7) * 2;

    // Deduct for maintainability issues
    score -= analysis.maintainabilityAnalysis.fileMetrics.violations.length * 3;
    score -= analysis.maintainabilityAnalysis.functionMetrics.violations.length * 2;
    score -= analysis.maintainabilityAnalysis.duplication.percentage * 0.5;

    // Add bonus for good maintainability index
    if (analysis.maintainabilityAnalysis.index > 80) {
      score += 5;
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }
}

interface FunctionComplexity {
  name: string;
  cyclomatic: number;
  cognitive: number;
  nesting: number;
  lines: number;
}