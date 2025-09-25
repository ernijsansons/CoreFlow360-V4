/**
 * SUPERNOVA Code Quality Enhancements
 * Critical code quality improvements for CoreFlow360 V4
 */

import { Logger } from '../shared/logger';

const logger = new Logger({ component: 'supernova-code-quality' });

// ============================================================================
// DEAD CODE DETECTION AND REMOVAL
// ============================================================================

export interface DeadCodeItem {
  type: 'function' | 'variable' | 'import' | 'class' | 'interface';
  name: string;
  file: string;
  line: number;
  reason: string;
  canRemove: boolean;
}

export class SupernovaDeadCodeDetector {
  private static readonly UNUSED_IMPORT_PATTERN = /^import\s+.*?from\s+['"][^'"]+['"];?$/gm;
  private static readonly UNUSED_FUNCTION_PATTERN = /^export\s+function\s+(\w+)/gm;
  private static readonly UNUSED_VARIABLE_PATTERN = /^export\s+const\s+(\w+)/gm;

  /**
   * SUPERNOVA Enhanced: Detect dead code with high accuracy
   */
  static detectDeadCode(content: string, filePath: string): DeadCodeItem[] {
    const deadCode: DeadCodeItem[] = [];

    // Detect unused imports
    const unusedImports = this.detectUnusedImports(content, filePath);
    deadCode.push(...unusedImports);

    // Detect unused functions
    const unusedFunctions = this.detectUnusedFunctions(content, filePath);
    deadCode.push(...unusedFunctions);

    // Detect unused variables
    const unusedVariables = this.detectUnusedVariables(content, filePath);
    deadCode.push(...unusedVariables);

    return deadCode;
  }

  /**
   * SUPERNOVA Enhanced: Remove dead code safely
   */
  static removeDeadCode(content: string, deadCode: DeadCodeItem[]): string {
    let cleanedContent = content;

    // Sort by line number in descending order to avoid offset issues
    const sortedDeadCode = deadCode
      .filter(item => item.canRemove)
      .sort((a, b) => b.line - a.line);

    for (const item of sortedDeadCode) {
      cleanedContent = this.removeItem(cleanedContent, item);
    }

    return cleanedContent;
  }

  private static detectUnusedImports(content: string, filePath: string): DeadCodeItem[] {
    const imports: DeadCodeItem[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const importMatch = line.match(/^import\s+.*?from\s+['"]([^'"]+)['"];?$/);
      if (importMatch) {
        const importPath = importMatch[1];
        const isUsed = this.isImportUsed(content, importPath);
        
        if (!isUsed) {
          imports.push({
            type: 'import',
            name: importPath,
            file: filePath,
            line: index + 1,
            reason: 'Import not used in file',
            canRemove: true
          });
        }
      }
    });

    return imports;
  }

  private static detectUnusedFunctions(content: string, filePath: string): DeadCodeItem[] {
    const functions: DeadCodeItem[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const functionMatch = line.match(/^export\s+function\s+(\w+)/);
      if (functionMatch) {
        const functionName = functionMatch[1];
        const isUsed = this.isFunctionUsed(content, functionName);
        
        if (!isUsed) {
          functions.push({
            type: 'function',
            name: functionName,
            file: filePath,
            line: index + 1,
            reason: 'Exported function not used',
            canRemove: false // Be conservative with exported functions
          });
        }
      }
    });

    return functions;
  }

  private static detectUnusedVariables(content: string, filePath: string): DeadCodeItem[] {
    const variables: DeadCodeItem[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const variableMatch = line.match(/^export\s+const\s+(\w+)/);
      if (variableMatch) {
        const variableName = variableMatch[1];
        const isUsed = this.isVariableUsed(content, variableName);
        
        if (!isUsed) {
          variables.push({
            type: 'variable',
            name: variableName,
            file: filePath,
            line: index + 1,
            reason: 'Exported variable not used',
            canRemove: false // Be conservative with exported variables
          });
        }
      }
    });

    return variables;
  }

  private static isImportUsed(content: string, importPath: string): boolean {
    // Simple check - in real implementation, this would be more sophisticated
    return content.includes(importPath);
  }

  private static isFunctionUsed(content: string, functionName: string): boolean {
    // Check for function calls
    const functionCallPattern = new RegExp(`\\b${functionName}\\s*\\(`, 'g');
    return functionCallPattern.test(content);
  }

  private static isVariableUsed(content: string, variableName: string): boolean {
    // Check for variable usage
    const variablePattern = new RegExp(`\\b${variableName}\\b`, 'g');
    const matches = content.match(variablePattern);
    return matches && matches.length > 1; // More than just the declaration
  }

  private static removeItem(content: string, item: DeadCodeItem): string {
    const lines = content.split('\n');
    
    if (item.line > 0 && item.line <= lines.length) {
      lines.splice(item.line - 1, 1);
    }
    
    return lines.join('\n');
  }
}

// ============================================================================
// TECHNICAL DEBT DETECTION
// ============================================================================

export interface TechnicalDebtItem {
  type: 'TODO' | 'FIXME' | 'HACK' | 'XXX' | 'DEPRECATED' | 'WORKAROUND';
  message: string;
  file: string;
  line: number;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  age: number; // days
  effort: number; // hours
  impact: string[];
}

export class SupernovaTechDebtDetector {
  private static readonly DEBT_PATTERNS = {
    TODO: /TODO[:\s]*(.+)/gi,
    FIXME: /FIXME[:\s]*(.+)/gi,
    HACK: /HACK[:\s]*(.+)/gi,
    XXX: /XXX[:\s]*(.+)/gi,
    DEPRECATED: /@deprecated[:\s]*(.+)/gi,
    WORKAROUND: /workaround[:\s]*(.+)/gi
  };

  /**
   * SUPERNOVA Enhanced: Detect technical debt with priority assessment
   */
  static detectTechnicalDebt(content: string, filePath: string): TechnicalDebtItem[] {
    const debtItems: TechnicalDebtItem[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      for (const [type, pattern] of Object.entries(this.DEBT_PATTERNS)) {
        const match = line.match(pattern);
        if (match) {
          const message = match[1].trim();
          const priority = this.assessPriority(type, message, line);
          const effort = this.estimateEffort(message, type);
          const impact = this.assessImpact(message, type);

          debtItems.push({
            type: type as TechnicalDebtItem['type'],
            message,
            file: filePath,
            line: index + 1,
            priority,
            age: 0, // Would be calculated from git history
            effort,
            impact
          });
        }
      }
    });

    return debtItems;
  }

  /**
   * SUPERNOVA Enhanced: Generate technical debt report
   */
  static generateDebtReport(debtItems: TechnicalDebtItem[]): TechnicalDebtReport {
    const totalDebt = debtItems.length;
    const criticalDebt = debtItems.filter(item => item.priority === 'CRITICAL').length;
    const highDebt = debtItems.filter(item => item.priority === 'HIGH').length;
    const totalEffort = debtItems.reduce((sum, item) => sum + item.effort, 0);

    const debtByType = debtItems.reduce((acc, item) => {
      acc[item.type] = (acc[item.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const debtByPriority = debtItems.reduce((acc, item) => {
      acc[item.priority] = (acc[item.priority] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalDebt,
      criticalDebt,
      highDebt,
      totalEffort,
      debtByType,
      debtByPriority,
      recommendations: this.generateRecommendations(debtItems)
    };
  }

  private static assessPriority(type: string, message: string, line: string): TechnicalDebtItem['priority'] {
    const criticalKeywords = ['security', 'vulnerability', 'data loss', 'crash', 'critical'];
    const highKeywords = ['performance', 'memory leak', 'bug', 'error', 'fix'];
    const mediumKeywords = ['refactor', 'improve', 'optimize', 'cleanup'];

    const lowerMessage = message.toLowerCase();
    const lowerLine = line.toLowerCase();

    if (criticalKeywords.some(keyword => lowerMessage.includes(keyword) || lowerLine.includes(keyword))) {
      return 'CRITICAL';
    }

    if (highKeywords.some(keyword => lowerMessage.includes(keyword) || lowerLine.includes(keyword))) {
      return 'HIGH';
    }

    if (mediumKeywords.some(keyword => lowerMessage.includes(keyword) || lowerLine.includes(keyword))) {
      return 'MEDIUM';
    }

    return 'LOW';
  }

  private static estimateEffort(message: string, type: string): number {
    const effortKeywords = {
      'quick': 1,
      'simple': 2,
      'medium': 4,
      'complex': 8,
      'major': 16,
      'rewrite': 32
    };

    const lowerMessage = message.toLowerCase();
    
    for (const [keyword, effort] of Object.entries(effortKeywords)) {
      if (lowerMessage.includes(keyword)) {
        return effort;
      }
    }

    // Default effort based on type
    const defaultEffort = {
      'TODO': 2,
      'FIXME': 4,
      'HACK': 8,
      'XXX': 4,
      'DEPRECATED': 16,
      'WORKAROUND': 8
    };

    return defaultEffort[type as keyof typeof defaultEffort] || 4;
  }

  private static assessImpact(message: string, type: string): string[] {
    const impacts: string[] = [];
    const lowerMessage = message.toLowerCase();

    if (lowerMessage.includes('security') || lowerMessage.includes('vulnerability')) {
      impacts.push('security');
    }

    if (lowerMessage.includes('performance') || lowerMessage.includes('slow')) {
      impacts.push('performance');
    }

    if (lowerMessage.includes('memory') || lowerMessage.includes('leak')) {
      impacts.push('memory');
    }

    if (lowerMessage.includes('maintainability') || lowerMessage.includes('readability')) {
      impacts.push('maintainability');
    }

    if (lowerMessage.includes('test') || lowerMessage.includes('coverage')) {
      impacts.push('testing');
    }

    return impacts;
  }

  private static generateRecommendations(debtItems: TechnicalDebtItem[]): string[] {
    const recommendations: string[] = [];

    const criticalItems = debtItems.filter(item => item.priority === 'CRITICAL');
    if (criticalItems.length > 0) {
      recommendations.push(`Address ${criticalItems.length} critical technical debt items immediately`);
    }

    const highItems = debtItems.filter(item => item.priority === 'HIGH');
    if (highItems.length > 0) {
      recommendations.push(`Plan to address ${highItems.length} high-priority items in next sprint`);
    }

    const totalEffort = debtItems.reduce((sum, item) => sum + item.effort, 0);
    if (totalEffort > 100) {
      recommendations.push(`Consider allocating
  dedicated time for technical debt reduction (${totalEffort} hours total)`);
    }

    const deprecatedItems = debtItems.filter(item => item.type === 'DEPRECATED');
    if (deprecatedItems.length > 0) {
      recommendations.push(`Remove ${deprecatedItems.length} deprecated code items`);
    }

    return recommendations;
  }
}

// ============================================================================
// CODE COMPLEXITY ANALYSIS
// ============================================================================

export interface ComplexityMetrics {
  cyclomaticComplexity: number;
  cognitiveComplexity: number;
  nestingDepth: number;
  functionLength: number;
  parameterCount: number;
  maintainabilityIndex: number;
}

export class SupernovaComplexityAnalyzer {
  /**
   * SUPERNOVA Enhanced: Analyze function complexity
   */
  static analyzeFunction(functionCode: string): ComplexityMetrics {
    const lines = functionCode.split('\n');
    const functionLength = lines.length;
    
    const cyclomaticComplexity = this.calculateCyclomaticComplexity(functionCode);
    const cognitiveComplexity = this.calculateCognitiveComplexity(functionCode);
    const nestingDepth = this.calculateNestingDepth(functionCode);
    const parameterCount = this.countParameters(functionCode);
    const maintainabilityIndex = this.calculateMaintainabilityIndex({
      cyclomaticComplexity,
      cognitiveComplexity,
      nestingDepth,
      functionLength,
      parameterCount
    });

    return {
      cyclomaticComplexity,
      cognitiveComplexity,
      nestingDepth,
      functionLength,
      parameterCount,
      maintainabilityIndex
    };
  }

  /**
   * SUPERNOVA Enhanced: Get complexity recommendations
   */
  static getComplexityRecommendations(metrics: ComplexityMetrics): string[] {
    const recommendations: string[] = [];

    if (metrics.cyclomaticComplexity > 10) {
      recommendations.push('Reduce cyclomatic complexity by breaking down into smaller functions');
    }

    if (metrics.cognitiveComplexity > 15) {
      recommendations.push('Simplify logic to reduce cognitive complexity');
    }

    if (metrics.nestingDepth > 4) {
      recommendations.push('Reduce nesting depth by using early returns or guard clauses');
    }

    if (metrics.functionLength > 50) {
      recommendations.push('Break down long function into smaller, focused functions');
    }

    if (metrics.parameterCount > 5) {
      recommendations.push('Consider using an options object instead of many parameters');
    }

    if (metrics.maintainabilityIndex < 50) {
      recommendations.push('Overall maintainability is low - consider refactoring');
    }

    return recommendations;
  }

  private static calculateCyclomaticComplexity(code: string): number {
    const complexityKeywords = [
      'if', 'else', 'while', 'for', 'switch', 'case', 'catch', '&&', '||', '?'
    ];

    let complexity = 1; // Base complexity

    for (const keyword of complexityKeywords) {
      const regex = new RegExp(`\\b${keyword}\\b`, 'g');
      const matches = code.match(regex);
      if (matches) {
        complexity += matches.length;
      }
    }

    return complexity;
  }

  private static calculateCognitiveComplexity(code: string): number {
    // Simplified cognitive complexity calculation
    let complexity = 0;
    const lines = code.split('\n');
    let nestingLevel = 0;

    for (const line of lines) {
      const trimmedLine = line.trim();
      
      // Increase complexity for control structures
      if (trimmedLine.match(/^\s*(if|while|for|switch|catch)\s*\(/)) {
        complexity += 1 + nestingLevel;
        nestingLevel++;
      } else if (trimmedLine.match(/^\s*(else|elseif)\s*/)) {
        complexity += 1;
      } else if (trimmedLine.match(/^\s*}\s*$/)) {
        nestingLevel = Math.max(0, nestingLevel - 1);
      }
    }

    return complexity;
  }

  private static calculateNestingDepth(code: string): number {
    let maxDepth = 0;
    let currentDepth = 0;

    for (const char of code) {
      if (char === '{') {
        currentDepth++;
        maxDepth = Math.max(maxDepth, currentDepth);
      } else if (char === '}') {
        currentDepth = Math.max(0, currentDepth - 1);
      }
    }

    return maxDepth;
  }

  private static countParameters(code: string): number {
    const functionMatch = code.match(/function\s+\w+\s*\(([^)]*)\)/);
    if (!functionMatch) return 0;

    const parameters = functionMatch[1].split(',').filter(param => param.trim());
    return parameters.length;
  }

  private static calculateMaintainabilityIndex(metrics: ComplexityMetrics): number {
    // Simplified maintainability index calculation
    const { cyclomaticComplexity, cognitiveComplexity, nestingDepth, functionLength, parameterCount } = metrics;
    
    let index = 100;
    index -= cyclomaticComplexity * 2;
    index -= cognitiveComplexity * 1.5;
    index -= nestingDepth * 3;
    index -= Math.min(functionLength / 10, 20);
    index -= parameterCount * 2;

    return Math.max(0, Math.min(100, index));
  }
}

// ============================================================================
// CODE FORMATTING AND STYLE
// ============================================================================

export class SupernovaCodeFormatter {
  /**
   * SUPERNOVA Enhanced: Format code with consistent style
   */
  static formatCode(code: string, options: FormattingOptions = {}): string {
    const {
      indentSize = 2,
      useTabs = false,
      maxLineLength = 100,
      trailingComma = true,
      semicolons = true
    } = options;

    let formatted = code;

    // Normalize line endings
    formatted = formatted.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

    // Fix indentation
    formatted = this.fixIndentation(formatted, indentSize, useTabs);

    // Fix line length
    formatted = this.fixLineLength(formatted, maxLineLength);

    // Fix trailing commas
    if (trailingComma) {
      formatted = this.addTrailingCommas(formatted);
    }

    // Fix semicolons
    if (semicolons) {
      formatted = this.addSemicolons(formatted);
    }

    return formatted;
  }

  private static fixIndentation(code: string, indentSize: number, useTabs: boolean): string {
    const lines = code.split('\n');
    const indentChar = useTabs ? '\t' : ' '.repeat(indentSize);
    let currentIndent = 0;

    return lines.map(line => {
      const trimmed = line.trim();
      if (!trimmed) return '';

      // Decrease indent for closing braces
      if (trimmed.startsWith('}') || trimmed.startsWith(']') || trimmed.startsWith(')')) {
        currentIndent = Math.max(0, currentIndent - 1);
      }

      const indented = indentChar.repeat(currentIndent) + trimmed;

      // Increase indent for opening braces
      if (trimmed.endsWith('{') || trimmed.endsWith('[') || trimmed.endsWith('(')) {
        currentIndent++;
      }

      return indented;
    }).join('\n');
  }

  private static fixLineLength(code: string, maxLength: number): string {
    const lines = code.split('\n');
    
    return lines.map(line => {
      if (line.length <= maxLength) return line;
      
      // Simple line breaking - in real implementation, this would be more sophisticated
      const words = line.split(' ');
      const result: string[] = [];
      let currentLine = '';

      for (const word of words) {
        if (currentLine.length + word.length + 1 <= maxLength) {
          currentLine += (currentLine ? ' ' : '') + word;
        } else {
          if (currentLine) result.push(currentLine);
          currentLine = word;
        }
      }

      if (currentLine) result.push(currentLine);
      return result.join('\n');
    }).join('\n');
  }

  private static addTrailingCommas(code: string): string {
    // Add trailing commas to objects and arrays
    return code
      .replace(/(\w+)\s*$/gm, '$1,')
      .replace(/,(\s*[}\]])/g, '$1');
  }

  private static addSemicolons(code: string): string {
    // Add semicolons to statements
    return code
      .replace(/([^;{}])\s*$/gm, '$1;')
      .replace(/;\s*;/g, ';');
  }
}

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================

export interface TechnicalDebtReport {
  totalDebt: number;
  criticalDebt: number;
  highDebt: number;
  totalEffort: number;
  debtByType: Record<string, number>;
  debtByPriority: Record<string, number>;
  recommendations: string[];
}

export interface FormattingOptions {
  indentSize?: number;
  useTabs?: boolean;
  maxLineLength?: number;
  trailingComma?: boolean;
  semicolons?: boolean;
}

// ============================================================================
// SUPERNOVA CODE QUALITY UTILITIES
// ============================================================================

export class SupernovaCodeQualityUtils {
  /**
   * SUPERNOVA Enhanced: Comprehensive code quality analysis
   */
  static async analyzeCodeQuality(filePath: string, content: string): Promise<CodeQualityReport> {
    const deadCode = SupernovaDeadCodeDetector.detectDeadCode(content, filePath);
    const technicalDebt = SupernovaTechDebtDetector.detectTechnicalDebt(content, filePath);
    const debtReport = SupernovaTechDebtDetector.generateDebtReport(technicalDebt);

    // Analyze functions for complexity
    const functions = this.extractFunctions(content);
    const complexityMetrics = functions.map(func => 
      SupernovaComplexityAnalyzer.analyzeFunction(func)
    );

    const averageComplexity = complexityMetrics.reduce((sum, metrics) => 
      sum + metrics.cyclomaticComplexity, 0) / complexityMetrics.length || 0;

    return {
      filePath,
      deadCodeCount: deadCode.length,
      technicalDebtCount: technicalDebt.length,
      averageComplexity,
      maintainabilityScore: this.calculateOverallMaintainability(complexityMetrics),
      recommendations: this.generateOverallRecommendations(deadCode, technicalDebt, complexityMetrics),
      debtReport
    };
  }

  private static extractFunctions(content: string): string[] {
    // Simple function extraction - in real implementation, this would use AST
    const functionRegex = /function\s+\w+\s*\([^)]*\)\s*\{[^}]*\}/g;
    return content.match(functionRegex) || [];
  }

  private static calculateOverallMaintainability(metrics: ComplexityMetrics[]): number {
    if (metrics.length === 0) return 100;
    
    const averageMaintainability = metrics.reduce((sum, m) => sum + m.maintainabilityIndex, 0) / metrics.length;
    return Math.round(averageMaintainability);
  }

  private static generateOverallRecommendations(
    deadCode: DeadCodeItem[],
    technicalDebt: TechnicalDebtItem[],
    complexityMetrics: ComplexityMetrics[]
  ): string[] {
    const recommendations: string[] = [];

    if (deadCode.length > 0) {
      recommendations.push(`Remove ${deadCode.length} dead code items`);
    }

    if (technicalDebt.length > 0) {
      recommendations.push(`Address ${technicalDebt.length} technical debt items`);
    }

    const highComplexityFunctions = complexityMetrics.filter(m => m.cyclomaticComplexity > 10);
    if (highComplexityFunctions.length > 0) {
      recommendations.push(`Refactor ${highComplexityFunctions.length} high-complexity functions`);
    }

    return recommendations;
  }
}

export interface CodeQualityReport {
  filePath: string;
  deadCodeCount: number;
  technicalDebtCount: number;
  averageComplexity: number;
  maintainabilityScore: number;
  recommendations: string[];
  debtReport: TechnicalDebtReport;
}
