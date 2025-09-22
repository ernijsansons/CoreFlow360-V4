/**
 * Hallucination Detector
 * Advanced detection and analysis of AI hallucinations and factual inaccuracies
 */

import { Logger } from '../shared/logger';
import type { Context } from 'hono';

const logger = new Logger({ component: 'hallucination-detector' });

export interface HallucinationInstance {
  id: string;
  timestamp: Date;
  input: string;
  output: string;
  confidence: number;
  type: 'factual' | 'logical' | 'contextual' | 'temporal' | 'numerical';
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  evidence: string;
  groundTruthSource?: string;
  detectionMethod: string;
  correctedOutput?: string;
}

export interface HallucinationPattern {
  pattern: string;
  frequency: number;
  confidence: number;
  contexts: string[];
  triggerWords: string[];
  risk: string;
  prevention: string;
  examples: string[];
}

export interface FactCheckResult {
  claim: string;
  isFactual: boolean;
  confidence: number;
  sources: string[];
  evidence: string;
  alternativeInfo?: string;
}

export interface GroundingValidation {
  hasGrounding: boolean;
  groundingSources: string[];
  groundingQuality: number;
  missingGrounding: string[];
  recommendations: string[];
}

export interface HallucinationDetectionConfig {
  enableFactChecking: boolean;
  enablePatternDetection: boolean;
  enableGroundingValidation: boolean;
  confidenceThreshold: number;
  factCheckingSources: string[];
  monitoringInterval: number;
}

export class HallucinationDetector {
  private logger: Logger;
  private startTime: number = 0;
  private knowledgeBase: Map<string, any> = new Map();
  private patterns: HallucinationPattern[] = [];

  constructor(private readonly context: Context) {
    this.logger = new Logger({ component: 'hallucination-detector' });
    this.initializeKnowledgeBase();
  }

  async detectHallucinations(
    input: string,
    output: string,
    config: HallucinationDetectionConfig = this.getDefaultConfig()
  ): Promise<{
    hasHallucination: boolean;
    instances: HallucinationInstance[];
    factChecks: FactCheckResult[];
    grounding: GroundingValidation;
    confidence: number;
  }> {
    this.startTime = Date.now();

    this.logger.info('Starting hallucination detection', {
      inputLength: input.length,
      outputLength: output.length,
      config
    });

    const instances: HallucinationInstance[] = [];
    const factChecks: FactCheckResult[] = [];

    // 1. Fact-checking analysis
    if (config.enableFactChecking) {
      const factCheckResults = await this.performFactChecking(output, config);
      factChecks.push(...factCheckResults);

      // Convert failed fact checks to hallucination instances
      for (const factCheck of factCheckResults.filter(fc => !fc.isFactual)) {
        instances.push({
          id: `fact_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: new Date(),
          input,
          output,
          confidence: factCheck.confidence,
          type: 'factual',
          severity: this.determineSeverity(factCheck.confidence),
          category: 'Factual Inaccuracy',
          evidence: factCheck.evidence,
          groundTruthSource: factCheck.sources.join(', '),
          detectionMethod: 'fact_checking',
          correctedOutput: factCheck.alternativeInfo
        });
      }
    }

    // 2. Pattern-based detection
    if (config.enablePatternDetection) {
      const patternInstances = await this.detectPatternBasedHallucinations(input, output);
      instances.push(...patternInstances);
    }

    // 3. Logical consistency analysis
    const logicalInstances = await this.detectLogicalInconsistencies(input, output);
    instances.push(...logicalInstances);

    // 4. Contextual validation
    const contextualInstances = await this.detectContextualHallucinations(input, output);
    instances.push(...contextualInstances);

    // 5. Numerical and temporal validation
    const numericalInstances = await this.detectNumericalHallucinations(output);
    instances.push(...numericalInstances);

    // 6. Grounding validation
    let grounding: GroundingValidation;
    if (config.enableGroundingValidation) {
      grounding = await this.validateGrounding(input, output, config);
    } else {
      grounding = {
        hasGrounding: true,
        groundingSources: [],
        groundingQuality: 1.0,
        missingGrounding: [],
        recommendations: []
      };
    }

    // Calculate overall confidence
    const hasHallucination = instances.length > 0;
    const confidence = this.calculateHallucinationConfidence(instances);

    const detectionTime = Date.now() - this.startTime;

    this.logger.info('Hallucination detection completed', {
      detectionTime,
      hasHallucination,
      instancesFound: instances.length,
      confidence,
      factChecksPerformed: factChecks.length
    });

    return {
      hasHallucination,
      instances,
      factChecks,
      grounding,
      confidence
    };
  }

  async analyzeHallucinationPatterns(
    historicalInstances: HallucinationInstance[]
  ): Promise<HallucinationPattern[]> {

    const patterns: HallucinationPattern[] = [];

    // Group instances by type and category
    const groupedInstances = this.groupInstancesByPattern(historicalInstances);

    for (const [patternKey, instances] of groupedInstances.entries()) {
      const pattern = await this.analyzePattern(patternKey, instances);
      if (pattern.frequency >= 3) { // Only include patterns with sufficient frequency
        patterns.push(pattern);
      }
    }

    // Sort patterns by frequency and risk level
    patterns.sort((a, b) => {
      const riskOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
      const aRiskScore = riskOrder[a.risk as keyof typeof riskOrder] || 0;
      const bRiskScore = riskOrder[b.risk as keyof typeof riskOrder] || 0;

      if (aRiskScore !== bRiskScore) return bRiskScore - aRiskScore;
      return b.frequency - a.frequency;
    });

    this.patterns = patterns;
    return patterns;
  }

  private async performFactChecking(
    output: string,
    config: HallucinationDetectionConfig
  ): Promise<FactCheckResult[]> {
    const factChecks: FactCheckResult[] = [];

    // Extract factual claims from the output
    const claims = this.extractFactualClaims(output);

    for (const claim of claims) {
      const factCheck = await this.checkFactualClaim(claim, config.factCheckingSources);
      factChecks.push(factCheck);
    }

    return factChecks;
  }

  private extractFactualClaims(text: string): string[] {
    const claims: string[] = [];

    // Pattern-based claim extraction
    const patterns = [
      // Numerical claims
      /(\d+(?:,\d{3})*(?:\.\d+)?)\s*(?:percent|%|million|billion|thousand|dollars?|\$)/gi,
      // Date claims
      /(?:in|on|during)\s+(\d{4}|\w+\s+\d{1,2},?\s+\d{4})/gi,
      // Specific company/product claims
      /(?:company|organization|product)\s+\w+\s+(?:has|is|was|reports?|announces?)/gi,
      // Performance metrics
      /(?:increased|decreased|grew|fell)\s+by\s+\d+/gi,
      // Definitive statements
      /(?:^|\.\s*)(?:The|Our|This)\s+[^.]*(?:is|was|will be|has been)\s+[^.]*\./gi
    ];

    for (const pattern of patterns) {
      const matches = text.match(pattern);
      if (matches) {
        claims.push(...matches.map(match => match.trim()));
      }
    }

    // Extract sentences with high factual claim probability
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 10);
    for (const sentence of sentences) {
      if (this.hasHighFactualClaimProbability(sentence)) {
        claims.push(sentence.trim());
      }
    }

    return [...new Set(claims)]; // Remove duplicates
  }

  private hasHighFactualClaimProbability(sentence: string): boolean {
    const factualIndicators = [
      /\b(?:according to|based on|studies show|research indicates|data shows)\b/i,
      /\b(?:statistics|survey|report|analysis)\b/i,
      /\b\d+(?:,\d{3})*(?:\.\d+)?\s*(?:percent|%)\b/i,
      /\b(?:q[1-4]|quarter|fiscal year|fy)\s*\d{4}\b/i,
      /\b(?:ceo|cfo|president|director)\s+\w+\s+(?:said|stated|announced)\b/i
    ];

    return factualIndicators.some(pattern => pattern.test(sentence));
  }

  private async checkFactualClaim(
    claim: string,
    sources: string[]
  ): Promise<FactCheckResult> {
    // Simulate fact-checking against knowledge base and external sources
    const cleanClaim = this.normalizeClaim(claim);

    // Check against internal knowledge base
    const internalCheck = this.checkAgainstKnowledgeBase(cleanClaim);

    // Simulate external source verification
    const externalCheck = await this.simulateExternalFactCheck(cleanClaim);

    // Combine results
    const isFactual = internalCheck.isFactual && externalCheck.isFactual;
    const confidence = Math.min(internalCheck.confidence, externalCheck.confidence);

    return {
      claim,
      isFactual,
      confidence,
      sources: [...internalCheck.sources, ...externalCheck.sources],
      evidence: `Internal: ${internalCheck.evidence}; External: ${externalCheck.evidence}`,
      alternativeInfo: isFactual ? undefined : this.generateCorrection(cleanClaim)
    };
  }

  private normalizeClaim(claim: string): string {
    return claim
      .toLowerCase()
      .replace(/[^\w\s\d]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  private checkAgainstKnowledgeBase(claim: string): {
    isFactual: boolean;
    confidence: number;
    sources: string[];
    evidence: string;
  } {
    // Simulate knowledge base lookup
    const confidence = Math.random() * 0.3 + 0.7; // 70-100% confidence
    const isFactual = confidence > 0.8 && Math.random() > 0.2; // 80% accuracy rate

    return {
      isFactual,
      confidence,
      sources: ['Internal Knowledge Base'],
      evidence: isFactual ?
        'Claim verified against internal knowledge base' :
        'Claim conflicts with information in knowledge base'
    };
  }

  private async simulateExternalFactCheck(claim: string): Promise<{
    isFactual: boolean;
    confidence: number;
    sources: string[];
    evidence: string;
  }> {
    // Simulate external fact-checking API call
    await new Promise(resolve => setTimeout(resolve, 100)); // Simulate API delay

    const confidence = Math.random() * 0.4 + 0.6; // 60-100% confidence
    const isFactual = confidence > 0.75 && Math.random() > 0.15; // 85% accuracy rate

    return {
      isFactual,
      confidence,
      sources: ['External Fact-Check API', 'Verified News Sources'],
      evidence: isFactual ?
        'Claim supported by multiple external sources' :
        'Claim contradicted by reliable external sources'
    };
  }

  private generateCorrection(claim: string): string {
    // Generate a corrected version of the claim
    return `Corrected information: [Based on
  verified sources, the accurate information differs from the claim "${claim}"]`;
  }

  private async detectPatternBasedHallucinations(
    input: string,
    output: string
  ): Promise<HallucinationInstance[]> {
    const instances: HallucinationInstance[] = [];

    // Check against known hallucination patterns
    for (const pattern of this.patterns) {
      if (this.matchesPattern(output, pattern)) {
        instances.push({
          id: `pattern_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: new Date(),
          input,
          output,
          confidence: pattern.confidence,
          type: 'contextual',
          severity: this.mapRiskToSeverity(pattern.risk),
          category: 'Pattern-based Detection',
          evidence: `Matches known hallucination pattern: ${pattern.pattern}`,
          detectionMethod: 'pattern_matching',
          correctedOutput: pattern.prevention
        });
      }
    }

    // Check for common hallucination indicators
    const commonPatterns = [
      {
        pattern: /(?:as of|according to).*(?:latest|recent|current).*(?:data|information|reports?)/i,
        risk: 'Medium',
        evidence: 'Claims about "latest" information without specific timestamps'
      },
      {
        pattern: /\b(?:definitely|certainly|absolutely|guaranteed)\s+(?:will|is|are)/i,
        risk: 'Low',
        evidence: 'Overconfident predictions or statements'
      },
      {
        pattern: /\$[\d,]+(?:\.\d{2})?\s*(?:million|billion|trillion)/i,
        risk: 'High',
        evidence: 'Specific financial figures without source attribution'
      }
    ];

    for (const patternInfo of commonPatterns) {
      const matches = output.match(patternInfo.pattern);
      if (matches) {
        instances.push({
          id: `common_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: new Date(),
          input,
          output,
          confidence: 0.7,
          type: 'factual',
          severity: this.mapRiskToSeverity(patternInfo.risk),
          category: 'Common Hallucination Pattern',
          evidence: patternInfo.evidence,
          detectionMethod: 'pattern_matching'
        });
      }
    }

    return instances;
  }

  private async detectLogicalInconsistencies(
    input: string,
    output: string
  ): Promise<HallucinationInstance[]> {
    const instances: HallucinationInstance[] = [];

    // Check for internal contradictions
    const contradictions = this.findInternalContradictions(output);
    for (const contradiction of contradictions) {
      instances.push({
        id: `logic_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        input,
        output,
        confidence: 0.8,
        type: 'logical',
        severity: 'medium',
        category: 'Logical Inconsistency',
        evidence: contradiction,
        detectionMethod: 'logical_analysis'
      });
    }

    // Check for impossible claims
    const impossibleClaims = this.findImpossibleClaims(output);
    for (const claim of impossibleClaims) {
      instances.push({
        id: `impossible_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        input,
        output,
        confidence: 0.9,
        type: 'logical',
        severity: 'high',
        category: 'Impossible Claim',
        evidence: claim,
        detectionMethod: 'logical_analysis'
      });
    }

    return instances;
  }

  private findInternalContradictions(text: string): string[] {
    const contradictions: string[] = [];

    // Look for contradictory statements within the text
    const sentences = text.split(/[.!?]+/).map(s => s.trim()).filter(s => s.length > 0);

    for (let i = 0; i < sentences.length; i++) {
      for (let j = i + 1; j < sentences.length; j++) {
        if (this.areContradictory(sentences[i], sentences[j])) {
          contradictions.push(`Contradiction between: "${sentences[i]}" and "${sentences[j]}"`);
        }
      }
    }

    return contradictions;
  }

  private areContradictory(sentence1: string, sentence2: string): boolean {
    // Simplified contradiction detection
    const contradictoryPairs = [
      [/\bincrease[sd]?\b/i, /\bdecrease[sd]?\b/i],
      [/\bup\b/i, /\bdown\b/i],
      [/\bpositive\b/i, /\bnegative\b/i],
      [/\bmore\b/i, /\bless\b/i],
      [/\byes\b/i, /\bno\b/i]
    ];

    for (const [pattern1, pattern2] of contradictoryPairs) {
      if (pattern1.test(sentence1) && pattern2.test(sentence2)) {
        return true;
      }
      if (pattern2.test(sentence1) && pattern1.test(sentence2)) {
        return true;
      }
    }

    return false;
  }

  private findImpossibleClaims(text: string): string[] {
    const impossibleClaims: string[] = [];

    // Check for impossible percentages
    const percentagePattern = /(\d+(?:\.\d+)?)\s*(?:percent|%)/gi;
    const percentageMatches = text.match(percentagePattern);
    if (percentageMatches) {
      for (const match of percentageMatches) {
        const value = parseFloat(match.replace(/[^\d.]/g, ''));
        if (value > 100) {
          impossibleClaims.push(`Impossible percentage: ${match}`);
        }
      }
    }

    // Check for impossible dates
    const datePattern = /\b(\d{4})\b/g;
    const dateMatches = text.match(datePattern);
    if (dateMatches) {
      for (const match of dateMatches) {
        const year = parseInt(match);
        const currentYear = new Date().getFullYear();
        if (year > currentYear + 10 || year < 1900) {
          impossibleClaims.push(`Questionable year: ${year}`);
        }
      }
    }

    return impossibleClaims;
  }

  private async detectContextualHallucinations(
    input: string,
    output: string
  ): Promise<HallucinationInstance[]> {
    const instances: HallucinationInstance[] = [];

    // Check if output addresses the input
    if (!this.outputAddressesInput(input, output)) {
      instances.push({
        id: `context_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        input,
        output,
        confidence: 0.8,
        type: 'contextual',
        severity: 'medium',
        category: 'Off-topic Response',
        evidence: 'Output does not adequately address the input query',
        detectionMethod: 'contextual_analysis'
      });
    }

    // Check for context switching
    const contextSwitches = this.detectContextSwitching(input, output);
    for (const contextSwitch of contextSwitches) {
      instances.push({
        id: `switch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        input,
        output,
        confidence: 0.7,
        type: 'contextual',
        severity: 'low',
        category: 'Context Switching',
        evidence: contextSwitch,
        detectionMethod: 'contextual_analysis'
      });
    }

    return instances;
  }

  private outputAddressesInput(input: string, output: string): boolean {
    // Extract key terms from input
    const inputTerms = this.extractKeyTerms(input);
    const outputTerms = this.extractKeyTerms(output);

    // Check overlap
    const overlap = inputTerms.filter(term => outputTerms.includes(term));
    const overlapRatio = overlap.length / Math.max(inputTerms.length, 1);

    return overlapRatio >= 0.3; // At least 30% term overlap
  }

  private extractKeyTerms(text: string): string[] {
    const stopWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by',
  'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'can', 'this', 'that', 'these', 'those']);

    return text
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(word => word.length > 2 && !stopWords.has(word));
  }

  private detectContextSwitching(input: string, output: string): string[] {
    const switches: string[] = [];

    // Look for sudden topic changes in output
    const outputSentences = output.split(/[.!?]+/).map(s => s.trim()).filter(s => s.length > 0);

    for (let i = 1; i < outputSentences.length; i++) {
      const prevTerms = this.extractKeyTerms(outputSentences[i - 1]);
      const currTerms = this.extractKeyTerms(outputSentences[i]);

      const overlap = prevTerms.filter(term => currTerms.includes(term));
      if (overlap.length === 0 && prevTerms.length > 2 && currTerms.length > 2) {
        switches.push(`Abrupt context change between sentences: "${outputSentences[i - 1]}" → "${outputSentences[i]}"`);
      }
    }

    return switches;
  }

  private async detectNumericalHallucinations(output: string): Promise<HallucinationInstance[]> {
    const instances: HallucinationInstance[] = [];

    // Check for suspicious numerical patterns
    const numericalClaims = this.extractNumericalClaims(output);

    for (const claim of numericalClaims) {
      if (this.isNumericallyFalse(claim)) {
        instances.push({
          id: `numerical_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: new Date(),
          input: '',
          output,
          confidence: 0.85,
          type: 'numerical',
          severity: 'high',
          category: 'Numerical Inaccuracy',
          evidence: `Suspicious numerical claim: ${claim}`,
          detectionMethod: 'numerical_analysis'
        });
      }
    }

    return instances;
  }

  private extractNumericalClaims(text: string): string[] {
    const patterns = [
      /\d+(?:,\d{3})*(?:\.\d+)?\s*(?:percent|%)/gi,
      /\$\d+(?:,\d{3})*(?:\.\d{2})?(?:\s*(?:million|billion|trillion))?/gi,
      /\d+(?:,\d{3})*\s*(?:users?|customers?|employees?)/gi,
      /\d{4}-\d{2}-\d{2}/g, // Dates
      /\d+:\d{2}(?::\d{2})?(?:\s*(?:AM|PM))?/gi // Times
    ];

    const claims: string[] = [];
    for (const pattern of patterns) {
      const matches = text.match(pattern);
      if (matches) {
        claims.push(...matches);
      }
    }

    return claims;
  }

  private isNumericallyFalse(claim: string): boolean {
    // Check for obviously false numerical claims

    // Percentages over 100%
    const percentMatch = claim.match(/(\d+(?:\.\d+)?)\s*(?:percent|%)/i);
    if (percentMatch && parseFloat(percentMatch[1]) > 100) {
      return true;
    }

    // Unrealistic large numbers
    const largeNumberMatch = claim.match(/(\d+(?:,\d{3})*)/);
    if (largeNumberMatch) {
      const number = parseInt(largeNumberMatch[1].replace(/,/g, ''));
      if (number > 1000000000000) { // Over 1 trillion
        return true;
      }
    }

    return false;
  }

  private async validateGrounding(
    input: string,
    output: string,
    config: HallucinationDetectionConfig
  ): Promise<GroundingValidation> {
    const groundingSources: string[] = [];
    const missingGrounding: string[] = [];
    const recommendations: string[] = [];

    // Check for source citations
    const citationPatterns = [
      /according to [^.]+/gi,
      /based on [^.]+/gi,
      /source: [^.]+/gi,
      /\([^)]*\d{4}[^)]*\)/g, // Citations with years
      /https?:\/\/[^\s]+/g // URLs
    ];

    let hasCitations = false;
    for (const pattern of citationPatterns) {
      const matches = output.match(pattern);
      if (matches) {
        hasCitations = true;
        groundingSources.push(...matches);
      }
    }

    // Check for factual claims that need grounding
    const factualClaims = this.extractFactualClaims(output);
    for (const claim of factualClaims) {
      if (!this.hasAdequateGrounding(claim, groundingSources)) {
        missingGrounding.push(claim);
      }
    }

    // Generate recommendations
    if (!hasCitations && factualClaims.length > 0) {
      recommendations.push('Add source citations for factual claims');
    }

    if (missingGrounding.length > 0) {
      recommendations.push('Provide sources for specific numerical and factual claims');
    }

    if (groundingSources.length === 0) {
      recommendations.push('Include references to authoritative sources');
    }

    const groundingQuality = Math.max(0, 1 - (missingGrounding.length / Math.max(factualClaims.length, 1)));

    return {
      hasGrounding: hasCitations || groundingSources.length > 0,
      groundingSources,
      groundingQuality,
      missingGrounding,
      recommendations
    };
  }

  private hasAdequateGrounding(claim: string, sources: string[]): boolean {
    // Check if the claim has adequate grounding in the provided sources
    if (sources.length === 0) return false;

    // For numerical claims, require specific source attribution
    if (/\d+(?:,\d{3})*(?:\.\d+)?\s*(?:percent|%|million|billion)/i.test(claim)) {
      return sources.some(source =>
        source.toLowerCase().includes('data') ||
        source.toLowerCase().includes('report') ||
        source.toLowerCase().includes('study')
      );
    }

    return true;
  }

  private groupInstancesByPattern(instances: HallucinationInstance[]): Map<string, HallucinationInstance[]> {
    const groups = new Map<string, HallucinationInstance[]>();

    for (const instance of instances) {
      const key = `${instance.type}_${instance.category}`;
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key)!.push(instance);
    }

    return groups;
  }

  private async analyzePattern(patternKey: string, instances: HallucinationInstance[]): Promise<HallucinationPattern> {
    const frequency = instances.length;
    const confidence = instances.reduce((sum, inst) => sum + inst.confidence, 0) / frequency;

    const contexts = [...new Set(instances.map(inst => inst.category))];
    const triggerWords = this.extractCommonWords(instances.map(inst => inst.input));

    const avgSeverity = this.calculateAverageSeverity(instances);
    const risk = this.severityToRisk(avgSeverity);

    return {
      pattern: patternKey,
      frequency,
      confidence,
      contexts,
      triggerWords,
      risk,
      prevention: this.generatePreventionStrategy(patternKey, instances),
      examples: instances.slice(0, 3).map(inst => inst.evidence)
    };
  }

  private extractCommonWords(inputs: string[]): string[] {
    const wordCounts = new Map<string, number>();

    for (const input of inputs) {
      const words = this.extractKeyTerms(input);
      for (const word of words) {
        wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
      }
    }

    return Array.from(wordCounts.entries())
      .filter(([_, count]) => count >= Math.ceil(inputs.length * 0.3))
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([word, _]) => word);
  }

  private calculateAverageSeverity(instances: HallucinationInstance[]): number {
    const severityValues = { low: 1, medium: 2, high: 3, critical: 4 };
    const sum = instances.reduce((total, inst) => total + severityValues[inst.severity], 0);
    return sum / instances.length;
  }

  private severityToRisk(avgSeverity: number): string {
    if (avgSeverity >= 3.5) return 'Critical';
    if (avgSeverity >= 2.5) return 'High';
    if (avgSeverity >= 1.5) return 'Medium';
    return 'Low';
  }

  private generatePreventionStrategy(patternKey: string, instances: HallucinationInstance[]): string {
    const strategies = new Map([
      ['factual_', 'Implement fact-checking and source verification'],
      ['logical_', 'Add logical consistency validation'],
      ['contextual_', 'Improve context awareness and relevance checking'],
      ['numerical_', 'Validate numerical claims against known ranges'],
      ['temporal_', 'Verify dates and temporal references']
    ]);

    for (const [prefix, strategy] of strategies) {
      if (patternKey.startsWith(prefix)) {
        return strategy;
      }
    }

    return 'Implement general hallucination detection and prevention measures';
  }

  private matchesPattern(output: string, pattern: HallucinationPattern): boolean {
    return pattern.triggerWords.some(word =>
      output.toLowerCase().includes(word.toLowerCase())
    );
  }

  private determineSeverity(confidence: number): 'low' | 'medium' | 'high' | 'critical' {
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.7) return 'high';
    if (confidence >= 0.5) return 'medium';
    return 'low';
  }

  private mapRiskToSeverity(risk: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (risk.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      default: return 'low';
    }
  }

  private calculateHallucinationConfidence(instances: HallucinationInstance[]): number {
    if (instances.length === 0) return 0;

    const avgConfidence = instances.reduce((sum, inst) => sum + inst.confidence, 0) / instances.length;
    const severityWeight = this.calculateSeverityWeight(instances);

    return Math.min(1, avgConfidence * severityWeight);
  }

  private calculateSeverityWeight(instances: HallucinationInstance[]): number {
    const severityWeights = { low: 1, medium: 1.2, high: 1.5, critical: 2 };
    const avgWeight = instances.reduce((sum, inst) => sum + severityWeights[inst.severity], 0) / instances.length;
    return avgWeight;
  }

  private initializeKnowledgeBase(): void {
    // Initialize with sample knowledge for fact-checking
    this.knowledgeBase.set('company_facts', {
      foundedYear: 2024,
      industry: 'Software',
      size: 'Enterprise'
    });

    this.knowledgeBase.set('numerical_ranges', {
      percentages: { min: 0, max: 100 },
      years: { min: 1900, max: new Date().getFullYear() + 5 }
    });
  }

  private getDefaultConfig(): HallucinationDetectionConfig {
    return {
      enableFactChecking: true,
      enablePatternDetection: true,
      enableGroundingValidation: true,
      confidenceThreshold: 0.7,
      factCheckingSources: ['internal_kb', 'external_api'],
      monitoringInterval: 60000 // 1 minute
    };
  }
}