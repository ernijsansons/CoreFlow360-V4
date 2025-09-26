/**
 * Data Anomaly Detector
 * AI-powered anomaly detection and pattern analysis for CoreFlow360 V4
 */
import { Logger } from '../shared/logger';
import type { Context } from 'hono';
import type {
  DataAnomalyReport,
  DataAnomaly,
  AnomalyPattern,
  AnomalyPrediction,
  AnomalyStatistics
} from './quantum-data-auditor';

// Additional type definitions for missing properties
interface DataAnomalyReportExtended extends Omit<DataAnomalyReport, 'anomalies'> {
  anomalies: DataAnomalyExtended[];
  detectionTime: number;
  confidence: number;
}

interface AnomalyPatternExtended extends AnomalyPattern {
  id: string;
  table: string;
  column: string;
  type: string;
  frequency: number;
  mean: number;
  variance: number;
  stdDev: number;
  trend: 'increasing' | 'decreasing' | 'stable';
  seasonality: boolean;
  lastUpdated: Date;
  confidence: number;
}

interface AnomalyPredictionExtended extends AnomalyPrediction {
  id: string;
  table: string;
  column: string;
  predictedValue: number;
  predictedTimestamp: Date;
  anomalyProbability: number;
  confidence: number;
  factors: string[];
}

interface AnomalyStatisticsExtended extends AnomalyStatistics {
  totalAnomalies: number;
  anomaliesByType: Map<string, number>;
  anomaliesByTable: Map<string, number>;
  detectionAccuracy: number;
  falsePositiveRate: number;
  lastDetection: Date | null;
}

// Local anomaly type for internal processing
interface DataAnomalyExtended {
  id: string;
  type: 'statistical' | 'temporal' | 'categorical' | 'numerical';
  table: string;
  column: string;
  value: any;
  expectedValue: any;
  expectedRange?: { min: any; max: any };
  deviation: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: Date;
  businessId: string;
  description: string;
  confidence: number;
  explanation?: string;
  action?: string;
}

interface DataSample {
  table: string;
  column: string;
  value: any;
  timestamp: Date;
  businessId: string;
}

interface AnomalyDetectionConfig {
  sensitivity: number; // 0-1, higher = more sensitive
  minSamples: number; // Minimum samples needed for detection
  timeWindow: number; // Time window in milliseconds
  patterns: string[]; // Pattern types to detect
}

export class DataAnomalyDetector {
  private logger: Logger;
  private config: AnomalyDetectionConfig;
  private patterns: Map<string, AnomalyPatternExtended> = new Map();
  private statistics: AnomalyStatisticsExtended = {
    totalAnomalies: 0,
    anomaliesByType: new Map(),
    anomaliesByTable: new Map(),
    detectionAccuracy: 0,
    falsePositiveRate: 0,
    lastDetection: null,
    criticalAnomalies: 0,
    averageResolutionTime: 0
  };

  constructor(private readonly context: Context, config?: Partial<AnomalyDetectionConfig>) {
    this.logger = new Logger({ component: 'data-anomaly-detector' });
    this.config = {
      sensitivity: 0.7,
      minSamples: 100,
      timeWindow: 24 * 60 * 60 * 1000, // 24 hours
      patterns: ['statistical', 'temporal', 'categorical', 'numerical'],
      ...config
    };
  }

  async detectAnomalies(samples: DataSample[]): Promise<DataAnomalyReportExtended> {
    this.logger.info('Starting anomaly detection', { sampleCount: samples.length });

    const anomalies: DataAnomalyExtended[] = [];
    const startTime = Date.now();

    // Group samples by table and column
    const groupedSamples = this.groupSamples(samples);

    for (const [key, groupSamples] of groupedSamples) {
      const [table, column] = key.split(':');
      
      // Detect different types of anomalies
      const statisticalAnomalies = await this.detectStatisticalAnomalies(table, column, groupSamples);
      const temporalAnomalies = await this.detectTemporalAnomalies(table, column, groupSamples);
      const categoricalAnomalies = await this.detectCategoricalAnomalies(table, column, groupSamples);
      const numericalAnomalies = await this.detectNumericalAnomalies(table, column, groupSamples);

      anomalies.push(...statisticalAnomalies, ...temporalAnomalies, ...categoricalAnomalies, ...numericalAnomalies);
    }

    // Update statistics
    this.updateStatistics(anomalies);

    const detectionTime = Date.now() - startTime;
    this.logger.info('Anomaly detection completed', {
      anomaliesFound: anomalies.length,
      detectionTime,
      accuracy: this.statistics.detectionAccuracy
    });

    return {
      anomalies,
      statistics: this.statistics,
      patterns: Array.from(this.patterns.values()) as AnomalyPatternExtended[],
      detectionTime,
      confidence: this.calculateConfidence(anomalies),
      score: this.calculateAnomalyScore(anomalies),
      predictions: [],
      anomaliesDetected: anomalies.length,
      highSeverityAnomalies: anomalies.filter(a => a.severity === 'high' || a.severity === 'critical').length
    };
  }

  async predictAnomalies(samples: DataSample[]): Promise<AnomalyPredictionExtended[]> {
    const predictions: AnomalyPredictionExtended[] = [];
    const groupedSamples = this.groupSamples(samples);

    for (const [key, groupSamples] of groupedSamples) {
      const [table, column] = key.split(':');
      const pattern = this.patterns.get(key);

      if (pattern) {
        const prediction = await this.generatePrediction(table, column, groupSamples, pattern);
        predictions.push(prediction);
      }
    }

    return predictions;
  }

  async updatePatterns(samples: DataSample[]): Promise<void> {
    const groupedSamples = this.groupSamples(samples);

    for (const [key, groupSamples] of groupedSamples) {
      const [table, column] = key.split(':');
      const pattern = await this.analyzePattern(table, column, groupSamples);
      this.patterns.set(key, pattern);
    }
  }

  getStatistics(): AnomalyStatisticsExtended {
    return { ...this.statistics };
  }

  getPatterns(): AnomalyPatternExtended[] {
    return Array.from(this.patterns.values());
  }

  private groupSamples(samples: DataSample[]): Map<string, DataSample[]> {
    const grouped = new Map<string, DataSample[]>();

    for (const sample of samples) {
      const key = `${sample.table}:${sample.column}`;
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key)!.push(sample);
    }

    return grouped;
  }

  private async detectStatisticalAnomalies(table: string, column: string, samples: DataSample[]): Promise<DataAnomalyExtended[]> {
    const anomalies: DataAnomalyExtended[] = [];
    
    if (samples.length < this.config.minSamples) {
      return anomalies;
    }

    const values = samples.map(s => s.value).filter(v => typeof v === 'number');
    if (values.length === 0) return anomalies;

    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);
    const threshold = mean + (this.config.sensitivity * stdDev * 3);

    for (let i = 0; i < values.length; i++) {
      if (Math.abs(values[i] - mean) > threshold) {
        anomalies.push({
          id: `statistical_${table}_${column}_${i}`,
          type: 'statistical',
          table,
          column,
          value: values[i],
          expectedValue: mean,
          deviation: Math.abs(values[i] - mean),
          severity: this.calculateSeverity(Math.abs(values[i] - mean), stdDev),
          timestamp: samples[i].timestamp,
          businessId: samples[i].businessId,
          description: `Statistical anomaly detected: value ${values[i]} deviates significantly from mean ${mean.toFixed(2)}`,
          confidence: this.calculateConfidence([anomalies[anomalies.length - 1]])
        });
      }
    }

    return anomalies;
  }

  private async detectTemporalAnomalies(table: string, column: string, samples: DataSample[]): Promise<DataAnomalyExtended[]> {
    const anomalies: DataAnomalyExtended[] = [];
    
    if (samples.length < this.config.minSamples) {
      return anomalies;
    }

    // Sort by timestamp
    const sortedSamples = samples.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    
    // Detect sudden changes in values
    for (let i = 1; i < sortedSamples.length; i++) {
      const current = sortedSamples[i];
      const previous = sortedSamples[i - 1];
      
      if (typeof current.value === 'number' && typeof previous.value === 'number') {
        const change = Math.abs(current.value - previous.value);
        const changePercent = (change / Math.abs(previous.value)) * 100;
        
        if (changePercent > (this.config.sensitivity * 100)) {
          anomalies.push({
            id: `temporal_${table}_${column}_${i}`,
            type: 'temporal',
            table,
            column,
            value: current.value,
            expectedValue: previous.value,
            deviation: change,
            severity: this.calculateSeverity(change, Math.abs(previous.value)),
            timestamp: current.timestamp,
            businessId: current.businessId,
            description: `Temporal anomaly detected: sudden change of ${changePercent.toFixed(2)}% from ${previous.value} to ${current.value}`,
            confidence: this.calculateConfidence([anomalies[anomalies.length - 1]])
          });
        }
      }
    }

    return anomalies;
  }

  private async detectCategoricalAnomalies(table: string, column: string, samples: DataSample[]): Promise<DataAnomalyExtended[]> {
    const anomalies: DataAnomalyExtended[] = [];
    
    if (samples.length < this.config.minSamples) {
      return anomalies;
    }

    // Count frequency of each category
    const categoryCounts = new Map<string, number>();
    for (const sample of samples) {
      const category = String(sample.value);
      categoryCounts.set(category, (categoryCounts.get(category) || 0) + 1);
    }

    // Find rare categories
    const totalSamples = samples.length;
    const threshold = totalSamples * (1 - this.config.sensitivity) * 0.01; // 1% threshold

    for (const [category, count] of categoryCounts) {
      if (count < threshold) {
        const sample = samples.find(s => String(s.value) === category);
        if (sample) {
          anomalies.push({
            id: `categorical_${table}_${column}_${category}`,
            type: 'categorical',
            table,
            column,
            value: category,
            expectedValue: 'common_category',
            deviation: count,
            severity: this.calculateSeverity(totalSamples - count, totalSamples),
            timestamp: sample.timestamp,
            businessId: sample.businessId,
            description: `Categorical anomaly detected: rare category '${category}' appears only ${count} times out of ${totalSamples}`,
            confidence: this.calculateConfidence([anomalies[anomalies.length - 1]])
          });
        }
      }
    }

    return anomalies;
  }

  private async detectNumericalAnomalies(table: string, column: string, samples: DataSample[]): Promise<DataAnomalyExtended[]> {
    const anomalies: DataAnomalyExtended[] = [];
    
    if (samples.length < this.config.minSamples) {
      return anomalies;
    }

    const values = samples.map(s => s.value).filter(v => typeof v === 'number');
    if (values.length === 0) return anomalies;

    // Detect outliers using IQR method
    const sortedValues = [...values].sort((a, b) => a - b);
    const q1 = this.percentile(sortedValues, 25);
    const q3 = this.percentile(sortedValues, 75);
    const iqr = q3 - q1;
    const lowerBound = q1 - (1.5 * iqr);
    const upperBound = q3 + (1.5 * iqr);

    for (let i = 0; i < values.length; i++) {
      if (values[i] < lowerBound || values[i] > upperBound) {
        anomalies.push({
          id: `numerical_${table}_${column}_${i}`,
          type: 'numerical',
          table,
          column,
          value: values[i],
          expectedValue: `${lowerBound.toFixed(2)} - ${upperBound.toFixed(2)}`,
          deviation: Math.min(Math.abs(values[i] - lowerBound), Math.abs(values[i] - upperBound)),
          severity: this.calculateSeverity(Math.abs(values[i] - (q1 + q3) / 2), iqr),
          timestamp: samples[i].timestamp,
          businessId: samples[i].businessId,
          description: `Numerical anomaly detected: value ${values[i]} is outside the expected range [${lowerBound.toFixed(2)}, ${upperBound.toFixed(2)}]`,
          confidence: this.calculateConfidence([anomalies[anomalies.length - 1]])
        });
      }
    }

    return anomalies;
  }

  private async analyzePattern(table: string, column: string, samples: DataSample[]): Promise<AnomalyPatternExtended> {
    const values = samples.map(s => s.value);
    const timestamps = samples.map(s => s.timestamp);

    // Calculate basic statistics
    const numericValues = values.filter(v => typeof v === 'number');
    const mean = numericValues.length > 0 ? numericValues.reduce((sum, val) => sum + val, 0) / numericValues.length : 0;
    const variance = numericValues.length > 0 ? numericValues.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / numericValues.length : 0;
    const stdDev = Math.sqrt(variance);

    // Detect trends
    const trend = this.detectTrend(timestamps, numericValues);

    // Detect seasonality
    const seasonality = this.detectSeasonality(timestamps, numericValues);

    return {
      id: `pattern_${table}_${column}_${Date.now()}`,
      table,
      column,
      type: typeof numericValues[0] === 'number' ? 'numerical' : 'categorical',
      pattern: `${table}_${column}`,
      frequency: samples.length,
      tables: [table],
      timeRange: {
        start: new Date(Math.min(...timestamps.map(t => t.getTime()))),
        end: new Date(Math.max(...timestamps.map(t => t.getTime())))
      },
      correlation: `statistical_${column}`,
      significance: this.calculatePatternConfidence(samples),
      mean,
      variance,
      stdDev,
      trend,
      seasonality,
      lastUpdated: new Date(),
      confidence: this.calculatePatternConfidence(samples)
    };
  }

  private async generatePrediction(table: string, column: string, samples: DataSample[], pattern: AnomalyPattern): Promise<AnomalyPredictionExtended> {
    const nextTimestamp = new Date(Date.now() + this.config.timeWindow);
    const predictedValue = this.predictValue(samples, pattern);
    const anomalyProbability = this.calculateAnomalyProbability(predictedValue, pattern);

    return {
      id: `prediction_${table}_${column}_${Date.now()}`,
      table,
      column,
      predictedAnomaly: `Potential anomaly in ${column}`,
      probability: anomalyProbability,
      timeframe: nextTimestamp.toISOString(),
      prevention: 'Monitor values and apply appropriate thresholds',
      predictedValue,
      predictedTimestamp: nextTimestamp,
      anomalyProbability,
      confidence: this.calculatePatternConfidence(samples),
      factors: this.identifyPredictionFactors(samples, pattern)
    };
  }

  private calculateSeverity(deviation: number, baseline: number): 'low' | 'medium' | 'high' | 'critical' {
    const ratio = deviation / baseline;
    
    if (ratio > 3) return 'critical';
    if (ratio > 2) return 'high';
    if (ratio > 1) return 'medium';
    return 'low';
  }

  private calculateConfidence(anomalies: DataAnomalyExtended[]): number {
    if (anomalies.length === 0) return 0;
    
    const avgConfidence = anomalies.reduce((sum, anomaly) => sum + (anomaly.confidence || 0), 0) / anomalies.length;
    return Math.min(1, Math.max(0, avgConfidence));
  }

  private calculateAnomalyScore(anomalies: DataAnomalyExtended[]): number {
    if (anomalies.length === 0) return 0;
    
    const totalScore = anomalies.reduce((sum, anomaly) => {
      const severity = anomaly.severity === 'critical' ? 4 : 
                     anomaly.severity === 'high' ? 3 :
                     anomaly.severity === 'medium' ? 2 : 1;
      return sum + severity * (anomaly.confidence || 0);
    }, 0);
    
    return Math.min(100, Math.max(0, totalScore / anomalies.length * 25));
  }

  private updateStatistics(anomalies: DataAnomalyExtended[]): void {
    this.statistics.totalAnomalies += anomalies.length;
    this.statistics.lastDetection = new Date();

    for (const anomaly of anomalies) {
      // Update by type
      const typeCount = this.statistics.anomaliesByType.get(anomaly.type) || 0;
      this.statistics.anomaliesByType.set(anomaly.type, typeCount + 1);

      // Update by table
      const tableCount = this.statistics.anomaliesByTable.get(anomaly.table) || 0;
      this.statistics.anomaliesByTable.set(anomaly.table, tableCount + 1);
    }

    // Update accuracy (mock calculation)
    this.statistics.detectionAccuracy = Math.min(0.95, 0.7 + (anomalies.length * 0.01));
    this.statistics.falsePositiveRate = Math.max(0.05, 0.1 - (anomalies.length * 0.001));
  }

  private percentile(sortedArray: number[], percentile: number): number {
    const index = (percentile / 100) * (sortedArray.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    const weight = index % 1;

    if (upper >= sortedArray.length) {
      return sortedArray[sortedArray.length - 1];
    }

    return sortedArray[lower] * (1 - weight) + sortedArray[upper] * weight;
  }

  private detectTrend(timestamps: Date[], values: number[]): 'increasing' | 'decreasing' | 'stable' {
    if (values.length < 2) return 'stable';

    const firstHalf = values.slice(0, Math.floor(values.length / 2));
    const secondHalf = values.slice(Math.floor(values.length / 2));

    const firstMean = firstHalf.reduce((sum, val) => sum + val, 0) / firstHalf.length;
    const secondMean = secondHalf.reduce((sum, val) => sum + val, 0) / secondHalf.length;

    const change = (secondMean - firstMean) / firstMean;

    if (change > 0.1) return 'increasing';
    if (change < -0.1) return 'decreasing';
    return 'stable';
  }

  private detectSeasonality(timestamps: Date[], values: number[]): boolean {
    if (values.length < 24) return false; // Need at least 24 data points

    // Simple seasonality detection based on hourly patterns
    const hourlyAverages = new Map<number, number[]>();
    
    for (let i = 0; i < timestamps.length; i++) {
      const hour = timestamps[i].getHours();
      if (!hourlyAverages.has(hour)) {
        hourlyAverages.set(hour, []);
      }
      hourlyAverages.get(hour)!.push(values[i]);
    }

    const hourlyMeans = Array.from(hourlyAverages.entries()).map(([hour, vals]) => ({
      hour,
      mean: vals.reduce((sum, val) => sum + val, 0) / vals.length
    }));

    // Check for significant variation between hours
    const overallMean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = hourlyMeans.reduce((sum, { mean }) => sum + Math.pow(mean - overallMean, 2), 0) / hourlyMeans.length;
    const coefficientOfVariation = Math.sqrt(variance) / overallMean;

    return coefficientOfVariation > 0.2; // 20% variation indicates seasonality
  }

  private calculatePatternConfidence(samples: DataSample[]): number {
    // Confidence based on sample size and consistency
    const sampleSizeFactor = Math.min(1, samples.length / 1000); // Max confidence at 1000 samples
    const consistencyFactor = this.calculateConsistency(samples);
    
    return (sampleSizeFactor + consistencyFactor) / 2;
  }

  private calculateConsistency(samples: DataSample[]): number {
    if (samples.length < 2) return 0;

    const values = samples.map(s => s.value).filter(v => typeof v === 'number');
    if (values.length < 2) return 0;

    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    const coefficientOfVariation = Math.sqrt(variance) / mean;

    return Math.max(0, 1 - coefficientOfVariation);
  }

  private predictValue(samples: DataSample[], pattern: AnomalyPattern): number {
    // Simple linear prediction based on most recent values
    const recentValues = samples.slice(-10).map(s => parseFloat(s.value.toString()));
    const mean = recentValues.reduce((sum, val) => sum + val, 0) / recentValues.length;
    return mean || 0;
  }

  private calculateAnomalyProbability(predictedValue: number, pattern: AnomalyPattern): number {
    // Use pattern significance as probability indicator
    return Math.min(1, pattern.significance);
  }

  private identifyPredictionFactors(samples: DataSample[], pattern: AnomalyPattern): string[] {
    const factors: string[] = [];

    factors.push(`Pattern: ${pattern.pattern}`);
    factors.push(`Frequency: ${pattern.frequency}`);
    factors.push(`Significance: ${pattern.significance.toFixed(2)}`);

    if (samples.length < 100) {
      factors.push('Limited historical data');
    }

    return factors;
  }
}

