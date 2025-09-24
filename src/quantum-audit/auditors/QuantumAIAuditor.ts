import * as fs from 'fs/promises';
import * as path from 'path';
import { AISystemsAuditResult, Issue } from '../types/index';

export class QuantumAIAuditor {
  async auditAISystems(): Promise<AISystemsAuditResult> {

    const [
      modelIssues,
      biasIssues,
      accuracyIssues,
      trainingIssues
    ] = await Promise.all([
      this.auditModels(),
      this.checkBias(),
      this.validateAccuracy(),
      this.auditTraining()
    ]);

    const allIssues = [
      ...modelIssues,
      ...biasIssues,
      ...accuracyIssues,
      ...trainingIssues
    ];

    const score = this.calculateAIScore(allIssues);


    return {
      modelIssues,
      biasIssues,
      accuracyIssues,
      trainingIssues,
      score
    };
  }

  private async auditModels(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const aiFiles = await this.findAIFiles();

    for (const file of aiFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for model versioning
      if (content.includes('model') && !content.includes('version')) {
        issues.push({
          id: `ai-model-${Date.now()}-no-versioning`,
          category: 'ai-systems',
          severity: 'HIGH',
          description: 'AI models without version control',
          file,
          autoFixable: false,
          impact: ['model-governance', 'reproducibility'],
          recommendation: 'Implement model versioning and tracking'
        });
      }

      // Check for model validation
      if (content.includes('predict') && !content.includes('validate')) {
        issues.push({
          id: `ai-model-${Date.now()}-no-validation`,
          category: 'ai-systems',
          severity: 'CRITICAL',
          description: 'Model predictions without input validation',
          file,
          autoFixable: true,
          impact: ['security', 'reliability'],
          recommendation: 'Add input validation before model inference'
        });
      }

      // Check for error handling in model inference
      if (content.includes('predict') && !content.includes('catch')) {
        issues.push({
          id: `ai-model-${Date.now()}-no-error-handling`,
          category: 'ai-systems',
          severity: 'HIGH',
          description: 'Model inference without proper error handling',
          file,
          autoFixable: true,
          impact: ['reliability', 'user-experience'],
          recommendation: 'Add try-catch blocks around model inference'
        });
      }

      // Check for model performance monitoring
      if (content.includes('model') && !content.includes('metrics') && !content.includes('monitoring')) {
        issues.push({
          id: `ai-model-${Date.now()}-no-monitoring`,
          category: 'ai-systems',
          severity: 'MEDIUM',
          description: 'AI models without performance monitoring',
          file,
          autoFixable: false,
          impact: ['model-drift', 'performance'],
          recommendation: 'Implement model performance monitoring and alerting'
        });
      }

      // Check for model explainability
      if (content.includes('predict') && !content.includes('explain') && !content.includes('interpret')) {
        issues.push({
          id: `ai-model-${Date.now()}-no-explainability`,
          category: 'ai-systems',
          severity: 'MEDIUM',
          description: 'AI models without explainability features',
          file,
          autoFixable: false,
          impact: ['transparency', 'compliance'],
          recommendation: 'Add model explanation and interpretation capabilities'
        });
      }
    }

    return issues;
  }

  private async checkBias(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const aiFiles = await this.findAIFiles();

    for (const file of aiFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for bias detection
      if (content.includes('train') && !content.includes('bias')) {
        issues.push({
          id: `ai-bias-${Date.now()}-no-detection`,
          category: 'ai-systems',
          severity: 'HIGH',
          description: 'AI training without bias detection',
          file,
          autoFixable: false,
          impact: ['fairness', 'ethics', 'compliance'],
          recommendation: 'Implement bias detection and mitigation strategies'
        });
      }

      // Check for demographic parity
      if (content.includes('demographic') || content.includes('gender') || content.includes('race')) {
        if (!content.includes('fairness') && !content.includes('equity')) {
          issues.push({
            id: `ai-bias-${Date.now()}-demographic-issues`,
            category: 'ai-systems',
            severity: 'CRITICAL',
            description: 'Demographic data usage without fairness considerations',
            file,
            autoFixable: false,
            impact: ['fairness', 'legal-compliance', 'ethics'],
            recommendation: 'Implement demographic parity checks and fairness metrics'
          });
        }
      }

      // Check for data diversity
      if (content.includes('dataset') && !content.includes('diverse') && !content.includes('balanced')) {
        issues.push({
          id: `ai-bias-${Date.now()}-dataset-diversity`,
          category: 'ai-systems',
          severity: 'MEDIUM',
          description: 'Training datasets without diversity assessment',
          file,
          autoFixable: false,
          impact: ['bias', 'model-performance', 'generalization'],
          recommendation: 'Assess and ensure dataset diversity and balance'
        });
      }

      // Check for protected attributes
      const protectedAttributes = ['age', 'gender', 'race', 'religion', 'nationality'];
      for (const attr of protectedAttributes) {
        if (content.includes(attr) && content.includes('feature')) {
          if (!content.includes('protected') && !content.includes('sensitive')) {
            issues.push({
              id: `ai-bias-${Date.now()}-protected-attrs`,
              category: 'ai-systems',
              severity: 'HIGH',
              description: `Protected attribute '${attr}' used without proper safeguards`,
              file,
              autoFixable: false,
              impact: ['discrimination', 'legal-compliance'],
              recommendation: 'Implement protections for sensitive attributes'
            });
          }
        }
      }
    }

    return issues;
  }

  private async validateAccuracy(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const aiFiles = await this.findAIFiles();

    for (const file of aiFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for accuracy metrics
      if (content.includes('model') && !content.includes('accuracy') && !content.includes('f1')) {
        issues.push({
          id: `ai-accuracy-${Date.now()}-no-metrics`,
          category: 'ai-systems',
          severity: 'HIGH',
          description: 'AI models without accuracy metrics tracking',
          file,
          autoFixable: true,
          impact: ['model-quality', 'performance'],
          recommendation: 'Implement comprehensive accuracy metrics (precision, recall, F1)'
        });
      }

      // Check for validation sets
      if (content.includes('train') && !content.includes('validation') && !content.includes('test')) {
        issues.push({
          id: `ai-accuracy-${Date.now()}-no-validation-set`,
          category: 'ai-systems',
          severity: 'CRITICAL',
          description: 'Model training without validation/test sets',
          file,
          autoFixable: false,
          impact: ['overfitting', 'model-reliability'],
          recommendation: 'Split data into training, validation, and test sets'
        });
      }

      // Check for cross-validation
      if (content.includes('train') && !content.includes('cross_val') && !content.includes('k_fold')) {
        issues.push({
          id: `ai-accuracy-${Date.now()}-no-cross-validation`,
          category: 'ai-systems',
          severity: 'MEDIUM',
          description: 'Model training without cross-validation',
          file,
          autoFixable: false,
          impact: ['model-robustness', 'generalization'],
          recommendation: 'Implement k-fold cross-validation'
        });
      }

      // Check for confidence scores
      if (content.includes('predict') && !content.includes('confidence') && !content.includes('probability')) {
        issues.push({
          id: `ai-accuracy-${Date.now()}-no-confidence`,
          category: 'ai-systems',
          severity: 'MEDIUM',
          description: 'Model predictions without confidence scores',
          file,
          autoFixable: true,
          impact: ['interpretability', 'decision-making'],
          recommendation: 'Include confidence scores with predictions'
        });
      }

      // Check for accuracy thresholds
      if (content.includes('predict') && !content.includes('threshold')) {
        issues.push({
          id: `ai-accuracy-${Date.now()}-no-threshold`,
          category: 'ai-systems',
          severity: 'MEDIUM',
          description: 'Model predictions without accuracy thresholds',
          file,
          autoFixable: true,
          impact: ['quality-control', 'reliability'],
          recommendation: 'Set minimum accuracy thresholds for predictions'
        });
      }
    }

    return issues;
  }

  private async auditTraining(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const aiFiles = await this.findAIFiles();

    for (const file of aiFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for training data provenance
      if (content.includes('train') && !content.includes('source') && !content.includes('provenance')) {
        issues.push({
          id: `ai-training-${Date.now()}-no-provenance`,
          category: 'ai-systems',
          severity: 'MEDIUM',
          description: 'Training data without provenance tracking',
          file,
          autoFixable: false,
          impact: ['data-governance', 'reproducibility'],
          recommendation: 'Document training data sources and lineage'
        });
      }

      // Check for data quality validation
      if (content.includes('dataset') && !content.includes('clean') && !content.includes('validate')) {
        issues.push({
          id: `ai-training-${Date.now()}-no-data-quality`,
          category: 'ai-systems',
          severity: 'HIGH',
          description: 'Training data without quality validation',
          file,
          autoFixable: false,
          impact: ['model-quality', 'accuracy'],
          recommendation: 'Implement data quality checks and cleaning procedures'
        });
      }

      // Check for hyperparameter tuning
      if (content.includes('train') && !content.includes('hyperparameter') && !content.includes('grid_search')) {
        issues.push({
          id: `ai-training-${Date.now()}-no-tuning`,
          category: 'ai-systems',
          severity: 'LOW',
          description: 'Model training without hyperparameter optimization',
          file,
          autoFixable: false,
          impact: ['model-performance', 'optimization'],
          recommendation: 'Implement hyperparameter tuning procedures'
        });
      }

      // Check for training reproducibility
      if (content.includes('train') && !content.includes('seed') && !content.includes('random_state')) {
        issues.push({
          id: `ai-training-${Date.now()}-not-reproducible`,
          category: 'ai-systems',
          severity: 'MEDIUM',
          description: 'Model training without reproducibility controls',
          file,
          autoFixable: true,
          impact: ['reproducibility', 'debugging'],
          recommendation: 'Set random seeds for reproducible training'
        });
      }

      // Check for model checkpointing
      if (content.includes('train') && !content.includes('checkpoint') && !content.includes('save')) {
        issues.push({
          id: `ai-training-${Date.now()}-no-checkpoints`,
          category: 'ai-systems',
          severity: 'MEDIUM',
          description: 'Model training without checkpointing',
          file,
          autoFixable: true,
          impact: ['training-efficiency', 'recovery'],
          recommendation: 'Implement model checkpointing during training'
        });
      }
    }

    return issues;
  }

  private calculateAIScore(issues: Issue[]): number {
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

  private async findAIFiles(): Promise<string[]> {
    const aiKeywords = ['ai', 'ml', 'model', 'train', 'predict', 'neural', 'learning'];
    const files: string[] = [];

    async function scanDirectory(dir: string): Promise<void> {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
            await scanDirectory(fullPath);
          } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.js'))) {
            // Check if file is AI-related
            const isAIFile = aiKeywords.some(keyword => 
              entry.name.toLowerCase().includes(keyword) || 
              fullPath.toLowerCase().includes(keyword)
            );
            
            if (isAIFile) {
              files.push(fullPath);
            }
          }
        }
      } catch (error) {
        // Skip directories we can't read
      }
    }

    await scanDirectory('./src');
    return files;
  }
}