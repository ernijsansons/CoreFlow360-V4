export interface Issue {
  id: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  file?: string;
  line?: number;
  autoFixable: boolean;
  impact: string[];
  recommendation: string;
}

export interface Fix {
  issueId: string;
  description: string;
  appliedAt: Date;
  changes: string[];
  status: 'SUCCESS' | 'PARTIAL' | 'FAILED';
}

export interface AuditCategory {
  score: number;
  issues: Issue[];
  metrics: Record<string, any>;
  recommendations: string[];
}

export interface AIAnalysis {
  security: AuditCategory;
  performance: AuditCategory;
  codeQuality: AuditCategory;
  dataIntegrity: AuditCategory;
  aiSystems: AuditCategory;
  compliance: AuditCategory;
  overallInsights: string[];
  criticalRisks: string[];
}

export interface MasterAuditReport {
  summary: {
    duration: number;
    totalIssues: number;
    critical: number;
    autoFixed: number;
    score: number;
  };
  findings: {
    security: SecurityAuditResult;
    performance: PerformanceAuditResult;
    codeQuality: CodeQualityAuditResult;
    dataIntegrity: DataIntegrityAuditResult;
    aiSystems: AISystemsAuditResult;
    compliance: ComplianceAuditResult;
  };
  recommendations: {
    immediate: Issue[];
    high: Issue[];
    medium: Issue[];
    low: Issue[];
  };
  autoFixes: Fix[];
  nextSteps: ActionPlan;
  certification: CertificationReport;
}

export interface SecurityAuditResult {
  vulnerabilities: Issue[];
  misconfigurations: Issue[];
  authIssues: Issue[];
  encryptionIssues: Issue[];
  score: number;
}

export interface PerformanceAuditResult {
  bottlenecks: Issue[];
  memoryLeaks: Issue[];
  inefficientQueries: Issue[];
  cachingIssues: Issue[];
  score: number;
}

export interface CodeQualityAuditResult {
  complexity: Issue[];
  duplication: Issue[];
  testCoverage: Issue[];
  documentation: Issue[];
  score: number;
}

export interface DataIntegrityAuditResult {
  validationIssues: Issue[];
  consistencyIssues: Issue[];
  backupIssues: Issue[];
  retentionIssues: Issue[];
  score: number;
}

export interface AISystemsAuditResult {
  modelIssues: Issue[];
  biasIssues: Issue[];
  accuracyIssues: Issue[];
  trainingIssues: Issue[];
  score: number;
}

export interface ComplianceAuditResult {
  gdprIssues: Issue[];
  ccpaIssues: Issue[];
  hipaaIssues: Issue[];
  pciDssIssues: Issue[];
  score: number;
}

export interface ActionPlan {
  immediate: string[];
  shortTerm: string[];
  longTerm: string[];
  preventive: string[];
}

export interface CertificationReport {
  passed: boolean;
  level: 'PLATINUM' | 'GOLD' | 'SILVER' | 'BRONZE' | 'FAILED';
  scores: Record<string, number>;
  recommendations: string[];
  validUntil: Date;
}