export interface LaunchStatus {
  stage: LaunchStage;
  progress: number;
  status: 'PREPARING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED' | 'ROLLING_BACK';
  startTime: Date;
  endTime?: Date;
  currentMetrics: LaunchMetrics;
  issues: LaunchIssue[];
  rollbackPlan?: RollbackPlan;
}

export interface LaunchStage {
  name: string;
  users: string;
  duration: string;
  targetUsers: number;
  currentUsers: number;
  healthScore: number;
  startTime?: Date;
  endTime?: Date;
  status: 'PENDING' | 'ACTIVE' | 'COMPLETED' | 'FAILED';
}

export interface PreFlightChecks {
  security: SecurityValidation;
  performance: PerformanceValidation;
  compliance: ComplianceValidation;
  infrastructure: InfrastructureValidation;
  backups: BackupValidation;
  monitoring: MonitoringValidation;
  rollback: RollbackValidation;
  allPassed: boolean;
  failures: string[];
}

export interface SecurityValidation {
  vulnerabilityScore: number;
  penetrationTestPassed: boolean;
  accessControlsValidated: boolean;
  encryptionValidated: boolean;
  secretsRotated: boolean;
  complianceScore: number;
  issues: string[];
  passed: boolean;
}

export interface PerformanceValidation {
  loadTestPassed: boolean;
  responseTimeTarget: number;
  actualResponseTime: number;
  throughputTarget: number;
  actualThroughput: number;
  errorRateTarget: number;
  actualErrorRate: number;
  scalabilityValidated: boolean;
  issues: string[];
  passed: boolean;
}

export interface ComplianceValidation {
  gdprCompliant: boolean;
  hipaaCompliant: boolean;
  pciDssCompliant: boolean;
  ccpaCompliant: boolean;
  auditTrailEnabled: boolean;
  dataRetentionPolicies: boolean;
  issues: string[];
  passed: boolean;
}

export interface InfrastructureValidation {
  cloudflareConfigured: boolean;
  dnsConfigured: boolean;
  sslCertificatesValid: boolean;
  cdnConfigured: boolean;
  loadBalancerHealthy: boolean;
  databaseHealthy: boolean;
  storageHealthy: boolean;
  issues: string[];
  passed: boolean;
}

export interface BackupValidation {
  automatedBackupsEnabled: boolean;
  backupTestSuccessful: boolean;
  recoveryTimeObjective: number;
  recoveryPointObjective: number;
  crossRegionReplication: boolean;
  encryptedBackups: boolean;
  issues: string[];
  passed: boolean;
}

export interface MonitoringValidation {
  healthChecksEnabled: boolean;
  alertingConfigured: boolean;
  loggingEnabled: boolean;
  metricsCollectionEnabled: boolean;
  dashboardsOperational: boolean;
  incidentResponseReady: boolean;
  issues: string[];
  passed: boolean;
}

export interface RollbackValidation {
  rollbackPlanTested: boolean;
  rollbackTimeTarget: number;
  estimatedRollbackTime: number;
  dataIntegrityValidated: boolean;
  rollbackTriggersConfigured: boolean;
  communicationPlanReady: boolean;
  issues: string[];
  passed: boolean;
}

export interface LaunchMetrics {
  activeUsers: number;
  errorRate: number;
  responseTime: number;
  throughput: number;
  cpuUtilization: number;
  memoryUtilization: number;
  diskUtilization: number;
  networkLatency: number;
  databasePerformance: number;
  customerSatisfaction: number;
  businessMetrics: BusinessMetrics;
}

export interface BusinessMetrics {
  revenue: number;
  conversionRate: number;
  userEngagement: number;
  supportTickets: number;
  nps: number;
  churnRate: number;
}

export interface LaunchIssue {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  description: string;
  detectedAt: Date;
  stage: string;
  impact: string[];
  resolution?: string;
  resolvedAt?: Date;
}

export interface RollbackPlan {
  trigger: 'MANUAL' | 'AUTOMATIC';
  conditions: RollbackCondition[];
  steps: RollbackStep[];
  estimatedTime: number;
  dataBackupRequired: boolean;
  communicationPlan: string[];
}

export interface RollbackCondition {
  metric: string;
  threshold: number;
  duration: number;
  enabled: boolean;
}

export interface RollbackStep {
  order: number;
  description: string;
  command: string;
  estimatedTime: number;
  verification: string;
  rollbackRequired: boolean;
}

export interface ProgressiveRolloutConfig {
  stages: LaunchStageConfig[];
  rollbackConditions: RollbackCondition[];
  monitoringInterval: number;
  approvalRequired: boolean;
}

export interface LaunchStageConfig {
  name: string;
  users: string;
  duration: string;
  userPercentage?: number;
  healthThresholds: HealthThresholds;
  approvalRequired: boolean;
  canaryMetrics: string[];
}

export interface HealthThresholds {
  errorRate: number;
  responseTime: number;
  availability: number;
  customerSatisfaction: number;
}

export interface DeploymentEnvironment {
  name: string;
  type: 'production' | 'staging' | 'canary';
  region: string;
  cloudflareZone: string;
  databaseUrl: string;
  storageUrl: string;
  monitoringUrl: string;
}

export interface LaunchNotification {
  type: 'EMAIL' | 'SLACK' | 'SMS' | 'WEBHOOK';
  recipients: string[];
  template: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface LaunchReport {
  launchId: string;
  startTime: Date;
  endTime?: Date;
  status: LaunchStatus['status'];
  stages: LaunchStageReport[];
  metrics: LaunchMetricsReport;
  issues: LaunchIssue[];
  lessons: string[];
  recommendations: string[];
}

export interface LaunchStageReport {
  stage: LaunchStage;
  duration: number;
  userAdoption: number;
  healthScore: number;
  keyMetrics: Record<string, number>;
  issues: LaunchIssue[];
  success: boolean;
}

export interface LaunchMetricsReport {
  preLaunch: LaunchMetrics;
  postLaunch: LaunchMetrics;
  peak: LaunchMetrics;
  average: LaunchMetrics;
  trends: MetricTrend[];
}

export interface MetricTrend {
  metric: string;
  direction: 'UP' | 'DOWN' | 'STABLE';
  magnitude: number;
  significance: 'LOW' | 'MEDIUM' | 'HIGH';
}