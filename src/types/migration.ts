export interface Schema {
  name: string;
  tables: Table[];
  version: string;
  metadata: Record<string, any>;
}

export interface Table {
  name: string;
  columns: Column[];
  primaryKey: string[];
  foreignKeys: ForeignKey[];
  indexes: Index[];
  constraints: Constraint[];
  metadata: Record<string, any>;
}

export interface Column {
  name: string;
  type: string;
  nullable: boolean;
  defaultValue?: any;
  length?: number;
  precision?: number;
  scale?: number;
  metadata: Record<string, any>;
}

export interface ForeignKey {
  name: string;
  columns: string[];
  referencedTable: string;
  referencedColumns: string[];
  onDelete: 'CASCADE' | 'SET NULL' | 'RESTRICT' | 'NO ACTION';
  onUpdate: 'CASCADE' | 'SET NULL' | 'RESTRICT' | 'NO ACTION';
}

export interface Index {
  name: string;
  columns: string[];
  unique: boolean;
  type: 'BTREE' | 'HASH' | 'GIN' | 'GIST';
}

export interface Constraint {
  name: string;
  type: 'CHECK' | 'UNIQUE' | 'NOT NULL';
  definition: string;
}

export interface MappingRules {
  id: string;
  sourceSchema: string;
  targetSchema: string;
  tableMappings: TableMapping[];
  globalTransformations: Transformation[];
  confidence: number;
  createdAt: Date;
  updatedAt: Date;
  metadata: Record<string, any>;
}

export interface TableMapping {
  sourceTable: string;
  targetTable: string;
  columnMappings: ColumnMapping[];
  filters: FilterRule[];
  transformations: Transformation[];
  confidence: number;
}

export interface ColumnMapping {
  sourceColumn: string;
  targetColumn: string;
  transformation?: Transformation;
  confidence: number;
  required: boolean;
  metadata: Record<string, any>;
}

export interface Transformation {
  id: string;
  type: 'DIRECT' | 'EXPRESSION' | 'LOOKUP' | 'CALCULATION' | 'ENRICHMENT' | 'CUSTOM';
  expression?: string;
  lookupTable?: string;
  lookupKey?: string;
  parameters: Record<string, any>;
  description: string;
}

export interface FilterRule {
  column: string;
  operator: 'EQUALS' | 'NOT_EQUALS' | 'GREATER' | 'LESS' | 'LIKE' | 'IN' | 'NOT_IN' | 'IS_NULL' | 'IS_NOT_NULL';
  value: any;
  logicalOperator?: 'AND' | 'OR';
}

export interface MigrationConfig {
  id: string;
  name: string;
  description: string;
  sourceConnection: ConnectionConfig;
  targetConnection: ConnectionConfig;
  mappingRules: MappingRules;
  executionConfig: ExecutionConfig;
  validationConfig: ValidationConfig;
  rollbackConfig: RollbackConfig;
  status: MigrationStatus;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ConnectionConfig {
  id: string;
  type: 'DATABASE' | 'FILE' | 'API' | 'STREAM';
  name: string;
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  password?: string;
  ssl?: boolean;
  url?: string;
  filePath?: string;
  apiKey?: string;
  headers?: Record<string, string>;
  parameters: Record<string, any>;
  testQuery?: string;
}

export interface ExecutionConfig {
  mode: 'FULL' | 'INCREMENTAL' | 'DIFFERENTIAL';
  batchSize: number;
  parallelStreams: number;
  resumeFromCheckpoint: boolean;
  enableCheckpoints: boolean;
  checkpointInterval: number;
  retryAttempts: number;
  retryBackoff: 'LINEAR' | 'EXPONENTIAL';
  timeoutSeconds: number;
  preserveOrder: boolean;
  enableCompression: boolean;
}

export interface ValidationConfig {
  enablePreValidation: boolean;
  enablePostValidation: boolean;
  sampleValidationSize: number;
  dataQualityChecks: DataQualityCheck[];
  businessRules: BusinessRule[];
  complianceChecks: ComplianceCheck[];
  customValidations: CustomValidation[];
}

export interface DataQualityCheck {
  id: string;
  name: string;
  type: 'COMPLETENESS' | 'ACCURACY' | 'CONSISTENCY' | 'VALIDITY' | 'UNIQUENESS';
  column?: string;
  rule: string;
  threshold: number;
  severity: 'ERROR' | 'WARNING' | 'INFO';
  enabled: boolean;
}

export interface BusinessRule {
  id: string;
  name: string;
  description: string;
  expression: string;
  errorMessage: string;
  severity: 'ERROR' | 'WARNING';
  enabled: boolean;
}

export interface ComplianceCheck {
  id: string;
  regulation: 'GDPR' | 'HIPAA' | 'SOX' | 'PCI_DSS' | 'CUSTOM';
  name: string;
  description: string;
  checkType: 'PII_DETECTION' | 'ENCRYPTION' | 'ACCESS_CONTROL' | 'AUDIT_TRAIL';
  parameters: Record<string, any>;
  enabled: boolean;
}

export interface CustomValidation {
  id: string;
  name: string;
  code: string;
  language: 'JAVASCRIPT' | 'SQL' | 'PYTHON';
  parameters: Record<string, any>;
  enabled: boolean;
}

export interface RollbackConfig {
  enableSnapshots: boolean;
  snapshotInterval: number;
  retentionDays: number;
  compressionLevel: number;
  enablePointInTimeRecovery: boolean;
  backupToR2: boolean;
  encryptBackups: boolean;
}

export type MigrationStatus =
  | 'DRAFT'
  | 'VALIDATING'
  | 'READY'
  | 'RUNNING'
  | 'PAUSED'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'ROLLING_BACK'
  | 'ROLLED_BACK';

export interface MigrationExecution {
  id: string;
  migrationId: string;
  status: MigrationStatus;
  startTime: Date;
  endTime?: Date;
  progress: MigrationProgress;
  statistics: MigrationStatistics;
  checkpoints: Checkpoint[];
  errors: MigrationError[];
  warnings: MigrationWarning[];
  logs: MigrationLog[];
}

export interface MigrationProgress {
  totalRecords: number;
  processedRecords: number;
  successfulRecords: number;
  failedRecords: number;
  skippedRecords: number;
  percentage: number;
  estimatedTimeRemaining: number;
  currentBatch: number;
  totalBatches: number;
  recordsPerSecond: number;
}

export interface MigrationStatistics {
  executionTime: number;
  throughput: number;
  peakMemoryUsage: number;
  networkBytesTransferred: number;
  storageUsed: number;
  costCents: number;
  resourceUtilization: ResourceUtilization;
}

export interface ResourceUtilization {
  cpu: number;
  memory: number;
  network: number;
  storage: number;
  database: number;
}

export interface Checkpoint {
  id: string;
  timestamp: Date;
  recordsProcessed: number;
  batchNumber: number;
  state: Record<string, any>;
  metadata: Record<string, any>;
}

export interface MigrationError {
  id: string;
  timestamp: Date;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  type: 'CONNECTION' | 'TRANSFORMATION' | 'VALIDATION' | 'CONSTRAINT' | 'TIMEOUT' | 'SYSTEM';
  message: string;
  details: string;
  recordId?: string;
  batchId?: string;
  retryCount: number;
  resolved: boolean;
  resolution?: string;
}

export interface MigrationWarning {
  id: string;
  timestamp: Date;
  type: 'DATA_QUALITY' | 'PERFORMANCE' | 'COMPATIBILITY' | 'BUSINESS_RULE';
  message: string;
  details: string;
  recordId?: string;
  acknowledged: boolean;
}

export interface MigrationLog {
  id: string;
  timestamp: Date;
  level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
  category: string;
  message: string;
  details?: Record<string, any>;
}

export interface Correction {
  sourceField: string;
  targetField: string;
  correctMapping: string;
  transformation?: Transformation;
  confidence: number;
  userFeedback: string;
  timestamp: Date;
}

export interface LineageGraph {
  nodes: LineageNode[];
  edges: LineageEdge[];
}

export interface LineageNode {
  id: string;
  type: 'SOURCE' | 'TRANSFORMATION' | 'TARGET';
  name: string;
  metadata: Record<string, any>;
}

export interface LineageEdge {
  source: string;
  target: string;
  type: 'DATA_FLOW' | 'DEPENDENCY';
  transformation?: string;
  metadata: Record<string, any>;
}

export interface Approval {
  id: string;
  type: 'MIGRATION_START' | 'SCHEMA_CHANGE' | 'DATA_DELETION' | 'ROLLBACK';
  requestedBy: string;
  approvedBy?: string;
  requestedAt: Date;
  approvedAt?: Date;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  reason?: string;
  metadata: Record<string, any>;
}

export interface ComplianceResult {
  checkId: string;
  status: 'PASS' | 'FAIL' | 'WARNING';
  message: string;
  details: Record<string, any>;
  timestamp: Date;
}

export interface MigrationAudit {
  migrationId: string;
  startTime: Date;
  endTime?: Date;
  sourceSystem: string;
  targetSystem: string;
  recordsProcessed: number;
  recordsFailed: number;
  transformationsApplied: Transformation[];
  dataLineage: LineageGraph;
  approvals: Approval[];
  complianceChecks: ComplianceResult[];
  costCents: number;
  executedBy: string;
  reviewedBy?: string;
  metadata: Record<string, any>;
}

export interface TestReport {
  id: string;
  migrationId: string;
  testType: 'UNIT' | 'INTEGRATION' | 'PERFORMANCE' | 'FULL';
  status: 'RUNNING' | 'PASSED' | 'FAILED' | 'WARNING';
  startTime: Date;
  endTime?: Date;
  dataIntegrity: DataIntegrityResult;
  performanceMetrics: PerformanceMetrics;
  errorAnalysis: ErrorAnalysis;
  recommendations: Recommendation[];
  sampleData: TestSampleData;
}

export interface DataIntegrityResult {
  totalRecords: number;
  matchedRecords: number;
  mismatchedRecords: number;
  missingRecords: number;
  extraRecords: number;
  integrityScore: number;
  fieldComparisons: FieldComparison[];
}

export interface FieldComparison {
  field: string;
  matches: number;
  mismatches: number;
  accuracy: number;
  commonIssues: string[];
}

export interface PerformanceMetrics {
  executionTime: number;
  throughput: number;
  memoryUsage: number;
  cpuUsage: number;
  networkLatency: number;
  bottlenecks: Bottleneck[];
}

export interface Bottleneck {
  type: 'CPU' | 'MEMORY' | 'NETWORK' | 'DISK' | 'DATABASE';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  impact: number;
  recommendation: string;
}

export interface ErrorAnalysis {
  totalErrors: number;
  errorsByType: Record<string, number>;
  errorsByTable: Record<string, number>;
  criticalErrors: MigrationError[];
  errorPatterns: ErrorPattern[];
}

export interface ErrorPattern {
  pattern: string;
  frequency: number;
  impact: 'HIGH' | 'MEDIUM' | 'LOW';
  suggestion: string;
}

export interface Recommendation {
  type: 'PERFORMANCE' | 'DATA_QUALITY' | 'CONFIGURATION' | 'SCHEMA';
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  action: string;
  estimatedImpact: string;
}

export interface TestSampleData {
  sourceRecords: any[];
  targetRecords: any[];
  transformedRecords: any[];
  comparisonResults: any[];
}

export interface Pipeline {
  id: string;
  name: string;
  stages: PipelineStage[];
  parallelism: number;
  errorHandling: ErrorHandlingStrategy;
}

export interface PipelineStage {
  id: string;
  name: string;
  type: 'CLEANING' | 'TRANSFORMATION' | 'VALIDATION' | 'ENRICHMENT' | 'CUSTOM';
  order: number;
  enabled: boolean;
  configuration: Record<string, any>;
  outputs: string[];
}

export interface ErrorHandlingStrategy {
  onError: 'FAIL' | 'SKIP' | 'RETRY' | 'FALLBACK';
  retryAttempts: number;
  retryDelay: number;
  fallbackValue?: any;
  logLevel: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
}

export interface SyncConfig {
  id: string;
  name: string;
  sourceConnection: ConnectionConfig;
  targetConnection: ConnectionConfig;
  syncMode: 'REAL_TIME' | 'SCHEDULED' | 'MANUAL';
  direction: 'UNIDIRECTIONAL' | 'BIDIRECTIONAL';
  conflictResolution: ConflictResolutionStrategy;
  schedule?: ScheduleConfig;
  filters: FilterRule[];
  transformations: Transformation[];
  enabled: boolean;
}

export interface ConflictResolutionStrategy {
  strategy: 'SOURCE_WINS' | 'TARGET_WINS' | 'TIMESTAMP' | 'CUSTOM';
  customResolver?: string;
  mergeFields?: string[];
}

export interface ScheduleConfig {
  type: 'CRON' | 'INTERVAL';
  expression: string;
  timezone: string;
  startDate?: Date;
  endDate?: Date;
}

export interface CDCEvent {
  id: string;
  timestamp: Date;
  operation: 'INSERT' | 'UPDATE' | 'DELETE';
  table: string;
  oldData?: Record<string, any>;
  newData?: Record<string, any>;
  primaryKey: Record<string, any>;
  metadata: Record<string, any>;
}

export interface MigrationTemplate {
  id: string;
  name: string;
  description: string;
  category: 'DATABASE' | 'CRM' | 'ERP' | 'CUSTOM';
  sourceType: string;
  targetType: string;
  mappingRules: MappingRules;
  transformations: Transformation[];
  validations: ValidationConfig;
  usage: number;
  rating: number;
  tags: string[];
  createdBy: string;
  createdAt: Date;
}

export interface DataSource {
  id: string;
  name: string;
  type: string;
  connection: ConnectionConfig;
  schema?: Schema;
  status: 'CONNECTED' | 'DISCONNECTED' | 'ERROR';
  lastSync?: Date;
  metadata: Record<string, any>;
}

export interface QueueJob {
  id: string;
  type: 'MIGRATION' | 'SYNC' | 'VALIDATION' | 'ROLLBACK';
  priority: number;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  payload: Record<string, any>;
  attempts: number;
  maxAttempts: number;
  scheduledAt: Date;
  startedAt?: Date;
  completedAt?: Date;
  error?: string;
}