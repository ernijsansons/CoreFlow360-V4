export interface ReplicationTopology {
  regions: RegionNode[];
  links: ReplicationLink[];
  strategy: 'star' | 'mesh' | 'ring' | 'tree' | 'hybrid';
  consistency: 'strong' | 'eventual' | 'causal' | 'session';
}

export interface RegionNode {
  id: string;
  role: 'primary' | 'secondary' | 'backup';
  capabilities: NodeCapabilities;
  health: NodeHealth;
  location: GeographicLocation;
  compliance: ComplianceConstraints;
}

export interface NodeCapabilities {
  read: boolean;
  write: boolean;
  replicate: boolean;
  backup: boolean;
  storage: number; // GB
  bandwidth: number; // Mbps
  latency: number; // ms
}

export interface NodeHealth {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'offline';
  uptime: number;
  lastCheck: Date;
  metrics: HealthMetrics;
}

export interface HealthMetrics {
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  errors: number;
}

export interface ComplianceConstraints {
  dataResidency: boolean;
  crossBorder: 'allowed' | 'restricted' | 'prohibited';
  encryption: 'required' | 'optional';
  audit: 'full' | 'minimal' | 'none';
}

export interface ReplicationLink {
  from: string;
  to: string;
  type: 'sync' | 'async' | 'hybrid';
  direction: 'bidirectional' | 'unidirectional';
  priority: number;
  bandwidth: number;
  latency: number;
  reliability: number;
  cost: number;
  enabled: boolean;
}

export interface GeographicLocation {
  country: string;
  region: string;
  city: string;
  coordinates: {
    latitude: number;
    longitude: number;
  };
  timezone: string;
  dataCenter: string;
}

export interface ReplicationConfig {
  id: string;
  name: string;
  description: string;
  topology: ReplicationTopology;
  consistency: ConsistencyConfig;
  conflictResolution: ConflictResolutionConfig;
  monitoring: MonitoringConfig;
  security: SecurityConfig;
  performance: PerformanceConfig;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ConsistencyConfig {
  level: 'strong' | 'eventual' | 'causal' | 'session';
  timeout: number; // ms
  retries: number;
  quorum: number;
  readRepair: boolean;
  hintedHandoff: boolean;
}

export interface ConflictResolutionConfig {
  strategy: 'last-write-wins' | 'first-write-wins' | 'custom' | 'manual';
  customResolver?: string;
  timestampField: string;
  versionField: string;
  mergeStrategy: 'overwrite' | 'merge' | 'custom';
}

export interface MonitoringConfig {
  enabled: boolean;
  interval: number; // seconds
  metrics: string[];
  alerts: AlertConfig[];
  dashboards: DashboardConfig[];
  reports: ReportConfig[];
}

export interface AlertConfig {
  id: string;
  name: string;
  condition: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  channels: string[];
  cooldown: number; // minutes
}

export interface DashboardConfig {
  id: string;
  name: string;
  widgets: WidgetConfig[];
  refreshInterval: number; // seconds
  public: boolean;
}

export interface WidgetConfig {
  id: string;
  type: 'metric' | 'chart' | 'table' | 'log';
  title: string;
  query: string;
  position: { x: number; y: number; w: number; h: number };
  options: Record<string, any>;
}

export interface ReportConfig {
  id: string;
  name: string;
  schedule: string; // cron expression
  format: 'pdf' | 'html' | 'csv' | 'json';
  recipients: string[];
  enabled: boolean;
}

export interface SecurityConfig {
  encryption: EncryptionConfig;
  authentication: AuthenticationConfig;
  authorization: AuthorizationConfig;
  audit: AuditConfig;
  compliance: ComplianceConfig;
}

export interface EncryptionConfig {
  atRest: boolean;
  inTransit: boolean;
  algorithm: string;
  keySize: number;
  keyRotation: number; // days
  keyManagement: 'internal' | 'external' | 'hybrid';
}

export interface AuthenticationConfig {
  method: 'token' | 'certificate' | 'oauth' | 'saml';
  provider: string;
  timeout: number; // seconds
  refreshInterval: number; // seconds
  mfa: boolean;
}

export interface AuthorizationConfig {
  model: 'rbac' | 'abac' | 'custom';
  policies: PolicyConfig[];
  defaultDeny: boolean;
  audit: boolean;
}

export interface PolicyConfig {
  id: string;
  name: string;
  description: string;
  rules: RuleConfig[];
  enabled: boolean;
}

export interface RuleConfig {
  id: string;
  effect: 'allow' | 'deny';
  action: string;
  resource: string;
  condition: string;
  priority: number;
}

export interface AuditConfig {
  enabled: boolean;
  level: 'minimal' | 'standard' | 'detailed' | 'comprehensive';
  retention: number; // days
  realTime: boolean;
  encryption: boolean;
}

export interface ComplianceConfig {
  standards: string[];
  requirements: RequirementConfig[];
  reporting: ReportingConfig;
  validation: ValidationConfig;
}

export interface RequirementConfig {
  id: string;
  standard: string;
  description: string;
  mandatory: boolean;
  validation: string;
  documentation: string;
}

export interface ReportingConfig {
  frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly';
  format: 'pdf' | 'html' | 'csv' | 'json';
  recipients: string[];
  automated: boolean;
}

export interface ValidationConfig {
  enabled: boolean;
  frequency: 'continuous' | 'daily' | 'weekly' | 'monthly';
  rules: ValidationRule[];
  alerts: boolean;
}

export interface ValidationRule {
  id: string;
  name: string;
  description: string;
  query: string;
  threshold: number;
  operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  enabled: boolean;
}

export interface PerformanceConfig {
  optimization: OptimizationConfig;
  caching: CachingConfig;
  compression: CompressionConfig;
  batching: BatchingConfig;
  throttling: ThrottlingConfig;
}

export interface OptimizationConfig {
  enabled: boolean;
  algorithms: string[];
  parameters: Record<string, any>;
  autoTuning: boolean;
  monitoring: boolean;
}

export interface CachingConfig {
  enabled: boolean;
  strategy: 'lru' | 'lfu' | 'fifo' | 'ttl';
  size: number; // MB
  ttl: number; // seconds
  invalidation: InvalidationConfig;
}

export interface InvalidationConfig {
  strategy: 'time' | 'event' | 'manual' | 'hybrid';
  events: string[];
  timeout: number; // seconds
  batch: boolean;
}

export interface CompressionConfig {
  enabled: boolean;
  algorithm: 'gzip' | 'brotli' | 'lz4' | 'zstd';
  level: number;
  threshold: number; // bytes
  types: string[];
}

export interface BatchingConfig {
  enabled: boolean;
  size: number;
  timeout: number; // ms
  strategy: 'size' | 'time' | 'hybrid';
  compression: boolean;
}

export interface ThrottlingConfig {
  enabled: boolean;
  rate: number; // requests per second
  burst: number;
  window: number; // seconds
  strategy: 'token-bucket' | 'leaky-bucket' | 'sliding-window';
}

export interface ReplicationStatus {
  id: string;
  configId: string;
  status: 'active' | 'paused' | 'stopped' | 'error';
  health: HealthStatus;
  metrics: ReplicationMetrics;
  lastSync: Date;
  nextSync: Date;
  errors: ReplicationError[];
  warnings: ReplicationWarning[];
}

export interface HealthStatus {
  overall: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  regions: RegionHealthStatus[];
  links: LinkHealthStatus[];
  lastCheck: Date;
}

export interface RegionHealthStatus {
  regionId: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'offline';
  latency: number;
  throughput: number;
  errorRate: number;
  lastCheck: Date;
}

export interface LinkHealthStatus {
  linkId: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'down';
  latency: number;
  bandwidth: number;
  reliability: number;
  lastCheck: Date;
}

export interface ReplicationMetrics {
  totalOperations: number;
  successfulOperations: number;
  failedOperations: number;
  averageLatency: number;
  p95Latency: number;
  p99Latency: number;
  throughput: number;
  dataTransferred: number; // bytes
  conflicts: number;
  repairs: number;
}

export interface ReplicationError {
  id: string;
  type: 'network' | 'authentication' | 'authorization' | 'data' | 'system';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  region: string;
  timestamp: Date;
  resolved: boolean;
  resolution?: string;
}

export interface ReplicationWarning {
  id: string;
  type: 'performance' | 'capacity' | 'security' | 'compliance';
  severity: 'low' | 'medium' | 'high';
  message: string;
  region: string;
  timestamp: Date;
  acknowledged: boolean;
  action?: string;
}

export interface ReplicationTask {
  id: string;
  configId: string;
  type: 'sync' | 'backup' | 'restore' | 'migrate' | 'validate';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  priority: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  target: string;
  data: ReplicationData;
  progress: number;
  startTime: Date;
  endTime?: Date;
  error?: string;
  retries: number;
  maxRetries: number;
}

export interface ReplicationData {
  tables: string[];
  filters: Record<string, any>;
  transformations: TransformationConfig[];
  validation: ValidationConfig;
  compression: boolean;
  encryption: boolean;
}

export interface TransformationConfig {
  id: string;
  name: string;
  type: 'filter' | 'map' | 'reduce' | 'aggregate' | 'custom';
  parameters: Record<string, any>;
  enabled: boolean;
  order: number;
}

export interface ReplicationLog {
  id: string;
  taskId: string;
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  timestamp: Date;
  region: string;
  details: Record<string, any>;
}

export interface ReplicationAnalytics {
  period: {
    start: Date;
    end: Date;
  };
  metrics: {
    totalTasks: number;
    successfulTasks: number;
    failedTasks: number;
    averageDuration: number;
    totalDataTransferred: number;
    conflicts: number;
    repairs: number;
  };
  trends: {
    throughput: number[];
    latency: number[];
    errorRate: number[];
    timestamps: Date[];
  };
  regions: {
    [regionId: string]: {
      tasks: number;
      successRate: number;
      averageLatency: number;
      dataTransferred: number;
    };
  };
}

export interface QuantumReplicationEngine {
  // Configuration management
  createConfig(config: Omit<ReplicationConfig, 'id' | 'createdAt' | 'updatedAt'>): Promise<ReplicationConfig>;
  updateConfig(configId: string, updates: Partial<ReplicationConfig>): Promise<ReplicationConfig>;
  deleteConfig(configId: string): Promise<void>;
  getConfig(configId: string): Promise<ReplicationConfig | null>;
  getConfigs(): Promise<ReplicationConfig[]>;
  
  // Status and health monitoring
  getStatus(configId: string): Promise<ReplicationStatus>;
  getHealth(configId: string): Promise<HealthStatus>;
  getMetrics(configId: string, period?: { start: Date; end: Date }): Promise<ReplicationMetrics>;
  
  // Task management
  createTask(task: Omit<ReplicationTask, 'id' | 'startTime' | 'retries'>): Promise<ReplicationTask>;
  getTask(taskId: string): Promise<ReplicationTask | null>;
  getTasks(configId?: string, status?: string): Promise<ReplicationTask[]>;
  cancelTask(taskId: string): Promise<void>;
  retryTask(taskId: string): Promise<void>;
  
  // Logging and monitoring
  getLogs(taskId: string, level?: string, limit?: number): Promise<ReplicationLog[]>;
  getAlerts(configId: string): Promise<AlertConfig[]>;
  acknowledgeAlert(alertId: string): Promise<void>;
  
  // Analytics and reporting
  getAnalytics(configId: string, period: { start: Date; end: Date }): Promise<ReplicationAnalytics>;
  generateReport(configId: string, format: string, period: { start: Date; end: Date }): Promise<Buffer>;
  
  // Topology management
  updateTopology(configId: string, topology: ReplicationTopology): Promise<void>;
  addRegion(configId: string, region: RegionNode): Promise<void>;
  removeRegion(configId: string, regionId: string): Promise<void>;
  updateRegion(configId: string, regionId: string, updates: Partial<RegionNode>): Promise<void>;
  
  // Conflict resolution
  resolveConflict(conflictId: string, resolution: any): Promise<void>;
  getConflicts(configId: string): Promise<Array<{
    id: string;
    type: string;
    data: any;
    timestamp: Date;
    regions: string[];
  }>>;
  
  // Performance optimization
  optimizeConfig(configId: string): Promise<ReplicationConfig>;
  getOptimizationSuggestions(configId: string): Promise<Array<{
    type: string;
    description: string;
    impact: 'low' | 'medium' | 'high';
    effort: 'low' | 'medium' | 'high';
    recommendation: string;
  }>>;
  
  // Security and compliance
  validateCompliance(configId: string): Promise<{
    compliant: boolean;
    violations: Array<{
      standard: string;
      requirement: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      description: string;
      recommendation: string;
    }>;
  }>;
  
  // Backup and restore
  createBackup(configId: string, region: string): Promise<{
    backupId: string;
    location: string;
    size: number;
    timestamp: Date;
  }>;
  restoreFromBackup(backupId: string, targetRegion: string): Promise<void>;
  getBackups(configId: string): Promise<Array<{
    id: string;
    region: string;
    size: number;
    timestamp: Date;
    location: string;
  }>>;
  
  // Testing and validation
  testReplication(configId: string, testData: any): Promise<{
    success: boolean;
    latency: number;
    throughput: number;
    errors: string[];
  }>;
  validateData(configId: string, region: string): Promise<{
    valid: boolean;
    errors: string[];
    warnings: string[];
  }>;
  
  // Maintenance
  startMaintenance(configId: string, region: string, duration: number): Promise<void>;
  endMaintenance(configId: string, region: string): Promise<void>;
  getMaintenanceSchedule(): Promise<Array<{
    configId: string;
    region: string;
    startTime: Date;
    endTime: Date;
    description: string;
  }>>;
}

