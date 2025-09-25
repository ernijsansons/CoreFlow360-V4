export interface FailurePrediction {
  region: string;
  failureProbability: number;
  timeToFailure: number; // minutes
  confidence: number;
  predictedCause: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  affectedServices: string[];
  recommendation: FailoverRecommendation;
}

export interface FailoverRecommendation {
  action: 'monitor' | 'prepare' | 'gradual-drain' | 'immediate-failover';
  targetRegions: string[];
  timeline: number; // minutes
  estimatedDowntime: number; // seconds
  businessImpact: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
}

export interface HealthMetrics {
  region: string;
  timestamp: Date;
  metrics: RegionMetrics;
  logs: LogAnalysis;
  traces: TraceAnalysis;
  synthetic: SyntheticTestResults;
  alerts: Alert[];
}

export interface RegionMetrics {
  availability: number;
  latency: LatencyMetrics;
  throughput: ThroughputMetrics;
  errorRate: number;
  capacity: CapacityMetrics;
  dependencies: DependencyHealth[];
}

export interface LatencyMetrics {
  p50: number;
  p95: number;
  p99: number;
  average: number;
  trend: 'improving' | 'degrading' | 'stable';
}

export interface ThroughputMetrics {
  requestsPerSecond: number;
  bytesPerSecond: number;
  connectionsPerSecond: number;
  utilization: number;
}

export interface CapacityMetrics {
  cpu: ResourceMetric;
  memory: ResourceMetric;
  disk: ResourceMetric;
  network: ResourceMetric;
}

export interface ResourceMetric {
  current: number;
  maximum: number;
  utilization: number;
  trend: 'increasing' | 'decreasing' | 'stable';
  threshold: number;
}

export interface DependencyHealth {
  service: string;
  region: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  latency: number;
  errorRate: number;
  lastCheck: Date;
}

export interface LogAnalysis {
  errorCount: number;
  warningCount: number;
  criticalErrors: string[];
  patterns: LogPattern[];
  anomalies: LogAnomaly[];
}

export interface LogPattern {
  pattern: string;
  frequency: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface LogAnomaly {
  type: 'spike' | 'drop' | 'pattern_change' | 'new_error';
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: Date;
  affectedServices: string[];
}

export interface TraceAnalysis {
  totalTraces: number;
  errorTraces: number;
  slowTraces: number;
  averageDuration: number;
  p95Duration: number;
  p99Duration: number;
  bottlenecks: TraceBottleneck[];
  errors: TraceError[];
}

export interface TraceBottleneck {
  service: string;
  operation: string;
  duration: number;
  frequency: number;
  impact: 'low' | 'medium' | 'high' | 'critical';
}

export interface TraceError {
  service: string;
  operation: string;
  errorType: string;
  frequency: number;
  impact: 'low' | 'medium' | 'high' | 'critical';
  lastOccurrence: Date;
}

export interface SyntheticTestResults {
  totalTests: number;
  passedTests: number;
  failedTests: number;
  averageResponseTime: number;
  availability: number;
  tests: SyntheticTest[];
}

export interface SyntheticTest {
  name: string;
  status: 'pass' | 'fail' | 'timeout' | 'error';
  responseTime: number;
  errorMessage?: string;
  timestamp: Date;
}

export interface Alert {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  source: string;
  timestamp: Date;
  acknowledged: boolean;
  resolved: boolean;
}

export interface FailoverPlan {
  id: string;
  name: string;
  description: string;
  triggerConditions: TriggerCondition[];
  steps: FailoverStep[];
  rollbackSteps: FailoverStep[];
  estimatedDuration: number; // minutes
  businessImpact: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
  lastTested: Date;
  successRate: number;
}

export interface TriggerCondition {
  metric: string;
  operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  threshold: number;
  duration: number; // minutes
  region?: string;
  service?: string;
}

export interface FailoverStep {
  id: string;
  name: string;
  description: string;
  type: 'drain' | 'redirect' | 'scale' | 'restart' | 'notify' | 'wait';
  order: number;
  timeout: number; // seconds
  retries: number;
  parameters: Record<string, any>;
  dependencies: string[];
}

export interface FailoverExecution {
  id: string;
  planId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  startTime: Date;
  endTime?: Date;
  currentStep?: string;
  completedSteps: string[];
  failedSteps: string[];
  logs: ExecutionLog[];
  metrics: ExecutionMetrics;
}

export interface ExecutionLog {
  timestamp: Date;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  stepId?: string;
  details?: Record<string, any>;
}

export interface ExecutionMetrics {
  totalDuration: number; // seconds
  stepsCompleted: number;
  stepsFailed: number;
  successRate: number;
  businessImpact: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
  downtime: number; // seconds
  dataLoss: number; // bytes
}

export interface RegionStatus {
  region: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'maintenance' | 'unknown';
  lastCheck: Date;
  healthScore: number;
  services: ServiceStatus[];
  capacity: CapacityStatus;
  connectivity: ConnectivityStatus;
}

export interface ServiceStatus {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  version: string;
  lastDeployment: Date;
  uptime: number; // seconds
  errorRate: number;
  latency: number;
  throughput: number;
}

export interface CapacityStatus {
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  connections: number;
  maxConnections: number;
}

export interface ConnectivityStatus {
  latency: number;
  packetLoss: number;
  bandwidth: number;
  jitter: number;
  lastCheck: Date;
}

export interface FailoverPolicy {
  id: string;
  name: string;
  description: string;
  regions: string[];
  primaryRegion: string;
  secondaryRegions: string[];
  tertiaryRegions: string[];
  triggers: PolicyTrigger[];
  actions: PolicyAction[];
  constraints: PolicyConstraint[];
  enabled: boolean;
  lastModified: Date;
}

export interface PolicyTrigger {
  id: string;
  name: string;
  condition: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cooldown: number; // minutes
  enabled: boolean;
}

export interface PolicyAction {
  id: string;
  name: string;
  type: 'failover' | 'scale' | 'notify' | 'maintenance';
  parameters: Record<string, any>;
  order: number;
  timeout: number; // seconds
  enabled: boolean;
}

export interface PolicyConstraint {
  id: string;
  name: string;
  type: 'time' | 'resource' | 'dependency' | 'business';
  condition: string;
  enabled: boolean;
}

export interface FailoverHistory {
  id: string;
  region: string;
  trigger: string;
  status: 'success' | 'failure' | 'partial';
  startTime: Date;
  endTime: Date;
  duration: number; // seconds
  steps: HistoryStep[];
  metrics: HistoryMetrics;
  businessImpact: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
}

export interface HistoryStep {
  id: string;
  name: string;
  status: 'success' | 'failure' | 'skipped';
  startTime: Date;
  endTime: Date;
  duration: number; // seconds
  errorMessage?: string;
  details?: Record<string, any>;
}

export interface HistoryMetrics {
  totalDuration: number; // seconds
  stepsCompleted: number;
  stepsFailed: number;
  successRate: number;
  downtime: number; // seconds
  dataLoss: number; // bytes
  cost: number; // USD
}

export interface QuantumFailoverOrchestrator {
  // Health monitoring
  getHealthMetrics(region: string): Promise<HealthMetrics>;
  getAllRegionsHealth(): Promise<RegionStatus[]>;
  getServiceHealth(service: string, region?: string): Promise<ServiceStatus[]>;
  
  // Failure prediction
  predictFailures(region: string): Promise<FailurePrediction[]>;
  getAllFailurePredictions(): Promise<FailurePrediction[]>;
  getFailureHistory(region: string, days: number): Promise<FailoverHistory[]>;
  
  // Failover planning
  createFailoverPlan(plan: Omit<FailoverPlan, 'id'>): Promise<FailoverPlan>;
  updateFailoverPlan(planId: string, updates: Partial<FailoverPlan>): Promise<FailoverPlan>;
  deleteFailoverPlan(planId: string): Promise<void>;
  getFailoverPlans(): Promise<FailoverPlan[]>;
  getFailoverPlan(planId: string): Promise<FailoverPlan | null>;
  
  // Failover execution
  executeFailover(planId: string, region: string, reason: string): Promise<FailoverExecution>;
  getFailoverExecution(executionId: string): Promise<FailoverExecution | null>;
  cancelFailoverExecution(executionId: string): Promise<void>;
  getActiveFailovers(): Promise<FailoverExecution[]>;
  
  // Policy management
  createFailoverPolicy(policy: Omit<FailoverPolicy, 'id'>): Promise<FailoverPolicy>;
  updateFailoverPolicy(policyId: string, updates: Partial<FailoverPolicy>): Promise<FailoverPolicy>;
  deleteFailoverPolicy(policyId: string): Promise<void>;
  getFailoverPolicies(): Promise<FailoverPolicy[]>;
  getFailoverPolicy(policyId: string): Promise<FailoverPolicy | null>;
  
  // Testing and validation
  testFailoverPlan(planId: string, region: string): Promise<FailoverExecution>;
  validateFailoverPlan(planId: string): Promise<{
    valid: boolean;
    errors: string[];
    warnings: string[];
  }>;
  
  // Monitoring and alerting
  getAlerts(region?: string, severity?: string): Promise<Alert[]>;
  acknowledgeAlert(alertId: string): Promise<void>;
  resolveAlert(alertId: string): Promise<void>;
  
  // Analytics and reporting
  getFailoverAnalytics(region: string, days: number): Promise<{
    totalFailovers: number;
    successRate: number;
    averageDuration: number;
    businessImpact: Record<string, number>;
    trends: Record<string, number[]>;
  }>;
  
  getHealthTrends(region: string, days: number): Promise<{
    availability: number[];
    latency: number[];
    errorRate: number[];
    throughput: number[];
    timestamps: Date[];
  }>;
  
  // Configuration
  updateConfiguration(config: Record<string, any>): Promise<void>;
  getConfiguration(): Promise<Record<string, any>>;
  
  // Maintenance
  startMaintenance(region: string, duration: number): Promise<void>;
  endMaintenance(region: string): Promise<void>;
  getMaintenanceSchedule(): Promise<Array<{
    region: string;
    startTime: Date;
    endTime: Date;
    description: string;
  }>>;
}

