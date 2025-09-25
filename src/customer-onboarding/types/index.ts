export interface OnboardingFlow {
  id: string;
  customerId: string;
  customerType: 'SMB' | 'ENTERPRISE' | 'STARTUP';
  industry: string;
  currentStep: OnboardingStep;
  steps: OnboardingStep[];
  progress: number;
  status: 'NOT_STARTED' | 'IN_PROGRESS' | 'COMPLETED' | 'PAUSED' | 'FAILED';
  startedAt: Date;
  completedAt?: Date;
  aiAssistant: AIAssistantConfig;
  metadata: OnboardingMetadata;
}

export interface OnboardingStep {
  id: string;
  name: string;
  title: string;
  description: string;
  type: 'TUTORIAL' | 'SETUP' | 'DATA_IMPORT' | 'CONFIGURATION' | 'VERIFICATION' | 'CERTIFICATION';
  order: number;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'SKIPPED' | 'FAILED';
  estimatedTime: number; // minutes
  actualTime?: number;
  requirements: string[];
  components: StepComponent[];
  aiGuidance: AIGuidance;
  successCriteria: SuccessCriteria;
  startedAt?: Date;
  completedAt?: Date;
}

export interface StepComponent {
  type: 'VIDEO' | 'INTERACTIVE_DEMO' | 'FORM' | 'CHECKLIST' | 'TUTORIAL' | 'QUIZ' | 'LIVE_DEMO';
  config: ComponentConfig;
  required: boolean;
  order: number;
}

export interface ComponentConfig {
  [key: string]: any;
  videoUrl?: string;
  demoScenario?: string;
  formSchema?: object;
  checklistItems?: string[];
  tutorialSteps?: TutorialStep[];
  quizQuestions?: QuizQuestion[];
}

export interface TutorialStep {
  id: string;
  title: string;
  description: string;
  selector?: string;
  position: 'top' | 'bottom' | 'left' | 'right';
  action?: 'click' | 'type' | 'hover' | 'scroll';
  content: string;
  screenshot?: string;
}

export interface QuizQuestion {
  id: string;
  question: string;
  type: 'MULTIPLE_CHOICE' | 'TRUE_FALSE' | 'TEXT' | 'DRAG_DROP';
  options?: string[];
  correctAnswer: string | string[];
  explanation: string;
  points: number;
}

export interface AIAssistantConfig {
  enabled: boolean;
  personality: 'FRIENDLY' | 'PROFESSIONAL' | 'EXPERT' | 'CASUAL';
  features: AIFeature[];
  contextualHelp: boolean;
  proactiveGuidance: boolean;
  voiceEnabled: boolean;
}

export interface AIFeature {
  type: 'CHAT' | 'VOICE' | 'SUGGESTIONS' | 'AUTO_COMPLETE' | 'ERROR_HELP' | 'BEST_PRACTICES';
  enabled: boolean;
  config: Record<string, any>;
}

export interface AIGuidance {
  tips: string[];
  commonMistakes: string[];
  bestPractices: string[];
  troubleshooting: TroubleshootingGuide[];
  contextualHelp: ContextualHelp[];
}

export interface TroubleshootingGuide {
  issue: string;
  symptoms: string[];
  solutions: string[];
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface ContextualHelp {
  trigger: string;
  content: string;
  type: 'TIP' | 'WARNING' | 'INFO' | 'ERROR';
  showCondition: string;
}

export interface SuccessCriteria {
  required: Criterion[];
  optional: Criterion[];
  validation: ValidationRule[];
}

export interface Criterion {
  id: string;
  description: string;
  type: 'COMPLETION' | 'ACCURACY' | 'TIME' | 'QUALITY' | 'UNDERSTANDING';
  threshold: number;
  unit: string;
}

export interface ValidationRule {
  field: string;
  rule: string;
  message: string;
  severity: 'ERROR' | 'WARNING' | 'INFO';
}

export interface OnboardingMetadata {
  referralSource: string;
  expectedUseCase: string;
  teamSize: number;
  businessGoals: string[];
  techExperience: 'BEGINNER' | 'INTERMEDIATE' | 'ADVANCED' | 'EXPERT';
  urgency: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
  budget: string;
  timeline: string;
}

export interface DemoEnvironment {
  id: string;
  customerId: string;
  type: 'SANDBOX' | 'GUIDED_DEMO' | 'LIVE_ENVIRONMENT';
  features: DemoFeature[];
  preloadedData: DemoData;
  restrictions: DemoRestriction[];
  expirationDate: Date;
  accessCount: number;
  maxAccess: number;
}

export interface DemoFeature {
  module: string;
  enabled: boolean;
  limitedMode: boolean;
  customization: Record<string, any>;
}

export interface DemoData {
  customers: number;
  orders: number;
  products: number;
  invoices: number;
  transactions: number;
  workflows: number;
  reports: string[];
  scenarios: DemoScenario[];
}

export interface DemoScenario {
  id: string;
  name: string;
  description: string;
  industry: string;
  complexity: 'SIMPLE' | 'INTERMEDIATE' | 'ADVANCED';
  duration: number; // minutes
  objectives: string[];
  steps: DemoStep[];
}

export interface DemoStep {
  id: string;
  title: string;
  description: string;
  action: string;
  expectedResult: string;
  hints: string[];
  validation: string;
}

export interface DemoRestriction {
  type: 'TIME_LIMIT' | 'ACTION_LIMIT' | 'DATA_LIMIT' | 'FEATURE_LIMIT';
  value: number;
  description: string;
}

export interface CustomerSuccess {
  customerId: string;
  csmAssigned: string;
  healthScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  engagementLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  onboardingProgress: number;
  adoptionMetrics: AdoptionMetrics;
  touchpoints: Touchpoint[];
  goals: CustomerGoal[];
  initiatives: Initiative[];
}

export interface AdoptionMetrics {
  loginFrequency: number;
  featureUsage: Record<string, number>;
  workflowsCreated: number;
  dataImported: boolean;
  teamMembersActive: number;
  supportTickets: number;
  timeToValue: number; // days
}

export interface Touchpoint {
  id: string;
  type: 'EMAIL' | 'CALL' | 'VIDEO' | 'CHAT' | 'IN_APP' | 'WEBINAR';
  date: Date;
  purpose: string;
  outcome: string;
  nextAction: string;
  sentiment: 'POSITIVE' | 'NEUTRAL' | 'NEGATIVE';
  notes: string;
}

export interface CustomerGoal {
  id: string;
  description: string;
  category: 'EFFICIENCY' | 'COST_REDUCTION' | 'GROWTH' | 'COMPLIANCE' | 'INNOVATION';
  targetDate: Date;
  progress: number;
  metrics: GoalMetric[];
  status: 'NOT_STARTED' | 'IN_PROGRESS' | 'ACHIEVED' | 'AT_RISK' | 'MISSED';
}

export interface GoalMetric {
  name: string;
  currentValue: number;
  targetValue: number;
  unit: string;
  trend: 'UP' | 'DOWN' | 'STABLE';
}

export interface Initiative {
  id: string;
  name: string;
  description: string;
  type: 'TRAINING' | 'IMPLEMENTATION' | 'OPTIMIZATION' | 'EXPANSION';
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'PLANNED' | 'IN_PROGRESS' | 'COMPLETED' | 'PAUSED' | 'CANCELLED';
  startDate: Date;
  endDate: Date;
  owner: string;
  progress: number;
  deliverables: Deliverable[];
}

export interface Deliverable {
  id: string;
  name: string;
  description: string;
  dueDate: Date;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'OVERDUE';
  assignee: string;
}

export interface ProgressTracking {
  customerId: string;
  onboardingId: string;
  overallProgress: number;
  stepProgress: StepProgress[];
  timeSpent: number; // minutes
  completionRate: number;
  engagementScore: number;
  learningVelocity: number;
  blockers: Blocker[];
  achievements: Achievement[];
  analytics: OnboardingAnalytics;
}

export interface StepProgress {
  stepId: string;
  progress: number;
  timeSpent: number;
  attempts: number;
  errors: Error[];
  helpRequests: number;
  status: OnboardingStep['status'];
}

export interface Blocker {
  id: string;
  type: 'TECHNICAL' | 'PROCESS' | 'DATA' | 'TRAINING' | 'RESOURCE';
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  detectedAt: Date;
  resolvedAt?: Date;
  resolution?: string;
  impact: string;
}

export interface Achievement {
  id: string;
  title: string;
  description: string;
  type: 'MILESTONE' | 'SKILL' | 'SPEED' | 'QUALITY' | 'INNOVATION';
  earnedAt: Date;
  points: number;
  badge: string;
  shareWorthy: boolean;
}

export interface OnboardingAnalytics {
  startDate: Date;
  currentDate: Date;
  expectedCompletion: Date;
  actualCompletion?: Date;
  benchmarkComparison: BenchmarkData;
  usagePatterns: UsagePattern[];
  performanceMetrics: PerformanceMetric[];
  predictionModels: PredictionModel[];
}

export interface BenchmarkData {
  industryAverage: number;
  companySize: string;
  completionTime: number;
  adoptionRate: number;
  satisfactionScore: number;
}

export interface UsagePattern {
  feature: string;
  frequency: number;
  duration: number;
  efficiency: number;
  trend: 'INCREASING' | 'DECREASING' | 'STABLE';
}

export interface PerformanceMetric {
  metric: string;
  value: number;
  target: number;
  variance: number;
  trend: 'IMPROVING' | 'DECLINING' | 'STABLE';
}

export interface PredictionModel {
  type: 'COMPLETION_TIME' | 'SUCCESS_PROBABILITY' | 'CHURN_RISK' | 'EXPANSION_OPPORTUNITY';
  prediction: number;
  confidence: number;
  factors: PredictionFactor[];
}

export interface PredictionFactor {
  factor: string;
  weight: number;
  impact: 'POSITIVE' | 'NEGATIVE' | 'NEUTRAL';
}

export interface CertificationProgram {
  id: string;
  name: string;
  description: string;
  level: 'BASIC' | 'INTERMEDIATE' | 'ADVANCED' | 'EXPERT';
  modules: CertificationModule[];
  requirements: CertificationRequirement[];
  assessment: Assessment;
  badge: CertificationBadge;
  validity: number; // months
  prerequisites: string[];
}

export interface CertificationModule {
  id: string;
  name: string;
  description: string;
  type: 'THEORY' | 'PRACTICAL' | 'PROJECT' | 'ASSESSMENT';
  duration: number; // minutes
  content: ModuleContent[];
  order: number;
  required: boolean;
}

export interface ModuleContent {
  type: 'VIDEO' | 'DOCUMENT' | 'INTERACTIVE' | 'QUIZ' | 'LAB' | 'SIMULATION';
  title: string;
  url: string;
  duration: number;
  description: string;
}

export interface CertificationRequirement {
  type: 'COMPLETION' | 'SCORE' | 'TIME' | 'PROJECT' | 'PEER_REVIEW';
  description: string;
  threshold: number;
  weight: number;
}

export interface Assessment {
  id: string;
  type: 'QUIZ' | 'PRACTICAL' | 'PROJECT' | 'ORAL' | 'PEER_REVIEW';
  questions: AssessmentQuestion[];
  timeLimit: number; // minutes
  passingScore: number;
  attempts: number;
  proctored: boolean;
}

export interface AssessmentQuestion {
  id: string;
  type: 'MULTIPLE_CHOICE' | 'TRUE_FALSE' | 'ESSAY' | 'PRACTICAL' | 'SIMULATION';
  question: string;
  options?: string[];
  correctAnswer: any;
  points: number;
  difficulty: 'EASY' | 'MEDIUM' | 'HARD';
  topic: string;
  explanation: string;
}

export interface CertificationBadge {
  id: string;
  name: string;
  description: string;
  imageUrl: string;
  criteria: string[];
  level: string;
  issuer: string;
  verificationUrl: string;
}

export interface GuidedTour {
  id: string;
  name: string;
  description: string;
  type: 'FEATURE_TOUR' | 'WORKFLOW_DEMO' | 'SETUP_GUIDE' | 'BEST_PRACTICES';
  target: 'NEW_USER' | 'FEATURE_LAUNCH' | 'ADVANCED_USER' | 'ADMIN';
  steps: GuidedTourStep[];
  triggers: TourTrigger[];
  settings: TourSettings;
}

export interface GuidedTourStep {
  id: string;
  title: string;
  content: string;
  element: string; // CSS selector
  placement: 'top' | 'bottom' | 'left' | 'right' | 'center';
  action?: 'click' | 'hover' | 'focus' | 'scroll';
  waitFor?: string; // CSS selector or condition
  highlight: boolean;
  skippable: boolean;
  order: number;
}

export interface TourTrigger {
  type: 'PAGE_LOAD' | 'ELEMENT_CLICK' | 'TIME_DELAY' | 'USER_ACTION' | 'MANUAL';
  condition: string;
  priority: number;
}

export interface TourSettings {
  showProgress: boolean;
  allowSkip: boolean;
  showNext: boolean;
  showPrevious: boolean;
  backdrop: boolean;
  highlightClass: string;
  animation: string;
  theme: string;
}

export interface VideoTutorial {
  id: string;
  title: string;
  description: string;
  category: string;
  level: 'BEGINNER' | 'INTERMEDIATE' | 'ADVANCED';
  duration: number; // seconds
  videoUrl: string;
  thumbnailUrl: string;
  transcriptUrl?: string;
  subtitles: Subtitle[];
  chapters: VideoChapter[];
  tags: string[];
  relatedVideos: string[];
  views: number;
  rating: number;
  completionRate: number;
}

export interface Subtitle {
  language: string;
  url: string;
}

export interface VideoChapter {
  title: string;
  startTime: number; // seconds
  endTime: number;
  description: string;
}

export interface OnboardingEvent {
  id: string;
  customerId: string;
  onboardingId: string;
  type: 'STEP_STARTED' | 'STEP_COMPLETED' | 'HELP_REQUESTED' | 'ERROR_OCCURRED' | 'MILESTONE_REACHED';
  timestamp: Date;
  stepId?: string;
  data: Record<string, any>;
  metadata: EventMetadata;
}

export interface EventMetadata {
  userAgent: string;
  ipAddress: string;
  sessionId: string;
  source: 'WEB' | 'MOBILE' | 'API' | 'SYSTEM';
  version: string;
}