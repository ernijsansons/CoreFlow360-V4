import {
  OnboardingFlow,
  OnboardingStep,
  OnboardingMetadata,
  DemoEnvironment,
  AIAssistantConfig,
  SuccessCriteria
} from '../types/index';
import { DemoEnvironmentManager } from '../demo/DemoEnvironmentManager';
import { OnboardingAIAssistant } from '../ai-assistant/OnboardingAIAssistant';
import { CustomerSuccessManager } from '../success/CustomerSuccessManager';
import { ProgressTracker } from '../analytics/ProgressTracker';

export class CustomerOnboardingEngine {
  private demoManager: DemoEnvironmentManager;
  private aiAssistant: OnboardingAIAssistant;
  private successManager: CustomerSuccessManager;
  private progressTracker: ProgressTracker;
  private activeFlows = new Map<string, OnboardingFlow>();

  constructor() {
    this.demoManager = new DemoEnvironmentManager();
    this.successManager = new CustomerSuccessManager();
    this.progressTracker = new ProgressTracker();

    // Default AI configuration
    const aiConfig: AIAssistantConfig = {
      enabled: true,
      personality: 'FRIENDLY',
      features: [
        { type: 'CHAT', enabled: true, config: {} },
        { type: 'SUGGESTIONS', enabled: true, config: {} },
        { type: 'AUTO_COMPLETE', enabled: true, config: {} },
        { type: 'ERROR_HELP', enabled: true, config: {} },
        { type: 'BEST_PRACTICES', enabled: true, config: {} }
      ],
      contextualHelp: true,
      proactiveGuidance: true,
      voiceEnabled: false
    };

    this.aiAssistant = new OnboardingAIAssistant(aiConfig);
  }

  async createOnboardingFlow(customerId: string, customerData: {
    customerType: 'SMB' | 'ENTERPRISE' | 'STARTUP';
    industry: string;
    metadata: OnboardingMetadata;
  }): Promise<OnboardingFlow> {

    // Generate onboarding steps based on customer profile
    const steps = await this.generateOnboardingSteps(customerData);

    // Create onboarding flow
    const onboardingFlow: OnboardingFlow = {
      id: this.generateFlowId(),
      customerId,
      customerType: customerData.customerType,
      industry: customerData.industry,
      currentStep: steps[0] || { id: 'step-1', name: 'Initial Setup', title: 'Initial Setup', description: 'Getting started', type: 'SETUP', status: 'PENDING', order: 1, estimatedTime:
  10, requirements: [], aiGuidance: { tips: [], commonMistakes: [], bestPractices: [], troubleshooting: [], contextualHelp: [] }, components: [], successCriteria: { required: [], optional: [], validation: [] } },
      steps,
      progress: 0,
      status: 'NOT_STARTED',
      startedAt: new Date(),
      aiAssistant: {
        enabled: true,
        personality: this.selectPersonality(customerData.metadata),
        features: this.configureAIFeatures(customerData.customerType),
        contextualHelp: true,
        proactiveGuidance: true,
        voiceEnabled: customerData.metadata.techExperience === 'EXPERT'
      },
      metadata: customerData.metadata
    };

    // Setup demo environment
    await this.setupDemoEnvironment({
      customerId,
      preloadedData: true,
      guidedTours: true,
      aiAssistant: true,
      videoTutorials: true
    });

    // Initialize AI assistant
    await this.aiAssistant.initializeAssistant(customerId, onboardingFlow);

    // Setup customer success tracking
    await this.setupCustomerSuccess({
      customerId,
      onboardingSteps: steps.map((s: any) => s.name),
      aiCoaching: true,
      progressTracking: true,
      certificationProgram: customerData.customerType === 'ENTERPRISE'
    });

    // Store the flow
    this.activeFlows.set(customerId, onboardingFlow);


    return onboardingFlow;
  }

  private async generateOnboardingSteps(customerData: any): Promise<OnboardingStep[]> {
    const baseSteps = [
      'Account Creation',
      'Business Setup',
      'Team Invites',
      'Data Import',
      'First Workflow',
      'Go Live'
    ];

    const steps: OnboardingStep[] = [];

    for (let i = 0; i < baseSteps.length; i++) {
      const stepName = baseSteps[i];
      if (stepName) {
        const step = await this.createStep(stepName, i + 1, customerData);
        steps.push(step);
      }
    }

    // Add industry-specific steps
    const industrySteps = await this.getIndustrySpecificSteps(customerData.industry);
    steps.push(...industrySteps);

    // Add enterprise-specific steps
    if (customerData.customerType === 'ENTERPRISE') {
      const enterpriseSteps = await this.getEnterpriseSteps();
      steps.push(...enterpriseSteps);
    }

    return steps;
  }

  private async createStep(stepName: string, order: number, customerData: any): Promise<OnboardingStep> {
    const stepConfigs = {
      'Account Creation': {
        title: 'Welcome! Let\'s Set Up Your Account',
        description: 'Complete your profile and security settings to get started with CoreFlow360.',
        type: 'SETUP' as const,
        estimatedTime: 10,
        requirements: ['Valid email address', 'Company information'],
        components: [
          {
            type: 'FORM' as const,
            config: {
              formSchema: {
                companyName: { type: 'string', required: true },
                website: { type: 'url', required: false },
                phone: { type: 'phone', required: true },
                address: { type: 'address', required: true }
              }
            },
            required: true,
            order: 1
          },
          {
            type: 'VIDEO' as const,
            config: {
              videoUrl: '/videos/account-setup-welcome.mp4'
            },
            required: false,
            order: 2
          }
        ]
      },
      'Business Setup': {
        title: 'Configure Your Business Settings',
        description: 'Set up your business structure, fiscal year, and core preferences.',
        type: 'CONFIGURATION' as const,
        estimatedTime: 20,
        requirements: ['Business structure decision', 'Fiscal year information'],
        components: [
          {
            type: 'INTERACTIVE_DEMO' as const,
            config: {
              demoScenario: customerData.industry === 'retail' ? 'retail-startup' : 'manufacturing-workflow'
            },
            required: true,
            order: 1
          },
          {
            type: 'CHECKLIST' as const,
            config: {
              checklistItems: [
                'Select business type',
                'Set fiscal year dates',
                'Configure tax settings',
                'Set up chart of accounts'
              ]
            },
            required: true,
            order: 2
          }
        ]
      },
      'Team Invites': {
        title: 'Invite Your Team Members',
        description: 'Add team members and set up their roles and permissions.',
        type: 'SETUP' as const,
        estimatedTime: 15,
        requirements: ['Team member email addresses', 'Role definitions'],
        components: [
          {
            type: 'FORM' as const,
            config: {
              formSchema: {
                teamMembers: {
                  type: 'array',
                  items: {
                    email: { type: 'email', required: true },
                    role: { type: 'select', options: ['Admin', 'Manager', 'User'], required: true },
                    department: { type: 'string', required: false }
                  }
                }
              }
            },
            required: true,
            order: 1
          },
          {
            type: 'TUTORIAL' as const,
            config: {
              tutorialSteps: [
                {
                  id: 'step1',
                  title: 'Access Team Management',
                  description: 'Navigate to the team management section',
                  selector: '[data-tour="team-management"]',
                  position: 'bottom' as const,
                  action: 'click' as const,
                  content: 'Click here to manage your team members'
                }
              ]
            },
            required: false,
            order: 2
          }
        ]
      },
      'Data Import': {
        title: 'Import Your Existing Data',
        description: 'Bring in your customers, products, and transaction history.',
        type: 'DATA_IMPORT' as const,
        estimatedTime: 30,
        requirements: ['Existing data files', 'Data mapping decisions'],
        components: [
          {
            type: 'INTERACTIVE_DEMO' as const,
            config: {
              demoScenario: 'data-import-wizard'
            },
            required: true,
            order: 1
          },
          {
            type: 'CHECKLIST' as const,
            config: {
              checklistItems: [
                'Download data templates',
                'Prepare customer data',
                'Prepare product data',
                'Import and validate data',
                'Review import results'
              ]
            },
            required: true,
            order: 2
          }
        ]
      },
      'First Workflow': {
        title: 'Create Your First Automated Workflow',
        description: 'Build a workflow to automate a common business process.',
        type: 'TUTORIAL' as const,
        estimatedTime: 25,
        requirements: ['Business process to automate', 'Workflow design understanding'],
        components: [
          {
            type: 'INTERACTIVE_DEMO' as const,
            config: {
              demoScenario: customerData.industry === 'services' ? 'services-automation' : 'retail-startup'
            },
            required: true,
            order: 1
          },
          {
            type: 'TUTORIAL' as const,
            config: {
              tutorialSteps: [
                {
                  id: 'workflow1',
                  title: 'Open Workflow Builder',
                  description: 'Access the workflow creation tool',
                  selector: '[data-tour="workflow-builder"]',
                  position: 'right' as const,
                  action: 'click' as const,
                  content: 'Click here to start building workflows'
                },
                {
                  id: 'workflow2',
                  title: 'Choose a Template',
                  description: 'Select from pre-built workflow templates',
                  selector: '[data-tour="workflow-templates"]',
                  position: 'top' as const,
                  action: 'click' as const,
                  content: 'Choose a template that matches your business process'
                }
              ]
            },
            required: true,
            order: 2
          }
        ]
      },
      'Go Live': {
        title: 'Launch Your System',
        description: 'Final checks and go-live preparation for your CoreFlow360 system.',
        type: 'VERIFICATION' as const,
        estimatedTime: 20,
        requirements: ['All previous steps completed', 'Final verification checklist'],
        components: [
          {
            type: 'CHECKLIST' as const,
            config: {
              checklistItems: [
                'Verify all data is imported correctly',
                'Test key workflows',
                'Confirm team access',
                'Set up notifications',
                'Schedule training sessions',
                'Plan go-live communication'
              ]
            },
            required: true,
            order: 1
          },
          {
            type: 'QUIZ' as const,
            config: {
              quizQuestions: [
                {
                  id: 'q1',
                  question: 'What should you do if a workflow fails to execute?',
                  type: 'MULTIPLE_CHOICE' as const,
                  options: [
                    'Check the workflow logs',
                    'Restart the entire system',
                    'Delete and recreate the workflow',
                    'Contact support immediately'
                  ],
                  correctAnswer: 'Check the workflow logs',
                  explanation: 'Always check workflow logs first to understand what went wrong.',
                  points: 10
                }
              ]
            },
            required: true,
            order: 2
          }
        ]
      }
    };

    const config = stepConfigs[stepName as keyof typeof stepConfigs];

    return {
      id: `step-${order}`,
      name: stepName,
      title: config.title,
      description: config.description,
      type: config.type,
      order,
      status: 'PENDING',
      estimatedTime: config.estimatedTime,
      requirements: config.requirements,
      components: config.components,
      aiGuidance: await this.generateAIGuidance(stepName, customerData),
      successCriteria: await this.generateSuccessCriteria(stepName)
    };
  }

  private async getIndustrySpecificSteps(industry: string): Promise<OnboardingStep[]> {
    const industrySteps: Record<string, OnboardingStep[]> = {
      retail: [
        {
          id: 'retail-pos',
          name: 'POS Integration',
          title: 'Connect Your Point of Sale',
          description: 'Integrate your POS system for real-time sales data.',
          type: 'SETUP',
          order: 7,
          status: 'PENDING',
          estimatedTime: 15,
          requirements: ['POS system credentials'],
          components: [],
          aiGuidance: {
            tips: ['Ensure POS system is compatible'],
            commonMistakes: ['Wrong API credentials'],
            bestPractices: ['Test with small transaction first'],
            troubleshooting: [],
            contextualHelp: []
          },
          successCriteria: {
            required:
  [{ id: 'pos-connected', description: 'POS system connected', type: 'COMPLETION', threshold: 1, unit: 'connection' }],
            optional: [],
            validation: []
          }
        }
      ],
      manufacturing: [
        {
          id: 'mfg-bom',
          name: 'Bill of Materials Setup',
          title: 'Configure Your Manufacturing BOMs',
          description: 'Set up bill of materials for your products.',
          type: 'CONFIGURATION',
          order: 7,
          status: 'PENDING',
          estimatedTime: 25,
          requirements: ['Product specifications', 'Component lists'],
          components: [],
          aiGuidance: {
            tips: ['Start with simple products first'],
            commonMistakes: ['Incomplete component lists'],
            bestPractices: ['Include alternate components'],
            troubleshooting: [],
            contextualHelp: []
          },
          successCriteria: {
            required:
  [{ id: 'bom-created', description: 'BOM created', type: 'COMPLETION', threshold: 1, unit: 'bom' }],
            optional: [],
            validation: []
          }
        }
      ]
    };

    return industrySteps[industry] || [];
  }

  private async getEnterpriseSteps(): Promise<OnboardingStep[]> {
    return [
      {
        id: 'enterprise-sso',
        name: 'SSO Configuration',
        title: 'Configure Single Sign-On',
        description: 'Set up enterprise SSO for secure team access.',
        type: 'SETUP',
        order: 10,
        status: 'PENDING',
        estimatedTime: 30,
        requirements: ['IT team coordination', 'SSO provider details'],
        components: [],
        aiGuidance: {
          tips: ['Work with IT team for SSO setup'],
          commonMistakes: ['Incorrect SAML configuration'],
          bestPractices: ['Test with limited users first'],
          troubleshooting: [],
          contextualHelp: []
        },
        successCriteria: {
          required: [{
  id: 'sso-configured', description: 'SSO configured', type: 'COMPLETION', threshold: 1, unit: 'configuration' }],
          optional: [],
          validation: []
        }
      }
    ];
  }

  private async generateAIGuidance(stepName: string, _customerData: any): Promise<any> {
    const guidanceMap: Record<string, any> = {
      'Account Creation': {
        tips: [
          'Use your primary business email for better communication',
          'Complete all fields for a personalized experience',
          'Enable two-factor authentication for security'
        ],
        commonMistakes: [
          'Using personal email instead of business email',
          'Skipping optional fields that help with customization'
        ],
        bestPractices: [
          'Add a professional profile photo',
          'Provide accurate business information for compliance'
        ],
        troubleshooting: [],
        contextualHelp: []
      },
      'Business Setup': {
        tips: [
          'Choose the business type that matches your legal structure',
          'Set fiscal year to match your accounting practices',
          'Use the industry template for faster setup'
        ],
        commonMistakes: [
          'Selecting wrong business type',
          'Mismatched fiscal year dates'
        ],
        bestPractices: [
          'Consult with your accountant on chart of accounts',
          'Set up tax rates based on your locations'
        ],
        troubleshooting: [],
        contextualHelp: []
      }
    };

    return guidanceMap[stepName] || {
      tips: ['Take your time with this step'],
      commonMistakes: [],
      bestPractices: ['Follow the guided instructions'],
      troubleshooting: [],
      contextualHelp: []
    };
  }

  private async generateSuccessCriteria(stepName: string): Promise<SuccessCriteria> {
    const criteriaMap: Record<string, SuccessCriteria> = {
      'Account Creation': {
        required: [
          { id:
  'profile-complete', description: 'Profile 100% complete', type: 'COMPLETION', threshold: 100, unit: 'percent' },
          {
  id: 'email-verified', description: 'Email verified', type: 'COMPLETION', threshold: 1, unit: 'verification' }
        ],
        optional: [
          { id:
  'photo-uploaded', description: 'Profile photo uploaded', type: 'COMPLETION', threshold: 1, unit: 'upload' }
        ],
        validation: [
          { field: 'email', rule: 'email_format', message: 'Please enter a valid email address', severity: 'ERROR' },
          { field: 'companyName', rule: 'required', message: 'Company name is required', severity: 'ERROR' }
        ]
      },
      'Business Setup': {
        required: [
          { id:
  'business-type-selected', description: 'Business type selected', type: 'COMPLETION', threshold: 1, unit: 'selection' },
          { id:
  'fiscal-year-set', description: 'Fiscal year configured', type: 'COMPLETION', threshold: 1, unit: 'configuration' }
        ],
        optional: [
          { id:
  'chart-accounts-customized', description: 'Chart of accounts customized', type: 'COMPLETION', threshold: 1, unit: 'customization' }
        ],
        validation: []
      }
    };

    return criteriaMap[stepName] || {
      required: [{ id: 'step-completed',
  description: 'Step completed', type: 'COMPLETION', threshold: 1, unit: 'step' }],
      optional: [],
      validation: []
    };
  }

  private selectPersonality(metadata: OnboardingMetadata): 'FRIENDLY' | 'PROFESSIONAL' | 'EXPERT' | 'CASUAL' {
    if (metadata.techExperience === 'EXPERT') return 'EXPERT';
    if (metadata.techExperience === 'ADVANCED') return 'PROFESSIONAL';
    if (metadata.urgency === 'HIGH' || metadata.urgency === 'URGENT') return 'PROFESSIONAL';
    return 'FRIENDLY';
  }

  private configureAIFeatures(customerType: 'SMB' | 'ENTERPRISE' | 'STARTUP'): any[] {
    const baseFeatures = [
      { type: 'CHAT', enabled: true, config: {} },
      { type: 'SUGGESTIONS', enabled: true, config: {} },
      { type: 'ERROR_HELP', enabled: true, config: {} }
    ];

    if (customerType === 'ENTERPRISE') {
      baseFeatures.push(
        { type: 'VOICE', enabled: true, config: {} },
        { type: 'AUTO_COMPLETE', enabled: true, config: {} },
        { type: 'BEST_PRACTICES', enabled: true, config: {} }
      );
    }

    return baseFeatures;
  }

  private async setupDemoEnvironment(config: {
    customerId: string;
    preloadedData: boolean;
    guidedTours: boolean;
    aiAssistant: boolean;
    videoTutorials: boolean;
  }): Promise<DemoEnvironment> {
    return await this.demoManager.setupDemoEnvironment(config.customerId, {
      preloadedData: config.preloadedData,
      guidedTours: config.guidedTours,
      aiAssistant: config.aiAssistant,
      videoTutorials: config.videoTutorials
    });
  }

  private async setupCustomerSuccess(config: {
    customerId: string;
    onboardingSteps: string[];
    aiCoaching: boolean;
    progressTracking: boolean;
    certificationProgram: boolean;
  }): Promise<void> {
    await this.successManager.initializeCustomer(config.customerId, {
      onboardingSteps: config.onboardingSteps,
      aiCoaching: config.aiCoaching,
      progressTracking: config.progressTracking,
      certificationProgram: config.certificationProgram
    });

    await this.progressTracker.initializeTracking(config.customerId, config.onboardingSteps);
  }

  async startOnboarding(customerId: string): Promise<OnboardingFlow> {
    const flow = this.activeFlows.get(customerId);
    if (!flow) {
      throw new Error(`No onboarding flow found for customer ${customerId}`);
    }

    flow.status = 'IN_PROGRESS';
    flow.currentStep.status = 'IN_PROGRESS';
    flow.currentStep.startedAt = new Date();


    return flow;
  }

  async completeStep(customerId: string, stepId: string, completionData: any): Promise<{
    success: boolean;
    nextStep?: OnboardingStep;
    message: string;
  }> {
    const flow = this.activeFlows.get(customerId);
    if (!flow) {
      throw new Error(`No onboarding flow found for customer ${customerId}`);
    }

    const step = flow.steps.find(s => s.id === stepId);
    if (!step) {
      throw new Error(`Step ${stepId} not found`);
    }

    // Validate completion data against success criteria
    const validation = await this.validateStepCompletion(step, completionData);

    if (!validation.success) {
      return {
        success: false,
        message: `Step validation failed: ${validation.errors.join(', ')}`
      };
    }

    // Mark step as completed
    step.status = 'COMPLETED';
    step.completedAt = new Date();
    step.actualTime = step.startedAt
      ? Math.round((Date.now() - step.startedAt.getTime()) / 60000)
      : step.estimatedTime;

    // Update progress
    const completedSteps = flow.steps.filter((s: any) => s.status === 'COMPLETED').length;
    flow.progress = Math.round((completedSteps / flow.steps.length) * 100);

    // Move to next step
    const currentIndex = flow.steps.findIndex(s => s.id === stepId);
    const nextStep = currentIndex < flow.steps.length - 1 ? flow.steps[currentIndex + 1] : undefined;

    if (nextStep) {
      flow.currentStep = nextStep;
      nextStep.status = 'IN_PROGRESS';
      nextStep.startedAt = new Date();
    } else {
      // Onboarding completed
      flow.status = 'COMPLETED';
      flow.completedAt = new Date();
    }

    // Update tracking
    await this.progressTracker.updateStepProgress(customerId, stepId, {
      completed: true,
      timeSpent: step.actualTime || 0,
      completionData
    });

    if (nextStep) {
    } else {
    }

    return {
      success: true,
      ...(nextStep && { nextStep }),
      message: nextStep
        ? `Great! Moving on to: ${nextStep.name}`
        : 'Congratulations! You\'ve completed your onboarding!'
    };
  }

  private async validateStepCompletion(step: OnboardingStep, data: any): Promise<{
    success: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    // Check required criteria
    for (const criterion of step.successCriteria.required) {
      const isValid = await this.validateCriterion(criterion, data);
      if (!isValid) {
        errors.push(`Required: ${criterion.description}`);
      }
    }

    // Validate form data
    for (const validation of step.successCriteria.validation) {
      const isValid = await this.validateField(validation, data);
      if (!isValid) {
        errors.push(validation.message);
      }
    }

    return {
      success: errors.length === 0,
      errors
    };
  }

  private async validateCriterion(criterion: any, data: any): Promise<boolean> {
    // Simplified validation - real implementation would be more sophisticated
    switch (criterion.type) {
      case 'COMPLETION':
        return data && data[criterion.id] >= criterion.threshold;
      case 'ACCURACY':
        return data && data.accuracy >= criterion.threshold;
      case 'TIME':
        return data && data.timeSpent <= criterion.threshold;
      default:
        return true;
    }
  }

  private async validateField(validation: any, data: any): Promise<boolean> {
    const fieldValue = data[validation.field];

    switch (validation.rule) {
      case 'required':
        return fieldValue !== undefined && fieldValue !== null && fieldValue !== '';
      case 'email_format':
        return typeof fieldValue === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fieldValue);
      default:
        return true;
    }
  }

  async getOnboardingStatus(customerId: string): Promise<OnboardingFlow | null> {
    return this.activeFlows.get(customerId) || null;
  }

  async getOnboardingAnalytics(customerId: string): Promise<{
    overallProgress: number;
    currentStep: string;
    timeSpent: number;
    estimatedTimeRemaining: number;
    completionRate: number;
    stuckPoints: string[];
  }> {
    const flow = this.activeFlows.get(customerId);
    if (!flow) {
      return {
        overallProgress: 0,
        currentStep: 'Not Started',
        timeSpent: 0,
        estimatedTimeRemaining: 0,
        completionRate: 0,
        stuckPoints: []
      };
    }

    const completedSteps = flow.steps.filter((s: any) => s.status === 'COMPLETED');
    const totalTimeSpent = completedSteps.reduce((sum, step) => sum + (step.actualTime || 0), 0);
    const remainingSteps = flow.steps.filter((s: any) => s.status === 'PENDING');
    const estimatedTimeRemaining = remainingSteps.reduce((sum, step) => sum + step.estimatedTime, 0);

    return {
      overallProgress: flow.progress,
      currentStep: flow.currentStep.name,
      timeSpent: totalTimeSpent,
      estimatedTimeRemaining,
      completionRate: completedSteps.length / flow.steps.length,
      stuckPoints: [] // Would analyze where users typically get stuck
    };
  }

  private generateFlowId(): string {
    return `flow-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Public getters for monitoring
  getActiveFlows(): Map<string, OnboardingFlow> {
    return new Map(this.activeFlows);
  }

  getDemoManager(): DemoEnvironmentManager {
    return this.demoManager;
  }

  getAIAssistant(): OnboardingAIAssistant {
    return this.aiAssistant;
  }
}