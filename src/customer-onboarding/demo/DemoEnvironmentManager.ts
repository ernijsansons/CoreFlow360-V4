import {
  DemoEnvironment,
  DemoFeature,
  DemoData,
  DemoScenario,
  DemoRestriction
} from '../types/index';

export // TODO: Consider splitting DemoEnvironmentManager into smaller, focused classes
class DemoEnvironmentManager {
  private environments = new Map<string, DemoEnvironment>();
  private scenarios = new Map<string, DemoScenario>();

  async setupDemoEnvironment(customerId: string, config: {
    preloadedData: boolean;
    guidedTours: boolean;
    aiAssistant: boolean;
    videoTutorials: boolean;
  }): Promise<DemoEnvironment> {

    const demoId = this.generateDemoId();
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + 30); // 30-day demo

    const demoEnvironment: DemoEnvironment = {
      id: demoId,
      customerId,
      type: 'GUIDED_DEMO',
      features: await this.createDemoFeatures(config),
      preloadedData: await this.generatePreloadedData(),
      restrictions: this.createDemoRestrictions(),
      expirationDate,
      accessCount: 0,
      maxAccess: 100
    };

    this.environments.set(demoId, demoEnvironment);


    return demoEnvironment;
  }

  private async createDemoFeatures(config: any): Promise<DemoFeature[]> {
    const features: DemoFeature[] = [
      {
        module: 'dashboard',
        enabled: true,
        limitedMode: false,
        customization: { theme: 'demo', showHelp: true }
      },
      {
        module: 'finance',
        enabled: true,
        limitedMode: true,
        customization: { maxTransactions: 100, demoData: true }
      },
      {
        module: 'inventory',
        enabled: true,
        limitedMode: true,
        customization: { maxProducts: 50, demoData: true }
      },
      {
        module: 'crm',
        enabled: true,
        limitedMode: true,
        customization: { maxContacts: 25, demoData: true }
      },
      {
        module: 'ai-assistant',
        enabled: config.aiAssistant,
        limitedMode: true,
        customization: {
          maxQueries: 50,
          features: ['chat', 'suggestions', 'help'],
          personality: 'friendly'
        }
      },
      {
        module: 'guided-tours',
        enabled: config.guidedTours,
        limitedMode: false,
        customization: {
          autoStart: true,
          showProgress: true,
          allowSkip: true
        }
      },
      {
        module: 'video-tutorials',
        enabled: config.videoTutorials,
        limitedMode: false,
        customization: {
          autoplay: false,
          showTranscripts: true,
          trackProgress: true
        }
      },
      {
        module: 'reports',
        enabled: true,
        limitedMode: true,
        customization: {
          predefinedReports: true,
          customReports: false,
          exportFormats: ['PDF', 'Excel']
        }
      },
      {
        module: 'workflows',
        enabled: true,
        limitedMode: true,
        customization: {
          maxWorkflows: 10,
          templates: true,
          customWorkflows: true
        }
      }
    ];

    return features;
  }

  private async generatePreloadedData(): Promise<DemoData> {

    const scenarios = await this.createDemoScenarios();

    return {
      customers: 25,
      orders: 150,
      products: 50,
      invoices: 75,
      transactions: 200,
      workflows: 8,
      reports: [
        'Sales Performance Dashboard',
        'Inventory Turnover Report',
        'Customer Acquisition Analysis',
        'Financial Summary',
        'Workflow Efficiency Report'
      ],
      scenarios
    };
  }

  private async createDemoScenarios(): Promise<DemoScenario[]> {
    const scenarios: DemoScenario[] = [
      {
        id: 'retail-startup',
        name: 'Retail Startup Journey',
        description: 'Follow a growing retail business from startup to scale',
        industry: 'Retail',
        complexity: 'SIMPLE',
        duration: 15,
        objectives: [
          'Set up your first product catalog',
          'Process your first order',
          'Generate sales report',
          'Set up inventory alerts'
        ],
        steps: [
          {
            id: 'step1',
            title: 'Add Your First Product',
            description: 'Learn how to add products to your inventory',
            action: 'Navigate to Inventory → Add Product',
            expectedResult: 'Product successfully added to catalog',
            hints: ['Use the quick add form', 'Add product images for better presentation'],
            validation: 'product.count > 0'
          },
          {
            id: 'step2',
            title: 'Create Your First Customer',
            description: 'Add a customer to your CRM system',
            action: 'Go to CRM → Add Customer',
            expectedResult: 'Customer profile created with contact information',
            hints: ['Fill in all required fields', 'Add customer tags for segmentation'],
            validation: 'customer.count > 0'
          },
          {
            id: 'step3',
            title: 'Process Your First Order',
            description: 'Create and process a sales order',
            action: 'Navigate to Sales → New Order',
            expectedResult: 'Order created and marked as fulfilled',
            hints: ['Select existing customer and product', 'Review order total before submitting'],
            validation: 'order.status === "fulfilled"'
          },
          {
            id: 'step4',
            title: 'Generate Sales Report',
            description: 'Create your first sales performance report',
            action: 'Go to Reports → Sales Performance',
            expectedResult: 'Sales report generated showing order data',
            hints: ['Use date filters for specific periods', 'Export report as PDF'],
            validation: 'report.generated === true'
          }
        ]
      },
      {
        id: 'manufacturing-workflow',
        name: 'Manufacturing Efficiency',
        description: 'Optimize production workflows and inventory management',
        industry: 'Manufacturing',
        complexity: 'INTERMEDIATE',
        duration: 25,
        objectives: [
          'Set up bill of materials',
          'Create production workflow',
          'Track work orders',
          'Analyze production efficiency'
        ],
        steps: [
          {
            id: 'mfg1',
            title: 'Create Bill of Materials',
            description: 'Define components needed for your product',
            action: 'Navigate to Manufacturing → BOM → Create',
            expectedResult: 'BOM created with all required components',
            hints: ['Include all raw materials', 'Set accurate quantities'],
            validation: 'bom.components.length > 0'
          },
          {
            id: 'mfg2',
            title: 'Design Production Workflow',
            description: 'Create automated production process',
            action: 'Go to Workflows → Manufacturing → New',
            expectedResult: 'Production workflow with quality checkpoints',
            hints: ['Add quality control steps', 'Set up approval gates'],
            validation: 'workflow.steps.length > 3'
          },
          {
            id: 'mfg3',
            title: 'Create Work Order',
            description: 'Generate work order from customer demand',
            action: 'Manufacturing → Work Orders → Create',
            expectedResult: 'Work order scheduled and assigned',
            hints: ['Check material availability', 'Assign to production team'],
            validation: 'workOrder.status === "scheduled"'
          },
          {
            id: 'mfg4',
            title: 'Track Production Progress',
            description: 'Monitor work order through completion',
            action: 'Track work order status in real-time',
            expectedResult: 'Work order completed with quality metrics',
            hints: ['Update progress at each station', 'Record quality measurements'],
            validation: 'workOrder.status === "completed"'
          }
        ]
      },
      {
        id: 'services-automation',
        name: 'Service Business Automation',
        description: 'Automate service delivery and customer management',
        industry: 'Services',
        complexity: 'ADVANCED',
        duration: 30,
        objectives: [
          'Set up service catalog',
          'Create client onboarding workflow',
          'Automate billing and invoicing',
          'Track customer satisfaction'
        ],
        steps: [
          {
            id: 'svc1',
            title: 'Build Service Catalog',
            description: 'Define your service offerings and pricing',
            action: 'Services → Catalog → Add Services',
            expectedResult: 'Complete service catalog with pricing tiers',
            hints: ['Include service descriptions', 'Set up tiered pricing'],
            validation: 'services.count >= 3'
          },
          {
            id: 'svc2',
            title: 'Design Client Onboarding',
            description: 'Create automated client onboarding process',
            action: 'Workflows → Client Onboarding → Design',
            expectedResult: 'Multi-step onboarding workflow with notifications',
            hints: ['Include welcome email', 'Set up document collection'],
            validation: 'workflow.notifications > 0'
          },
          {
            id: 'svc3',
            title: 'Configure Automated Billing',
            description: 'Set up recurring billing for service contracts',
            action: 'Finance → Billing → Automation Rules',
            expectedResult: 'Automated billing rules for different service types',
            hints: ['Set billing frequencies', 'Configure payment reminders'],
            validation: 'billing.automation.enabled === true'
          },
          {
            id: 'svc4',
            title: 'Implement Satisfaction Tracking',
            description: 'Create customer feedback and NPS tracking',
            action: 'CRM → Satisfaction → Configure Surveys',
            expectedResult: 'Automated satisfaction surveys after service delivery',
            hints: ['Use NPS surveys', 'Set up follow-up workflows'],
            validation: 'surveys.active > 0'
          }
        ]
      }
    ];

    // Store scenarios for later use
    scenarios.forEach((scenario: any) => {
      this.scenarios.set(scenario.id, scenario);
    });

    return scenarios;
  }

  private createDemoRestrictions(): DemoRestriction[] {
    return [
      {
        type: 'TIME_LIMIT',
        value: 30, // 30 days
        description: 'Demo environment expires after 30 days'
      },
      {
        type: 'ACTION_LIMIT',
        value: 1000,
        description: 'Maximum 1000 actions per session'
      },
      {
        type: 'DATA_LIMIT',
        value: 100,
        description: 'Maximum 100 records per entity type'
      },
      {
        type: 'FEATURE_LIMIT',
        value: 80,
        description: 'Access to 80% of platform features'
      }
    ];
  }

  async accessDemoEnvironment(demoId: string, customerId: string): Promise<DemoEnvironment | null> {
    const demo = this.environments.get(demoId);

    if (!demo) {
      return null;
    }

    if (demo.customerId !== customerId) {
      return null;
    }

    if (demo.expirationDate < new Date()) {
      return null;
    }

    if (demo.accessCount >= demo.maxAccess) {
      return null;
    }

    // Increment access count
    demo.accessCount++;
    this.environments.set(demoId, demo);


    return demo;
  }

  async getDemoScenario(scenarioId: string): Promise<DemoScenario | null> {
    return this.scenarios.get(scenarioId) || null;
  }

  async validateDemoStep(scenarioId: string, stepId: string, userAction: any): Promise<{
    valid: boolean;
    feedback: string;
    nextStep?: string;
  }> {
    const scenario = this.scenarios.get(scenarioId);
    if (!scenario) {
      return { valid: false, feedback: 'Scenario not found' };
    }

    const step = scenario.steps.find(s => s.id === stepId);
    if (!step) {
      return { valid: false, feedback: 'Step not found' };
    }

    // Simulate validation logic
    const valid = this.evaluateValidation(step.validation, userAction);

    if (valid) {
      const currentIndex = scenario.steps.findIndex(s => s.id === stepId);
      const nextStep = currentIndex < scenario.steps.length - 1
        ? scenario.steps[currentIndex + 1]?.id
        : undefined;

      return {
        valid: true,
        feedback: `✅ ${step.expectedResult}`,
        ...(nextStep && { nextStep })
      };
    } else {
      return {
        valid: false,
        feedback: `❌ Action did not meet step requirements. ${step.hints.join('. ')}`
      };
    }
  }

  private evaluateValidation(validation: string, userAction: any): boolean {
    // Simplified validation logic - in real implementation, this would be more sophisticated
    try {
      // This is a simplified example - real validation would parse and evaluate the condition
      if (validation.includes('count > 0')) {
        return userAction && userAction.count > 0;
      }
      if (validation.includes('status === "fulfilled"')) {
        return userAction && userAction.status === 'fulfilled';
      }
      if (validation.includes('generated === true')) {
        return userAction && userAction.generated === true;
      }

      // Default to true for demo purposes
      return Math.random() > 0.3; // 70% success rate for demo
    } catch (error: any) {
      return false;
    }
  }

  async extendDemoEnvironment(demoId: string, additionalDays: number): Promise<boolean> {
    const demo = this.environments.get(demoId);
    if (!demo) return false;

    demo.expirationDate.setDate(demo.expirationDate.getDate() + additionalDays);
    this.environments.set(demoId, demo);

    return true;
  }

  async getDemoAnalytics(demoId: string): Promise<{
    accessCount: number;
    completedScenarios: number;
    timeSpent: number;
    engagementScore: number;
    conversionProbability: number;
  }> {
    const demo = this.environments.get(demoId);
    if (!demo) {
      return {
        accessCount: 0,
        completedScenarios: 0,
        timeSpent: 0,
        engagementScore: 0,
        conversionProbability: 0
      };
    }

    // Simulate analytics data
    const analytics = {
      accessCount: demo.accessCount,
      completedScenarios: Math.floor(Math.random() * 3),
      timeSpent: Math.floor(Math.random() * 120) + 30, // 30-150 minutes
      engagementScore: Math.floor(Math.random() * 40) + 60, // 60-100
      conversionProbability: Math.random() * 0.4 + 0.3 // 30-70%
    };

    return analytics;
  }

  async cleanupExpiredDemos(): Promise<number> {
    const now = new Date();
    let cleanedCount = 0;

    for (const [demoId, demo] of this.environments) {
      if (demo.expirationDate < now) {
        this.environments.delete(demoId);
        cleanedCount++;
      }
    }

    return cleanedCount;
  }

  private generateDemoId(): string {
    return `demo-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Public getters for monitoring
  getDemoEnvironments(): Map<string, DemoEnvironment> {
    return new Map(this.environments);
  }

  getDemoScenarios(): Map<string, DemoScenario> {
    return new Map(this.scenarios);
  }
}