import { CustomerSuccess, Touchpoint, CustomerGoal, Initiative } from '../types/index.js';

export // TODO: Consider splitting CustomerSuccessManager into smaller, focused classes
class CustomerSuccessManager {
  private customers = new Map<string, CustomerSuccess>();

  async initializeCustomer(customerId: string, config: {
    onboardingSteps: string[];
    aiCoaching: boolean;
    progressTracking: boolean;
    certificationProgram: boolean;
  }): Promise<void> {

    const customerSuccess: CustomerSuccess = {
      customerId,
      csmAssigned: 'ai-assistant-primary',
      healthScore: 100,
      riskLevel: 'LOW',
      engagementLevel: 'HIGH',
      onboardingProgress: 0,
      adoptionMetrics: {
        loginFrequency: 0,
        featureUsage: {},
        workflowsCreated: 0,
        dataImported: false,
        teamMembersActive: 0,
        supportTickets: 0,
        timeToValue: 0
      },
      touchpoints: [],
      goals: await this.generateInitialGoals(config),
      initiatives: await this.generateInitialInitiatives(config)
    };

    this.customers.set(customerId, customerSuccess);
  }

  private async generateInitialGoals(config: any): Promise<CustomerGoal[]> {
    return [
      {
        id: 'onboarding-completion',
        description: 'Complete onboarding process',
        category: 'EFFICIENCY',
        targetDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000), // 14 days
        progress: 0,
        metrics: [
          {
  name: 'Steps Completed', currentValue: 0, targetValue: config.onboardingSteps.length, unit: 'steps', trend: 'UP' }
        ],
        status: 'NOT_STARTED'
      },
      {
        id: 'time-to-value',
        description: 'Achieve first business value',
        category: 'EFFICIENCY',
        targetDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        progress: 0,
        metrics: [
          { name: 'Workflows Active', currentValue: 0, targetValue: 3, unit: 'workflows', trend: 'STABLE' }
        ],
        status: 'NOT_STARTED'
      }
    ];
  }

  private async generateInitialInitiatives(config: any): Promise<Initiative[]> {
    return [
      {
        id: 'onboarding-training',
        name: 'Onboarding Training Program',
        description: 'Complete guided onboarding with AI assistance',
        type: 'TRAINING',
        priority: 'HIGH',
        status: 'PLANNED',
        startDate: new Date(),
        endDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000),
        owner: 'ai-assistant',
        progress: 0,
        deliverables: config.onboardingSteps.map((step: string, index: number) => ({
          id: `deliverable-${index}`,
          name: step,
          description: `Complete ${step} onboarding step`,
          dueDate: new Date(Date.now() + (index + 1) * 2 * 24 * 60 * 60 * 1000),
          status: 'PENDING',
          assignee: 'customer'
        }))
      }
    ];
  }

  async updateHealthScore(customerId: string): Promise<number> {
    const customer = this.customers.get(customerId);
    if (!customer) return 0;

    // Calculate health score based on multiple factors
    let score = 100;

    // Onboarding progress factor (40% weight)
    const onboardingWeight = 0.4;
    score -= (100 - customer.onboardingProgress) * onboardingWeight;

    // Engagement factor (30% weight)
    const engagementWeight = 0.3;
    const engagementScore = customer.adoptionMetrics.loginFrequency > 0 ? 100 : 0;
    score -= (100 - engagementScore) * engagementWeight;

    // Support tickets factor (20% weight)
    const supportWeight = 0.2;
    const supportPenalty = Math.min(customer.adoptionMetrics.supportTickets * 10, 50);
    score -= supportPenalty * supportWeight;

    // Time factor (10% weight)
    const timeWeight = 0.1;
    const daysSinceStart = Math.floor((Date.now() - new Date().getTime()) / (24 * 60 * 60 * 1000));
    if (daysSinceStart > 30 && customer.onboardingProgress < 50) {
      score -= 30 * timeWeight;
    }

    customer.healthScore = Math.max(0, Math.round(score));
    return customer.healthScore;
  }

  async addTouchpoint(customerId: string, touchpoint: Omit<Touchpoint, 'id'>): Promise<void> {
    const customer = this.customers.get(customerId);
    if (!customer) return;

    const newTouchpoint: Touchpoint = {
      id: `touchpoint-${Date.now()}`,
      ...touchpoint
    };

    customer.touchpoints.push(newTouchpoint);
  }

  getCustomerSuccess(customerId: string): CustomerSuccess | undefined {
    return this.customers.get(customerId);
  }
}