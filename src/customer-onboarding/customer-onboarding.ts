#!/usr/bin/env ts-node

import { CustomerOnboardingEngine } from './engine/CustomerOnboardingEngine';
import { OnboardingMetadata } from './types/index';

async function main() {
  try {

    const engine = new CustomerOnboardingEngine();

    // Check command line arguments
    const args = process.argv.slice(2);
    const command = args[0];
    const customerId = args[1] || 'demo-customer-001';

    switch (command) {
      case 'create':
        await createOnboardingFlow(engine, customerId);
        break;
      case 'start':
        await startOnboarding(engine, customerId);
        break;
      case 'status':
        await showOnboardingStatus(engine, customerId);
        break;
      case 'complete-step':
        const stepId = args[2];
        if (!stepId) {
          return;
        }
        await completeStep(engine, customerId, stepId);
        break;
      case 'demo':
        await runDemoScenario(engine, customerId);
        break;
      case 'ai-chat':
        const message = args.slice(2).join(' ');
        await chatWithAI(engine, customerId, message);
        break;
      case 'analytics':
        await showAnalytics(engine, customerId);
        break;
      default:
        showUsage();
        break;
    }

  } catch (error) {
    process.exit(1);
  }
}

async function createOnboardingFlow(engine: CustomerOnboardingEngine, customerId: string): Promise<void> {

  const customerData = {
    customerType: 'SMB' as const,
    industry: 'retail',
    metadata: {
      referralSource: 'website',
      expectedUseCase: 'inventory management',
      teamSize: 5,
      businessGoals: ['efficiency', 'automation', 'growth'],
      techExperience: 'INTERMEDIATE' as const,
      urgency: 'MEDIUM' as const,
      budget: '$500-2000/month',
      timeline: '30 days'
    } as OnboardingMetadata
  };

  const flow = await engine.createOnboardingFlow(customerId, customerData);


  flow.steps.forEach((step, index) => {
  });

}

async function startOnboarding(engine: CustomerOnboardingEngine, customerId: string): Promise<void> {

  const flow = await engine.startOnboarding(customerId);


  flow.currentStep.requirements.forEach((req, index) => {
  });

  flow.currentStep.aiGuidance.tips.forEach((tip) => {
  });
}

async function showOnboardingStatus(engine: CustomerOnboardingEngine, customerId: string): Promise<void> {

  const flow = await engine.getOnboardingStatus(customerId);

  if (!flow) {
    return;
  }


  if (flow.completedAt) {
  }

  flow.steps.forEach((step, index) => {
    const status = step.status === 'COMPLETED' ? '✅' :
                  step.status === 'IN_PROGRESS' ? '🔄' :
                  step.status === 'FAILED' ? '❌' : '⏳';

    if (step.actualTime) {
    }
  });

  // Show analytics
  const analytics = await engine.getOnboardingAnalytics(customerId);
}

async function completeStep(engine: CustomerOnboardingEngine, customerId: string, stepId: string): Promise<void> {

  if (!stepId) {
    return;
  }

  // Simulate completion data
  const completionData = {
    'step-1': { 'profile-complete': 100, 'email-verified': 1 },
    'step-2': { 'business-type-selected': 1, 'fiscal-year-set': 1 },
    'step-3': { teamMembers: [{ email: 'user@example.com', role: 'Admin' }] },
    'step-4': { count: 1, imported: true },
    'step-5': { workflowCreated: true, templatesUsed: 1 },
    'step-6': { verified: true, goLiveReady: true }
  };

  const result = await engine.completeStep(customerId,
  stepId, completionData[stepId as keyof typeof completionData] || {});

  if (result.success) {

    if (result.nextStep) {
    }
  } else {
  }
}

async function runDemoScenario(engine: CustomerOnboardingEngine, _customerId: string): Promise<void> {

  const demoManager = engine.getDemoManager();
  const scenario = await demoManager.getDemoScenario('retail-startup');

  if (!scenario) {
    return;
  }


  scenario.objectives.forEach((objective, index) => {
  });

  for (let i = 0; i < scenario.steps.length; i++) {
    const step = scenario.steps[i];
    if (!step) continue;

    // Simulate step validation
    const userAction = { count: 1, status: 'fulfilled', generated: true }; // Mock user action
    const validation = await demoManager.validateDemoStep(scenario.id, step.id, userAction);

    if (validation.valid) {
    } else {
    }

    // Small delay for demo effect
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

}

async function chatWithAI(engine: CustomerOnboardingEngine, _customerId: string, message: string): Promise<void> {

  if (!message) {
    return;
  }

  const aiAssistant = engine.getAIAssistant();


  const response = await aiAssistant.processUserMessage(message);


  if (response.actions.length > 0) {
    response.actions.forEach((action, index) => {
    });
  }

  if (response.suggestions.length > 0) {
    response.suggestions.forEach((suggestion, index) => {
    });
  }
}

async function showAnalytics(engine: CustomerOnboardingEngine, customerId: string): Promise<void> {

  const analytics = await engine.getOnboardingAnalytics(customerId);


  // Show demo analytics if available
  const demoManager = engine.getDemoManager();
  const demoEnvs = demoManager.getDemoEnvironments();

  for (const [demoId, demo] of demoEnvs) {
    if (demo.customerId === customerId) {
      const demoAnalytics = await demoManager.getDemoAnalytics(demoId);

      break;
    }
  }

  // Show AI analytics
  const aiAssistant = engine.getAIAssistant();
  const aiAnalytics = await aiAssistant.getAssistantAnalytics();


  aiAnalytics.commonQueries.forEach((query, index) => {
  });
}

function showUsage(): void {
}

// Execute if run directly
main();

export { main as runCustomerOnboarding };