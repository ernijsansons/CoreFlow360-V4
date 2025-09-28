// src/types/workflow.ts
export interface WorkflowExecution {
  id: string;
  workflowId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt: Date;
  completedAt?: Date;
  error?: string;
  variables: Record<string, any>;
}

export interface OnboardingFlow {
  id: string;
  name: string;
  experience: 'beginner' | 'intermediate' | 'advanced';
  goals: string[];
  steps: OnboardingStep[];
  estimatedTime: number;
}

export interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  type: 'setup' | 'tutorial' | 'verification';
  completed: boolean;
}

export interface AIGuidance {
  response: string;
  suggestions: string[];
  nextSteps: string[];
  confidence: number;
}

export interface TroubleshootingGuide {
  id: string;
  title: string;
  steps: TroubleshootingStep[];
  category: string;
}

export interface TroubleshootingStep {
  title: string;
  description: string;
  action?: string;
  expected: string;
}

export interface ContextualHelp {
  stepId: string;
  content: string;
  resources: HelpResource[];
}

export interface HelpResource {
  type: 'video' | 'document' | 'tutorial';
  title: string;
  url: string;
}
