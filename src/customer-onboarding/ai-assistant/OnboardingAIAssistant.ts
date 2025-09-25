import {
  AIAssistantConfig,
  AIGuidance,
  TroubleshootingGuide,
  ContextualHelp,
  OnboardingFlow
} from '../types/index';

export class OnboardingAIAssistant {
  private config: AIAssistantConfig;
  private currentContext: OnboardingContext;
  private conversationHistory: ConversationEntry[] = [];

  constructor(config: AIAssistantConfig) {
    this.config = config;
    this.currentContext = {
      customerId: '',
      currentStep: '',
      industry: '',
      experience: 'BEGINNER',
      goals: [],
      blockers: []
    };
  }

  async initializeAssistant(customerId: string, onboardingFlow: OnboardingFlow): Promise<void> {
    this.currentContext = {
      customerId,
      currentStep: onboardingFlow.currentStep.id,
      industry: onboardingFlow.industry,
      experience: onboardingFlow.experience,
      goals: onboardingFlow.goals,
      blockers: []
    };

    await this.loadConversationHistory(customerId);
  }

  async provideGuidance(question: string, context?: Partial<OnboardingContext>): Promise<AIGuidance> {
    const enrichedContext = { ...this.currentContext, ...context };
    
    const guidance = await this.generateGuidance(question, enrichedContext);
    
    this.conversationHistory.push({
      timestamp: new Date(),
      type: 'user_question',
      content: question,
      context: enrichedContext
    });

    this.conversationHistory.push({
      timestamp: new Date(),
      type: 'ai_response',
      content: guidance.response,
      context: enrichedContext
    });

    return guidance;
  }

  async getTroubleshootingGuide(issue: string): Promise<TroubleshootingGuide> {
    const guide = await this.generateTroubleshootingGuide(issue, this.currentContext);
    
    this.conversationHistory.push({
      timestamp: new Date(),
      type: 'troubleshooting_request',
      content: issue,
      context: this.currentContext
    });

    return guide;
  }

  async getContextualHelp(stepId: string): Promise<ContextualHelp> {
    const help = await this.generateContextualHelp(stepId, this.currentContext);
    
    this.conversationHistory.push({
      timestamp: new Date(),
      type: 'contextual_help_request',
      content: stepId,
      context: this.currentContext
    });

    return help;
  }

  async updateContext(updates: Partial<OnboardingContext>): Promise<void> {
    this.currentContext = { ...this.currentContext, ...updates };
    
    this.conversationHistory.push({
      timestamp: new Date(),
      type: 'context_update',
      content: JSON.stringify(updates),
      context: this.currentContext
    });
  }

  async getConversationHistory(): Promise<ConversationEntry[]> {
    return [...this.conversationHistory];
  }

  async clearConversationHistory(): Promise<void> {
    this.conversationHistory = [];
  }

  private async loadConversationHistory(customerId: string): Promise<void> {
    this.conversationHistory = [];
  }

  private async generateGuidance(question: string, context: OnboardingContext): Promise<AIGuidance> {
    const response = this.generateResponse(question, context);
    
    return {
      response,
      suggestions: this.generateSuggestions(context),
      nextSteps: this.generateNextSteps(context),
      resources: this.generateResources(context),
      confidence: Math.random() * 0.3 + 0.7
    };
  }

  private async generateTroubleshootingGuide(issue: string, context: OnboardingContext): Promise<TroubleshootingGuide> {
    const steps = this.generateTroubleshootingSteps(issue, context);
    
    return {
      issue,
      steps,
      estimatedTime: steps.length * 5,
      difficulty: this.assessDifficulty(issue),
      prerequisites: this.getPrerequisites(issue),
      resources: this.getTroubleshootingResources(issue)
    };
  }

  private async generateContextualHelp(stepId: string, context: OnboardingContext): Promise<ContextualHelp> {
    const help = this.getStepHelp(stepId);
    
    return {
      stepId,
      title: help.title,
      description: help.description,
      instructions: help.instructions,
      tips: help.tips,
      commonIssues: help.commonIssues,
      videoUrl: help.videoUrl,
      documentationUrl: help.documentationUrl
    };
  }

  private generateResponse(question: string, context: OnboardingContext): string {
    const responses = {
      'BEGINNER': [
        "I understand you're new to this. Let me break it down step by step...",
        "Don't worry, this is a common question for beginners. Here's what you need to know...",
        "Great question! As a beginner, you'll want to focus on..."
      ],
      'INTERMEDIATE': [
        "You're on the right track! Here's how to take it to the next level...",
        "Good question! This is where you can optimize your workflow...",
        "Since you have some experience, you might want to consider..."
      ],
      'ADVANCED': [
        "Excellent question! Let's dive into the advanced features...",
        "You're ready for the more complex aspects. Here's what you need to know...",
        "This is a sophisticated topic. Let me explain the nuances..."
      ]
    };

    const levelResponses = responses[context.experience] || responses['BEGINNER'];
    return levelResponses[Math.floor(Math.random() * levelResponses.length)];
  }

  private generateSuggestions(context: OnboardingContext): string[] {
    const suggestions = [
      "Try exploring the dashboard to get familiar with the interface",
      "Check out our video tutorials for hands-on learning",
      "Join our community forum to connect with other users",
      "Set up your first workflow to see the system in action",
      "Customize your settings to match your preferences"
    ];

    return suggestions.slice(0, 3);
  }

  private generateNextSteps(context: OnboardingContext): string[] {
    const nextSteps = [
      "Complete your profile setup",
      "Configure your first integration",
      "Set up your team members",
      "Create your first workflow",
      "Explore advanced features"
    ];

    return nextSteps.slice(0, 3);
  }

  private generateResources(context: OnboardingContext): string[] {
    const resources = [
      "https://docs.coreflow360.com/getting-started",
      "https://docs.coreflow360.com/tutorials",
      "https://docs.coreflow360.com/api-reference",
      "https://community.coreflow360.com",
      "https://support.coreflow360.com"
    ];

    return resources.slice(0, 3);
  }

  private generateTroubleshootingSteps(issue: string, context: OnboardingContext): string[] {
    const steps = [
      "Check your internet connection",
      "Verify your login credentials",
      "Clear your browser cache",
      "Try refreshing the page",
      "Contact support if the issue persists"
    ];

    return steps;
  }

  private assessDifficulty(issue: string): 'easy' | 'medium' | 'hard' {
    const easyKeywords = ['login', 'password', 'refresh', 'cache'];
    const hardKeywords = ['integration', 'api', 'webhook', 'database'];

    if (easyKeywords.some(keyword => issue.toLowerCase().includes(keyword))) {
      return 'easy';
    }
    if (hardKeywords.some(keyword => issue.toLowerCase().includes(keyword))) {
      return 'hard';
    }
    return 'medium';
  }

  private getPrerequisites(issue: string): string[] {
    return [
      "Basic understanding of the platform",
      "Access to your account",
      "Stable internet connection"
    ];
  }

  private getTroubleshootingResources(issue: string): string[] {
    return [
      "https://docs.coreflow360.com/troubleshooting",
      "https://support.coreflow360.com/common-issues",
      "https://community.coreflow360.com/help"
    ];
  }

  private getStepHelp(stepId: string): any {
    const helpData = {
      'profile-setup': {
        title: 'Profile Setup',
        description: 'Complete your profile to get started',
        instructions: [
          'Enter your personal information',
          'Upload a profile picture',
          'Set your preferences'
        ],
        tips: [
          'Use a professional photo',
          'Complete all required fields',
          'Verify your email address'
        ],
        commonIssues: [
          'Email verification not received',
          'Profile picture upload failed',
          'Required fields validation errors'
        ],
        videoUrl: 'https://videos.coreflow360.com/profile-setup',
        documentationUrl: 'https://docs.coreflow360.com/profile-setup'
      },
      'team-setup': {
        title: 'Team Setup',
        description: 'Invite team members and set permissions',
        instructions: [
          'Invite team members via email',
          'Set role-based permissions',
          'Configure team settings'
        ],
        tips: [
          'Start with a small team',
          'Use clear role descriptions',
          'Set appropriate permissions'
        ],
        commonIssues: [
          'Invitation emails not sent',
          'Permission conflicts',
          'Team member access issues'
        ],
        videoUrl: 'https://videos.coreflow360.com/team-setup',
        documentationUrl: 'https://docs.coreflow360.com/team-setup'
      }
    };

    return helpData[stepId] || {
      title: 'Step Help',
      description: 'Get help with this step',
      instructions: ['Follow the on-screen instructions'],
      tips: ['Take your time', 'Ask for help if needed'],
      commonIssues: ['Step not working as expected'],
      videoUrl: '',
      documentationUrl: ''
    };
  }
}

interface OnboardingContext {
  customerId: string;
  currentStep: string;
  industry: string;
  experience: 'BEGINNER' | 'INTERMEDIATE' | 'ADVANCED';
  goals: string[];
  blockers: string[];
}

interface ConversationEntry {
  timestamp: Date;
  type: 'user_question' | 'ai_response' | 'troubleshooting_request' | 'contextual_help_request' | 'context_update';
  content: string;
  context: OnboardingContext;
}

