import { ProgressTracking } from '../types/index';

export class ProgressTracker {
  private tracking = new Map<string, ProgressTracking>();

  async initializeTracking(customerId: string, steps: string[]): Promise<void> {

    const progressTracking: ProgressTracking = {
      customerId,
      onboardingId: `onboarding-${customerId}`,
      overallProgress: 0,
      stepProgress: steps.map((_step, index) => ({
        stepId: `step-${index + 1}`,
        progress: 0,
        timeSpent: 0,
        attempts: 0,
        errors: [],
        helpRequests: 0,
        status: 'PENDING'
      })),
      timeSpent: 0,
      completionRate: 0,
      engagementScore: 100,
      learningVelocity: 0,
      blockers: [],
      achievements: [],
      analytics: {
        startDate: new Date(),
        currentDate: new Date(),
        expectedCompletion: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000),
        benchmarkComparison: {
          industryAverage: 85,
          companySize: 'SMB',
          completionTime: 10,
          adoptionRate: 0.8,
          satisfactionScore: 4.2
        },
        usagePatterns: [],
        performanceMetrics: [],
        predictionModels: []
      }
    };

    this.tracking.set(customerId, progressTracking);
  }

  async updateStepProgress(customerId: string, stepId: string, update: {
    completed?: boolean;
    timeSpent?: number;
    completionData?: any;
  }): Promise<void> {
    const tracking = this.tracking.get(customerId);
    if (!tracking) return;

    const stepProgress = tracking.stepProgress.find(sp => sp.stepId === stepId);
    if (!stepProgress) return;

    if (update.completed) {
      stepProgress.status = 'COMPLETED';
      stepProgress.progress = 100;
    }

    if (update.timeSpent) {
      stepProgress.timeSpent += update.timeSpent;
      tracking.timeSpent += update.timeSpent;
    }

    // Update overall progress
    const completedSteps = tracking.stepProgress.filter(sp => sp.status === 'COMPLETED').length;
    tracking.overallProgress = Math.round((completedSteps / tracking.stepProgress.length) * 100);
    tracking.completionRate = completedSteps / tracking.stepProgress.length;

  }

  getProgressTracking(customerId: string): ProgressTracking | undefined {
    return this.tracking.get(customerId);
  }
}