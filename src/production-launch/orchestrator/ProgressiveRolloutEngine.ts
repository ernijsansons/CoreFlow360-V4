import { LaunchStage, LaunchStageConfig, ProgressiveRolloutConfig } from '../types/index';

export class ProgressiveRolloutEngine {
  private isPaused = false;
  private currentStage?: LaunchStage;

  async executeStage(stage: LaunchStage,
  config: LaunchStageConfig, rolloutConfig: ProgressiveRolloutConfig): Promise<void> {
    
    this.currentStage = stage;
    stage.status = 'ACTIVE';
    stage.startTime = new Date();

    // Gradual user ramp-up
    await this.rampUpUsers(stage, config);

    // Monitor during execution
    await this.monitorStageExecution(stage, config);

  }

  private async rampUpUsers(stage: LaunchStage, config: LaunchStageConfig): Promise<void> {
    const rampSteps = 5;
    const stepSize = stage.targetUsers / rampSteps;

    for (let step = 1; step <= rampSteps; step++) {
      if (this.isPaused) {
        await this.waitForResume();
      }

      const targetForStep = Math.floor(stepSize * step);
      stage.currentUsers = targetForStep;

      
      // Simulate traffic routing changes
      await this.updateTrafficRouting(targetForStep, stage.targetUsers);
      
      // Wait between ramp steps
      await this.delay(2000);
    }
  }

  private async monitorStageExecution(stage: LaunchStage, config: LaunchStageConfig): Promise<void> {
    const monitoringDuration = this.parseDuration(stage.duration);
    const monitoringSteps = Math.min(monitoringDuration / 10000, 10); // 10 second intervals, max 10 steps

    for (let i = 0; i < monitoringSteps; i++) {
      if (this.isPaused) {
        await this.waitForResume();
      }

      // Simulate monitoring
      await this.delay(1000);
      
    }
  }

  private async updateTrafficRouting(currentUsers: number, targetUsers: number): Promise<void> {
    const percentage = (currentUsers / targetUsers) * 100;
    
    // Simulate routing update
    await this.delay(500);
  }

  async pauseRollout(): Promise<void> {
    this.isPaused = true;
  }

  async resumeRollout(): Promise<void> {
    this.isPaused = false;
  }

  private async waitForResume(): Promise<void> {
    while (this.isPaused) {
      await this.delay(1000);
    }
  }

  private parseDuration(duration: string): number {
    const match = duration.match(/(\d+)([dhm])/);
    if (!match) return 300000; // 5 minutes default

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 'd': return value * 24 * 60 * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'm': return value * 60 * 1000;
      default: return 300000;
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}