import type {
  VoiceAgentConfig,
  CallInitiationRequest,
  CallResult,
  CallQueueItem,
  CallPriority,
  VoiceAgentPerformance,
  RealTimeCallState
} from '../types/voice-agent';
import type { Lead } from '../types/crm';
import { AIVoiceAgent } from './ai-voice-agent';
import { CRMService } from './crm-service';

export interface CallOrchestratorConfig {
  max_concurrent_calls: number;
  queue_processing_interval: number;
  retry_delays: number[]; // [300, 900, 1800] - 5min, 15min, 30min
  business_hours: {
    start: string; // "09:00"
    end: string;   // "17:00"
    timezone: string; // "America/New_York"
    days: number[]; // [1,2,3,4,5] Monday-Friday
  };
  call_volume_limits: {
    per_hour: number;
    per_day: number;
  };
}

export interface CallQueueStats {
  total_queued: number;
  by_priority: Record<CallPriority, number>;
  estimated_wait_times: Record<CallPriority, number>;
  processing_rate: number;
  success_rate: number;
}

export class CallOrchestrator {
  private voiceAgent: AIVoiceAgent;
  private crmService: CRMService;
  private config: CallOrchestratorConfig;
  private callQueue: CallQueueItem[] = [];
  private activeCalls: Map<string, RealTimeCallState> = new Map();
  private processedToday: number = 0;
  private processedThisHour: number = 0;
  private queueProcessor: any;
  private hourlyReset: any;
  private dailyReset: any;

  constructor(
    voiceAgentConfig: VoiceAgentConfig,
    orchestratorConfig: CallOrchestratorConfig
  ) {
    this.voiceAgent = new AIVoiceAgent(voiceAgentConfig);
    this.crmService = new CRMService();
    this.config = orchestratorConfig;

    this.startQueueProcessor();
    this.setupResetTimers();
  }

  /**
   * Initiate a new call
   */
  async initiateCall(request: CallInitiationRequest): Promise<CallResult> {
    try {
      // Check business hours
      if (!this.isBusinessHours()) {
        return {
          success: false,
          callId: '',
          error: 'Call initiated outside business hours',
          timestamp: new Date(),
        };
      }

      // Check volume limits
      if (!this.checkVolumeLimits()) {
        return {
          success: false,
          callId: '',
          error: 'Call volume limits exceeded',
          timestamp: new Date(),
        };
      }

      // Check concurrent call limits
        if (this.activeCalls.size >= this.config.max_concurrent_calls) {
        // Queue the call
        const queueItem: CallQueueItem = {
          id: `queue_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          request,
          priority: request.priority || 'normal',
          queuedAt: new Date(),
          retryCount: 0,
        };

        this.callQueue.push(queueItem);
        this.sortQueueByPriority();

        return {
          success: true,
          callId: queueItem.id,
          queued: true,
          estimatedWaitTime: this.calculateEstimatedWaitTime(queueItem.priority),
          timestamp: new Date(),
        };
      }

      // Initiate the call immediately
      const callId = `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const result = await this.executeCall(callId, request);

      return result;

    } catch (error: any) {
      return {
        success: false,
        callId: '',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date(),
      };
    }
  }

  /**
   * Execute a call
   */
  private async executeCall(callId: string, request: CallInitiationRequest): Promise<CallResult> {
    try {
      // Create call state
      const callState: RealTimeCallState = {
        callId,
        status: 'initiating',
        startTime: new Date(),
        endTime: null,
        duration: 0,
        lead: null,
        transcript: [],
        sentiment: 'neutral',
        intent: null,
        confidence: 0,
        nextAction: null,
        error: null,
      };

      this.activeCalls.set(callId, callState);

      // Update counters
        this.processedToday++;
        this.processedThisHour++;

      // Execute the call
      const result = await this.voiceAgent.makeCall({
        ...request,
        callId,
      });

      // Update call state
      callState.status = result.success ? 'completed' : 'failed';
      callState.endTime = new Date();
      callState.duration = callState.endTime.getTime() - callState.startTime.getTime();
      callState.lead = result.lead;
      callState.transcript = result.transcript || [];
      callState.sentiment = result.sentiment || 'neutral';
      callState.intent = result.intent;
      callState.confidence = result.confidence || 0;
      callState.error = result.error;

      // Update CRM if lead was created
      if (result.lead) {
        await this.crmService.createLead(result.lead);
      }

      // Remove from active calls
      this.activeCalls.delete(callId);

      return {
        success: result.success,
        callId,
        lead: result.lead,
        transcript: result.transcript,
        sentiment: result.sentiment,
        intent: result.intent,
        confidence: result.confidence,
        duration: callState.duration,
        timestamp: new Date(),
      };

    } catch (error: any) {
      // Update call state with error
      const callState = this.activeCalls.get(callId);
      if (callState) {
        callState.status = 'failed';
        callState.endTime = new Date();
        callState.duration = callState.endTime.getTime() - callState.startTime.getTime();
        callState.error = error instanceof Error ? error.message : 'Unknown error';
        this.activeCalls.delete(callId);
      }

      return {
        success: false,
        callId,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date(),
      };
    }
  }

  /**
   * Process the call queue
   */
  private async processQueue(): Promise<void> {
    if (this.callQueue.length === 0) {
      return;
    }

    if (this.activeCalls.size >= this.config.max_concurrent_calls) {
      return;
    }

    if (!this.isBusinessHours()) {
      return;
    }

    if (!this.checkVolumeLimits()) {
      return;
    }

    // Get the next call from queue
    const queueItem = this.callQueue.shift();
    if (!queueItem) {
      return;
    }

    try {
      // Execute the call
      const result = await this.executeCall(queueItem.id, queueItem.request);

      if (!result.success && queueItem.retryCount < this.config.retry_delays.length) {
        // Retry the call
        queueItem.retryCount++;
        queueItem.queuedAt = new Date(Date.now() + this.config.retry_delays[queueItem.retryCount - 1] * 1000);
        this.callQueue.push(queueItem);
        this.sortQueueByPriority();
      }

    } catch (error: any) {
      console.error('Error processing queue item:', error);
    }
  }

  /**
   * Start the queue processor
   */
  private startQueueProcessor(): void {
    this.queueProcessor = setInterval(() => {
      this.processQueue();
    }, this.config.queue_processing_interval);
  }

  /**
   * Setup reset timers
   */
  private setupResetTimers(): void {
    // Reset hourly counter
    this.hourlyReset = setInterval(() => {
      this.processedThisHour = 0;
    }, 60 * 60 * 1000); // Every hour

    // Reset daily counter
    this.dailyReset = setInterval(() => {
      this.processedToday = 0;
    }, 24 * 60 * 60 * 1000); // Every day
  }

  /**
   * Check if it's business hours
   */
  private isBusinessHours(): boolean {
    const now = new Date();
    const timezone = this.config.business_hours.timezone;
    const localTime = new Date(now.toLocaleString('en-US', { timeZone: timezone }));
    
    const currentHour = localTime.getHours();
    const currentMinute = localTime.getMinutes();
    const currentDay = localTime.getDay();

    const startHour = parseInt(this.config.business_hours.start.split(':')[0]);
    const startMinute = parseInt(this.config.business_hours.start.split(':')[1]);
    const endHour = parseInt(this.config.business_hours.end.split(':')[0]);
    const endMinute = parseInt(this.config.business_hours.end.split(':')[1]);

    const currentTime = currentHour * 60 + currentMinute;
    const startTime = startHour * 60 + startMinute;
    const endTime = endHour * 60 + endMinute;

    return this.config.business_hours.days.includes(currentDay) &&
           currentTime >= startTime &&
           currentTime <= endTime;
  }

  /**
   * Check volume limits
   */
  private checkVolumeLimits(): boolean {
    return this.processedThisHour < this.config.call_volume_limits.per_hour &&
           this.processedToday < this.config.call_volume_limits.per_day;
  }

  /**
   * Sort queue by priority
   */
  private sortQueueByPriority(): void {
    const priorityOrder: Record<CallPriority, number> = { 'high': 0, 'normal': 1, 'low': 2 };
    this.callQueue.sort((a, b) => {
      const aPriority = priorityOrder[a.priority] || 1;
      const bPriority = priorityOrder[b.priority] || 1;
      return aPriority - bPriority;
    });
  }

  /**
   * Calculate estimated wait time
   */
  private calculateEstimatedWaitTime(priority: CallPriority): number {
    const priorityOrder: Record<CallPriority, number> = { 'high': 0, 'normal': 1, 'low': 2 };
    const currentPriority = priorityOrder[priority] || 1;
    
    let waitTime = 0;
    for (const item of this.callQueue) {
      const itemPriority = priorityOrder[item.priority] || 1;
      if (itemPriority <= currentPriority) {
        waitTime += this.config.queue_processing_interval;
      }
    }

    return waitTime;
  }

  /**
   * Get queue statistics
   */
  getQueueStats(): CallQueueStats {
    const byPriority: Record<CallPriority, number> = {
      'high': 0,
      'normal': 0,
      'low': 0,
    };

    for (const item of this.callQueue) {
      byPriority[item.priority]++;
    }

    const estimatedWaitTimes: Record<CallPriority, number> = {
      'high': this.calculateEstimatedWaitTime('high'),
      'normal': this.calculateEstimatedWaitTime('normal'),
      'low': this.calculateEstimatedWaitTime('low'),
    };

    return {
      total_queued: this.callQueue.length,
      by_priority: byPriority,
      estimated_wait_times: estimatedWaitTimes,
      processing_rate: this.calculateProcessingRate(),
      success_rate: this.calculateSuccessRate(),
    };
  }

  /**
   * Calculate processing rate
   */
  private calculateProcessingRate(): number {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    
    // This would typically query a database for actual processing history
    // For now, we'll return a mock value
    return this.processedThisHour;
  }

  /**
   * Calculate success rate
   */
  private calculateSuccessRate(): number {
    // This would typically query a database for actual success history
    // For now, we'll return a mock value
    return 0.85; // 85% success rate
  }

  /**
   * Get active calls
   */
  getActiveCalls(): RealTimeCallState[] {
    return Array.from(this.activeCalls.values());
  }

  /**
   * Get call by ID
   */
  getCall(callId: string): RealTimeCallState | null {
    return this.activeCalls.get(callId) || null;
  }

  /**
   * Cancel a call
   */
  async cancelCall(callId: string): Promise<boolean> {
    try {
      // Check if call is active
      const callState = this.activeCalls.get(callId);
      if (callState) {
        // Cancel the active call
        await this.voiceAgent.cancelCall(callId);
        callState.status = 'cancelled';
        callState.endTime = new Date();
        callState.duration = callState.endTime.getTime() - callState.startTime.getTime();
        this.activeCalls.delete(callId);
        return true;
      }

      // Check if call is in queue
      const queueIndex = this.callQueue.findIndex(item => item.id === callId);
      if (queueIndex !== -1) {
        this.callQueue.splice(queueIndex, 1);
        return true;
      }

      return false;

    } catch (error: any) {
      console.error('Error cancelling call:', error);
      return false;
    }
  }

  /**
   * Get performance metrics
   */
  async getPerformanceMetrics(): Promise<VoiceAgentPerformance> {
    const activeCalls = this.getActiveCalls();
    const queueStats = this.getQueueStats();

    return {
      totalCalls: this.processedToday,
      activeCalls: activeCalls.length,
      queuedCalls: queueStats.total_queued,
      successRate: queueStats.success_rate,
      averageCallDuration: this.calculateAverageCallDuration(),
      averageWaitTime: this.calculateAverageWaitTime(),
      peakConcurrency: this.calculatePeakConcurrency(),
      errorRate: this.calculateErrorRate(),
      throughput: queueStats.processing_rate,
      leadConversionRate: this.calculateLeadConversionRate(),
      customerSatisfaction: this.calculateCustomerSatisfaction(),
    };
  }

  /**
   * Calculate average call duration
   */
  private calculateAverageCallDuration(): number {
    // This would typically query a database for actual call history
    // For now, we'll return a mock value
    return 300000; // 5 minutes
  }

  /**
   * Calculate average wait time
   */
  private calculateAverageWaitTime(): number {
    const queueStats = this.getQueueStats();
    const totalWaitTime = Object.values(queueStats.estimated_wait_times).reduce((sum, time) => sum + time, 0);
    const totalQueued = queueStats.total_queued;
    
    return totalQueued > 0 ? totalWaitTime / totalQueued : 0;
  }

  /**
   * Calculate peak concurrency
   */
  private calculatePeakConcurrency(): number {
    // This would typically track peak concurrency over time
    // For now, we'll return the current active calls count
    return this.activeCalls.size;
  }

  /**
   * Calculate error rate
   */
  private calculateErrorRate(): number {
    // This would typically query a database for actual error history
    // For now, we'll return a mock value
    return 0.15; // 15% error rate
  }

  /**
   * Calculate lead conversion rate
   */
  private calculateLeadConversionRate(): number {
    // This would typically query a database for actual conversion history
    // For now, we'll return a mock value
    return 0.25; // 25% conversion rate
  }

  /**
   * Calculate customer satisfaction
   */
  private calculateCustomerSatisfaction(): number {
    // This would typically query a database for actual satisfaction scores
    // For now, we'll return a mock value
    return 4.2; // 4.2 out of 5
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<CallOrchestratorConfig>): void {
    this.config = { ...this.config, ...newConfig };
    
    // Restart queue processor if interval changed
    if (newConfig.queue_processing_interval) {
      clearInterval(this.queueProcessor);
      this.startQueueProcessor();
    }
  }

  /**
   * Shutdown the orchestrator
   */
  async shutdown(): Promise<void> {
    // Clear timers
    if (this.queueProcessor) {
      clearInterval(this.queueProcessor);
    }
    if (this.hourlyReset) {
      clearInterval(this.hourlyReset);
    }
    if (this.dailyReset) {
      clearInterval(this.dailyReset);
    }

    // Cancel all active calls
    for (const callId of this.activeCalls.keys()) {
      await this.cancelCall(callId);
    }

    // Clear queue
    this.callQueue = [];
  }
}

