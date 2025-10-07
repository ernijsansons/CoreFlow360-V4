import type {
  VoiceAgentConfig,
  CallInitiationRequest,
  CallResult,
  CallQueueItem,
  CallPriority,
  VoiceAgentPerformance,
  RealTimeCallState,
  CallStatus
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
    orchestratorConfig: CallOrchestratorConfig,
    env?: any
  ) {
    this.voiceAgent = new AIVoiceAgent(voiceAgentConfig, env);
    this.crmService = new CRMService(env);
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
          call_id: '',
          lead_id: request.lead_id || '',
          status: 'failed' as CallStatus,
          duration_seconds: 0,
          answered: false,
          voicemail_detected: false,
          machine_detected: false,
          next_actions: [],
          cost: 0,
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        };
      }

      // Check volume limits
      if (!this.checkVolumeLimits()) {
        return {
          call_id: '',
          lead_id: request.lead_id || '',
          status: 'failed' as CallStatus,
          duration_seconds: 0,
          answered: false,
          voicemail_detected: false,
          machine_detected: false,
          next_actions: [],
          cost: 0,
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        };
      }

      // Check concurrent call limits
        if (this.activeCalls.size >= this.config.max_concurrent_calls) {
        // Queue the call
        const queueItem: CallQueueItem = {
          id: `queue_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          lead_id: request.lead_id,
          priority: request.priority || 'medium',
          call_type: request.call_type,
          scheduled_at: request.scheduled_at || new Date().toISOString(),
          retry_count: 0,
          max_retries: 3,
          context: request.context || { previous_interactions: [] },
          estimated_duration: 300,
          created_at: new Date().toISOString(),
        };

        this.callQueue.push(queueItem);
        this.sortQueueByPriority();

        return {
          call_id: queueItem.id,
          lead_id: request.lead_id,
          status: 'initiated' as CallStatus,
          duration_seconds: 0,
          answered: false,
          voicemail_detected: false,
          machine_detected: false,
          next_actions: [{
            action: 'queued_for_call',
            priority: 'medium',
            description: `Call queued, estimated wait time: ${this.calculateEstimatedWaitTime(queueItem.priority)}ms`,
            automated: true
          }],
          cost: 0,
          created_at: new Date().toISOString(),
        };
      }

      // Initiate the call immediately
      const callId = `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const result = await this.executeCall(callId, request);

      return result;

    } catch (error: unknown) {
      return {
        call_id: '',
        lead_id: request.lead_id || '',
        status: 'failed' as CallStatus,
        duration_seconds: 0,
        answered: false,
        voicemail_detected: false,
        machine_detected: false,
        next_actions: [],
        cost: 0,
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
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
        call_id: callId,
        lead_id: request.lead_id,
        status: 'initiated',
        state: 'greeting',
        current_intent: 'initial_greeting',
        transcript_buffer: '',
        conversation_history: [],
        detected_entities: [],
        qualification_progress: {
          budget: 'unknown',
          authority: 'unknown',
          need: 'unknown',
          timeline: 'unknown',
          overall_score: 0,
          qualified: false
        },
        objections_encountered: [],
        next_questions: [],
        call_start_time: new Date().toISOString(),
        last_activity_time: new Date().toISOString(),
      };

      this.activeCalls.set(callId, callState);

      // Update counters
      this.processedToday++;
      this.processedThisHour++;

      // Get lead from CRM
      const leadResponse = await this.crmService.getLead(request.lead_id);
      if (!leadResponse.success || !leadResponse.data) {
        throw new Error('Lead not found');
      }
      const lead = leadResponse.data;

      // Execute the call using initiateCall
      const result = await this.voiceAgent.initiateCall(lead, request);

      // Build call result from voice agent response
      const callResult: CallResult = {
        call_id: result.call_id || callId,
        lead_id: request.lead_id,
        status: result.success ? 'completed' : 'failed',
        duration_seconds: 0,
        answered: result.success,
        voicemail_detected: false,
        machine_detected: false,
        next_actions: [],
        cost: result.cost_estimate || 0,
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      };

      // Remove from active calls
      this.activeCalls.delete(callId);

      return callResult;

    } catch (error: unknown) {
      // Update call state with error
      const callState = this.activeCalls.get(callId);
      if (callState) {
        callState.status = 'failed';
        this.activeCalls.delete(callId);
      }

      return {
        call_id: callId,
        lead_id: request.lead_id,
        status: 'failed',
        duration_seconds: 0,
        answered: false,
        voicemail_detected: false,
        machine_detected: false,
        next_actions: [],
        cost: 0,
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
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
      // Build request from queue item
      const request: CallInitiationRequest = {
        lead_id: queueItem.lead_id,
        priority: queueItem.priority,
        call_type: queueItem.call_type,
        scheduled_at: queueItem.scheduled_at,
        context: queueItem.context,
      };

      // Execute the call
      const result = await this.executeCall(queueItem.id, request);

      if (result.status === 'failed' && queueItem.retry_count < this.config.retry_delays.length) {
        // Retry the call
        queueItem.retry_count++;
        queueItem.scheduled_at = new Date(Date.now() + this.config.retry_delays[queueItem.retry_count - 1] * 1000).toISOString();
        this.callQueue.push(queueItem);
        this.sortQueueByPriority();
      }

    } catch (error: unknown) {
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
    const priorityOrder: Record<CallPriority, number> = { 'urgent': 0, 'high': 1, 'medium': 2, 'low': 3 };
    this.callQueue.sort((a, b) => {
      const aPriority = priorityOrder[a.priority] || 2;
      const bPriority = priorityOrder[b.priority] || 2;
      return aPriority - bPriority;
    });
  }

  /**
   * Calculate estimated wait time
   */
  private calculateEstimatedWaitTime(priority: CallPriority): number {
    const priorityOrder: Record<CallPriority, number> = { 'urgent': 0, 'high': 1, 'medium': 2, 'low': 3 };
    const currentPriority = priorityOrder[priority] || 2;

    let waitTime = 0;
    for (const item of this.callQueue) {
      const itemPriority = priorityOrder[item.priority] || 2;
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
      'urgent': 0,
      'high': 0,
      'medium': 0,
      'low': 0,
    };

    for (const item of this.callQueue) {
      byPriority[item.priority]++;
    }

    const estimatedWaitTimes: Record<CallPriority, number> = {
      'urgent': this.calculateEstimatedWaitTime('urgent'),
      'high': this.calculateEstimatedWaitTime('high'),
      'medium': this.calculateEstimatedWaitTime('medium'),
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
        // Mark as cancelled and remove from active calls
        callState.status = 'busy'; // No 'cancelled' in CallStatus, use 'busy'
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

    } catch (error: unknown) {
      console.error('Error cancelling call:', error);
      return false;
    }
  }

  /**
   * Cancel queued call by queue item ID
   */
  async cancelQueuedCall(queueItemId: string): Promise<boolean> {
    return this.cancelCall(queueItemId);
  }

  /**
   * Update call priority in queue
   */
  async updateCallPriority(queueItemId: string, priority: CallPriority): Promise<boolean> {
    try {
      const queueItem = this.callQueue.find(item => item.id === queueItemId);
      if (!queueItem) {
        return false;
      }

      queueItem.priority = priority;
      this.sortQueueByPriority();
      return true;

    } catch (error: unknown) {
      console.error('Error updating call priority:', error);
      return false;
    }
  }

  /**
   * Handle call completion from webhook
   */
  async handleCallCompletion(callSid: string): Promise<void> {
    try {
      // Remove from active calls if present
      this.activeCalls.delete(callSid);

      // Increment processed count
      this.processedThisHour++;
      this.processedToday++;

    } catch (error: unknown) {
      console.error('Error handling call completion:', error);
    }
  }

  /**
   * Get performance metrics
   */
  async getPerformanceMetrics(): Promise<VoiceAgentPerformance> {
    const activeCalls = this.getActiveCalls();
    const queueStats = this.getQueueStats();

    return {
      time_period: 'today',
      total_calls: this.processedToday,
      successful_calls: Math.floor(this.processedToday * queueStats.success_rate),
      answer_rate: queueStats.success_rate,
      qualification_rate: 0.5,
      meeting_booking_rate: 0.25,
      average_call_duration: this.calculateAverageCallDuration(),
      average_cost_per_call: 0.5,
      average_qualification_score: 65,
      top_objections: [],
      conversion_funnel: {
        calls_initiated: this.processedToday,
        calls_answered: Math.floor(this.processedToday * queueStats.success_rate),
        conversations_completed: Math.floor(this.processedToday * queueStats.success_rate * 0.8),
        qualified_leads: Math.floor(this.processedToday * 0.5),
        meetings_scheduled: Math.floor(this.processedToday * 0.25),
        deals_closed: Math.floor(this.processedToday * 0.05),
      },
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

