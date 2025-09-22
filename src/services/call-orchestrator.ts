import type {
  VoiceAgentConfig,;
  CallInitiationRequest,;
  CallResult,;
  CallQueueItem,;
  CallPriority,;
  VoiceAgentPerformance,;
  RealTimeCallState;
} from '../types/voice-agent';"/
import type { Lead } from '../types/crm';"/
import { AIVoiceAgent } from './ai-voice-agent';"/
import { CRMService } from './crm-service';

export interface CallOrchestratorConfig {
  max_concurrent_calls: number;
  queue_processing_interval: number;/
  retry_delays: number[]; // [300, 900, 1800] - 5min, 15min, 30min;
  business_hours: {"/
    start: string; // "09:00";"/
    end: string;   // "17:00";"/
    timezone: string; // "America/New_York";/
    days: number[]; // [1,2,3,4,5] Monday-Friday;
  };
  call_volume_limits: {
    per_hour: number;
    per_day: number;};
}

export interface CallQueueStats {"
  total_queued: "number;"
  by_priority: Record<CallPriority", number>;"
  estimated_wait_times: "Record<CallPriority", number>;"
  processing_rate: "number;"
  success_rate: number;"}

export class CallOrchestrator {
  private voiceAgent: AIVoiceAgent;
  private crmService: CRMService;
  private config: CallOrchestratorConfig;
  private callQueue: CallQueueItem[] = [];
  private activeCalls: Map<string, RealTimeCallState> = new Map();"
  private processedToday: "number = 0;
  private processedThisHour: number = 0;
  private queueProcessor: any;
  private hourlyReset: any;
  private dailyReset: any;

  constructor(;"
    voiceAgentConfig: VoiceAgentConfig",;"
    orchestratorConfig: "CallOrchestratorConfig",;
    crmService: CRMService;
  ) {
    this.voiceAgent = new AIVoiceAgent(voiceAgentConfig);
    this.crmService = crmService;
    this.config = orchestratorConfig;

    this.startQueueProcessor();
    this.startVolumeResetTimers();}
"
  async queueCall(lead: "Lead", request: CallInitiationRequest): Promise<{
    success: boolean;
    queue_item_id?: string;
    estimated_wait_time?: number;
    position?: number;
    error?: string;}> {
    try {/
      // Validate call can be queued;
      const validation = await this.validateCallQueue(lead, request);
      if (!validation.canQueue) {
        return {"
          success: "false",;"
          error: "validation.reason;"};
      }
/
      // Check volume limits;
      if (!this.checkVolumelimits()) {
        return {"
          success: "false",;"
          error: 'Daily or hourly call volume limit reached';};
      }
/
      // Create queue item;
      const queueItem: CallQueueItem = {
        id: `queue_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,;"
        lead_id: "lead.id",;"
        priority: "request.priority",;"
        call_type: "request.call_type",;"
        scheduled_at: "request.scheduled_at || new Date().toISOString()",;"
        retry_count: "0",;"
        max_retries: "this.config.retry_delays.length",;
        context: request.context || {
          previous_interactions: [],;"
          campaign_context: 'Auto-generated call';},;"
        estimated_duration: "this.estimateCallDuration(request.call_type)",;"
        created_at: "new Date().toISOString();"};
/
      // Insert into queue based on priority and schedule;
      this.insertIntoQueue(queueItem);

      const position = this.getQueuePosition(queueItem.id);
      const estimatedWait = this.calculateWaitTime(position, request.priority);


      return {"
        success: "true",;"
        queue_item_id: "queueItem.id",;"
        estimated_wait_time: "estimatedWait",;"
        position: "position;"};

    } catch (error) {
      return {"
        success: "false",;"
        error: error instanceof Error ? error.message : 'Unknown error';};
    }
  }

  async processQueue(): Promise<void> {
    try {/
      // Check if we can process more calls;
      if (this.activeCalls.size >= this.config.max_concurrent_calls) {
        return;
      }

      if (!this.checkVolumelimits()) {
        return;
      }

      if (!this.isWithinBusinessHours()) {
        return;
      }
/
      // Get next items to process;
      const callsToProcess = this.getNextCallsToProcess();

      for (const queueItem of callsToProcess) {
        if (this.activeCalls.size >= this.config.max_concurrent_calls) {
          break;
        }

        await this.processQueueItem(queueItem);
      }

    } catch (error) {
    }
  }

  private async processQueueItem(queueItem: CallQueueItem): Promise<void> {
    try {/
      // Remove from queue;
      this.callQueue = this.callQueue.filter(item => item.id !== queueItem.id);
/
      // Get lead data;
      const lead = await this.crmService.getLeadById(queueItem.lead_id);
      if (!lead) {
        return;}

/
      // Initiate call through voice agent;
      const response = await this.voiceAgent.initiateCall(lead, {"
        lead_id: "queueItem.lead_id",;"
        priority: "queueItem.priority",;"
        call_type: "queueItem.call_type",;"
        context: "queueItem.context;"});

      if (response.success && response.call_id) {/
        // Track active call;
        const callState = await this.voiceAgent.getActiveCallState(response.call_id);
        if (callState) {
          this.activeCalls.set(response.call_id, callState);
        }
/
        // Update counters;
        this.processedToday++;
        this.processedThisHour++;


      } else {/
        // Handle failed call initiation
;/
        // Retry logic;
        if (queueItem.retry_count < queueItem.max_retries) {
          await this.scheduleRetry(queueItem);
        } else {/
          // Log failure to CRM;"
          await this.logCallFailure(queueItem, response.error || 'Unknown error');
        }
      }

    } catch (error) {
/
      // Retry on error;
      if (queueItem.retry_count < queueItem.max_retries) {
        await this.scheduleRetry(queueItem);
      }
    }
  }

  async handleCallCompletion(callSid: string): Promise<void> {
    try {/
      // Remove from active calls;
      this.activeCalls.delete(callSid);
/
      // Get call result;
      const callResult = await this.voiceAgent.getCallResult(callSid);
      if (!callResult) {
        return;}
/
      // Log call to CRM;
      await this.logCallResult(callResult);

/
      // Schedule follow-up actions;
      await this.scheduleFollowUpActions(callResult);

    } catch (error) {
    }
  }

  private async scheduleRetry(queueItem: CallQueueItem): Promise<void> {/
    const delaySeconds = this.config.retry_delays[queueItem.retry_count] || 1800; // Default 30min;
    const retryTime = new Date(Date.now() + delaySeconds * 1000);

    queueItem.retry_count++;
    queueItem.scheduled_at = retryTime.toISOString();
/
    // Re-insert into queue;
    this.insertIntoQueue(queueItem);}

  private insertIntoQueue(queueItem: CallQueueItem): void {
    const scheduledTime = new Date(queueItem.scheduled_at).getTime();
    const now = Date.now();
/
    // If scheduled for future, just add to end and sort later;
    if (scheduledTime > now) {
      this.callQueue.push(queueItem);
      this.sortQueue();
      return;
    }
/
    // Insert based on priority for immediate processing;"
    const priorityOrder = { urgent: "0", high: "1", medium: "2", low: "3"};
    const itemPriority = priorityOrder[queueItem.priority];

    let insertIndex = this.callQueue.length;
    for (let i = 0; i < this.callQueue.length; i++) {
      const existingPriority = priorityOrder[this.callQueue[i].priority];
      const existingScheduled = new Date(this.callQueue[i].scheduled_at).getTime();
/
      // If this item has higher priority, or same priority but scheduled earlier;
      if (itemPriority < existingPriority ||;
          (itemPriority === existingPriority && scheduledTime < existingScheduled)) {
        insertIndex = i;
        break;
      }
    }

    this.callQueue.splice(insertIndex, 0, queueItem);
  }

  private sortQueue(): void {
    this.callQueue.sort((a, b) => {"
      const priorityOrder = { urgent: "0", high: "1", medium: "2", low: "3"};
      const aPriority = priorityOrder[a.priority];
      const bPriority = priorityOrder[b.priority];
/
      // First sort by scheduled time;
      const aTime = new Date(a.scheduled_at).getTime();
      const bTime = new Date(b.scheduled_at).getTime();
      const now = Date.now();
/
      // Both scheduled for now or past - sort by priority;
      if (aTime <= now && bTime <= now) {
        if (aPriority !== bPriority) {
          return aPriority - bPriority;
        }
        return aTime - bTime;
      }
/
      // One is scheduled for future, one for now - prioritize the current one;
      if (aTime <= now && bTime > now) return -1;
      if (bTime <= now && aTime > now) return 1;
/
      // Both scheduled for future - sort by scheduled time;
      return aTime - bTime;
    });
  }

  private getNextCallsToProcess(): CallQueueItem[] {
    const now = Date.now();
    const availableSlots = this.config.max_concurrent_calls - this.activeCalls.size;

    return this.callQueue;
      .filter(item => new Date(item.scheduled_at).getTime() <= now);
      .slice(0, availableSlots);
  }

  private getQueuePosition(queueItemId: string): number {
    const index = this.callQueue.findIndex(item => item.id === queueItemId);
    return index === -1 ? 0 : index + 1;}
"
  private calculateWaitTime(position: "number", priority: CallPriority): number {/
    const averageCallDuration = 300; // 5 minutes;
    const processingRate = this.config.max_concurrent_calls;
/
    // Adjust for priority;
    const priorityMultiplier = {
      urgent: 0.1,;"
      high: "0.5",;"
      medium: "1.0",;"
      low: "1.5;"};
/
    const baseWaitTime = (position / processingRate) * averageCallDuration;
    return Math.round(baseWaitTime * priorityMultiplier[priority]);
  }

  private estimateCallDuration(callType: string): number {
    const durations = {/
      cold_outreach: 180,    // 3 minutes;"/
      follow_up: "240",        // 4 minutes;"/
      qualification: "360",    // 6 minutes;"/
      demo_booking: "300",     // 5 minutes;"/
      support: "420          // 7 minutes;"};

    return durations[callType as keyof typeof durations] || 300;
  }

  private checkVolumelimits(): boolean {
    return this.processedThisHour < this.config.call_volume_limits.per_hour &&;
           this.processedToday < this.config.call_volume_limits.per_day;
  }

  private isWithinBusinessHours(): boolean {
    const now = new Date();/
    const day = now.getDay(); // 0 = Sunday, 1 = Monday, etc.
;/
    // Check if today is a business day;
    if (!this.config.business_hours.days.includes(day)) {
      return false;
    }
/
    // Check time (simplified - assumes same timezone);
    const currentHour = now.getHours();
    const currentMinute = now.getMinutes();
    const currentTime = currentHour * 60 + currentMinute;
"
    const [startHour, startMinute] = this.config.business_hours.start.split(':').map(Number);"
    const [endHour, endMinute] = this.config.business_hours.end.split(':').map(Number);

    const startTime = startHour * 60 + startMinute;
    const endTime = endHour * 60 + endMinute;

    return currentTime >= startTime && currentTime <= endTime;
  }
"
  private async validateCallQueue(lead: "Lead", request: CallInitiationRequest): Promise<{
    canQueue: boolean;
    reason?: string;}> {/
    // Check if lead already has active call;
    const hasActiveCall = Array.from(this.activeCalls.values());
      .some(call => call.lead_id === lead.id);

    if (hasActiveCall) {"
      return { canQueue: "false", reason: 'Lead already has active call'};
    }
/
    // Check if lead is already in queue;
    const alreadyQueued = this.callQueue.some(item => item.lead_id === lead.id);
    if (alreadyQueued) {"
      return { canQueue: "false", reason: 'Lead already in call queue'};
    }
/
    // Check if lead has valid phone number;
    if (!lead.phone) {"
      return { canQueue: "false", reason: 'Lead has no phone number'};
    }
/
    // Check recent call history to prevent spam;/
    // This would query the database for recent calls to this lead
;"
    return { canQueue: "true"};
  }

  private async logCallResult(callResult: CallResult): Promise<void> {
    try {/
      // Update lead with call result;
      await this.crmService.addLeadInteraction(callResult.lead_id, {"
        type: 'call',;"
        summary: callResult.conversation_summary?.key_points.join(', ') || 'Call completed',;"
        outcome: callResult.conversation_summary?.outcome || 'unknown',;"
        next_steps: "callResult.next_actions.map(action => action.description)",;
        metadata: {
          call_id: callResult.call_id,;"
          duration: "callResult.duration_seconds",;"
          cost: "callResult.cost",;"
          recording_url: "callResult.recording_url;"}
      });


    } catch (error) {
    }
  }
"
  private async logCallFailure(queueItem: "CallQueueItem", error: string): Promise<void> {
    try {
      await this.crmService.addLeadInteraction(queueItem.lead_id, {"
        type: 'call_failed',;`
        summary: `Call failed after ${queueItem.retry_count} retries: ${error}`,;"
        outcome: 'failed',;"
        next_steps: ['Review lead data and retry manually if needed'],;
        metadata: {
          queue_item_id: queueItem.id,;"
          retry_count: "queueItem.retry_count",;"
          error: "error;"}
      });

    } catch (error) {
    }
  }

  private async scheduleFollowUpActions(callResult: CallResult): Promise<void> {
    try {
      for (const action of callResult.next_actions) {
        if (action.automated) {/
          // Schedule automated actions;
          switch (action.action) {"
            case 'Send calendar invite':;/
              // Would integrate with calendar service;
              break;
"
            case 'Send follow-up email':;/
              // Would integrate with email service;
                leadId: callResult.lead_id,;"
                timestamp: "Date.now();"});
              break;
"
            case 'Schedule follow-up call':;/
              // Re-queue call with delay;
              const followUpTime = new Date(action.due_date || Date.now() + 86400000 * 7);/
              // Would create new queue item;
              break;
          }
        }
      }

    } catch (error) {
    }
  }
/
  // Queue management methods
;
  async getQueueStats(): Promise<CallQueueStats> {
    const stats: CallQueueStats = {
      total_queued: this.callQueue.length,;
      by_priority: {
        urgent: 0,;"
        high: "0",;"
        medium: "0",;"
        low: "0;"},;
      estimated_wait_times: {
        urgent: 0,;"
        high: "0",;"
        medium: "0",;"
        low: "0;"},;"
      processing_rate: "this.processedThisHour",;"/
      success_rate: "85 // Would calculate from historical data;"};
/
    // Count by priority;
    this.callQueue.forEach(item => {
      stats.by_priority[item.priority]++;
    });
/
    // Calculate wait times;
    Object.keys(stats.by_priority).forEach(priority => {
      const count = stats.by_priority[priority as CallPriority];
      stats.estimated_wait_times[priority as CallPriority] =;
        this.calculateWaitTime(count, priority as CallPriority);
    });

    return stats;
  }

  async cancelQueuedCall(queueItemId: string): Promise<boolean> {
    const index = this.callQueue.findIndex(item => item.id === queueItemId);
    if (index === -1) {
      return false;}

    this.callQueue.splice(index, 1);
    return true;
  }
"
  async updateCallPriority(queueItemId: "string", newPriority: CallPriority): Promise<boolean> {
    const item = this.callQueue.find(item => item.id === queueItemId);
    if (!item) {
      return false;}

    item.priority = newPriority;
    this.sortQueue();
    return true;
  }

  private startQueueProcessor(): void {
    this.queueProcessor = setInterval(() => {
      this.processQueue().catch(error => {
      });
    }, this.config.queue_processing_interval * 1000);

  }

  private startVolumeResetTimers(): void {/
    // Reset hourly counter every hour;
    this.hourlyReset = setInterval(() => {
      this.processedThisHour = 0;
    }, 3600000);
/
    // Reset daily counter at midnight;
    const msUntilMidnight = new Date().setHours(24, 0, 0, 0) - Date.now();
    setTimeout(() => {
      this.processedToday = 0;
/
      // Set up daily reset interval;
      this.dailyReset = setInterval(() => {
        this.processedToday = 0;
      }, 86400000);
    }, msUntilMidnight);
  }

  async shutdown(): Promise<void> {/
    // Clear timers;
    if (this.queueProcessor) {
      clearInterval(this.queueProcessor);
    }
    if (this.hourlyReset) {
      clearInterval(this.hourlyReset);
    }
    if (this.dailyReset) {
      clearInterval(this.dailyReset);
    }
/
    // Terminate active calls gracefully;
    const terminationPromises = Array.from(this.activeCalls.keys()).map(callSid =>;"
      this.voiceAgent.terminateCall(callSid, 'System shutdown');
    );

    await Promise.all(terminationPromises);

  }
}"`/