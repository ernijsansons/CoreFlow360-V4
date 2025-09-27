import type {
  VoiceAgentConfig,
  CallInitiationRequest,
  CallResult,
  CallStatus,
  ConversationState,
  RealTimeCallState,
  VoiceAgentResponse,
  CallAnalytics,
  ConversationSummary
} from '../types/voice-agent';
import type { Lead } from '../types/crm';
import { TwilioService } from './twilio-service';
import { ConversationHandler } from './conversation-handler';
import { VoiceScriptGenerator } from './voice-script-generator';

export class AIVoiceAgent {
  private twilioService: TwilioService;
  private conversationHandler: ConversationHandler;
  private scriptGenerator: VoiceScriptGenerator;
  private config: VoiceAgentConfig;
  private activeCalls: Map<string, RealTimeCallState> = new Map();

  constructor(config: VoiceAgentConfig) {
    this.config = config;
    this.twilioService = new TwilioService(config.twilio);
    this.conversationHandler = new ConversationHandler(config);
    this.scriptGenerator = new VoiceScriptGenerator(config);
  }

  async initiateCall(lead: Lead, request?: Partial<CallInitiationRequest>): Promise<VoiceAgentResponse> {
    try {

      // 1. Validate lead and check if call is possible
      const validation = await this.validateCallRequest(lead);
      if (!validation.canCall) {
        return {
          success: false,
          message: validation.reason || 'Cannot initiate call',
          error: validation.reason
        };
      }

      // 2. Generate dynamic script based on lead data and enrichment
      const script = await this.scriptGenerator.generatePersonalizedScript(lead, {
        call_type: request?.call_type || 'cold_outreach',
        context: request?.context,
        custom_script: request?.custom_script
      });


      // 3. Estimate call costs and duration
      const costEstimate = this.estimateCallCost(script.estimated_duration);

      // 4. Initiate Twilio call
      const twilioResult = await this.twilioService.initiateCall(lead, {
        timeout: this.config.call_settings.answer_timeout,
        machine_detection: this.config.twilio.machine_detection ? 'DetectMessageEnd' : undefined,
        machine_detection_timeout: this.config.call_settings.machine_detection_timeout
      });

      if (!twilioResult.success || !twilioResult.call_sid) {
        return {
          success: false,
          message: 'Failed to initiate call',
          error: twilioResult.error
        };
      }

      // 5. Initialize real-time call state
      const callState: RealTimeCallState = {
        call_id: twilioResult.call_sid,
        lead_id: lead.id,
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
        next_questions: script.opening.questions,
        call_start_time: new Date().toISOString(),
        last_activity_time: new Date().toISOString()
      };

      // 6. Store active call state
      this.activeCalls.set(twilioResult.call_sid, callState);

      // 7. Set up conversation handler for this call
      await this.conversationHandler.initializeCall(twilioResult.call_sid, lead, script);


      return {
        success: true,
        call_id: twilioResult.call_sid,
        message: 'Call initiated successfully',
        estimated_call_time: script.estimated_duration,
        cost_estimate: costEstimate,
        queue_position: 0
      };

    } catch (error: any) {
      return {
        success: false,
        message: 'Internal error during call initiation',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async handleTwilioWebhook(callSid: string, webhookData: any): Promise<string> {
    try {
      const callState = this.activeCalls.get(callSid);
      if (!callState) {
        return this.twilioService.generateTwiMLResponse(
          "I'm sorry, there was an issue with this call. Please try again later.",
          { hangup: true }
        );
      }

      // Update call status based on webhook
      const newStatus = this.twilioService.mapTwilioStatusToCallStatus(
        webhookData.CallStatus,
        webhookData.AnsweredBy
      );

      callState.status = newStatus;
      callState.last_activity_time = new Date().toISOString();


      // Handle different webhook events
      switch (webhookData.CallStatus) {
        case 'ringing':
          return this.handleRingingState(callState);

        case 'in-progress':
          if (webhookData.AnsweredBy?.includes('machine')) {
            return this.handleVoicemailDetected(callState);
          }
          return this.handleCallAnswered(callState, webhookData);

        case 'completed':
          return this.handleCallCompleted(callState, webhookData);

        case 'busy':
        case 'no-answer':
        case 'failed':
          return this.handleCallFailed(callState, webhookData);

        default:
          return this.conversationHandler.handleIncomingAudio(callSid, webhookData);
      }

    } catch (error: any) {
      return this.twilioService.generateTwiMLResponse(
        "I apologize, but we're experiencing technical difficulties. Please try again later.",
        { hangup: true }
      );
    }
  }

  async getCallResult(callSid: string): Promise<CallResult | null> {
    try {
      const callState = this.activeCalls.get(callSid);
      if (!callState) {
        return null;
      }

      // Get final call details from Twilio
      const twilioCall = await this.twilioService.getCallDetails(callSid);
      if (!twilioCall) {
        return null;
      }

      // Generate conversation summary
      const summary = await this.conversationHandler.generateCallSummary(callSid);

      // Calculate final analytics
      const analytics = await this.calculateCallAnalytics(callState, twilioCall);

      const result: CallResult = {
        call_id: callSid,
        lead_id: callState.lead_id,
        status: callState.status,
        duration_seconds: twilioCall.duration ? parseInt(twilioCall.duration) : 0,
        answered: callState.status === 'answered' || callState.status === 'completed',
        voicemail_detected: callState.status === 'voicemail',
        machine_detected: twilioCall.answered_by?.includes('machine') || false,
        conversation_summary: summary,
        next_actions: await this.generateNextActions(callState, summary),
        recording_url: await this.getCallRecordingUrl(callSid),
        transcript: await this.conversationHandler.getCallTranscript(callSid),
        cost: this.twilioService.estimateCallCost(
          twilioCall.direction,
          twilioCall.duration ? parseInt(twilioCall.duration) : 0
        ),
        created_at: callState.call_start_time,
        completed_at: new Date().toISOString()
      };

      // Clean up active call state
      this.activeCalls.delete(callSid);

      return result;

    } catch (error: any) {
      return null;
    }
  }

  async getActiveCallState(callSid: string): Promise<RealTimeCallState | null> {
    return this.activeCalls.get(callSid) || null;
  }

  async updateCallState(callSid: string, updates: Partial<RealTimeCallState>): Promise<boolean> {
    const callState = this.activeCalls.get(callSid);
    if (!callState) {
      return false;
    }

    Object.assign(callState, updates);
    callState.last_activity_time = new Date().toISOString();

    return true;
  }

  async terminateCall(callSid: string, reason: string = 'User terminated'): Promise<boolean> {
    try {
      const callState = this.activeCalls.get(callSid);
      if (callState) {
        callState.status = 'completed';
        callState.last_activity_time = new Date().toISOString();
      }

      // Update Twilio call to completed
      const success = await this.twilioService.updateCall(callSid, {
        status: 'completed',
        twiml: this.twilioService.generateTwiMLResponse(
          "Thank you for your time. Have a great day!",
          { hangup: true }
        )
      });

      // Clean up conversation handler
      await this.conversationHandler.endCall(callSid);

      return success;

    } catch (error: any) {
      return false;
    }
  }

  private async validateCallRequest(lead: Lead): Promise<{ canCall: boolean; reason?: string }> {
    // Check if lead has valid phone number
    if (!lead.phone) {
      return { canCall: false, reason: 'Lead has no phone number' };
    }

    // Check Twilio account limits
    const limits = await this.twilioService.checkTwilioLimits();
    if (!limits.can_make_call) {
      return { canCall: false, reason: 'Twilio concurrent call limit reached' };
    }

    // Check account balance
    const balance = await this.twilioService.getAccountBalance();
    if (balance && balance.balance <= 0) {
      return { canCall: false, reason: 'Insufficient Twilio account balance' };
    }

    // Check if lead was called recently (prevent spam)
    // This would check against call history in database

    return { canCall: true };
  }

  private async handleRingingState(callState: RealTimeCallState): Promise<string> {
    callState.status = 'ringing';

    // Return empty response - Twilio will continue ringing
    return '<?xml version="1.0" encoding="UTF-8"?><Response></Response>';
  }

  private async handleCallAnswered(callState: RealTimeCallState, webhookData: any): Promise<string> {
    callState.status = 'answered';
    callState.state = 'greeting';


    // Start the conversation with personalized greeting
    return this.conversationHandler.startConversation(callState.call_id, webhookData);
  }

  private async handleVoicemailDetected(callState: RealTimeCallState): Promise<string> {
    callState.status = 'voicemail';

    // Get voicemail script and leave message
    return this.conversationHandler.handleVoicemail(callState.call_id);
  }

  private async handleCallCompleted(callState: RealTimeCallState, webhookData: any): Promise<string> {
    callState.status = 'completed';

    // Finalize conversation and generate summary
    await this.conversationHandler.endCall(callState.call_id);

    return '<?xml version="1.0" encoding="UTF-8"?><Response></Response>';
  }

  private async handleCallFailed(callState: RealTimeCallState, webhookData: any): Promise<string> {
    callState.status = 'failed';

    // Clean up and log failure
    await this.conversationHandler.endCall(callState.call_id);

    return '<?xml version="1.0" encoding="UTF-8"?><Response></Response>';
  }

  private estimateCallCost(durationSeconds: number): number {
    return this.twilioService.estimateCallCost('outbound-api', durationSeconds);
  }

  private async calculateCallAnalytics(
    callState: RealTimeCallState,
    twilioCall: any
  ): Promise<CallAnalytics> {
    const duration = twilioCall.duration ? parseInt(twilioCall.duration) : 0;
    const talkTime = callState.conversation_history.reduce((total, turn) => {
      return total + (turn.speaker === 'ai' ? turn.duration_ms : 0);
    }, 0) / 1000;

    return {
      call_id: callState.call_id,
      lead_id: callState.lead_id,
      dial_time: 5, // Estimated
      ring_time: 10, // Estimated
      talk_time: talkTime,
      total_duration: duration,
      ai_talk_ratio: duration > 0 ? (talkTime / duration) * 100 : 0,
      interruptions: callState.conversation_history.filter((turn: any) =>
        turn.text.includes('[interrupted]')
      ).length,
      silence_periods: 0, // Would calculate from audio analysis
      average_response_time: 2.5, // Estimated
      audio_quality_score: 85, // Would get from Twilio
      transcription_confidence: callState.conversation_history.reduce((avg, turn) =>
        avg + turn.confidence, 0) / callState.conversation_history.length || 0,
      conversation_flow_score: 80, // AI-calculated
      qualification_score: callState.qualification_progress.overall_score,
      interest_score: 70, // AI-calculated from sentiment
      objection_count: callState.objections_encountered.length,
      objections_resolved: callState.objections_encountered.filter((obj: any) => obj.resolved).length,
      call_cost: this.twilioService.estimateCallCost('outbound-api', duration),
      conversion_value: 0, // Would calculate based on outcome
      roi_estimate: 0 // Would calculate based on conversion probability
    };
  }

  private async generateNextActions(
    callState: RealTimeCallState,
    summary?: ConversationSummary
  ): Promise<any[]> {
    const actions = [];

    if (summary?.next_meeting_scheduled) {
      actions.push({
        action: 'Send calendar invite',
        priority: 'high',
        due_date: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
        description: `Send calendar invite for ${summary.next_meeting_scheduled.type}`,
        automated: true
      });
    }

    if (summary?.follow_up_required) {
      actions.push({
        action: 'Schedule follow-up call',
        priority: 'medium',
        due_date: summary.follow_up_timing || new Date(Date.now() + 86400000 * 7).toISOString(),
        description: 'Schedule follow-up based on conversation outcome',
        automated: false
      });
    }

    if (callState.objections_encountered.some(obj => !obj.resolved)) {
      actions.push({
        action: 'Prepare objection handling materials',
        priority: 'medium',
        description: 'Create materials to address unresolved objections',
        automated: false
      });
    }

    return actions;
  }

  private async getCallRecordingUrl(callSid: string): Promise<string | undefined> {
    try {
      const recordings = await this.twilioService.getCallRecordings(callSid);
      return recordings.length > 0 ? recordings[0].uri : undefined;
    } catch (error: any) {
      return undefined;
    }
  }
}