import type { Env } from '../types/env';
import type {
  ConversationTurn,
  ConversationTranscript,
  ConversationState,
  RealTimeCallState,
  ConversationSummary,
  ConversationOutcome,
  Objection,
  ObjectionType,
  QualificationStatus,
  QualificationLevel,
  ExtractedEntity,
  EntityType,
  VoiceAgentConfig
} from '../types/voice-agent';
import type { Lead } from '../types/crm';

export interface ConversationHandlerEvents {
  speech: (text: string, confidence: number) => void;
  silence: (duration: number) => void;
  interruption: () => void;
  objection: (objection: Objection) => void;
  qualification_update: (status: Partial<QualificationStatus>) => void;
  meeting_request: (details: any) => void;
  call_ended: (summary: ExtendedConversationSummary) => void;
  error: (error: Error) => void;
}

// Extended types for internal conversation tracking
interface ExtendedConversationSummary {
  // ConversationSummary required fields
  outcome: ConversationOutcome;
  key_points: string[];
  objections_raised: Objection[];
  interest_level: 'low' | 'medium' | 'high';
  qualification_status: QualificationStatus;
  next_meeting_scheduled?: any;
  follow_up_required: boolean;
  follow_up_timing?: string;
  sentiment: 'positive' | 'neutral' | 'negative';
  lead_quality_score: number;

  // Extended fields for internal tracking
  call_id: string;
  lead_id: string;
  duration: number;
  turns: number;
  intent: string;
  objections: ExtendedObjection[];
  entities: ExtractedEntity[];
  meeting_requested: boolean;
  ai_confidence: number;
  error_count: number;
  interruption_count: number;
  end_reason: 'completed' | 'timeout' | 'error' | 'user_ended';
  transcript: ConversationTurn[];
  summary: string;
  timestamp: string;
}

interface ExtendedObjection extends Objection {
  id: string;
  severity: 'low' | 'medium' | 'high';
  timestamp: string;
  text: string;
  handled: boolean;
}

// Extended call state for internal tracking
interface ExtendedCallState extends RealTimeCallState {
  call_duration: number;
  ai_confidence: number;
  error_count: number;
  interruption_count: number;
  meeting_requested: boolean;
  objections: ExtendedObjection[];
}

export class ConversationHandler {
  private env: Env;
  private lead: Lead;
  private callState: ExtendedCallState;
  private config: VoiceAgentConfig;
  private eventListeners: Partial<ConversationHandlerEvents> = {};
  private conversationTimeout: NodeJS.Timeout | null = null;
  private silenceTimeout: NodeJS.Timeout | null = null;
  private isActive: boolean = false;

  constructor(env: Env, lead: Lead, callId: string, config: VoiceAgentConfig) {
    this.env = env;
    this.lead = lead;
    this.config = config;

    this.callState = {
      call_id: callId,
      lead_id: lead.id,
      status: 'answered',
      state: 'greeting',
      current_intent: 'greeting',
      transcript_buffer: '',
      conversation_history: [],
      detected_entities: [],
      qualification_progress: {
        budget: 'unknown',
        authority: 'unknown',
        need: 'unknown',
        timeline: 'unknown'
      },
      objections_encountered: [],
      next_questions: [],
      call_start_time: new Date().toISOString(),
      last_activity_time: new Date().toISOString(),
      // Extended fields
      objections: [],
      meeting_requested: false,
      call_duration: 0,
      ai_confidence: 0.0,
      error_count: 0,
      interruption_count: 0
    };
  }

  // Event Management
  on<K extends keyof ConversationHandlerEvents>(event: K, listener: ConversationHandlerEvents[K]): void {
    this.eventListeners[event] = listener;
  }

  off<K extends keyof ConversationHandlerEvents>(event: K): void {
    delete this.eventListeners[event];
  }

  private emit<K extends keyof ConversationHandlerEvents>(event: K, ...args: Parameters<ConversationHandlerEvents[K]>): void {
    const listener = this.eventListeners[event];
    if (listener) {
      (listener as any)(...args);
    }
  }

  // Conversation Management
  async startConversation(): Promise<void> {
    this.isActive = true;
    this.callState.status = 'answered';
    this.callState.state = 'greeting';

    // Start conversation timeout
    this.conversationTimeout = setTimeout(() => {
      this.endConversation('timeout');
    }, this.config.call_settings.max_call_duration * 1000);

    // Begin with greeting
    await this.processTurn('greeting', 'Hello! Thank you for taking my call. How are you today?');
  }

  async processSpeech(audioData: ArrayBuffer): Promise<void> {
    if (!this.isActive) return;

    try {
      // Mock speech recognition - would use real speech-to-text in production
      const transcript = await this.transcribeAudio(audioData);
      const confidence = 0.85; // Mock confidence score

      this.callState.transcript_buffer += transcript + ' ';
      this.callState.last_activity_time = new Date().toISOString();

      // Emit speech event
      this.emit('speech', transcript, confidence);

      // Process the speech
      await this.processTurn('speech', transcript);

    } catch (error: any) {
      this.callState.error_count++;
      this.emit('error', error instanceof Error ? error : new Error('Speech processing failed'));
    }
  }

  async processSilence(duration: number): Promise<void> {
    if (!this.isActive) return;

    this.emit('silence', duration);

    // Handle long silence - using AI config timeout
    const silenceThreshold = this.config.ai_config.conversation_timeout || 30;
    if (duration > silenceThreshold) {
      if (this.silenceTimeout) {
        clearTimeout(this.silenceTimeout);
      }

      this.silenceTimeout = setTimeout(() => {
        this.handleLongSilence();
      }, 5000);
    }
  }

  async processInterruption(): Promise<void> {
    if (!this.isActive) return;

    this.callState.interruption_count++;
    this.emit('interruption');

    // Clear any pending responses
    if (this.silenceTimeout) {
      clearTimeout(this.silenceTimeout);
      this.silenceTimeout = null;
    }
  }

  private async processTurn(type: 'greeting' | 'speech', content: string): Promise<void> {
    const turn: ConversationTurn = {
      id: `turn_${Date.now()}`,
      speaker: type === 'greeting' ? 'ai' : 'human',
      text: content,
      timestamp: new Date().toISOString(),
      confidence: type === 'greeting' ? 1.0 : 0.85,
      duration_ms: 0,
      entities: [],
      intent: type === 'greeting' ? 'greeting' : await this.detectIntent(content),
      sentiment: await this.analyzeSentiment(content)
    };

    // Add to conversation history
    this.callState.conversation_history.push(turn);

    // Process based on turn type
    if (turn.speaker === 'human') {
      await this.processHumanTurn(turn);
    } else {
      await this.processAITurn(turn);
    }
  }

  private async processHumanTurn(turn: ConversationTurn): Promise<void> {
    // Extract entities
    const entities = await this.extractEntities(turn.text);
    turn.entities = entities;
    this.callState.detected_entities.push(...entities);

    // Detect objections
    const objections = await this.detectObjections(turn.text);
    for (const objection of objections) {
      this.callState.objections.push(objection);
      this.emit('objection', objection);
    }

    // Update qualification progress
    await this.updateQualificationProgress(turn);

    // Detect meeting requests
    if (await this.detectMeetingRequest(turn.text)) {
      this.callState.meeting_requested = true;
      this.emit('meeting_request', { lead: this.lead, turn });
    }

    // Generate AI response
    const aiResponse = await this.generateAIResponse(turn);
    if (aiResponse) {
      await this.processTurn('speech', aiResponse);
    }
  }

  private async processAITurn(turn: ConversationTurn): Promise<void> {
    // Convert text to speech and play
    await this.speak(turn.text);
  }

  // Speech Processing
  private async transcribeAudio(audioData: ArrayBuffer): Promise<string> {
    // Mock transcription - would use real speech-to-text service in production
    return "This is a mock transcription of the audio data";
  }

  private async speak(text: string): Promise<void> {
    // Mock text-to-speech - would use real TTS service in production
    console.log(`Speaking: ${text}`);
  }

  // Intent Detection
  private async detectIntent(text: string): Promise<string> {
    // Mock intent detection - would use AI in production
    const intents = [
      { pattern: /hello|hi|hey/i, intent: 'greeting' },
      { pattern: /price|cost|pricing/i, intent: 'pricing_inquiry' },
      { pattern: /demo|show|presentation/i, intent: 'demo_request' },
      { pattern: /meeting|schedule|book/i, intent: 'meeting_request' },
      { pattern: /budget|money|afford/i, intent: 'budget_discussion' },
      { pattern: /timeline|when|schedule/i, intent: 'timeline_discussion' },
      { pattern: /no|not interested|decline/i, intent: 'rejection' },
      { pattern: /yes|interested|sounds good/i, intent: 'acceptance' },
      { pattern: /help|support|assistance/i, intent: 'support_request' },
      { pattern: /bye|goodbye|thanks/i, intent: 'closing' }
    ];

    for (const { pattern, intent } of intents) {
      if (pattern.test(text)) {
        return intent;
      }
    }

    return 'general_inquiry';
  }

  // Sentiment Analysis
  private async analyzeSentiment(text: string): Promise<'positive' | 'neutral' | 'negative'> {
    // Mock sentiment analysis - would use AI in production
    const positiveWords = ['good', 'great', 'excellent', 'amazing', 'love', 'like', 'interested'];
    const negativeWords = ['bad', 'terrible', 'awful', 'hate', 'dislike', 'not interested', 'no'];

    const lowerText = text.toLowerCase();
    const positiveCount = positiveWords.filter((word: any) => lowerText.includes(word)).length;
    const negativeCount = negativeWords.filter((word: any) => lowerText.includes(word)).length;

    if (positiveCount > negativeCount) return 'positive';
    if (negativeCount > positiveCount) return 'negative';
    return 'neutral';
  }

  // Entity Extraction
  private async extractEntities(text: string): Promise<ExtractedEntity[]> {
    // Mock entity extraction - would use AI in production
    const entities: ExtractedEntity[] = [];

    // Extract numbers (budget as money)
    const moneyPattern = /\$?\d{1,3}(,?\d{3})*(\.\d{2})?/g;
    const moneyMatches = text.matchAll(moneyPattern);
    for (const match of moneyMatches) {
      if (match.index !== undefined) {
        entities.push({
          type: 'money',
          value: match[0],
          confidence: 0.8,
          start_pos: match.index,
          end_pos: match.index + match[0].length
        });
      }
    }

    // Extract time references
    const timePatterns = [
      { pattern: /next week|this week/i, type: 'time' as EntityType },
      { pattern: /next month|this month/i, type: 'time' as EntityType },
      { pattern: /quarter|3 months/i, type: 'time' as EntityType },
      { pattern: /year|12 months/i, type: 'time' as EntityType }
    ];

    for (const { pattern, type } of timePatterns) {
      const match = text.match(pattern);
      if (match && match.index !== undefined) {
        entities.push({
          type,
          value: match[0],
          confidence: 0.9,
          start_pos: match.index,
          end_pos: match.index + match[0].length
        });
      }
    }

    // Extract dates
    const datePattern = /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g;
    const dateMatches = text.matchAll(datePattern);
    for (const match of dateMatches) {
      if (match.index !== undefined) {
        entities.push({
          type: 'date',
          value: match[0],
          confidence: 0.95,
          start_pos: match.index,
          end_pos: match.index + match[0].length
        });
      }
    }

    return entities;
  }

  // Objection Detection
  private async detectObjections(text: string): Promise<ExtendedObjection[]> {
    // Mock objection detection - would use AI in production
    const objections: ExtendedObjection[] = [];

    const objectionPatterns: Array<{
      pattern: RegExp;
      type: ObjectionType;
      severity: 'low' | 'medium' | 'high';
    }> = [
      { pattern: /too expensive|cost too much/i, type: 'price', severity: 'high' },
      { pattern: /budget concerns/i, type: 'budget', severity: 'high' },
      { pattern: /not interested|not right time|busy/i, type: 'timing', severity: 'medium' },
      { pattern: /don't need|not necessary|happy with current/i, type: 'need', severity: 'high' },
      { pattern: /need to think|discuss with team|get approval/i, type: 'authority', severity: 'medium' },
      { pattern: /competitor|other solution|already using/i, type: 'competitor', severity: 'medium' }
    ];

    for (const { pattern, type, severity } of objectionPatterns) {
      if (pattern.test(text)) {
        const matchText = text.match(pattern)?.[0] || '';
        objections.push({
          id: `objection_${Date.now()}`,
          type,
          severity,
          text: matchText,
          timestamp: new Date().toISOString(),
          handled: false,
          objection: matchText,
          response_given: '',
          resolved: false,
          follow_up_needed: true
        });
      }
    }

    return objections;
  }

  // Qualification Progress
  private async updateQualificationProgress(turn: ConversationTurn): Promise<void> {
    const progress = this.callState.qualification_progress;
    let updated = false;
    const lowerText = turn.text.toLowerCase();

    // Check for budget indicators
    if ((turn.entities && turn.entities.some(e => e.type === 'money')) ||
        lowerText.includes('budget') ||
        lowerText.includes('cost') ||
        lowerText.includes('price')) {
      if (progress.budget === 'unknown') {
        progress.budget = 'low';
        updated = true;
      }
    }

    // Check for authority indicators
    if (lowerText.includes('decision') ||
        lowerText.includes('approve') ||
        lowerText.includes('team') ||
        lowerText.includes('manager')) {
      if (progress.authority === 'unknown') {
        progress.authority = 'low';
        updated = true;
      }
    }

    // Check for need indicators
    if (lowerText.includes('need') ||
        lowerText.includes('problem') ||
        lowerText.includes('challenge') ||
        lowerText.includes('issue')) {
      if (progress.need === 'unknown') {
        progress.need = 'low';
        updated = true;
      }
    }

    // Check for timeline indicators
    if ((turn.entities && turn.entities.some(e => e.type === 'time' || e.type === 'date')) ||
        lowerText.includes('when') ||
        lowerText.includes('timeline') ||
        lowerText.includes('schedule')) {
      if (progress.timeline === 'unknown') {
        progress.timeline = 'low';
        updated = true;
      }
    }

    if (updated) {
      this.emit('qualification_update', progress);
    }
  }

  // Meeting Request Detection
  private async detectMeetingRequest(text: string): Promise<boolean> {
    const meetingPatterns = [
      /schedule.*meeting/i,
      /book.*call/i,
      /set.*up.*time/i,
      /when.*can.*we.*talk/i,
      /demo.*sounds.*good/i,
      /interested.*in.*learning/i
    ];

    return meetingPatterns.some(pattern => pattern.test(text));
  }

  // AI Response Generation
  private async generateAIResponse(turn: ConversationTurn): Promise<string | null> {
    // Mock AI response generation - would use real AI in production
    const responses: Record<string, string> = {
      'greeting': "Hello! Thank you for taking my call. How are you today?",
      'pricing_inquiry': "I'd be happy to discuss our pricing with you. What's your budget range?",
      'demo_request': "Great! I can schedule a demo for you. What time works best?",
      'meeting_request': "I'd love to schedule a meeting. What's your preferred time?",
      'budget_discussion': "That's helpful to know. What specific features are you most interested in?",
      'timeline_discussion': "That timeline works for us. What's your biggest challenge right now?",
      'rejection': "I understand. Is there anything specific that concerns you?",
      'acceptance': "That's great to hear! What would you like to know more about?",
      'support_request': "I'm here to help! What specific issue are you experiencing?",
      'closing': "Thank you for your time today. I'll follow up with you soon!",
      'general_inquiry': "I'd be happy to help you with that. Could you tell me more about your needs?"
    };

    const intent = turn.intent || 'general_inquiry';
    return responses[intent] || responses['general_inquiry'];
  }

  // Silence Handling
  private handleLongSilence(): void {
    if (!this.isActive) return;

    // Generate follow-up question
    const followUpQuestions = [
      "Are you still there?",
      "Would you like me to explain anything else?",
      "Do you have any questions?",
      "What would you like to know more about?"
    ];

    const question = followUpQuestions[Math.floor(Math.random() * followUpQuestions.length)];
    this.processTurn('speech', question);
  }

  // Conversation End
  async endConversation(reason: 'completed' | 'timeout' | 'error' | 'user_ended'): Promise<ExtendedConversationSummary> {
    this.isActive = false;
    this.callState.status = 'completed';

    // Clear timeouts
    if (this.conversationTimeout) {
      clearTimeout(this.conversationTimeout);
      this.conversationTimeout = null;
    }
    if (this.silenceTimeout) {
      clearTimeout(this.silenceTimeout);
      this.silenceTimeout = null;
    }

    // Generate summary
    const summary: ExtendedConversationSummary = {
      // Required ConversationSummary fields
      outcome: this.determineOutcome(),
      key_points: this.extractKeyPoints(),
      objections_raised: this.callState.objections,
      interest_level: this.determineInterestLevel(),
      qualification_status: this.buildQualificationStatus(),
      follow_up_required: this.callState.meeting_requested || this.callState.objections.length > 0,
      sentiment: this.calculateOverallSentiment(),
      lead_quality_score: this.calculateLeadScore(),

      // Extended fields
      call_id: this.callState.call_id,
      lead_id: this.callState.lead_id,
      duration: this.callState.call_duration,
      turns: this.callState.conversation_history.length,
      intent: this.callState.current_intent,
      objections: this.callState.objections,
      entities: this.callState.detected_entities,
      meeting_requested: this.callState.meeting_requested,
      ai_confidence: this.callState.ai_confidence,
      error_count: this.callState.error_count,
      interruption_count: this.callState.interruption_count,
      end_reason: reason,
      transcript: this.callState.conversation_history,
      summary: this.generateConversationSummary(),
      timestamp: new Date().toISOString()
    };

    this.emit('call_ended', summary);
    return summary;
  }

  private determineOutcome(): ConversationOutcome {
    if (this.callState.meeting_requested) return 'meeting_scheduled';
    if (this.callState.objections.some(o => o.type === 'need')) return 'not_interested';
    if (this.calculateLeadScore() > 70) return 'qualified';
    return 'interested_follow_up';
  }

  private extractKeyPoints(): string[] {
    const points: string[] = [];
    if (this.callState.meeting_requested) {
      points.push('Meeting requested');
    }
    if (this.callState.objections.length > 0) {
      points.push(`${this.callState.objections.length} objections raised`);
    }
    return points;
  }

  private determineInterestLevel(): 'low' | 'medium' | 'high' {
    const score = this.calculateLeadScore();
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  private buildQualificationStatus(): QualificationStatus {
    const progress = this.callState.qualification_progress;
    const qualified = Object.values(progress).filter(v => v && v !== 'unknown').length >= 3;

    return {
      budget: progress.budget || 'unknown',
      authority: progress.authority || 'unknown',
      need: progress.need || 'unknown',
      timeline: progress.timeline || 'unknown',
      overall_score: this.calculateLeadScore(),
      qualified
    };
  }

  private calculateOverallSentiment(): 'positive' | 'neutral' | 'negative' {
    const sentiments = this.callState.conversation_history
      .filter(t => t.sentiment)
      .map(t => t.sentiment);

    if (sentiments.length === 0) return 'neutral';

    const positiveCount = sentiments.filter(s => s === 'positive').length;
    const negativeCount = sentiments.filter(s => s === 'negative').length;

    if (positiveCount > negativeCount) return 'positive';
    if (negativeCount > positiveCount) return 'negative';
    return 'neutral';
  }

  private calculateLeadScore(): number {
    let score = 50; // Base score

    // Qualification progress
    const progress = this.callState.qualification_progress;
    const qualifiedAreas = Object.values(progress).filter(v => v && v !== 'unknown').length;
    score += qualifiedAreas * 10;

    // Meeting requested
    if (this.callState.meeting_requested) {
      score += 20;
    }

    // Objections
    score -= this.callState.objections.length * 5;

    // Sentiment
    const sentiment = this.calculateOverallSentiment();
    if (sentiment === 'positive') score += 10;
    if (sentiment === 'negative') score -= 10;

    return Math.max(0, Math.min(100, score));
  }

  private generateConversationSummary(): string {
    const turns = this.callState.conversation_history.length;
    const objections = this.callState.objections.length;
    const meetingRequested = this.callState.meeting_requested;
    const qualification = this.callState.qualification_progress;

    let summary = `Conversation with lead ${this.lead.id} lasted ${this.callState.call_duration} minutes. `;
    summary += `${turns} turns exchanged. `;

    if (objections > 0) {
      summary += `${objections} objections raised. `;
    }

    if (meetingRequested) {
      summary += 'Meeting requested. ';
    }

    const qualifiedAreas = Object.values(qualification).filter((status: any) => status !== 'unknown').length;
    summary += `${qualifiedAreas}/4 qualification areas discussed.`;

    return summary;
  }

  // Utility Methods
  getCallState(): RealTimeCallState {
    return { ...this.callState };
  }

  isConversationActive(): boolean {
    return this.isActive;
  }

  async cleanup(): Promise<void> {
    if (this.conversationTimeout) {
      clearTimeout(this.conversationTimeout);
    }
    if (this.silenceTimeout) {
      clearTimeout(this.silenceTimeout);
    }
    
    this.isActive = false;
    this.eventListeners = {};
  }
}

