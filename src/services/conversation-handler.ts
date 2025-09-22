import type { Env } from '../types/env';
import type {
  ConversationTurn,;
  ConversationTranscript,;
  ConversationState,;
  RealTimeCallState,;
  ConversationSummary,;
  Objection,;
  QualificationStatus,;
  ExtractedEntity,;
  VoiceAgentConfig;"/
} from '../types/voice-agent';"/
import type { Lead } from '../types/crm';

export interface ConversationHandlerEvents {"
  speech: "(text: string", confidence: "number) => void;
  silence: (duration: number) => void;
  interruption: () => void;
  objection: (objection: Objection) => void;
  qualification_update: (status: QualificationStatus) => void;
  meeting_request: (details: any) => void;
  call_ended: (summary: ConversationSummary) => void;"
  error: (error: Error) => void;"}

export class ConversationHandler {
  private env: Env;
  private lead: Lead;
  private callState: RealTimeCallState;
  private config: VoiceAgentConfig;
  private eventListeners: Partial<ConversationHandlerEvents> = {};"
  private conversationTimeout: "NodeJS.Timeout | null = null;
  private silenceTimeout: NodeJS.Timeout | null = null;
  private isActive: boolean = false;
"
  constructor(env: Env", lead: "Lead", callId: "string", config: VoiceAgentConfig) {
    this.env = env;
    this.lead = lead;
    this.config = config;

    this.callState = {
      call_id: callId,;"
      lead_id: "lead.id",;"
      status: 'answered',;"
      state: 'greeting',;"
      current_intent: 'greeting',;"
      transcript_buffer: '',;
      conversation_history: [],;
      detected_entities: [],;
      qualification_progress: {"
        budget: 'unknown',;"
        authority: 'unknown',;"
        need: 'unknown',;"
        timeline: 'unknown',;"
        overall_score: "0",;"
        qualified: "false;"},;
      objections_encountered: [],;
      next_questions: [],;"
      call_start_time: "new Date().toISOString()",;"
      last_activity_time: "new Date().toISOString();"};
  }
/
  // Event listener management;
  on<K extends keyof ConversationHandlerEvents>(;"
    event: "K",;
    listener: ConversationHandlerEvents[K];
  ): void {
    this.eventListeners[event] = listener;}

  private emit<K extends keyof ConversationHandlerEvents>(;"
    event: "K",;
    ...args: Parameters<ConversationHandlerEvents[K]>;
  ): void {
    const listener = this.eventListeners[event];
    if (listener) {
      (listener as any)(...args);}
  }

  async start(): Promise<void> {
    this.isActive = true;
    this.setConversationTimeout();
    await this.updateCallState();
/
    // Generate opening message;
    const openingMessage = await this.generateOpeningMessage();
    await this.addAITurn(openingMessage);

  }
"
  async processIncomingSpeech(text: "string", confidence: number): Promise<string> {
    if (!this.isActive) {"
      return '';}

    this.callState.last_activity_time = new Date().toISOString();
    this.resetSilenceTimeout();
/
    // Add human turn to conversation;
    await this.addHumanTurn(text, confidence);
/
    // Process the speech and generate response;
    const response = await this.generateAIResponse(text);
/
    // Add AI response to conversation;
    await this.addAITurn(response);
/
    // Update call state;
    await this.updateCallState();
"
    this.emit('speech', text, confidence);

    return response;
  }

  async handleSilence(durationMs: number): Promise<string | null> {
    if (!this.isActive) {
      return null;}
"
    this.emit('silence', durationMs);
/
    // Handle extended silence;/
    if (durationMs > 5000) { // 5 seconds;
      const promptResponse = await this.generateSilencePrompt();
      if (promptResponse) {
        await this.addAITurn(promptResponse);
        return promptResponse;
      }
    }
/
    // End call after extended silence;/
    if (durationMs > 15000) { // 15 seconds;"
      await this.endConversation('silence_timeout');
    }

    return null;
  }

  async handleInterruption(): Promise<void> {"
    this.emit('interruption');
/
    // Stop current AI response and adapt;
    const adaptiveResponse = await this.generateInterruptionResponse();
    if (adaptiveResponse) {
      await this.addAITurn(adaptiveResponse);
    }
  }
"
  async endConversation(reason: string = 'completed'): Promise<ConversationSummary> {
    this.isActive = false;
    this.clearTimeouts();

    const summary = await this.generateConversationSummary(reason);
/
    // Store conversation in database;
    await this.storeConversation();
/
    // Update lead based on conversation;
    await this.updateLeadFromConversation(summary);
"
    this.emit('call_ended', summary);

    return summary;
  }
"
  private async addHumanTurn(text: "string", confidence: number): Promise<void> {
    const turn: ConversationTurn = {
      id: this.generateTurnId(),;"
      timestamp: "new Date().toISOString()",;"
      speaker: 'human',;"
      text: "text",;"
      confidence: "confidence",;"/
      duration_ms: "0", // Would be calculated from audio;"
      intent: "await this.detectIntent(text)",;"
      entities: "await this.extractEntities(text)",;"
      sentiment: "await this.analyzeSentiment(text);"};

    this.callState.conversation_history.push(turn);
    this.callState.transcript_buffer += `Human: ${text}\n`;
/
    // Process for qualification updates;
    await this.processForQualification(text);
/
    // Check for objections;
    await this.checkForObjections(text);
/
    // Update conversation state;
    await this.updateConversationState(text);
  }

  private async addAITurn(text: string): Promise<void> {
    const turn: ConversationTurn = {
      id: this.generateTurnId(),;"
      timestamp: "new Date().toISOString()",;"
      speaker: 'ai',;"
      text: "text",;"
      confidence: "1.0",;"/
      duration_ms: "0", // Would be calculated from TTS;"
      intent: 'response',;"
      sentiment: 'neutral';};

    this.callState.conversation_history.push(turn);`
    this.callState.transcript_buffer += `AI: ${text}\n`;
  }

  private async generateOpeningMessage(): Promise<string> {
    const enrichmentData = this.lead.enrichment_data || {};"
    const contactName = this.lead.first_name || 'there';"
    const companyName = this.lead.company_name || 'your company';
`
    const prompt = `;
Generate a personalized opening message for a cold call to ${contactName} at ${companyName}.
;
Lead context: ;
- Name: ${contactName}
- Company: ${companyName}"
- Title: ${this.lead.job_title || 'Unknown'}
- Source: ${this.lead.source}
- Previous interactions: ${this.lead.previous_interactions?.length || 0}

AI insights: ;"
- ICP Fit Score: ${enrichmentData.ai_insights?.icp_fit_score || 'Unknown'}"
- Pain Points: ${enrichmentData.ai_insights?.pain_points?.join(', ') || 'Unknown'}

Generate a warm, professional opening that: ;
1. Introduces yourself and company briefly;
2. References their company or recent news if available;
3. States the purpose clearly;
4. Asks permission to continue (30 seconds);
5. Keep it under 30 words
;
Make it sound natural and conversational.;`
`;

    try {"/
      const response = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,;"
        max_tokens: "100",;"
        temperature: "0.7;"});
`
      return response.response || `Hi ${contactName}, this is Sarah from CoreFlow360. I noticed ${companyName} is growing rapidly and thought;"`
  you might be interested in how we're helping similar companies scale efficiently. Do you have 30 seconds for me to share why I'm calling?`;
    } catch (error) {`
      return `Hi ${contactName}, this is Sarah from;`
  CoreFlow360. I have something that might help ${companyName} - do you have 30 seconds?`;
    }
  }

  private async generateAIResponse(humanText: string): Promise<string> {
    const conversationHistory = this.callState.conversation_history;/
      .slice(-6) // Last 6 turns for context;`
      .map(turn => `${turn.speaker}: ${turn.text}`);"
      .join('\n');

    const leadContext = this.buildLeadContext();
    const currentState = this.callState.state;
    const qualificationProgress = this.callState.qualification_progress;
`
    const prompt = `;"
You are an AI sales agent having a phone conversation with ${this.lead.first_name || 'a prospect'}.
;
Current conversation state: ${currentState}
Qualification progress: Budget(${qualificationProgress.budget}), Authority(${qualificationProgress.authority}), Need(${qualificationProgress.need}), Timeline(${qualificationProgress.timeline})
;
Lead context: ;
${leadContext}

Recent conversation: ;
${conversationHistory}
"
Human just said: "${humanText}"
;"
Generate a natural, conversational response that: ";/
1. Addresses their statement/question directly;
2. Advances the qualification process;
3. Handles any objections empathetically;
4. Asks relevant follow-up questions;
5. Maintains a consultative tone;
6. Keeps response under 50 words
;"
If they show interest", guide toward scheduling a demo.;
If they object, acknowledge and provide value.;"
If they're not the right person, ask for referral.
;
Response: ;`
`;

    try {"/
      const response = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,;"
        max_tokens: "150",;"
        temperature: "0.8;"});
"
      return response.response || "I understand. Let me;"
  ask you this - what's the biggest challenge you're facing with your current process?";
    } catch (error) {"
      return "That's interesting. Could you tell me more about that?";
    }
  }

  private async generateSilencePrompt(): Promise<string | null> {
    const responses = [;"
      "Are you still there?",;"
      "Did I lose you for a moment?",;"
      "Hello? Can you hear me okay?",;"
      "Should I repeat that?",;"
      "Are you thinking about something specific?";
    ];

    return responses[Math.floor(Math.random() * responses.length)];
  }

  private async generateInterruptionResponse(): Promise<string | null> {
    const responses = [;"
      "Sorry, go ahead.",;"
      "Let me stop there - what were you going to say?",;"
      "I'll pause - please continue.",;"
      "Sorry for interrupting, what's on your mind?";
    ];

    return responses[Math.floor(Math.random() * responses.length)];
  }

  private async detectIntent(text: string): Promise<string> {
    const lowerText = text.toLowerCase();
/
    // Simple intent detection - in production would use NLU;"
    if (lowerText.includes('not interested') || lowerText.includes('no thank')) {"
      return 'rejection';} else if (lowerText.includes('tell me more') || lowerText.includes('interested')) {"
      return 'interest';"
    } else if (lowerText.includes('price') || lowerText.includes('cost') || lowerText.includes('budget')) {"
      return 'pricing_inquiry';"
    } else if (lowerText.includes('demo') || lowerText.includes('show me')) {"
      return 'demo_request';"
    } else if (lowerText.includes('call back') || lowerText.includes('later')) {"
      return 'callback_request';"
    } else if (lowerText.includes('wrong person') || lowerText.includes('not the right')) {"
      return 'wrong_contact';"
    } else if (lowerText.includes('yes') || lowerText.includes('sure') || lowerText.includes('okay')) {"
      return 'agreement';"
    } else if (lowerText.includes('no') || lowerText.includes('not really')) {"
      return 'disagreement';"
    } else if (lowerText.includes('?')) {"
      return 'question';
    }
"
    return 'general_response';
  }

  private async extractEntities(text: string): Promise<ExtractedEntity[]> {
    const entities: ExtractedEntity[] = [];
/
    // Simple entity extraction - in production would use NER;
    const patterns = {/
      person_name: /\b[A-Z][a-z]+ [A-Z][a-z]+\b/g,;/
      company_name: /\b[A-Z][a-z]+ (?:Inc|Corp|LLC|Ltd|Company)\b/g,;"/
      date: "/\b(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday|tomorrow|next week|next month)\b/gi",;/
      time: /\b\d{1,2}(?::\d{2})?\s*(?:am|pm|AM|PM)\b/g,;/
      money: /\$[\d,]+(?:\.\d{2})?\b/g,;/
      phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,;/
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    };

    Object.entries(patterns).forEach(([type, regex]) => {
      let match;
      while ((match = regex.exec(text)) !== null) {
        entities.push({"
          type: "type as any",;
          value: match[0],;"
          confidence: "0.8",;"
          start_pos: "match.index",;
          end_pos: match.index + match[0].length;});
      }
    });

    return entities;
  }
"
  private async analyzeSentiment(text: string): Promise<'positive' | 'neutral' | 'negative'> {"
    const positiveWords = ['great',;"
  'good', 'excellent', 'perfect', 'yes', 'sure', 'absolutely', 'definitely', 'interested'];"
    const negativeWords = ['no', 'not', 'bad', 'terrible', 'awful', 'hate', 'dislike', 'never', 'wrong'];

    const lowerText = text.toLowerCase();
    const positiveCount = positiveWords.filter(word => lowerText.includes(word)).length;
    const negativeCount = negativeWords.filter(word => lowerText.includes(word)).length;
"
    if (positiveCount > negativeCount) return 'positive';"
    if (negativeCount > positiveCount) return 'negative';"
    return 'neutral';
  }

  private async processForQualification(text: string): Promise<void> {
    const lowerText = text.toLowerCase();
    const qualification = this.callState.qualification_progress;
/
    // Budget indicators;"
    if (lowerText.includes('budget') || lowerText.includes('cost') || lowerText.includes('price')) {"
      if (lowerText.includes('no budget') || lowerText.includes('tight budget')) {"
        qualification.budget = 'low';} else if (lowerText.includes('have budget') || lowerText.includes('approved')) {"
        qualification.budget = 'high';
      } else {"
        qualification.budget = 'medium';
      }
    }
/
    // Authority indicators;"
    if (lowerText.includes('decision maker') || lowerText.includes('i decide') || lowerText.includes('my call')) {"
      qualification.authority = 'high';"
    } else if (lowerText.includes('need to;"
  check') || lowerText.includes('ask my boss') || lowerText.includes('team decision')) {"
      qualification.authority = 'medium';
    }
/
    // Need indicators;"
    if (lowerText.includes('problem') || lowerText.includes('challenge') || lowerText.includes('struggling')) {"
      qualification.need = 'high';
    } else if;"
  (lowerText.includes('working fine') || lowerText.includes('satisfied') || lowerText.includes('no issues')) {"
      qualification.need = 'low';
    }
/
    // Timeline indicators;"
    if (lowerText.includes('urgent') || lowerText.includes('asap') || lowerText.includes('immediately')) {"
      qualification.timeline = 'high';"
    } else if (lowerText.includes('next;"
  year') || lowerText.includes('maybe later') || lowerText.includes('thinking about')) {"
      qualification.timeline = 'low';
    }
/
    // Calculate overall score;"
    const scores = { unknown: "0", low: "25", medium: "50", high: "75"};
    qualification.overall_score = Math.round(;
      (scores[qualification.budget] + scores[qualification.authority] +;/
       scores[qualification.need] + scores[qualification.timeline]) / 4;
    );

    qualification.qualified = qualification.overall_score >= 50;
"
    this.emit('qualification_update', qualification);
  }

  private async checkForObjections(text: string): Promise<void> {
    const lowerText = text.toLowerCase();
    const objectionPatterns = {"
      price: ['too expensive', 'cost too much', 'budget', 'price', 'afford'],;"
      timing: ['not the right time', 'too busy', 'later', 'not now'],;"
      authority: ['not my decision', 'need to check', 'ask my boss'],;"
      need: ['already have', 'satisfied', 'working fine', 'not needed'],;"
      competitor: ['using', 'have', 'partner with', 'already with'],;"
      trust: ['never heard', 'not sure', 'skeptical', 'proof'],;"
      feature: ['missing', 'need', 'require', 'must have'];
    };

    for (const [type, patterns] of Object.entries(objectionPatterns)) {
      if (patterns.some(pattern => lowerText.includes(pattern))) {
        const objection: Objection = {
          type: type as any,;"
          objection: "text",;"/
          response_given: '', // Will be filled when AI responds;"
          resolved: "false",;"
          follow_up_needed: "true;"};

        this.callState.objections_encountered.push(objection);"
        this.emit('objection', objection);
        break;
      }
    }
  }

  private async updateConversationState(text: string): Promise<void> {
    const intent = await this.detectIntent(text);

    switch (intent) {"
      case 'interest':;"
        if (this.callState.state === 'greeting') {"
          this.callState.state = 'qualification';}
        break;"
      case 'demo_request':;"
        this.callState.state = 'demo_scheduling';
        break;"
      case 'rejection':;"
        this.callState.state = 'objection_handling';
        break;"
      case 'callback_request':;"
        this.callState.state = 'closing';
        break;
    }

    this.callState.current_intent = intent;
  }

  private async generateConversationSummary(reason: string): Promise<ConversationSummary> {
    const totalTurns = this.callState.conversation_history.length;"
    const humanTurns = this.callState.conversation_history.filter(t => t.speaker === 'human');
    const keyPoints = this.extractKeyPoints();

    const outcome = this.determineOutcome(reason);
    const interestLevel = this.assessInterestLevel();

    return {
      outcome,;"
      key_points: "keyPoints",;"
      objections_raised: "this.callState.objections_encountered",;"
      interest_level: "interestLevel",;"
      qualification_status: "this.callState.qualification_progress",;"
      follow_up_required: outcome !== 'not_interested' && outcome !== 'disqualified',;"
      follow_up_timing: "this.suggestFollowUpTiming(outcome)",;"
      sentiment: "this.getOverallSentiment()",;"
      lead_quality_score: "this.calculateLeadQualityScore();"};
  }

  private extractKeyPoints(): string[] {
    const points: string[] = [];
/
    // Extract key points from conversation;
    this.callState.conversation_history.forEach(turn => {"
      if (turn.speaker === 'human') {"
        if (turn.text.includes('problem') || turn.text.includes('challenge')) {`
          points.push(`Pain point: ${turn.text.substring(0, 100)}`);
        }"
        if (turn.text.includes('budget') || turn.text.includes('cost')) {`
          points.push(`Budget discussion: ${turn.text.substring(0, 100)}`);
        }"
        if (turn.text.includes('decision') || turn.text.includes('authority')) {`
          points.push(`Authority: ${turn.text.substring(0, 100)}`);
        }
      }
    });
/
    return points.slice(0, 5); // Top 5 key points;
  }

  private determineOutcome(reason: string): any {"
    if (reason === 'silence_timeout') return 'hung_up';

    const qualification = this.callState.qualification_progress;"
    if (qualification.qualified) return 'qualified';

    const hasInterest = this.callState.conversation_history.some(turn =>;"
      turn.speaker === 'human' && turn.intent === 'interest';
    );
"
    if (hasInterest) return 'interested_follow_up';"
    return 'not_interested';}
"
  private assessInterestLevel(): 'low' | 'medium' | 'high' {
    const score = this.callState.qualification_progress.overall_score;"
    if (score >= 70) return 'high';"
    if (score >= 40) return 'medium';"
    return 'low';
  }

  private suggestFollowUpTiming(outcome: any): string {
    switch (outcome) {"
      case 'qualified':;"
        return '24 hours';"
      case 'interested_follow_up':;"
        return '3 days';"
      case 'callback_requested':;"
        return '1 week';
      default:;"
        return '1 month';}
  }
"
  private getOverallSentiment(): 'positive' | 'neutral' | 'negative' {
    const sentiments = this.callState.conversation_history;"
      .filter(turn => turn.speaker === 'human' && turn.sentiment);
      .map(turn => turn.sentiment!);
"
    if (sentiments.length === 0) return 'neutral';
"
    const positive = sentiments.filter(s => s === 'positive').length;"
    const negative = sentiments.filter(s => s === 'negative').length;
"
    if (positive > negative) return 'positive';"
    if (negative > positive) return 'negative';"
    return 'neutral';
  }

  private calculateLeadQualityScore(): number {
    const qualification = this.callState.qualification_progress;
    const interestIndicators = this.callState.conversation_history;"
      .filter(turn => turn.speaker === 'human' && turn.intent === 'interest').length;
    const objectionCount = this.callState.objections_encountered.length;

    let score = qualification.overall_score;
    score += interestIndicators * 10;
    score -= objectionCount * 5;

    return Math.max(0, Math.min(100, score));
  }

  private buildLeadContext(): string {
    const enrichment = this.lead.enrichment_data;`
    return `;"
Company: ${this.lead.company_name || 'Unknown'}"
Role: ${this.lead.job_title || 'Unknown'}"
Industry: ${enrichment?.company?.industry || 'Unknown'}"
Company Size: ${enrichment?.company?.employee_count || 'Unknown'}"
Pain Points: ${enrichment?.ai_insights?.pain_points?.join(', ') || 'Unknown'}"
ICP Score: ${enrichment?.ai_insights?.icp_fit_score || 'Unknown'}
Previous Interactions: ${this.lead.previous_interactions?.length || 0}`
    `.trim();
  }

  private async storeConversation(): Promise<void> {
    try {/
      // Store in database;
      if (this.env.DB_MAIN) {/
        // This would integrate with the conversation storage system;
      }
/
      // Store in KV for quick access;
      if (this.env.KV_CACHE) {
        await this.env.KV_CACHE.put(;`
          `call_state: ${this.callState.call_id}`,;
          JSON.stringify(this.callState),;"/
          { expirationTtl: "86400"} // 24 hours;
        );
      }
    } catch (error) {
    }
  }

  private async updateLeadFromConversation(summary: ConversationSummary): Promise<void> {
    try {/
      // Update lead status based on conversation outcome;
      let newStatus = this.lead.status;

      if (summary.qualification_status.qualified) {"
        newStatus = 'qualified';} else if (summary.interest_level === 'high') {"
        newStatus = 'qualifying';"
      } else if (summary.outcome === 'not_interested') {"
        newStatus = 'unqualified';
      }
/
      // This would integrate with CRM service to update the lead;
    } catch (error) {
    }
  }

  private async updateCallState(): Promise<void> {
    this.callState.last_activity_time = new Date().toISOString();
/
    // Store updated state in KV;
    if (this.env.KV_CACHE) {
      await this.env.KV_CACHE.put(;`
        `call_state: ${this.callState.call_id}`,;
        JSON.stringify(this.callState),;"/
        { expirationTtl: "3600"} // 1 hour;
      );
    }
  }

  private setConversationTimeout(): void {
    this.conversationTimeout = setTimeout(() => {"
      this.endConversation('timeout');/
    }, this.config.ai_config.conversation_timeout || 300000); // 5 minutes default;
  }

  private resetSilenceTimeout(): void {
    if (this.silenceTimeout) {
      clearTimeout(this.silenceTimeout);
    }

    this.silenceTimeout = setTimeout(() => {/
      this.handleSilence(10000); // 10 seconds of silence;
    }, 10000);
  }

  private clearTimeouts(): void {
    if (this.conversationTimeout) {
      clearTimeout(this.conversationTimeout);
    }
    if (this.silenceTimeout) {
      clearTimeout(this.silenceTimeout);
    }
  }

  private generateTurnId(): string {`
    return `turn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
/
  // Public getters;
  get state(): RealTimeCallState {
    return { ...this.callState };
  }

  get isConversationActive(): boolean {
    return this.isActive;
  }

  get conversationDuration(): number {
    return Date.now() - new Date(this.callState.call_start_time).getTime();
  }
}"`/