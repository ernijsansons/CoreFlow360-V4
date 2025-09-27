import type { Env } from '../types/env';
import type {
  CallStream,
  TranscriptChunk,
  Situation,
  Guidance,
  Battlecard,
  PricingGuidance,
  CoachingTip,
  LiveCoachingMessage,
  Lead,
  Participant
} from '../types/crm';

export class RealTimeSalesCoach {
  private env: Env;
  private battlecards = new Map<string, Battlecard>();
  private activeCoaches = new Map<string, WebSocket>();
  private callSituations = new Map<string, Situation[]>();
  private speakingTimeTracker = new Map<string, { salesRep: number; prospect: number; lastUpdate: number }>();

  constructor(env: Env) {
    this.env = env;
    this.initializeBattlecards();
  }

  async provideLiveCoaching(callStream: CallStream): Promise<void> {

    // Initialize coaching channel
    const coach = new WebSocket(callStream.coachingChannel);
    this.activeCoaches.set(callStream.id, coach);

    // Initialize tracking
    this.callSituations.set(callStream.id, []);
    this.speakingTimeTracker.set(callStream.id, {
      salesRep: 0,
      prospect: 0,
      lastUpdate: Date.now()
    });

    coach.addEventListener('open', () => {
      this.sendMessage(callStream.id, {
        type: 'tip',
        content: {
          type: 'rapport',
          message: 'Start with rapport building - ask about their business or recent news',
          priority: 'medium',
          timing: 'immediate',
          actionable: true,
          context: 'Call start'
        } as CoachingTip,
        priority: 'medium',
        category: 'coaching'
      });
    });

    // Listen for transcript updates
    callStream.on('transcript_update', async (chunk: TranscriptChunk) => {
      await this.processTranscriptChunk(callStream.id, chunk);
    });

    // Listen for call events
    callStream.on('call_end', () => {
      this.cleanupCall(callStream.id);
    });

    // Periodic coaching checks
    this.startPeriodicCoaching(callStream.id);
  }

  private async processTranscriptChunk(callId: string, chunk: TranscriptChunk): Promise<void> {
    // Update speaking time tracking
    this.updateSpeakingTime(callId, chunk);

    // Analyze the current situation
    const situation = await this.analyzeSituation(chunk);

    if (situation) {
      // Store situation for context
      const situations = this.callSituations.get(callId) || [];
      situations.push(situation);
      this.callSituations.set(callId, situations);

      // Provide real-time coaching based on situation
      await this.handleSituation(callId, situation, chunk);
    }

    // Check for coaching opportunities
    await this.checkCoachingOpportunities(callId, chunk);
  }

  private async analyzeSituation(chunk: TranscriptChunk): Promise<Situation | null> {
    const text = chunk.text.toLowerCase();
    const speaker = chunk.speaker.toLowerCase();
    const isProspect = !speaker.includes('sales') && !speaker.includes('rep');

    // Objection detection
    const objectionKeywords = [
      'too expensive', 'too costly', 'budget', 'price', 'cost',
      'not sure', 'need to think', 'have to discuss',
      'already have', 'happy with current', 'works fine',
      'not the right time', 'maybe later', 'not ready',
      'not authorized', 'need approval', 'talk to my boss'
    ];

    for (const keyword of objectionKeywords) {
      if (text.includes(keyword) && isProspect) {
        return {
          type: 'objection',
          confidence: 0.8,
          timestamp: chunk.timestamp,
          context: chunk.text,
          severity: this.assessObjectionSeverity(keyword, chunk.text),
          objection: chunk.text,
          urgency: 'high',
          suggestedAction: 'Address objection immediately'
        };
      }
    }

    // Competitor mention detection
    const competitors = ['salesforce', 'hubspot', 'pipedrive', 'zoho', 'monday', 'asana', 'clickup'];
    for (const competitor of competitors) {
      if (text.includes(competitor)) {
        return {
          type: 'competitor_mention',
          confidence: 0.9,
          timestamp: chunk.timestamp,
          context: chunk.text,
          severity: 'medium',
          competitor: competitor.charAt(0).toUpperCase() + competitor.slice(1),
          urgency: 'medium',
          suggestedAction: 'Send competitive battlecard'
        };
      }
    }

    // Pricing discussion detection
    const pricingKeywords = ['price', 'cost', 'budget', 'investment', 'roi', 'return'];
    if (pricingKeywords.some(keyword => text.includes(keyword))) {
      return {
        type: 'pricing_discussion',
        confidence: 0.7,
        timestamp: chunk.timestamp,
        context: chunk.text,
        severity: 'medium',
        urgency: 'medium',
        suggestedAction: 'Provide pricing guidance'
      };
    }

    // Buying signal detection
    const buyingSignals = [
      'when can we start', 'how long to implement', 'next steps',
      'sounds good', 'looks interesting', 'like this',
      'trial', 'pilot', 'demo', 'proposal'
    ];

    for (const signal of buyingSignals) {
      if (text.includes(signal) && isProspect) {
        return {
          type: 'buying_signal',
          confidence: 0.8,
          timestamp: chunk.timestamp,
          context: chunk.text,
          severity: 'low',
          buyingSignal: signal,
          urgency: 'medium',
          suggestedAction: 'Capitalize on buying signal'
        };
      }
    }

    // Pain point detection
    const painKeywords = [
      'problem', 'issue', 'challenge', 'difficult', 'frustrating',
      'slow', 'manual', 'time-consuming', 'inefficient'
    ];

    for (const pain of painKeywords) {
      if (text.includes(pain) && isProspect) {
        return {
          type: 'pain_point',
          confidence: 0.7,
          timestamp: chunk.timestamp,
          context: chunk.text,
          severity: 'medium',
          painPoint: chunk.text,
          urgency: 'medium',
          suggestedAction: 'Dig deeper into pain point'
        };
      }
    }

    // Long monologue detection (handled elsewhere but can trigger here too)
    const speakingDuration = this.estimateSpeakingDuration(chunk.text);
    if (speakingDuration > 60 && speaker.includes('sales')) {
      return {
        type: 'long_monologue',
        confidence: 0.9,
        timestamp: chunk.timestamp,
        context: 'Sales rep speaking for over 60 seconds',
        severity: 'high',
        urgency: 'immediate',
        suggestedAction: 'Ask a question to re-engage prospect'
      };
    }

    return null;
  }

  private async handleSituation(callId: string, situation: Situation, chunk: TranscriptChunk): Promise<void> {
    switch (situation.type) {
      case 'objection':
        await this.handleObjection(callId, situation.objection!, chunk);
        break;

      case 'competitor_mention':
        await this.handleCompetitorMention(callId, situation.competitor!, chunk);
        break;

      case 'pricing_discussion':
        await this.handlePricingDiscussion(callId, situation.context, chunk);
        break;

      case 'long_monologue':
        await this.handleLongMonologue(callId);
        break;

      case 'buying_signal':
        await this.handleBuyingSignal(callId, situation.buyingSignal!, chunk);
        break;

      case 'pain_point':
        await this.handlePainPoint(callId, situation.painPoint!, chunk);
        break;

      default:
    }
  }

  private async handleObjection(callId: string, objection: string, chunk: TranscriptChunk): Promise<void> {
    const guidance = await this.getObjectionGuidance(objection, chunk);

    this.sendMessage(callId, {
      type: 'guidance',
      content: guidance,
      priority: 'high',
      category: 'objection_handling',
      displayDuration: 15,
      requiresAcknowledgment: true
    });
  }

  private async handleCompetitorMention(callId: string, competitor: string, chunk: TranscriptChunk): Promise<void> {
    const battlecard = await this.getBattlecard(competitor);

    this.sendMessage(callId, {
      type: 'battlecard',
      content: battlecard,
      priority: 'high',
      category: 'competitive',
      displayDuration: 20
    });
  }

  private async handlePricingDiscussion(callId: string, context: string, chunk: TranscriptChunk): Promise<void> {
    const pricingGuidance = await this.getPricingGuidance(context, chunk);

    this.sendMessage(callId, {
      type: 'pricing',
      content: pricingGuidance,
      priority: 'medium',
      category: 'pricing',
      displayDuration: 12
    });
  }

  private async handleLongMonologue(callId: string): Promise<void> {
    const tip: CoachingTip = {
      type: 'talk_time',
      message: 'You\'ve been talking for a while - ask a question to re-engage the prospect',
      priority: 'critical',
      timing: 'immediate',
      actionable: true,
      context: 'Long monologue detected'
    };

    this.sendMessage(callId, {
      type: 'tip',
      content: tip,
      priority: 'critical',
      category: 'engagement'
    });
  }

  private async handleBuyingSignal(callId: string, signal: string, chunk: TranscriptChunk): Promise<void> {
    const tip: CoachingTip = {
      type: 'next_steps',
      message: `Buying signal detected: "${signal}" - Ask about timeline and next steps`,
      priority: 'high',
      timing: 'next_pause',
      actionable: true,
      context: chunk.text
    };

    this.sendMessage(callId, {
      type: 'tip',
      content: tip,
      priority: 'high',
      category: 'opportunity'
    });
  }

  private async handlePainPoint(callId: string, painPoint: string, chunk: TranscriptChunk): Promise<void> {
    const guidance = await this.getPainPointGuidance(painPoint, chunk);

    this.sendMessage(callId, {
      type: 'guidance',
      content: guidance,
      priority: 'medium',
      category: 'discovery',
      displayDuration: 10
    });
  }

  private async getObjectionGuidance(objection: string, chunk: TranscriptChunk): Promise<Guidance> {
    const prompt = `
      The prospect just said: "${objection}"

      This is a sales objection that needs to be handled skillfully.

      Provide coaching guidance with:
      1. What this objection really means (underlying concern)
      2. Discovery questions to understand better
      3. How to reframe the conversation
      4. Social proof or case studies to share
      5. Phrases to avoid
      6. Suggested response phrases

      Keep it brief for quick reading during a live call.

      Return as JSON:
      {
        "type": "objection_handling",
        "title": "string",
        "whatThisMeans": "string",
        "discoveryQuestions": ["string"],
        "reframeApproach": "string",
        "socialProof": ["string"],
        "doNotSay": ["string"],
        "suggestedPhrases": ["string"],
        "urgency": "immediate",
        "effectiveness": number
      }
    `;

    try {
      const response = await this.callAI(prompt);
      return JSON.parse(response);
    } catch (error: any) {
      return this.getFallbackObjectionGuidance(objection);
    }
  }

  private async getBattlecard(competitor: string): Promise<Battlecard> {
    // Check cache first
    if (this.battlecards.has(competitor)) {
      return this.battlecards.get(competitor)!;
    }

    // Generate battlecard dynamically
    const battlecard = await this.generateBattlecard(competitor);
    this.battlecards.set(competitor, battlecard);
    return battlecard;
  }

  private async generateBattlecard(competitor: string): Promise<Battlecard> {
    const prompt = `
      Generate a competitive battlecard for ${competitor}.

      Include:
      1. Their key strengths and how to counter them
      2. Their weaknesses and how to exploit them
      3. Positioning statements
      4. Common objections prospects have about us vs them
      5. Winning messages that differentiate us
      6. Trap questions to expose their weaknesses
      7. Customer success stories vs this competitor

      Return as JSON matching the Battlecard interface.
    `;

    try {
      const response = await this.callAI(prompt);
      return JSON.parse(response);
    } catch (error: any) {
      return this.getFallbackBattlecard(competitor);
    }
  }

  private async getPricingGuidance(context: string, chunk: TranscriptChunk): Promise<PricingGuidance> {
    const prompt = `
      The prospect mentioned pricing in this context: "${context}"

      Provide pricing guidance including:
      1. Best approach (value-first, ROI focus, comparison, etc.)
      2. Value proposition points to emphasize
      3. ROI calculation if appropriate
      4. Competitive comparisons
      5. Negotiation tactics
      6. Red lines (what not to negotiate)
      7. Suggested phrases

      Return as JSON matching PricingGuidance interface.
    `;

    try {
      const response = await this.callAI(prompt);
      return JSON.parse(response);
    } catch (error: any) {
      return this.getFallbackPricingGuidance(context);
    }
  }

  private async getPainPointGuidance(painPoint: string, chunk: TranscriptChunk): Promise<Guidance> {
    const prompt = `
      The prospect mentioned this pain point: "${painPoint}"

      Provide discovery guidance to:
      1. Understand the pain better
      2. Quantify the impact
      3. Explore implications
      4. Connect to our solution
      5. Build urgency

      Return as JSON matching Guidance interface.
    `;

    try {
      const response = await this.callAI(prompt);
      return JSON.parse(response);
    } catch (error: any) {
      return this.getFallbackPainPointGuidance(painPoint);
    }
  }

  private async checkCoachingOpportunities(callId: string, chunk: TranscriptChunk): Promise<void> {
    const speakingData = this.speakingTimeTracker.get(callId);
    if (!speakingData) return;

    const totalTime = speakingData.salesRep + speakingData.prospect;
    if (totalTime < 60) return; // Not enough data yet

    const salesRepRatio = speakingData.salesRep / totalTime;

    // Check talk time balance
    if (salesRepRatio > 0.7) {
      const tip: CoachingTip = {
        type: 'talk_time',
        message: `You're talking ${Math.round(salesRepRatio * 100)}% of the time - ask more questions`,
        priority: 'high',
        timing: 'next_pause',
        actionable: true,
        context: 'Talk time imbalance'
      };

      this.sendMessage(callId, {
        type: 'tip',
        content: tip,
        priority: 'high',
        category: 'coaching'
      });
    }

    // Check for question frequency
    const situations = this.callSituations.get(callId) || [];
    const recentQuestions = situations.filter((s: any) =>
      s.timestamp > Date.now() - 300000 && // Last 5 minutes
      s.context.includes('?')
    );

    if (totalTime > 300 && recentQuestions.length < 2) { // 5 minutes with < 2 questions
      const tip: CoachingTip = {
        type: 'questions',
        message: 'Ask more discovery questions - you haven\'t asked many recently',
        priority: 'medium',
        timing: 'next_pause',
        actionable: true,
        context: 'Low question frequency'
      };

      this.sendMessage(callId, {
        type: 'tip',
        content: tip,
        priority: 'medium',
        category: 'discovery'
      });
    }
  }

  private startPeriodicCoaching(callId: string): void {
    const interval = setInterval(() => {
      const coach = this.activeCoaches.get(callId);
      if (!coach) {
        clearInterval(interval);
        return;
      }

      // Send periodic coaching tips
      this.sendPeriodicTips(callId);
    }, 30000); // Every 30 seconds
  }

  private async sendPeriodicTips(callId: string): Promise<void> {
    const situations = this.callSituations.get(callId) || [];
    const recentSituations = situations.filter((s: any) => s.timestamp > Date.now() - 180000); // Last 3 minutes

    // If no recent activity, send engagement tip
    if (recentSituations.length === 0) {
      const tip: CoachingTip = {
        type: 'energy',
        message: 'Keep the energy up - ask an engaging question about their goals',
        priority: 'low',
        timing: 'when_appropriate',
        actionable: true,
        context: 'Low recent activity'
      };

      this.sendMessage(callId, {
        type: 'tip',
        content: tip,
        priority: 'low',
        category: 'engagement'
      });
    }
  }

  private sendMessage(callId: string, message: Omit<LiveCoachingMessage, 'id' | 'timestamp'>): void {
    const coach = this.activeCoaches.get(callId);
    if (!coach) return;

    const fullMessage: LiveCoachingMessage = {
      id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      ...message
    };

    try {
      coach.send(JSON.stringify(fullMessage));
    } catch (error: any) {
    }
  }

  private updateSpeakingTime(callId: string, chunk: TranscriptChunk): void {
    const speakingData = this.speakingTimeTracker.get(callId);
    if (!speakingData) return;

    const duration = this.estimateSpeakingDuration(chunk.text);
    const isSalesRep = chunk.speaker.toLowerCase().includes('sales') ||
                      chunk.speaker.toLowerCase().includes('rep');

    if (isSalesRep) {
      speakingData.salesRep += duration;
    } else {
      speakingData.prospect += duration;
    }

    speakingData.lastUpdate = Date.now();
    this.speakingTimeTracker.set(callId, speakingData);
  }

  private estimateSpeakingDuration(text: string): number {
    // Estimate speaking duration based on text length
    // Average speaking rate is ~150 words per minute
    const words = text.split(' ').length;
    return (words / 150) * 60; // Convert to seconds
  }

  private assessObjectionSeverity(keyword: string, text: string): 'low' | 'medium' | 'high' {
    const highSeverityKeywords = ['too expensive', 'can\'t afford', 'no budget'];
    const mediumSeverityKeywords = ['need to think', 'not sure', 'have to discuss'];

    if (highSeverityKeywords.some(k => text.toLowerCase().includes(k))) {
      return 'high';
    }
    if (mediumSeverityKeywords.some(k => text.toLowerCase().includes(k))) {
      return 'medium';
    }
    return 'low';
  }

  private cleanupCall(callId: string): void {
    // Clean up resources
    const coach = this.activeCoaches.get(callId);
    if (coach) {
      coach.close();
      this.activeCoaches.delete(callId);
    }

    this.callSituations.delete(callId);
    this.speakingTimeTracker.delete(callId);
  }

  private async callAI(prompt: string): Promise<string> {
    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-3-sonnet-20240229',
          max_tokens: 1500,
          messages: [{
            role: 'user',
            content: prompt
          }],
          temperature: 0.3
        })
      });

      const result = await response.json() as any;
      const content = result.content[0].text;

      // Extract JSON if present
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      return jsonMatch ? jsonMatch[0] : content;
    } catch (error: any) {
      throw error;
    }
  }

  // Fallback methods when AI fails
  private getFallbackObjectionGuidance(objection: string): Guidance {
    return {
      type: 'objection_handling',
      title: 'Objection Detected',
      whatThisMeans: 'The prospect has a concern that needs to be addressed',
      discoveryQuestions: [
        'Can you help me understand your concern better?',
        'What would need to change for this to work?',
        'What\'s driving that concern?'
      ],
      reframeApproach: 'Acknowledge the concern and redirect to value',
      socialProof: ['Similar customers had the same concern initially'],
      doNotSay: ['That\'s not a problem', 'You\'re wrong', 'That\'s not important'],
      suggestedPhrases: [
        'I understand that concern...',
        'That\'s a great question...',
        'Many of our clients initially thought the same thing...'
      ],
      urgency: 'immediate',
      effectiveness: 0.7
    };
  }

  private getFallbackBattlecard(competitor: string): Battlecard {
    return {
      competitor,
      strengths: [
        {
          point: 'Market presence',
          counterStrategy: 'Emphasize our innovation and agility'
        }
      ],
      weaknesses: [
        {
          point: 'Complex implementation',
          howToExploit: 'Highlight our simple setup process',
          proof: 'Customer testimonials about easy implementation'
        }
      ],
      positioning: [
        {
          theirClaim: 'Industry leader',
          ourResponse: 'We\'re the innovation leader',
          differentiation: 'AI-native vs legacy architecture'
        }
      ],
      commonObjections: [
        {
          objection: 'They have more features',
          response: 'We focus on the features that matter most',
          framework: 'Quality over quantity'
        }
      ],
      winningMessages: ['Modern architecture built for AI'],
      trapQuestions: ['How long does it take to implement their solution?'],
      caseStudies: [
        {
          situation: 'Customer switched from ' + competitor,
          outcome: '50% faster implementation',
          metrics: ['6 months faster', '30% cost reduction']
        }
      ]
    };
  }

  private getFallbackPricingGuidance(context: string): PricingGuidance {
    return {
      situation: context,
      approach: 'value_first',
      valueProposition: [
        'Focus on ROI and business impact',
        'Compare total cost of ownership',
        'Highlight implementation speed'
      ],
      negotiationTactics: [
        'Bundle services for better value',
        'Offer flexible payment terms',
        'Emphasize limited-time incentives'
      ],
      redLines: [
        'Minimum viable deal size',
        'Required contract length',
        'Non-negotiable terms'
      ],
      suggestedPhrases: [
        'Let\'s focus on the value you\'ll receive...',
        'The real question is ROI...',
        'When you consider the total cost of ownership...'
      ]
    };
  }

  private getFallbackPainPointGuidance(painPoint: string): Guidance {
    return {
      type: 'discovery',
      title: 'Pain Point Discovery',
      whatThisMeans: 'The prospect revealed a pain point - dig deeper',
      discoveryQuestions: [
        'How is this impacting your team?',
        'What have you tried to solve this?',
        'What would happen if this continues?',
        'How are you measuring this impact?'
      ],
      reframeApproach: 'Connect the pain to business impact and urgency',
      socialProof: ['Other customers had similar challenges'],
      doNotSay: ['That\'s easy to fix', 'Everyone has that problem'],
      suggestedPhrases: [
        'That sounds challenging...',
        'Help me understand the impact...',
        'What would solving this mean for your business?'
      ],
      urgency: 'next_pause',
      effectiveness: 0.8
    };
  }

  private initializeBattlecards(): void {
    // Pre-load common competitor battlecards
    const commonCompetitors = ['Salesforce', 'HubSpot', 'Pipedrive', 'Zoho'];

    for (const competitor of commonCompetitors) {
      // In production, these would be loaded from database
      this.battlecards.set(competitor, this.getFallbackBattlecard(competitor));
    }
  }

  // Public methods for managing coaching
  async updateBattlecard(competitor: string, battlecard: Battlecard): Promise<void> {
    this.battlecards.set(competitor, battlecard);

    // Store in database
    const db = this.env.DB_CRM;
    await db.prepare(`
      INSERT OR REPLACE INTO battlecards (
        competitor, battlecard_data, updated_at
      ) VALUES (?, ?, ?)
    `).bind(
      competitor,
      JSON.stringify(battlecard),
      new Date().toISOString()
    ).run();
  }

  async getCoachingStats(callIds: string[]): Promise<{
    totalMessages: number;
    messagesByType: Record<string, number>;
    averageResponseTime: number;
    effectiveness: number;
  }> {
    // Implementation for coaching analytics
    return {
      totalMessages: 0,
      messagesByType: {},
      averageResponseTime: 0,
      effectiveness: 0
    };
  }

  async getActiveCoaches(): Promise<string[]> {
    return Array.from(this.activeCoaches.keys());
  }
}