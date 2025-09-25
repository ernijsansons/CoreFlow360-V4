import type {
  CalendarSlot,
  ScheduleNegotiation,
  NegotiationRound,
  Conversation,
  Lead,
  MeetingType,
  NegotiationStatus
} from '../types/crm';
import type { Env } from '../types/env';

export class ScheduleNegotiator {
  private availableSlots: CalendarSlot[];
  private leadTimezone: string;
  private env: Env;
  private maxRounds: number = 5;
  private negotiationTimeout: number = 3600000; // 1 hour

  constructor(availableSlots: CalendarSlot[], leadTimezone: string, env: Env) {
    this.availableSlots = availableSlots;
    this.leadTimezone = leadTimezone;
    this.env = env;
  }

  async negotiate(conversation: Conversation, lead: Lead,
  meetingType: MeetingType = 'discovery_call'): Promise<CalendarSlot | null> {
    try {
      // Create negotiation session
      const negotiation = await this.createNegotiation(conversation.id, lead.id || '');

      // Extract scheduling preferences from conversation
      const preferences = await this.extractSchedulingPreferences(conversation.transcript || '');

      // Start negotiation process
      let currentRound = 1;
      let agreedSlot: CalendarSlot | null = null;

      while (currentRound <= this.maxRounds && !agreedSlot) {
        const round = await this.conductNegotiationRound(
          negotiation,
          currentRound,
          preferences,
          conversation,
          meetingType
        );

        if (round.lead_response?.response_type === 'accept') {
          agreedSlot = round.ai_proposal.slots[0]; // First proposed slot was accepted
          negotiation.final_agreed_slot = agreedSlot;
          negotiation.status = 'agreed';
          break;
        }

        if (round.lead_response?.response_type === 'reject') {
          negotiation.status = 'failed';
          break;
        }

        currentRound++;
      }

      if (!agreedSlot && currentRound > this.maxRounds) {
        negotiation.status = 'failed';
      }

      // Save final negotiation state
      await this.saveNegotiation(negotiation);

      return agreedSlot;

    } catch (error) {
      return null;
    }
  }

  private async createNegotiation(conversationId: string, leadId: string): Promise<ScheduleNegotiation> {
    const expiresAt = new Date(Date.now() + this.negotiationTimeout).toISOString();

    return {
      id: this.generateId(),
      lead_id: leadId,
      conversation_id: conversationId,
      proposed_slots: this.availableSlots,
      negotiation_rounds: [],
      status: 'in_progress',
      expires_at: expiresAt,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
  }

  private async extractSchedulingPreferences(transcript: string): Promise<any> {
    // Use AI to extract scheduling preferences from conversation
    const preferencesPrompt = `
      Analyze this conversation transcript and extract scheduling preferences:

      Transcript: "${transcript}"

      Extract and return JSON with:
      - preferred_times: ["morning", "afternoon", "evening"]
      - preferred_days: ["monday", "tuesday", etc.]
      - duration_preference: number in minutes
      - urgency_level: "immediate", "soon", "flexible"
      - meeting_type_preference: type of meeting mentioned
      - timezone_hints: any timezone mentions
      - constraints: any scheduling constraints mentioned

      Focus on explicit statements like "I prefer mornings" or "Tuesday works best".
    `;

    // In real implementation, this would call Claude API
    return this.simulateAIPreferenceExtraction(transcript);
  }

  private async conductNegotiationRound(
    negotiation: ScheduleNegotiation,
    roundNumber: number,
    preferences: any,
    conversation: Conversation,
    meetingType: MeetingType
  ): Promise<NegotiationRound> {

    // AI generates optimal proposal based on preferences and available slots
    const aiProposal = await this.generateAIProposal(
      negotiation.proposed_slots,
      preferences,
      roundNumber,
      meetingType
    );

    // Simulate lead response (in real implementation, this would be from actual conversation)
    const leadResponse = await this.simulateLeadResponse(aiProposal, preferences, roundNumber);

    const round: NegotiationRound = {
      round_number: roundNumber,
      ai_proposal: aiProposal,
      lead_response: leadResponse,
      timestamp: new Date().toISOString()
    };

    negotiation.negotiation_rounds.push(round);
    negotiation.updated_at = new Date().toISOString();

    return round;
  }

  private async generateAIProposal(
    availableSlots: CalendarSlot[],
    preferences: any,
    roundNumber: number,
    meetingType: MeetingType
  ): Promise<{ slots: CalendarSlot[]; reasoning: string; persuasion_strategy?: string }> {

    // Filter slots based on preferences
    let filteredSlots = [...availableSlots];

    if (preferences.preferred_times) {
      filteredSlots = this.filterSlotsByTimeOfDay(filteredSlots, preferences.preferred_times);
    }

    if (preferences.preferred_days) {
      filteredSlots = this.filterSlotsByDayOfWeek(filteredSlots, preferences.preferred_days);
    }

    // Sort by preference match score
    const scoredSlots = filteredSlots.map(slot => ({
      slot,
      score: this.calculateSlotScore(slot, preferences)
    })).sort((a, b) => b.score - a.score);

    // Select top 3 slots to propose
    const topSlots = scoredSlots.slice(0, 3).map(item => item.slot);

    // Generate reasoning and persuasion strategy based on round number
    const reasoning = this.generateReasoning(topSlots, preferences, roundNumber);
    const persuasionStrategy = this.generatePersuasionStrategy(roundNumber, preferences, meetingType);

    return {
      slots: topSlots,
      reasoning,
      persuasion_strategy: persuasionStrategy
    };
  }

  private filterSlotsByTimeOfDay(slots: CalendarSlot[], preferredTimes: string[]): CalendarSlot[] {
    return slots.filter(slot => {
      const hour = new Date(slot.start).getHours();

      for (const timePreference of preferredTimes) {
        switch (timePreference.toLowerCase()) {
          case 'morning':
            if (hour >= 9 && hour < 12) return true;
            break;
          case 'afternoon':
            if (hour >= 12 && hour < 17) return true;
            break;
          case 'evening':
            if (hour >= 17 && hour < 20) return true;
            break;
        }
      }
      return false;
    });
  }

  private filterSlotsByDayOfWeek(slots: CalendarSlot[], preferredDays: string[]): CalendarSlot[] {
    const dayMap = {
      'sunday': 0, 'monday': 1, 'tuesday': 2, 'wednesday': 3,
      'thursday': 4, 'friday': 5, 'saturday': 6
    };

    return slots.filter(slot => {
      const dayOfWeek = new Date(slot.start).getDay();
      return preferredDays.some(day => dayMap[day.toLowerCase() as keyof typeof dayMap] === dayOfWeek);
    });
  }

  private calculateSlotScore(slot: CalendarSlot, preferences: any): number {
    let score = 100; // Base score

    const hour = new Date(slot.start).getHours();
    const dayOfWeek = new Date(slot.start).getDay();

    // Time of day preference scoring
    if (preferences.preferred_times) {
      let timeMatch = false;
      for (const timePreference of preferences.preferred_times) {
        switch (timePreference.toLowerCase()) {
          case 'morning':
            if (hour >= 9 && hour < 12) timeMatch = true;
            break;
          case 'afternoon':
            if (hour >= 12 && hour < 17) timeMatch = true;
            break;
          case 'evening':
            if (hour >= 17 && hour < 20) timeMatch = true;
            break;
        }
      }
      if (timeMatch) score += 50;
    }

    // Day of week preference scoring
    if (preferences.preferred_days) {
      const dayMap = {
        'sunday': 0, 'monday': 1, 'tuesday': 2, 'wednesday': 3,
        'thursday': 4, 'friday': 5, 'saturday': 6
      };

      const dayMatch = preferences.preferred_days.some((day: string) =>
        dayMap[day.toLowerCase() as keyof typeof dayMap] === dayOfWeek
      );

      if (dayMatch) score += 30;
    }

    // Urgency scoring - prefer sooner slots for urgent requests
    if (preferences.urgency_level === 'immediate') {
      const hoursFromNow = (new Date(slot.start).getTime() - Date.now()) / (1000 * 60 * 60);
      if (hoursFromNow < 24) score += 40;
      else if (hoursFromNow < 48) score += 20;
    }

    // Business hours scoring (prefer standard business hours)
    if (hour >= 9 && hour <= 17 && dayOfWeek >= 1 && dayOfWeek <= 5) {
      score += 20;
    }

    return score;
  }

  private generateReasoning(slots: CalendarSlot[], preferences: any, roundNumber: number): string {
    if (roundNumber === 1) {
      return `Based on your preferences, I've
  found these optimal time slots that align with your availability and scheduling needs.`;
    } else if (roundNumber === 2) {
      return `I understand your constraints. Let
  me suggest these alternative times that might work better for your schedule.`;
    } else {
      return `I want to find a time
  that works perfectly for you. Here are some flexible options that accommodate your requirements.`;
    }
  }

  private generatePersuasionStrategy(roundNumber: number, preferences: any, meetingType: MeetingType): string {
    const strategies = {
      1: 'value_proposition',
      2: 'flexibility_emphasis',
      3: 'urgency_gentle',
      4: 'relationship_building',
      5: 'final_opportunity'
    };

    const strategy = strategies[roundNumber as keyof typeof strategies] || 'relationship_building';

    switch (strategy) {
      case 'value_proposition':
        return `This ${meetingType.replace('_', ' ')} will help
  us understand your specific needs and show you exactly how we can solve your challenges.`;

      case 'flexibility_emphasis':
        return `I'm happy to work around your schedule. These times are flexible and can be adjusted if needed.`;

      case 'urgency_gentle':
        return `I'd love to get this
  scheduled soon so we can start addressing your needs and move forward with a solution.`;

      case 'relationship_building':
        return `Finding the right time for both of us
  is important. I want to make sure we have a productive conversation that works for your schedule.`;

      case 'final_opportunity':
        return `Let's find a time that works. These are
  the most flexible options I have available, and I'm confident we can make one of them work.`;

      default:
        return `I'm committed to finding a time that works perfectly for both of us.`;
    }
  }

  private async simulateLeadResponse(
    aiProposal: any,
    preferences: any,
    roundNumber: number
  ): Promise<{ response_type: 'accept' | 'counter' |
  'reject' | 'request_different'; feedback: string; counter_proposal?: CalendarSlot[] }> {

    // Simulate different response patterns based on round number and slot quality
    const slotScore = this.calculateSlotScore(aiProposal.slots[0], preferences);

    if (slotScore > 150) {
      return {
        response_type: 'accept',
        feedback: 'Perfect! That time works great for me.'
      };
    } else if (slotScore > 120 && roundNumber <= 2) {
      return {
        response_type: 'counter',
        feedback: 'That could work, but do you have anything earlier in the day?'
      };
    } else if (roundNumber >= 4) {
      return {
        response_type: 'accept',
        feedback: 'Okay, let\'s go with the first option.'
      };
    } else {
      return {
        response_type: 'request_different',
        feedback: 'I\'m not available at those times. Do you have any morning slots?'
      };
    }
  }

  private simulateAIPreferenceExtraction(transcript: string): any {
    // Simulate preference extraction (in real implementation, would use Claude API)
    const preferences: any = {
      preferred_times: [],
      preferred_days: [],
      urgency_level: 'flexible'
    };

    // Simple pattern matching for demonstration
    if (/morning/i.test(transcript)) preferences.preferred_times.push('morning');
    if (/afternoon/i.test(transcript)) preferences.preferred_times.push('afternoon');
    if (/evening/i.test(transcript)) preferences.preferred_times.push('evening');

    if (/monday/i.test(transcript)) preferences.preferred_days.push('monday');
    if (/tuesday/i.test(transcript)) preferences.preferred_days.push('tuesday');
    if (/wednesday/i.test(transcript)) preferences.preferred_days.push('wednesday');
    if (/thursday/i.test(transcript)) preferences.preferred_days.push('thursday');
    if (/friday/i.test(transcript)) preferences.preferred_days.push('friday');

    if (/urgent|asap|soon/i.test(transcript)) preferences.urgency_level = 'immediate';
    if (/flexible|anytime/i.test(transcript)) preferences.urgency_level = 'flexible';

    // Default to business hours if no preferences extracted
    if (preferences.preferred_times.length === 0) {
      preferences.preferred_times = ['morning', 'afternoon'];
    }
    if (preferences.preferred_days.length === 0) {
      preferences.preferred_days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'];
    }

    return preferences;
  }

  private async saveNegotiation(negotiation: ScheduleNegotiation): Promise<void> {
    // In real implementation, save to database
  }

  private generateId(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }

  // Helper method to analyze conversation for meeting booking intent
  static async detectBookingIntent(transcript: string): Promise<{
    hasBookingIntent: boolean;
    confidence: number;
    preferredMeetingType?: MeetingType;
    urgency?: 'immediate' | 'soon' | 'flexible';
    extractedPreferences?: any;
  }> {
    const bookingKeywords = [
      'schedule', 'book', 'meet', 'call', 'appointment', 'demo', 'consultation',
      'available', 'free time', 'calendar', 'when can', 'what time'
    ];

    const urgentKeywords = ['urgent', 'asap', 'soon', 'quickly', 'immediate'];
    const flexibleKeywords = ['flexible', 'anytime', 'whenever', 'no rush'];

    let bookingScore = 0;
    const words = transcript.toLowerCase().split(/\s+/);

    // Count booking-related keywords
    for (const word of words) {
      if (bookingKeywords.some(keyword => word.includes(keyword))) {
        bookingScore++;
      }
    }

    const confidence = Math.min(bookingScore / words.length * 100, 0.95);
    const hasBookingIntent = confidence > 0.3;

    let urgency: 'immediate' | 'soon' | 'flexible' = 'flexible';
    if (urgentKeywords.some(keyword => transcript.toLowerCase().includes(keyword))) {
      urgency = 'immediate';
    } else if (transcript.toLowerCase().includes('soon')) {
      urgency = 'soon';
    }

    // Detect meeting type preference
    let preferredMeetingType: MeetingType | undefined;
    if (/demo/i.test(transcript)) preferredMeetingType = 'demo';
    else if (/consultation/i.test(transcript)) preferredMeetingType = 'consultation';
    else if (/discovery|learn|understand/i.test(transcript)) preferredMeetingType = 'discovery_call';
    else if (/follow.?up/i.test(transcript)) preferredMeetingType = 'follow_up';

    return {
      hasBookingIntent,
      confidence,
      preferredMeetingType,
      urgency,
      extractedPreferences: {
        meeting_type: preferredMeetingType,
        urgency_level: urgency
      }
    };
  }
}