import type {
  Lead,
  Voicemail,
  VoicemailTemplate,
  VoicemailType,
  VoiceSettings,
  PersonalizationLevel,
  VoicemailDeliveryStatus,
  LeaveVoicemailTaskPayload,
  VoicemailFollowUp,
  FollowUpType,
  ContactMethod
} from '../types/crm';
import type { Env } from '../types/env';

export class VoicemailHandler {
  private env: Env;
  private voiceSynthesizer: VoiceSynthesizer;
  private twilioService: any; // Would be actual Twilio service

  constructor(env: Env) {
    this.env = env;
    this.voiceSynthesizer = new VoiceSynthesizer(env);
  }

  /**
   * Leave an intelligent voicemail for a lead
   */
  async leaveVoicemail(
    lead: Lead,
    callAttempt: number,
    options?: {
      voicemailType?: VoicemailType;
      campaignId?: string;
      personalizationData?: any;
      voiceSettings?: Partial<VoiceSettings>;
    }
  ): Promise<Voicemail | null> {
    try {
      // Generate personalized voicemail message
      const voicemailText = await this.generateVoicemail(lead, callAttempt, options);

      // Get voice settings based on attempt number and lead profile
      const voiceSettings = this.determineVoiceSettings(lead, callAttempt, options?.voiceSettings);

      // Convert text to speech
      const audio = await this.textToSpeech(voicemailText, voiceSettings);

      // Play/deliver the audio
      const delivered = await this.playAudio(audio, lead);

      // Create voicemail record
      const voicemail = await this.createVoicemailRecord({
        lead,
        callAttempt,
        voicemailText,
        audio,
        voiceSettings,
        delivered,
        voicemailType: options?.voicemailType || this.determineVoicemailType(callAttempt),
        campaignId: options?.campaignId
      });

      // Schedule follow-up
      await this.scheduleNextAttempt(lead, callAttempt + 1, voicemail);

      // Analyze voicemail effectiveness
      await this.analyzeVoicemailEffectiveness(voicemail);

      return voicemail;

    } catch (error) {
      return null;
    }
  }

  /**
   * Generate personalized voicemail message based on lead data and attempt number
   */
  async generateVoicemail(
    lead: Lead,
    callAttempt: number,
    options?: {
      voicemailType?: VoicemailType;
      personalizationData?: any;
    }
  ): Promise<string> {
    // Get appropriate template based on attempt number and type
    const template = await this.getVoicemailTemplate(
      options?.voicemailType || this.determineVoicemailType(callAttempt),
      callAttempt
    );

    // Determine personalization level based on available data
    const personalizationLevel = this.determinePersonalizationLevel(lead, options?.personalizationData);

    // Generate message based on attempt strategy
    let message = '';

    switch (callAttempt) {
      case 1:
      
   message = await this.generateFirstAttemptMessage(lead, template, personalizationLevel, options?.personalizationData);
        break;
      case 2:
      
   message = await this.generateSecondAttemptMessage(lead, template, personalizationLevel, options?.personalizationData);
        break;
      case 3:
      
   message = await this.generateThirdAttemptMessage(lead, template, personalizationLevel, options?.personalizationData);
        break;
      default:
      
   message = await this.generateFinalAttemptMessage(lead, template, personalizationLevel, options?.personalizationData);
        break;
    }

    // Ensure message is within duration limits
    return this.optimizeMessageLength(message, template.max_duration_seconds);
  }

  private async generateFirstAttemptMessage(
    lead: Lead,
    template: VoicemailTemplate,
    personalizationLevel: PersonalizationLevel,
    personalizationData?: any
  ): Promise<string> {
    let message = template.message_template;

    // Basic personalization
    message = message
      .replace('{lead_name}', `${lead.first_name} ${lead.last_name}`.trim() || 'there')
      .replace('{company_name}', lead.company_name || 'your company')
      .replace('{rep_name}', personalizationData?.rep_name || 'the team');

    // Add value proposition for first attempt
    if (personalizationLevel === 'high' || personalizationLevel === 'hyper_personalized') {
      const valueProposition = personalizationData?.value_proposition ||
        `help ${lead.company_name || 'companies like yours'} improve efficiency and reduce costs`;

      message += ` I wanted to discuss how we can ${valueProposition}.`;
    }

    // Add call to action
    message += ` ${template.call_to_action}`;

    return message;
  }

  private async generateSecondAttemptMessage(
    lead: Lead,
    template: VoicemailTemplate,
    personalizationLevel: PersonalizationLevel,
    personalizationData?: any
  ): Promise<string> {
    // Second attempt - reference previous attempt and add urgency
    let message = `Hi ${lead.first_name || 'there'}, this is a quick follow-up to my previous message. `;

    if (personalizationData?.recent_interaction) {
      message += `I noticed ${personalizationData.recent_interaction}. `;
    }

    // Add different angle or benefit
    if (personalizationData?.pain_points && personalizationData.pain_points.length > 0) {
      const painPoint = personalizationData.pain_points[0];
      message += `I have some ideas on how to address ${painPoint} that I'd love to share with you. `;
    } else {
      message += `I have some time-sensitive information that could benefit your business. `;
    }

    message += template.call_to_action;

    return message;
  }

  private async generateThirdAttemptMessage(
    lead: Lead,
    template: VoicemailTemplate,
    personalizationLevel: PersonalizationLevel,
    personalizationData?: any
  ): Promise<string> {
    // Third attempt - pattern interrupt, different approach
    let message = `${lead.first_name || 'Hi'}, I know you're busy, so I'll be brief. `;

    // Use social proof or case study
    if (personalizationData?.case_study) {
      message += `We recently helped ${personalizationData.case_study} achieve remarkable results. `;
    } else {
      message += `We've helped similar companies in your industry save significant time and money. `;
    }

    // Create urgency
    message += `I'm only reaching out to a select few companies this quarter. `;
    message += `If this isn't a priority right now, just let me know and I'll follow up next quarter. `;

    message += template.call_to_action;

    return message;
  }

  private async generateFinalAttemptMessage(
    lead: Lead,
    template: VoicemailTemplate,
    personalizationLevel: PersonalizationLevel,
    personalizationData?: any
  ): Promise<string> {
    // Final attempt - respectful closure with open door
    let message = `Hi ${lead.first_name || 'there'}, this will be my last attempt to reach you for now. `;

    message += `I understand timing might not be right. `;
    message += `I'll send you some helpful resources via email that you can review when convenient. `;
    message += `Feel free to reach out anytime if priorities change. `;

    message += `Wishing you and ${lead.company_name || 'your team'} continued success!`;

    return message;
  }

  /**
   * Convert text to speech with specified voice settings
   */
  async textToSpeech(
    text: string,
    voiceSettings: VoiceSettings
  ): Promise<AudioData> {
    return await this.voiceSynthesizer.synthesize(text, voiceSettings);
  }

  /**
   * Play audio through phone system or save to voicemail
   */
  async playAudio(audio: AudioData, lead: Lead): Promise<boolean> {
    try {
      // In real implementation, this would interface with Twilio or similar

      // Simulate voicemail delivery
      return true;

    } catch (error) {
      return false;
    }
  }

  /**
   * Schedule next follow-up attempt
   */
  async scheduleNextAttempt(
    lead: Lead,
    nextAttemptNumber: number,
    voicemail: Voicemail
  ): Promise<void> {
    try {
      // Determine optimal follow-up time based on patterns
      const optimalTime = await this.calculateOptimalFollowUpTime(lead, nextAttemptNumber);

      // Determine follow-up method based on attempt number
      const followUpMethod = this.determineFollowUpMethod(nextAttemptNumber);

      // Create follow-up record
      const followUp: Partial<VoicemailFollowUp> = {
        voicemail_id: voicemail.id,
        lead_id: lead.id || '',
        follow_up_type: followUpMethod === 'call' ? 'call_attempt' : followUpMethod as FollowUpType,
        scheduled_time: optimalTime.toISOString(),
        status: 'scheduled',
        method: followUpMethod as ContactMethod,
        created_at: new Date().toISOString()
      };

      await this.saveFollowUp(followUp);

      // Schedule AI task for follow-up
      await this.scheduleFollowUpTask({
        lead_id: lead.id || '',
        voicemail_id: voicemail.id,
        attempt_number: nextAttemptNumber,
        scheduled_time: optimalTime,
        method: followUpMethod
      });

    } catch (error) {
    }
  }

  /**
   * Determine voice settings based on lead profile and attempt number
   */
  private determineVoiceSettings(
    lead: Lead,
    callAttempt: number,
    customSettings?: Partial<VoiceSettings>
  ): VoiceSettings {
    const baseSettings: VoiceSettings = {
      voice: 'professional_female',
      pace: 'moderate',
      emotion: 'friendly',
      language: 'en-US',
      pitch: 0,
      volume: 0.8
    };

    // Adjust based on attempt number
    switch (callAttempt) {
      case 1:
        baseSettings.emotion = 'enthusiastic';
        baseSettings.pace = 'normal';
        break;
      case 2:
        baseSettings.emotion = 'professional';
        baseSettings.pace = 'moderate';
        break;
      case 3:
        baseSettings.emotion = 'empathetic';
        baseSettings.pace = 'moderate';
        break;
      default:
        baseSettings.emotion = 'warm';
        baseSettings.pace = 'slow';
        break;
    }

    // Adjust based on lead's industry/role
    if (lead.seniority_level === 'c_level' || lead.seniority_level === 'vp') {
      baseSettings.voice = 'professional_male';
      baseSettings.emotion = 'professional';
    }

    // Apply custom settings
    return { ...baseSettings, ...customSettings };
  }

  /**
   * Determine voicemail type based on attempt number and context
   */
  private determineVoicemailType(callAttempt: number): VoicemailType {
    switch (callAttempt) {
      case 1:
        return 'initial_outreach';
      case 2:
      case 3:
        return 'follow_up';
      default:
        return 'nurture';
    }
  }

  /**
   * Determine personalization level based on available data
   */
  private determinePersonalizationLevel(lead: Lead, personalizationData?: any): PersonalizationLevel {
    let dataPoints = 0;

    if (lead.first_name) dataPoints++;
    if (lead.company_name) dataPoints++;
    if (lead.ai_qualification_score) dataPoints++;
    if (personalizationData?.pain_points) dataPoints++;
    if (personalizationData?.recent_interaction) dataPoints++;
    if (personalizationData?.value_proposition) dataPoints++;

    if (dataPoints >= 5) return 'hyper_personalized';
    if (dataPoints >= 4) return 'high';
    if (dataPoints >= 2) return 'moderate';
    if (dataPoints >= 1) return 'basic';
    return 'generic';
  }

  /**
   * Calculate optimal follow-up time based on lead patterns
   */
  private async calculateOptimalFollowUpTime(lead: Lead, attemptNumber: number): Promise<Date> {
    const now = new Date();
    let delayHours = 24; // Default delay

    // Adjust delay based on attempt number
    switch (attemptNumber) {
      case 2:
        delayHours = 48; // 2 days
        break;
      case 3:
        delayHours = 72; // 3 days
        break;
      case 4:
        delayHours = 120; // 5 days
        break;
      default:
        delayHours = 168; // 1 week
        break;
    }

    const followUpTime = new Date(now.getTime() + delayHours * 60 * 60 * 1000);

    // Adjust to business hours (9 AM - 5 PM)
    const hour = followUpTime.getHours();
    if (hour < 9) {
      followUpTime.setHours(9, 0, 0, 0);
    } else if (hour >= 17) {
      followUpTime.setDate(followUpTime.getDate() + 1);
      followUpTime.setHours(9, 0, 0, 0);
    }

    // Skip weekends
    const dayOfWeek = followUpTime.getDay();
    if (dayOfWeek === 0) { // Sunday
      followUpTime.setDate(followUpTime.getDate() + 1);
    } else if (dayOfWeek === 6) { // Saturday
      followUpTime.setDate(followUpTime.getDate() + 2);
    }

    return followUpTime;
  }

  /**
   * Determine follow-up method based on attempt number
   */
  private determineFollowUpMethod(attemptNumber: number): string {
    if (attemptNumber <= 3) return 'call';
    if (attemptNumber === 4) return 'email';
    if (attemptNumber === 5) return 'sms';
    return 'email'; // Default to email for later attempts
  }

  /**
   * Optimize message length to fit within duration limits
   */
  private optimizeMessageLength(message: string, maxDurationSeconds: number): string {
    // Approximate words per second (average speaking rate)
    const wordsPerSecond = 2.5;
    const maxWords = maxDurationSeconds * wordsPerSecond;

    const words = message.split(/\s+/);
    if (words.length <= maxWords) {
      return message;
    }

    // Truncate and add closing
    const truncated = words.slice(0, maxWords - 10).join(' ');
    return `${truncated}... Please give me a call back when you get a chance. Thank you!`;
  }

  /**
   * Get appropriate voicemail template
   */
  private async getVoicemailTemplate(
    voicemailType: VoicemailType,
    attemptNumber: number
  ): Promise<VoicemailTemplate> {
    // In real implementation, fetch from database
    // For now, return a default template
    return {
      id: 'default',
      business_id: 'default',
      name: `${voicemailType} - Attempt ${attemptNumber}`,
      voicemail_type: voicemailType,
      attempt_range: { min: attemptNumber, max: attemptNumber },
      message_template: this.getDefaultTemplate(voicemailType, attemptNumber),
      personalization_fields: ['lead_name', 'company_name', 'rep_name'],
      voice_settings: {
        voice: 'professional_female',
        pace: 'moderate',
        emotion: 'friendly',
        language: 'en-US'
      },
      call_to_action: 'Please give me a call back at your earliest convenience.',
      urgency_level: attemptNumber <= 2 ? 'medium' : 'low',
      max_duration_seconds: 30,
      follow_up_delay_hours: attemptNumber * 24,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
  }

  private getDefaultTemplate(voicemailType: VoicemailType, attemptNumber: number): string {
    const templates: Record<string, string> = {
      'initial_outreach': 'Hi {lead_name}, this is {rep_name}. I\'m reaching out to {company_name} because',
      'follow_up': 'Hi {lead_name}, {rep_name} here following up on my previous message.',
      'appointment_reminder': 'Hi {lead_name}, this is a reminder about our upcoming meeting',
      'missed_meeting': 'Hi {lead_name}, we had a meeting scheduled but I wasn\'t able to connect with you.',
      'proposal_follow_up': 'Hi {lead_name}, I wanted to follow up on the proposal we sent over.',
      'nurture': 'Hi {lead_name}, I hope you\'re doing well. I wanted to share something that might interest you.',
      'win_back': 'Hi {lead_name}, it\'s been a while since we last connected.',
      'thank_you': 'Hi {lead_name}, I wanted to thank you for your time.',
      'urgent': 'Hi {lead_name}, this is an urgent message regarding',
      'custom': 'Hi {lead_name}, this is {rep_name} from'
    };

    return templates[voicemailType] || templates['custom'];
  }

  /**
   * Create and save voicemail record
   */
  private async createVoicemailRecord(data: {
    lead: Lead;
    callAttempt: number;
    voicemailText: string;
    audio: AudioData;
    voiceSettings: VoiceSettings;
    delivered: boolean;
    voicemailType: VoicemailType;
    campaignId?: string;
  }): Promise<Voicemail> {
    const voicemail: Voicemail = {
      id: this.generateId(),
      business_id: data.lead.business_id,
      lead_id: data.lead.id || '',
      contact_id: data.lead.contact_id,
      attempt_number: data.callAttempt,
      voicemail_type: data.voicemailType,
      message_text: data.voicemailText,
      message_duration_seconds: data.audio.duration,
      audio_url: data.audio.url,
      ai_generated: true,
      personalization_level: this.determinePersonalizationLevel(data.lead),
      voice_settings: data.voiceSettings,
      delivery_status: data.delivered ? 'delivered' : 'failed',
      delivered_at: data.delivered ? new Date().toISOString() : undefined,
      listened: false,
      response_received: false,
      follow_up_scheduled: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Save to database (in real implementation)
    await this.saveVoicemail(voicemail);

    return voicemail;
  }

  /**
   * Analyze voicemail effectiveness using AI
   */
  private async analyzeVoicemailEffectiveness(voicemail: Voicemail): Promise<void> {
    try {
      // Calculate sentiment score
      const sentimentScore = await this.analyzeSentiment(voicemail.message_text);

      // Calculate effectiveness based on historical data
      const effectivenessScore = await this.calculateEffectivenessScore(voicemail);

      // Update voicemail record
      voicemail.sentiment_score = sentimentScore;
      voicemail.effectiveness_score = effectivenessScore;

      await this.saveVoicemail(voicemail);

    } catch (error) {
    }
  }

  private async analyzeSentiment(text: string): Promise<number> {
    // Simple sentiment analysis (in real implementation, use AI service)
    const positiveWords = ['great', 'excellent', 'opportunity', 'benefit', 'help', 'value', 'save'];
    const negativeWords = ['sorry', 'unfortunately', 'last', 'final'];

    let score = 0.5; // Neutral baseline

    const words = text.toLowerCase().split(/\s+/);
    for (const word of words) {
      if (positiveWords.includes(word)) score += 0.05;
      if (negativeWords.includes(word)) score -= 0.05;
    }

    return Math.max(0, Math.min(1, score));
  }

  private async calculateEffectivenessScore(voicemail: Voicemail): Promise<number> {
    // Factors that contribute to effectiveness
    let score = 0.5;

    // Personalization increases effectiveness
    switch (voicemail.personalization_level) {
      case 'hyper_personalized': score += 0.3; break;
      case 'high': score += 0.2; break;
      case 'moderate': score += 0.1; break;
      case 'basic': score += 0.05; break;
    }

    // Optimal message length (20-30 seconds)
    if (voicemail.message_duration_seconds >= 20 && voicemail.message_duration_seconds <= 30) {
      score += 0.1;
    }

    // Voice emotion effectiveness
    if (['friendly', 'enthusiastic', 'warm'].includes(voicemail.voice_settings.emotion)) {
      score += 0.05;
    }

    // Attempt number (earlier attempts are more effective)
    if (voicemail.attempt_number === 1) score += 0.1;
    else if (voicemail.attempt_number === 2) score += 0.05;

    return Math.min(1, score);
  }

  // Database operations (mock implementations)
  private async saveVoicemail(voicemail: Voicemail): Promise<void> {
  }

  private async saveFollowUp(followUp: Partial<VoicemailFollowUp>): Promise<void> {
  }

  private async scheduleFollowUpTask(task: any): Promise<void> {
  }

  private generateId(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }

  // Batch operations for campaigns
  async processVoicemailCampaign(campaignId: string): Promise<{
    processed: number;
    successful: number;
    failed: number;
  }> {
    try {
      // Get campaign details
      const campaign = await this.getVoicemailCampaign(campaignId);
      if (!campaign) {
        throw new Error('Campaign not found');
      }

      // Get target leads
      const leads = await this.getCampaignTargetLeads(campaign);

      let processed = 0;
      let successful = 0;
      let failed = 0;

      // Process each lead
      for (const lead of leads) {
        try {
          const voicemail = await this.leaveVoicemail(lead, 1, {
            campaignId,
            voicemailType: 'initial_outreach'
          });

          processed++;
          if (voicemail) {
            successful++;
          } else {
            failed++;
          }

        } catch (error) {
          failed++;
          processed++;
        }

        // Rate limiting
        await this.delay(1000); // 1 second between calls
      }

      return { processed, successful, failed };

    } catch (error) {
      return { processed: 0, successful: 0, failed: 0 };
    }
  }

  private async getVoicemailCampaign(campaignId: string): Promise<any> {
    // Mock implementation
    return { id: campaignId };
  }

  private async getCampaignTargetLeads(campaign: any): Promise<Lead[]> {
    // Mock implementation
    return [];
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Voice synthesizer service
class VoiceSynthesizer {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async synthesize(text: string, settings: VoiceSettings): Promise<AudioData> {
    try {
      // In real implementation, this would use a TTS service like:
      // - Amazon Polly
      // - Google Cloud Text-to-Speech
      // - Azure Cognitive Services Speech
      // - ElevenLabs


      // Mock audio data
      return {
        url: `https://storage.example.com/voicemails/${Date.now()}.mp3`,
        duration: Math.ceil(text.split(' ').length / 2.5), // Approximate duration
        format: 'mp3',
        sampleRate: 16000,
        bitRate: 128
      };

    } catch (error) {
      throw error;
    }
  }
}

interface AudioData {
  url: string;
  duration: number; // seconds
  format: string;
  sampleRate: number;
  bitRate: number;
}