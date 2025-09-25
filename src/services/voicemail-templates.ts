import type {
  VoicemailTemplate,
  VoicemailType,
  VoiceSettings,
  UrgencyLevel,
  Lead
} from '../types/crm';

export // TODO: Consider splitting VoicemailTemplateManager into smaller, focused classes
class VoicemailTemplateManager {
  private templates: Map<string, VoicemailTemplate[]> = new Map();

  constructor() {
    this.initializeDefaultTemplates();
  }

  /**
   * Initialize default voicemail templates for various scenarios
   */
  private initializeDefaultTemplates(): void {
    // Initial Outreach Templates (Attempt 1)
    this.addTemplate({
      id: 'initial_professional',
      business_id: 'default',
      name: 'Professional Initial Outreach',
      voicemail_type: 'initial_outreach',
      attempt_range: { min: 1, max: 1 },
      message_template: `Hi {lead_name}, this is {rep_name} from {company}. I'm reaching out because I noticed {trigger_event}. Many companies in {industry} are leveraging our solution to
  {value_prop}. I'd love to share how we've helped {similar_company} achieve {specific_result}. Please give me a call back at {callback_number} or feel free to reply to my email. Looking forward to connecting!`,
      personalization_fields: ['lead_name',
  'rep_name', 'company', 'trigger_event', 'industry', 'value_prop', 'similar_company', 'specific_result', 'callback_number'],
      voice_settings: {
        voice: 'professional_female',
        pace: 'moderate',
        emotion: 'enthusiastic',
        language: 'en-US'
      },
      call_to_action: 'Please give me a call back at your earliest convenience.',
      urgency_level: 'medium',
      max_duration_seconds: 30,
      follow_up_delay_hours: 48,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    this.addTemplate({
      id: 'initial_friendly',
      business_id: 'default',
      name: 'Friendly Initial Outreach',
      voicemail_type: 'initial_outreach',
      attempt_range: { min: 1, max: 1 },
      message_template: `Hey {lead_name}! {rep_name} here from {company}. I was just reviewing {company_name} and was really impressed by {compliment}. I have some ideas that
  could help you {benefit}. I promise to keep our call brief and valuable. Give me a ring at {callback_number} when you have 5 minutes. Thanks, and have a great day!`,
      personalization_fields:
  ['lead_name', 'rep_name', 'company', 'company_name', 'compliment', 'benefit', 'callback_number'],
      voice_settings: {
        voice: 'friendly_male',
        pace: 'normal',
        emotion: 'friendly',
        language: 'en-US'
      },
      call_to_action: 'Would love to connect when you have a few minutes!',
      urgency_level: 'low',
      max_duration_seconds: 25,
      follow_up_delay_hours: 48,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    // Follow-up Templates (Attempts 2-3)
    this.addTemplate({
      id: 'followup_value',
      business_id: 'default',
      name: 'Value-Based Follow-up',
      voicemail_type: 'follow_up',
      attempt_range: { min: 2, max: 2 },
      message_template: `Hi {lead_name}, {rep_name} again from {company}. I wanted to follow up on my previous message about {previous_topic}. Since we last spoke, we've helped
  {case_study_company} reduce their {metric} by {percentage}%. I have a {duration}-minute case study that's directly relevant to {company_name}. Text me at {sms_number} if you'd prefer that, or call me at {callback_number}. Thanks!`,
      personalization_fields: ['lead_name', 'rep_name',
  'company', 'previous_topic', 'case_study_company', 'metric', 'percentage', 'duration', 'company_name', 'sms_number', 'callback_number'],
      voice_settings: {
        voice: 'professional_male',
        pace: 'moderate',
        emotion: 'professional',
        language: 'en-US'
      },
      call_to_action: 'I\'d love to share this with you - just need 5 minutes of your time.',
      urgency_level: 'medium',
      max_duration_seconds: 28,
      follow_up_delay_hours: 72,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    this.addTemplate({
      id: 'followup_pattern_interrupt',
      business_id: 'default',
      name: 'Pattern Interrupt Follow-up',
      voicemail_type: 'follow_up',
      attempt_range: { min: 3, max: 3 },
      message_template: `{lead_name}, I know I'm being persistent, and I apologize if my timing has been off. Here's the thing - I only reach out this much when I genuinely believe we
  can help. {company_name} is leaving money on the table without {solution}. I'll send you a 2-minute video showing exactly what I mean. If it's not relevant, just let me know and I'll stop reaching out. Fair enough? {callback_number}`,
      personalization_fields: ['lead_name', 'company_name', 'solution', 'callback_number'],
      voice_settings: {
        voice: 'conversational',
        pace: 'moderate',
        emotion: 'empathetic',
        language: 'en-US'
      },
      call_to_action: 'Just let me know either way - I respect your time.',
      urgency_level: 'low',
      max_duration_seconds: 25,
      follow_up_delay_hours: 120,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    // Appointment Reminder Templates
    this.addTemplate({
      id: 'appointment_reminder_friendly',
      business_id: 'default',
      name: 'Friendly Appointment Reminder',
      voicemail_type: 'appointment_reminder',
      attempt_range: { min: 1, max: 99 },
      message_template: `Hi {lead_name}! Just a quick reminder about our {meeting_type} scheduled for {meeting_time}. I'm looking forward to
  discussing {meeting_topic}. If you need to reschedule, just give me a call at {callback_number} or reply to the calendar invite. See you soon!`,
      personalization_fields: ['lead_name', 'meeting_type', 'meeting_time', 'meeting_topic', 'callback_number'],
      voice_settings: {
        voice: 'friendly_female',
        pace: 'normal',
        emotion: 'warm',
        language: 'en-US'
      },
      call_to_action: 'Looking forward to our conversation!',
      urgency_level: 'medium',
      max_duration_seconds: 20,
      follow_up_delay_hours: 24,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    // Missed Meeting Templates
    this.addTemplate({
      id: 'missed_meeting_understanding',
      business_id: 'default',
      name: 'Understanding Missed Meeting',
      voicemail_type: 'missed_meeting',
      attempt_range: { min: 1, max: 99 },
      message_template: `Hi {lead_name}, this is {rep_name}. We had a meeting scheduled for {meeting_time} but weren't able to connect. I know things come up - no worries at
  all! I'm still available if you'd like to reschedule. I have openings {available_times}. Just give me a call at {callback_number} or click the reschedule link I'm sending via email. Hope everything is okay!`,
      personalization_fields: ['lead_name', 'rep_name', 'meeting_time', 'available_times', 'callback_number'],
      voice_settings: {
        voice: 'professional_female',
        pace: 'moderate',
        emotion: 'empathetic',
        language: 'en-US'
      },
      call_to_action: 'Let\'s find a time that works better for you.',
      urgency_level: 'low',
      max_duration_seconds: 25,
      follow_up_delay_hours: 4,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    // Proposal Follow-up Templates
    this.addTemplate({
      id: 'proposal_followup_executive',
      business_id: 'default',
      name: 'Executive Proposal Follow-up',
      voicemail_type: 'proposal_follow_up',
      attempt_range: { min: 1, max: 99 },
      message_template: `{lead_name}, {rep_name} here. I wanted to follow up on the proposal we sent over for {proposal_topic}. I know you're reviewing several options. I wanted to
  highlight that our solution specifically addresses {key_pain_point} which you mentioned was critical. We're offering {special_offer} if we can move forward by {deadline}. Happy to answer any questions at {callback_number}. Thanks for considering us!`,
      personalization_fields:
  ['lead_name', 'rep_name', 'proposal_topic', 'key_pain_point', 'special_offer', 'deadline', 'callback_number'],
      voice_settings: {
        voice: 'authoritative',
        pace: 'moderate',
        emotion: 'professional',
        language: 'en-US'
      },
      call_to_action: 'Let me know what questions you have.',
      urgency_level: 'high',
      max_duration_seconds: 30,
      follow_up_delay_hours: 72,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    // Nurture Campaign Templates
    this.addTemplate({
      id: 'nurture_educational',
      business_id: 'default',
      name: 'Educational Nurture',
      voicemail_type: 'nurture',
      attempt_range: { min: 1, max: 99 },
      message_template: `Hi {lead_name}, {rep_name} from {company}. I wanted to share something that might interest you. We just published a report on {topic} that's getting a lot of attention in
  {industry}. No sales pitch - just thought you'd find the insights valuable for {company_name}. I'll send it to your email. If you'd like to discuss any of the findings, I'm at {callback_number}. Have a great day!`,
      personalization_fields:
  ['lead_name', 'rep_name', 'company', 'topic', 'industry', 'company_name', 'callback_number'],
      voice_settings: {
        voice: 'professional_female',
        pace: 'normal',
        emotion: 'friendly',
        language: 'en-US'
      },
      call_to_action: 'Feel free to reach out if you find it useful.',
      urgency_level: 'low',
      max_duration_seconds: 25,
      follow_up_delay_hours: 336, // 2 weeks
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    // Win-back Templates
    this.addTemplate({
      id: 'winback_special_offer',
      business_id: 'default',
      name: 'Win-back with Special Offer',
      voicemail_type: 'win_back',
      attempt_range: { min: 1, max: 99 },
      message_template: `{lead_name}, it's been a while! {rep_name} from {company} here. I wanted to reach out because we've made some significant improvements to our {product} since we last spoke. Plus, for previous
  customers, we're offering {special_offer}. I'd love to show you what's new - just 10 minutes could save you {savings} annually. Call me at {callback_number} if you're interested. No pressure - just wanted you to know about the opportunity.`,
      personalization_fields:
  ['lead_name', 'rep_name', 'company', 'product', 'special_offer', 'savings', 'callback_number'],
      voice_settings: {
        voice: 'friendly_male',
        pace: 'moderate',
        emotion: 'warm',
        language: 'en-US'
      },
      call_to_action: 'Would love to reconnect when you have time.',
      urgency_level: 'medium',
      max_duration_seconds: 28,
      follow_up_delay_hours: 168, // 1 week
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    // Thank You Templates
    this.addTemplate({
      id: 'thank_you_post_meeting',
      business_id: 'default',
      name: 'Post-Meeting Thank You',
      voicemail_type: 'thank_you',
      attempt_range: { min: 1, max: 99 },
      message_template: `{lead_name}, just wanted to say thank you for taking the time to meet today. I really enjoyed our conversation about {discussion_topic}. As
  promised, I'll send over {follow_up_item} by {deadline}. If any questions come up in the meantime, don't hesitate to call me at {callback_number}. Thanks again, and have a wonderful day!`,
      personalization_fields: ['lead_name', 'discussion_topic', 'follow_up_item', 'deadline', 'callback_number'],
      voice_settings: {
        voice: 'professional_female',
        pace: 'moderate',
        emotion: 'warm',
        language: 'en-US'
      },
      call_to_action: 'Looking forward to our next steps!',
      urgency_level: 'low',
      max_duration_seconds: 20,
      follow_up_delay_hours: 48,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    // Urgent Templates
    this.addTemplate({
      id: 'urgent_limited_time',
      business_id: 'default',
      name: 'Urgent Limited Time Offer',
      voicemail_type: 'urgent',
      attempt_range: { min: 1, max: 99 },
      message_template: `{lead_name}, this is {rep_name} with an urgent update. The {offer} we discussed is ending {deadline}. I don't want you to miss
  out on {benefit}. This could save {company_name} approximately {savings}. Please call me back at {callback_number} as soon as possible so we can secure this for you. Time-sensitive - thanks!`,
      personalization_fields:
  ['lead_name', 'rep_name', 'offer', 'deadline', 'benefit', 'company_name', 'savings', 'callback_number'],
      voice_settings: {
        voice: 'professional_male',
        pace: 'quick',
        emotion: 'urgent',
        language: 'en-US'
      },
      call_to_action: 'Please call me back today if possible.',
      urgency_level: 'critical',
      max_duration_seconds: 22,
      follow_up_delay_hours: 24,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });
  }

  /**
   * Add a template to the collection
   */
  private addTemplate(template: VoicemailTemplate): void {
    const key = `${template.voicemail_type}_${template.attempt_range.min}_${template.attempt_range.max}`;

    if (!this.templates.has(key)) {
      this.templates.set(key, []);
    }

    this.templates.get(key)!.push(template);
  }

  /**
   * Get best matching template for a given scenario
   */
  getTemplate(
    type: VoicemailType,
    attemptNumber: number,
    criteria?: {
      urgency?: UrgencyLevel;
      industry?: string;
      leadLevel?: string;
    }
  ): VoicemailTemplate | null {
    // Find templates matching type and attempt range
    const matchingTemplates: VoicemailTemplate[] = [];

    for (const [key, templates] of this.templates.entries()) {
      for (const template of templates) {
        if (template.voicemail_type === type &&
            attemptNumber >= template.attempt_range.min &&
            attemptNumber <= template.attempt_range.max &&
            template.is_active) {
          matchingTemplates.push(template);
        }
      }
    }

    if (matchingTemplates.length === 0) return null;

    // Score and sort templates based on criteria
    if (criteria) {
      const scoredTemplates = matchingTemplates.map(template => ({
        template,
        score: this.scoreTemplate(template, criteria)
      }));

      scoredTemplates.sort((a, b) => b.score - a.score);
      return scoredTemplates[0].template;
    }

    // Return first matching template if no criteria
    return matchingTemplates[0];
  }

  /**
   * Score a template based on matching criteria
   */
  private scoreTemplate(template: VoicemailTemplate, criteria: any): number {
    let score = 100; // Base score

    // Urgency matching
    if (criteria.urgency && template.urgency_level === criteria.urgency) {
      score += 20;
    }

    // Add more scoring logic based on industry, lead level, etc.

    return score;
  }

  /**
   * Personalize a template with lead data
   */
  personalizeTemplate(
    template: VoicemailTemplate,
    lead: Lead,
    additionalData?: Record<string, string>
  ): string {
    let message = template.message_template;

    // Default replacements
    const replacements: Record<string, string> = {
      lead_name: `${lead.first_name || ''} ${lead.last_name || ''}`.trim() || 'there',
      company_name: lead.company_name || 'your company',
      industry: 'your industry', // Would come from company data
      ...additionalData
    };

    // Replace all placeholders
    for (const [key, value] of Object.entries(replacements)) {
      const regex = new RegExp(`\\{${key}\\}`, 'g');
      message = message.replace(regex, value);
    }

    return message;
  }

  /**
   * Get all templates for a specific type
   */
  getTemplatesByType(type: VoicemailType): VoicemailTemplate[] {
    const result: VoicemailTemplate[] = [];

    for (const templates of this.templates.values()) {
      for (const template of templates) {
        if (template.voicemail_type === type && template.is_active) {
          result.push(template);
        }
      }
    }

    return result;
  }

  /**
   * Calculate success rate for a template based on historical data
   */
  async calculateTemplateSuccessRate(templateId: string): Promise<number> {
    // In real implementation, query database for:
    // - Total voicemails sent with this template
    // - Number that received callbacks
    // - Number that led to meetings
    // - Number that converted

    // Mock calculation
    const mockData = {
      total_sent: 100,
      callbacks_received: 15,
      meetings_scheduled: 8,
      conversions: 3
    };

    // Weighted success calculation
    const callbackWeight = 0.3;
    const meetingWeight = 0.5;
    const conversionWeight = 0.2;

    const callbackRate = mockData.callbacks_received / mockData.total_sent;
    const meetingRate = mockData.meetings_scheduled / mockData.total_sent;
    const conversionRate = mockData.conversions / mockData.total_sent;

    const successRate = (callbackRate * callbackWeight) +
                        (meetingRate * meetingWeight) +
                        (conversionRate * conversionWeight);

    return Math.round(successRate * 100);
  }

  /**
   * Get recommended templates based on lead characteristics
   */
  getRecommendedTemplates(
    lead: Lead,
    attemptNumber: number
  ): VoicemailTemplate[] {
    const recommendations: VoicemailTemplate[] = [];

    // Determine voicemail type based on lead status and attempt
    let type: VoicemailType;

    if (attemptNumber === 1) {
      type = 'initial_outreach';
    } else if (attemptNumber <= 3) {
      type = 'follow_up';
    } else {
      type = 'nurture';
    }

    // Special cases
    if (lead.status === 'meeting_scheduled') {
      type = 'appointment_reminder';
    } else if (lead.status === 'unqualified') {
      type = 'nurture';
    }

    // Get matching templates
    const templates = this.getTemplatesByType(type);

    // Sort by success rate (if available)
    templates.sort((a, b) => (b.success_rate || 0) - (a.success_rate || 0));

    return templates.slice(0, 3); // Return top 3 recommendations
  }
}

// Export singleton instance
export const voicemailTemplates = new VoicemailTemplateManager();