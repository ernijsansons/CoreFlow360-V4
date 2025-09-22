import type { Env } from '../types/env';
import type {
  CallScript,
  CallType,
  ScriptSection,
  ObjectionType,
  ScriptResponse
} from '../types/voice-agent';
import type { Lead } from '../types/crm';

export interface ScriptGenerationRequest {
  lead: Lead;
  call_type: CallType;
  context?: {
    previous_interactions?: string[];
    urgency_reason?: string;
    campaign_context?: string;
    referral_source?: string;
  };
  customization?: {
    tone?: 'professional' | 'casual' | 'consultative' | 'direct';
    industry_focus?: string;
    product_focus?: string[];
    max_call_duration?: number;
    primary_objective?: string;
  };
}

export interface GeneratedScript {
  script: CallScript;
  personalization_data: PersonalizationData;
  success_probability: number;
  estimated_duration: number;
  key_talking_points: string[];
  likely_objections: ObjectionPrediction[];
}

export interface PersonalizationData {
  contact_name: string;
  company_name: string;
  industry: string;
  company_size: string;
  recent_news?: string;
  pain_points: string[];
  value_propositions: string[];
  competitive_alternatives?: string[];
  meeting_best_times?: string[];
}

export interface ObjectionPrediction {
  type: ObjectionType;
  likelihood: number; // 0-1
  trigger_phrases: string[];
  response_strategy: string;
  evidence_needed?: string[];
}

export class VoiceScriptGenerator {
  private env: Env;
  private scriptTemplates: Map<CallType, CallScript>;

  constructor(env: Env) {
    this.env = env;
    this.scriptTemplates = new Map();
    this.initializeTemplates();
  }

  async generateScript(request: ScriptGenerationRequest): Promise<GeneratedScript> {
    try {
      // Get base template
      const baseTemplate = this.scriptTemplates.get(request.call_type);
      if (!baseTemplate) {
        throw new Error(`No template found for call type: ${request.call_type}`);
      }

      // Extract personalization data
      const personalizationData = await this.extractPersonalizationData(request.lead);

      // Generate personalized script sections
      const personalizedScript = await this.personalizeScript(
        baseTemplate,
        request,
        personalizationData
      );

      // Predict likely objections
      const objectionPredictions = await this.predictObjections(request.lead, personalizationData);

      // Generate objection responses
      const objectionHandling = await this.generateObjectionResponses(
        objectionPredictions,
        personalizationData
      );

      // Combine into final script
      const finalScript: CallScript = {
        ...personalizedScript,
        objection_handling: objectionHandling
      };

      // Calculate success metrics
      const successProbability = this.calculateSuccessProbability(request.lead, personalizationData);
      const estimatedDuration = this.estimateCallDuration(request.call_type, personalizedScript);

      return {
        script: finalScript,
        personalization_data: personalizationData,
        success_probability: successProbability,
        estimated_duration: estimatedDuration,
        key_talking_points: this.extractKeyTalkingPoints(finalScript, personalizationData),
        likely_objections: objectionPredictions
      };
    } catch (error) {
      throw error;
    }
  }

  private async extractPersonalizationData(lead: Lead): Promise<PersonalizationData> {
    const enrichmentData = lead.enrichment_data;

    return {
      contact_name: lead.first_name || 'there',
      company_name: lead.company_name || 'your company',
      industry: enrichmentData?.company?.industry || 'technology',
      company_size: this.formatCompanySize(enrichmentData?.company?.employee_count),
      recent_news: enrichmentData?.news?.recent_news?.[0]?.title,
      pain_points: enrichmentData?.ai_insights?.pain_points || this.getDefaultPainPoints(enrichmentData?.company?.industry),
      value_propositions: enrichmentData?.ai_insights?.value_propositions || this.getDefaultValueProps(),
      competitive_alternatives: enrichmentData?.ai_insights?.current_solutions?.map(s => s.vendor) || [],
      meeting_best_times: enrichmentData?.ai_insights?.meeting_best_times?.map(t => t.time_range) || []
    };
  }

  private async personalizeScript(
    baseTemplate: CallScript,
    request: ScriptGenerationRequest,
    personalizationData: PersonalizationData
  ): Promise<CallScript> {
    const tone = request.customization?.tone || 'consultative';
    const industry = personalizationData.industry;

    // Personalize opening
    const personalizedOpening = await this.personalizeOpening(
      baseTemplate.opening,
      personalizationData,
      request.context,
      tone
    );

    // Personalize qualification questions
    const personalizedQualification = await this.personalizeQualification(
      baseTemplate.qualification,
      personalizationData,
      industry
    );

    // Personalize closing
    const personalizedClosing = await this.personalizeClosing(
      baseTemplate.closing,
      personalizationData,
      request.call_type
    );

    // Personalize voicemail
    const personalizedVoicemail = await this.personalizeVoicemail(
      baseTemplate.voicemail,
      personalizationData
    );

    return {
      ...baseTemplate,
      opening: personalizedOpening,
      qualification: personalizedQualification,
      closing: personalizedClosing,
      voicemail: personalizedVoicemail
    };
  }

  private async personalizeOpening(
    baseOpening: ScriptSection,
    personalizationData: PersonalizationData,
    context?: any,
    tone: string = 'consultative'
  ): Promise<ScriptSection> {
    const prompt = `
Generate a personalized cold call opening for:

Contact: ${personalizationData.contact_name}
Company: ${personalizationData.company_name}
Industry: ${personalizationData.industry}
Company Size: ${personalizationData.company_size}
Recent News: ${personalizationData.recent_news || 'None'}
Pain Points: ${personalizationData.pain_points.join(', ')}
Tone: ${tone}

Context:
- Previous interactions: ${context?.previous_interactions?.length || 0}
- Referral source: ${context?.referral_source || 'Direct outreach'}
- Urgency: ${context?.urgency_reason || 'None'}

Generate an opening that:
1. Immediately introduces yourself and company (5 seconds)
2. Creates relevance with specific company/industry reference (10 seconds)
3. States clear value proposition (10 seconds)
4. Asks permission to continue (5 seconds)
5. Total under 30 seconds when spoken

Make it sound natural and conversational, not scripted.
`;

    try {
      const response = await this.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        prompt,
        max_tokens: 200,
        temperature: 0.7
      });

      const generatedIntro = response.response || baseOpening.intro;

      return {
        intro: generatedIntro,
        key_points: [
          `Reference ${personalizationData.company_name}'s ${personalizationData.industry} background`,
          `Mention ${personalizationData.recent_news ? 'recent company news' : 'industry trends'}`,
          `Connect to pain point: ${personalizationData.pain_points[0] || 'operational efficiency'}`
        ],
        questions: [
          `Does this sound relevant to what you're seeing at ${personalizationData.company_name}?`,
          'Is this a good time for a quick 30-second overview?',
          'Are you the right person to discuss operational improvements?'
        ],
        transitions: [
          "Great, let me quickly share why I'm calling...",
          "Perfect, this will be valuable for you...",
          "Excellent, here's what I'm seeing with similar companies..."
        ],
        fallbacks: [
          "I understand you're busy. This will just take 30 seconds.",
          "I know cold calls can be disruptive. Can I earn 30 seconds?",
          "Would a different time work better for a quick conversation?"
        ]
      };
    } catch (error) {
      return baseOpening;
    }
  }

  private async personalizeQualification(
    baseQualification: ScriptSection,
    personalizationData: PersonalizationData,
    industry: string
  ): Promise<ScriptSection> {
    const industryQuestions = this.getIndustrySpecificQuestions(industry);
    const painPointQuestions = personalizationData.pain_points.map(pain =>
      `How are you currently handling ${pain.toLowerCase()}?`
    );

    return {
      intro: `I'd love to understand more about ${personalizationData.company_name}'s current situation...`,
      key_points: [
        `Understand current ${industry} challenges`,
        'Identify decision-making process',
        'Assess timeline and budget authority',
        'Determine technical requirements'
      ],
      questions: [
        ...industryQuestions,
        ...painPointQuestions,
        `What's your biggest priority for ${personalizationData.company_name} this quarter?`,
        'Who else would be involved in evaluating a solution like this?',
        'What does your typical vendor evaluation process look like?',
        'When would you ideally want to have a solution in place?'
      ],
      transitions: [
        "That's exactly what I was hoping to hear...",
        "This is very common in the " + industry + " space...",
        "I've seen similar challenges with other companies..."
      ],
      fallbacks: [
        "Let me ask it differently...",
        "Maybe I can share what other similar companies are doing...",
        "Would it help if I explained why this matters?"
      ]
    };
  }

  private async personalizeClosing(
    baseClosing: ScriptSection,
    personalizationData: PersonalizationData,
    callType: CallType
  ): Promise<ScriptSection> {
    const closingType = callType === 'demo_booking' ? 'demo' : 'follow-up meeting';

    return {
      intro: `Based on what
  you've shared about ${personalizationData.company_name}, I think a ${closingType} would be valuable...`,
      key_points: [
        `Show specific ${personalizationData.industry} use cases`,
        'Demonstrate ROI potential',
        'Address specific pain points discussed',
        'Provide implementation timeline'
      ],
      questions: [
        `Would you be interested in seeing how we've helped other ${personalizationData.industry} companies?`,
        `Are
  ${personalizationData.meeting_best_times?.[0] || 'Tuesday or Wednesday afternoons'} generally good for you?`,
        'Who else should be included in this conversation?',
        'Would 30 minutes be enough time, or should we plan for longer?'
      ],
      transitions: [
        "Perfect, let me get that scheduled...",
        "Excellent, I'll send you a calendar invite...",
        "Great, I'm looking forward to showing you..."
      ],
      fallbacks: [
        "Would a different time work better?",
        "What if we started with a shorter conversation?",
        "Can I send you some information to review first?"
      ]
    };
  }

  private async personalizeVoicemail(
    baseVoicemail: ScriptSection,
    personalizationData: PersonalizationData
  ): Promise<ScriptSection> {
    const voicemailMessage = `Hi ${personalizationData.contact_name}, this is [Name] from CoreFlow360. I'm reaching out because I noticed ${personalizationData.company_name} ${personalizationData.recent_news ? 'recently ' + personalizationData.recent_news.toLowerCase() : 'is growing in the ' + personalizationData.industry +
  ' space'}, and I wanted to share how we're helping similar companies ${personalizationData.pain_points[0] ? 'solve ' + personalizationData.pain_points[0].toLowerCase() : 'improve their operations'}. I'll try you again, or feel free to call me back at [phone]. Thanks!`;

    return {
      intro: voicemailMessage,
      key_points: [
        'Keep under 30 seconds',
        'Reference specific company context',
        'Mention one clear value proposition',
        'Provide clear callback number'
      ],
      questions: [],
      transitions: [],
      fallbacks: []
    };
  }

  private async predictObjections(lead: Lead, personalizationData: PersonalizationData): Promise<ObjectionPrediction[]> {
    const predictions: ObjectionPrediction[] = [];

    // Industry-based objection predictions
    const industry = personalizationData.industry.toLowerCase();

    // Price objections (common across all industries)
    predictions.push({
      type: 'price',
      likelihood: 0.7,
      trigger_phrases: ['too expensive', 'budget', 'cost', 'price'],
      response_strategy: 'Focus on ROI and cost of inaction',
      evidence_needed: ['ROI calculator', 'cost savings examples', 'implementation timeline']
    });

    // Timing objections (common for growing companies)
    if (personalizationData.company_size.includes('growing') || personalizationData.recent_news) {
      predictions.push({
        type: 'timing',
        likelihood: 0.6,
        trigger_phrases: ['not the right time', 'too busy', 'later this year'],
        response_strategy: 'Emphasize competitive advantage and growth enablement',
        evidence_needed: ['quick implementation', 'minimal disruption', 'immediate value']
      });
    }

    // Authority objections (higher likelihood for larger companies)
    const employeeCount = lead.enrichment_data?.company?.employee_count || 0;
    if (employeeCount > 100) {
      predictions.push({
        type: 'authority',
        likelihood: 0.8,
        trigger_phrases: ['need to check', 'not my decision', 'team decision'],
        response_strategy: 'Request introduction to decision maker',
        evidence_needed: ['executive briefing', 'business case template']
      });
    }

    // Competitor objections
    if (personalizationData.competitive_alternatives.length > 0) {
      predictions.push({
        type: 'competitor',
        likelihood: 0.5,
        trigger_phrases: ['already using', 'have a solution', 'working with'],
        response_strategy: 'Differentiate and show unique value',
        evidence_needed: ['comparison chart', 'customer migration stories']
      });
    }

    // Industry-specific objections
    if (industry.includes('healthcare')) {
      predictions.push({
        type: 'trust',
        likelihood: 0.6,
        trigger_phrases: ['compliance', 'security', 'regulations'],
        response_strategy: 'Emphasize security and compliance credentials',
        evidence_needed: ['security certifications', 'compliance documentation']
      });
    }

    return predictions.sort((a, b) => b.likelihood - a.likelihood);
  }

  private async generateObjectionResponses(
    objectionPredictions: ObjectionPrediction[],
    personalizationData: PersonalizationData
  ): Promise<Record<ObjectionType, ScriptResponse[]>> {
    const responses: Record<ObjectionType, ScriptResponse[]> = {} as any;

    for (const prediction of objectionPredictions) {
      const objectionResponses = await this.generateSpecificObjectionResponses(
        prediction,
        personalizationData
      );
      responses[prediction.type] = objectionResponses;
    }

    return responses;
  }

  private async generateSpecificObjectionResponses(
    prediction: ObjectionPrediction,
    personalizationData: PersonalizationData
  ): Promise<ScriptResponse[]> {
    const responses: ScriptResponse[] = [];

    switch (prediction.type) {
      case 'price':
        responses.push({
          trigger: 'cost too much',
          response: `I understand budget is always a consideration. Let me ask
  - what's the cost of ${personalizationData.pain_points[0] || 'your current challenges'}? Most ${personalizationData.industry} companies save 3x their investment in the first year.`,
          follow_up: 'Would it help to see a specific ROI calculation for your situation?'
        });
        break;

      case 'timing':
        responses.push({
          trigger: 'not the right time',
          response: `I hear that often. The question is - when is the right
  time to gain a competitive advantage? Companies that wait often find themselves further behind. What if we could implement this with minimal disruption?`,
          follow_up: 'What would need to happen for timing to be better?'
        });
        break;

      case 'authority':
        responses.push({
          trigger: 'need to check',
          response: `That makes complete sense. Who else would be
  involved in this decision? I'd be happy to present to the broader team and show exactly how this impacts ${personalizationData.company_name}.`,
          follow_up: 'Would you be able to make an introduction?',
          escalation: true
        });
        break;

      case 'competitor':
        responses.push({
          trigger: 'already using',
          response: `Many of our best customers had existing solutions. The
  question is - are you getting everything you need? Most companies find they're only using 30% of their current system's potential.`,
          follow_up: 'What if I could show you what you might be missing?'
        });
        break;

      case 'need':
        responses.push({
          trigger: 'working fine',
          response: `That's great to hear! Many successful ${personalizationData.industry} companies say the
  same thing. But 'fine' and 'competitive advantage' are different things. What if there was a way to go from fine to extraordinary?`,
          follow_up: 'Would you be curious to see what that could look like?'
        });
        break;

      case 'trust':
        responses.push({
          trigger: 'never heard',
          response: `I completely understand. We work with companies
  like [similar customer] and focus specifically on ${personalizationData.industry}. We'd be happy to provide references and show our track record.`,
          follow_up: 'Would speaking with a similar customer be helpful?'
        });
        break;
    }

    return responses;
  }

  private calculateSuccessProbability(lead: Lead, personalizationData: PersonalizationData): number {
    let probability = 0.5; // Base probability

    // ICP fit score
    const icpScore = lead.enrichment_data?.ai_insights?.icp_fit_score || 50;
    probability += (icpScore - 50) / 200; // Adjust by ICP fit

    // Company size factor
    const employeeCount = lead.enrichment_data?.company?.employee_count || 0;
    if (employeeCount > 50 && employeeCount < 1000) {
      probability += 0.1; // Sweet spot for B2B sales
    }

    // Industry factor
    const industryBonus = this.getIndustrySuccessBonus(personalizationData.industry);
    probability += industryBonus;

    // Recent news factor
    if (personalizationData.recent_news) {
      probability += 0.05; // Timing advantage
    }

    // Previous interactions factor
    const interactions = lead.previous_interactions?.length || 0;
    if (interactions > 0) {
      probability -= 0.1; // Already contacted, may be less receptive
    }

    return Math.max(0.1, Math.min(0.9, probability));
  }

  private estimateCallDuration(callType: CallType, script: CallScript): number {
    const baseDurations = {
      cold_outreach: 180, // 3 minutes
      follow_up: 240, // 4 minutes
      qualification: 600, // 10 minutes
      demo_booking: 300, // 5 minutes
      support: 480 // 8 minutes
    };

    const base = baseDurations[callType] || 300;

    // Adjust based on script complexity
    const questionCount = script.qualification.questions.length;
    const adjustedDuration = base + (questionCount * 30); // 30 seconds per question

    return adjustedDuration;
  }

  private extractKeyTalkingPoints(script: CallScript, personalizationData: PersonalizationData): string[] {
    return [
      `Industry expertise in ${personalizationData.industry}`,
      `Specific value for ${personalizationData.company_name}`,
      `Address pain point: ${personalizationData.pain_points[0]}`,
      `ROI and competitive advantage`,
      `Implementation and timeline`,
      ...script.qualification.key_points.slice(0, 2)
    ];
  }

  private getIndustrySpecificQuestions(industry: string): string[] {
    const questions: Record<string, string[]> = {
      technology: [
        'How are you currently handling scaling challenges?',
        'What\'s your biggest technical bottleneck right now?',
        'How is your team managing development velocity?'
      ],
      healthcare: [
        'How are you ensuring compliance with current regulations?',
        'What\'s your biggest operational challenge?',
        'How are you managing patient data security?'
      ],
      finance: [
        'How are you handling regulatory compliance requirements?',
        'What\'s your biggest risk management challenge?',
        'How are you managing operational efficiency?'
      ],
      retail: [
        'How are you managing inventory across channels?',
        'What\'s your biggest customer experience challenge?',
        'How are you handling omnichannel integration?'
      ]
    };

    return questions[industry.toLowerCase()] || questions.technology;
  }

  private getDefaultPainPoints(industry?: string): string[] {
    const painPoints: Record<string, string[]> = {
      technology: ['Scaling challenges', 'Development velocity', 'Infrastructure costs'],
      healthcare: ['Compliance complexity', 'Operational efficiency', 'Patient experience'],
      finance: ['Regulatory compliance', 'Risk management', 'Process automation'],
      retail: ['Inventory management', 'Customer experience', 'Omnichannel integration']
    };

    return painPoints[industry?.toLowerCase() || 'technology'];
  }

  private getDefaultValueProps(): string[] {
    return [
      'Operational efficiency improvements',
      'Cost savings and ROI',
      'Competitive advantage',
      'Scalability and growth enablement',
      'Risk reduction and compliance'
    ];
  }

  private formatCompanySize(employeeCount?: number): string {
    if (!employeeCount) return 'growing company';
    if (employeeCount < 50) return 'small but growing company';
    if (employeeCount < 200) return 'mid-size company';
    if (employeeCount < 1000) return 'established company';
    return 'large enterprise';
  }

  private getIndustrySuccessBonus(industry: string): number {
    // Industries where the product/service typically performs well
    const highSuccessIndustries = ['technology', 'saas', 'finance'];
    const mediumSuccessIndustries = ['healthcare', 'retail', 'manufacturing'];

    if (highSuccessIndustries.includes(industry.toLowerCase())) {
      return 0.1;
    } else if (mediumSuccessIndustries.includes(industry.toLowerCase())) {
      return 0.05;
    }
    return 0;
  }

  private initializeTemplates(): void {
    // Initialize base script templates for different call types
    this.scriptTemplates.set('cold_outreach', {
      id: 'cold_outreach_base',
      name: 'Cold Outreach Template',
      call_type: 'cold_outreach',
      opening: {
        intro: 'Hi [contact_name], this is [agent_name] from CoreFlow360...',
        key_points: ['Quick introduction', 'Relevance statement', 'Permission to continue'],
        questions: ['Is this a good time for a quick conversation?'],
        transitions: ['Great, let me quickly share...'],
        fallbacks: ['I understand you\'re busy...']
      },
      qualification: {
        intro: 'I\'d love to understand your current situation...',
        key_points: ['Current challenges', 'Decision process', 'Timeline', 'Budget'],
        questions: ['What\'s your biggest challenge?', 'How are you handling this now?'],
        transitions: ['That\'s interesting...', 'I see...'],
        fallbacks: ['Let me ask differently...']
      },
      objection_handling: {} as any,
      closing: {
        intro: 'Based on what you\'ve shared...',
        key_points: ['Demo value', 'Next steps', 'Timeline'],
        questions: ['Would you be interested in seeing this?'],
        transitions: ['Perfect, let me get that scheduled...'],
        fallbacks: ['Would a different approach work better?']
      },
      voicemail: {
        intro: 'Hi [contact_name], this is [agent_name] from CoreFlow360...',
        key_points: ['Brief introduction', 'Specific value', 'Clear callback'],
        questions: [],
        transitions: [],
        fallbacks: []
      },
      personalization_variables: ['contact_name', 'company_name', 'industry', 'pain_points'],
      success_metrics: [
        { name: 'call_completion_rate', target_value: 0.3, measurement: 'percentage' },
        { name: 'qualification_rate', target_value: 0.15, measurement: 'percentage' },
        { name: 'meeting_booking_rate', target_value: 0.05, measurement: 'percentage' }
      ]
    });

    // Add other templates...
    this.addFollowUpTemplate();
    this.addQualificationTemplate();
    this.addDemoBookingTemplate();
  }

  private addFollowUpTemplate(): void {
    this.scriptTemplates.set('follow_up', {
      id: 'follow_up_base',
      name: 'Follow-up Call Template',
      call_type: 'follow_up',
      opening: {
        intro: 'Hi [contact_name], this is [agent_name] following up from our previous conversation...',
        key_points: ['Reference previous conversation', 'New information', 'Next steps'],
        questions: ['How has your thinking evolved since we last spoke?'],
        transitions: ['Since we last talked...'],
        fallbacks: ['Let me refresh your memory...']
      },
      qualification: {
        intro: 'Let me dive deeper into what we discussed...',
        key_points: ['Progress since last call', 'New requirements', 'Decision timeline'],
        questions: ['What\'s changed since our last conversation?'],
        transitions: ['That makes sense...'],
        fallbacks: ['Let me clarify...']
      },
      objection_handling: {} as any,
      closing: {
        intro: 'It sounds like we should move forward...',
        key_points: ['Clear next steps', 'Timeline confirmation', 'Resource allocation'],
        questions: ['Are you ready to see this in action?'],
        transitions: ['Excellent, here\'s what I\'ll do...'],
        fallbacks: ['What would help you move forward?']
      },
      voicemail: {
        intro: 'Hi [contact_name], following up on our conversation about...',
        key_points: ['Reference previous discussion', 'New value', 'Clear next step'],
        questions: [],
        transitions: [],
        fallbacks: []
      },
      personalization_variables: ['contact_name', 'company_name', 'previous_discussion'],
      success_metrics: [
        { name: 'call_completion_rate', target_value: 0.5, measurement: 'percentage' },
        { name: 'progression_rate', target_value: 0.4, measurement: 'percentage' },
        { name: 'meeting_booking_rate', target_value: 0.2, measurement: 'percentage' }
      ]
    });
  }

  private addQualificationTemplate(): void {
    this.scriptTemplates.set('qualification', {
      id: 'qualification_base',
      name: 'Qualification Call Template',
      call_type: 'qualification',
      opening: {
        intro: 'Hi [contact_name], thank you for agreeing to this qualification call...',
        key_points: ['Appreciation for time', 'Call agenda', 'Mutual evaluation'],
        questions: ['Shall we dive into understanding your needs?'],
        transitions: ['Perfect, let\'s start...'],
        fallbacks: ['Let me outline what we\'ll cover...']
      },
      qualification: {
        intro: 'I\'d like to understand your current situation in detail...',
        key_points: ['BANT qualification', 'Technical requirements', 'Success criteria', 'Decision process'],
        questions: [
          'What\'s driving this initiative?',
          'What does success look like?',
          'Who else is involved in this decision?',
          'What\'s your timeline?',
          'What\'s your budget range?'
        ],
        transitions: ['That\'s helpful...', 'I understand...'],
        fallbacks: ['Let me approach this differently...']
      },
      objection_handling: {} as any,
      closing: {
        intro: 'Based on everything you\'ve shared...',
        key_points: ['Fit assessment', 'Mutual next steps', 'Resource commitment'],
        questions: ['Does this sound like a good fit?'],
        transitions: ['Great, let\'s discuss next steps...'],
        fallbacks: ['What concerns do you have?']
      },
      voicemail: {
        intro: 'Hi [contact_name], this is regarding our scheduled qualification call...',
        key_points: ['Reschedule request', 'Maintain momentum', 'Clear callback'],
        questions: [],
        transitions: [],
        fallbacks: []
      },
      personalization_variables: ['contact_name', 'company_name', 'initiative_driver'],
      success_metrics: [
        { name: 'call_completion_rate', target_value: 0.8, measurement: 'percentage' },
        { name: 'qualification_completion_rate', target_value: 0.7, measurement: 'percentage' },
        { name: 'progression_rate', target_value: 0.5, measurement: 'percentage' }
      ]
    });
  }

  private addDemoBookingTemplate(): void {
    this.scriptTemplates.set('demo_booking', {
      id: 'demo_booking_base',
      name: 'Demo Booking Template',
      call_type: 'demo_booking',
      opening: {
        intro: 'Hi [contact_name], I\'m calling to schedule that demo we discussed...',
        key_points: ['Demo value preview', 'Logistics discussion', 'Attendee planning'],
        questions: ['What would you most like to see in the demo?'],
        transitions: ['Perfect, let me make sure we cover that...'],
        fallbacks: ['Let me suggest what would be most valuable...']
      },
      qualification: {
        intro: 'To make this demo as valuable as possible...',
        key_points: ['Demo objectives', 'Attendee roles', 'Success criteria', 'Follow-up process'],
        questions: [
          'Who else should attend?',
          'What specific use cases should we focus on?',
          'What would make this demo a success?'
        ],
        transitions: ['That\'s exactly what we should show...'],
        fallbacks: ['Let me suggest some options...']
      },
      objection_handling: {} as any,
      closing: {
        intro: 'Great, let me get this scheduled...',
        key_points: ['Calendar coordination', 'Pre-demo preparation', 'Success metrics'],
        questions: ['What days work best for your team?'],
        transitions: ['I\'ll send the calendar invite...'],
        fallbacks: ['What would work better for your schedule?']
      },
      voicemail: {
        intro: 'Hi [contact_name], calling about scheduling your demo...',
        key_points: ['Demo value reminder', 'Scheduling options', 'Clear callback'],
        questions: [],
        transitions: [],
        fallbacks: []
      },
      personalization_variables: ['contact_name', 'company_name', 'demo_focus'],
      success_metrics: [
        { name: 'call_completion_rate', target_value: 0.9, measurement: 'percentage' },
        { name: 'demo_booking_rate', target_value: 0.8, measurement: 'percentage' },
        { name: 'demo_attendance_rate', target_value: 0.7, measurement: 'percentage' }
      ]
    });
  }
}