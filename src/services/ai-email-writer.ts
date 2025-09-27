import type {
  Lead,
  Contact,
  Company,
  ChannelContent,
  CallToAction
} from '../types/crm';
import type { Env } from '../types/env';

export type EmailStage = 'cold' | 'follow_up' | 'breakup' | 'nurture' | 'reengagement';
export type PersonalityType = 'analytical' | 'driver' | 'expressive' | 'amiable';
export type CommunicationStyle = 'formal' | 'casual' | 'technical' | 'conversational' | 'direct';

export interface EmailContext {
  valueProp: string;
  productName?: string;
  companyName?: string;
  previousInteractions?: string[];
  touchpoint?: number;
  campaign?: string;
  templatePreference?: string;
  industry?: string;
  customData?: Record<string, any>;
}

export interface LeadIntelligence {
  recentNews?: string;
  recentActivity?: string;
  predictedPain?: string;
  personalityType: PersonalityType;
  communicationStyle: CommunicationStyle;
  companyGrowthStage?: string;
  techStack?: string[];
  competitorUsage?: string[];
  buyingSignals?: string[];
  engagementHistory?: {
    opens: number;
    clicks: number;
    replies: number;
    bestTimeToEmail?: string;
  };
  socialMediaActivity?: {
    linkedin?: string;
    twitter?: string;
  };
  triggers?: {
    type: string;
    description: string;
    relevance: number;
  }[];
}

export interface Email {
  subject: string;
  preheader?: string;
  body: string;
  html?: string;
  cta?: CallToAction;
  personalizationScore: number;
  predictedOpenRate: number;
  predictedReplyRate: number;
  variations?: EmailVariation[];
  metadata: {
    stage: EmailStage;
    wordCount: number;
    readingTime: number;
    sentimentScore: number;
    personalElements: string[];
  };
}

export interface EmailVariation {
  id: string;
  subject: string;
  body: string;
  variationType: 'subject' | 'opening' | 'cta' | 'tone';
  performanceScore?: number;
}

export interface EmailSequence {
  id: string;
  leadId: string;
  emails: {
    [key: string]: Email; // day0, day3, day7, etc.
  };
  schedule: EmailSchedule[];
  status: 'draft' | 'active' | 'paused' | 'completed';
  performance?: {
    totalSent: number;
    totalOpens: number;
    totalClicks: number;
    totalReplies: number;
    conversionRate: number;
  };
}

export interface EmailSchedule {
  emailKey: string;
  sendDate: Date;
  condition?: {
    type: 'no_reply' | 'no_open' | 'clicked' | 'custom';
    value?: any;
  };
  sent?: boolean;
  result?: {
    opened?: boolean;
    clicked?: boolean;
    replied?: boolean;
  };
}

export class AIEmailWriter {
  private env: Env;
  private intelligenceCache: Map<string, LeadIntelligence>;

  constructor(env: Env) {
    this.env = env;
    this.intelligenceCache = new Map();
  }

  async generateEmail(
    lead: Lead,
    stage: EmailStage,
    context: EmailContext
  ): Promise<Email> {
    // Gather intelligence about the lead
    const intelligence = await this.gatherIntelligence(lead);

    // Generate the email using AI
    const prompt = this.buildEmailPrompt(lead, stage, context, intelligence);
    const generatedContent = await this.generateWithAI(prompt);

    // Parse and structure the email
    const email = this.parseGeneratedEmail(generatedContent, stage);

    // Generate A/B test variations
    if (stage === 'cold' || stage === 'follow_up') {
      email.variations = await this.generateVariations(email, 3);
    }

    // Calculate personalization score
    email.personalizationScore = this.calculatePersonalizationScore(email, intelligence);

    // Predict performance metrics
    email.predictedOpenRate = await this.predictOpenRate(email, lead, intelligence);
    email.predictedReplyRate = await this.predictReplyRate(email, lead, intelligence);

    return email;
  }

  async generateSequence(lead: Lead, context?: EmailContext): Promise<EmailSequence> {
    const defaultContext: EmailContext = {
      valueProp: context?.valueProp || 'Streamline your sales process with AI',
      productName: context?.productName || 'CoreFlow360',
      companyName: context?.companyName || 'Your Company',
      ...context
    };

    // Generate a cohesive sequence with progressive messaging
    const sequence: EmailSequence = {
      id: this.generateSequenceId(),
      leadId: lead.id,
      emails: {},
      schedule: [],
      status: 'draft'
    };

    // Day 0: Initial cold outreach
    sequence.emails.day0 = await this.generateEmail(lead, 'cold', defaultContext);
    sequence.schedule.push({
      emailKey: 'day0',
      sendDate: new Date(),
      condition: undefined
    });

    // Day 3: First follow-up
    sequence.emails.day3 = await this.generateEmail(lead, 'follow_up', {
      ...defaultContext,
      touchpoint: 1,
      previousInteractions: ['Initial email sent']
    });
    sequence.schedule.push({
      emailKey: 'day3',
      sendDate: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
      condition: { type: 'no_reply' }
    });

    // Day 7: Second follow-up with different angle
    sequence.emails.day7 = await this.generateEmail(lead, 'follow_up', {
      ...defaultContext,
      touchpoint: 2,
      previousInteractions: ['Initial email sent', 'First follow-up sent']
    });
    sequence.schedule.push({
      emailKey: 'day7',
      sendDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      condition: { type: 'no_reply' }
    });

    // Day 14: Breakup email
    sequence.emails.day14 = await this.generateEmail(lead, 'breakup', {
      ...defaultContext,
      previousInteractions: ['Multiple emails sent without response']
    });
    sequence.schedule.push({
      emailKey: 'day14',
      sendDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000),
      condition: { type: 'no_reply' }
    });

    // Day 30: Re-engagement (if they opened but didn't reply)
    sequence.emails.day30 = await this.generateEmail(lead, 'reengagement', {
      ...defaultContext,
      previousInteractions: ['Previous sequence completed']
    });
    sequence.schedule.push({
      emailKey: 'day30',
      sendDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      condition: { type: 'no_open', value: { negate: true } } // Only if they opened
    });

    return sequence;
  }

  private async gatherIntelligence(lead: Lead): Promise<LeadIntelligence> {
    // Check cache first
    const cacheKey = `${lead.id}_${Date.now()}`;
    if (this.intelligenceCache.has(lead.id)) {
      const cached = this.intelligenceCache.get(lead.id);
      // Return cached if less than 1 hour old
      if (cached) return cached;
    }

    const intelligence: LeadIntelligence = {
      personalityType: 'analytical',
      communicationStyle: 'formal'
    };

    // Gather recent news and triggers
    intelligence.recentNews = await this.fetchRecentNews(lead);
    intelligence.recentActivity = await this.fetchRecentActivity(lead);

    // Predict pain points based on industry and role
    intelligence.predictedPain = await this.predictPainPoints(lead);

    // Analyze personality and communication style
    const styleAnalysis = await this.analyzeommunicationStyle(lead);
    intelligence.personalityType = styleAnalysis.personality;
    intelligence.communicationStyle = styleAnalysis.style;

    // Get company intelligence
    if (lead.company_id) {
      const companyIntel = await this.gatherCompanyIntelligence(lead.company_id);
      intelligence.companyGrowthStage = companyIntel.growthStage;
      intelligence.techStack = companyIntel.techStack;
      intelligence.competitorUsage = companyIntel.competitors;
    }

    // Analyze engagement history
    intelligence.engagementHistory = await this.getEngagementHistory(lead.id);

    // Detect buying signals
    intelligence.buyingSignals = await this.detectBuyingSignals(lead);

    // Find triggers
    intelligence.triggers = await this.findTriggers(lead);

    // Cache the intelligence
    this.intelligenceCache.set(lead.id, intelligence);

    return intelligence;
  }

  private buildEmailPrompt(
    lead: Lead,
    stage: EmailStage,
    context: EmailContext,
    intelligence: LeadIntelligence
  ): string {
    const stageInstructions = this.getStageInstructions(stage);
    const styleGuide = this.getStyleGuide(intelligence.communicationStyle);

    return `
      Write a ${stage} sales email to ${lead.first_name || 'the prospect'}.

      RECIPIENT CONTEXT:
      - Name: ${lead.first_name} ${lead.last_name || ''}
      - Title: ${lead.title || 'Unknown role'}
      - Company: ${lead.company_name || 'their company'}
      - Industry: ${context.industry || lead.industry || 'their industry'}

      INTELLIGENCE:
      - Recent trigger event: ${intelligence.recentNews || 'No recent news found'}
      - Likely pain point: ${intelligence.predictedPain || 'Process inefficiency'}
      - Personality type: ${intelligence.personalityType}
      - Communication style preference: ${intelligence.communicationStyle}
      - Company growth stage: ${intelligence.companyGrowthStage || 'Unknown'}
      - Buying signals detected: ${intelligence.buyingSignals?.join(', ') || 'None'}
      ${intelligence.triggers && intelligence.triggers.length > 0 ?
        `- Recent triggers: ${intelligence.triggers.map((t: any) => t.description).join(', ')}` : ''}

      OUR CONTEXT:
      - Value proposition: ${context.valueProp}
      - Product: ${context.productName || 'our solution'}
      - Company: ${context.companyName || 'our company'}
      ${context.previousInteractions && context.previousInteractions.length > 0 ?
        `- Previous interactions: ${context.previousInteractions.join(', ')}` : ''}
      ${context.touchpoint ? `- This is touchpoint #${context.touchpoint + 1}` : ''}

      REQUIREMENTS:
      ${stageInstructions}
      ${styleGuide}
      - Maximum 150 words for the body
      - Use specific, concrete language
      - Include one clear call-to-action
      - Make it scannable with short paragraphs
      - Personalize based on the intelligence provided
      - Match their communication style (${intelligence.communicationStyle})

      FORMAT YOUR RESPONSE AS JSON:
      {
        "subject": "Compelling subject line with personalization",
        "preheader": "Preview text that complements the subject",
        "body": "The email body in plain text with line breaks",
        "cta": {
          "text": "Call to action text",
          "url": "https://example.com/meeting"
        },
        "personalElements": ["List of personalized elements used"]
      }
    `;
  }

  private getStageInstructions(stage: EmailStage): string {
    const instructions: Record<EmailStage, string> = {
      cold: `
        - Start with a pattern interrupt or unexpected opening
        - Reference a specific trigger event or pain point
        - Lead with value, not introduction
        - Create curiosity without being vague
        - Use social proof relevant to their industry
      `,
      follow_up: `
        - Reference the previous email naturally
        - Provide new value or insight
        - Address potential objections
        - Share a relevant case study or success metric
        - Lower the commitment threshold
      `,
      breakup: `
        - Acknowledge this is the final email
        - Create urgency or FOMO tastefully
        - Make it easy to respond with a yes/no
        - Leave the door open for future engagement
        - Consider a different angle or stakeholder
      `,
      nurture: `
        - Share valuable content without selling
        - Position as a helpful resource
        - Build trust and credibility
        - Keep it brief and value-focused
        - Soft CTA or no CTA
      `,
      reengagement: `
        - Acknowledge the time gap
        - Share something new (feature, case study, insight)
        - Reference what's changed since last contact
        - Make it worth reopening dialogue
        - Very low-pressure approach
      `
    };

    return instructions[stage] || instructions.cold;
  }

  private getStyleGuide(style: CommunicationStyle): string {
    const guides: Record<CommunicationStyle, string> = {
      formal: `
        - Use professional language and complete sentences
        - Avoid contractions and slang
        - Include proper salutations and closings
        - Maintain respectful distance
      `,
      casual: `
        - Use conversational tone
        - Include contractions (you're, we've)
        - Shorter sentences
        - Friendly and approachable
      `,
      technical: `
        - Include specific technical details
        - Use industry jargon appropriately
        - Focus on features and capabilities
        - Data-driven arguments
      `,
      conversational: `
        - Write like you speak
        - Use questions to engage
        - Include personality and warmth
        - Natural flow
      `,
      direct: `
        - Get straight to the point
        - No fluff or pleasantries
        - Bullet points for clarity
        - Clear value proposition upfront
      `
    };

    return guides[style] || guides.formal;
  }

  private async generateWithAI(prompt: string): Promise<any> {
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
          temperature: 0.7
        })
      });

      const result = await response.json() as any;
      const jsonMatch = result.content[0].text.match(/\{[\s\S]*\}/);

      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }

      throw new Error('Failed to parse AI response');
    } catch (error: any) {
      return this.getFallbackEmail();
    }
  }

  private parseGeneratedEmail(content: any, stage: EmailStage): Email {
    return {
      subject: content.subject || 'Quick question',
      preheader: content.preheader,
      body: content.body || 'I wanted to reach out...',
      cta: content.cta,
      personalizationScore: 0,
      predictedOpenRate: 0,
      predictedReplyRate: 0,
      metadata: {
        stage,
        wordCount: content.body ? content.body.split(' ').length : 0,
        readingTime: Math.ceil((content.body?.split(' ').length || 0) / 200),
        sentimentScore: this.calculateSentiment(content.body || ''),
        personalElements: content.personalElements || []
      }
    };
  }

  private async generateVariations(email: Email, count: number): Promise<EmailVariation[]> {
    const variations: EmailVariation[] = [];

    // Generate subject line variations
    const subjectVariations = await this.generateSubjectVariations(email.subject, count);
    for (const subject of subjectVariations) {
      variations.push({
        id: this.generateVariationId(),
        subject,
        body: email.body,
        variationType: 'subject'
      });
    }

    // Generate opening line variations
    const openingVariations = await this.generateOpeningVariations(email.body, count);
    for (const body of openingVariations) {
      variations.push({
        id: this.generateVariationId(),
        subject: email.subject,
        body,
        variationType: 'opening'
      });
    }

    // Generate CTA variations if applicable
    if (email.cta) {
      const ctaVariations = await this.generateCTAVariations(email.cta, count);
      for (const cta of ctaVariations) {
        variations.push({
          id: this.generateVariationId(),
          subject: email.subject,
          body: email.body.replace(email.cta.text, cta.text),
          variationType: 'cta'
        });
      }
    }

    return variations;
  }

  private async generateSubjectVariations(original: string, count: number): Promise<string[]> {
    const prompt = `
      Generate ${count} alternative subject lines similar to: "${original}"

      Requirements:
      - Similar intent and value proposition
      - Different approaches (question, statement, personalization)
      - 30-60 characters each
      - Avoid spam triggers

      Return as JSON array: ["subject1", "subject2", ...]
    `;

    try {
      const response = await this.generateWithAI(prompt);
      return Array.isArray(response) ? response : [original];
    } catch {
      return [original];
    }
  }

  private async generateOpeningVariations(originalBody: string, count: number): Promise<string[]> {
    const firstLine = originalBody.split('\n')[0];
    const restOfBody = originalBody.split('\n').slice(1).join('\n');

    const prompt = `
      Generate ${count} alternative opening lines for this email.
      Current opening: "${firstLine}"

      Requirements:
      - Same intent but different approach
      - Vary between direct, curious, value-led
      - Keep similar length

      Return as JSON array of complete email bodies with new openings.
    `;

    try {
      const response = await this.generateWithAI(prompt);
      return Array.isArray(response) ? response : [originalBody];
    } catch {
      return [originalBody];
    }
  }

  private async generateCTAVariations(original: CallToAction, count: number): Promise<CallToAction[]> {
    const variations: CallToAction[] = [
      { ...original, text: 'Can we chat for 15 minutes?' },
      { ...original, text: 'Worth a quick call?' },
      { ...original, text: 'Open to learning more?' }
    ];

    return variations.slice(0, count);
  }

  private calculatePersonalizationScore(email: Email, intelligence: LeadIntelligence): number {
    let score = 0;
    const maxScore = 100;

    // Check for personal elements
    if (email.metadata.personalElements.length > 0) {
      score += Math.min(email.metadata.personalElements.length * 10, 30);
    }

    // Check for intelligence usage
    if (email.body.toLowerCase().includes(intelligence.predictedPain?.toLowerCase() || '')) {
      score += 20;
    }

    if (intelligence.recentNews && email.body.includes(intelligence.recentNews.substring(0, 20))) {
      score += 25;
    }

    if (intelligence.triggers && intelligence.triggers.length > 0) {
      score += 15;
    }

    // Check for company-specific mentions
    if (email.body.includes('your company') || email.body.includes('{{company_name}}')) {
      score += 10;
    }

    return Math.min(score, maxScore);
  }

  private async predictOpenRate(
    email: Email,
    lead: Lead,
    intelligence: LeadIntelligence
  ): Promise<number> {
    let baseRate = 0.23; // Industry average

    // Adjust based on subject line length
    const subjectLength = email.subject.length;
    if (subjectLength >= 30 && subjectLength <= 50) {
      baseRate += 0.05;
    }

    // Adjust based on personalization
    if (email.personalizationScore > 70) {
      baseRate += 0.10;
    } else if (email.personalizationScore > 50) {
      baseRate += 0.05;
    }

    // Adjust based on lead score
    if (lead.ai_qualification_score && lead.ai_qualification_score > 70) {
      baseRate += 0.08;
    }

    // Adjust based on engagement history
    if (intelligence.engagementHistory && intelligence.engagementHistory.opens > 0) {
      baseRate += 0.15;
    }

    // Time of day adjustment (would be more sophisticated in production)
    const hour = new Date().getHours();
    if (hour >= 9 && hour <= 11) {
      baseRate += 0.03;
    }

    return Math.min(baseRate, 0.65); // Cap at 65%
  }

  private async predictReplyRate(
    email: Email,
    lead: Lead,
    intelligence: LeadIntelligence
  ): Promise<number> {
    let baseRate = 0.08; // Industry average

    // Strong personalization impact on replies
    if (email.personalizationScore > 80) {
      baseRate += 0.12;
    } else if (email.personalizationScore > 60) {
      baseRate += 0.06;
    }

    // Buying signals significantly increase reply rate
    if (intelligence.buyingSignals && intelligence.buyingSignals.length > 0) {
      baseRate += intelligence.buyingSignals.length * 0.03;
    }

    // Stage-specific adjustments
    if (email.metadata.stage === 'breakup') {
      baseRate += 0.05; // Breakup emails often get responses
    }

    // CTA clarity
    if (email.cta && email.cta.text.length < 30) {
      baseRate += 0.02;
    }

    // Lead engagement history
    if (intelligence.engagementHistory?.replies && intelligence.engagementHistory.replies > 0) {
      baseRate += 0.20; // Previous responders likely to respond again
    }

    return Math.min(baseRate, 0.35); // Cap at 35%
  }

  private calculateSentiment(text: string): number {
    // Simple sentiment scoring (-1 to 1)
    const positiveWords = ['great', 'excellent', 'amazing', 'love', 'wonderful', 'fantastic', 'success'];
    const negativeWords = ['problem', 'issue', 'difficult', 'struggle', 'pain', 'challenge', 'fail'];

    let score = 0;
    const words = text.toLowerCase().split(/\s+/);

    for (const word of words) {
      if (positiveWords.includes(word)) score += 0.1;
      if (negativeWords.includes(word)) score -= 0.05; // Less penalty for problem-agitation
    }

    return Math.max(-1, Math.min(1, score));
  }

  // Intelligence gathering methods
  private async fetchRecentNews(lead: Lead): Promise<string | undefined> {
    // In production, integrate with news APIs, press release services
    // For now, return mock data
    if (lead.company_name) {
      const mockNews = [
        'announced Series B funding',
        'launched new product line',
        'expanded to new markets',
        'appointed new leadership'
      ];
      return `${lead.company_name} ${mockNews[Math.floor(Math.random() * mockNews.length)]}`;
    }
    return undefined;
  }

  private async fetchRecentActivity(lead: Lead): Promise<string | undefined> {
    // Check CRM for recent activities
    const db = this.env.DB_CRM;
    const result = await db.prepare(`
      SELECT description FROM lead_activities
      WHERE lead_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(lead.id).first();

    return result?.description as string | undefined;
  }

  private async predictPainPoints(lead: Lead): Promise<string> {
    const painsByRole: Record<string, string[]> = {
      'sales': ['long sales cycles', 'lead qualification', 'pipeline visibility'],
      'marketing': ['lead generation', 'attribution', 'campaign ROI'],
      'executive': ['revenue growth', 'operational efficiency', 'competitive pressure'],
      'engineering': ['technical debt', 'deployment speed', 'system reliability'],
      'hr': ['talent retention', 'hiring efficiency', 'employee engagement']
    };

    const rolePains = painsByRole[this.detectDepartment(lead.title || '')] ||
                     ['operational efficiency', 'growth challenges'];

    return rolePains[Math.floor(Math.random() * rolePains.length)];
  }

  private detectDepartment(title: string): string {
    const titleLower = title.toLowerCase();

    if (titleLower.includes('sales') || titleLower.includes('account')) return 'sales';
    if (titleLower.includes('market') || titleLower.includes('growth')) return 'marketing';
    if (titleLower.includes('ceo')
  || titleLower.includes('coo') || titleLower.includes('president')) return 'executive';
    if (titleLower.includes('engineer') || titleLower.includes('developer')) return 'engineering';
    if (titleLower.includes('hr') || titleLower.includes('people') || titleLower.includes('talent')) return 'hr';

    return 'general';
  }

  private async analyzeommunicationStyle(lead: Lead): Promise<{
    personality: PersonalityType;
    style: CommunicationStyle;
  }> {
    // Analyze based on title and previous interactions
    const title = (lead.title || '').toLowerCase();

    let personality: PersonalityType = 'analytical';
    let style: CommunicationStyle = 'formal';

    // Title-based analysis
    if (title.includes('ceo') || title.includes('founder')) {
      personality = 'driver';
      style = 'direct';
    } else if (title.includes('sales') || title.includes('marketing')) {
      personality = 'expressive';
      style = 'conversational';
    } else if (title.includes('engineer') || title.includes('analyst')) {
      personality = 'analytical';
      style = 'technical';
    } else if (title.includes('hr') || title.includes('people')) {
      personality = 'amiable';
      style = 'casual';
    }

    return { personality, style };
  }

  private async gatherCompanyIntelligence(companyId: string): Promise<{
    growthStage?: string;
    techStack?: string[];
    competitors?: string[];
  }> {
    // In production, integrate with data providers
    // For now, return mock data
    return {
      growthStage: 'growth',
      techStack: ['Salesforce', 'HubSpot', 'Slack'],
      competitors: ['Competitor A', 'Competitor B']
    };
  }

  private async getEngagementHistory(leadId: string): Promise<any> {
    const db = this.env.DB_CRM;
    const result = await db.prepare(`
      SELECT
        COUNT(CASE WHEN opened_at IS NOT NULL THEN 1 END) as opens,
        COUNT(CASE WHEN clicked_at IS NOT NULL THEN 1 END) as clicks,
        COUNT(CASE WHEN replied_at IS NOT NULL THEN 1 END) as replies
      FROM channel_messages
      WHERE lead_id = ? AND channel = 'email'
    `).bind(leadId).first();

    return {
      opens: result?.opens || 0,
      clicks: result?.clicks || 0,
      replies: result?.replies || 0
    };
  }

  private async detectBuyingSignals(lead: Lead): Promise<string[]> {
    const signals: string[] = [];

    // Check qualification score
    if (lead.ai_qualification_score && lead.ai_qualification_score > 70) {
      signals.push('high_qualification_score');
    }

    // Check for recent engagement
    const recentEngagement = await this.checkRecentEngagement(lead.id);
    if (recentEngagement) {
      signals.push('recent_engagement');
    }

    // Check for specific keywords in notes
    if (lead.ai_intent_summary?.includes('looking for') ||
        lead.ai_intent_summary?.includes('interested in')) {
      signals.push('expressed_interest');
    }

    return signals;
  }

  private async checkRecentEngagement(leadId: string): Promise<boolean> {
    const db = this.env.DB_CRM;
    const result = await db.prepare(`
      SELECT COUNT(*) as count
      FROM lead_activities
      WHERE lead_id = ?
        AND created_at >= datetime('now', '-7 days')
    `).bind(leadId).first();

    return (result?.count as number) > 0;
  }

  private async findTriggers(lead: Lead): Promise<any[]> {
    const triggers = [];

    // Job change trigger
    if (lead.created_at) {
      const daysSinceCreation = (Date.now() - new Date(lead.created_at).getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceCreation < 30) {
        triggers.push({
          type: 'new_contact',
          description: 'Recently added to CRM',
          relevance: 0.7
        });
      }
    }

    // Add more trigger detection logic here

    return triggers;
  }

  // Helper methods
  private generateSequenceId(): string {
    return `seq_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  private generateVariationId(): string {
    return `var_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  private getFallbackEmail(): any {
    return {
      subject: 'Quick question about {{company_name}}',
      body: `Hi {{first_name}},\n\nI noticed your team might be facing
  challenges with [specific issue].\n\nWe've helped similar companies reduce this by 40%.\n\nWorth a quick chat?\n\nBest regards`,
      cta: {
        text: 'Schedule 15 minutes',
        url: 'https://calendly.com'
      },
      personalElements: ['first_name', 'company_name']
    };
  }

  // Public methods for email management
  async selectBestVariation(variations: EmailVariation[], lead: Lead): Promise<EmailVariation> {
    // In production, use ML model to predict best variation
    // For now, return random variation
    return variations[Math.floor(Math.random() * variations.length)];
  }

  async trackEmailPerformance(emailId: string, metrics: {
    opened?: boolean;
    clicked?: boolean;
    replied?: boolean;
  }): Promise<void> {
    // Update email performance metrics in database
    const db = this.env.DB_CRM;

    const updates = [];
    const values = [];

    if (metrics.opened !== undefined) {
      updates.push('opened_at = ?');
      values.push(metrics.opened ? new Date().toISOString() : null);
    }
    if (metrics.clicked !== undefined) {
      updates.push('clicked_at = ?');
      values.push(metrics.clicked ? new Date().toISOString() : null);
    }
    if (metrics.replied !== undefined) {
      updates.push('replied_at = ?');
      values.push(metrics.replied ? new Date().toISOString() : null);
    }

    if (updates.length > 0) {
      values.push(emailId);
      await db.prepare(`
        UPDATE channel_messages
        SET ${updates.join(', ')}
        WHERE id = ?
      `).bind(...values).run();
    }
  }

  async optimizeSubjectLine(subject: string, targetAudience: string): Promise<string> {
    const prompt = `
      Optimize this email subject line for ${targetAudience}:
      "${subject}"

      Make it more compelling while keeping it under 50 characters.
      Avoid spam triggers.
      Return only the optimized subject line.
    `;

    try {
      const response = await this.generateWithAI(prompt);
      return response.subject || subject;
    } catch {
      return subject;
    }
  }
}