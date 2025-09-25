import type { Lead, Contact } from '../types/crm';
import { AIEmailWriter, EmailStage, EmailContext } from './ai-email-writer';
import type { Env } from '../types/env';

export interface EmailTemplate {
  id: string;
  name: string;
  category: EmailTemplateCategory;
  stage: EmailStage;
  subject: string;
  body: string;
  variables: TemplateVariable[];
  performance?: {
    sent: number;
    opened: number;
    clicked: number;
    replied: number;
    openRate?: number;
    clickRate?: number;
    replyRate?: number;
  };
  aiOptimized?: boolean;
  bestPerformingVariation?: string;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export type EmailTemplateCategory =
  | 'cold_outreach'
  | 'follow_up'
  | 'meeting_request'
  | 'demo_follow_up'
  | 'proposal'
  | 'negotiation'
  | 'win_back'
  | 'referral_request'
  | 'event_invitation'
  | 'content_share'
  | 'case_study'
  | 'testimonial_request';

export interface TemplateVariable {
  key: string;
  description: string;
  defaultValue?: string;
  required: boolean;
  source?: 'lead' | 'company' | 'custom' | 'ai_generated';
}

export class EmailTemplateEngine {
  private env: Env;
  private aiWriter: AIEmailWriter;
  private templateCache: Map<string, EmailTemplate>;

  constructor(env: Env) {
    this.env = env;
    this.aiWriter = new AIEmailWriter(env);
    this.templateCache = new Map();
  }

  async createTemplate(
    name: string,
    category: EmailTemplateCategory,
    stage: EmailStage,
    content?: { subject?: string; body?: string }
  ): Promise<EmailTemplate> {
    const template: EmailTemplate = {
      id: this.generateTemplateId(),
      name,
      category,
      stage,
      subject: content?.subject || this.getDefaultSubject(category),
      body: content?.body || this.getDefaultBody(category),
      variables: this.extractVariables(content?.body || ''),
      active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Save to database
    await this.saveTemplate(template);

    // Cache it
    this.templateCache.set(template.id, template);

    return template;
  }

  async getTemplate(templateId: string): Promise<EmailTemplate | null> {
    // Check cache
    if (this.templateCache.has(templateId)) {
      return this.templateCache.get(templateId)!;
    }

    // Fetch from database
    const db = this.env.DB_CRM;
    const result = await db.prepare(`
      SELECT * FROM email_templates WHERE id = ?
    `).bind(templateId).first();

    if (result) {
      const template = {
        ...result,
        variables: JSON.parse(result.variables as string),
        performance: result.performance ? JSON.parse(result.performance as string) : undefined
      } as EmailTemplate;

      this.templateCache.set(templateId, template);
      return template;
    }

    return null;
  }

  async getTemplatesByCategory(category: EmailTemplateCategory): Promise<EmailTemplate[]> {
    const db = this.env.DB_CRM;
    const results = await db.prepare(`
      SELECT * FROM email_templates
      WHERE category = ? AND active = 1
      ORDER BY created_at DESC
    `).bind(category).all();

    return results.results.map(r => ({
      ...r,
      variables: JSON.parse(r.variables as string),
      performance: r.performance ? JSON.parse(r.performance as string) : undefined
    })) as EmailTemplate[];
  }

  async renderTemplate(
    templateId: string,
    lead: Lead,
    customVariables?: Record<string, string>
  ): Promise<{ subject: string; body: string }> {
    const template = await this.getTemplate(templateId);
    if (!template) {
      throw new Error('Template not found');
    }

    let subject = template.subject;
    let body = template.body;

    // Replace variables
    for (const variable of template.variables) {
      const value = await this.resolveVariable(variable, lead, customVariables);
      const regex = new RegExp(`{{${variable.key}}}`, 'g');
      subject = subject.replace(regex, value);
      body = body.replace(regex, value);
    }

    return { subject, body };
  }

  async optimizeTemplate(templateId: string): Promise<EmailTemplate> {
    const template = await this.getTemplate(templateId);
    if (!template) {
      throw new Error('Template not found');
    }

    // Generate optimized version using AI
    const optimizedContent = await this.aiWriter.optimizeSubjectLine(
      template.subject,
      template.category
    );

    // Create variations for A/B testing
    const variations = await this.generateTemplateVariations(template);

    // Update template with best performing variation
    if (template.performance && template.performance.sent > 100) {
      const bestVariation = await this.selectBestVariation(variations, template.performance);
      template.subject = bestVariation.subject;
      template.body = bestVariation.body;
      template.aiOptimized = true;
      template.bestPerformingVariation = bestVariation.id;
    }

    // Save updated template
    await this.updateTemplate(template);

    return template;
  }

  async generateTemplateVariations(template: EmailTemplate): Promise<any[]> {
    const variations = [];

    // Subject line variations
    const subjects = [
      template.subject,
      `Re: ${template.subject}`,
      template.subject.replace('?', ''),
      `Quick question - ${template.subject}`
    ];

    // Opening line variations
    const openings = [
      template.body.split('\n')[0],
      `I hope this email finds you well.`,
      `I'll keep this brief.`,
      `I noticed something interesting about your company.`
    ];

    // Generate combinations
    for (const subject of subjects) {
      for (const opening of openings) {
        variations.push({
          id: this.generateTemplateId(),
          subject,
          body: template.body.replace(template.body.split('\n')[0], opening)
        });
      }
    }

    return variations;
  }

  async trackTemplatePerformance(
    templateId: string,
    metric: 'sent' | 'opened' | 'clicked' | 'replied'
  ): Promise<void> {
    const template = await this.getTemplate(templateId);
    if (!template) return;

    if (!template.performance) {
      template.performance = {
        sent: 0,
        opened: 0,
        clicked: 0,
        replied: 0
      };
    }

    template.performance[metric]++;

    // Calculate rates
    if (template.performance.sent > 0) {
      template.performance.openRate = template.performance.opened / template.performance.sent;
      template.performance.clickRate = template.performance.clicked / template.performance.sent;
      template.performance.replyRate = template.performance.replied / template.performance.sent;
    }

    await this.updateTemplate(template);
  }

  // Default templates by category
  private getDefaultSubject(category: EmailTemplateCategory): string {
    const subjects: Record<EmailTemplateCategory, string> = {
      cold_outreach: 'Quick question about {{company_name}}',
      follow_up: 'Following up on my previous email',
      meeting_request: '15 minutes to discuss {{pain_point}}?',
      demo_follow_up: 'Thank you for your time today',
      proposal: 'Proposal for {{company_name}}',
      negotiation: 'Re: Our discussion about pricing',
      win_back: 'We miss you at {{product_name}}',
      referral_request: 'Quick favor to ask',
      event_invitation: 'You\'re invited: {{event_name}}',
      content_share: 'Thought you might find this useful',
      case_study: 'How {{similar_company}} achieved {{result}}',
      testimonial_request: 'Quick request for feedback'
    };

    return subjects[category] || 'Following up';
  }

  private getDefaultBody(category: EmailTemplateCategory): string {
    const bodies: Record<EmailTemplateCategory, string> = {
      cold_outreach: `Hi {{first_name}},

I noticed {{company_name}} is {{recent_trigger}}. Many companies in {{industry}} struggle with {{pain_point}}.

We've helped companies like {{similar_company}} {{value_prop}}.

Worth a quick chat to see if we can help?

Best regards,
{{sender_name}}`,

      follow_up: `Hi {{first_name}},

I wanted to follow up on my previous email about {{topic}}.

I understand you're busy, so I'll keep this brief. {{value_statement}}

Are you available for a quick 15-minute call this week?

Best,
{{sender_name}}`,

      meeting_request: `Hi {{first_name}},

Based on what I know about {{company_name}}, I believe we could help with {{specific_challenge}}.

I'd love to show you how we've helped {{similar_company}} achieve {{specific_result}}.

Do you have 15 minutes this week for a brief call?

{{calendar_link}}

Best regards,
{{sender_name}}`,

      demo_follow_up: `Hi {{first_name}},

Thank you for taking the time to see our demo today.

As discussed, here are the key points:
{{key_points}}

Next steps:
{{next_steps}}

Let me know if you have any questions!

Best,
{{sender_name}}`,

      proposal: `Hi {{first_name}},

As promised, I'm sending over our proposal for {{company_name}}.

{{proposal_link}}

Key highlights:
{{highlights}}

I'm available to discuss any questions you might have.

Best regards,
{{sender_name}}`,

      negotiation: `Hi {{first_name}},

I've discussed your requirements with our team, and we can offer:
{{offer_details}}

This represents a {{discount_percentage}}% discount from our standard pricing.

Does this work for your budget?

Best,
{{sender_name}}`,

      win_back: `Hi {{first_name}},

It's been a while since we last connected. I wanted to reach out because we've recently {{new_feature_or_update}}.

{{special_offer}}

Would you be interested in giving us another try?

Best regards,
{{sender_name}}`,

      referral_request: `Hi {{first_name}},

I hope you're enjoying {{product_benefit}}.

I'm reaching out to ask if you know anyone in your network who might benefit from {{value_prop}}.

If you could introduce me to anyone who might be interested, I'd really appreciate it.

Thanks in advance!
{{sender_name}}`,

      event_invitation: `Hi {{first_name}},

You're invited to {{event_name}} on {{event_date}}.

{{event_description}}

{{registration_link}}

Hope to see you there!

{{sender_name}}`,

      content_share: `Hi {{first_name}},

I came across this {{content_type}} and immediately thought of our conversation about {{topic}}.

{{content_link}}

Key takeaways:
{{key_takeaways}}

Thought you might find it useful.

Best,
{{sender_name}}`,

      case_study: `Hi {{first_name}},

I wanted to share how {{similar_company}} in {{industry}} achieved {{impressive_result}}.

{{case_study_link}}

The approach they took could work well for {{company_name}} too.

Interested in discussing how we could implement something similar?

Best regards,
{{sender_name}}`,

      testimonial_request: `Hi {{first_name}},

I hope you're seeing great results with {{product_name}}.

Would you be willing to share a brief testimonial about your experience?

It would really help other {{target_audience}} understand the value we provide.

{{testimonial_link}}

Thanks so much!
{{sender_name}}`
    };

    return bodies[category] || bodies.cold_outreach;
  }

  private extractVariables(body: string): TemplateVariable[] {
    const variables: TemplateVariable[] = [];
    const regex = /{{([^}]+)}}/g;
    const found = new Set<string>();
    let match;

    while ((match = regex.exec(body)) !== null) {
      const key = match[1];
      if (!found.has(key)) {
        found.add(key);
        variables.push({
          key,
          description: this.getVariableDescription(key),
          required: this.isRequiredVariable(key),
          source: this.getVariableSource(key)
        });
      }
    }

    return variables;
  }

  private getVariableDescription(key: string): string {
    const descriptions: Record<string, string> = {
      first_name: 'Recipient first name',
      last_name: 'Recipient last name',
      company_name: 'Recipient company name',
      industry: 'Company industry',
      pain_point: 'Identified pain point',
      value_prop: 'Our value proposition',
      sender_name: 'Sender name',
      product_name: 'Product name',
      recent_trigger: 'Recent event or trigger',
      similar_company: 'Similar company example'
    };

    return descriptions[key] || `Variable: ${key}`;
  }

  private isRequiredVariable(key: string): boolean {
    const required = ['first_name', 'sender_name'];
    return required.includes(key);
  }

  private getVariableSource(key: string): 'lead' | 'company' | 'custom' | 'ai_generated' {
    const leadVars = ['first_name', 'last_name', 'title', 'email', 'phone'];
    const companyVars = ['company_name', 'industry', 'company_size'];
    const aiVars = ['pain_point', 'recent_trigger', 'value_prop', 'similar_company'];

    if (leadVars.includes(key)) return 'lead';
    if (companyVars.includes(key)) return 'company';
    if (aiVars.includes(key)) return 'ai_generated';
    return 'custom';
  }

  private async resolveVariable(
    variable: TemplateVariable,
    lead: Lead,
    customVariables?: Record<string, string>
  ): Promise<string> {
    // Check custom variables first
    if (customVariables && customVariables[variable.key]) {
      return customVariables[variable.key];
    }

    // Resolve based on source
    switch (variable.source) {
      case 'lead':
        return this.resolveLeadVariable(variable.key, lead);
      case 'company':
        return this.resolveCompanyVariable(variable.key, lead);
      case 'ai_generated':
        return this.resolveAIVariable(variable.key, lead);
      default:
        return variable.defaultValue || '';
    }
  }

  private resolveLeadVariable(key: string, lead: Lead): string {
    const value = (lead as any)[key];
    return value || this.getDefaultValue(key);
  }

  private resolveCompanyVariable(key: string, lead: Lead): string {
    const companyData: any = {
      company_name: lead.company_name,
      industry: lead.industry,
      company_size: lead.company_size
    };

    return companyData[key] || this.getDefaultValue(key);
  }

  private async resolveAIVariable(key: string, lead: Lead): Promise<string> {
    // Generate AI content based on variable
    const context: EmailContext = {
      valueProp: 'improve sales efficiency',
      productName: 'CoreFlow360'
    };

    const intelligence = await this.aiWriter['gatherIntelligence'](lead);

    switch (key) {
      case 'pain_point':
        return intelligence.predictedPain || 'operational challenges';
      case 'recent_trigger':
        return intelligence.recentNews || 'growing rapidly';
      case 'value_prop':
        return '30% increase in sales productivity';
      case 'similar_company':
        return 'companies in your industry';
      default:
        return '';
    }
  }

  private getDefaultValue(key: string): string {
    const defaults: Record<string, string> = {
      first_name: 'there',
      company_name: 'your company',
      industry: 'your industry',
      sender_name: 'The CoreFlow Team'
    };

    return defaults[key] || '';
  }

  private async selectBestVariation(variations: any[], performance: any): any {
    // Simple selection based on performance
    // In production, use more sophisticated ML models
    return variations[0];
  }

  private async saveTemplate(template: EmailTemplate): Promise<void> {
    const db = this.env.DB_CRM;

    await db.prepare(`
      INSERT INTO email_templates (
        id, name, category, stage, subject, body,
        variables, active, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      template.id,
      template.name,
      template.category,
      template.stage,
      template.subject,
      template.body,
      JSON.stringify(template.variables),
      template.active ? 1 : 0,
      template.created_at,
      template.updated_at
    ).run();
  }

  private async updateTemplate(template: EmailTemplate): Promise<void> {
    const db = this.env.DB_CRM;

    await db.prepare(`
      UPDATE email_templates
      SET subject = ?, body = ?, variables = ?,
          performance = ?, ai_optimized = ?,
          best_performing_variation = ?, updated_at = ?
      WHERE id = ?
    `).bind(
      template.subject,
      template.body,
      JSON.stringify(template.variables),
      template.performance ? JSON.stringify(template.performance) : null,
      template.aiOptimized ? 1 : 0,
      template.bestPerformingVariation || null,
      new Date().toISOString(),
      template.id
    ).run();
  }

  private generateTemplateId(): string {
    return `tpl_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  // Bulk operations
  async createDefaultTemplates(): Promise<void> {
    const categories: EmailTemplateCategory[] = [
      'cold_outreach',
      'follow_up',
      'meeting_request',
      'demo_follow_up',
      'proposal',
      'negotiation',
      'win_back',
      'referral_request',
      'event_invitation',
      'content_share',
      'case_study',
      'testimonial_request'
    ];

    for (const category of categories) {
      await this.createTemplate(
        `Default ${category.replace('_', ' ')} template`,
        category,
        this.getStageForCategory(category)
      );
    }
  }

  private getStageForCategory(category: EmailTemplateCategory): EmailStage {
    const stageMap: Record<EmailTemplateCategory, EmailStage> = {
      cold_outreach: 'cold',
      follow_up: 'follow_up',
      meeting_request: 'follow_up',
      demo_follow_up: 'follow_up',
      proposal: 'follow_up',
      negotiation: 'follow_up',
      win_back: 'reengagement',
      referral_request: 'nurture',
      event_invitation: 'nurture',
      content_share: 'nurture',
      case_study: 'nurture',
      testimonial_request: 'nurture'
    };

    return stageMap[category] || 'cold';
  }
}