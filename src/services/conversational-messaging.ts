import type { Lead, Contact } from '../types/crm';
import type { Env } from '../types/env';
import { SMSChannel } from './channels/sms-channel';
import { WhatsAppChannel } from './channels/whatsapp-channel';
import { MeetingBooker } from './meeting-booker';
import { AIEmailWriter } from './ai-email-writer';

export interface Message {
  id: string;
  channel: 'sms' | 'whatsapp';
  from: string;
  to: string;
  body: string;
  media?: MediaAttachment[];
  timestamp: string;
  direction: 'inbound' | 'outbound';
  status: 'received' | 'sent' | 'delivered' | 'read' | 'failed';
  metadata?: {
    twilioSid?: string;
    whatsappMessageId?: string;
    isTemplate?: boolean;
    templateName?: string;
  };
}

export interface MediaAttachment {
  type: 'image' | 'video' | 'audio' | 'document';
  url: string;
  caption?: string;
  mimeType?: string;
  size?: number;
}

export interface Conversation {
  id: string;
  leadId: string;
  channel: 'sms' | 'whatsapp';
  status: 'active' | 'paused' | 'closed';
  messages: ConversationMessage[];
  context: ConversationContext;
  startedAt: string;
  lastMessageAt: string;
  aiSummary?: string;
  detectedIntents?: DetectedIntent[];
}

export interface ConversationMessage {
  role: 'human' | 'ai' | 'system';
  content: string;
  timestamp: string;
  metadata?: any;
}

export interface ConversationContext {
  lead: Lead;
  contact?: Contact;
  currentStep: string;
  variables: Record<string, any>;
  lastActivity: string;
  sessionData: Record<string, any>;
}

export interface DetectedIntent {
  intent: string;
  confidence: number;
  entities: Record<string, any>;
  timestamp: string;
}

export interface ConversationFlow {
  id: string;
  name: string;
  steps: FlowStep[];
  triggers: FlowTrigger[];
  variables: FlowVariable[];
  conditions: FlowCondition[];
}

export interface FlowStep {
  id: string;
  type: 'message' | 'question' | 'action' | 'condition' | 'wait';
  content?: string;
  question?: string;
  action?: string;
  nextStep?: string;
  conditions?: FlowCondition[];
}

export interface FlowTrigger {
  type: 'keyword' | 'intent' | 'time' | 'event';
  value: string;
  conditions?: FlowCondition[];
}

export interface FlowVariable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'date';
  required: boolean;
  defaultValue?: any;
}

export interface FlowCondition {
  variable: string;
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than' | 'exists';
  value: any;
}

export interface ConversationTemplate {
  id: string;
  name: string;
  channel: 'sms' | 'whatsapp';
  content: string;
  variables: string[];
  category: 'greeting' | 'follow_up' | 'reminder' | 'confirmation' | 'closing';
}

export class ConversationalMessagingService {
  private env: Env;
  private smsChannel: SMSChannel;
  private whatsappChannel: WhatsAppChannel;
  private meetingBooker: MeetingBooker;
  private aiEmailWriter: AIEmailWriter;
  private conversations: Map<string, Conversation> = new Map();
  private flows: Map<string, ConversationFlow> = new Map();
  private templates: Map<string, ConversationTemplate> = new Map();

  constructor(env: Env) {
    this.env = env;
    this.smsChannel = new SMSChannel(env);
    this.whatsappChannel = new WhatsAppChannel(env);
    this.meetingBooker = new MeetingBooker(env);
    this.aiEmailWriter = new AIEmailWriter(env);
    this.initializeFlows();
    this.initializeTemplates();
  }

  async sendMessage(message: Omit<Message, 'id' | 'timestamp' | 'status'>): Promise<Message> {
    const fullMessage: Message = {
      ...message,
      id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      status: 'sent'
    };

    try {
      if (message.channel === 'sms') {
        await this.smsChannel.send(fullMessage);
      } else if (message.channel === 'whatsapp') {
        await this.whatsappChannel.send(fullMessage);
      }

      fullMessage.status = 'delivered';
    } catch (error: any) {
      fullMessage.status = 'failed';
      console.error('Failed to send message:', error);
    }

    return fullMessage;
  }

  async receiveMessage(message: Message): Promise<void> {
    // Find or create conversation
    const conversation = await this.getOrCreateConversation(message.leadId, message.channel);
    
    // Add message to conversation
    conversation.messages.push({
      role: 'human',
      content: message.body,
      timestamp: message.timestamp,
      metadata: message.metadata
    });

    // Update conversation context
    conversation.lastMessageAt = message.timestamp;
    conversation.context.lastActivity = message.timestamp;

    // Process message through AI
    await this.processMessage(conversation, message);

    // Save conversation
    this.conversations.set(conversation.id, conversation);
  }

  async processMessage(conversation: Conversation, message: Message): Promise<void> {
    // Detect intent
    const intent = await this.detectIntent(message.body);
    if (intent) {
      conversation.detectedIntents = conversation.detectedIntents || [];
      conversation.detectedIntents.push(intent);
    }

    // Find matching flow
    const flow = this.findMatchingFlow(conversation, message);
    if (flow) {
      await this.executeFlow(conversation, flow, message);
    } else {
      // Default AI response
      const response = await this.generateAIResponse(conversation, message);
      if (response) {
        await this.sendMessage({
          channel: conversation.channel,
          from: this.env.TWILIO_PHONE_NUMBER || '',
          to: message.from,
          body: response,
          direction: 'outbound'
        });
      }
    }
  }

  private async detectIntent(text: string): Promise<DetectedIntent | null> {
    // Mock intent detection - would use AI in production
    const intents = [
      { pattern: /schedule|meeting|book/i, intent: 'schedule_meeting' },
      { pattern: /price|cost|pricing/i, intent: 'pricing_inquiry' },
      { pattern: /demo|show|presentation/i, intent: 'request_demo' },
      { pattern: /help|support|assistance/i, intent: 'support_request' },
      { pattern: /yes|sure|okay|agree/i, intent: 'positive_response' },
      { pattern: /no|not|decline|refuse/i, intent: 'negative_response' }
    ];

    for (const { pattern, intent } of intents) {
      if (pattern.test(text)) {
        return {
          intent,
          confidence: 0.8,
          entities: {},
          timestamp: new Date().toISOString()
        };
      }
    }

    return null;
  }

  private findMatchingFlow(conversation: Conversation, message: Message): ConversationFlow | null {
    for (const flow of this.flows.values()) {
      for (const trigger of flow.triggers) {
        if (this.matchesTrigger(trigger, message, conversation)) {
          return flow;
        }
      }
    }
    return null;
  }

  private matchesTrigger(trigger: FlowTrigger, message: Message, conversation: Conversation): boolean {
    switch (trigger.type) {
      case 'keyword':
        return message.body.toLowerCase().includes(trigger.value.toLowerCase());
      case 'intent':
        const lastIntent = conversation.detectedIntents?.[conversation.detectedIntents.length - 1];
        return lastIntent?.intent === trigger.value;
      case 'time':
        // Time-based triggers would be handled separately
        return false;
      case 'event':
        // Event-based triggers would be handled separately
        return false;
      default:
        return false;
    }
  }

  private async executeFlow(conversation: Conversation, flow: ConversationFlow, message: Message): Promise<void> {
    let currentStep = flow.steps[0];
    
    while (currentStep) {
      await this.executeStep(conversation, currentStep, message);
      
      // Find next step
      if (currentStep.nextStep) {
        currentStep = flow.steps.find(step => step.id === currentStep.nextStep) || null;
      } else {
        break;
      }
    }
  }

  private async executeStep(conversation: Conversation, step: FlowStep, message: Message): Promise<void> {
    switch (step.type) {
      case 'message':
        if (step.content) {
          const processedContent = this.processTemplate(step.content, conversation.context);
          await this.sendMessage({
            channel: conversation.channel,
            from: this.env.TWILIO_PHONE_NUMBER || '',
            to: conversation.context.lead.phone || '',
            body: processedContent,
            direction: 'outbound'
          });
        }
        break;
        
      case 'question':
        if (step.question) {
          const processedQuestion = this.processTemplate(step.question, conversation.context);
          await this.sendMessage({
            channel: conversation.channel,
            from: this.env.TWILIO_PHONE_NUMBER || '',
            to: conversation.context.lead.phone || '',
            body: processedQuestion,
            direction: 'outbound'
          });
        }
        break;
        
      case 'action':
        if (step.action) {
          await this.executeAction(step.action, conversation, message);
        }
        break;
        
      case 'condition':
        // Handle conditional logic
        break;
        
      case 'wait':
        // Handle waiting logic
        break;
    }
  }

  private async executeAction(action: string, conversation: Conversation, message: Message): Promise<void> {
    switch (action) {
      case 'schedule_meeting':
        await this.meetingBooker.scheduleMeeting(conversation.context.lead);
        break;
        
      case 'send_demo_invite':
        // Send demo invitation
        break;
        
      case 'create_follow_up':
        // Create follow-up task
        break;
        
      case 'escalate_to_human':
        // Escalate to human agent
        break;
    }
  }

  private async generateAIResponse(conversation: Conversation, message: Message): Promise<string | null> {
    // Mock AI response generation
    const responses = [
      "Thanks for your message! I'll get back to you soon.",
      "I understand. Let me help you with that.",
      "That's a great question. Let me find the right person to help you.",
      "I'd be happy to schedule a meeting with you. When works best?",
      "Let me connect you with our team to discuss this further."
    ];

    return responses[Math.floor(Math.random() * responses.length)];
  }

  private processTemplate(template: string, context: ConversationContext): string {
    let processed = template;
    
    // Replace variables
    for (const [key, value] of Object.entries(context.variables)) {
      processed = processed.replace(new RegExp(`{{${key}}}`, 'g'), String(value));
    }
    
    // Replace lead data
    processed = processed.replace(/{{lead\.name}}/g, context.lead.name || '');
    processed = processed.replace(/{{lead\.company}}/g, context.lead.company || '');
    processed = processed.replace(/{{lead\.phone}}/g, context.lead.phone || '');
    processed = processed.replace(/{{lead\.email}}/g, context.lead.email || '');
    
    return processed;
  }

  private async getOrCreateConversation(leadId: string, channel: 'sms' | 'whatsapp'): Promise<Conversation> {
    // Find existing conversation
    for (const conversation of this.conversations.values()) {
      if (conversation.leadId === leadId && conversation.channel === channel) {
        return conversation;
      }
    }

    // Create new conversation
    const conversation: Conversation = {
      id: `conv_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      leadId,
      channel,
      status: 'active',
      messages: [],
      context: {
        lead: { id: leadId, name: '', email: '', phone: '', company: '' } as Lead,
        currentStep: 'greeting',
        variables: {},
        lastActivity: new Date().toISOString(),
        sessionData: {}
      },
      startedAt: new Date().toISOString(),
      lastMessageAt: new Date().toISOString()
    };

    this.conversations.set(conversation.id, conversation);
    return conversation;
  }

  private initializeFlows(): void {
    // Greeting flow
    const greetingFlow: ConversationFlow = {
      id: 'greeting',
      name: 'Initial Greeting',
      steps: [
        {
          id: 'greet',
          type: 'message',
          content: 'Hi {{lead.name}}! Thanks for your interest. How can I help you today?',
          nextStep: 'wait_response'
        },
        {
          id: 'wait_response',
          type: 'wait'
        }
      ],
      triggers: [
        {
          type: 'keyword',
          value: 'hello'
        }
      ],
      variables: [],
      conditions: []
    };

    this.flows.set('greeting', greetingFlow);

    // Meeting scheduling flow
    const meetingFlow: ConversationFlow = {
      id: 'schedule_meeting',
      name: 'Schedule Meeting',
      steps: [
        {
          id: 'confirm_meeting',
          type: 'message',
          content: 'I\'d be happy to schedule a meeting with you. What time works best?',
          nextStep: 'collect_preferences'
        },
        {
          id: 'collect_preferences',
          type: 'wait'
        }
      ],
      triggers: [
        {
          type: 'intent',
          value: 'schedule_meeting'
        }
      ],
      variables: [],
      conditions: []
    };

    this.flows.set('schedule_meeting', meetingFlow);
  }

  private initializeTemplates(): void {
    const templates: ConversationTemplate[] = [
      {
        id: 'greeting',
        name: 'Welcome Message',
        channel: 'sms',
        content: 'Hi {{lead.name}}! Thanks for reaching out. How can I help you today?',
        variables: ['lead.name'],
        category: 'greeting'
      },
      {
        id: 'follow_up',
        name: 'Follow Up',
        channel: 'sms',
        content: 'Hi {{lead.name}}, just following up on our conversation. Do you have any questions?',
        variables: ['lead.name'],
        category: 'follow_up'
      },
      {
        id: 'meeting_confirmation',
        name: 'Meeting Confirmation',
        channel: 'sms',
        content: 'Great! I\'ve scheduled a meeting for you. You\'ll receive a calendar invite shortly.',
        variables: [],
        category: 'confirmation'
      }
    ];

    for (const template of templates) {
      this.templates.set(template.id, template);
    }
  }

  // Public methods
  async getConversation(conversationId: string): Promise<Conversation | null> {
    return this.conversations.get(conversationId) || null;
  }

  async getConversationsByLead(leadId: string): Promise<Conversation[]> {
    const conversations: Conversation[] = [];
    for (const conversation of this.conversations.values()) {
      if (conversation.leadId === leadId) {
        conversations.push(conversation);
      }
    }
    return conversations;
  }

  async updateConversationContext(conversationId: string, updates: Partial<ConversationContext>): Promise<void> {
    const conversation = this.conversations.get(conversationId);
    if (conversation) {
      conversation.context = { ...conversation.context, ...updates };
      this.conversations.set(conversationId, conversation);
    }
  }

  async pauseConversation(conversationId: string): Promise<void> {
    const conversation = this.conversations.get(conversationId);
    if (conversation) {
      conversation.status = 'paused';
      this.conversations.set(conversationId, conversation);
    }
  }

  async resumeConversation(conversationId: string): Promise<void> {
    const conversation = this.conversations.get(conversationId);
    if (conversation) {
      conversation.status = 'active';
      this.conversations.set(conversationId, conversation);
    }
  }

  async closeConversation(conversationId: string): Promise<void> {
    const conversation = this.conversations.get(conversationId);
    if (conversation) {
      conversation.status = 'closed';
      this.conversations.set(conversationId, conversation);
    }
  }

  async getConversationSummary(conversationId: string): Promise<string | null> {
    const conversation = this.conversations.get(conversationId);
    if (conversation) {
      return conversation.aiSummary || null;
    }
    return null;
  }

  async generateConversationSummary(conversationId: string): Promise<string> {
    const conversation = this.conversations.get(conversationId);
    if (!conversation) {
      return '';
    }

    // Mock summary generation
    const messageCount = conversation.messages.length;
    const lastIntent = conversation.detectedIntents?.[conversation.detectedIntents.length - 1];
    
    let summary = `Conversation with ${conversation.context.lead.name} via ${conversation.channel}. `;
    summary += `${messageCount} messages exchanged. `;
    
    if (lastIntent) {
      summary += `Last detected intent: ${lastIntent.intent}. `;
    }
    
    summary += `Status: ${conversation.status}.`;

    conversation.aiSummary = summary;
    this.conversations.set(conversationId, conversation);

    return summary;
  }
}

