import type {
  IAgent,
  AgentTask,
  AgentResult,
  BusinessContext,
  ValidationResult,
  HealthStatus,
  CapabilityDetails,
  AgentType
} from './types';
import type {
  QualificationCriteria,
  QualificationAnswer,
  QualificationResult,
  BANTQualification,
  ConversationContext,
  QualifyLeadTaskPayload,
  AuthorityLevel,
  BudgetRange,
  TimelineUrgency,
  QualificationStatus
} from '../../types/crm';
import { z } from 'zod';

export class QualificationAgent implements IAgent {
  // Agent identity
  readonly id = 'qualification-agent';
  readonly name = 'BANT Qualification Agent';
  readonly type: AgentType = 'specialized';
  readonly version = '1.0.0';

  // Agent capabilities
  readonly capabilities = ['lead_qualification', 'bant_analysis', 'conversation_analysis'];
  readonly departments = ['sales', 'marketing'];
  readonly tags = ['qualification', 'bant', 'sales', 'ai'];

  // Agent characteristics
  readonly costPerCall = 0.15; // USD per qualification
  readonly maxConcurrency = 10;
  readonly averageLatency = 5000; // 5 seconds
  readonly supportedLanguages = ['en'];
  readonly supportedFormats = ['text', 'json'];

  private anthropic: any; // In real implementation, this would be the Anthropic client

  constructor(private env: any) {
    // Initialize Anthropic client in real implementation
    // this.anthropic = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY });
  }

  // BANT qualification criteria with natural conversation approach
  private qualificationCriteria: Record<string, QualificationCriteria> = {
    budget: {
      question: "To ensure we're aligned, what budget range are you working with for this initiative?",
      required: true,
      weight: 0.3,
      extractor: this.extractBudget.bind(this)
    },
    authority: {
      question: "Are you involved in the decision-making process for this type of solution?",
      required: true,
      weight: 0.25,
      extractor: this.extractAuthority.bind(this)
    },
    need: {
      question: "What specific challenges are you trying to solve with this solution?",
      required: true,
      weight: 0.25,
      extractor: this.extractNeed.bind(this)
    },
    timeline: {
      question: "When are you looking to have a solution in place?",
      required: true,
      weight: 0.2,
      extractor: this.extractTimeline.bind(this)
    }
  };

  async execute(task: AgentTask, context: BusinessContext): Promise<AgentResult> {
    const startTime = Date.now();

    try {
      // Validate the task
      const validation = await this.validateInput(task.input, task.capability);
      if (!validation.valid) {
        return this.createErrorResult(task.id, 'VALIDATION_ERROR', 'Invalid input', validation.errors, startTime);
      }

      let result: any;

      switch (task.capability) {
        case 'lead_qualification':
          result = await this.qualifyLead(task.input.data as QualifyLeadTaskPayload, context);
          break;
        case 'bant_analysis':
          result = await this.analyzeBantFromConversation(task.input.data as ConversationContext, context);
          break;
        case 'conversation_analysis':
          result = await this.analyzeConversationForQualification(task.input.data as ConversationContext, context);
          break;
        default:
        
   return this.createErrorResult(task.id, 'UNSUPPORTED_CAPABILITY', `Capability ${task.capability} not supported`, [], startTime);
      }

      return {
        taskId: task.id,
        agentId: this.id,
        status: 'completed',
        result: {
          data: result,
          confidence: result.confidence_level || 0.8,
          reasoning: result.qualification_summary || 'Qualification completed',
          sources: ['conversation_analysis', 'ai_inference']
        },
        metrics: {
          executionTime: Date.now() - startTime,
          tokensUsed: 2500, // Estimated
          costUSD: this.costPerCall,
          modelUsed: 'claude-3-sonnet',
          retryCount: 0
        },
        startedAt: startTime,
        completedAt: Date.now()
      };

    } catch (error: any) {
      return this.createErrorResult(
        task.id,
        'EXECUTION_ERROR',
        error instanceof Error ? error.message : 'Unknown error',
        [],
        startTime
      );
    }
  }

  async qualifyLead(payload: QualifyLeadTaskPayload, context: BusinessContext): Promise<QualificationResult> {
    const { lead_id, conversation_context, force_requalification } = payload;

    // In a real implementation, we'd fetch conversation data from the database
    // For now, we'll work with the provided context
    if (!conversation_context) {
      throw new Error('Conversation context required for qualification');
    }

    // Analyze the conversation for BANT information
    const bantData = await this.extractBantFromConversation(conversation_context);

    // Calculate overall qualification score
    const overallScore = this.calculateQualificationScore(bantData);

    // Determine qualification status
    const qualificationStatus = this.determineQualificationStatus(overallScore, bantData);

    // Generate next questions for missing information
    const nextQuestions = this.generateNextQuestions(bantData);

    // Generate AI insights
    const aiInsights = await this.generateAIInsights(conversation_context, bantData);

    return {
      leadId: lead_id,
      overall_score: overallScore,
      bant_data: bantData,
      qualification_status: qualificationStatus,
      next_questions: nextQuestions,
      confidence_level: this.calculateConfidenceLevel(bantData),
      qualified_at: qualificationStatus === 'qualified' ? new Date().toISOString() : undefined,
      qualification_summary: this.generateQualificationSummary(bantData, overallScore),
      ai_insights: aiInsights
    };
  }

  async analyzeBantFromConversation(conversationContext: ConversationContext, context: BusinessContext): Promise<BANTQualification> {
    return this.extractBantFromConversation(conversationContext);
  }

  async analyzeConversationForQualification(conversationContext: ConversationContext, context: BusinessContext): Promise<any> {
    const qualification = await this.qualifyLead({
      lead_id: conversationContext.leadId,
      conversation_context: conversationContext
    }, context);

    return {
      qualification_result: qualification,
      conversation_insights: {
        key_topics: await this.extractKeyTopics(conversationContext.transcript),
        sentiment_analysis: conversationContext.metadata?.sentiment || 'neutral',
        engagement_level: this.calculateEngagementLevel(conversationContext)
      }
    };
  }

  private async extractBantFromConversation(conversation: ConversationContext): Promise<BANTQualification> {
    const transcript = conversation.transcript;

    return {
      budget: await this.extractBudget(transcript),
      authority: await this.extractAuthority(transcript),
      need: await this.extractNeed(transcript),
      timeline: await this.extractTimeline(transcript)
    };
  }

  private async extractBudget(text: string): Promise<QualificationAnswer | null> {
    // In real implementation, this would use Claude API to analyze text
    const budgetIndicators = [
      /\$[\d,]+k?/gi,
      /budget.*\$?[\d,]+/gi,
      /\b(thousand|million|k|m)\b/gi,
      /budget.*range.*\$?[\d,]+/gi
    ];

    let foundBudget = false;
    let budgetValue: BudgetRange = 'undefined';
    let confidence = 0.0;
    let rawText = '';

    for (const pattern of budgetIndicators) {
      const matches = text.match(pattern);
      if (matches) {
        foundBudget = true;
        rawText = matches[0];
        confidence = 0.7;

        // Extract budget range based on found values
        const numericValue = parseInt(rawText.replace(/[^\d]/g, ''));
        if (numericValue < 10) budgetValue = 'under_10k';
        else if (numericValue < 25) budgetValue = '10k_25k';
        else if (numericValue < 50) budgetValue = '25k_50k';
        else if (numericValue < 100) budgetValue = '50k_100k';
        else if (numericValue < 250) budgetValue = '100k_250k';
        else if (numericValue < 500) budgetValue = '250k_500k';
        else budgetValue = '500k_plus';

        break;
      }
    }

    if (!foundBudget) return null;

    return {
      value: budgetValue,
      confidence,
      source: 'transcript',
      extractedAt: new Date().toISOString(),
      rawText
    };
  }

  private async extractAuthority(text: string): Promise<QualificationAnswer | null> {
    const authorityIndicators = [
      /\b(decision|decide|authority|approve|sign off)\b/gi,
      /\b(ceo|cto|cfo|vp|director|manager|head of)\b/gi,
      /\b(budget owner|final say|can approve)\b/gi
    ];

    let authorityLevel: AuthorityLevel = 'no_authority';
    let confidence = 0.0;
    let rawText = '';

    // Check for authority indicators
    for (const pattern of authorityIndicators) {
      const matches = text.match(pattern);
      if (matches) {
        rawText = matches[0];
        confidence = 0.6;

        // Determine authority level
        if (/\b(ceo|cfo|cto|president)\b/gi.test(text)) {
          authorityLevel = 'economic_buyer';
          confidence = 0.9;
        } else if (/\b(vp|director|head of)\b/gi.test(text)) {
          authorityLevel = 'decision_maker';
          confidence = 0.8;
        } else if (/\b(manager|lead)\b/gi.test(text)) {
          authorityLevel = 'influencer';
          confidence = 0.7;
        } else if (/\b(champion|advocate|recommend)\b/gi.test(text)) {
          authorityLevel = 'champion';
          confidence = 0.6;
        }
        break;
      }
    }

    if (authorityLevel === 'no_authority') return null;

    return {
      value: authorityLevel,
      confidence,
      source: 'transcript',
      extractedAt: new Date().toISOString(),
      rawText
    };
  }

  private async extractNeed(text: string): Promise<QualificationAnswer | null> {
    const needIndicators = [
      /\b(problem|challenge|issue|pain|difficulty)\b/gi,
      /\b(need|require|looking for|want)\b/gi,
      /\b(improve|optimize|solve|fix)\b/gi
    ];

    let hasNeed = false;
    let confidence = 0.0;
    let rawText = '';
    const needsFound: string[] = [];

    for (const pattern of needIndicators) {
      const matches = text.match(pattern);
      if (matches) {
        hasNeed = true;
        needsFound.push(...matches);
        confidence = Math.min(0.9, confidence + 0.3);
      }
    }

    if (!hasNeed) return null;

    rawText = needsFound.slice(0, 3).join(', '); // First few matches

    return {
      value: true,
      confidence,
      source: 'transcript',
      extractedAt: new Date().toISOString(),
      rawText
    };
  }

  private async extractTimeline(text: string): Promise<QualificationAnswer | null> {
    const timelineIndicators = [
      /\b(immediately|asap|urgent|right away)\b/gi,
      /\b(this quarter|q[1-4]|next quarter)\b/gi,
      /\b(this year|next year|\d{4})\b/gi,
      /\b(month|weeks?|days?)\b/gi
    ];

    let timeline: TimelineUrgency = 'no_timeline';
    let confidence = 0.0;
    let rawText = '';

    for (const pattern of timelineIndicators) {
      const matches = text.match(pattern);
      if (matches) {
        rawText = matches[0];
        confidence = 0.7;

        // Determine timeline urgency
        if (/\b(immediately|asap|urgent|right away|days?)\b/gi.test(text)) {
          timeline = 'immediate';
          confidence = 0.9;
        } else if (/\b(this quarter|q[1-4]|weeks?|month)\b/gi.test(text)) {
          timeline = 'this_quarter';
          confidence = 0.8;
        } else if (/\b(next quarter)\b/gi.test(text)) {
          timeline = 'next_quarter';
          confidence = 0.8;
        } else if (/\b(this year)\b/gi.test(text)) {
          timeline = 'this_year';
          confidence = 0.7;
        } else if (/\b(next year|\d{4})\b/gi.test(text)) {
          timeline = 'next_year';
          confidence = 0.6;
        }
        break;
      }
    }

    if (timeline === 'no_timeline') return null;

    return {
      value: timeline,
      confidence,
      source: 'transcript',
      extractedAt: new Date().toISOString(),
      rawText
    };
  }

  private calculateQualificationScore(bantData: BANTQualification): number {
    let totalScore = 0;
    let weightSum = 0;

    for (const [key, criteria] of Object.entries(this.qualificationCriteria)) {
      const answer = bantData[key as keyof BANTQualification];
      const weight = criteria.weight || 1;

      if (answer) {
        // Score based on confidence and answer quality
        const answerScore = answer.confidence * 100;
        totalScore += answerScore * weight;
      }

      weightSum += weight;
    }

    return weightSum > 0 ? Math.round(totalScore / weightSum) : 0;
  }

  private determineQualificationStatus(score: number, bantData: BANTQualification): QualificationStatus {
    const hasAllBant = Object.values(bantData).every(answer => answer !== null);

    if (score >= 80 && hasAllBant) return 'qualified';
    if (score >= 60) return 'needs_review';
    if (score < 40) return 'unqualified';
    return 'in_progress';
  }

  private generateNextQuestions(bantData: BANTQualification): string[] {
    const questions: string[] = [];

    if (!bantData.budget) {
      questions.push("Could you share what budget range you're working with for this project?");
    }
    if (!bantData.authority) {
      questions.push("Who else would be involved in making the final decision on this solution?");
    }
    if (!bantData.need) {
      questions.push("What specific challenges are you hoping this solution will address?");
    }
    if (!bantData.timeline) {
      questions.push("What's your timeline for implementing a solution like this?");
    }

    return questions;
  }

  private calculateConfidenceLevel(bantData: BANTQualification): number {
    const answers = Object.values(bantData).filter((answer: any) => answer !== null);
    if (answers.length === 0) return 0;

    const avgConfidence = answers.reduce((sum, answer) => sum + answer!.confidence, 0) / answers.length;
    return Math.round(avgConfidence * 100) / 100;
  }

  private generateQualificationSummary(bantData: BANTQualification, score: number): string {
    const hasAnswers = Object.entries(bantData).filter(([_, answer]) => answer !== null);
    const missingAnswers = Object.entries(bantData).filter(([_, answer]) => answer === null);

    let summary = `Qualification score: ${score}/100. `;
    summary += `Found information for: ${hasAnswers.map(([key]) => key).join(', ')}. `;

    if (missingAnswers.length > 0) {
      summary += `Still need: ${missingAnswers.map(([key]) => key).join(', ')}.`;
    }

    return summary;
  }

  private async generateAIInsights(conversation: ConversationContext, bantData: BANTQualification): Promise<any> {
    // In real implementation, this would use Claude API for deep analysis
    return {
      buying_signals: this.extractBuyingSignals(conversation.transcript),
      objections: this.extractObjections(conversation.transcript),
      pain_points: this.extractPainPoints(conversation.transcript),
      decision_timeline: bantData.timeline?.value?.toString() || 'unclear',
      budget_indicators: bantData.budget ? [bantData.budget.rawText || ''] : [],
      authority_level: (bantData.authority?.value as AuthorityLevel) || 'no_authority'
    };
  }

  private extractBuyingSignals(text: string): string[] {
    const signals = [];
    if (/\b(budget.*approved|ready to move|let's proceed)\b/gi.test(text)) {
      signals.push('Budget approved');
    }
    if (/\b(timeline.*urgent|need.*soon|deadline)\b/gi.test(text)) {
      signals.push('Urgent timeline');
    }
    if (/\b(decision.*made|signed off|approved)\b/gi.test(text)) {
      signals.push('Decision authority confirmed');
    }
    return signals;
  }

  private extractObjections(text: string): string[] {
    const objections = [];
    if (/\b(too expensive|budget.*concern|cost.*issue)\b/gi.test(text)) {
      objections.push('Price concerns');
    }
    if (/\b(not sure|need.*think|discuss.*team)\b/gi.test(text)) {
      objections.push('Need more time to decide');
    }
    if (/\b(current solution|already have|satisfied with)\b/gi.test(text)) {
      objections.push('Status quo bias');
    }
    return objections;
  }

  private extractPainPoints(text: string): string[] {
    const pains = [];
    if (/\b(inefficient|slow|manual|time.*consuming)\b/gi.test(text)) {
      pains.push('Process inefficiency');
    }
    if (/\b(expensive|costly|budget.*strain)\b/gi.test(text)) {
      pains.push('High costs');
    }
    if (/\b(error|mistake|inaccurate|wrong)\b/gi.test(text)) {
      pains.push('Accuracy issues');
    }
    return pains;
  }

  private async extractKeyTopics(transcript: string): Promise<string[]> {
    // Simple keyword extraction - in real implementation, use Claude API
    const topics = [];
    if (/\b(integration|api|system)\b/gi.test(transcript)) topics.push('Integration');
    if (/\b(security|compliance|gdpr)\b/gi.test(transcript)) topics.push('Security');
    if (/\b(scale|growth|expansion)\b/gi.test(transcript)) topics.push('Scalability');
    if (/\b(cost|price|budget)\b/gi.test(transcript)) topics.push('Pricing');
    return topics;
  }

  private calculateEngagementLevel(conversation: ConversationContext): number {
    const messageCount = conversation.messages.length;
    const avgMessageLength = conversation.messages.reduce((sum, msg) => sum + msg.content.length, 0) / messageCount;

    // Simple engagement scoring
    let engagement = 0.5;
    if (messageCount > 10) engagement += 0.2;
    if (avgMessageLength > 50) engagement += 0.2;
    if (conversation.metadata?.callDuration && conversation.metadata.callDuration > 600) engagement += 0.1;

    return Math.min(1.0, engagement);
  }

  async validateInput(input: unknown, capability: string): Promise<ValidationResult> {
    const validationSchema = z.object({
      data: z.union([
        z.object({
          lead_id: z.string(),
          conversation_context: z.object({
            leadId: z.string(),
            transcript: z.string(),
            messages: z.array(z.object({
              role: z.enum(['ai', 'human']),
              content: z.string(),
              timestamp: z.string()
            }))
          }).optional(),
          force_requalification: z.boolean().optional()
        }),
        z.object({
          leadId: z.string(),
          transcript: z.string(),
          messages: z.array(z.any())
        })
      ])
    });

    try {
      validationSchema.parse(input);
      return { valid: true };
    } catch (error: any) {
      return {
        valid: false,
        errors: [{
          field: 'input',
          code: 'INVALID_SCHEMA',
          message: 'Input does not match expected schema'
        }]
      };
    }
  }

  async estimateCost(task: AgentTask): Promise<number> {
    return this.costPerCall;
  }

  async healthCheck(): Promise<HealthStatus> {
    return {
      status: 'online',
      latency: this.averageLatency,
      errorRate: 0.02,
      lastCheck: Date.now(),
      details: {
        apiConnectivity: true,
        rateLimitStatus: {
          remaining: 1000,
          resetAt: Date.now() + 3600000
        },
        memoryUsage: 45,
        activeConnections: 3
      }
    };
  }

  getCapabilityDetails(capability: string): CapabilityDetails | undefined {
    const capabilities: Record<string, CapabilityDetails> = {
      lead_qualification: {
        id: 'lead_qualification',
        name: 'Lead Qualification',
        description: 'Analyze conversations to qualify leads using BANT methodology',
        inputSchema: {
          type: 'object',
          properties: {
            lead_id: { type: 'string' },
            conversation_context: { type: 'object' }
          },
          required: ['lead_id']
        },
        outputSchema: {
          type: 'object',
          properties: {
            overall_score: { type: 'number' },
            qualification_status: { type: 'string' },
            bant_data: { type: 'object' }
          }
        },
        examples: [{
          input: { lead_id: '123', conversation_context: { transcript: 'We have a $50k budget...' } },
          output: { overall_score: 85, qualification_status: 'qualified' },
          description: 'Qualify a lead with budget information'
        }],
        constraints: {
          maxInputSize: 50000,
          timeoutMs: 30000,
          costLimit: 1.0
        },
        requiredPermissions: ['read:leads', 'write:qualification'],
        department: 'sales'
      }
    };

    return capabilities[capability];
  }

  private createErrorResult(taskId: string, code: string,
  message: string, errors: any[], startTime: number): AgentResult {
    return {
      taskId,
      agentId: this.id,
      status: 'failed',
      error: {
        code,
        message,
        details: { errors },
        retryable: code === 'RATE_LIMIT_EXCEEDED',
        category: 'api'
      },
      metrics: {
        executionTime: Date.now() - startTime,
        costUSD: 0,
        retryCount: 0
      },
      startedAt: startTime,
      completedAt: Date.now()
    };
  }
}