import type { Env } from '../types/env';
import { sanitizeUserInput, createSecureAIPrompt } from '../security/ai-prompt-sanitizer';

// Define interfaces locally as they are not exported from crm.ts
interface Call {
  id: string;
  transcript: Transcript;
  duration: number;
  participants: Participant[];
  date: string;
}

interface CallSummary {
  id: string;
  callId: string;
  generatedAt: string;
  sections: SummarySection[];
  keyPoints: string[];
  actionItems: any[];
  sentiment: any;
  participants: Participant[];
  duration: number;
  confidence: number;
}

interface SummarySection {
  id: string;
  title: string;
  content: string;
  order: number;
}

interface Participant {
  name: string;
  role: string;
}

interface ConversationAnalysis {
  id: string;
  transcript: Transcript;
  participants: any[];
  sentiment: any;
  topics: any;
  objections: any;
  competitors: any;
  nextSteps: any;
  metrics: any;
  insights: any;
  coaching: any;
  summary: string;
  score: any;
  timestamp: Date;
  processingTimeMs: number;
}

interface Transcript {
  id: string;
  segments: any[];
  duration: number;
  language: string;
  confidence: number;
  timestamp: Date;
}

interface Lead {
  company: string;
  name: string;
}

export class CallSummarizer {
  private env: Env;
  private summaryCache = new Map<string, CallSummary>();

  constructor(env: Env) {
    this.env = env;
  }

  async generateSummary(call: Call): Promise<CallSummary> {
    // Check cache first
    const cacheKey = `summary_${call.id}`;
    const cached = this.summaryCache.get(cacheKey);
    if (cached) return cached;

    // Sanitize all user-provided content
    const sanitizedTranscript = call.transcript.segments
      .map((s: any) => {
        const speakerResult = sanitizeUserInput(s.speaker, { maxLength: 100 });
        const textResult = sanitizeUserInput(s.text, { maxLength: 5000 });

        if (speakerResult.blocked || textResult.blocked) {
          return `[BLOCKED]: [BLOCKED]`;
        }

        return `${speakerResult.sanitized}: ${textResult.sanitized}`;
      })
      .join('\n');

    const sanitizedParticipants = call.participants
      .map((p: any) => {
        const nameResult = sanitizeUserInput(p.name, { maxLength: 100 });
        const roleResult = sanitizeUserInput(p.role, { maxLength: 50 });
        return `${nameResult.sanitized} (${roleResult.sanitized})`;
      })
      .join(', ');

    // Generate AI prompt with sanitized content
    const prompt = createSecureAIPrompt(`
      Analyze this call transcript and generate a comprehensive summary.
      
      Call Details:
      - Duration: ${call.duration} minutes
      - Participants: ${sanitizedParticipants}
      - Date: ${call.date}
      
      Transcript:
      ${sanitizedTranscript}
      
      Please provide:
      1. Key discussion points
      2. Decisions made
      3. Action items
      4. Next steps
      5. Overall sentiment
    `, );

    try {
      // Mock AI analysis - would use real AI in production
      const analysis = await this.analyzeCallWithAI(prompt);
      
      const summary: CallSummary = {
        id: `summary_${call.id}`,
        callId: call.id,
        generatedAt: new Date().toISOString(),
        sections: this.createSummarySections(analysis),
        keyPoints: this.extractKeyPoints(analysis),
        actionItems: this.extractActionItems(analysis),
        sentiment: this.analyzeSentiment(analysis),
        participants: call.participants,
        duration: call.duration,
        confidence: 0.85
      };

      // Cache the summary
      this.summaryCache.set(cacheKey, summary);
      
      return summary;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error('Failed to generate call summary:', errorMessage);
      throw new Error('Call summary generation failed');
    }
  }

  private async analyzeCallWithAI(prompt: string): Promise<ConversationAnalysis> {
    // Mock AI analysis - would use real AI service in production
    return {
      id: `analysis_${Date.now()}`,
      transcript: {
        id: `transcript_${Date.now()}`,
        segments: [],
        duration: 0,
        language: 'en-US',
        confidence: 0.95,
        timestamp: new Date()
      },
      participants: [],
      sentiment: {
        overall: {
          primary: 'positive',
          confidence: 0.8,
          intensity: 0.6,
          trends: []
        },
        byParticipant: {},
        trends: [],
        keyMoments: []
      },
      topics: {
        primaryTopics: ['pricing', 'features', 'timeline'],
        allTopics: ['pricing', 'features', 'timeline', 'budget'],
        confidence: {},
        topicDistribution: {},
        topicTrends: []
      },
      objections: {
        detected: ['price concerns', 'timeline issues'],
        responses: [],
        patterns: [],
        resolution: []
      },
      competitors: {
        mentioned: ['competitor1', 'competitor2'],
        mentionCount: {},
        context: {},
        positioning: {
          overall: 'competitive',
          pricing: 'competitive',
          features: 'comparable',
          relationship: 'moderate'
        },
        winRate: 0.7,
        differentiators: ['feature1', 'feature2'],
        threats: ['threat1'],
        opportunities: ['opportunity1']
      },
      nextSteps: {
        identified: ['schedule demo', 'send proposal'],
        byParticipant: {},
        timeline: [],
        priority: []
      },
      metrics: {
        duration: 30,
        segmentCount: 50,
        speakingRatios: [],
        questions: [],
        monologues: [],
        engagement: {
          averageResponseTime: 2000,
          interactionFrequency: 0.8,
          participationBalance: 0.7,
          engagementScore: 8.5
        },
        talkTrack: {
          keyPhrases: ['phrase1', 'phrase2'],
          objections: ['objection1'],
          valueProps: ['value1', 'value2'],
          effectiveness: 0.75
        }
      },
      insights: {
        keyInsights: ['insight1', 'insight2'],
        strengths: ['strength1'],
        weaknesses: ['weakness1'],
        opportunities: ['opportunity1'],
        threats: ['threat1'],
        criticalSuccessFactors: ['factor1'],
        dealDrivers: ['driver1'],
        potentialBlockers: ['blocker1']
      },
      coaching: {
        realTime: {
          alerts: [],
          recommendations: []
        },
        postCall: {
          recommendations: [],
          score: 85,
          strengths: ['strength1'],
          improvements: ['improvement1']
        }
      },
      summary: 'Mock call summary',
      score: {
        overall: 85,
        engagement: 8.5,
        questioning: 20,
        actionItems: 25,
        recommendations: 15,
        breakdown: {
          engagement: 8.5,
          questioning: 20,
          actionItems: 25,
          recommendations: 15
        }
      },
      timestamp: new Date(),
      processingTimeMs: 1000
    };
  }

  private createSummarySections(analysis: ConversationAnalysis): SummarySection[] {
    return [
      {
        id: 'overview',
        title: 'Call Overview',
        content: `Call lasted ${analysis.metrics.duration} minutes with ${analysis.metrics.segmentCount} segments. Overall sentiment: ${analysis.sentiment.overall.primary}.`,
        order: 1
      },
      {
        id: 'key_points',
        title: 'Key Discussion Points',
        content: analysis.insights.keyInsights.join('\n• '),
        order: 2
      },
      {
        id: 'decisions',
        title: 'Decisions Made',
        content: 'Mock decisions made during the call.',
        order: 3
      },
      {
        id: 'next_steps',
        title: 'Next Steps',
        content: analysis.nextSteps.identified.join('\n• '),
        order: 4
      }
    ];
  }

  private extractKeyPoints(analysis: ConversationAnalysis): string[] {
    return analysis.insights.keyInsights;
  }

  private extractActionItems(analysis: ConversationAnalysis): Array<{
    id: string;
    description: string;
    assignee: string;
    dueDate: string;
    priority: 'low' | 'medium' | 'high';
  }> {
    return analysis.nextSteps.identified.map((step: any, index: any) => ({
      id: `action_${index}`,
      description: step,
      assignee: 'TBD',
      dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      priority: 'medium' as const
    }));
  }

  private analyzeSentiment(analysis: ConversationAnalysis): {
    overall: 'positive' | 'neutral' | 'negative';
    confidence: number;
    keyMoments: Array<{
      timestamp: string;
      sentiment: string;
      description: string;
    }>;
  } {
    return {
      overall: analysis.sentiment.overall.primary as 'positive' | 'neutral' | 'negative',
      confidence: analysis.sentiment.overall.confidence,
      keyMoments: analysis.sentiment.keyMoments.map((moment: any) => ({
        timestamp: moment.timestamp,
        sentiment: moment.sentiment || 'neutral',
        description: moment.description || 'Key moment'
      }))
    };
  }

  async generateQuickSummary(call: Call): Promise<string> {
    try {
      const sanitizedTranscript = call.transcript.segments
        .map((s: any) => `${s.speaker}: ${s.text}`)
        .join('\n')
        .substring(0, 1000); // Limit for quick summary

      const prompt = createSecureAIPrompt(`
        Provide a brief 2-3 sentence summary of this call:
        
        ${sanitizedTranscript}
      `, );

      // Mock quick summary - would use real AI in production
      return `Call with ${call.participants.length} participants discussing ${call.duration} minutes. Key topics included pricing and features. Next steps: schedule demo.`;
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error('Failed to generate quick summary:', errorMessage);
      return 'Summary generation failed';
    }
  }

  async generateActionItems(call: Call): Promise<Array<{
    id: string;
    description: string;
    assignee: string;
    dueDate: string;
    priority: 'low' | 'medium' | 'high';
    status: 'pending' | 'in_progress' | 'completed';
  }>> {
    try {
      const summary = await this.generateSummary(call);
      return summary.actionItems.map((item: any) => ({
        ...item,
        status: 'pending' as const
      }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error('Failed to generate action items:', errorMessage);
      return [];
    }
  }

  async generateFollowUpEmail(call: Call, lead: Lead): Promise<string> {
    try {
      const summary = await this.generateSummary(call);
      
      const email = `
Subject: Follow-up on our call - ${lead.company}

Hi ${lead.name},

Thank you for taking the time to speak with me today about ${lead.company}'s needs.

Key points from our discussion:
${summary.keyPoints.map((point: any) => `• ${point}`).join('\n')}

Next steps:
${summary.actionItems.map((item: any) => `• ${item.description}`).join('\n')}

I'll follow up with you ${summary.actionItems[0]?.dueDate ? `by ${new Date(summary.actionItems[0].dueDate).toLocaleDateString()}` : 'soon'}.

Best regards,
[Your Name]
      `;

      return email.trim();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error('Failed to generate follow-up email:', errorMessage);
      return 'Follow-up email generation failed';
    }
  }

  async getSummaryById(callId: string): Promise<CallSummary | null> {
    const cacheKey = `summary_${callId}`;
    return this.summaryCache.get(cacheKey) || null;
  }

  async updateSummary(callId: string, updates: Partial<CallSummary>): Promise<CallSummary | null> {
    const cacheKey = `summary_${callId}`;
    const existing = this.summaryCache.get(cacheKey);
    
    if (!existing) {
      return null;
    }

    const updated = { ...existing, ...updates };
    this.summaryCache.set(cacheKey, updated);
    return updated;
  }

  async deleteSummary(callId: string): Promise<boolean> {
    const cacheKey = `summary_${callId}`;
    return this.summaryCache.delete(cacheKey);
  }

  async getSummaryStats(): Promise<{
    totalSummaries: number;
    averageConfidence: number;
    mostCommonSentiment: string;
    averageActionItems: number;
  }> {
    const summaries = Array.from(this.summaryCache.values());
    
    if (summaries.length === 0) {
      return {
        totalSummaries: 0,
        averageConfidence: 0,
        mostCommonSentiment: 'neutral',
        averageActionItems: 0
      };
    }

    const totalConfidence = summaries.reduce((sum, s) => sum + s.confidence, 0);
    const sentimentCounts: Record<string, number> = {};
    const totalActionItems = summaries.reduce((sum, s) => sum + s.actionItems.length, 0);

    summaries.forEach(summary => {
      const sentiment = summary.sentiment.overall;
      sentimentCounts[sentiment] = (sentimentCounts[sentiment] || 0) + 1;
    });

    const mostCommonSentiment = Object.entries(sentimentCounts)
      .sort(([,a], [,b]) => b - a)[0]?.[0] || 'neutral';

    return {
      totalSummaries: summaries.length,
      averageConfidence: totalConfidence / summaries.length,
      mostCommonSentiment,
      averageActionItems: totalActionItems / summaries.length
    };
  }

  async clearCache(): Promise<void> {
    this.summaryCache.clear();
  }

  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      return {
        status: 'healthy',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      };
    }
  }
}

