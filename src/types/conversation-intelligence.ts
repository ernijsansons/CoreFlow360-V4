// Conversation Intelligence Types
// Types for AI-powered conversation analysis and coaching

import type { Sentiment, Participant } from './crm';

export interface AudioStream {
  id: string;
  stream: ReadableStream;
  format: 'mp3' | 'wav' | 'webm' | 'ogg';
  sampleRate: number;
  channels: number;
  duration?: number;
  metadata?: Record<string, any>;
}

export interface TranscriptSegment {
  id: string;
  speaker: string;
  text: string;
  startTime: number;
  endTime: number;
  confidence: number;
  sentiment?: Sentiment;
}

export interface Transcript {
  id: string;
  segments: TranscriptSegment[];
  duration: number;
  language: string;
  confidence: number;
  timestamp: Date;
}

export interface SentimentTrend {
  timestamp: number;
  sentiment: Sentiment;
  confidence: number;
}

export interface SentimentData {
  primary: Sentiment;
  confidence: number;
  intensity: number;
  trends?: SentimentTrend[];
}

export interface SentimentAnalysis {
  overall: SentimentData;
  byParticipant: Record<string, SentimentData>;
  trends: SentimentTrend[];
  keyMoments: Array<{
    timestamp: string;
    sentiment: Sentiment;
    description: string;
    confidence: number;
  }>;
}

export interface TopicTrend {
  timestamp: number;
  topic: string;
  confidence: number;
}

export interface TopicAnalysis {
  primaryTopics: string[];
  allTopics: string[];
  confidence: Record<string, number>;
  topicDistribution: Record<string, number>;
  topicTrends: TopicTrend[];
}

export interface ObjectionDetected {
  id: string;
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  timestamp: string;
  confidence: number;
}

export interface ObjectionResponse {
  objectionId: string;
  response: string;
  effectiveness: number;
  timestamp: string;
}

export interface ObjectionPattern {
  pattern: string;
  frequency: number;
  averageSeverity: 'low' | 'medium' | 'high';
  commonResponses: string[];
}

export interface ObjectionResolution {
  objectionId: string;
  resolved: boolean;
  resolutionMethod: string;
  timestamp: string;
}

export interface ObjectionAnalysis {
  detected: ObjectionDetected[];
  responses: ObjectionResponse[];
  patterns: ObjectionPattern[];
  resolution: ObjectionResolution[];
}

export interface CompetitorPositioning {
  overall: string;
  pricing: string;
  features: string;
  relationship: string;
}

export interface CompetitorAnalysis {
  mentioned: string[];
  mentionCount: Record<string, number>;
  context: Record<string, string>;
  positioning: CompetitorPositioning;
  winRate: number;
  differentiators: string[];
  threats: string[];
  opportunities: string[];
}

export interface NextStepIdentified {
  id: string;
  action: string;
  description: string;
  priority: 'low' | 'medium' | 'high';
  timeline: string;
  owner: string;
  confidence: number;
}

export interface NextStepTimeline {
  action: string;
  date: string;
  confidence: number;
}

export interface NextStepPriority {
  action: string;
  priority: 'low' | 'medium' | 'high';
  reason: string;
}

export interface NextStepAnalysis {
  identified: NextStepIdentified[];
  byParticipant: Record<string, string[]>;
  timeline: NextStepTimeline[];
  priority: NextStepPriority[];
}

export interface SpeakingRatio {
  participant: string;
  ratio: number;
  duration: number;
}

export interface QuestionAnalysis {
  id: string;
  speaker: string;
  text: string;
  timestamp: string;
  type: string;
}

export interface MonologueAnalysis {
  id: string;
  speaker: string;
  duration: number;
  startTime: string;
  endTime: string;
  topic: string;
}

export interface EngagementMetrics {
  averageResponseTime: number;
  interactionFrequency: number;
  participationBalance: number;
  engagementScore: number;
}

export interface TalkTrack {
  keyPhrases: string[];
  objections: string[];
  valueProps: string[];
  effectiveness: number;
}

export interface ConversationMetrics {
  duration: number;
  segmentCount: number;
  speakingRatios: SpeakingRatio[];
  questions: QuestionAnalysis[];
  monologues: MonologueAnalysis[];
  engagement: EngagementMetrics;
  talkTrack: TalkTrack;
}

export interface ConversationInsights {
  keyInsights: string[];
  strengths: string[];
  weaknesses: string[];
  opportunities: string[];
  threats: string[];
  criticalSuccessFactors: string[];
  dealDrivers: string[];
  potentialBlockers: string[];
}

export interface CoachingAlert {
  id: string;
  type: string;
  message: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high';
}

export interface CoachingRecommendation {
  id: string;
  type: string;
  message: string;
  timestamp: string;
  priority: 'low' | 'medium' | 'high';
}

export interface RealTimeCoaching {
  alerts: CoachingAlert[];
  recommendations: CoachingRecommendation[];
}

export interface PostCallRecommendation {
  id: string;
  type: string;
  message: string;
  priority: 'low' | 'medium' | 'high';
  reason: string;
}

export interface PostCallCoaching {
  recommendations: PostCallRecommendation[];
  score: number;
  strengths: string[];
  improvements: string[];
}

export interface CallCoaching {
  realTime: RealTimeCoaching;
  postCall: PostCallCoaching;
}

export interface ConversationSummary {
  overview: string;
  keyPoints: string[];
  outcomes: string[];
  nextSteps: string[];
  sentiment: Sentiment;
  confidence: number;
}

export interface ConversationScore {
  overall: number;
  engagement: number;
  questioning: number;
  actionItems: number;
  recommendations: number;
  breakdown: {
    engagement: number;
    questioning: number;
    actionItems: number;
    recommendations: number;
  };
}

export interface ConversationAnalysis {
  id: string;
  transcript: Transcript;
  participants: Participant[];
  sentiment: SentimentAnalysis;
  topics: TopicAnalysis;
  objections: ObjectionAnalysis;
  competitors: CompetitorAnalysis;
  nextSteps: NextStepAnalysis;
  metrics: ConversationMetrics;
  insights: ConversationInsights;
  coaching: CallCoaching;
  summary: ConversationSummary;
  score: ConversationScore;
  timestamp: Date;
  processingTimeMs: number;
}

export interface EmotionalState {
  emotion: string;
  intensity: number;
  timestamp: string;
  confidence: number;
}
