import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { Context } from 'hono';
import type {
  VoiceAgentConfig,
  CallInitiationRequest,
  VoiceAgentResponse,
  CallResult,
  RealTimeCallState,
  CallQueueStats,
  VoiceAgentPerformance
} from '../types/voice-agent';
import type { Lead } from '../types/crm';
import { AIVoiceAgent } from '../services/ai-voice-agent';
import { CallOrchestrator, type CallOrchestratorConfig } from '../services/call-orchestrator';
import { CallAnalyticsService } from '../services/call-analytics-service';
import { CRMService } from '../services/crm-service';
import { TwilioService } from '../services/twilio-service';

// Validation schemas
const CallInitiationSchema = z.object({
  lead_id: z.string().min(1),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
  call_type: z.enum(['cold_outreach', 'follow_up', 'qualification', 'demo_booking', 'support']),
  scheduled_at: z.string().datetime().optional(),
  custom_script: z.string().optional(),
  context: z.object({
    previous_interactions: z.array(z.object({
      type: z.enum(['email', 'call', 'chat', 'meeting']),
      date: z.string(),
      summary: z.string(),
      outcome: z.string(),
      next_steps: z.array(z.string()).optional()
    })).default([]),
    enrichment_data: z.any().optional(),
    campaign_context: z.string().optional(),
    referral_source: z.string().optional(),
    urgency_reason: z.string().optional()
  }).optional()
});

const BulkCallSchema = z.object({
  lead_ids: z.array(z.string()).min(1).max(100),
  call_type: z.enum(['cold_outreach', 'follow_up', 'qualification', 'demo_booking', 'support']),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
  scheduled_at: z.string().datetime().optional(),
  stagger_delay_minutes: z.number().min(1).max(60).default(5)
});

const AnalyticsQuerySchema = z.object({
  start_date: z.string().datetime(),
  end_date: z.string().datetime(),
  lead_ids: z.array(z.string()).optional(),
  call_types: z.array(z.string()).optional(),
  outcomes: z.array(z.string()).optional(),
  min_duration: z.number().optional(),
  max_duration: z.number().optional()
});

const TwilioWebhookSchema = z.object({
  CallSid: z.string(),
  AccountSid: z.string(),
  From: z.string(),
  To: z.string(),
  CallStatus: z.string(),
  Direction: z.string(),
  ApiVersion: z.string(),
  ForwardedFrom: z.string().optional(),
  CallerName: z.string().optional(),
  ParentCallSid: z.string().optional(),
  CallDuration: z.string().optional(),
  SipResponseCode: z.string().optional(),
  RecordingUrl: z.string().optional(),
  RecordingSid: z.string().optional(),
  RecordingStatus: z.string().optional(),
  Digits: z.string().optional(),
  FinishedOnKey: z.string().optional(),
  SpeechResult: z.string().optional(),
  Confidence: z.string().optional(),
  AnsweredBy: z.string().optional(),
  MachineDetectionDuration: z.string().optional()
});

export function createVoiceAgentRoutes(
  voiceAgentConfig: VoiceAgentConfig,
  orchestratorConfig: CallOrchestratorConfig
): Hono {
  const app = new Hono();

  // CORS middleware
  app.use('*', cors({
    origin: ['http://localhost:3000', 'https://*.cloudflare.workers.dev'],
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  }));

  // Initialize services
  let voiceAgent: AIVoiceAgent;
  let callOrchestrator: CallOrchestrator;
  let analyticsService: CallAnalyticsService;
  let crmService: CRMService;

  // Middleware to initialize services
  app.use('*', async (c: Context, next) => {
    if (!voiceAgent) {
      crmService = new CRMService(c.env);
      voiceAgent = new AIVoiceAgent(voiceAgentConfig);
      callOrchestrator = new CallOrchestrator(voiceAgentConfig, orchestratorConfig, crmService);
      analyticsService = new CallAnalyticsService();
    }
    await next();
  });

  // Health check
  app.get('/health', (c: Context) => {
    return c.json({
      status: 'healthy',
      service: 'voice-agent',
      timestamp: new Date().toISOString()
    });
  });

  // Initiate single call
  app.post('/calls/initiate',
    zValidator('json', CallInitiationSchema),
    async (c: Context) => {
      try {
        const request = c.req.valid('json') as CallInitiationRequest;

        // Get lead data
        const lead = await crmService.getLeadById(request.lead_id);
        if (!lead) {
          return c.json({
            success: false,
            error: 'Lead not found'
          }, 404);
        }

        // Queue call through orchestrator
        const result = await callOrchestrator.queueCall(lead, request);

        if (result.success) {
          return c.json({
            success: true,
            message: 'Call queued successfully',
            queue_item_id: result.queue_item_id,
            estimated_wait_time: result.estimated_wait_time,
            position: result.position
          });
        } else {
          return c.json({
            success: false,
            error: result.error
          }, 400);
        }

      } catch (error: any) {
        return c.json({
          success: false,
          error: 'Internal server error'
        }, 500);
      }
    }
  );

  // Initiate bulk calls
  app.post('/calls/bulk',
    zValidator('json', BulkCallSchema),
    async (c: Context) => {
      try {
        const request = c.req.valid('json');
        const results = [];

        for (let i = 0; i < request.lead_ids.length; i++) {
          const leadId = request.lead_ids[i];

          // Get lead data
          const lead = await crmService.getLeadById(leadId);
          if (!lead) {
            results.push({
              lead_id: leadId,
              success: false,
              error: 'Lead not found'
            });
            continue;
          }

          // Calculate staggered schedule time
          const scheduledAt = request.scheduled_at
            ? new Date(new Date(request.scheduled_at).getTime() + i * request.stagger_delay_minutes * 60000)
            : new Date(Date.now() + i * request.stagger_delay_minutes * 60000);

          // Queue call
          const result = await callOrchestrator.queueCall(lead, {
            lead_id: leadId,
            priority: request.priority,
            call_type: request.call_type,
            scheduled_at: scheduledAt.toISOString()
          });

          results.push({
            lead_id: leadId,
            ...result
          });
        }

        const successCount = results.filter((r: any) => r.success).length;

        return c.json({
          success: true,
          message: `Queued ${successCount}/${request.lead_ids.length} calls`,
          results
        });

      } catch (error: any) {
        return c.json({
          success: false,
          error: 'Internal server error'
        }, 500);
      }
    }
  );

  // Get call result
  app.get('/calls/:callId/result', async (c: Context) => {
    try {
      const callId = c.req.param('callId');
      const result = await voiceAgent.getCallResult(callId);

      if (!result) {
        return c.json({
          success: false,
          error: 'Call result not found'
        }, 404);
      }

      return c.json({
        success: true,
        data: result
      });

    } catch (error: any) {
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  });

  // Get real-time call state
  app.get('/calls/:callId/state', async (c: Context) => {
    try {
      const callId = c.req.param('callId');
      const state = await voiceAgent.getActiveCallState(callId);

      if (!state) {
        return c.json({
          success: false,
          error: 'Call state not found'
        }, 404);
      }

      return c.json({
        success: true,
        data: state
      });

    } catch (error: any) {
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  });

  // Terminate active call
  app.post('/calls/:callId/terminate', async (c: Context) => {
    try {
      const callId = c.req.param('callId');
      const reason = c.req.query('reason') || 'User terminated';

      const success = await voiceAgent.terminateCall(callId, reason);

      if (success) {
        return c.json({
          success: true,
          message: 'Call terminated successfully'
        });
      } else {
        return c.json({
          success: false,
          error: 'Failed to terminate call'
        }, 400);
      }

    } catch (error: any) {
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  });

  // Twilio webhook endpoints
  app.post('/webhooks/twilio/voice/:leadId', async (c: Context) => {
    try {
      const leadId = c.req.param('leadId');
      const body = await c.req.parseBody();

      // Parse Twilio webhook data
      const twilioService = new TwilioService(voiceAgentConfig.twilio);
      const webhookData = twilioService.parseWebhookData(body);

      // Validate webhook (optional - requires signature validation)
      const signature = c.req.header('X-Twilio-Signature');
      const url = c.req.url;

      if (signature && !twilioService.validateWebhook(signature, url, body)) {
        return c.text('Unauthorized', 401);
      }

      // Handle webhook through voice agent
      const twimlResponse = await voiceAgent.handleTwilioWebhook(webhookData.CallSid, webhookData);

      return c.text(twimlResponse, 200, {
        'Content-Type': 'application/xml'
      });

    } catch (error: any) {
      return c.text('Internal Server Error', 500);
    }
  });

  // Twilio status callback
  app.post('/webhooks/twilio/status/:leadId', async (c: Context) => {
    try {
      const leadId = c.req.param('leadId');
      const body = await c.req.parseBody();

      const twilioService = new TwilioService(voiceAgentConfig.twilio);
      const webhookData = twilioService.parseWebhookData(body);

      // Handle call completion
      if (webhookData.CallStatus === 'completed') {
        await callOrchestrator.handleCallCompletion(webhookData.CallSid);
      }

      return c.text('OK', 200);

    } catch (error: any) {
      return c.text('Internal Server Error', 500);
    }
  });

  // Twilio recording callback
  app.post('/webhooks/twilio/recording/:leadId', async (c: Context) => {
    try {
      const leadId = c.req.param('leadId');
      const body = await c.req.parseBody();

      const twilioService = new TwilioService(voiceAgentConfig.twilio);
      const webhookData = twilioService.parseWebhookData(body);

      // Process recording

      // Store recording URL and trigger transcription if needed
      if (webhookData.RecordingUrl) {
        // Update call result with recording URL
        // This would typically update the database
      }

      return c.text('OK', 200);

    } catch (error: any) {
      return c.text('Internal Server Error', 500);
    }
  });

  // Queue management
  app.get('/queue/stats', async (c: Context) => {
    try {
      const stats = await callOrchestrator.getQueueStats();

      return c.json({
        success: true,
        data: stats
      });

    } catch (error: any) {
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  });

  app.delete('/queue/:queueItemId', async (c: Context) => {
    try {
      const queueItemId = c.req.param('queueItemId');
      const success = await callOrchestrator.cancelQueuedCall(queueItemId);

      if (success) {
        return c.json({
          success: true,
          message: 'Queued call cancelled'
        });
      } else {
        return c.json({
          success: false,
          error: 'Queue item not found'
        }, 404);
      }

    } catch (error: any) {
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  });

  app.put('/queue/:queueItemId/priority', async (c: Context) => {
    try {
      const queueItemId = c.req.param('queueItemId');
      const { priority } = await c.req.json();

      const success = await callOrchestrator.updateCallPriority(queueItemId, priority);

      if (success) {
        return c.json({
          success: true,
          message: 'Priority updated'
        });
      } else {
        return c.json({
          success: false,
          error: 'Queue item not found'
        }, 404);
      }

    } catch (error: any) {
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  });

  // Analytics endpoints
  app.post('/analytics/performance',
    zValidator('json', AnalyticsQuerySchema),
    async (c: Context) => {
      try {
        const query = c.req.valid('json');
        const performance = await analyticsService.getPerformanceMetrics(query);

        return c.json({
          success: true,
          data: performance
        });

      } catch (error: any) {
        return c.json({
          success: false,
          error: 'Internal server error'
        }, 500);
      }
    }
  );

  app.get('/analytics/calls/:callId', async (c: Context) => {
    try {
      const callId = c.req.param('callId');

      const [analytics, insights] = await Promise.all([
        analyticsService.getCallAnalytics(callId),
        analyticsService.getCallInsights(callId)
      ]);

      if (!analytics || !insights) {
        return c.json({
          success: false,
          error: 'Call analytics not found'
        }, 404);
      }

      return c.json({
        success: true,
        data: {
          analytics,
          insights
        }
      });

    } catch (error: any) {
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  });

  app.post('/analytics/cost-analysis',
    zValidator('json', AnalyticsQuerySchema),
    async (c: Context) => {
      try {
        const query = c.req.valid('json');
        const costAnalysis = await analyticsService.getCostAnalysis(query);

        return c.json({
          success: true,
          data: costAnalysis
        });

      } catch (error: any) {
        return c.json({
          success: false,
          error: 'Internal server error'
        }, 500);
      }
    }
  );

  app.get('/analytics/benchmarks', async (c: Context) => {
    try {
      const benchmarks = await analyticsService.getPerformanceBenchmarks();

      return c.json({
        success: true,
        data: benchmarks
      });

    } catch (error: any) {
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  });

  app.post('/analytics/metrics',
    zValidator('json', AnalyticsQuerySchema),
    async (c: Context) => {
      try {
        const query = c.req.valid('json');
        const metrics = await analyticsService.getVoiceAgentMetrics(query);

        return c.json({
          success: true,
          data: metrics
        });

      } catch (error: any) {
        return c.json({
          success: false,
          error: 'Internal server error'
        }, 500);
      }
    }
  );

  // Configuration endpoints
  app.get('/config', (c: Context) => {
    return c.json({
      success: true,
      data: {
        max_concurrent_calls: orchestratorConfig.max_concurrent_calls,
        business_hours: orchestratorConfig.business_hours,
        call_volume_limits: orchestratorConfig.call_volume_limits,
        voice_provider: voiceAgentConfig.voice_synthesis.provider,
        ai_model: voiceAgentConfig.ai_config.model
      }
    });
  });

  // Debug endpoints (remove in production)
  app.get('/debug/active-calls', async (c: Context) => {
    try {
      // Get all active call states
      const activeCalls = []; // Would get from orchestrator

      return c.json({
        success: true,
        data: {
          active_calls_count: activeCalls.length,
          calls: activeCalls
        }
      });

    } catch (error: any) {
      return c.json({
        success: false,
        error: 'Internal server error'
      }, 500);
    }
  });

  return app;
}

// Example usage and configuration
export const defaultVoiceAgentConfig: VoiceAgentConfig = {
  twilio: {
    account_sid: '',
    auth_token: '',
    phone_number: '',
    webhook_url: '',
    recording_enabled: true,
    machine_detection: true
  },
  voice_synthesis: {
    provider: 'elevenlabs',
    voice_id: 'default',
    stability: 0.8,
    similarity_boost: 0.8,
    api_key: ''
  },
  ai_config: {
    model: 'claude-3-sonnet-20240229',
    temperature: 0.7,
    max_tokens: 150,
    system_prompt: 'You are a professional sales representative making calls to potential customers.',
    conversation_timeout: 1800 // 30 minutes
  },
  call_settings: {
    max_call_duration: 900, // 15 minutes
    answer_timeout: 20,
    machine_detection_timeout: 30,
    retry_attempts: 3,
    retry_delay: 300 // 5 minutes
  }
};

export const defaultOrchestratorConfig: CallOrchestratorConfig = {
  max_concurrent_calls: 5,
  queue_processing_interval: 10, // seconds
  retry_delays: [300, 900, 1800], // 5min, 15min, 30min
  business_hours: {
    start: '09:00',
    end: '17:00',
    timezone: 'America/New_York',
    days: [1, 2, 3, 4, 5] // Monday-Friday
  },
  call_volume_limits: {
    per_hour: 50,
    per_day: 200
  }
};