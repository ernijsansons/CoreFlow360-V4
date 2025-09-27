import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { LeadIngestionService } from '../services/lead-ingestion-service';
import type { Env } from '../types/env';
import type {
  MetaLeadPayload,
  ChatMessage,
  ParsedEmail,
  LeadInput,
  FormSubmission,
  ChatAIResponse
} from '../types/lead-ingestion';

const app = new Hono<{ Bindings: Env }>();

// Validation schemas
const MetaWebhookSchema = z.object({
  object: z.literal('page'),
  entry: z.array(z.object({
    id: z.string(),
    time: z.number(),
    changes: z.array(z.object({
      value: z.object({
        ad_id: z.string().optional(),
        form_id: z.string(),
        leadgen_id: z.string(),
        created_time: z.number(),
        page_id: z.string(),
        adgroup_id: z.string().optional(),
        campaign_id: z.string().optional()
      }),
      field: z.literal('leadgen')
    }))
  }))
});

const ChatMessageSchema = z.object({
  id: z.string(),
  session_id: z.string(),
  message: z.string(),
  timestamp: z.string(),
  sender: z.enum(['visitor', 'ai', 'human']),
  visitor_info: z.object({
    ip: z.string(),
    user_agent: z.string(),
    referrer: z.string().optional(),
    utm_source: z.string().optional(),
    utm_medium: z.string().optional(),
    utm_campaign: z.string().optional(),
    page_url: z.string()
  }).optional(),
  metadata: z.object({
    email: z.string().optional(),
    phone: z.string().optional(),
    name: z.string().optional(),
    company: z.string().optional()
  }).optional()
});

const LeadInputSchema = z.object({
  source: z.enum(['meta_ads', 'google_ads', 'website_chat', 'contact_form',
  'email', 'phone', 'linkedin', 'organic', 'referral', 'integration', 'manual']),
  source_campaign: z.string().optional(),
  source_metadata: z.record(z.any()).optional(),
  email: z.string().email().optional(),
  phone: z.string().optional(),
  first_name: z.string().optional(),
  last_name: z.string().optional(),
  full_name: z.string().optional(),
  company_name: z.string().optional(),
  company_domain: z.string().optional(),
  job_title: z.string().optional(),
  message: z.string().optional(),
  interests: z.array(z.string()).optional(),
  budget_range: z.string().optional(),
  timeline: z.string().optional(),
  utm_source: z.string().optional(),
  utm_medium: z.string().optional(),
  utm_campaign: z.string().optional(),
  referrer: z.string().optional(),
  landing_page: z.string().optional(),
  custom_fields: z.record(z.any()).optional()
});

const FormSubmissionSchema = z.object({
  form_id: z.string(),
  form_name: z.string().optional(),
  page_url: z.string(),
  submission_time: z.string(),
  fields: z.record(z.any()),
  visitor_session: z.object({
    session_id: z.string(),
    pages_visited: z.array(z.string()),
    time_on_site: z.number(),
    referrer: z.string(),
    utm_data: z.record(z.string())
  }).optional()
});

const EmailSchema = z.object({
  id: z.string(),
  from: z.object({
    email: z.string().email(),
    name: z.string().optional()
  }),
  to: z.array(z.object({
    email: z.string().email(),
    name: z.string().optional()
  })),
  subject: z.string(),
  body: z.object({
    text: z.string().optional(),
    html: z.string().optional()
  }),
  headers: z.record(z.string()),
  attachments: z.array(z.object({
    filename: z.string(),
    content_type: z.string(),
    size: z.number(),
    url: z.string().optional()
  })).optional(),
  timestamp: z.string(),
  thread_id: z.string().optional(),
  in_reply_to: z.string().optional(),
  references: z.array(z.string()).optional()
});

// Middleware to setup lead ingestion service
app.use('*', async (c, next) => {
  const businessId = c.req.header('X-Business-ID') || 'default-business';
  const config = {
    meta_webhook: {
      verify_token: c.env.META_VERIFY_TOKEN || 'verify-token',
      app_secret: c.env.META_APP_SECRET || '',
      access_token: c.env.META_ACCESS_TOKEN || ''
    }
  };

  c.set('businessId', businessId);
  c.set('leadIngestionService', new LeadIngestionService(c.env, config));
  await next();
});

// Meta (Facebook/Instagram) Webhook
app.get('/webhooks/meta', async (c: any) => {
  const mode = c.req.query('hub.mode');
  const token = c.req.query('hub.verify_token');
  const challenge = c.req.query('hub.challenge');

  const leadIngestionService = c.get('leadIngestionService') as LeadIngestionService;
  const verification = await leadIngestionService.verifyWebhook('meta', {
    'hub.verify_token': token,
    'hub.mode': mode,
    'hub.challenge': challenge
  });

  if (verification.valid && mode === 'subscribe') {
    return c.text(challenge || '');
  }

  return c.text('Forbidden', 403);
});

app.post('/webhooks/meta', zValidator('json', MetaWebhookSchema), async (c: any) => {
  const leadIngestionService = c.get('leadIngestionService') as LeadIngestionService;
  const businessId = c.get('businessId') as string;
  const payload = c.req.valid('json') as MetaLeadPayload;

  try {
    const result = await leadIngestionService.handleMetaWebhook(payload, businessId);

    if (result.success) {
    } else {
    }

    // Always return 200 to Meta to avoid retries
    return c.json({
      status: 'received',
      lead_id: result.lead_id,
      qualified: result.qualification_result?.qualified
    });
  } catch (error: any) {
    return c.json({ status: 'error' });
  }
});

// Real-time Website Chat
app.post('/chat/message', zValidator('json', ChatMessageSchema), async (c: any) => {
  const leadIngestionService = c.get('leadIngestionService') as LeadIngestionService;
  const businessId = c.get('businessId') as string;
  const message = c.req.valid('json') as ChatMessage;

  try {
    const response = await leadIngestionService.handleWebsiteChat(message, businessId);

    return c.json({
      success: true,
      response: response.message,
      typing_indicator: response.typing_indicator,
      delay_ms: response.delay_ms,
      suggested_responses: response.suggested_responses,
      qualification_questions: response.qualification_questions,
      meeting_booking_trigger: response.meeting_booking_trigger,
      transfer_to_human: response.transfer_to_human,
      context: response.context
    });
  } catch (error: any) {
    return c.json({
      success: false,
      response: "I'm sorry, I'm experiencing technical difficulties. Please try again.",
      transfer_to_human: true
    }, 500);
  }
});

app.get('/chat/session/:sessionId', async (c: any) => {
  const sessionId = c.req.param('sessionId');

  try {
    // Retrieve session from KV
    const sessionData = await c.env.KV_SESSION.get(`chat:${sessionId}`);

    if (!sessionData) {
      return c.json({
        success: false,
        error: 'Session not found'
      }, 404);
    }

    const session = JSON.parse(sessionData);

    return c.json({
      success: true,
      session: {
        id: session.id,
        status: session.status,
        qualification_score: session.qualification_score,
        created_at: session.created_at,
        messages: session.messages.slice(-20) // Return last 20 messages
      }
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to retrieve session'
    }, 500);
  }
});

// Email Processing
app.post('/email/inbound', zValidator('json', EmailSchema), async (c: any) => {
  const leadIngestionService = c.get('leadIngestionService') as LeadIngestionService;
  const businessId = c.get('businessId') as string;
  const email = c.req.valid('json') as ParsedEmail;

  try {
    const result = await leadIngestionService.handleInboundEmail(email, businessId);

    return c.json({
      success: result.success,
      lead_id: result.lead_id,
      qualification_result: result.qualification_result,
      processing_time_ms: result.processing_time_ms,
      ai_tasks_created: result.ai_tasks_created,
      error: result.error
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Email processing failed'
    }, 500);
  }
});

// Form Submissions
app.post('/forms/submit', zValidator('json', FormSubmissionSchema), async (c: any) => {
  const leadIngestionService = c.get('leadIngestionService') as LeadIngestionService;
  const businessId = c.get('businessId') as string;
  const submission = c.req.valid('json') as FormSubmission;

  try {
    const result = await leadIngestionService.handleFormSubmission(submission, businessId);

    return c.json({
      success: result.success,
      lead_id: result.lead_id,
      contact_id: result.contact_id,
      company_id: result.company_id,
      qualification_result: result.qualification_result,
      instant_response: result.instant_response,
      processing_time_ms: result.processing_time_ms,
      error: result.error
    }, result.success ? 201 : 400);
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Form processing failed'
    }, 500);
  }
});

// Direct Lead Creation API
app.post('/leads', zValidator('json', LeadInputSchema), async (c: any) => {
  const leadIngestionService = c.get('leadIngestionService') as LeadIngestionService;
  const businessId = c.get('businessId') as string;
  const leadData = c.req.valid('json') as LeadInput;

  try {
    const result = await leadIngestionService.createLead(leadData, businessId);

    return c.json({
      success: result.success,
      lead_id: result.lead_id,
      contact_id: result.contact_id,
      company_id: result.company_id,
      qualification_result: result.qualification_result,
      instant_response: result.instant_response,
      processing_time_ms: result.processing_time_ms,
      ai_tasks_created: result.ai_tasks_created,
      error: result.error
    }, result.success ? 201 : 400);
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Lead creation failed'
    }, 500);
  }
});

// Bulk Lead Import
app.post('/leads/bulk', async (c: any) => {
  const leadIngestionService = c.get('leadIngestionService') as LeadIngestionService;
  const businessId = c.get('businessId') as string;

  try {
    const body = await c.req.json();
    const leads = body.leads as LeadInput[];

    if (!Array.isArray(leads) || leads.length === 0) {
      return c.json({
        success: false,
        error: 'Invalid leads array'
      }, 400);
    }

    if (leads.length > 100) {
      return c.json({
        success: false,
        error: 'Maximum 100 leads per batch'
      }, 400);
    }

    const results = [];
    let successful = 0;
    let failed = 0;

    for (const leadData of leads) {
      try {
        const result = await leadIngestionService.createLead(leadData, businessId);
        results.push(result);
        if (result.success) successful++;
        else failed++;
      } catch (error: any) {
        results.push({
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
          processing_time_ms: 0,
          ai_tasks_created: 0
        });
        failed++;
      }
    }

    return c.json({
      success: failed === 0,
      total: leads.length,
      successful,
      failed,
      results
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Bulk import failed'
    }, 500);
  }
});

// Integration Webhooks (Generic)
app.post('/webhooks/:integration', async (c: any) => {
  const integration = c.req.param('integration');
  const leadIngestionService = c.get('leadIngestionService') as LeadIngestionService;
  const businessId = c.get('businessId') as string;

  try {
    const body = await c.req.json();

    // Map integration data to LeadInput format
    let leadData: LeadInput;

    switch (integration) {
      case 'calendly':
        leadData = {
          source: 'integration',
          source_campaign: 'calendly_booking',
          email: body.payload?.email,
          full_name: body.payload?.name,
          message: `Scheduled meeting: ${body.payload?.event_type?.name}`,
          source_metadata: {
            integration: 'calendly',
            event_type: body.payload?.event_type,
            scheduled_event: body.payload?.scheduled_event
          }
        };
        break;

      case 'zapier':
        leadData = {
          source: 'integration',
          source_campaign: 'zapier_automation',
          ...body, // Zapier should send data in our format
          source_metadata: {
            integration: 'zapier',
            zap_id: body.zap_id
          }
        };
        break;

      case 'hubspot':
        leadData = {
          source: 'integration',
          source_campaign: 'hubspot_sync',
          email: body.properties?.email?.value,
          first_name: body.properties?.firstname?.value,
          last_name: body.properties?.lastname?.value,
          company_name: body.properties?.company?.value,
          phone: body.properties?.phone?.value,
          source_metadata: {
            integration: 'hubspot',
            contact_id: body.objectId,
            properties: body.properties
          }
        };
        break;

      default:
        // Generic webhook format
        leadData = {
          source: 'integration',
          source_campaign: `${integration}_webhook`,
          ...body,
          source_metadata: {
            integration,
            raw_payload: body
          }
        };
    }

    const result = await leadIngestionService.createLead(leadData, businessId);

    return c.json({
      success: result.success,
      message: `Lead processed from ${integration}`,
      lead_id: result.lead_id,
      qualified: result.qualification_result?.qualified
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: `Failed to process ${integration} webhook`
    }, 500);
  }
});

// Health check
app.get('/health', async (c: any) => {
  return c.json({
    status: 'healthy',
    service: 'Lead Ingestion Service',
    timestamp: new Date().toISOString(),
    endpoints: {
      meta_webhook: '/webhooks/meta',
      chat: '/chat/message',
      email: '/email/inbound',
      forms: '/forms/submit',
      direct_api: '/leads',
      bulk_import: '/leads/bulk'
    }
  });
});

// Analytics endpoint
app.get('/analytics/ingestion', async (c: any) => {
  const businessId = c.get('businessId') as string;
  const period = c.req.query('period') || '24h';

  // This would query actual analytics data
  return c.json({
    success: true,
    business_id: businessId,
    period,
    metrics: {
      total_leads: 45,
      qualified_leads: 32,
      sources: {
        meta_ads: 15,
        website_chat: 12,
        contact_form: 8,
        email: 5,
        integration: 5
      },
      qualification_rate: 0.71,
      avg_processing_time_ms: 1245,
      instant_responses_sent: 28,
      ai_calls_triggered: 12
    }
  });
});

// Error handling
app.onError((error, c) => {

  return c.json({
    success: false,
    error: 'Internal server error',
    message: error.message,
    timestamp: new Date().toISOString()
  }, 500);
});

export default app;