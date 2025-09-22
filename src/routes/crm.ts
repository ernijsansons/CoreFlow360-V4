import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { CRMService } from '../services/crm-service';
import { CRMMigrationManager } from '../database/crm-migration-manager';
import type { Env } from '../types/env';
import type {
  LeadFilters,
  ContactFilters,
  ConversationFilters,
  PaginationOptions
} from '../types/crm';

const app = new Hono<{ Bindings: Env }>();

// Request validation schemas
const CreateCompanySchema = z.object({
  name: z.string().min(1, 'Company name is required'),
  domain: z.string().optional(),
  industry: z.string().optional(),
  size_range: z.enum(['1-10', '11-50', '51-200', '201-500', '501-1000', '1000+']).optional(),
  revenue_range: z.enum(['0-1M', '1M-5M', '5M-10M', '10M-50M', '50M-100M', '100M+']).optional()
});

const CreateContactSchema = z.object({
  company_id: z.string().optional(),
  email: z.string().email('Valid email is required'),
  phone: z.string().optional(),
  first_name: z.string().optional(),
  last_name: z.string().optional(),
  title: z.string().optional(),
  seniority_level: z.enum(['individual_contributor', 'team_lead', 'manager', 'director', 'vp', 'c_level', 'founder']).optional(),
  department: z.enum(['engineering', 'sales', 'marketing',
  'hr', 'finance', 'operations', 'legal', 'executive', 'other']).optional(),
  linkedin_url: z.string().optional()
});

const CreateLeadSchema = z.object({
  contact_id: z.string().optional(),
  company_id: z.string().optional(),
  source: z.string().min(1, 'Lead source is required'),
  source_campaign: z.string().optional(),
  assigned_to: z.string().optional()
});

const CreateConversationSchema = z.object({
  lead_id: z.string().optional(),
  contact_id: z.string().optional(),
  type: z.enum(['call', 'email', 'chat', 'sms', 'meeting', 'demo']),
  direction: z.enum(['inbound', 'outbound']),
  participant_type: z.enum(['ai', 'human', 'mixed']),
  subject: z.string().optional(),
  transcript: z.string().optional(),
  duration_seconds: z.number().optional(),
  external_id: z.string().optional()
});

const UpdateLeadStatusSchema = z.object({
  status: z.enum(['new', 'qualifying',
  'qualified', 'meeting_scheduled', 'opportunity', 'unqualified', 'closed_won', 'closed_lost']),
  notes: z.string().optional()
});

const PaginationSchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(50),
  sortBy: z.string().default('created_at'),
  sortOrder: z.enum(['ASC', 'DESC']).default('DESC')
});

// Middleware to extract business context
app.use('*', async (c, next) => {
  // In a real implementation, this would extract business_id from JWT or session
  const businessId = c.req.header('X-Business-ID') || 'default-business';
  c.set('businessId', businessId);
  c.set('crmService', new CRMService(c.env));
  await next();
});

// Health check and setup routes
app.get('/health', async (c) => {
  const migrationManager = new CRMMigrationManager(c.env);
  const status = await migrationManager.getCRMMigrationStatus();

  return c.json({
    status: 'healthy',
    database: 'connected',
    migrations: status.length,
    timestamp: new Date().toISOString()
  });
});

app.post('/setup', async (c) => {
  try {
    const migrationManager = new CRMMigrationManager(c.env);
    const result = await migrationManager.initializeCRM();

    if (!result.success) {
      return c.json({
        success: false,
        errors: result.errors
      }, 500);
    }

    return c.json({
      success: true,
      message: 'CRM database initialized successfully',
      migrations: result.results.length
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

app.get('/verify', async (c) => {
  try {
    const migrationManager = new CRMMigrationManager(c.env);
    const result = await migrationManager.verifyCRMSchema();

    return c.json({
      valid: result.valid,
      issues: result.issues
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// Company routes
app.post('/companies', zValidator('json', CreateCompanySchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const data = c.req.valid('json');

  const result = await crmService.createCompany({
    ...data,
    business_id: businessId
  });

  return c.json(result, result.success ? 201 : 400);
});

app.get('/companies/:id', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const id = c.req.param('id');

  // For demo purposes - in real app, you'd get company through service
  return c.json({
    success: true,
    data: { id, message: 'Company endpoint - implement company retrieval' }
  });
});

app.post('/companies/:id/enrich', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const id = c.req.param('id');

  const result = await crmService.enrichCompanyWithAI(id);
  return c.json(result, result.success ? 200 : 400);
});

// Contact routes
app.post('/contacts', zValidator('json', CreateContactSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const data = c.req.valid('json');

  const result = await crmService.createContact({
    ...data,
    business_id: businessId
  });

  return c.json(result, result.success ? 201 : 400);
});

app.get('/contacts/:id', async (c) => {
  const id = c.req.param('id');
  // Implement contact retrieval
  return c.json({
    success: true,
    data: { id, message: 'Contact endpoint - implement contact retrieval' }
  });
});

// Lead routes
app.post('/leads', zValidator('json', CreateLeadSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const data = c.req.valid('json');

  const result = await crmService.createLead({
    ...data,
    business_id: businessId
  });

  return c.json(result, result.success ? 201 : 400);
});

app.get('/leads', zValidator('query', PaginationSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const pagination = c.req.valid('query');

  // Parse filters from query params
  const filters: LeadFilters = {};

  const status = c.req.query('status');
  if (status) filters.status = [status as any];

  const assignedTo = c.req.query('assigned_to');
  if (assignedTo) filters.assigned_to = [assignedTo];

  const source = c.req.query('source');
  if (source) filters.source = [source];

  const minScore = c.req.query('min_score');
  if (minScore) filters.ai_qualification_score_min = parseInt(minScore);

  const result = await crmService.getLeads(businessId, filters, pagination);
  return c.json(result, result.success ? 200 : 400);
});

app.get('/leads/:id', async (c) => {
  const id = c.req.param('id');
  // Implement lead retrieval
  return c.json({
    success: true,
    data: { id, message: 'Lead endpoint - implement lead retrieval' }
  });
});

app.patch('/leads/:id/status', zValidator('json', UpdateLeadStatusSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const id = c.req.param('id');
  const { status, notes } = c.req.valid('json');

  const result = await crmService.updateLeadStatus(id, status, notes);
  return c.json(result, result.success ? 200 : 400);
});

// Lead Qualification routes
const QualifyLeadSchema = z.object({
  conversation_context: z.object({
    leadId: z.string(),
    contactId: z.string().optional(),
    transcript: z.string(),
    messages: z.array(z.object({
      role: z.enum(['ai', 'human']),
      content: z.string(),
      timestamp: z.string()
    })),
    metadata: z.object({
      callDuration: z.number().optional(),
      sentiment: z.enum(['positive', 'neutral', 'negative']).optional(),
      topics: z.array(z.string()).optional()
    }).optional()
  }).optional(),
  force_requalification: z.boolean().optional().default(false)
});

const UpdateQualificationStatusSchema = z.object({
  status: z.enum(['not_started', 'in_progress', 'qualified', 'unqualified', 'needs_review']),
  notes: z.string().optional()
});

app.post('/leads/:id/qualify', zValidator('json', QualifyLeadSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const leadId = c.req.param('id');
  const { conversation_context, force_requalification } = c.req.valid('json');

  const result = await crmService.qualifyLead(leadId, conversation_context, force_requalification);
  return c.json(result, result.success ? 200 : 400);
});

app.get('/leads/:id/qualification', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const leadId = c.req.param('id');

  const result = await crmService.getLeadQualification(leadId);
  return c.json(result, result.success ? 200 : 400);
});

app.patch('/leads/:id/qualification-status', zValidator('json', UpdateQualificationStatusSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const leadId = c.req.param('id');
  const { status, notes } = c.req.valid('json');

  const result = await crmService.updateQualificationStatus(leadId, status, notes);
  return c.json(result, result.success ? 200 : 400);
});

// Qualification Analytics endpoint
app.get('/analytics/qualification', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const period = c.req.query('period') as 'day' | 'week' | 'month' || 'week';

  // This would aggregate qualification metrics
  return c.json({
    success: true,
    data: {
      business_id: businessId,
      period,
      metrics: {
        total_qualified: 0,
        qualification_rate: 0,
        avg_qualification_score: 0,
        qualification_by_source: {},
        bant_completion_rates: {
          budget: 0,
          authority: 0,
          need: 0,
          timeline: 0
        }
      },
      message: 'Qualification analytics - implement qualification metrics aggregation'
    }
  });
});

// Meeting Booking routes
const BookMeetingDuringCallSchema = z.object({
  conversation_id: z.string(),
  meeting_type: z.enum(['discovery_call', 'demo', 'consultation',
  'follow_up', 'closing_call', 'technical_review', 'onboarding', 'check_in', 'custom']).optional().default('discovery_call'),
  duration: z.number().min(15).max(180).optional().default(30),
  auto_confirm: z.boolean().optional().default(true),
  send_invite: z.boolean().optional().default(true)
});

const BookInstantMeetingSchema = z.object({
  meeting_type: z.enum(['discovery_call', 'demo', 'consultation',
  'follow_up', 'closing_call', 'technical_review', 'onboarding', 'check_in', 'custom']),
  duration_minutes: z.number().min(15).max(180).optional().default(30),
  preferred_slots: z.array(z.object({
    start: z.string(),
    end: z.string(),
    timezone: z.string(),
    available: z.boolean()
  })).optional(),
  timezone: z.string().optional(),
  auto_confirm: z.boolean().optional().default(true),
  send_calendar_invite: z.boolean().optional().default(true)
});

const UpdateMeetingStatusSchema = z.object({
  status: z.enum(['scheduled', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show', 'rescheduled']),
  notes: z.string().optional(),
  outcome: z.enum(['qualified', 'needs_follow_up', 'closed_won', 'closed_lost', 'rescheduled', 'no_show', 'cancelled']).optional()
});

const RescheduleMeetingSchema = z.object({
  new_slot: z.object({
    start: z.string(),
    end: z.string(),
    timezone: z.string(),
    available: z.boolean()
  }),
  reason: z.string().optional()
});

// Book meeting during active conversation (AI negotiated)
app.post('/leads/:id/book-meeting-during-call', zValidator('json', BookMeetingDuringCallSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const leadId = c.req.param('id');
  const { conversation_id, meeting_type, duration, auto_confirm, send_invite } = c.req.valid('json');

  const result = await crmService.bookMeetingDuringCall(leadId, conversation_id, meeting_type, {
    duration,
    autoConfirm: auto_confirm,
    sendInvite: send_invite
  });

  return c.json(result, result.success ? 201 : 400);
});

// Book instant meeting with predefined slots
app.post('/leads/:id/book-instant-meeting', zValidator('json', BookInstantMeetingSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const leadId = c.req.param('id');
  const bookingData = c.req.valid('json');

  const result = await crmService.bookInstantMeeting({
    lead_id: leadId,
    ...bookingData
  });

  return c.json(result, result.success ? 201 : 400);
});

// Get available meeting slots for a lead
app.get('/leads/:id/available-slots', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const leadId = c.req.param('id');
  const duration = parseInt(c.req.query('duration') || '30');
  const daysAhead = parseInt(c.req.query('days_ahead') || '14');

  const result = await crmService.getAvailableSlots(leadId, duration, daysAhead);
  return c.json(result, result.success ? 200 : 400);
});

// Detect meeting booking intent from conversation transcript
app.post('/conversations/detect-booking-intent', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const { transcript } = await c.req.json();

  if (!transcript) {
    return c.json({
      success: false,
      error: 'Transcript is required'
    }, 400);
  }

  const result = await crmService.detectMeetingBookingIntent(transcript);
  return c.json(result, result.success ? 200 : 400);
});

// Meeting management routes
app.get('/meetings/:id', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const meetingId = c.req.param('id');

  const result = await crmService.getMeeting(meetingId);
  return c.json(result, result.success ? 200 : 400);
});

app.patch('/meetings/:id/status', zValidator('json', UpdateMeetingStatusSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const meetingId = c.req.param('id');
  const { status, notes, outcome } = c.req.valid('json');

  const result = await crmService.updateMeetingStatus(meetingId, status, notes, outcome);
  return c.json(result, result.success ? 200 : 400);
});

app.delete('/meetings/:id', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const meetingId = c.req.param('id');
  const reason = c.req.query('reason');

  const result = await crmService.cancelMeeting(meetingId, reason);
  return c.json(result, result.success ? 200 : 400);
});

app.post('/meetings/:id/reschedule', zValidator('json', RescheduleMeetingSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const meetingId = c.req.param('id');
  const { new_slot, reason } = c.req.valid('json');

  const result = await crmService.rescheduleMeeting(meetingId, new_slot, reason);
  return c.json(result, result.success ? 200 : 400);
});

// Meeting templates
app.get('/meeting-templates', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const meetingType = c.req.query('meeting_type') as any;

  const result = await crmService.getMeetingTemplates(businessId, meetingType);
  return c.json(result, result.success ? 200 : 400);
});

// Meeting analytics
app.get('/analytics/meetings', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const period = c.req.query('period') as 'day' | 'week' | 'month' || 'week';

  // This would aggregate meeting metrics
  return c.json({
    success: true,
    data: {
      business_id: businessId,
      period,
      metrics: {
        total_meetings: 0,
        meetings_booked: 0,
        meetings_completed: 0,
        no_show_rate: 0,
        cancellation_rate: 0,
        conversion_rate: 0,
        avg_meeting_duration: 0,
        booking_sources: {},
        meeting_types: {},
        ai_negotiated_meetings: 0,
        instant_bookings: 0
      },
      message: 'Meeting analytics - implement meeting metrics aggregation'
    }
  });
});

// Bulk operations for meetings
app.post('/meetings/bulk-reschedule', async (c) => {
  const { meeting_ids, new_slots, reason } = await c.req.json();

  if (!meeting_ids || !Array.isArray(meeting_ids) || !new_slots) {
    return c.json({
      success: false,
      error: 'Invalid bulk reschedule request'
    }, 400);
  }

  // This would handle bulk rescheduling
  return c.json({
    success: true,
    data: {
      rescheduled: 0,
      failed: 0,
      message: 'Bulk reschedule - implement bulk operations'
    }
  });
});

// Calendar integration status
app.get('/calendar-integration/status', async (c) => {
  const businessId = c.get('businessId') as string;

  // This would check calendar integration status
  return c.json({
    success: true,
    data: {
      business_id: businessId,
      integrations: {
        google: { connected: false, last_sync: null },
        outlook: { connected: false, last_sync: null },
        caldav: { connected: false, last_sync: null }
      },
      default_provider: 'google',
      sync_enabled: false
    }
  });
});

// Voicemail routes
const LeaveVoicemailSchema = z.object({
  lead_id: z.string(),
  attempt_number: z.number().optional(),
  scenario: z.string().optional(),
  customMessage: z.string().optional()
});

app.post('/voicemails/leave', zValidator('json', LeaveVoicemailSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const data = c.req.valid('json');

  const result = await crmService.leaveVoicemail(data);
  return c.json(result, result.success ? 201 : 400);
});

app.get('/voicemails/:id', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const voicemailId = c.req.param('id');

  const result = await crmService.getVoicemail(voicemailId);
  return c.json(result, result.success ? 200 : 404);
});

app.get('/leads/:leadId/voicemails', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const leadId = c.req.param('leadId');
  const limit = parseInt(c.req.query('limit') || '10');

  const result = await crmService.getLeadVoicemails(leadId, limit);
  return c.json(result, result.success ? 200 : 400);
});

// Voicemail response tracking
const MarkVoicemailResponseSchema = z.object({
  response_type: z.enum(['callback', 'email', 'text', 'no_response']),
  notes: z.string().optional()
});

app.post('/voicemails/:id/response', zValidator('json', MarkVoicemailResponseSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const voicemailId = c.req.param('id');
  const { response_type, notes } = c.req.valid('json');

  const result = await crmService.markVoicemailResponse(voicemailId, response_type, notes);
  return c.json(result, result.success ? 200 : 400);
});

// Voicemail templates
const CreateVoicemailTemplateSchema = z.object({
  name: z.string(),
  scenario: z.string(),
  template_text: z.string(),
  personalization_fields: z.array(z.string()),
  voice_settings: z.object({
    voice_id: z.string(),
    speed: z.number(),
    pitch: z.number()
  }).optional(),
  active: z.boolean().default(true)
});

app.post('/voicemail-templates', zValidator('json', CreateVoicemailTemplateSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const data = c.req.valid('json');

  const result = await crmService.createVoicemailTemplate({
    ...data,
    business_id: businessId,
    success_rate: 0,
    usage_count: 0
  });

  return c.json(result, result.success ? 201 : 400);
});

app.get('/voicemail-templates', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const scenario = c.req.query('scenario');

  const result = await crmService.getVoicemailTemplates(businessId, scenario);
  return c.json(result, result.success ? 200 : 400);
});

app.patch('/voicemail-templates/:id', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const templateId = c.req.param('id');
  const updates = await c.req.json();

  const result = await crmService.updateVoicemailTemplate(templateId, updates);
  return c.json(result, result.success ? 200 : 400);
});

// Voicemail campaigns
const CreateVoicemailCampaignSchema = z.object({
  name: z.string(),
  template_id: z.string(),
  lead_filters: z.object({
    status: z.string().optional(),
    source: z.string().optional(),
    score_min: z.number().optional(),
    score_max: z.number().optional(),
    days_since_last_contact: z.number().optional()
  }),
  max_attempts: z.number().default(3),
  attempt_interval_hours: z.number().default(48),
  personalization_level: z.enum(['generic', 'basic', 'medium', 'high', 'hyper_personalized']).default('medium')
});

app.post('/voicemail-campaigns', zValidator('json', CreateVoicemailCampaignSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const data = c.req.valid('json');

  const result = await crmService.createVoicemailCampaign({
    ...data,
    business_id: businessId
  });

  return c.json(result, result.success ? 201 : 400);
});

app.get('/voicemail-campaigns/:id', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const campaignId = c.req.param('id');

  const result = await crmService.getVoicemailCampaign(campaignId);
  return c.json(result, result.success ? 200 : 404);
});

app.post('/voicemail-campaigns/:id/pause', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const campaignId = c.req.param('id');

  const result = await crmService.pauseVoicemailCampaign(campaignId);
  return c.json(result, result.success ? 200 : 400);
});

app.post('/voicemail-campaigns/:id/resume', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const campaignId = c.req.param('id');

  const result = await crmService.resumeVoicemailCampaign(campaignId);
  return c.json(result, result.success ? 200 : 400);
});

// Voicemail analytics
app.get('/analytics/voicemails', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const period = c.req.query('period') as 'day' | 'week' | 'month' || 'week';

  const result = await crmService.getVoicemailStats(businessId, period);
  return c.json(result, result.success ? 200 : 400);
});

// Detect voicemail opportunity from conversation
app.post('/conversations/detect-voicemail-opportunity', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const { transcript, lead_id } = await c.req.json();

  if (!transcript || !lead_id) {
    return c.json({
      success: false,
      error: 'Transcript and lead_id are required'
    }, 400);
  }

  const result = await crmService.detectVoicemailOpportunity(transcript, lead_id);
  return c.json(result, result.success ? 200 : 400);
});

// Conversation routes
app.post('/conversations', zValidator('json', CreateConversationSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const data = c.req.valid('json');

  const result = await crmService.createConversation({
    ...data,
    business_id: businessId
  });

  return c.json(result, result.success ? 201 : 400);
});

app.get('/conversations', zValidator('query', PaginationSchema), async (c) => {
  const pagination = c.req.valid('query');

  // Parse conversation filters
  const leadId = c.req.query('lead_id');
  const contactId = c.req.query('contact_id');
  const type = c.req.query('type');

  return c.json({
    success: true,
    data: {
      message: 'Conversations endpoint - implement conversation listing',
      filters: { leadId, contactId, type },
      pagination
    }
  });
});

// AI Task routes
app.get('/ai-tasks', zValidator('query', PaginationSchema), async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const limit = parseInt(c.req.query('limit') || '10');

  const result = await crmService.processPendingAITasks(limit);
  return c.json(result, result.success ? 200 : 400);
});

app.post('/ai-tasks/process', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const limit = parseInt(c.req.query('limit') || '5');

  const result = await crmService.processPendingAITasks(limit);
  return c.json({
    success: true,
    message: `Processed ${result.data?.processed || 0} tasks`,
    data: result.data
  });
});

// Analytics routes
app.get('/analytics/leads', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;
  const period = c.req.query('period') as 'day' | 'week' | 'month' || 'week';

  const result = await crmService.getLeadMetrics(businessId, period);
  return c.json(result, result.success ? 200 : 400);
});

app.get('/analytics/overview', async (c) => {
  const businessId = c.get('businessId') as string;
  const period = c.req.query('period') || 'week';

  // This would aggregate data from multiple analytics endpoints
  return c.json({
    success: true,
    data: {
      business_id: businessId,
      period,
      summary: {
        total_leads: 0,
        total_contacts: 0,
        total_companies: 0,
        pending_ai_tasks: 0
      },
      message: 'Analytics overview - implement aggregated metrics'
    }
  });
});

// Webhook endpoints for external integrations
app.post('/webhooks/lead-source', async (c) => {
  const crmService = c.get('crmService') as CRMService;
  const businessId = c.get('businessId') as string;

  try {
    const body = await c.req.json();

    // Create lead from webhook data
    const result = await crmService.createLead({
      business_id: businessId,
      source: body.source || 'webhook',
      source_campaign: body.campaign,
      // Map other fields from webhook payload
    });

    return c.json(result, result.success ? 201 : 400);
  } catch (error) {
    return c.json({
      success: false,
      error: 'Invalid webhook payload'
    }, 400);
  }
});

// Sample data endpoint for testing
app.post('/sample-data', async (c) => {
  try {
    const migrationManager = new CRMMigrationManager(c.env);
    const businessId = c.get('businessId') as string;

    const result = await migrationManager.createSampleData(businessId);

    return c.json({
      success: result.success,
      message: result.success ? 'Sample data created successfully' : 'Failed to create sample data',
      error: result.error
    });
  } catch (error) {
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// Error handling middleware
app.onError((error, c) => {

  return c.json({
    success: false,
    error: 'Internal server error',
    message: error.message
  }, 500);
});

export default app;