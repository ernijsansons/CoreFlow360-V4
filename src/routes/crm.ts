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
  subject: z.string().optional(),
  content: z.string().optional(),
  duration: z.number().optional(),
  outcome: z.enum(['positive', 'neutral', 'negative', 'no_response']).optional()
});

const CreateAITaskSchema = z.object({
  lead_id: z.string().optional(),
  contact_id: z.string().optional(),
  type: z.enum(['research_company', 'qualify_lead', 'send_followup', 'analyze_conversation']),
  status: z.enum(['pending', 'in_progress', 'completed', 'failed']).optional(),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).optional(),
  due_date: z.string().optional(),
  metadata: z.record(z.any()).optional()
});

const LeadFiltersSchema = z.object({
  status: z.enum(['new', 'contacted', 'qualified', 'proposal', 'negotiation', 'closed_won', 'closed_lost']).optional(),
  source: z.string().optional(),
  assigned_to: z.string().optional(),
  created_after: z.string().optional(),
  created_before: z.string().optional(),
  score_min: z.number().optional(),
  score_max: z.number().optional()
});

const ContactFiltersSchema = z.object({
  company_id: z.string().optional(),
  department: z.string().optional(),
  seniority_level: z.string().optional(),
  created_after: z.string().optional(),
  created_before: z.string().optional()
});

const ConversationFiltersSchema = z.object({
  lead_id: z.string().optional(),
  contact_id: z.string().optional(),
  type: z.string().optional(),
  direction: z.string().optional(),
  outcome: z.string().optional(),
  created_after: z.string().optional(),
  created_before: z.string().optional()
});

const PaginationSchema = z.object({
  page: z.number().min(1).default(1),
  limit: z.number().min(1).max(100).default(20),
  sort_by: z.string().optional(),
  sort_order: z.enum(['asc', 'desc']).default('desc')
});

// Companies endpoints
app.post('/companies', zValidator('json', CreateCompanySchema), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const company = await crmService.createCompany(c.get('validatedData'));
    return c.json({ success: true, data: company });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 400);
  }
});

app.get('/companies', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const companies = await crmService.getCompanies();
    return c.json({ success: true, data: companies });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.get('/companies/:id', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const company = await crmService.getCompany(c.req.param('id'));
    if (!company) {
      return c.json({ success: false, error: 'Company not found' }, 404);
    }
    return c.json({ success: true, data: company });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.put('/companies/:id', zValidator('json', CreateCompanySchema.partial()), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const company = await crmService.updateCompany(c.req.param('id'), c.get('validatedData'));
    if (!company) {
      return c.json({ success: false, error: 'Company not found' }, 404);
    }
    return c.json({ success: true, data: company });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 400);
  }
});

app.delete('/companies/:id', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const success = await crmService.deleteCompany(c.req.param('id'));
    if (!success) {
      return c.json({ success: false, error: 'Company not found' }, 404);
    }
    return c.json({ success: true });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// Contacts endpoints
app.post('/contacts', zValidator('json', CreateContactSchema), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const contact = await crmService.createContact(c.get('validatedData'));
    return c.json({ success: true, data: contact });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 400);
  }
});

app.get('/contacts', zValidator('query', ContactFiltersSchema.merge(PaginationSchema)), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const { page, limit, sort_by, sort_order, ...filters } = c.get('validatedData');
    const pagination: PaginationOptions = { page, limit, sort_by, sort_order };
    const contacts = await crmService.getContacts(filters, pagination);
    return c.json({ success: true, data: contacts });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.get('/contacts/:id', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const contact = await crmService.getContact(c.req.param('id'));
    if (!contact) {
      return c.json({ success: false, error: 'Contact not found' }, 404);
    }
    return c.json({ success: true, data: contact });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.put('/contacts/:id', zValidator('json', CreateContactSchema.partial()), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const contact = await crmService.updateContact(c.req.param('id'), c.get('validatedData'));
    if (!contact) {
      return c.json({ success: false, error: 'Contact not found' }, 404);
    }
    return c.json({ success: true, data: contact });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 400);
  }
});

app.delete('/contacts/:id', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const success = await crmService.deleteContact(c.req.param('id'));
    if (!success) {
      return c.json({ success: false, error: 'Contact not found' }, 404);
    }
    return c.json({ success: true });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// Leads endpoints
app.post('/leads', zValidator('json', CreateLeadSchema), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const lead = await crmService.createLead(c.get('validatedData'));
    return c.json({ success: true, data: lead });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 400);
  }
});

app.get('/leads', zValidator('query', LeadFiltersSchema.merge(PaginationSchema)), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const { page, limit, sort_by, sort_order, ...filters } = c.get('validatedData');
    const pagination: PaginationOptions = { page, limit, sort_by, sort_order };
    const leads = await crmService.getLeads(filters, pagination);
    return c.json({ success: true, data: leads });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.get('/leads/:id', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const lead = await crmService.getLead(c.req.param('id'));
    if (!lead) {
      return c.json({ success: false, error: 'Lead not found' }, 404);
    }
    return c.json({ success: true, data: lead });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.put('/leads/:id', zValidator('json', CreateLeadSchema.partial()), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const lead = await crmService.updateLead(c.req.param('id'), c.get('validatedData'));
    if (!lead) {
      return c.json({ success: false, error: 'Lead not found' }, 404);
    }
    return c.json({ success: true, data: lead });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 400);
  }
});

app.delete('/leads/:id', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const success = await crmService.deleteLead(c.req.param('id'));
    if (!success) {
      return c.json({ success: false, error: 'Lead not found' }, 404);
    }
    return c.json({ success: true });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// Conversations endpoints
app.post('/conversations', zValidator('json', CreateConversationSchema), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const conversation = await crmService.createConversation(c.get('validatedData'));
    return c.json({ success: true, data: conversation });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 400);
  }
});

app.get('/conversations', zValidator('query', ConversationFiltersSchema.merge(PaginationSchema)), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const { page, limit, sort_by, sort_order, ...filters } = c.get('validatedData');
    const pagination: PaginationOptions = { page, limit, sort_by, sort_order };
    const conversations = await crmService.getConversations(filters, pagination);
    return c.json({ success: true, data: conversations });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.get('/conversations/:id', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const conversation = await crmService.getConversation(c.req.param('id'));
    if (!conversation) {
      return c.json({ success: false, error: 'Conversation not found' }, 404);
    }
    return c.json({ success: true, data: conversation });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// AI Tasks endpoints
app.post('/ai-tasks', zValidator('json', CreateAITaskSchema), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const task = await crmService.createAITask(c.get('validatedData'));
    return c.json({ success: true, data: task });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 400);
  }
});

app.get('/ai-tasks', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const tasks = await crmService.getAITasks();
    return c.json({ success: true, data: tasks });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.get('/ai-tasks/:id', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const task = await crmService.getAITask(c.req.param('id'));
    if (!task) {
      return c.json({ success: false, error: 'AI Task not found' }, 404);
    }
    return c.json({ success: true, data: task });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.put('/ai-tasks/:id', zValidator('json', CreateAITaskSchema.partial()), async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const task = await crmService.updateAITask(c.req.param('id'), c.get('validatedData'));
    if (!task) {
      return c.json({ success: false, error: 'AI Task not found' }, 404);
    }
    return c.json({ success: true, data: task });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 400);
  }
});

// Metrics endpoints
app.get('/metrics/leads', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const metrics = await crmService.getLeadMetrics();
    return c.json({ success: true, data: metrics });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.get('/metrics/contacts', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const metrics = await crmService.getContactMetrics();
    return c.json({ success: true, data: metrics });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.get('/metrics/ai-tasks', async (c) => {
  try {
    const crmService = new CRMService(c.env);
    const metrics = await crmService.getAITaskMetrics();
    return c.json({ success: true, data: metrics });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// Migration endpoints
app.post('/migrate', async (c) => {
  try {
    const migrationManager = new CRMMigrationManager(c.env);
    const result = await migrationManager.runMigrations();
    return c.json({ success: true, data: result });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

app.get('/migrate/status', async (c) => {
  try {
    const migrationManager = new CRMMigrationManager(c.env);
    const status = await migrationManager.getMigrationStatus();
    return c.json({ success: true, data: status });
  } catch (error) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

export default app;

