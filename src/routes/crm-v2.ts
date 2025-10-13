// @ts-nocheck
/**
 * CRM V2 API Routes - Fortune 50 Level
 * Complete customer relationship management endpoints
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';
import { CRMService } from '../services/crm/crm-service';
import { authenticate } from '../middleware/auth';
import { asyncHandler } from '../shared/error-handler';

const crmV2 = new Hono<{ Bindings: Env }>();

// Apply authentication to all routes
crmV2.use('*', authenticate());

// ============================================================
// COMPANIES
// ============================================================

crmV2.get('/companies', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;

  const filters = {
    lifecycle_stage: c.req.query('lifecycle_stage'),
    status: c.req.query('status'),
    owner_id: c.req.query('owner_id'),
    min_score: c.req.query('min_score') ? parseInt(c.req.query('min_score')!) : undefined,
    limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50,
    offset: c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0
  };

  const crmService = new CRMService(db, businessId);
  const result = await crmService.getCompanies(filters);

  return c.json({
    success: true,
    data: result.companies,
    total: result.total,
    page: Math.floor(filters.offset / filters.limit) + 1,
    per_page: filters.limit
  });
}));

crmV2.get('/companies/:id', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;
  const companyId = c.req.param('id');

  const crmService = new CRMService(db, businessId);
  const company = await crmService.getCompanyById(companyId);

  if (!company) {
    return c.json({ success: false, error: 'Company not found' }, 404);
  }

  return c.json({ success: true, data: company });
}));

crmV2.post('/companies', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const userId = c.get('userId');
  const db = c.env.DB_MAIN || c.env.DB;
  const body = await c.req.json();

  const crmService = new CRMService(db, businessId);
  const company = await crmService.createCompany({
    ...body,
    owner_id: body.owner_id || userId
  });

  return c.json({ success: true, data: company }, 201);
}));

crmV2.put('/companies/:id', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;
  const companyId = c.req.param('id');
  const body = await c.req.json();

  const crmService = new CRMService(db, businessId);
  const company = await crmService.updateCompany(companyId, body);

  return c.json({ success: true, data: company });
}));

// ============================================================
// CONTACTS
// ============================================================

crmV2.get('/contacts', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;

  const filters = {
    company_id: c.req.query('company_id'),
    lifecycle_stage: c.req.query('lifecycle_stage'),
    status: c.req.query('status'),
    min_score: c.req.query('min_score') ? parseInt(c.req.query('min_score')!) : undefined,
    limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50,
    offset: c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0
  };

  const crmService = new CRMService(db, businessId);
  const result = await crmService.getContacts(filters);

  return c.json({
    success: true,
    data: result.contacts,
    total: result.total,
    page: Math.floor(filters.offset / filters.limit) + 1,
    per_page: filters.limit
  });
}));

crmV2.post('/contacts', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const userId = c.get('userId');
  const db = c.env.DB_MAIN || c.env.DB;
  const body = await c.req.json();

  const crmService = new CRMService(db, businessId);
  const contact = await crmService.createContact({
    ...body,
    owner_id: body.owner_id || userId
  });

  return c.json({ success: true, data: contact }, 201);
}));

// ============================================================
// DEALS
// ============================================================

crmV2.get('/deals', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;

  const filters = {
    stage: c.req.query('stage'),
    status: c.req.query('status'),
    owner_id: c.req.query('owner_id'),
    company_id: c.req.query('company_id'),
    limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50,
    offset: c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0
  };

  const crmService = new CRMService(db, businessId);
  const result = await crmService.getDeals(filters);

  return c.json({
    success: true,
    data: result.deals,
    total: result.total,
    page: Math.floor(filters.offset / filters.limit) + 1,
    per_page: filters.limit
  });
}));

crmV2.post('/deals', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const userId = c.get('userId');
  const db = c.env.DB_MAIN || c.env.DB;
  const body = await c.req.json();

  const crmService = new CRMService(db, businessId);
  const deal = await crmService.createDeal({
    ...body,
    owner_id: body.owner_id || userId
  });

  return c.json({ success: true, data: deal }, 201);
}));

crmV2.patch('/deals/:id/stage', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;
  const dealId = c.req.param('id');
  const { stage } = await c.req.json();

  const crmService = new CRMService(db, businessId);
  const deal = await crmService.updateDealStage(dealId, stage);

  return c.json({ success: true, data: deal });
}));

// ============================================================
// ACTIVITIES
// ============================================================

crmV2.get('/activities', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;

  const filters = {
    type: c.req.query('type'),
    status: c.req.query('status'),
    owner_id: c.req.query('owner_id'),
    company_id: c.req.query('company_id'),
    deal_id: c.req.query('deal_id'),
    limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50,
    offset: c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0
  };

  const crmService = new CRMService(db, businessId);
  const result = await crmService.getActivities(filters);

  return c.json({
    success: true,
    data: result.activities,
    total: result.total,
    page: Math.floor(filters.offset / filters.limit) + 1,
    per_page: filters.limit
  });
}));

// ============================================================
// ANALYTICS & INSIGHTS
// ============================================================

crmV2.get('/analytics/pipeline', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;

  const crmService = new CRMService(db, businessId);
  const metrics = await crmService.getPipelineMetrics();

  return c.json({ success: true, data: metrics });
}));

crmV2.get('/analytics/dashboard', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;

  const crmService = new CRMService(db, businessId);
  const stats = await crmService.getDashboardStats();

  return c.json({ success: true, data: stats });
}));

// ============================================================
// AI-POWERED FEATURES
// ============================================================

crmV2.post('/contacts/:id/calculate-score', asyncHandler(async (c: any) => {
  const businessId = c.get('businessId');
  const db = c.env.DB_MAIN || c.env.DB;
  const contactId = c.req.param('id');

  const crmService = new CRMService(db, businessId);
  const score = await crmService.calculateLeadScore(contactId);

  // Update the contact's lead score
  await db
    .prepare('UPDATE crm_contacts SET lead_score = ? WHERE id = ?')
    .bind(score, contactId)
    .run();

  return c.json({ success: true, data: { contact_id: contactId, lead_score: score } });
}));

export default crmV2;
