/**
 * Support Tickets API Routes
 * RESTful API for support ticket management
 */

import { Logger } from '@/shared/logger';
import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '../types/env';
import { authenticate } from '../middleware/auth';
import { validateInput } from '../middleware/validation';
import { AgentOrchestrator } from '../modules/agents/orchestrator';
import { CapabilityManager } from '../modules/agents/capability-manager';
import { AuditService } from '../modules/audit/audit.service';
import type { AgentTask, BusinessContext } from '../modules/agents/types';

const logger = new Logger({ component: 'SupportTickets' });

const supportTickets = new Hono<{ Bindings: Env }>();

// Helper to create orchestrator
async function getOrchestrator(env: Env): Promise<AgentOrchestrator> {
  const capabilityManager = new CapabilityManager() as any;
  const auditService = new AuditService(env.DB_MAIN) as any;
  return new AgentOrchestrator(env.KV_CACHE as any, env.DB_MAIN, capabilityManager, auditService);
}

// Validation schemas
const CreateTicketSchema = z.object({
  subject: z.string().min(5).max(200),
  description: z.string().min(10).max(5000),
  customerEmail: z.string().email().optional(),
  customerName: z.string().min(1).max(100).optional(),
  customerId: z.string().optional(),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  category: z.enum(['technical', 'billing', 'feature_request', 'bug', 'question', 'other']).optional(),
  metadata: z.record(z.any()).optional()
});

const UpdateTicketSchema = z.object({
  status: z.enum(['new', 'open', 'in_progress', 'waiting_customer', 'resolved', 'closed']).optional(),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  assignedTo: z.string().optional(),
  assignedTeam: z.string().optional(),
  resolution: z.string().optional()
});

const AddCommentSchema = z.object({
  content: z.string().min(1).max(2000),
  isPublic: z.boolean().default(true),
  attachments: z.array(z.object({
    name: z.string(),
    url: z.string(),
    type: z.string(),
    size: z.number()
  })).optional()
});

const RateSatisfactionSchema = z.object({
  rating: z.number().min(1).max(5)
});

/**
 * Create a new support ticket
 * POST /api/v1/support-tickets
 */
supportTickets.post(
  '/',
  authenticate() as any,
  validateInput(CreateTicketSchema) as any,
  async (c) => {
    try {
      const user = (c as any).get('user');
      const validatedData = (c as any).get('validatedData') as any;
      const env = c.env as Env;

      // Build business context
      const businessContext: BusinessContext = {
        userId: user.id,
        businessId: user.business_id,
        correlationId: c.req.header('x-correlation-id') || crypto.randomUUID(),
        businessData: {
          companyName: user.company_name || 'Unknown',
          industry: user.industry || 'General',
          size: 'small',
          timezone: 'UTC',
          locale: 'en-US',
          currency: 'USD',
          fiscalYearStart: '01-01'
        },
        userContext: {
          name: user.name,
          email: user.email,
          role: user.role,
          department: user.department || 'support',
          permissions: user.permissions || [],
          preferences: {}
        },
        requestContext: {
          timestamp: Date.now(),
          ipAddress: c.req.header('cf-connecting-ip') || '0.0.0.0',
          userAgent: c.req.header('user-agent') || 'unknown',
          platform: 'web',
          requestId: crypto.randomUUID()
        }
      };

      // Create agent task
      const task: AgentTask = {
        id: crypto.randomUUID(),
        capability: 'ticket_creation',
        type: 'action',
        priority: 'high',
        input: {
          data: {
            ...(validatedData as any),
            customerId: validatedData.customerId || user.id,
            customerName: validatedData.customerName || user.name,
            customerEmail: validatedData.customerEmail || user.email
          }
        },
        context: businessContext,
        createdAt: Date.now(),
        retryCount: 0
      };

      // Execute via orchestrator
      const orchestrator = await getOrchestrator(env);

      const result = await orchestrator.executeTask(task, businessContext);

      if (result.status === 'failed') {
        return c.json({
          error: result.error?.message || 'Failed to create ticket',
          code: result.error?.code
        }, 500);
      }

      return c.json({
        success: true,
        ticket: result.result?.data
      }, 201);

    } catch (error: any) {
      logger.error('Failed to create support ticket:', error);
      return c.json({
        error: 'Internal server error',
        message: error.message
      }, 500);
    }
  }
);

/**
 * List support tickets with filtering
 * GET /api/v1/support-tickets
 */
supportTickets.get(
  '/',
  authenticate() as any,
  async (c) => {
    try {
      const user = (c as any).get('user');
      const env = c.env as Env;

      // Query parameters
      const status = c.req.query('status');
      const priority = c.req.query('priority');
      const category = c.req.query('category');
      const limit = parseInt(c.req.query('limit') || '50');
      const offset = parseInt(c.req.query('offset') || '0');

      // Build SQL query
      let sql = `
        SELECT * FROM support_tickets
        WHERE business_id = ?
      `;
      const params: any[] = [user.business_id];

      if (status) {
        sql += ` AND status = ?`;
        params.push(status);
      }

      if (priority) {
        sql += ` AND priority = ?`;
        params.push(priority);
      }

      if (category) {
        sql += ` AND category = ?`;
        params.push(category);
      }

      sql += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
      params.push(limit, offset);

      const result = await env.DB_MAIN.prepare(sql).bind(...(params as any)).all();

      // Get total count
      let countSql = `SELECT COUNT(*) as total FROM support_tickets WHERE business_id = ?`;
      const countParams = [user.business_id];
      if (status) {
        countSql += ` AND status = ?`;
        countParams.push(status);
      }
      if (priority) {
        countSql += ` AND priority = ?`;
        countParams.push(priority);
      }
      if (category) {
        countSql += ` AND category = ?`;
        countParams.push(category);
      }

      const countResult = await env.DB_MAIN.prepare(countSql).bind(...(countParams as any)).first() as any;

      return c.json({
        success: true,
        tickets: result.results,
        pagination: {
          total: countResult?.total || 0,
          limit,
          offset,
          hasMore: (offset + limit) < (countResult?.total || 0)
        }
      });

    } catch (error: any) {
      logger.error('Failed to list support tickets:', error);
      return c.json({
        error: 'Internal server error',
        message: error.message
      }, 500);
    }
  }
);

/**
 * Get a single support ticket
 * GET /api/v1/support-tickets/:ticketId
 */
supportTickets.get(
  '/:ticketId',
  authenticate() as any,
  async (c) => {
    try {
      const user = (c as any).get('user');
      const env = c.env as Env;
      const ticketId = c.req.param('ticketId');

      const result = await env.DB_MAIN.prepare(`
        SELECT * FROM support_tickets
        WHERE id = ? AND business_id = ?
      `).bind(ticketId, user.business_id).first();

      if (!result) {
        return c.json({ error: 'Ticket not found' }, 404);
      }

      return c.json({
        success: true,
        ticket: result
      });

    } catch (error: any) {
      logger.error('Failed to get support ticket:', error);
      return c.json({
        error: 'Internal server error',
        message: error.message
      }, 500);
    }
  }
);

/**
 * Update a support ticket
 * PATCH /api/v1/support-tickets/:ticketId
 */
supportTickets.patch(
  '/:ticketId',
  authenticate() as any,
  validateInput(UpdateTicketSchema) as any,
  async (c) => {
    try {
      const user = (c as any).get('user');
      const env = c.env as Env;
      const ticketId = c.req.param('ticketId');
      const validatedData = (c as any).get('validatedData') as any;

      // Check ticket exists
      const ticket = await env.DB_MAIN.prepare(`
        SELECT * FROM support_tickets WHERE id = ? AND business_id = ?
      `).bind(ticketId, user.business_id).first();

      if (!ticket) {
        return c.json({ error: 'Ticket not found' }, 404);
      }

      // Build update query
      const updates: string[] = [];
      const params: any[] = [];

      if (validatedData.status) {
        updates.push('status = ?');
        params.push(validatedData.status);
      }

      if (validatedData.priority) {
        updates.push('priority = ?');
        params.push(validatedData.priority);
      }

      if (validatedData.assignedTo) {
        updates.push('assigned_to = ?');
        params.push(validatedData.assignedTo);
      }

      if (validatedData.assignedTeam) {
        updates.push('assigned_team = ?');
        params.push(validatedData.assignedTeam);
      }

      if (validatedData.resolution && validatedData.status === 'resolved') {
        updates.push('resolved_at = ?');
        params.push(new Date().toISOString());
      }

      if (validatedData.status === 'closed') {
        updates.push('closed_at = ?');
        params.push(new Date().toISOString());
      }

      updates.push('updated_at = ?', 'updated_by = ?');
      params.push(new Date().toISOString(), user.id);

      params.push(ticketId, user.business_id);

      await env.DB_MAIN.prepare(`
        UPDATE support_tickets
        SET ${updates.join(', ')}
        WHERE id = ? AND business_id = ?
      `).bind(...(params as any)).run();

      // Get updated ticket
      const updatedTicket = await env.DB_MAIN.prepare(`
        SELECT * FROM support_tickets WHERE id = ? AND business_id = ?
      `).bind(ticketId, user.business_id).first();

      return c.json({
        success: true,
        ticket: updatedTicket
      });

    } catch (error: any) {
      logger.error('Failed to update support ticket:', error);
      return c.json({
        error: 'Internal server error',
        message: error.message
      }, 500);
    }
  }
);

/**
 * Add comment to ticket
 * POST /api/v1/support-tickets/:ticketId/comments
 */
supportTickets.post(
  '/:ticketId/comments',
  authenticate() as any,
  validateInput(AddCommentSchema) as any,
  async (c) => {
    try {
      const user = (c as any).get('user');
      const env = c.env as Env;
      const ticketId = c.req.param('ticketId');
      const validatedData = (c as any).get('validatedData') as any;

      // Check ticket exists
      const ticket = await env.DB_MAIN.prepare(`
        SELECT conversation_history FROM support_tickets
        WHERE id = ? AND business_id = ?
      `).bind(ticketId, user.business_id).first() as any;

      if (!ticket) {
        return c.json({ error: 'Ticket not found' }, 404);
      }

      // Add comment to conversation history
      const history = JSON.parse(ticket.conversation_history || '[]');
      const comment = {
        id: crypto.randomUUID(),
        ticketId,
        type: 'agent',
        authorId: user.id,
        authorName: user.name,
        content: validatedData.content,
        isPublic: validatedData.isPublic,
        attachments: validatedData.attachments || [],
        createdAt: new Date().toISOString()
      };

      history.push(comment);

      await env.DB_MAIN.prepare(`
        UPDATE support_tickets
        SET conversation_history = ?, updated_at = ?
        WHERE id = ? AND business_id = ?
      `).bind(
        JSON.stringify(history),
        new Date().toISOString(),
        ticketId,
        user.business_id
      ).run();

      return c.json({
        success: true,
        comment
      }, 201);

    } catch (error: any) {
      logger.error('Failed to add comment:', error);
      return c.json({
        error: 'Internal server error',
        message: error.message
      }, 500);
    }
  }
);

/**
 * Rate ticket satisfaction
 * POST /api/v1/support-tickets/:ticketId/satisfaction
 */
supportTickets.post(
  '/:ticketId/satisfaction',
  authenticate() as any,
  validateInput(RateSatisfactionSchema) as any,
  async (c) => {
    try {
      const user = (c as any).get('user');
      const env = c.env as Env;
      const ticketId = c.req.param('ticketId');
      const validatedData = (c as any).get('validatedData') as any;

      await env.DB_MAIN.prepare(`
        UPDATE support_tickets
        SET customer_satisfaction = ?, updated_at = ?
        WHERE id = ? AND business_id = ?
      `).bind(
        validatedData.rating,
        new Date().toISOString(),
        ticketId,
        user.business_id
      ).run();

      return c.json({
        success: true,
        message: 'Thank you for your feedback!'
      });

    } catch (error: any) {
      logger.error('Failed to rate satisfaction:', error);
      return c.json({
        error: 'Internal server error',
        message: error.message
      }, 500);
    }
  }
);

/**
 * Get ticket statistics
 * GET /api/v1/support-tickets/stats
 */
supportTickets.get(
  '/stats/overview',
  authenticate() as any,
  async (c) => {
    try {
      const user = (c as any).get('user');
      const env = c.env as Env;

      const stats = await env.DB_MAIN.prepare(`
        SELECT
          COUNT(*) as total,
          COUNT(CASE WHEN status = 'new' THEN 1 END) as new_tickets,
          COUNT(CASE WHEN status = 'open' THEN 1 END) as open_tickets,
          COUNT(CASE WHEN status = 'in_progress' THEN 1 END) as in_progress,
          COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved,
          COUNT(CASE WHEN status = 'closed' THEN 1 END) as closed,
          COUNT(CASE WHEN priority = 'critical' THEN 1 END) as critical_priority,
          AVG(customer_satisfaction) as avg_satisfaction,
          AVG(response_time) as avg_response_time,
          AVG(resolution_time) as avg_resolution_time
        FROM support_tickets
        WHERE business_id = ?
        AND created_at >= datetime('now', '-30 days')
      `).bind(user.business_id).first();

      return c.json({
        success: true,
        stats
      });

    } catch (error: any) {
      logger.error('Failed to get ticket stats:', error);
      return c.json({
        error: 'Internal server error',
        message: error.message
      }, 500);
    }
  }
);

export default supportTickets;
