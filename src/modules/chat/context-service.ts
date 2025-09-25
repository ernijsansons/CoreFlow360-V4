/**
 * Chat Context Service
 * Provides business context awareness for AI chat interactions
 */

import { z } from 'zod'
import type { Env } from '@/types/env'
import { AppError } from '@/shared/errors/app-error'
import { AuditLogger } from '@/shared/services/audit-logger'

const ContextDataSchema = z.object({
  user: z.object({
    id: z.string(),
    name: z.string(),
    email: z.string(),
    role: z.string(),
    permissions: z.array(z.string())
  }),
  business: z.object({
    id: z.string(),
    name: z.string(),
    industry: z.string().optional(),
    timezone: z.string().optional()
  }),
  currentPage: z.string().optional(),
  currentEntity: z.object({
    type: z.enum(['invoice', 'customer', 'product', 'report']),
    id: z.string(),
    data: z.record(z.any())
  }).optional(),
  recentActivity: z.array(z.object({
    action: z.string(),
    entity: z.string(),
    timestamp: z.string()
  })).optional(),
  preferences: z.object({
    language: z.string().default('en'),
    currency: z.string().default('USD'),
    timezone: z.string().default('UTC')
  }).optional()
})

export type ChatContext = z.infer<typeof ContextDataSchema>

interface RelevantData {
  invoices?: any[]
  customers?: any[]
  products?: any[]
  metrics?: any
  trends?: any
}

export // TODO: Consider splitting ChatContextService into smaller, focused classes
class ChatContextService {
  constructor(
    private env: Env,
    private auditLogger: AuditLogger
  ) {}

  /**
   * Gather comprehensive context for chat interaction
   */
  async gatherContext(
    userId: string,
    businessId: string,
    currentPage?: string,
    entityContext?: { type: string; id: string }
  ): Promise<ChatContext & { relevantData: RelevantData }> {
    try {
      // Gather user context
      const userContext = await this.getUserContext(userId)

      // Gather business context
      const businessContext = await this.getBusinessContext(businessId)

      // Gather recent activity
      const recentActivity = await this.getRecentActivity(userId, businessId)

      // Gather page-specific context
      const relevantData = await this.getRelevantData(
        currentPage,
        entityContext,
        businessId
      )

      // Get user preferences
      const preferences = await this.getUserPreferences(userId)

      const context: ChatContext = {
        user: userContext,
        business: businessContext,
        currentPage,
        currentEntity: entityContext ? {
          type: entityContext.type as any,
          id: entityContext.id,
          data: await this.getEntityData(entityContext.type, entityContext.id)
        } : undefined,
        recentActivity,
        preferences
      }

      await this.auditLogger.log({
        action: 'chat_context_gathered',
        userId,
        details: {
          businessId,
          currentPage,
          entityContext,
          contextSize: JSON.stringify(context).length
        }
      })

      return {
        ...context,
        relevantData
      }

    } catch (error) {
      await this.auditLogger.log({
        action: 'chat_context_failed',
        userId,
        details: {
          businessId,
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      })

      throw new AppError(
        'Failed to gather chat context',
        'CONTEXT_ERROR',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Get user context information
   */
  private async getUserContext(userId: string) {
    const user = await this.env.DB.prepare(`
      SELECT id, name, email, role, permissions
      FROM users
      WHERE id = ?
    `).bind(userId).first()

    if (!user) {
      throw new AppError('User not found', 'USER_NOT_FOUND', 404)
    }

    return {
      id: user.id as string,
      name: user.name as string,
      email: user.email as string,
      role: user.role as string,
      permissions: JSON.parse(user.permissions as string || '[]')
    }
  }

  /**
   * Get business context information
   */
  private async getBusinessContext(businessId: string) {
    const business = await this.env.DB.prepare(`
      SELECT id, name, industry, timezone
      FROM businesses
      WHERE id = ?
    `).bind(businessId).first()

    if (!business) {
      throw new AppError('Business not found', 'BUSINESS_NOT_FOUND', 404)
    }

    return {
      id: business.id as string,
      name: business.name as string,
      industry: business.industry as string,
      timezone: business.timezone as string
    }
  }

  /**
   * Get recent user activity
   */
  private async getRecentActivity(userId: string, businessId: string) {
    const activities = await this.env.DB.prepare(`
      SELECT action, entity_type as entity, created_at as timestamp
      FROM audit_logs
      WHERE user_id = ? AND business_id = ?
      ORDER BY created_at DESC
      LIMIT 10
    `).bind(userId, businessId).all()

    return activities.results.map(activity => ({
      action: activity.action as string,
      entity: activity.entity as string,
      timestamp: activity.timestamp as string
    }))
  }

  /**
   * Get relevant data based on current context
   */
  private async getRelevantData(
    currentPage?: string,
    entityContext?: { type: string; id: string },
    businessId?: string
  ): Promise<RelevantData> {
    const relevantData: RelevantData = {}

    if (!businessId) return relevantData

    try {
      // Page-specific data gathering
      switch (currentPage) {
        case 'dashboard':
          relevantData.metrics = await this.getDashboardMetrics(businessId)
          relevantData.trends = await this.getRecentTrends(businessId)
          break

        case 'invoices':
          relevantData.invoices = await this.getRecentInvoices(businessId)
          if (entityContext?.type === 'invoice') {
            relevantData.invoices = [
              await this.getEntityData('invoice', entityContext.id),
              ...relevantData.invoices.slice(0, 4)
            ]
          }
          break

        case 'customers':
          relevantData.customers = await this.getRecentCustomers(businessId)
          if (entityContext?.type === 'customer') {
            relevantData.customers = [
              await this.getEntityData('customer', entityContext.id),
              ...relevantData.customers.slice(0, 4)
            ]
          }
          break

        case 'inventory':
          relevantData.products = await this.getRecentProducts(businessId)
          if (entityContext?.type === 'product') {
            relevantData.products = [
              await this.getEntityData('product', entityContext.id),
              ...relevantData.products.slice(0, 4)
            ]
          }
          break

        default:
          // General context - get a bit of everything
          relevantData.metrics = await this.getDashboardMetrics(businessId)
          relevantData.invoices = await this.getRecentInvoices(businessId, 3)
          relevantData.customers = await this.getRecentCustomers(businessId, 3)
          break
      }

    } catch (error) {
    }

    return relevantData
  }

  /**
   * Get entity data by type and ID
   */
  private async getEntityData(type: string, id: string): Promise<any> {
    switch (type) {
      case 'invoice':
        return await this.env.DB.prepare(`
          SELECT * FROM invoices WHERE id = ?
        `).bind(id).first()

      case 'customer':
        return await this.env.DB.prepare(`
          SELECT * FROM customers WHERE id = ?
        `).bind(id).first()

      case 'product':
        return await this.env.DB.prepare(`
          SELECT * FROM products WHERE id = ?
        `).bind(id).first()

      default:
        return null
    }
  }

  /**
   * Get user preferences
   */
  private async getUserPreferences(userId: string) {
    const preferences = await this.env.DB.prepare(`
      SELECT language, currency, timezone
      FROM user_preferences
      WHERE user_id = ?
    `).bind(userId).first()

    return {
      language: preferences?.language as string || 'en',
      currency: preferences?.currency as string || 'USD',
      timezone: preferences?.timezone as string || 'UTC'
    }
  }

  /**
   * Get dashboard metrics
   */
  private async getDashboardMetrics(businessId: string) {
    const metrics = await this.env.DB.prepare(`
      SELECT
        COUNT(*) as total_invoices,
        SUM(CASE WHEN status = 'paid' THEN total_amount ELSE 0 END) as total_revenue,
        SUM(CASE WHEN status = 'overdue' THEN 1 ELSE 0 END) as overdue_invoices,
        AVG(total_amount) as avg_invoice_amount
      FROM invoices
      WHERE business_id = ?
      AND created_at >= date('now', '-30 days')
    `).bind(businessId).first()

    return metrics
  }

  /**
   * Get recent trends
   */
  private async getRecentTrends(businessId: string) {
    const trends = await this.env.DB.prepare(`
      SELECT
        DATE(created_at) as date,
        COUNT(*) as invoice_count,
        SUM(total_amount) as daily_revenue
      FROM invoices
      WHERE business_id = ?
      AND created_at >= date('now', '-7 days')
      GROUP BY DATE(created_at)
      ORDER BY date DESC
    `).bind(businessId).all()

    return trends.results
  }

  /**
   * Get recent invoices
   */
  private async getRecentInvoices(businessId: string, limit: number = 5) {
    const invoices = await this.env.DB.prepare(`
      SELECT id, invoice_number, customer_id, total_amount, status, created_at
      FROM invoices
      WHERE business_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(businessId, limit).all()

    return invoices.results
  }

  /**
   * Get recent customers
   */
  private async getRecentCustomers(businessId: string, limit: number = 5) {
    const customers = await this.env.DB.prepare(`
      SELECT id, name, email, total_spent, created_at
      FROM customers
      WHERE business_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(businessId, limit).all()

    return customers.results
  }

  /**
   * Get recent products
   */
  private async getRecentProducts(businessId: string, limit: number = 5) {
    const products = await this.env.DB.prepare(`
      SELECT id, name, sku, price, stock_quantity, created_at
      FROM products
      WHERE business_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(businessId, limit).all()

    return products.results
  }

  /**
   * Update context based on user interaction
   */
  async updateContext(
    userId: string,
    updates: Partial<ChatContext>
  ): Promise<void> {
    try {
      // Store context updates in cache for quick retrieval
      const contextKey = `chat_context:${userId}`

      await this.env.CHAT_CONTEXT_KV.put(
        contextKey,
        JSON.stringify(updates),
        { expirationTtl: 3600 } // 1 hour
      )

      await this.auditLogger.log({
        action: 'chat_context_updated',
        userId,
        details: {
          updates: Object.keys(updates)
        }
      })

    } catch (error) {
    }
  }

  /**
   * Get cached context updates
   */
  async getCachedContext(userId: string): Promise<Partial<ChatContext> | null> {
    try {
      const contextKey = `chat_context:${userId}`
      const cached = await this.env.CHAT_CONTEXT_KV.get(contextKey)

      return cached ? JSON.parse(cached) : null

    } catch (error) {
      return null
    }
  }
}

export default ChatContextService