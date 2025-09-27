/**
 * Smart Suggestions Service
 * AI-powered proactive suggestions and recommendations
 */

import { z } from 'zod'
import type { Env } from '@/types/env'
import type { SmartSuggestion } from '@/types/chat'
import { AppError } from '@/shared/errors/app-error'
import { AuditLogger } from '@/shared/services/audit-logger'

const SuggestionContextSchema = z.object({
  userId: z.string(),
  businessId: z.string(),
  currentPage: z.string().optional(),
  recentActivity: z.array(z.object({
    action: z.string(),
    entity: z.string(),
    timestamp: z.string()
  })).optional(),
  businessMetrics: z.record(z.any()).optional(),
  timeContext: z.object({
    timeOfDay: z.string(),
    dayOfWeek: z.string(),
    isBusinessHours: z.boolean()
  }).optional()
})

export type SuggestionContext = z.infer<typeof SuggestionContextSchema>

interface BusinessInsight {
  type: 'revenue' | 'growth' | 'efficiency' | 'risk' | 'opportunity'
  metric: string
  value: number
  change: number
  significance: 'high' | 'medium' | 'low'
  timeframe: string
}

export // TODO: Consider splitting SuggestionsService into smaller, focused classes
class SuggestionsService {
  constructor(
    private env: Env,
    private auditLogger: AuditLogger
  ) {}

  /**
   * Generate smart suggestions based on context
   */
  async generateSuggestions(context: SuggestionContext): Promise<SmartSuggestion[]> {
    try {
      const validatedContext = SuggestionContextSchema.parse(context)

      await this.auditLogger.log({
        action: 'suggestions_generation_started',
        userId: context.userId,
        details: {
          businessId: context.businessId,
          currentPage: context.currentPage
        }
      })

      // Gather business data for analysis
      const businessData = await this.gatherBusinessData(context.businessId)

      // Generate different types of suggestions
      const suggestions: SmartSuggestion[] = []

      // Insights from business metrics
      const insightSuggestions = await this.generateInsightSuggestions(businessData, context)
      suggestions.push(...insightSuggestions)

      // Action recommendations
      const actionSuggestions = await this.generateActionSuggestions(businessData, context)
      suggestions.push(...actionSuggestions)

      // Optimization opportunities
      const optimizationSuggestions = await this.generateOptimizationSuggestions(businessData, context)
      suggestions.push(...optimizationSuggestions)

      // Alerts and warnings
      const alertSuggestions = await this.generateAlertSuggestions(businessData, context)
      suggestions.push(...alertSuggestions)

      // Business opportunities
      const opportunitySuggestions = await this.generateOpportunitySuggestions(businessData, context)
      suggestions.push(...opportunitySuggestions)

      // Time-based reminders
      const reminderSuggestions = await this.generateReminderSuggestions(businessData, context)
      suggestions.push(...reminderSuggestions)

      // AI-enhanced suggestions
      const aiSuggestions = await this.generateAISuggestions(suggestions, businessData, context)
      suggestions.push(...aiSuggestions)

      // Filter and rank suggestions
      const rankedSuggestions = this.rankSuggestions(suggestions, context)

      await this.auditLogger.log({
        action: 'suggestions_generated',
        userId: context.userId,
        details: {
          businessId: context.businessId,
          suggestionsCount: rankedSuggestions.length,
          types: rankedSuggestions.map((s: any) => s.type)
        }
      })

      return rankedSuggestions

    } catch (error: any) {
      await this.auditLogger.log({
        action: 'suggestions_generation_failed',
        userId: context.userId,
        details: {
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      })

      throw new AppError(
        'Failed to generate suggestions',
        'SUGGESTIONS_ERROR',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Gather business data for analysis
   */
  private async gatherBusinessData(businessId: string): Promise<any> {
    const now = new Date()
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)

    // Revenue metrics
    const revenueData = await this.env.DB.prepare(`
      SELECT
        SUM(CASE WHEN created_at >= ? THEN total_amount ELSE 0 END) as revenue_7d,
        SUM(CASE WHEN created_at >= ? THEN total_amount ELSE 0 END) as revenue_30d,
        COUNT(CASE WHEN created_at >= ? THEN 1 ELSE NULL END) as invoices_7d,
        COUNT(CASE WHEN created_at >= ? THEN 1 ELSE NULL END) as invoices_30d,
        AVG(CASE WHEN created_at >= ? THEN total_amount ELSE NULL END) as avg_invoice_7d
      FROM invoices
      WHERE business_id = ? AND status = 'paid'
    `).bind(
      sevenDaysAgo.toISOString(),
      thirtyDaysAgo.toISOString(),
      sevenDaysAgo.toISOString(),
      thirtyDaysAgo.toISOString(),
      sevenDaysAgo.toISOString(),
      businessId
    ).first()

    // Customer metrics
    const customerData = await this.env.DB.prepare(`
      SELECT
        COUNT(CASE WHEN created_at >= ? THEN 1 ELSE NULL END) as new_customers_7d,
        COUNT(CASE WHEN created_at >= ? THEN 1 ELSE NULL END) as new_customers_30d,
        COUNT(*) as total_customers
      FROM customers
      WHERE business_id = ?
    `).bind(
      sevenDaysAgo.toISOString(),
      thirtyDaysAgo.toISOString(),
      businessId
    ).first()

    // Inventory alerts
    const inventoryData = await this.env.DB.prepare(`
      SELECT
        COUNT(CASE WHEN stock_quantity <= reorder_point THEN 1 ELSE NULL END) as low_stock_items,
        COUNT(CASE WHEN stock_quantity = 0 THEN 1 ELSE NULL END) as out_of_stock_items,
        AVG(stock_quantity) as avg_stock_level
      FROM products
      WHERE business_id = ?
    `).bind(businessId).first()

    // Overdue invoices
    const overdueData = await this.env.DB.prepare(`
      SELECT
        COUNT(*) as overdue_count,
        SUM(total_amount) as overdue_amount
      FROM invoices
      WHERE business_id = ? AND status = 'sent' AND due_date < ?
    `).bind(businessId, now.toISOString()).first()

    return {
      revenue: revenueData,
      customers: customerData,
      inventory: inventoryData,
      overdue: overdueData,
      timeframe: {
        current: now,
        sevenDaysAgo,
        thirtyDaysAgo
      }
    }
  }

  /**
   * Generate insight suggestions
   */
  private async generateInsightSuggestions(
    businessData: any,
    context: SuggestionContext
  ): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = []

    // Revenue trend insights
    if (businessData.revenue?.revenue_7d && businessData.revenue?.revenue_30d) {
      const weeklyAvg = businessData.revenue.revenue_7d
      const monthlyAvg = businessData.revenue.revenue_30d / 4.3 // Convert to weekly

      const growth = ((weeklyAvg - monthlyAvg) / monthlyAvg) * 100

      if (Math.abs(growth) > 10) {
        suggestions.push({
          id: crypto.randomUUID(),
          type: 'insight',
          title: growth > 0 ? 'Revenue Growth Detected' : 'Revenue Decline Detected',
          description: `Your weekly revenue
  has ${growth > 0 ? 'increased' : 'decreased'} by ${Math.abs(growth).toFixed(1)}% compared to the monthly average.`,
          priority: Math.abs(growth) > 25 ? 'high' : 'medium',
          confidence: 0.85,
          metrics: [
            { label: 'Weekly Revenue', value: `$${weeklyAvg.toLocaleString()}` },
            { label: 'Growth`', value: `${growth > 0 ? '' : '`'}${growth.toFixed(1)}%` }
          ],
          actions: [
            { label: 'View Revenue Report', command: '/revenue-report' },
            { label: 'Analyze Trends', command: 'Show me detailed revenue analysis' }
          ],
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        })
      }
    }

    // Customer acquisition insights
    if (businessData.customers?.new_customers_7d > 0) {
      const acquisitionRate = businessData.customers.new_customers_7d

      suggestions.push({
        id: crypto.randomUUID(),
        type: 'insight',
        title: 'New Customer Acquisition',
        description: `You've acquired ${acquisitionRate} new customers this week.`,
        priority: 'medium',
        confidence: 0.9,
        metrics: [
          { label: 'New Customers', value: acquisitionRate.toString() },
          { label: 'Total Customers', value: businessData.customers.total_customers.toString() }
        ],
        actions: [
          { label: 'View Customer Report', command: '/customer-report' },
          { label: 'Customer Analysis', command: 'Analyze my customer acquisition trends' }
        ],
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
      })
    }

    return suggestions
  }

  /**
   * Generate action suggestions
   */
  private async generateActionSuggestions(
    businessData: any,
    context: SuggestionContext
  ): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = []

    // Follow up on overdue invoices
    if (businessData.overdue?.overdue_count > 0) {
      suggestions.push({
        id: crypto.randomUUID(),
        type: 'action',
        title: 'Follow Up on Overdue Invoices',
       
  description: `You have ${businessData.overdue.overdue_count} overdue invoices totaling $${businessData.overdue.overdue_amount.toLocaleString()}.`,
        priority: 'high',
        confidence: 0.95,
        impact: 'high',
        metrics: [
          { label: 'Overdue Invoices', value: businessData.overdue.overdue_count.toString() },
          { label: 'Amount', value: `$${businessData.overdue.overdue_amount.toLocaleString()}` }
        ],
        actions: [
          { label: 'Send Reminders', command: '/send-invoice-reminders' },
          { label: 'View Overdue', command: '/search-invoices status:overdue' }
        ],
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
      })
    }

    // Restock low inventory
    if (businessData.inventory?.low_stock_items > 0) {
      suggestions.push({
        id: crypto.randomUUID(),
        type: 'action',
        title: 'Restock Low Inventory Items',
        description: `${businessData.inventory.low_stock_items} products are running low on stock.`,
        priority: businessData.inventory.out_of_stock_items > 0 ? 'high' : 'medium',
        confidence: 0.9,
        impact: 'medium',
        metrics: [
          { label: 'Low Stock', value: businessData.inventory.low_stock_items.toString() },
          { label: 'Out of Stock', value: businessData.inventory.out_of_stock_items?.toString() || '0' }
        ],
        actions: [
          { label: 'View Inventory', command: '/inventory-report' },
          { label: 'Create Purchase Orders', command: 'Help me create purchase orders for low stock items' }
        ],
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
      })
    }

    return suggestions
  }

  /**
   * Generate optimization suggestions
   */
  private async generateOptimizationSuggestions(
    businessData: any,
    context: SuggestionContext
  ): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = []

    // Invoice automation
    if (businessData.revenue?.invoices_7d > 10) {
      suggestions.push({
        id: crypto.randomUUID(),
        type: 'optimization',
        title: 'Automate Invoice Workflows',
        description: 'With your high invoice volume, automation could save significant time.',
        priority: 'medium',
        confidence: 0.8,
        impact: 'high',
        metrics: [
          { label: 'Weekly Invoices', value: businessData.revenue.invoices_7d.toString() },
          { label: 'Potential Time Saved', value: '4-6 hours/week' }
        ],
        actions: [
          { label: 'Setup Automation', command: 'Help me set up invoice automation' },
          { label: 'Learn More', command: 'Tell me about invoice automation options' }
        ],
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
      })
    }

    return suggestions
  }

  /**
   * Generate alert suggestions
   */
  private async generateAlertSuggestions(
    businessData: any,
    context: SuggestionContext
  ): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = []

    // Cash flow alert
    if (businessData.overdue?.overdue_amount > businessData.revenue?.revenue_7d * 0.5) {
      suggestions.push({
        id: crypto.randomUUID(),
        type: 'alert',
        title: 'Cash Flow Alert',
        description: 'Overdue invoices represent a significant portion of your recent revenue.',
        priority: 'high',
        confidence: 0.9,
        impact: 'high',
        metrics: [
          { label: 'Overdue Amount', value: `$${businessData.overdue.overdue_amount.toLocaleString()}` },
          { label: 'Weekly Revenue', value: `$${businessData.revenue.revenue_7d.toLocaleString()}` }
        ],
        actions: [
          { label: 'Cash Flow Analysis', command: 'Analyze my cash flow situation' },
          { label: 'Collection Strategy', command: 'Help me create a collection strategy' }
        ],
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
      })
    }

    return suggestions
  }

  /**
   * Generate opportunity suggestions
   */
  private async generateOpportunitySuggestions(
    businessData: any,
    context: SuggestionContext
  ): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = []

    // Upselling opportunity
    if (businessData.revenue?.avg_invoice_7d && businessData.customers?.new_customers_7d > 0) {
      suggestions.push({
        id: crypto.randomUUID(),
        type: 'opportunity',
        title: 'Upselling Opportunity',
        description: 'Recent customers could be targets for upselling based on average invoice values.',
        priority: 'medium',
        confidence: 0.7,
        impact: 'medium',
        metrics: [
          { label: 'Avg Invoice', value: `$${businessData.revenue.avg_invoice_7d.toLocaleString()}` },
          { label: 'New Customers', value: businessData.customers.new_customers_7d.toString() }
        ],
        actions: [
          { label: 'Identify Prospects', command: 'Show me customers with upselling potential' },
          { label: 'Create Campaign', command: 'Help me create an upselling campaign' }
        ],
        expiresAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString()
      })
    }

    return suggestions
  }

  /**
   * Generate reminder suggestions
   */
  private async generateReminderSuggestions(
    businessData: any,
    context: SuggestionContext
  ): Promise<SmartSuggestion[]> {
    const suggestions: SmartSuggestion[] = []

    // Monthly reporting reminder
    const now = new Date()
    const dayOfMonth = now.getDate()

    if (dayOfMonth <= 5) { // First 5 days of month
      suggestions.push({
        id: crypto.randomUUID(),
        type: 'reminder',
        title: 'Monthly Report Due',
        description: 'Time to generate your monthly business reports.',
        priority: 'medium',
        confidence: 0.9,
        actions: [
          { label: 'Generate Reports', command: '/monthly-reports' },
          { label: 'Schedule Reports', command: 'Help me schedule automatic monthly reports' }
        ],
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
      })
    }

    return suggestions
  }

  /**
   * Generate AI-enhanced suggestions
   */
  private async generateAISuggestions(
    existingSuggestions: SmartSuggestion[],
    businessData: any,
    context: SuggestionContext
  ): Promise<SmartSuggestion[]> {
    // This would integrate with Cloudflare Workers AI for advanced insights
    // For now, return enhanced suggestions based on patterns

    const suggestions: SmartSuggestion[] = []

    // Predictive insights
    if (businessData.revenue?.revenue_7d && businessData.revenue?.revenue_30d) {
      const trend = businessData.revenue.revenue_7d / (businessData.revenue.revenue_30d / 4.3)

      if (trend > 1.2) {
        suggestions.push({
          id: crypto.randomUUID(),
          type: 'insight',
          title: 'Growth Trajectory Prediction',
          description: 'Based on current trends, you could see 20-30% monthly growth.',
          priority: 'medium',
          confidence: 0.75,
          actions: [
            { label: 'Forecast Analysis', command: 'Show me detailed growth forecasts' },
            { label: 'Capacity Planning', command: 'Help me plan for growth' }
          ],
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
        })
      }
    }

    return suggestions
  }

  /**
   * Rank suggestions by relevance and importance
   */
  private rankSuggestions(
    suggestions: SmartSuggestion[],
    context: SuggestionContext
  ): SmartSuggestion[] {
    return suggestions
      .filter((s: any) => {
        // Filter out expired suggestions
        if (s.expiresAt && new Date(s.expiresAt) < new Date()) {
          return false
        }
        return true
      })
      .sort((a, b) => {
        // Priority scoring
        const priorityScore = { high: 3, medium: 2, low: 1 }
        const aScore = priorityScore[a.priority || 'low']
        const bScore = priorityScore[b.priority || 'low']

        if (aScore !== bScore) {
          return bScore - aScore
        }

        // Confidence scoring
        return (b.confidence || 0) - (a.confidence || 0)
      })
      .slice(0, 10) // Limit to top 10 suggestions
  }

  /**
   * Dismiss a suggestion
   */
  async dismissSuggestion(
    suggestionId: string,
    userId: string,
    reason?: string
  ): Promise<void> {
    try {
      // Store dismissal in database for learning
      await this.env.DB.prepare(`
        INSERT INTO dismissed_suggestions (
          suggestion_id, user_id, reason, dismissed_at
        ) VALUES (?, ?, ?, ?)
      `).bind(
        suggestionId,
        userId,
        reason || null,
        new Date().toISOString()
      ).run()

      await this.auditLogger.log({
        action: 'suggestion_dismissed',
        userId,
        details: {
          suggestionId,
          reason
        }
      })

    } catch (error: any) {
    }
  }
}

export default SuggestionsService