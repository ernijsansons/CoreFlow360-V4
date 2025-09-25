/**
 * Invoice Approval Workflow System
 * Advanced approval workflow with configurable rules and notifications
 */

import { z } from 'zod'
import { Invoice, InvoiceStatus } from './types'
import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'

export enum ApprovalAction {
  APPROVE = 'approve',
  REJECT = 'reject',
  REQUEST_CHANGES = 'request_changes',
  DELEGATE = 'delegate',
  ESCALATE = 'escalate'
}

export enum ApprovalRuleType {
  AMOUNT_THRESHOLD = 'amount_threshold',
  CUSTOMER_SPECIFIC = 'customer_specific',
  DEPARTMENT_APPROVAL = 'department_approval',
  MULTI_LEVEL = 'multi_level',
  UNANIMOUS_REQUIRED = 'unanimous_required'
}

export enum NotificationMethod {
  EMAIL = 'email',
  SMS = 'sms',
  PUSH = 'push',
  SLACK = 'slack',
  TEAMS = 'teams'
}

export interface ApprovalRule {
  id: string
  name: string
  type: ApprovalRuleType
  isActive: boolean
  priority: number
  conditions: {
    minAmount?: number
    maxAmount?: number
    customerIds?: string[]
    departmentIds?: string[]
    invoiceTypes?: string[]
    currencies?: string[]
  }
  approvers: {
    userId: string
    role: string
    level: number
    isRequired: boolean
    canDelegate: boolean
    autoApprovalLimit?: number
  }[]
  escalationRules: {
    timeoutHours: number
    escalateToUserId: string
    escalateToRole?: string
    notificationMethods: NotificationMethod[]
  }[]
  notifications: {
    method: NotificationMethod
    recipients: string[]
    template: string
    triggerOn: ('created' | 'approved' | 'rejected' | 'escalated')[]
  }[]
  metadata?: Record<string, unknown>
}

export interface ApprovalRequest {
  id: string
  invoiceId: string
  requestedBy: string
  requestedAt: string
  rule: ApprovalRule
  currentLevel: number
  status: 'pending' | 'approved' | 'rejected' | 'escalated' | 'cancelled'
  approvals: ApprovalAction_Entry[]
  dueDate: string
  escalatedAt?: string
  completedAt?: string
  metadata?: Record<string, unknown>
}

export interface ApprovalAction_Entry {
  id: string
  approvalRequestId: string
  userId: string
  action: ApprovalAction
  level: number
  timestamp: string
  comments?: string
  delegatedTo?: string
  escalatedTo?: string
  ipAddress?: string
  userAgent?: string
}

export interface CreateApprovalRuleRequest {
  name: string
  type: ApprovalRuleType
  priority: number
  conditions: ApprovalRule['conditions']
  approvers: ApprovalRule['approvers']
  escalationRules?: ApprovalRule['escalationRules']
  notifications?: ApprovalRule['notifications']
  metadata?: Record<string, unknown>
}

export interface ProcessApprovalRequest {
  approvalRequestId: string
  userId: string
  action: ApprovalAction
  comments?: string
  delegatedTo?: string
  escalatedTo?: string
  ipAddress?: string
  userAgent?: string
}

const ApprovalRuleSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
  type: z.nativeEnum(ApprovalRuleType),
  isActive: z.boolean(),
  priority: z.number().int().min(1),
  conditions: z.object({
    minAmount: z.number().nonnegative().optional(),
    maxAmount: z.number().nonnegative().optional(),
    customerIds: z.array(z.string().uuid()).optional(),
    departmentIds: z.array(z.string().uuid()).optional(),
    invoiceTypes: z.array(z.string()).optional(),
    currencies: z.array(z.string().length(3)).optional()
  }),
  approvers: z.array(z.object({
    userId: z.string().uuid(),
    role: z.string(),
    level: z.number().int().min(1),
    isRequired: z.boolean(),
    canDelegate: z.boolean(),
    autoApprovalLimit: z.number().nonnegative().optional()
  })),
  escalationRules: z.array(z.object({
    timeoutHours: z.number().positive(),
    escalateToUserId: z.string().uuid(),
    escalateToRole: z.string().optional(),
    notificationMethods: z.array(z.nativeEnum(NotificationMethod))
  })),
  notifications: z.array(z.object({
    method: z.nativeEnum(NotificationMethod),
    recipients: z.array(z.string()),
    template: z.string(),
    triggerOn: z.array(z.enum(['created', 'approved', 'rejected', 'escalated']))
  })),
  metadata: z.record(z.unknown()).optional()
})

export // TODO: Consider splitting ApprovalWorkflowService into smaller, focused classes
class ApprovalWorkflowService {
  private approvalRules: Map<string, ApprovalRule> = new Map()
  private approvalRequests: Map<string, ApprovalRequest> = new Map()
  private userRoles: Map<string, string[]> = new Map()

  constructor(
    private readonly db: D1Database,
    private readonly notificationService: any // Would be injected notification service
  ) {
    this.initializeDefaultRules()
  }

  async submitForApproval(invoice: Invoice, requestedBy: string): Promise<ApprovalRequest[]> {
    try {
      auditLogger.log({
        action: 'approval_submission_started',
        invoiceId: invoice.id,
        userId: requestedBy,
        metadata: {
          invoiceAmount: invoice.totalAmount,
          customerId: invoice.customerId,
          currency: invoice.currency
        }
      })

      // Find applicable approval rules
      const applicableRules = await this.findApplicableRules(invoice)

      if (applicableRules.length === 0) {
        // No approval required, auto-approve
        await this.autoApproveInvoice(invoice, requestedBy)
        return []
      }

      // Create approval requests for each applicable rule
      const approvalRequests: ApprovalRequest[] = []

      for (const rule of applicableRules) {
        const approvalRequest = await this.createApprovalRequest(
          invoice,
          rule,
          requestedBy
        )
        approvalRequests.push(approvalRequest)

        // Send notifications
        await this.sendApprovalNotifications(approvalRequest, 'created')
      }

      // Update invoice status
      await this.updateInvoiceStatus(invoice.id, InvoiceStatus.PENDING_APPROVAL)

      auditLogger.log({
        action: 'approval_submission_completed',
        invoiceId: invoice.id,
        userId: requestedBy,
        metadata: {
          approvalRequestCount: approvalRequests.length,
          ruleIds: applicableRules.map(r => r.id)
        }
      })

      return approvalRequests

    } catch (error) {
      auditLogger.log({
        action: 'approval_submission_failed',
        invoiceId: invoice.id,
        userId: requestedBy,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Failed to submit invoice for approval',
        'APPROVAL_SUBMISSION_ERROR',
        500,
        { invoiceId: invoice.id, originalError: error }
      )
    }
  }

  async processApprovalAction(request: ProcessApprovalRequest): Promise<ApprovalRequest> {
    try {
      auditLogger.log({
        action: 'approval_action_started',
        approvalRequestId: request.approvalRequestId,
        userId: request.userId,
        action: request.action
      })

      const approvalRequest = this.approvalRequests.get(request.approvalRequestId)
      if (!approvalRequest) {
        throw new AppError(
          'Approval request not found',
          'APPROVAL_REQUEST_NOT_FOUND',
          404
        )
      }

      // Validate user can perform this action
      await this.validateApprovalAction(approvalRequest, request)

      // Create approval action entry
      const actionEntry: ApprovalAction_Entry = {
        id: this.generateActionId(),
        approvalRequestId: request.approvalRequestId,
        userId: request.userId,
        action: request.action,
        level: await this.getUserApprovalLevel(approvalRequest, request.userId),
        timestamp: new Date().toISOString(),
        comments: request.comments,
        delegatedTo: request.delegatedTo,
        escalatedTo: request.escalatedTo,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent
      }

      approvalRequest.approvals.push(actionEntry)

      // Process the action
      switch (request.action) {
        case ApprovalAction.APPROVE:
          await this.processApprovalAction_Approve(approvalRequest, actionEntry)
          break
        case ApprovalAction.REJECT:
          await this.processApprovalAction_Reject(approvalRequest, actionEntry)
          break
        case ApprovalAction.REQUEST_CHANGES:
          await this.processApprovalAction_RequestChanges(approvalRequest, actionEntry)
          break
        case ApprovalAction.DELEGATE:
          await this.processApprovalAction_Delegate(approvalRequest, actionEntry)
          break
        case ApprovalAction.ESCALATE:
          await this.processApprovalAction_Escalate(approvalRequest, actionEntry)
          break
      }

      // Update approval request
      this.approvalRequests.set(request.approvalRequestId, approvalRequest)

      auditLogger.log({
        action: 'approval_action_completed',
        approvalRequestId: request.approvalRequestId,
        userId: request.userId,
        action: request.action,
        newStatus: approvalRequest.status
      })

      return approvalRequest

    } catch (error) {
      auditLogger.log({
        action: 'approval_action_failed',
        approvalRequestId: request.approvalRequestId,
        userId: request.userId,
        action: request.action,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Failed to process approval action',
        'APPROVAL_ACTION_ERROR',
        500,
        { approvalRequestId: request.approvalRequestId, originalError: error }
      )
    }
  }

  private async findApplicableRules(invoice: Invoice): Promise<ApprovalRule[]> {
    const applicableRules: ApprovalRule[] = []

    for (const [_, rule] of this.approvalRules) {
      if (!rule.isActive) continue

      const isApplicable = this.evaluateRuleConditions(rule, invoice)
      if (isApplicable) {
        applicableRules.push(rule)
      }
    }

    // Sort by priority (higher priority first)
    return applicableRules.sort((a, b) => b.priority - a.priority)
  }

  private evaluateRuleConditions(rule: ApprovalRule, invoice: Invoice): boolean {
    const { conditions } = rule

    // Check amount thresholds
    if (conditions.minAmount !== undefined && invoice.totalAmount < conditions.minAmount) {
      return false
    }
    if (conditions.maxAmount !== undefined && invoice.totalAmount > conditions.maxAmount) {
      return false
    }

    // Check customer IDs
    if (conditions.customerIds && !conditions.customerIds.includes(invoice.customerId)) {
      return false
    }

    // Check invoice types
    if (conditions.invoiceTypes && !conditions.invoiceTypes.includes(invoice.type)) {
      return false
    }

    // Check currencies
    if (conditions.currencies && !conditions.currencies.includes(invoice.currency)) {
      return false
    }

    // Check department IDs (would need to get from invoice or user context)
    // if (conditions.departmentIds && !this.isInvoiceFromDepartment(invoice, conditions.departmentIds)) {
    //   return false
    // }

    return true
  }

  private async createApprovalRequest(
    invoice: Invoice,
    rule: ApprovalRule,
    requestedBy: string
  ): Promise<ApprovalRequest> {
    const approvalRequest: ApprovalRequest = {
      id: this.generateApprovalRequestId(),
      invoiceId: invoice.id,
      requestedBy,
      requestedAt: new Date().toISOString(),
      rule,
      currentLevel: 1,
      status: 'pending',
      approvals: [],
      dueDate: this.calculateDueDate(rule),
      metadata: {
        invoiceNumber: invoice.invoiceNumber,
        invoiceAmount: invoice.totalAmount,
        currency: invoice.currency
      }
    }

    this.approvalRequests.set(approvalRequest.id, approvalRequest)
    return approvalRequest
  }

  private calculateDueDate(rule: ApprovalRule): string {
    // Default to 24 hours if no escalation rules
    const timeoutHours = rule.escalationRules[0]?.timeoutHours || 24
    const dueDate = new Date()
    dueDate.setHours(dueDate.getHours() + timeoutHours)
    return dueDate.toISOString()
  }

  private async validateApprovalAction(
    approvalRequest: ApprovalRequest,
    request: ProcessApprovalRequest
  ): Promise<void> {
    // Check if request is still pending
    if (approvalRequest.status !== 'pending') {
      throw new AppError(
        'Approval request is no longer pending',
        'APPROVAL_REQUEST_NOT_PENDING',
        400
      )
    }

    // Check if user is authorized to approve at current level
    const userLevel = await this.getUserApprovalLevel(approvalRequest, request.userId)
    if (userLevel === 0) {
      throw new AppError(
        'User not authorized to approve this request',
        'APPROVAL_NOT_AUTHORIZED',
        403
      )
    }

    // Check if user has already acted on this request
    const existingAction = approvalRequest.approvals.find(a => a.userId === request.userId)
    if (existingAction) {
      throw new AppError(
        'User has already acted on this approval request',
        'APPROVAL_ALREADY_ACTED',
        400
      )
    }

    // Validate delegation
    if (request.action === ApprovalAction.DELEGATE) {
      if (!request.delegatedTo) {
        throw new AppError(
          'Delegated user must be specified',
          'DELEGATION_USER_REQUIRED',
          400
        )
      }

      const approver = approvalRequest.rule.approvers.find(a => a.userId === request.userId)
      if (!approver?.canDelegate) {
        throw new AppError(
          'User not authorized to delegate',
          'DELEGATION_NOT_AUTHORIZED',
          403
        )
      }
    }

    // Validate escalation
    if (request.action === ApprovalAction.ESCALATE) {
      if (!request.escalatedTo) {
        throw new AppError(
          'Escalation target must be specified',
          'ESCALATION_TARGET_REQUIRED',
          400
        )
      }
    }
  }

  private async getUserApprovalLevel(
    approvalRequest: ApprovalRequest,
    userId: string
  ): Promise<number> {
    const approver = approvalRequest.rule.approvers.find(a => a.userId === userId)
    if (approver) {
      return approver.level
    }

    // Check if user has role-based approval rights
    const userRoles = this.userRoles.get(userId) || []
    for (const approver of approvalRequest.rule.approvers) {
      if (userRoles.includes(approver.role)) {
        return approver.level
      }
    }

    return 0 // No approval rights
  }

  private async processApprovalAction_Approve(
    approvalRequest: ApprovalRequest,
    actionEntry: ApprovalAction_Entry
  ): Promise<void> {
    const approver = approvalRequest.rule.approvers.find(a => a.userId === actionEntry.userId)

    // Check if this approval completes the requirement
    if (await this.isApprovalComplete(approvalRequest)) {
      approvalRequest.status = 'approved'
      approvalRequest.completedAt = new Date().toISOString()

      // Update invoice status
      await this.updateInvoiceStatus(approvalRequest.invoiceId, InvoiceStatus.APPROVED)

      // Send approval notifications
      await this.sendApprovalNotifications(approvalRequest, 'approved')
    } else {
      // Move to next level if required
      const nextLevel = Math.max(...approvalRequest.rule.approvers.map(a => a.level))
      if (actionEntry.level < nextLevel) {
        approvalRequest.currentLevel = actionEntry.level + 1
      }
    }
  }

  private async processApprovalAction_Reject(
    approvalRequest: ApprovalRequest,
    actionEntry: ApprovalAction_Entry
  ): Promise<void> {
    approvalRequest.status = 'rejected'
    approvalRequest.completedAt = new Date().toISOString()

    // Update invoice status
    await this.updateInvoiceStatus(approvalRequest.invoiceId, InvoiceStatus.DRAFT)

    // Send rejection notifications
    await this.sendApprovalNotifications(approvalRequest, 'rejected')
  }

  private async processApprovalAction_RequestChanges(
    approvalRequest: ApprovalRequest,
    actionEntry: ApprovalAction_Entry
  ): Promise<void> {
    // Return to draft status for changes
    await this.updateInvoiceStatus(approvalRequest.invoiceId, InvoiceStatus.DRAFT)

    // Cancel approval request
    approvalRequest.status = 'cancelled'
    approvalRequest.completedAt = new Date().toISOString()
  }

  private async processApprovalAction_Delegate(
    approvalRequest: ApprovalRequest,
    actionEntry: ApprovalAction_Entry
  ): Promise<void> {
    // Add delegated user as approver
    const originalApprover = approvalRequest.rule.approvers.find(a => a.userId === actionEntry.userId)
    if (originalApprover && actionEntry.delegatedTo) {
      approvalRequest.rule.approvers.push({
        ...originalApprover,
        userId: actionEntry.delegatedTo
      })
    }
  }

  private async processApprovalAction_Escalate(
    approvalRequest: ApprovalRequest,
    actionEntry: ApprovalAction_Entry
  ): Promise<void> {
    approvalRequest.status = 'escalated'
    approvalRequest.escalatedAt = new Date().toISOString()

    // Add escalated user as approver
    if (actionEntry.escalatedTo) {
      const escalationRule = approvalRequest.rule.escalationRules[0]
      approvalRequest.rule.approvers.push({
        userId: actionEntry.escalatedTo,
        role: escalationRule?.escalateToRole || 'manager',
        level: Math.max(...approvalRequest.rule.approvers.map(a => a.level)) + 1,
        isRequired: true,
        canDelegate: true
      })
    }

    // Send escalation notifications
    await this.sendApprovalNotifications(approvalRequest, 'escalated')
  }

  private async isApprovalComplete(approvalRequest: ApprovalRequest): Promise<boolean> {
    const requiredApprovers = approvalRequest.rule.approvers.filter(a => a.isRequired)
    const approvedActions = approvalRequest.approvals.filter(a => a.action === ApprovalAction.APPROVE)

    // Check if all required approvers have approved
    for (const required of requiredApprovers) {
      const hasApproval = approvedActions.some(a => a.userId === required.userId)
      if (!hasApproval) {
        return false
      }
    }

    return true
  }

  private async sendApprovalNotifications(
    approvalRequest: ApprovalRequest,
    trigger: 'created' | 'approved' | 'rejected' | 'escalated'
  ): Promise<void> {
    const notifications = approvalRequest.rule.notifications.filter(n =>
      n.triggerOn.includes(trigger)
    )

    for (const notification of notifications) {
      try {
        await this.notificationService.send({
          method: notification.method,
          recipients: notification.recipients,
          template: notification.template,
          data: {
            approvalRequest,
            trigger,
            invoiceId: approvalRequest.invoiceId
          }
        })
      } catch (error) {
        auditLogger.log({
          action: 'notification_failed',
          approvalRequestId: approvalRequest.id,
          method: notification.method,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
      }
    }
  }

  private async autoApproveInvoice(invoice: Invoice, userId: string): Promise<void> {
    await this.updateInvoiceStatus(invoice.id, InvoiceStatus.APPROVED)

    auditLogger.log({
      action: 'invoice_auto_approved',
      invoiceId: invoice.id,
      userId,
      metadata: { reason: 'no_approval_rules_applicable' }
    })
  }

  private async updateInvoiceStatus(invoiceId: string, status: InvoiceStatus): Promise<void> {
    // This would update the invoice in the database
    // For now, just log the action
    auditLogger.log({
      action: 'invoice_status_updated',
      invoiceId,
      newStatus: status
    })
  }

  private generateApprovalRequestId(): string {
    return `approval_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateActionId(): string {
    return `action_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private initializeDefaultRules(): void {
    // Create default approval rules
    const defaultRules: ApprovalRule[] = [
      {
        id: 'high-value-invoices',
        name: 'High Value Invoice Approval',
        type: ApprovalRuleType.AMOUNT_THRESHOLD,
        isActive: true,
        priority: 1,
        conditions: {
          minAmount: 10000
        },
        approvers: [
          {
            userId: 'manager-001',
            role: 'finance_manager',
            level: 1,
            isRequired: true,
            canDelegate: true,
            autoApprovalLimit: 25000
          },
          {
            userId: 'director-001',
            role: 'finance_director',
            level: 2,
            isRequired: true,
            canDelegate: false
          }
        ],
        escalationRules: [
          {
            timeoutHours: 24,
            escalateToUserId: 'director-001',
            escalateToRole: 'finance_director',
            notificationMethods: [NotificationMethod.EMAIL, NotificationMethod.SLACK]
          }
        ],
        notifications: [
          {
            method: NotificationMethod.EMAIL,
            recipients: ['manager-001', 'director-001'],
            template: 'high_value_approval_request',
            triggerOn: ['created']
          },
          {
            method: NotificationMethod.SLACK,
            recipients: ['#finance-approvals'],
            template: 'approval_status_update',
            triggerOn: ['approved', 'rejected']
          }
        ]
      }
    ]

    for (const rule of defaultRules) {
      this.approvalRules.set(rule.id, rule)
    }

    // Initialize user roles
    this.userRoles.set('manager-001', ['finance_manager'])
    this.userRoles.set('director-001', ['finance_director'])
  }

  // Public API methods
  async createApprovalRule(request: CreateApprovalRuleRequest): Promise<ApprovalRule> {
    const rule: ApprovalRule = {
      id: this.generateApprovalRequestId(),
      isActive: true,
      escalationRules: [],
      notifications: [],
      ...request
    }

    // Validate rule
    ApprovalRuleSchema.parse(rule)

    this.approvalRules.set(rule.id, rule)

    auditLogger.log({
      action: 'approval_rule_created',
      ruleId: rule.id,
      name: rule.name,
      type: rule.type
    })

    return rule
  }

  async getApprovalRequests(filters?: {
    invoiceId?: string
    userId?: string
    status?: string
  }): Promise<ApprovalRequest[]> {
    let requests = Array.from(this.approvalRequests.values())

    if (filters) {
      if (filters.invoiceId) {
        requests = requests.filter(r => r.invoiceId === filters.invoiceId)
      }
      if (filters.userId) {
        requests = requests.filter(r =>
          r.requestedBy === filters.userId ||
          r.approvals.some(a => a.userId === filters.userId) ||
          r.rule.approvers.some(a => a.userId === filters.userId)
        )
      }
      if (filters.status) {
        requests = requests.filter(r => r.status === filters.status)
      }
    }

    return requests
  }
}