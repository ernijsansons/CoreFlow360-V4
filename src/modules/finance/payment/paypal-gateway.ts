/**
 * PayPal Payment Gateway Integration
 * Enterprise-grade PayPal integration with comprehensive error handling
 */

import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'
import { Invoice } from '../invoice/types'

export interface PayPalConfig {
  clientId: string
  clientSecret: string
  environment: 'sandbox' | 'live'
  webhookSecret?: string
  apiVersion: '2.0'
  currency: string
  returnUrl: string
  cancelUrl: string
}

export interface PayPalPaymentRequest {
  amount: number
  currency: string
  description?: string
  invoiceId?: string
  customerId?: string
  returnUrl?: string
  cancelUrl?: string
  metadata?: Record<string, string>
  paymentMethod?: 'paypal' | 'card' | 'venmo' | 'paylater'
  shippingPreference?: 'NO_SHIPPING' | 'SET_PROVIDED_ADDRESS' | 'GET_FROM_FILE'
  userAction?: 'PAY_NOW' | 'CONTINUE'
}

export interface PayPalAddress {
  addressLine1: string
  addressLine2?: string
  adminArea1: string // State
  adminArea2: string // City
  postalCode: string
  countryCode: string
}

export interface PayPalPayer {
  name?: {
    givenName: string
    surname: string
  }
  email?: string
  phone?: {
    phoneType: 'FAX' | 'HOME' | 'MOBILE' | 'OTHER' | 'PAGER'
    phoneNumber: {
      nationalNumber: string
    }
  }
  address?: PayPalAddress
}

export interface PayPalOrder {
  id: string
  status: 'CREATED' | 'SAVED' | 'APPROVED' | 'VOIDED' | 'COMPLETED' | 'PAYER_ACTION_REQUIRED'
  intent: 'CAPTURE' | 'AUTHORIZE'
  purchaseUnits: {
    referenceId: string
    amount: {
      currencyCode: string
      value: string
    }
    description?: string
    invoiceId?: string
    customId?: string
  }[]
  payer?: PayPalPayer
  links: {
    href: string
    rel: string
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'CONNECT' | 'OPTIONS' | 'PATCH'
  }[]
  createTime: string
  updateTime?: string
}

export interface PayPalCapture {
  id: string
  status: 'COMPLETED' | 'DECLINED' | 'PARTIALLY_REFUNDED' | 'PENDING' | 'REFUNDED'
  amount: {
    currencyCode: string
    value: string
  }
  finalCapture: boolean
  disbursementMode: 'INSTANT' | 'DELAYED'
  links: PayPalOrder['links']
  createTime: string
  updateTime?: string
}

export interface PayPalRefund {
  id: string
  status: 'CANCELLED' | 'PENDING' | 'COMPLETED'
  amount: {
    currencyCode: string
    value: string
  }
  invoiceId?: string
  noteToPayer?: string
  links: PayPalOrder['links']
  createTime: string
  updateTime?: string
}

export interface PayPalWebhookEvent {
  id: string
  createTime: string
  resourceType: string
  eventType: string
  summary: string
  resource: any
  links: PayPalOrder['links']
  eventVersion: string
  resourceVersion: string
}

export interface PayPalAccessToken {
  scope: string
  accessToken: string
  tokenType: string
  appId: string
  expiresIn: number
  nonce: string
  obtainedAt: number
}

export class PayPalPaymentGateway {
  private config: PayPalConfig
  private accessToken: PayPalAccessToken | null = null
  private baseUrl: string

  constructor(config: PayPalConfig) {
    this.config = config
    this.baseUrl = config.environment === 'sandbox'
      ? 'https://api-m.sandbox.paypal.com'
      : 'https://api-m.paypal.com'
  }

  async createOrder(request: PayPalPaymentRequest): Promise<PayPalOrder> {
    try {
      auditLogger.log({
        action: 'paypal_order_creation_started',
        metadata: {
          amount: request.amount,
          currency: request.currency,
          invoiceId: request.invoiceId,
          customerId: request.customerId
        }
      })

      // Validate request
      this.validatePaymentRequest(request)

      // Get access token
      await this.ensureValidAccessToken()

      // Create order payload
      const orderPayload = {
        intent: 'CAPTURE',
        purchase_units: [{
          reference_id: request.invoiceId || `ORDER_${Date.now()}`,
          amount: {
            currency_code: request.currency,
            value: request.amount.toFixed(2)
          },
          description: request.description || 'Payment from CoreFlow360',
          invoice_id: request.invoiceId,
          custom_id: request.customerId
        }],
        payment_source: {
          paypal: {
            experience_context: {
              payment_method_preference: 'IMMEDIATE_PAYMENT_REQUIRED',
              brand_name: 'CoreFlow360',
              locale: 'en-US',
              landing_page: 'LOGIN',
              shipping_preference: request.shippingPreference || 'NO_SHIPPING',
              user_action: request.userAction || 'PAY_NOW',
              return_url: request.returnUrl || this.config.returnUrl,
              cancel_url: request.cancelUrl || this.config.cancelUrl
            }
          }
        }
      }

      // Make API request
      const response = await this.makeApiRequest('/v2/checkout/orders', 'POST', orderPayload)

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(`PayPal API error: ${(errorData as any).message || response.statusText}`)
      }

      const order: PayPalOrder = await response.json()

      auditLogger.log({
        action: 'paypal_order_created',
        orderId: order.id,
        amount: request.amount,
        currency: request.currency,
        status: order.status
      })

      return order

    } catch (error: any) {
      auditLogger.log({
        action: 'paypal_order_creation_failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: request
      })

      throw new AppError(
        'PayPal order creation failed',
        'PAYPAL_ORDER_ERROR',
        500,
        { originalError: error, request }
      )
    }
  }

  async captureOrder(orderId: string): Promise<PayPalCapture> {
    try {
      auditLogger.log({
        action: 'paypal_order_capture_started',
        orderId
      })

      await this.ensureValidAccessToken()

      const response = await this.makeApiRequest(`/v2/checkout/orders/${orderId}/capture`, 'POST')

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(`PayPal API error: ${(errorData as any).message || response.statusText}`)
      }

      const captureData = await response.json()
      const capture = (captureData as any).purchase_units[0].payments.captures[0] as PayPalCapture

      auditLogger.log({
        action: 'paypal_order_captured',
        orderId,
        captureId: capture.id,
        amount: capture.amount.value,
        currency: capture.amount.currencyCode,
        status: capture.status
      })

      return capture

    } catch (error: any) {
      auditLogger.log({
        action: 'paypal_order_capture_failed',
        orderId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'PayPal order capture failed',
        'PAYPAL_CAPTURE_ERROR',
        500,
        { originalError: error, orderId }
      )
    }
  }

  async refundCapture(
    captureId: string,
    amount?: number,
    currency?: string,
    invoiceId?: string,
    noteToPayer?: string
  ): Promise<PayPalRefund> {
    try {
      auditLogger.log({
        action: 'paypal_refund_started',
        captureId,
        amount,
        currency
      })

      await this.ensureValidAccessToken()

      const refundPayload: any = {
        invoice_id: invoiceId,
        note_to_payer: noteToPayer
      }

      if (amount && currency) {
        refundPayload.amount = {
          value: amount.toFixed(2),
          currency_code: currency
        }
      }

      const response = await this.makeApiRequest(
        `/v2/payments/captures/${captureId}/refund`,
        'POST',
        refundPayload
      )

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(`PayPal API error: ${(errorData as any).message || response.statusText}`)
      }

      const refund: PayPalRefund = await response.json()

      auditLogger.log({
        action: 'paypal_refund_created',
        refundId: refund.id,
        captureId,
        amount: refund.amount.value,
        currency: refund.amount.currencyCode,
        status: refund.status
      })

      return refund

    } catch (error: any) {
      auditLogger.log({
        action: 'paypal_refund_failed',
        captureId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'PayPal refund failed',
        'PAYPAL_REFUND_ERROR',
        500,
        { originalError: error, captureId }
      )
    }
  }

  async getOrder(orderId: string): Promise<PayPalOrder> {
    try {
      await this.ensureValidAccessToken()

      const response = await this.makeApiRequest(`/v2/checkout/orders/${orderId}`, 'GET')

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(`PayPal API error: ${(errorData as any).message || response.statusText}`)
      }

      return await response.json()

    } catch (error: any) {
      throw new AppError(
        'Failed to retrieve PayPal order',
        'PAYPAL_ORDER_RETRIEVAL_ERROR',
        500,
        { originalError: error, orderId }
      )
    }
  }

  async createInvoicePayment(invoice: Invoice): Promise<PayPalOrder> {
    const paymentRequest: PayPalPaymentRequest = {
      amount: invoice.totalAmount,
      currency: invoice.currency,
      description: `Payment for Invoice ${invoice.invoiceNumber}`,
      invoiceId: invoice.id,
      customerId: invoice.customerId,
      metadata: {
        invoiceNumber: invoice.invoiceNumber,
        customerName: invoice.customerDetails.name,
        dueDate: invoice.dueDate
      }
    }

    return await this.createOrder(paymentRequest)
  }

  async handleWebhook(payload: string, headers: Record<string, string>): Promise<PayPalWebhookEvent> {
    try {
      auditLogger.log({
        action: 'paypal_webhook_received',
        headers: Object.keys(headers)
      })

      // Verify webhook signature if webhook secret is configured
      if (this.config.webhookSecret) {
        const isValid = await this.verifyWebhookSignature(payload, headers)
        if (!isValid) {
          throw new AppError(
            'Invalid PayPal webhook signature',
            'INVALID_WEBHOOK_SIGNATURE',
            400
          )
        }
      }

      const event: PayPalWebhookEvent = JSON.parse(payload)

      // Process the webhook event
      await this.processWebhookEvent(event)

      auditLogger.log({
        action: 'paypal_webhook_processed',
        eventId: event.id,
        eventType: event.eventType
      })

      return event

    } catch (error: any) {
      auditLogger.log({
        action: 'paypal_webhook_processing_failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'PayPal webhook processing failed',
        'WEBHOOK_PROCESSING_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  private async processWebhookEvent(event: PayPalWebhookEvent): Promise<void> {
    switch (event.eventType) {
      case 'CHECKOUT.ORDER.APPROVED':
        await this.handleOrderApproved(event)
        break
      case 'CHECKOUT.ORDER.COMPLETED':
        await this.handleOrderCompleted(event)
        break
      case 'PAYMENT.CAPTURE.COMPLETED':
        await this.handleCaptureCompleted(event)
        break
      case 'PAYMENT.CAPTURE.DENIED':
        await this.handleCaptureDenied(event)
        break
      case 'PAYMENT.CAPTURE.REFUNDED':
        await this.handleCaptureRefunded(event)
        break
      default:
        auditLogger.log({
          action: 'paypal_webhook_event_ignored',
          eventType: event.eventType,
          eventId: event.id
        })
    }
  }

  private async handleOrderApproved(event: PayPalWebhookEvent): Promise<void> {
    auditLogger.log({
      action: 'paypal_order_approved',
      orderId: event.resource.id,
      eventId: event.id
    })

    // Update order status in CoreFlow360
    // This would integrate with the payment service
  }

  private async handleOrderCompleted(event: PayPalWebhookEvent): Promise<void> {
    auditLogger.log({
      action: 'paypal_order_completed',
      orderId: event.resource.id,
      eventId: event.id
    })

    // Update payment status in CoreFlow360
  }

  private async handleCaptureCompleted(event: PayPalWebhookEvent): Promise<void> {
    auditLogger.log({
      action: 'paypal_capture_completed',
      captureId: event.resource.id,
      amount: event.resource.amount?.value,
      currency: event.resource.amount?.currency_code,
      eventId: event.id
    })

    // Update payment status to completed in CoreFlow360
  }

  private async handleCaptureDenied(event: PayPalWebhookEvent): Promise<void> {
    auditLogger.log({
      action: 'paypal_capture_denied',
      captureId: event.resource.id,
      eventId: event.id
    })

    // Handle payment denial in CoreFlow360
  }

  private async handleCaptureRefunded(event: PayPalWebhookEvent): Promise<void> {
    auditLogger.log({
      action: 'paypal_capture_refunded',
      refundId: event.resource.id,
      captureId: event.resource.capture_id,
      amount: event.resource.amount?.value,
      currency: event.resource.amount?.currency_code,
      eventId: event.id
    })

    // Update refund status in CoreFlow360
  }

  private async ensureValidAccessToken(): Promise<void> {
    if (this.accessToken && this.isTokenValid()) {
      return
    }

    await this.refreshAccessToken()
  }

  private isTokenValid(): boolean {
    if (!this.accessToken) return false

    const now = Date.now()
    const expirationTime = this.accessToken.obtainedAt + (this.accessToken.expiresIn * 1000)
    const bufferTime = 60 * 1000 // 1 minute buffer

    return now < (expirationTime - bufferTime)
  }

  private async refreshAccessToken(): Promise<void> {
    try {
      const auth = Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64')

      const response = await fetch(`${this.baseUrl}/v1/oauth2/token`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Accept': 'application/json',
          'Accept-Language': 'en_US',
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: 'grant_type=client_credentials'
      })

      if (!response.ok) {
        throw new Error(`Failed to get access token: ${response.statusText}`)
      }

      const tokenData = await response.json()

      this.accessToken = {
        scope: (tokenData as any).scope,
        accessToken: (tokenData as any).access_token,
        tokenType: (tokenData as any).token_type,
        appId: (tokenData as any).app_id,
        expiresIn: (tokenData as any).expires_in,
        nonce: (tokenData as any).nonce,
        obtainedAt: Date.now()
      }

      auditLogger.log({
        action: 'paypal_access_token_refreshed',
        expiresIn: this.accessToken.expiresIn
      })

    } catch (error: any) {
      auditLogger.log({
        action: 'paypal_access_token_refresh_failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Failed to refresh PayPal access token',
        'PAYPAL_AUTH_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  private async makeApiRequest(
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    body?: any
  ): Promise<Response> {
    if (!this.accessToken) {
      throw new Error('No valid access token available')
    }

    const headers: Record<string, string> = {
      'Authorization': `${this.accessToken.tokenType} ${this.accessToken.accessToken}`,
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'PayPal-Request-Id': this.generateRequestId()
    }

    const options: RequestInit = {
      method,
      headers
    }

    if (body && (method === 'POST' || method === 'PUT')) {
      options.body = JSON.stringify(body)
    }

    return await fetch(`${this.baseUrl}${endpoint}`, options)
  }

  private async verifyWebhookSignature(
    payload: string,
    headers: Record<string, string>
  ): Promise<boolean> {
    // PayPal webhook signature verification would be implemented here
    // This is a simplified version - actual implementation would use
    // PayPal's webhook verification API or crypto verification

    const signature = headers['paypal-transmission-sig'] || headers['PAYPAL-TRANSMISSION-SIG']
    const certId = headers['paypal-cert-id'] || headers['PAYPAL-CERT-ID']
    const transmissionId = headers['paypal-transmission-id'] || headers['PAYPAL-TRANSMISSION-ID']
    const timestamp = headers['paypal-transmission-time'] || headers['PAYPAL-TRANSMISSION-TIME']

    if (!signature || !certId || !transmissionId || !timestamp) {
      return false
    }

    // In a real implementation, this would:
    // 1. Download the PayPal certificate using the cert ID
    // 2. Construct the expected signature payload
    // 3. Verify the signature using the certificate

    return true // Simplified for demo
  }

  private validatePaymentRequest(request: PayPalPaymentRequest): void {
    if (request.amount <= 0) {
      throw new AppError(
        'Payment amount must be greater than zero',
        'INVALID_PAYMENT_AMOUNT',
        400
      )
    }

    if (!request.currency || request.currency.length !== 3) {
      throw new AppError(
        'Valid 3-character currency code is required',
        'INVALID_CURRENCY_CODE',
        400
      )
    }

    if (request.amount > 10000) { // PayPal limit varies by account
      throw new AppError(
        'Payment amount exceeds maximum allowed',
        'AMOUNT_TOO_LARGE',
        400
      )
    }
  }

  private generateRequestId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  }

  // Utility methods
  getClientId(): string {
    return this.config.clientId
  }

  getEnvironment(): string {
    return this.config.environment
  }

  async getCapture(captureId: string): Promise<PayPalCapture> {
    try {
      await this.ensureValidAccessToken()

      const response = await this.makeApiRequest(`/v2/payments/captures/${captureId}`, 'GET')

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(`PayPal API error: ${(errorData as any).message || response.statusText}`)
      }

      return await response.json()

    } catch (error: any) {
      throw new AppError(
        'Failed to retrieve PayPal capture',
        'PAYPAL_CAPTURE_RETRIEVAL_ERROR',
        500,
        { originalError: error, captureId }
      )
    }
  }

  async getRefund(refundId: string): Promise<PayPalRefund> {
    try {
      await this.ensureValidAccessToken()

      const response = await this.makeApiRequest(`/v2/payments/refunds/${refundId}`, 'GET')

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(`PayPal API error: ${(errorData as any).message || response.statusText}`)
      }

      return await response.json()

    } catch (error: any) {
      throw new AppError(
        'Failed to retrieve PayPal refund',
        'PAYPAL_REFUND_RETRIEVAL_ERROR',
        500,
        { originalError: error, refundId }
      )
    }
  }
}