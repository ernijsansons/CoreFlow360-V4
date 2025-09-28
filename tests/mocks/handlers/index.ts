/**
 * MSW Handlers Index
 * Central export for all mock handlers
 */

import { agentHandlers } from './agent-handlers'
import { externalServiceHandlers } from './external-service-handlers'
import { http, HttpResponse } from 'msw'

// Internal API handlers
export const internalApiHandlers = [
  // Auth endpoints
  http.post('/api/v1/auth/login', () => {
    return HttpResponse.json({
      success: true,
      data: {
        token: 'mock-jwt-token',
        refreshToken: 'mock-refresh-token',
        user: {
          id: 'user-1',
          email: 'test@example.com',
          name: 'Test User',
          roles: ['user']
        }
      }
    })
  }),

  http.post('/api/v1/auth/refresh', () => {
    return HttpResponse.json({
      success: true,
      data: {
        token: 'new-mock-jwt-token',
        refreshToken: 'new-mock-refresh-token'
      }
    })
  }),

  // Invoice endpoints
  http.get('/api/v1/invoices', () => {
    return HttpResponse.json({
      success: true,
      data: {
        invoices: [
          {
            id: 'inv-1',
            invoiceNumber: 'INV-2024-001',
            status: 'sent',
            totalAmount: 1250.00,
            currency: 'USD',
            issueDate: '2024-01-15T00:00:00Z',
            dueDate: '2024-02-15T00:00:00Z',
            customer: {
              id: 'cust-1',
              name: 'Acme Corp',
              email: 'billing@acme.com'
            }
          }
        ],
        pagination: {
          page: 1,
          limit: 50,
          total: 1,
          pages: 1,
          hasNext: false,
          hasPrev: false
        }
      }
    })
  }),

  http.get('/api/v1/invoices/:id', ({ params }) => {
    const { id } = params
    return HttpResponse.json({
      success: true,
      data: {
        id,
        invoiceNumber: 'INV-2024-001',
        status: 'sent',
        issueDate: '2024-01-15T00:00:00Z',
        dueDate: '2024-02-15T00:00:00Z',
        currency: 'USD',
        customer: {
          name: 'Acme Corp',
          email: 'billing@acme.com',
          address: {
            street: '123 Business St',
            city: 'New York',
            state: 'NY',
            postalCode: '10001',
            country: 'US'
          }
        },
        business: {
          name: 'CoreFlow360',
          email: 'billing@coreflow360.com',
          address: {
            street: '456 Enterprise Ave',
            city: 'San Francisco',
            state: 'CA',
            postalCode: '94102',
            country: 'US'
          }
        },
        lineItems: [
          {
            id: 'item-1',
            description: 'Professional Services',
            quantity: 10,
            unitPrice: 100.00,
            lineTotal: 1000.00
          },
          {
            id: 'item-2',
            description: 'Software License',
            quantity: 1,
            unitPrice: 200.00,
            lineTotal: 200.00
          }
        ],
        subtotal: 1200.00,
        totalTax: 50.00,
        totalAmount: 1250.00,
        amountDue: 1250.00
      }
    })
  }),

  http.post('/api/v1/invoices', () => {
    return HttpResponse.json({
      success: true,
      data: {
        id: 'inv-new',
        invoiceNumber: 'INV-2024-002',
        status: 'draft'
      }
    }, { status: 201 })
  }),

  // Product endpoints
  http.get('/api/v1/products', () => {
    return HttpResponse.json({
      success: true,
      data: {
        products: [
          {
            id: 'prod-1',
            name: 'Professional Services',
            sku: 'PROF-001',
            price: 100.00,
            currency: 'USD',
            inventory: {
              quantity: 0,
              trackInventory: false
            }
          }
        ],
        pagination: {
          page: 1,
          limit: 50,
          total: 1,
          pages: 1,
          hasNext: false,
          hasPrev: false
        }
      }
    })
  }),

  // Payment endpoints
  http.post('/api/v1/payments/stripe/payment-intent', () => {
    return HttpResponse.json({
      success: true,
      data: {
        id: 'pi_mock_payment_intent',
        clientSecret: 'pi_mock_payment_intent_secret',
        status: 'requires_payment_method'
      }
    })
  }),

  // Analytics endpoints
  http.get('/api/v1/analytics/dashboard', () => {
    return HttpResponse.json({
      success: true,
      data: {
        revenue: {
          total: 125000,
          growth: 12.5
        },
        invoices: {
          total: 156,
          pending: 23,
          overdue: 5
        },
        customers: {
          total: 89,
          active: 67
        }
      }
    })
  }),

  // Error simulation endpoints
  http.get('/api/v1/error-test', () => {
    return HttpResponse.json({
      success: false,
      error: 'Internal server error',
      message: 'Something went wrong'
    }, { status: 500 })
  }),

  http.get('/api/v1/not-found', () => {
    return HttpResponse.json({
      success: false,
      error: 'Not found',
      message: 'Resource not found'
    }, { status: 404 })
  })
]

// Combine all handlers
export const handlers = [
  ...agentHandlers,
  ...externalServiceHandlers,
  ...internalApiHandlers
]

export { agentHandlers, externalServiceHandlers }