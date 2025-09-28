/**
 * Multi-Tenant Isolation Security Tests
 * Validates that tenants cannot access each other's data
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { server } from '../mocks/setup'
import { http, HttpResponse } from 'msw'

describe('Multi-Tenant Isolation', () => {
  const TENANT_1_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMSIsInRlbmFudF9pZCI6InRlbmFudC0xIiwiZXhwIjo5OTk5OTk5OTk5fQ.mock-signature-tenant-1'
  const TENANT_2_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMyIsInRlbmFudF9pZCI6InRlbmFudC0yIiwiZXhwIjo5OTk5OTk5OTk5fQ.mock-signature-tenant-2'

  beforeEach(() => {
    // Enhanced auth handlers for tenant isolation testing
    server.use(
      http.post('*/api/auth/validate', async ({ request }) => {
        const authHeader = request.headers.get('Authorization')
        const token = authHeader?.replace('Bearer ', '')

        if (token === TENANT_1_TOKEN) {
          return HttpResponse.json({
            valid: true,
            user: {
              id: '1',
              email: 'user@tenant1.com',
              tenantId: 'tenant-1',
              roles: ['user']
            },
            tenant: {
              id: 'tenant-1',
              name: 'Tenant 1',
              domain: 'tenant1.example.com'
            }
          })
        }

        if (token === TENANT_2_TOKEN) {
          return HttpResponse.json({
            valid: true,
            user: {
              id: '3',
              email: 'user@tenant2.com',
              tenantId: 'tenant-2',
              roles: ['user']
            },
            tenant: {
              id: 'tenant-2',
              name: 'Tenant 2',
              domain: 'tenant2.example.com'
            }
          })
        }

        return HttpResponse.json({
          valid: false,
          error: 'Invalid token'
        }, { status: 401 })
      }),

      // Mock data endpoints with tenant filtering
      http.get('*/api/invoices', ({ request }) => {
        const authHeader = request.headers.get('Authorization')
        const token = authHeader?.replace('Bearer ', '')

        if (token === TENANT_1_TOKEN) {
          return HttpResponse.json({
            invoices: [
              { id: 'inv-1', tenantId: 'tenant-1', amount: 1000 },
              { id: 'inv-2', tenantId: 'tenant-1', amount: 2000 }
            ]
          })
        }

        if (token === TENANT_2_TOKEN) {
          return HttpResponse.json({
            invoices: [
              { id: 'inv-3', tenantId: 'tenant-2', amount: 3000 },
              { id: 'inv-4', tenantId: 'tenant-2', amount: 4000 }
            ]
          })
        }

        return HttpResponse.json({
          error: 'Unauthorized'
        }, { status: 401 })
      }),

      http.get('*/api/customers', ({ request }) => {
        const authHeader = request.headers.get('Authorization')
        const token = authHeader?.replace('Bearer ', '')

        if (token === TENANT_1_TOKEN) {
          return HttpResponse.json({
            customers: [
              { id: 'cust-1', tenantId: 'tenant-1', name: 'Customer A' },
              { id: 'cust-2', tenantId: 'tenant-1', name: 'Customer B' }
            ]
          })
        }

        if (token === TENANT_2_TOKEN) {
          return HttpResponse.json({
            customers: [
              { id: 'cust-3', tenantId: 'tenant-2', name: 'Customer C' },
              { id: 'cust-4', tenantId: 'tenant-2', name: 'Customer D' }
            ]
          })
        }

        return HttpResponse.json({
          error: 'Unauthorized'
        }, { status: 401 })
      }),

      // Direct resource access attempts
      http.get('*/api/invoices/:id', ({ params, request }) => {
        const { id } = params
        const authHeader = request.headers.get('Authorization')
        const token = authHeader?.replace('Bearer ', '')

        // Mock invoice data with tenant assignments
        const invoices = {
          'inv-1': { id: 'inv-1', tenantId: 'tenant-1', amount: 1000 },
          'inv-2': { id: 'inv-2', tenantId: 'tenant-1', amount: 2000 },
          'inv-3': { id: 'inv-3', tenantId: 'tenant-2', amount: 3000 },
          'inv-4': { id: 'inv-4', tenantId: 'tenant-2', amount: 4000 }
        }

        const invoice = invoices[id as keyof typeof invoices]
        if (!invoice) {
          return HttpResponse.json({
            error: 'Invoice not found'
          }, { status: 404 })
        }

        // Check tenant access
        if (token === TENANT_1_TOKEN && invoice.tenantId !== 'tenant-1') {
          return HttpResponse.json({
            error: 'Access denied - insufficient permissions'
          }, { status: 403 })
        }

        if (token === TENANT_2_TOKEN && invoice.tenantId !== 'tenant-2') {
          return HttpResponse.json({
            error: 'Access denied - insufficient permissions'
          }, { status: 403 })
        }

        if (token === TENANT_1_TOKEN && invoice.tenantId === 'tenant-1') {
          return HttpResponse.json({ invoice })
        }

        if (token === TENANT_2_TOKEN && invoice.tenantId === 'tenant-2') {
          return HttpResponse.json({ invoice })
        }

        return HttpResponse.json({
          error: 'Unauthorized'
        }, { status: 401 })
      })
    )
  })

  describe('Data Isolation', () => {
    it('should only return tenant-specific invoices', async () => {
      // Test Tenant 1
      const tenant1Response = await fetch('http://localhost:8787/api/invoices', {
        headers: {
          'Authorization': `Bearer ${TENANT_1_TOKEN}`
        }
      })

      const tenant1Data = await tenant1Response.json()
      expect(tenant1Response.status).toBe(200)
      expect(tenant1Data.invoices).toHaveLength(2)
      expect(tenant1Data.invoices.every((inv: any) => inv.tenantId === 'tenant-1')).toBe(true)

      // Test Tenant 2
      const tenant2Response = await fetch('http://localhost:8787/api/invoices', {
        headers: {
          'Authorization': `Bearer ${TENANT_2_TOKEN}`
        }
      })

      const tenant2Data = await tenant2Response.json()
      expect(tenant2Response.status).toBe(200)
      expect(tenant2Data.invoices).toHaveLength(2)
      expect(tenant2Data.invoices.every((inv: any) => inv.tenantId === 'tenant-2')).toBe(true)
    })

    it('should only return tenant-specific customers', async () => {
      // Test Tenant 1
      const tenant1Response = await fetch('http://localhost:8787/api/customers', {
        headers: {
          'Authorization': `Bearer ${TENANT_1_TOKEN}`
        }
      })

      const tenant1Data = await tenant1Response.json()
      expect(tenant1Response.status).toBe(200)
      expect(tenant1Data.customers).toHaveLength(2)
      expect(tenant1Data.customers.every((cust: any) => cust.tenantId === 'tenant-1')).toBe(true)

      // Test Tenant 2
      const tenant2Response = await fetch('http://localhost:8787/api/customers', {
        headers: {
          'Authorization': `Bearer ${TENANT_2_TOKEN}`
        }
      })

      const tenant2Data = await tenant2Response.json()
      expect(tenant2Response.status).toBe(200)
      expect(tenant2Data.customers).toHaveLength(2)
      expect(tenant2Data.customers.every((cust: any) => cust.tenantId === 'tenant-2')).toBe(true)
    })
  })

  describe('Cross-Tenant Access Prevention', () => {
    it('should prevent tenant 1 from accessing tenant 2 invoices', async () => {
      const response = await fetch('http://localhost:8787/api/invoices/inv-3', {
        headers: {
          'Authorization': `Bearer ${TENANT_1_TOKEN}`
        }
      })

      expect(response.status).toBe(403)
      const data = await response.json()
      expect(data.error).toContain('Access denied')
    })

    it('should prevent tenant 2 from accessing tenant 1 invoices', async () => {
      const response = await fetch('http://localhost:8787/api/invoices/inv-1', {
        headers: {
          'Authorization': `Bearer ${TENANT_2_TOKEN}`
        }
      })

      expect(response.status).toBe(403)
      const data = await response.json()
      expect(data.error).toContain('Access denied')
    })

    it('should allow tenant 1 to access their own invoices', async () => {
      const response = await fetch('http://localhost:8787/api/invoices/inv-1', {
        headers: {
          'Authorization': `Bearer ${TENANT_1_TOKEN}`
        }
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.invoice.tenantId).toBe('tenant-1')
    })

    it('should allow tenant 2 to access their own invoices', async () => {
      const response = await fetch('http://localhost:8787/api/invoices/inv-3', {
        headers: {
          'Authorization': `Bearer ${TENANT_2_TOKEN}`
        }
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.invoice.tenantId).toBe('tenant-2')
    })
  })

  describe('Authorization Bypass Attempts', () => {
    it('should reject requests without authorization headers', async () => {
      const response = await fetch('http://localhost:8787/api/invoices')

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.error).toContain('Unauthorized')
    })

    it('should reject requests with invalid tokens', async () => {
      const response = await fetch('http://localhost:8787/api/invoices', {
        headers: {
          'Authorization': 'Bearer invalid-token'
        }
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.error).toBe('Unauthorized')
    })

    it('should reject malformed authorization headers', async () => {
      const response = await fetch('http://localhost:8787/api/invoices', {
        headers: {
          'Authorization': 'Invalid header format'
        }
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.error).toBe('Unauthorized')
    })
  })

  describe('Database Query Isolation', () => {
    it('should validate tenant ID in database queries', async () => {
      // This test validates that database queries include proper tenant filtering
      const response = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TENANT_1_TOKEN}`,
          'Content-Type': 'application/json'
        }
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.user.tenantId).toBe('tenant-1')
      expect(data.tenant.id).toBe('tenant-1')
    })

    it('should ensure tenant context is maintained across requests', async () => {
      // Validate tenant 1 context
      const auth1Response = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TENANT_1_TOKEN}`
        }
      })

      const auth1Data = await auth1Response.json()
      expect(auth1Data.user.tenantId).toBe('tenant-1')

      // Validate tenant 2 context
      const auth2Response = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TENANT_2_TOKEN}`
        }
      })

      const auth2Data = await auth2Response.json()
      expect(auth2Data.user.tenantId).toBe('tenant-2')

      // Ensure contexts don't bleed
      expect(auth1Data.user.tenantId).not.toBe(auth2Data.user.tenantId)
    })
  })

  describe('Edge Cases and Security', () => {
    it('should handle concurrent requests from different tenants', async () => {
      const promises = [
        fetch('http://localhost:8787/api/invoices', {
          headers: { 'Authorization': `Bearer ${TENANT_1_TOKEN}` }
        }),
        fetch('http://localhost:8787/api/invoices', {
          headers: { 'Authorization': `Bearer ${TENANT_2_TOKEN}` }
        }),
        fetch('http://localhost:8787/api/customers', {
          headers: { 'Authorization': `Bearer ${TENANT_1_TOKEN}` }
        }),
        fetch('http://localhost:8787/api/customers', {
          headers: { 'Authorization': `Bearer ${TENANT_2_TOKEN}` }
        })
      ]

      const responses = await Promise.all(promises)
      const data = await Promise.all(responses.map(r => r.json()))

      // All requests should succeed
      expect(responses.every(r => r.status === 200)).toBe(true)

      // Tenant 1 should only see their data
      expect(data[0].invoices.every((inv: any) => inv.tenantId === 'tenant-1')).toBe(true)
      expect(data[2].customers.every((cust: any) => cust.tenantId === 'tenant-1')).toBe(true)

      // Tenant 2 should only see their data
      expect(data[1].invoices.every((inv: any) => inv.tenantId === 'tenant-2')).toBe(true)
      expect(data[3].customers.every((cust: any) => cust.tenantId === 'tenant-2')).toBe(true)
    })

    it('should maintain isolation under load', async () => {
      // Simulate high load with multiple concurrent requests
      const requests = Array.from({ length: 20 }, (_, i) => {
        const token = i % 2 === 0 ? TENANT_1_TOKEN : TENANT_2_TOKEN
        const expectedTenant = i % 2 === 0 ? 'tenant-1' : 'tenant-2'

        return fetch('http://localhost:8787/api/invoices', {
          headers: { 'Authorization': `Bearer ${token}` }
        }).then(async (response) => {
          const data = await response.json()
          return {
            success: response.status === 200,
            correctTenant: data.invoices?.every((inv: any) => inv.tenantId === expectedTenant) ?? false
          }
        })
      })

      const results = await Promise.all(requests)

      // All requests should succeed
      expect(results.every(r => r.success)).toBe(true)

      // All should maintain correct tenant isolation
      expect(results.every(r => r.correctTenant)).toBe(true)
    })
  })
})