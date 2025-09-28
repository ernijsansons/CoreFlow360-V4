/**
 * Database Mock Handlers
 * MSW handlers for database operations and in-memory testing
 */

import { http, HttpResponse } from 'msw'

// In-memory data store for testing
export const mockDatabase = {
  users: [
    {
      id: '1',
      email: 'test@example.com',
      name: 'Test User',
      tenantId: 'tenant-1',
      roles: ['user'],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    },
    {
      id: '2',
      email: 'admin@example.com',
      name: 'Admin User',
      tenantId: 'tenant-1',
      roles: ['admin'],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
  ],
  tenants: [
    {
      id: 'tenant-1',
      name: 'Test Company',
      domain: 'test.example.com',
      plan: 'professional',
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    },
    {
      id: 'tenant-2',
      name: 'Demo Company',
      domain: 'demo.example.com',
      plan: 'enterprise',
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
  ],
  invoices: [
    {
      id: 'inv-1',
      tenantId: 'tenant-1',
      customerId: 'cust-1',
      invoiceNumber: 'INV-2024-001',
      status: 'sent',
      totalAmount: 1250.00,
      currency: 'USD',
      issueDate: '2024-01-15T00:00:00Z',
      dueDate: '2024-02-15T00:00:00Z',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
  ],
  customers: [
    {
      id: 'cust-1',
      tenantId: 'tenant-1',
      name: 'Acme Corp',
      email: 'billing@acme.com',
      phone: '+1-555-0123',
      address: {
        street: '123 Business St',
        city: 'New York',
        state: 'NY',
        postalCode: '10001',
        country: 'US'
      },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
  ],
  sessions: [
    {
      id: 'session-1',
      userId: '1',
      tenantId: 'tenant-1',
      token: 'mock-session-token',
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      createdAt: new Date().toISOString()
    }
  ]
}

export const databaseHandlers = [
  // Generic database query endpoint
  http.post('*/api/db/query', async ({ request }) => {
    const body = await request.json() as any
    const { sql, params } = body

    // Mock query responses based on SQL patterns
    const sqlLower = sql.toLowerCase()

    if (sqlLower.includes('select') && sqlLower.includes('users')) {
      const tenantFilter = params?.tenantId
      const users = tenantFilter
        ? mockDatabase.users.filter(u => u.tenantId === tenantFilter)
        : mockDatabase.users

      return HttpResponse.json({
        success: true,
        data: users,
        rowCount: users.length,
        executionTime: 12.5
      })
    }

    if (sqlLower.includes('select') && sqlLower.includes('tenants')) {
      return HttpResponse.json({
        success: true,
        data: mockDatabase.tenants,
        rowCount: mockDatabase.tenants.length,
        executionTime: 8.3
      })
    }

    if (sqlLower.includes('insert') && sqlLower.includes('users')) {
      const newUser = {
        id: `user-${Date.now()}`,
        ...params,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
      mockDatabase.users.push(newUser)

      return HttpResponse.json({
        success: true,
        data: newUser,
        rowCount: 1,
        executionTime: 15.2
      })
    }

    if (sqlLower.includes('update')) {
      return HttpResponse.json({
        success: true,
        data: { affectedRows: 1 },
        rowCount: 1,
        executionTime: 10.1
      })
    }

    if (sqlLower.includes('delete')) {
      return HttpResponse.json({
        success: true,
        data: { deletedRows: 1 },
        rowCount: 1,
        executionTime: 8.7
      })
    }

    return HttpResponse.json({
      success: true,
      data: [],
      rowCount: 0,
      executionTime: 2.1
    })
  }),

  // Specific entity endpoints
  http.get('*/api/db/users', ({ request }) => {
    const url = new URL(request.url)
    const tenantId = url.searchParams.get('tenantId')

    const users = tenantId
      ? mockDatabase.users.filter(u => u.tenantId === tenantId)
      : mockDatabase.users

    return HttpResponse.json({
      success: true,
      data: users,
      total: users.length
    })
  }),

  http.get('*/api/db/users/:id', ({ params }) => {
    const { id } = params
    const user = mockDatabase.users.find(u => u.id === id)

    if (!user) {
      return HttpResponse.json({
        success: false,
        error: 'User not found'
      }, { status: 404 })
    }

    return HttpResponse.json({
      success: true,
      data: user
    })
  }),

  http.post('*/api/db/users', async ({ request }) => {
    const body = await request.json() as any

    const newUser = {
      id: `user-${Date.now()}`,
      ...body,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }

    mockDatabase.users.push(newUser)

    return HttpResponse.json({
      success: true,
      data: newUser
    }, { status: 201 })
  }),

  http.put('*/api/db/users/:id', async ({ params, request }) => {
    const { id } = params
    const body = await request.json() as any

    const userIndex = mockDatabase.users.findIndex(u => u.id === id)
    if (userIndex === -1) {
      return HttpResponse.json({
        success: false,
        error: 'User not found'
      }, { status: 404 })
    }

    mockDatabase.users[userIndex] = {
      ...mockDatabase.users[userIndex],
      ...body,
      updatedAt: new Date().toISOString()
    }

    return HttpResponse.json({
      success: true,
      data: mockDatabase.users[userIndex]
    })
  }),

  http.delete('*/api/db/users/:id', ({ params }) => {
    const { id } = params
    const userIndex = mockDatabase.users.findIndex(u => u.id === id)

    if (userIndex === -1) {
      return HttpResponse.json({
        success: false,
        error: 'User not found'
      }, { status: 404 })
    }

    mockDatabase.users.splice(userIndex, 1)

    return HttpResponse.json({
      success: true,
      message: 'User deleted successfully'
    })
  }),

  // Tenant endpoints
  http.get('*/api/db/tenants', () => {
    return HttpResponse.json({
      success: true,
      data: mockDatabase.tenants,
      total: mockDatabase.tenants.length
    })
  }),

  http.get('*/api/db/tenants/:id', ({ params }) => {
    const { id } = params
    const tenant = mockDatabase.tenants.find(t => t.id === id)

    if (!tenant) {
      return HttpResponse.json({
        success: false,
        error: 'Tenant not found'
      }, { status: 404 })
    }

    return HttpResponse.json({
      success: true,
      data: tenant
    })
  }),

  // Multi-tenant data isolation
  http.get('*/api/db/tenants/:tenantId/users', ({ params }) => {
    const { tenantId } = params
    const users = mockDatabase.users.filter(u => u.tenantId === tenantId)

    return HttpResponse.json({
      success: true,
      data: users,
      total: users.length,
      tenantId
    })
  }),

  http.get('*/api/db/tenants/:tenantId/invoices', ({ params }) => {
    const { tenantId } = params
    const invoices = mockDatabase.invoices.filter(i => i.tenantId === tenantId)

    return HttpResponse.json({
      success: true,
      data: invoices,
      total: invoices.length,
      tenantId
    })
  }),

  // Database health and metrics
  http.get('*/api/db/health', () => {
    return HttpResponse.json({
      status: 'healthy',
      connections: {
        active: 5,
        idle: 10,
        total: 15
      },
      performance: {
        averageQueryTime: 12.5,
        slowQueries: 0,
        queryCount: 1247
      },
      storage: {
        used: '256MB',
        available: '2GB',
        percentage: 12.5
      },
      timestamp: new Date().toISOString()
    })
  }),

  http.get('*/api/db/metrics', () => {
    return HttpResponse.json({
      queries: {
        total: 1247,
        successful: 1198,
        failed: 49,
        averageTime: 12.5
      },
      connections: {
        current: 15,
        max: 100,
        totalCreated: 567
      },
      tables: {
        users: { rows: mockDatabase.users.length, size: '12MB' },
        tenants: { rows: mockDatabase.tenants.length, size: '1MB' },
        invoices: { rows: mockDatabase.invoices.length, size: '45MB' },
        customers: { rows: mockDatabase.customers.length, size: '23MB' }
      },
      performance: {
        slowestQuery: 156.7,
        fastestQuery: 0.8,
        averageQuery: 12.5
      },
      timestamp: new Date().toISOString()
    })
  }),

  // Database migration endpoints
  http.post('*/api/db/migrate', async ({ request }) => {
    const body = await request.json() as any

    return HttpResponse.json({
      success: true,
      migration: {
        version: body.version || 'latest',
        applied: true,
        duration: 234,
        changes: [
          'Created table: audit_logs',
          'Added index: idx_users_tenant_id',
          'Updated column: users.updated_at'
        ]
      },
      timestamp: new Date().toISOString()
    })
  }),

  http.get('*/api/db/migrations/status', () => {
    return HttpResponse.json({
      current: '2024.01.15.001',
      pending: [],
      applied: [
        { version: '2024.01.01.001', name: 'Initial schema', appliedAt: '2024-01-01T00:00:00Z' },
        { version: '2024.01.10.001', name: 'Add tenants table', appliedAt: '2024-01-10T00:00:00Z' },
        { version: '2024.01.15.001', name: 'Add audit logging', appliedAt: new Date().toISOString() }
      ],
      status: 'up-to-date'
    })
  }),

  // Transaction testing
  http.post('*/api/db/transaction/begin', () => {
    return HttpResponse.json({
      success: true,
      transactionId: `tx-${Date.now()}`,
      timestamp: new Date().toISOString()
    })
  }),

  http.post('*/api/db/transaction/:id/commit', ({ params }) => {
    const { id } = params

    return HttpResponse.json({
      success: true,
      transactionId: id,
      committed: true,
      timestamp: new Date().toISOString()
    })
  }),

  http.post('*/api/db/transaction/:id/rollback', ({ params }) => {
    const { id } = params

    return HttpResponse.json({
      success: true,
      transactionId: id,
      rolledBack: true,
      timestamp: new Date().toISOString()
    })
  })
]