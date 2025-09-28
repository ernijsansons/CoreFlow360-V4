/**
 * Authentication Mock Handlers
 * MSW handlers for authentication, authorization, and JWT validation
 */

import { http, HttpResponse } from 'msw'
import { mockDatabase } from './database.handlers'

// Mock JWT tokens for testing
const mockTokens = {
  validToken: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMSIsInRlbmFudF9pZCI6InRlbmFudC0xIiwiZXhwIjo5OTk5OTk5OTk5fQ.mock-signature',
  expiredToken: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMSIsInRlbmFudF9pZCI6InRlbmFudC0xIiwiZXhwIjoxfQ.mock-signature',
  invalidToken: 'invalid.jwt.token'
}

// Mock user credentials
const mockCredentials = {
  'test@example.com': { password: 'password123', userId: '1', tenantId: 'tenant-1' },
  'admin@example.com': { password: 'admin123', userId: '2', tenantId: 'tenant-1' },
  'user@demo.com': { password: 'demo123', userId: '3', tenantId: 'tenant-2' }
}

export const authHandlers = [
  // Login endpoint
  http.post('*/api/auth/login', async ({ request }) => {
    const body = await request.json() as any
    const { email, password, tenantDomain } = body

    // Validate credentials
    const userCreds = mockCredentials[email as keyof typeof mockCredentials]
    if (!userCreds || userCreds.password !== password) {
      return HttpResponse.json({
        success: false,
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      }, { status: 401 })
    }

    // Find user in mock database
    const user = mockDatabase.users.find(u => u.id === userCreds.userId)
    if (!user) {
      return HttpResponse.json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      }, { status: 404 })
    }

    // Validate tenant domain if provided
    if (tenantDomain) {
      const tenant = mockDatabase.tenants.find(t => t.domain === tenantDomain)
      if (!tenant || tenant.id !== user.tenantId) {
        return HttpResponse.json({
          success: false,
          error: 'Invalid tenant domain',
          code: 'INVALID_TENANT'
        }, { status: 403 })
      }
    }

    return HttpResponse.json({
      success: true,
      data: {
        token: mockTokens.validToken,
        refreshToken: `refresh-${Date.now()}`,
        expiresIn: 3600,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          roles: user.roles,
          tenantId: user.tenantId
        },
        tenant: mockDatabase.tenants.find(t => t.id === user.tenantId)
      }
    })
  }),

  // Token refresh endpoint
  http.post('*/api/auth/refresh', async ({ request }) => {
    const body = await request.json() as any
    const { refreshToken } = body

    if (!refreshToken || !refreshToken.startsWith('refresh-')) {
      return HttpResponse.json({
        success: false,
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      }, { status: 401 })
    }

    return HttpResponse.json({
      success: true,
      data: {
        token: mockTokens.validToken,
        refreshToken: `refresh-${Date.now()}`,
        expiresIn: 3600
      }
    })
  }),

  // Token validation endpoint
  http.post('*/api/auth/validate', async ({ request }) => {
    const authHeader = request.headers.get('Authorization')
    const token = authHeader?.replace('Bearer ', '')

    if (!token) {
      return HttpResponse.json({
        valid: false,
        error: 'No token provided',
        code: 'NO_TOKEN'
      }, { status: 401 })
    }

    if (token === mockTokens.invalidToken) {
      return HttpResponse.json({
        valid: false,
        error: 'Invalid token format',
        code: 'INVALID_TOKEN'
      }, { status: 401 })
    }

    if (token === mockTokens.expiredToken) {
      return HttpResponse.json({
        valid: false,
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      }, { status: 401 })
    }

    if (token === mockTokens.validToken) {
      return HttpResponse.json({
        valid: true,
        user: {
          id: '1',
          email: 'test@example.com',
          name: 'Test User',
          roles: ['user'],
          tenantId: 'tenant-1'
        },
        tenant: {
          id: 'tenant-1',
          name: 'Test Company',
          domain: 'test.example.com'
        },
        permissions: ['read', 'write', 'delete'],
        expiresAt: new Date(Date.now() + 3600000).toISOString()
      })
    }

    return HttpResponse.json({
      valid: false,
      error: 'Invalid token',
      code: 'INVALID_TOKEN'
    }, { status: 401 })
  }),

  // User info endpoint
  http.get('*/api/auth/me', ({ request }) => {
    const authHeader = request.headers.get('Authorization')
    const token = authHeader?.replace('Bearer ', '')

    if (token !== mockTokens.validToken) {
      return HttpResponse.json({
        success: false,
        error: 'Unauthorized',
        code: 'UNAUTHORIZED'
      }, { status: 401 })
    }

    return HttpResponse.json({
      success: true,
      data: {
        user: {
          id: '1',
          email: 'test@example.com',
          name: 'Test User',
          roles: ['user'],
          tenantId: 'tenant-1',
          lastLogin: new Date().toISOString()
        },
        tenant: {
          id: 'tenant-1',
          name: 'Test Company',
          domain: 'test.example.com',
          plan: 'professional'
        },
        permissions: ['read', 'write', 'delete'],
        session: {
          id: 'session-1',
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
          lastActivity: new Date().toISOString()
        }
      }
    })
  }),

  // Logout endpoint
  http.post('*/api/auth/logout', ({ request }) => {
    const authHeader = request.headers.get('Authorization')
    const token = authHeader?.replace('Bearer ', '')

    return HttpResponse.json({
      success: true,
      message: 'Logged out successfully',
      token: token || null
    })
  }),

  // Multi-factor authentication
  http.post('*/api/auth/mfa/setup', ({ request }) => {
    const authHeader = request.headers.get('Authorization')
    const token = authHeader?.replace('Bearer ', '')

    if (token !== mockTokens.validToken) {
      return HttpResponse.json({
        success: false,
        error: 'Unauthorized',
        code: 'UNAUTHORIZED'
      }, { status: 401 })
    }

    return HttpResponse.json({
      success: true,
      data: {
        secret: 'MOCK-MFA-SECRET-KEY',
        qrCode: 'data:image/png;base64,mock-qr-code-data',
        backupCodes: [
          '123456-789012',
          '234567-890123',
          '345678-901234'
        ]
      }
    })
  }),

  http.post('*/api/auth/mfa/verify', async ({ request }) => {
    const body = await request.json() as any
    const { code } = body

    // Mock verification - accept specific codes
    const validCodes = ['123456', '000000', '111111']

    if (!validCodes.includes(code)) {
      return HttpResponse.json({
        success: false,
        error: 'Invalid MFA code',
        code: 'INVALID_MFA_CODE'
      }, { status: 400 })
    }

    return HttpResponse.json({
      success: true,
      data: {
        verified: true,
        token: mockTokens.validToken,
        user: {
          id: '1',
          email: 'test@example.com',
          mfaEnabled: true
        }
      }
    })
  }),

  // Password reset
  http.post('*/api/auth/password/reset-request', async ({ request }) => {
    const body = await request.json() as any
    const { email } = body

    // Always return success for security (don't reveal if email exists)
    return HttpResponse.json({
      success: true,
      message: 'If the email exists, a reset link has been sent'
    })
  }),

  http.post('*/api/auth/password/reset', async ({ request }) => {
    const body = await request.json() as any
    const { token, password } = body

    if (token !== 'mock-reset-token') {
      return HttpResponse.json({
        success: false,
        error: 'Invalid or expired reset token',
        code: 'INVALID_RESET_TOKEN'
      }, { status: 400 })
    }

    return HttpResponse.json({
      success: true,
      message: 'Password reset successfully'
    })
  }),

  // Permission and role checks
  http.get('*/api/auth/permissions', ({ request }) => {
    const authHeader = request.headers.get('Authorization')
    const token = authHeader?.replace('Bearer ', '')

    if (token !== mockTokens.validToken) {
      return HttpResponse.json({
        success: false,
        error: 'Unauthorized',
        code: 'UNAUTHORIZED'
      }, { status: 401 })
    }

    return HttpResponse.json({
      success: true,
      data: {
        permissions: [
          'dashboard:read',
          'invoices:read',
          'invoices:write',
          'customers:read',
          'customers:write',
          'reports:read'
        ],
        roles: ['user'],
        tenantPermissions: [
          'tenant:read',
          'tenant:settings'
        ]
      }
    })
  }),

  http.post('*/api/auth/check-permission', async ({ request }) => {
    const body = await request.json() as any
    const { permission } = body

    const authHeader = request.headers.get('Authorization')
    const token = authHeader?.replace('Bearer ', '')

    if (token !== mockTokens.validToken) {
      return HttpResponse.json({
        allowed: false,
        error: 'Unauthorized',
        code: 'UNAUTHORIZED'
      }, { status: 401 })
    }

    // Mock permission checking
    const userPermissions = [
      'dashboard:read',
      'invoices:read',
      'invoices:write',
      'customers:read',
      'customers:write',
      'reports:read'
    ]

    return HttpResponse.json({
      allowed: userPermissions.includes(permission),
      permission,
      user: {
        id: '1',
        roles: ['user']
      }
    })
  }),

  // Session management
  http.get('*/api/auth/sessions', ({ request }) => {
    const authHeader = request.headers.get('Authorization')
    const token = authHeader?.replace('Bearer ', '')

    if (token !== mockTokens.validToken) {
      return HttpResponse.json({
        success: false,
        error: 'Unauthorized',
        code: 'UNAUTHORIZED'
      }, { status: 401 })
    }

    return HttpResponse.json({
      success: true,
      data: {
        current: {
          id: 'session-1',
          device: 'Chrome on Windows',
          ip: '192.168.1.100',
          location: 'San Francisco, CA',
          lastActivity: new Date().toISOString(),
          isCurrent: true
        },
        other: [
          {
            id: 'session-2',
            device: 'Safari on iPhone',
            ip: '192.168.1.101',
            location: 'San Francisco, CA',
            lastActivity: new Date(Date.now() - 3600000).toISOString(),
            isCurrent: false
          }
        ]
      }
    })
  }),

  http.delete('*/api/auth/sessions/:sessionId', ({ params }) => {
    const { sessionId } = params

    return HttpResponse.json({
      success: true,
      message: `Session ${sessionId} terminated successfully`
    })
  }),

  // Tenant switching
  http.post('*/api/auth/switch-tenant', async ({ request }) => {
    const body = await request.json() as any
    const { tenantId } = body

    const authHeader = request.headers.get('Authorization')
    const token = authHeader?.replace('Bearer ', '')

    if (token !== mockTokens.validToken) {
      return HttpResponse.json({
        success: false,
        error: 'Unauthorized',
        code: 'UNAUTHORIZED'
      }, { status: 401 })
    }

    const tenant = mockDatabase.tenants.find(t => t.id === tenantId)
    if (!tenant) {
      return HttpResponse.json({
        success: false,
        error: 'Tenant not found',
        code: 'TENANT_NOT_FOUND'
      }, { status: 404 })
    }

    return HttpResponse.json({
      success: true,
      data: {
        token: mockTokens.validToken,
        tenant,
        user: {
          id: '1',
          email: 'test@example.com',
          name: 'Test User',
          tenantId
        }
      }
    })
  })
]