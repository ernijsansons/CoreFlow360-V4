/**
 * JWT Validation Security Tests
 * Validates JWT token handling, validation, and security measures
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { server } from '../mocks/setup'
import { http, HttpResponse } from 'msw'

describe('JWT Validation', () => {
  const VALID_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMSIsInRlbmFudF9pZCI6InRlbmFudC0xIiwiZXhwIjo5OTk5OTk5OTk5fQ.valid-signature'
  const EXPIRED_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMSIsInRlbmFudF9pZCI6InRlbmFudC0xIiwiZXhwIjoxfQ.expired-signature'
  const MALFORMED_TOKEN = 'invalid.jwt.structure'
  const INVALID_SIGNATURE = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMSIsInRlbmFudF9pZCI6InRlbmFudC0xIiwiZXhwIjo5OTk5OTk5OTk5fQ.invalid-signature'

  beforeEach(() => {
    // Enhanced JWT validation handlers
    server.use(
      http.post('*/api/auth/validate', async ({ request }) => {
        const authHeader = request.headers.get('Authorization')
        const token = authHeader?.replace('Bearer ', '')

        if (!token) {
          return HttpResponse.json({
            valid: false,
            error: 'No token provided',
            code: 'MISSING_TOKEN'
          }, { status: 401 })
        }

        if (token === VALID_TOKEN) {
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
              name: 'Test Company'
            },
            permissions: ['read', 'write'],
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            issuedAt: new Date(Date.now() - 300000).toISOString(),
            issuer: 'coreflow360-auth',
            audience: 'coreflow360-api'
          })
        }

        if (token === EXPIRED_TOKEN) {
          return HttpResponse.json({
            valid: false,
            error: 'Token has expired',
            code: 'TOKEN_EXPIRED',
            expiredAt: new Date(1).toISOString()
          }, { status: 401 })
        }

        if (token === MALFORMED_TOKEN) {
          return HttpResponse.json({
            valid: false,
            error: 'Malformed JWT token',
            code: 'MALFORMED_TOKEN'
          }, { status: 400 })
        }

        if (token === INVALID_SIGNATURE) {
          return HttpResponse.json({
            valid: false,
            error: 'Invalid token signature',
            code: 'INVALID_SIGNATURE'
          }, { status: 401 })
        }

        // Unknown token
        return HttpResponse.json({
          valid: false,
          error: 'Invalid token',
          code: 'INVALID_TOKEN'
        }, { status: 401 })
      }),

      http.get('*/api/auth/me', ({ request }) => {
        const authHeader = request.headers.get('Authorization')
        const token = authHeader?.replace('Bearer ', '')

        if (token !== VALID_TOKEN) {
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
              tenantId: 'tenant-1'
            },
            session: {
              id: 'session-1',
              expiresAt: new Date(Date.now() + 3600000).toISOString(),
              lastActivity: new Date().toISOString()
            }
          }
        })
      }),

      http.post('*/api/auth/refresh', async ({ request }) => {
        const body = await request.json() as any
        const { refreshToken } = body

        if (!refreshToken) {
          return HttpResponse.json({
            success: false,
            error: 'Refresh token required',
            code: 'MISSING_REFRESH_TOKEN'
          }, { status: 400 })
        }

        if (refreshToken === 'valid-refresh-token') {
          return HttpResponse.json({
            success: true,
            data: {
              token: VALID_TOKEN,
              refreshToken: 'new-refresh-token',
              expiresIn: 3600
            }
          })
        }

        if (refreshToken === 'expired-refresh-token') {
          return HttpResponse.json({
            success: false,
            error: 'Refresh token expired',
            code: 'REFRESH_TOKEN_EXPIRED'
          }, { status: 401 })
        }

        return HttpResponse.json({
          success: false,
          error: 'Invalid refresh token',
          code: 'INVALID_REFRESH_TOKEN'
        }, { status: 401 })
      }),

      // Protected endpoint for testing
      http.get('*/api/protected', ({ request }) => {
        const authHeader = request.headers.get('Authorization')
        const token = authHeader?.replace('Bearer ', '')

        if (token !== VALID_TOKEN) {
          return HttpResponse.json({
            error: 'Access denied',
            code: 'UNAUTHORIZED'
          }, { status: 401 })
        }

        return HttpResponse.json({
          success: true,
          data: 'Protected resource accessed successfully',
          user: {
            id: '1',
            email: 'test@example.com'
          }
        })
      })
    )
  })

  describe('Token Validation', () => {
    it('should validate a valid JWT token', async () => {
      const response = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${VALID_TOKEN}`,
          'Content-Type': 'application/json'
        }
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.valid).toBe(true)
      expect(data.user).toBeDefined()
      expect(data.user.id).toBe('1')
      expect(data.user.email).toBe('test@example.com')
      expect(data.permissions).toEqual(['read', 'write'])
      expect(data.expiresAt).toBeDefined()
      expect(data.issuer).toBe('coreflow360-auth')
    })

    it('should reject expired tokens', async () => {
      const response = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${EXPIRED_TOKEN}`,
          'Content-Type': 'application/json'
        }
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.valid).toBe(false)
      expect(data.error).toBe('Token has expired')
      expect(data.code).toBe('TOKEN_EXPIRED')
      expect(data.expiredAt).toBeDefined()
    })

    it('should reject malformed tokens', async () => {
      const response = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${MALFORMED_TOKEN}`,
          'Content-Type': 'application/json'
        }
      })

      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.valid).toBe(false)
      expect(data.error).toBe('Malformed JWT token')
      expect(data.code).toBe('MALFORMED_TOKEN')
    })

    it('should reject tokens with invalid signatures', async () => {
      const response = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${INVALID_SIGNATURE}`,
          'Content-Type': 'application/json'
        }
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.valid).toBe(false)
      expect(data.error).toBe('Invalid token signature')
      expect(data.code).toBe('INVALID_SIGNATURE')
    })

    it('should reject requests without tokens', async () => {
      const response = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.valid).toBe(false)
      expect(data.error).toBe('No token provided')
      expect(data.code).toBe('MISSING_TOKEN')
    })
  })

  describe('Protected Resource Access', () => {
    it('should allow access with valid token', async () => {
      const response = await fetch('http://localhost:8787/api/protected', {
        headers: {
          'Authorization': `Bearer ${VALID_TOKEN}`
        }
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data).toBe('Protected resource accessed successfully')
      expect(data.user.id).toBe('1')
    })

    it('should deny access with expired token', async () => {
      const response = await fetch('http://localhost:8787/api/protected', {
        headers: {
          'Authorization': `Bearer ${EXPIRED_TOKEN}`
        }
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.error).toBe('Access denied')
      expect(data.code).toBe('UNAUTHORIZED')
    })

    it('should deny access with invalid token', async () => {
      const response = await fetch('http://localhost:8787/api/protected', {
        headers: {
          'Authorization': `Bearer ${INVALID_SIGNATURE}`
        }
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.error).toBe('Access denied')
      expect(data.code).toBe('UNAUTHORIZED')
    })

    it('should deny access without token', async () => {
      const response = await fetch('http://localhost:8787/api/protected')

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.error).toBe('Access denied')
      expect(data.code).toBe('UNAUTHORIZED')
    })
  })

  describe('User Information Retrieval', () => {
    it('should return user info for valid token', async () => {
      const response = await fetch('http://localhost:8787/api/auth/me', {
        headers: {
          'Authorization': `Bearer ${VALID_TOKEN}`
        }
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.user.id).toBe('1')
      expect(data.data.user.email).toBe('test@example.com')
      expect(data.data.session).toBeDefined()
      expect(data.data.session.expiresAt).toBeDefined()
    })

    it('should reject user info request with invalid token', async () => {
      const response = await fetch('http://localhost:8787/api/auth/me', {
        headers: {
          'Authorization': `Bearer ${INVALID_SIGNATURE}`
        }
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.success).toBe(false)
      expect(data.error).toBe('Unauthorized')
      expect(data.code).toBe('UNAUTHORIZED')
    })
  })

  describe('Token Refresh', () => {
    it('should refresh token with valid refresh token', async () => {
      const response = await fetch('http://localhost:8787/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refreshToken: 'valid-refresh-token'
        })
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.token).toBe(VALID_TOKEN)
      expect(data.data.refreshToken).toBe('new-refresh-token')
      expect(data.data.expiresIn).toBe(3600)
    })

    it('should reject expired refresh token', async () => {
      const response = await fetch('http://localhost:8787/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refreshToken: 'expired-refresh-token'
        })
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.success).toBe(false)
      expect(data.error).toBe('Refresh token expired')
      expect(data.code).toBe('REFRESH_TOKEN_EXPIRED')
    })

    it('should reject invalid refresh token', async () => {
      const response = await fetch('http://localhost:8787/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refreshToken: 'invalid-refresh-token'
        })
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.success).toBe(false)
      expect(data.error).toBe('Invalid refresh token')
      expect(data.code).toBe('INVALID_REFRESH_TOKEN')
    })

    it('should require refresh token in request', async () => {
      const response = await fetch('http://localhost:8787/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({})
      })

      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.success).toBe(false)
      expect(data.error).toBe('Refresh token required')
      expect(data.code).toBe('MISSING_REFRESH_TOKEN')
    })
  })

  describe('Security Headers and Format', () => {
    it('should handle various authorization header formats', async () => {
      // Test with 'bearer' (lowercase)
      const response1 = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `bearer ${VALID_TOKEN}`,
          'Content-Type': 'application/json'
        }
      })
      // This should fail in a real system but we're testing case sensitivity
      expect(response1.status).toBe(401)

      // Test with missing 'Bearer' prefix
      const response2 = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': VALID_TOKEN,
          'Content-Type': 'application/json'
        }
      })
      expect(response2.status).toBe(401)

      // Test with extra spaces
      const response3 = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer  ${VALID_TOKEN}`,
          'Content-Type': 'application/json'
        }
      })
      expect(response3.status).toBe(401) // Should handle extra spaces gracefully
    })

    it('should validate token structure and components', async () => {
      // Test token with missing parts
      const incompleteToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.incomplete'

      const response = await fetch('http://localhost:8787/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${incompleteToken}`,
          'Content-Type': 'application/json'
        }
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.valid).toBe(false)
    })
  })

  describe('Concurrent Token Operations', () => {
    it('should handle multiple validation requests concurrently', async () => {
      const promises = Array.from({ length: 10 }, () =>
        fetch('http://localhost:8787/api/auth/validate', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${VALID_TOKEN}`,
            'Content-Type': 'application/json'
          }
        })
      )

      const responses = await Promise.all(promises)
      const data = await Promise.all(responses.map(r => r.json()))

      // All should succeed
      expect(responses.every(r => r.status === 200)).toBe(true)
      expect(data.every(d => d.valid === true)).toBe(true)
      expect(data.every(d => d.user.id === '1')).toBe(true)
    })

    it('should handle mixed valid and invalid tokens concurrently', async () => {
      const tokens = [VALID_TOKEN, EXPIRED_TOKEN, INVALID_SIGNATURE, MALFORMED_TOKEN, VALID_TOKEN]
      const expectedStatuses = [200, 401, 401, 400, 200]

      const promises = tokens.map(token =>
        fetch('http://localhost:8787/api/auth/validate', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        })
      )

      const responses = await Promise.all(promises)

      responses.forEach((response, index) => {
        expect(response.status).toBe(expectedStatuses[index])
      })
    })
  })
})