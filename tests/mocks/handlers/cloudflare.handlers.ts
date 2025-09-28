/**
 * Cloudflare Workers Environment Mock Handlers
 * MSW handlers for Cloudflare-specific APIs and environment
 */

import { http, HttpResponse } from 'msw'

export const cloudflareHandlers = [
  // Cloudflare Workers KV mock
  http.get('*/kv/:namespace/:key', ({ params }) => {
    const { namespace, key } = params

    // Mock KV responses based on key patterns
    const mockData = {
      'user-session': { userId: 'user-123', expiresAt: Date.now() + 3600000 },
      'cache-key': { data: 'cached-value', timestamp: Date.now() },
      'config': { environment: 'test', version: '1.0.0' }
    }

    return HttpResponse.json({
      value: mockData[key as keyof typeof mockData] || null,
      metadata: {
        namespace,
        key,
        timestamp: new Date().toISOString()
      }
    })
  }),

  http.put('*/kv/:namespace/:key', async ({ params, request }) => {
    const { namespace, key } = params
    const body = await request.json()

    return HttpResponse.json({
      success: true,
      namespace,
      key,
      value: body,
      timestamp: new Date().toISOString()
    })
  }),

  http.delete('*/kv/:namespace/:key', ({ params }) => {
    const { namespace, key } = params

    return HttpResponse.json({
      success: true,
      namespace,
      key,
      deleted: true,
      timestamp: new Date().toISOString()
    })
  }),

  // Cloudflare D1 Database mock
  http.post('*/d1/:database/query', async ({ params, request }) => {
    const { database } = params
    const body = await request.json() as any

    // Mock different query responses based on SQL
    const sql = body.sql?.toLowerCase() || ''

    if (sql.includes('select') && sql.includes('users')) {
      return HttpResponse.json({
        success: true,
        results: [
          {
            id: '1',
            email: 'test@example.com',
            name: 'Test User',
            created_at: new Date().toISOString()
          }
        ],
        meta: {
          duration: 12.5,
          rows_read: 1,
          rows_written: 0
        }
      })
    }

    if (sql.includes('insert') || sql.includes('update') || sql.includes('delete')) {
      return HttpResponse.json({
        success: true,
        results: [],
        meta: {
          duration: 8.3,
          rows_read: 0,
          rows_written: 1,
          last_row_id: 123
        }
      })
    }

    return HttpResponse.json({
      success: true,
      results: [],
      meta: {
        duration: 2.1,
        rows_read: 0,
        rows_written: 0
      }
    })
  }),

  // Cloudflare Durable Objects mock
  http.get('*/durable-objects/:namespace/:id', ({ params }) => {
    const { namespace, id } = params

    return HttpResponse.json({
      id,
      namespace,
      state: {
        initialized: true,
        lastActivity: new Date().toISOString(),
        memoryUsage: 1024 * 1024 * 2.5 // 2.5MB
      },
      metadata: {
        createdAt: new Date(Date.now() - 86400000).toISOString(),
        requests: 47
      }
    })
  }),

  http.post('*/durable-objects/:namespace/:id/invoke', async ({ params, request }) => {
    const { namespace, id } = params
    const body = await request.json() as any

    // Mock method invocation responses
    const method = body.method || 'process'

    return HttpResponse.json({
      success: true,
      method,
      objectId: id,
      namespace,
      result: {
        processed: true,
        timestamp: new Date().toISOString(),
        data: body.data || {}
      }
    })
  }),

  // Cloudflare Workers Analytics mock
  http.get('*/analytics/workers/:script', ({ params }) => {
    const { script } = params

    return HttpResponse.json({
      data: {
        viewer: {
          zones: [{
            httpRequests1dGroups: [{
              date: new Date().toISOString().split('T')[0],
              requests: 1247,
              errors: 12,
              bandwidth: 1024 * 1024 * 45.6
            }]
          }]
        }
      }
    })
  }),

  // Cloudflare R2 Object Storage mock
  http.get('*/r2/:bucket/:key', ({ params }) => {
    const { bucket, key } = params

    // Mock file content based on key
    if (key?.includes('.json')) {
      return HttpResponse.json({
        mockData: true,
        bucket,
        key,
        timestamp: new Date().toISOString()
      })
    }

    return new Response('Mock file content', {
      headers: {
        'Content-Type': 'text/plain',
        'ETag': '"mock-etag-123"',
        'Last-Modified': new Date().toUTCString()
      }
    })
  }),

  http.put('*/r2/:bucket/:key', async ({ params, request }) => {
    const { bucket, key } = params

    return HttpResponse.json({
      success: true,
      bucket,
      key,
      etag: '"mock-etag-456"',
      versionId: 'mock-version-123',
      uploaded: true,
      timestamp: new Date().toISOString()
    })
  }),

  http.delete('*/r2/:bucket/:key', ({ params }) => {
    const { bucket, key } = params

    return HttpResponse.json({
      success: true,
      bucket,
      key,
      deleted: true,
      timestamp: new Date().toISOString()
    })
  }),

  // Cloudflare Workers Environment Variables
  http.get('*/env', () => {
    return HttpResponse.json({
      NODE_ENV: 'test',
      CF_ZONE_ID: 'mock-zone-id',
      CF_ACCOUNT_ID: 'mock-account-id',
      ENVIRONMENT: 'test',
      DATABASE_URL: 'mock://test-db',
      KV_NAMESPACE: 'mock-kv',
      timestamp: new Date().toISOString()
    })
  }),

  // Cloudflare Edge locations mock
  http.get('*/edge/locations', () => {
    return HttpResponse.json({
      locations: [
        {
          colo: 'SJC',
          name: 'San Jose',
          country: 'US',
          region: 'North America'
        },
        {
          colo: 'LHR',
          name: 'London',
          country: 'GB',
          region: 'Europe'
        }
      ],
      current: {
        colo: 'SJC',
        name: 'San Jose',
        country: 'US'
      }
    })
  }),

  // Cloudflare Trace mock (cf-ray, etc.)
  http.get('*/cdn-cgi/trace', () => {
    return new Response([
      'fl=1f1',
      'h=cloudflare.com',
      'ip=203.0.113.1',
      'ts=1640995200.123',
      'visit_scheme=https',
      'uag=Mock-User-Agent',
      'colo=SJC',
      'sliver=none',
      'http=http/2',
      'loc=US',
      'tls=TLSv1.3',
      'sni=plaintext',
      'warp=off',
      'gateway=off',
      'rbi=off',
      'kex=X25519'
    ].join('\n'), {
      headers: {
        'Content-Type': 'text/plain'
      }
    })
  }),

  // Cloudflare Workers Limits mock
  http.get('*/limits', () => {
    return HttpResponse.json({
      cpu: {
        used: 12.5,
        limit: 50,
        unit: 'ms'
      },
      memory: {
        used: 1024 * 1024 * 2.1,
        limit: 1024 * 1024 * 128,
        unit: 'bytes'
      },
      subrequests: {
        used: 3,
        limit: 50,
        unit: 'count'
      }
    })
  })
]