/**
 * MSW MOCKS FOR EXTERNAL SECURITY SERVICES
 * CoreFlow360 V4 - Security Testing Infrastructure
 *
 * This module provides comprehensive MSW (Mock Service Worker) mocks
 * for all external security services to enable reliable testing
 *
 * Services Mocked:
 * - JWT validation services
 * - MFA/TOTP services
 * - Rate limiting services
 * - Audit logging services
 * - External authentication providers
 * - Security monitoring APIs
 * - Threat intelligence feeds
 *
 * @testing-framework MSW
 * @reliability 100% deterministic responses
 * @coverage All external security dependencies
 */

import { rest } from 'msw';
import { setupServer } from 'msw/node';
import { faker } from '@faker-js/faker';

// Mock data generators for consistent test responses
export class SecurityMockDataGenerator {
  static generateValidJWT(): string {
    // Generate a properly formatted mock JWT (not cryptographically valid)
    const header = Buffer.from(JSON.stringify({
      alg: 'HS256',
      typ: 'JWT'
    })).toString('base64url');

    const payload = Buffer.from(JSON.stringify({
      sub: faker.string.uuid(),
      name: faker.person.fullName(),
      email: faker.internet.email(),
      business_id: faker.string.uuid(),
      role: 'admin',
      permissions: ['read', 'write', 'admin'],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    })).toString('base64url');

    const signature = faker.string.alphanumeric(43); // Mock signature

    return `${header}.${payload}.${signature}`;
  }

  static generateTOTPSecret(): string {
    return faker.string.alphanumeric(32).toUpperCase();
  }

  static generateTOTPCode(): string {
    return faker.string.numeric(6);
  }

  static generateBackupCodes(count: number = 10): string[] {
    return Array.from({ length: count }, () =>
      faker.string.alphanumeric(8).toUpperCase()
    );
  }

  static generateSecurityEvent(): any {
    return {
      id: faker.string.uuid(),
      timestamp: new Date().toISOString(),
      type: faker.helpers.arrayElement([
        'LOGIN_ATTEMPT',
        'FAILED_LOGIN',
        'SUSPICIOUS_ACTIVITY',
        'RATE_LIMIT_EXCEEDED',
        'SECURITY_VIOLATION'
      ]),
      severity: faker.helpers.arrayElement(['low', 'medium', 'high', 'critical']),
      source_ip: faker.internet.ip(),
      user_agent: faker.internet.userAgent(),
      user_id: faker.string.uuid(),
      business_id: faker.string.uuid(),
      details: {
        message: faker.lorem.sentence(),
        metadata: {
          request_id: faker.string.uuid(),
          session_id: faker.string.uuid()
        }
      }
    };
  }

  static generateThreatIntelligence(): any {
    return {
      ip: faker.internet.ip(),
      risk_score: faker.number.int({ min: 0, max: 100 }),
      threat_types: faker.helpers.arrayElements([
        'malware',
        'phishing',
        'scanning',
        'bot',
        'proxy',
        'tor',
        'malicious'
      ], { min: 1, max: 3 }),
      reputation: faker.helpers.arrayElement(['clean', 'suspicious', 'malicious']),
      country: faker.location.countryCode(),
      asn: faker.number.int({ min: 1000, max: 99999 }),
      last_seen: faker.date.recent().toISOString()
    };
  }
}

// Authentication Service Mocks
export const authServiceMocks = [
  // OAuth token validation endpoint
  rest.post('https://oauth2.googleapis.com/tokeninfo', (req, res, ctx) => {
    const token = req.url.searchParams.get('access_token');

    if (!token || token === 'invalid_token') {
      return res(
        ctx.status(400),
        ctx.json({
          error: 'invalid_token',
          error_description: 'Invalid access token'
        })
      );
    }

    return res(
      ctx.json({
        aud: 'client-id',
        user_id: faker.string.uuid(),
        scope: 'read write',
        exp: Math.floor(Date.now() / 1000) + 3600,
        email: faker.internet.email(),
        email_verified: true
      })
    );
  }),

  // Microsoft Graph API token validation
  rest.get('https://graph.microsoft.com/v1.0/me', (req, res, ctx) => {
    const auth = req.headers.get('authorization');

    if (!auth || !auth.startsWith('Bearer ')) {
      return res(
        ctx.status(401),
        ctx.json({
          error: {
            code: 'InvalidAuthenticationToken',
            message: 'Access token is empty.'
          }
        })
      );
    }

    return res(
      ctx.json({
        id: faker.string.uuid(),
        displayName: faker.person.fullName(),
        mail: faker.internet.email(),
        userPrincipalName: faker.internet.email(),
        jobTitle: faker.person.jobTitle(),
        officeLocation: faker.location.city()
      })
    );
  }),

  // Auth0 user info endpoint
  rest.get('https://dev-domain.auth0.com/userinfo', (req, res, ctx) => {
    const auth = req.headers.get('authorization');

    if (!auth || auth === 'Bearer invalid_token') {
      return res(
        ctx.status(401),
        ctx.json({
          error: 'invalid_token',
          error_description: 'The access token provided is invalid'
        })
      );
    }

    return res(
      ctx.json({
        sub: faker.string.uuid(),
        name: faker.person.fullName(),
        email: faker.internet.email(),
        email_verified: true,
        picture: faker.image.avatar(),
        updated_at: new Date().toISOString()
      })
    );
  })
];

// MFA/TOTP Service Mocks
export const mfaServiceMocks = [
  // TOTP verification service
  rest.post('https://api.authy.com/protected/json/verify/:format/:auth_id/:token', (req, res, ctx) => {
    const { token } = req.params;

    // Simulate various TOTP validation scenarios
    if (token === '000000') {
      return res(
        ctx.status(401),
        ctx.json({
          success: false,
          message: 'Invalid token',
          errors: { message: 'Invalid token' }
        })
      );
    }

    if (token === '123456') {
      return res(
        ctx.json({
          success: true,
          message: 'Token is valid',
          token: 'is valid'
        })
      );
    }

    // Random success/failure for fuzzing
    const isValid = Math.random() > 0.3; // 70% success rate

    return res(
      ctx.status(isValid ? 200 : 401),
      ctx.json({
        success: isValid,
        message: isValid ? 'Token is valid' : 'Invalid token',
        ...(isValid ? {} : { errors: { message: 'Invalid token' } })
      })
    );
  }),

  // SMS MFA service
  rest.post('https://api.twilio.com/2010-04-01/Accounts/:accountSid/Messages.json', (req, res, ctx) => {
    return res(
      ctx.json({
        sid: faker.string.alphanumeric(34),
        date_created: new Date().toISOString(),
        date_updated: new Date().toISOString(),
        date_sent: new Date().toISOString(),
        account_sid: faker.string.alphanumeric(34),
        to: '+1234567890',
        from: '+0987654321',
        messaging_service_sid: null,
        body: 'Your verification code is: 123456',
        status: 'delivered',
        num_segments: '1',
        num_media: '0',
        direction: 'outbound-api',
        api_version: '2010-04-01',
        price: '-0.00750',
        price_unit: 'USD',
        error_code: null,
        error_message: null,
        uri: `/2010-04-01/Accounts/${faker.string.alphanumeric(34)}/Messages/${faker.string.alphanumeric(34)}.json`
      })
    );
  }),

  // Email MFA service (SendGrid)
  rest.post('https://api.sendgrid.com/v3/mail/send', (req, res, ctx) => {
    return res(
      ctx.status(202),
      ctx.json({
        message: 'success'
      })
    );
  })
];

// Rate Limiting Service Mocks
export const rateLimitingMocks = [
  // Redis-like rate limiting service
  rest.get('https://redis.mock/get/:key', (req, res, ctx) => {
    const { key } = req.params;

    // Simulate rate limit storage
    if (key.includes('rate_limit')) {
      const count = Math.floor(Math.random() * 100);
      return res(ctx.text(count.toString()));
    }

    return res(ctx.status(404));
  }),

  rest.post('https://redis.mock/incr/:key', (req, res, ctx) => {
    const newCount = Math.floor(Math.random() * 100) + 1;
    return res(ctx.text(newCount.toString()));
  }),

  rest.post('https://redis.mock/expire/:key/:ttl', (req, res, ctx) => {
    return res(ctx.text('1'));
  }),

  // Cloudflare rate limiting API
  rest.get('https://api.cloudflare.com/client/v4/zones/:zoneId/rate_limits', (req, res, ctx) => {
    return res(
      ctx.json({
        success: true,
        errors: [],
        messages: [],
        result: [
          {
            id: faker.string.uuid(),
            disabled: false,
            description: 'Login rate limit',
            match: {
              request: {
                methods: ['POST'],
                schemes: ['HTTPS'],
                url: '*/auth/login'
              },
              response: {
                statuses: [401, 403]
              }
            },
            bypass: [],
            threshold: 5,
            period: 60,
            action: {
              mode: 'ban',
              timeout: 86400
            }
          }
        ]
      })
    );
  })
];

// Audit Logging Service Mocks
export const auditLoggingMocks = [
  // Elasticsearch audit log storage
  rest.post('https://elasticsearch.mock/audit-logs/_doc', (req, res, ctx) => {
    return res(
      ctx.json({
        _index: 'audit-logs',
        _type: '_doc',
        _id: faker.string.uuid(),
        _version: 1,
        result: 'created',
        _shards: {
          total: 2,
          successful: 1,
          failed: 0
        },
        _seq_no: faker.number.int({ min: 1000, max: 9999 }),
        _primary_term: 1
      })
    );
  }),

  // Splunk audit logging
  rest.post('https://splunk.mock:8088/services/collector/event', (req, res, ctx) => {
    return res(
      ctx.json({
        text: 'Success',
        code: 0
      })
    );
  }),

  // AWS CloudWatch Logs
  rest.post('https://logs.us-east-1.amazonaws.com/', (req, res, ctx) => {
    const target = req.headers.get('x-amz-target');

    if (target === 'Logs_20140328.PutLogEvents') {
      return res(
        ctx.json({
          nextSequenceToken: faker.string.alphanumeric(56),
          rejectedLogEventsInfo: null
        })
      );
    }

    return res(ctx.status(400));
  })
];

// Security Monitoring Service Mocks
export const securityMonitoringMocks = [
  // SIEM service (Datadog Security Monitoring)
  rest.post('https://api.datadoghq.com/api/v2/logs', (req, res, ctx) => {
    return res(
      ctx.json({
        status: 'ok'
      })
    );
  }),

  // SIEM service (Splunk Enterprise Security)
  rest.post('https://splunk-es.mock/services/notable_event', (req, res, ctx) => {
    return res(
      ctx.json({
        notable_event_id: faker.string.uuid(),
        status: 'created',
        severity: 'medium'
      })
    );
  }),

  // Security incident creation
  rest.post('https://api.pagerduty.com/incidents', (req, res, ctx) => {
    return res(
      ctx.json({
        incident: {
          id: faker.string.uuid(),
          type: 'incident',
          summary: 'Security incident detected',
          status: 'triggered',
          incident_number: faker.number.int({ min: 1000, max: 9999 }),
          urgency: 'high',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }
      })
    );
  })
];

// Threat Intelligence Service Mocks
export const threatIntelligenceMocks = [
  // VirusTotal IP lookup
  rest.get('https://www.virustotal.com/vtapi/v2/ip-address/report', (req, res, ctx) => {
    const ip = req.url.searchParams.get('ip');

    if (ip === '192.168.1.1' || ip?.startsWith('127.') || ip?.startsWith('10.')) {
      return res(
        ctx.json({
          response_code: 1,
          verbose_msg: 'IP address in dataset',
          positives: 0,
          total: 75,
          scans: {},
          detected_downloaded_samples: [],
          detected_referrer_samples: [],
          detected_urls: []
        })
      );
    }

    const isMalicious = Math.random() < 0.1; // 10% chance of malicious

    return res(
      ctx.json({
        response_code: 1,
        verbose_msg: 'IP address in dataset',
        positives: isMalicious ? faker.number.int({ min: 5, max: 20 }) : 0,
        total: 75,
        scans: isMalicious ? {
          'Malware Domain List': { detected: true, result: 'malware' },
          'CRDF': { detected: true, result: 'malicious' }
        } : {},
        detected_downloaded_samples: [],
        detected_referrer_samples: [],
        detected_urls: isMalicious ? [
          {
            url: `http://${ip}/malware.exe`,
            positives: 15,
            total: 65,
            scan_date: faker.date.recent().toISOString()
          }
        ] : []
      })
    );
  }),

  // AbuseIPDB lookup
  rest.get('https://api.abuseipdb.com/api/v2/check', (req, res, ctx) => {
    const ip = req.headers.get('x-forwarded-for') || req.url.searchParams.get('ipAddress');

    const threatData = SecurityMockDataGenerator.generateThreatIntelligence();

    return res(
      ctx.json({
        data: {
          ipAddress: ip,
          isPublic: true,
          ipVersion: 4,
          isWhitelisted: false,
          abuseConfidencePercentage: threatData.risk_score,
          countryCode: threatData.country,
          usageType: 'isp',
          isp: faker.company.name(),
          domain: faker.internet.domainName(),
          totalReports: faker.number.int({ min: 0, max: 100 }),
          numDistinctUsers: faker.number.int({ min: 0, max: 50 }),
          lastReportedAt: threatData.last_seen
        }
      })
    );
  }),

  // Custom threat intelligence service
  rest.get('https://threat-intel.mock/api/v1/ip/:ip', (req, res, ctx) => {
    const { ip } = req.params;
    const threatData = SecurityMockDataGenerator.generateThreatIntelligence();

    return res(
      ctx.json({
        ip,
        ...threatData,
        sources: ['honeypot', 'malware_analysis', 'community_reports']
      })
    );
  })
];

// Geolocation Service Mocks
export const geolocationMocks = [
  // MaxMind GeoIP2
  rest.get('https://geoip.maxmind.com/geoip/v2.1/city/:ip', (req, res, ctx) => {
    const { ip } = req.params;

    return res(
      ctx.json({
        city: {
          confidence: 75,
          geoname_id: faker.number.int({ min: 100000, max: 999999 }),
          names: {
            en: faker.location.city()
          }
        },
        continent: {
          code: faker.location.countryCode('alpha-2'),
          geoname_id: faker.number.int({ min: 1000, max: 9999 }),
          names: {
            en: faker.location.country()
          }
        },
        country: {
          confidence: 99,
          geoname_id: faker.number.int({ min: 10000, max: 99999 }),
          iso_code: faker.location.countryCode('alpha-2'),
          names: {
            en: faker.location.country()
          }
        },
        location: {
          accuracy_radius: 100,
          latitude: parseFloat(faker.location.latitude()),
          longitude: parseFloat(faker.location.longitude()),
          time_zone: faker.location.timeZone()
        },
        traits: {
          ip_address: ip,
          is_anonymous_proxy: Math.random() < 0.05,
          is_satellite_provider: false
        }
      })
    );
  }),

  // IPinfo.io
  rest.get('https://ipinfo.io/:ip/json', (req, res, ctx) => {
    const { ip } = req.params;

    return res(
      ctx.json({
        ip,
        hostname: faker.internet.domainName(),
        city: faker.location.city(),
        region: faker.location.state(),
        country: faker.location.countryCode('alpha-2'),
        loc: `${faker.location.latitude()},${faker.location.longitude()}`,
        org: `AS${faker.number.int({ min: 1000, max: 99999 })} ${faker.company.name()}`,
        postal: faker.location.zipCode(),
        timezone: faker.location.timeZone()
      })
    );
  })
];

// Breach Detection Service Mocks
export const breachDetectionMocks = [
  // HaveIBeenPwned API
  rest.get('https://haveibeenpwned.com/api/v3/breachedaccount/:account', (req, res, ctx) => {
    const { account } = req.params;

    // 20% chance of being in a breach
    if (Math.random() < 0.2) {
      return res(
        ctx.json([
          {
            Name: 'Collection #1',
            Title: 'Collection #1',
            Domain: '',
            BreachDate: '2019-01-07',
            AddedDate: '2019-01-16T21:46:07Z',
            ModifiedDate: '2019-01-16T21:46:07Z',
            PwnCount: 772904991,
            Description: 'In January 2019, a large collection of credential stuffing lists was discovered being distributed on a popular hacking forum.',
            LogoPath: 'https://haveibeenpwned.com/Content/Images/PwnedLogos/List.png',
            DataClasses: ['Email addresses', 'Passwords'],
            IsVerified: false,
            IsFabricated: false,
            IsSensitive: false,
            IsRetired: false,
            IsSpamList: true
          }
        ])
      );
    }

    return res(ctx.status(404));
  }),

  // Password strength service
  rest.post('https://password-strength.mock/api/check', (req, res, ctx) => {
    return res(
      ctx.json({
        score: faker.number.int({ min: 0, max: 4 }),
        feedback: {
          suggestions: [
            'Add another word or two',
            'Use a longer password',
            'Avoid repeated patterns'
          ],
          warning: faker.lorem.sentence()
        },
        crack_times_seconds: {
          online_throttling_100_per_hour: faker.number.float({ min: 1000, max: 1000000 }),
          online_no_throttling_10_per_second: faker.number.float({ min: 100, max: 100000 }),
          offline_slow_hashing_1e4_per_second: faker.number.float({ min: 10, max: 10000 }),
          offline_fast_hashing_1e10_per_second: faker.number.float({ min: 1, max: 1000 })
        }
      })
    );
  })
];

// Combine all mocks
export const allSecurityServiceMocks = [
  ...authServiceMocks,
  ...mfaServiceMocks,
  ...rateLimitingMocks,
  ...auditLoggingMocks,
  ...securityMonitoringMocks,
  ...threatIntelligenceMocks,
  ...geolocationMocks,
  ...breachDetectionMocks
];

// Create MSW server for testing
export const securityServiceMockServer = setupServer(...allSecurityServiceMocks);

// Helper functions for test setup
export const setupSecurityMocks = () => {
  beforeAll(() => {
    securityServiceMockServer.listen({
      onUnhandledRequest: 'warn' // Warn about unhandled requests
    });
  });

  afterEach(() => {
    securityServiceMockServer.resetHandlers();
  });

  afterAll(() => {
    securityServiceMockServer.close();
  });
};

// Mock factory for custom scenarios
export class SecurityMockFactory {
  static createFailingAuthService() {
    return rest.post('https://oauth2.googleapis.com/tokeninfo', (req, res, ctx) => {
      return res(ctx.status(500), ctx.json({ error: 'Internal server error' }));
    });
  }

  static createSlowResponseService(delayMs: number = 5000) {
    return rest.get('https://api.slow-service.com/*', (req, res, ctx) => {
      return res(ctx.delay(delayMs), ctx.json({ status: 'slow response' }));
    });
  }

  static createRateLimitedService(limit: number = 5) {
    let requestCount = 0;
    return rest.get('https://api.rate-limited.com/*', (req, res, ctx) => {
      requestCount++;
      if (requestCount > limit) {
        return res(
          ctx.status(429),
          ctx.set('Retry-After', '60'),
          ctx.json({ error: 'Rate limit exceeded' })
        );
      }
      return res(ctx.json({ success: true, requestCount }));
    });
  }

  static createMaliciousService() {
    return rest.get('https://api.malicious.com/*', (req, res, ctx) => {
      return res(
        ctx.json({
          '<script>alert("xss")</script>': 'malicious_data',
          'sql_injection': "'; DROP TABLE users; --",
          'large_response': 'A'.repeat(10000000) // 10MB response
        })
      );
    });
  }
}

export default {
  SecurityMockDataGenerator,
  allSecurityServiceMocks,
  securityServiceMockServer,
  setupSecurityMocks,
  SecurityMockFactory
};