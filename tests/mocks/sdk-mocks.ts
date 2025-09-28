/**
 * SDK and Library Mocks
 * Comprehensive mocking for external SDKs and libraries
 */

import { vi } from 'vitest'

// Mock Anthropic SDK
export const mockAnthropic = {
  messages: {
    create: vi.fn().mockResolvedValue({
      id: 'msg_mock_123',
      type: 'message',
      role: 'assistant',
      content: [
        {
          type: 'text',
          text: 'This is a mock response from Claude'
        }
      ],
      model: 'claude-3-sonnet-20240229',
      stop_reason: 'end_turn',
      stop_sequence: null,
      usage: {
        input_tokens: 25,
        output_tokens: 15
      }
    })
  }
}

// Mock OpenAI SDK
export const mockOpenAI = {
  chat: {
    completions: {
      create: vi.fn().mockResolvedValue({
        id: 'chatcmpl-mock-123',
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: 'gpt-4',
        choices: [
          {
            index: 0,
            message: {
              role: 'assistant',
              content: 'This is a mock response from OpenAI'
            },
            finish_reason: 'stop'
          }
        ],
        usage: {
          prompt_tokens: 20,
          completion_tokens: 12,
          total_tokens: 32
        }
      })
    }
  }
}

// Mock Stripe SDK
export const mockStripe = {
  paymentIntents: {
    create: vi.fn().mockResolvedValue({
      id: 'pi_mock_payment_intent',
      object: 'payment_intent',
      amount: 2000,
      currency: 'usd',
      status: 'requires_payment_method',
      client_secret: 'pi_mock_payment_intent_secret_abc123'
    }),
    retrieve: vi.fn().mockResolvedValue({
      id: 'pi_mock_payment_intent',
      object: 'payment_intent',
      amount: 2000,
      currency: 'usd',
      status: 'succeeded'
    }),
    update: vi.fn().mockResolvedValue({
      id: 'pi_mock_payment_intent',
      object: 'payment_intent',
      amount: 2000,
      currency: 'usd',
      status: 'succeeded'
    })
  },
  customers: {
    create: vi.fn().mockResolvedValue({
      id: 'cus_mock_customer',
      object: 'customer',
      email: 'test@example.com',
      name: 'Test Customer'
    }),
    retrieve: vi.fn().mockResolvedValue({
      id: 'cus_mock_customer',
      object: 'customer',
      email: 'test@example.com',
      name: 'Test Customer'
    })
  },
  webhooks: {
    constructEvent: vi.fn().mockReturnValue({
      id: 'evt_mock_event',
      object: 'event',
      type: 'payment_intent.succeeded',
      data: {
        object: {
          id: 'pi_mock_payment_intent',
          status: 'succeeded'
        }
      }
    })
  }
}

// Mock Plaid SDK
export const mockPlaid = {
  linkTokenCreate: vi.fn().mockResolvedValue({
    data: {
      link_token: 'link-development-mock-token',
      expiration: new Date(Date.now() + 3600000).toISOString(),
      request_id: 'mock-request-id'
    }
  }),
  itemPublicTokenExchange: vi.fn().mockResolvedValue({
    data: {
      access_token: 'access-development-mock-token',
      item_id: 'mock-item-id',
      request_id: 'mock-request-id'
    }
  }),
  accountsGet: vi.fn().mockResolvedValue({
    data: {
      accounts: [
        {
          account_id: 'mock-account-1',
          balances: {
            available: 5000.00,
            current: 5000.00,
            iso_currency_code: 'USD'
          },
          name: 'Business Checking',
          official_name: 'Business Checking Account',
          type: 'depository',
          subtype: 'checking'
        }
      ],
      item: {
        item_id: 'mock-item-id',
        institution_id: 'ins_mock_1'
      },
      request_id: 'mock-request-id'
    }
  })
}

// Mock Twilio SDK
export const mockTwilio = {
  messages: {
    create: vi.fn().mockResolvedValue({
      sid: 'SM_mock_message_sid',
      accountSid: 'AC_mock_account_sid',
      from: '+15551234567',
      to: '+15559876543',
      body: 'Test message',
      status: 'sent',
      dateCreated: new Date()
    })
  },
  calls: {
    create: vi.fn().mockResolvedValue({
      sid: 'CA_mock_call_sid',
      accountSid: 'AC_mock_account_sid',
      from: '+15551234567',
      to: '+15559876543',
      status: 'queued',
      dateCreated: new Date()
    })
  }
}

// Mock Cloudflare AI
export const mockCloudflareAI = {
  run: vi.fn().mockResolvedValue({
    success: true,
    result: {
      response: 'This is a mock response from Cloudflare AI'
    }
  })
}

// Mock Circuit Breaker
export const mockCircuitBreaker = {
  fire: vi.fn().mockResolvedValue('mock-result'),
  close: vi.fn(),
  open: vi.fn(),
  fallback: vi.fn().mockReturnValue('fallback-result'),
  on: vi.fn(),
  state: 'CLOSED',
  stats: {
    successful: 0,
    failed: 0,
    timeout: 0,
    rejected: 0
  }
}

// Mock Logger
export const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn()
}

// Mock Database Connection
export const mockDatabase = {
  prepare: vi.fn().mockReturnValue({
    bind: vi.fn().mockReturnThis(),
    run: vi.fn().mockResolvedValue({ success: true }),
    get: vi.fn().mockResolvedValue({ id: 1, name: 'test' }),
    all: vi.fn().mockResolvedValue([{ id: 1, name: 'test' }]),
    first: vi.fn().mockResolvedValue({ id: 1, name: 'test' })
  }),
  exec: vi.fn().mockResolvedValue({ success: true }),
  transaction: vi.fn().mockImplementation((callback) => callback(mockDatabase))
}

// Mock KV Storage
export const mockKV = {
  get: vi.fn().mockResolvedValue('mock-value'),
  put: vi.fn().mockResolvedValue(undefined),
  delete: vi.fn().mockResolvedValue(undefined),
  list: vi.fn().mockResolvedValue({
    keys: [{ name: 'test-key' }],
    list_complete: true
  })
}

// Mock R2 Storage
export const mockR2 = {
  get: vi.fn().mockResolvedValue({
    body: new ReadableStream(),
    httpMetadata: { contentType: 'application/json' }
  }),
  put: vi.fn().mockResolvedValue({ etag: 'mock-etag' }),
  delete: vi.fn().mockResolvedValue(undefined),
  list: vi.fn().mockResolvedValue({
    objects: [{ key: 'test-file.json' }],
    truncated: false
  })
}

// Setup all mocks in global scope
export function setupSDKMocks() {
  // Mock Anthropic
  vi.doMock('@anthropic-ai/sdk', () => ({
    default: vi.fn().mockImplementation(() => mockAnthropic),
    Anthropic: vi.fn().mockImplementation(() => mockAnthropic)
  }))

  // Mock OpenAI
  vi.doMock('openai', () => ({
    default: vi.fn().mockImplementation(() => mockOpenAI),
    OpenAI: vi.fn().mockImplementation(() => mockOpenAI)
  }))

  // Mock Stripe
  vi.doMock('stripe', () => ({
    default: vi.fn().mockImplementation(() => mockStripe),
    Stripe: vi.fn().mockImplementation(() => mockStripe)
  }))

  // Mock Plaid
  vi.doMock('plaid', () => ({
    PlaidApi: vi.fn().mockImplementation(() => mockPlaid),
    Configuration: vi.fn(),
    PlaidEnvironments: { development: 'development', production: 'production' }
  }))

  // Mock Twilio
  vi.doMock('twilio', () => ({
    default: vi.fn().mockImplementation(() => mockTwilio),
    Twilio: vi.fn().mockImplementation(() => mockTwilio)
  }))

  // Mock other dependencies
  vi.doMock('obreaker', () => ({
    default: vi.fn().mockImplementation(() => mockCircuitBreaker)
  }))

  // Setup global mocks
  global.Anthropic = vi.fn().mockImplementation(() => mockAnthropic)
  global.OpenAI = vi.fn().mockImplementation(() => mockOpenAI)
  global.Stripe = vi.fn().mockImplementation(() => mockStripe)
}