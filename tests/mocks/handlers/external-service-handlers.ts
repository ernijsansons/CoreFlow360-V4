/**
 * External Service MSW Handlers
 * Mocking for third-party services and APIs
 */

import { http, HttpResponse } from 'msw'

export const externalServiceHandlers = [
  // Anthropic AI API
  http.post('https://api.anthropic.com/v1/messages', () => {
    return HttpResponse.json({
      id: 'msg_mock_123',
      type: 'message',
      role: 'assistant',
      content: [
        {
          type: 'text',
          text: 'This is a mock response from Claude API'
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
  }),

  // OpenAI API
  http.post('https://api.openai.com/v1/chat/completions', () => {
    return HttpResponse.json({
      id: 'chatcmpl-mock-123',
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: 'gpt-4',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: 'This is a mock response from OpenAI API'
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
  }),

  // Cloudflare AI API
  http.post('https://api.cloudflare.com/client/v4/accounts/:accountId/ai/run/:model', () => {
    return HttpResponse.json({
      success: true,
      result: {
        response: 'This is a mock response from Cloudflare AI'
      }
    })
  }),

  // Stripe API
  http.post('https://api.stripe.com/v1/payment_intents', () => {
    return HttpResponse.json({
      id: 'pi_mock_payment_intent',
      object: 'payment_intent',
      amount: 2000,
      currency: 'usd',
      status: 'requires_payment_method',
      client_secret: 'pi_mock_payment_intent_secret_abc123'
    })
  }),

  http.get('https://api.stripe.com/v1/payment_intents/:id', ({ params }) => {
    const { id } = params
    return HttpResponse.json({
      id,
      object: 'payment_intent',
      amount: 2000,
      currency: 'usd',
      status: 'succeeded'
    })
  }),

  http.post('https://api.stripe.com/v1/customers', () => {
    return HttpResponse.json({
      id: 'cus_mock_customer',
      object: 'customer',
      email: 'test@example.com',
      name: 'Test Customer'
    })
  }),

  // Plaid API
  http.post('https://production.plaid.com/link/token/create', () => {
    return HttpResponse.json({
      link_token: 'link-development-mock-token',
      expiration: new Date(Date.now() + 3600000).toISOString(),
      request_id: 'mock-request-id'
    })
  }),

  http.post('https://production.plaid.com/item/public_token/exchange', () => {
    return HttpResponse.json({
      access_token: 'access-development-mock-token',
      item_id: 'mock-item-id',
      request_id: 'mock-request-id'
    })
  }),

  http.post('https://production.plaid.com/accounts/get', () => {
    return HttpResponse.json({
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
    })
  }),

  // Twilio API
  http.post('https://api.twilio.com/2010-04-01/Accounts/:accountSid/Messages.json', () => {
    return HttpResponse.json({
      sid: 'SM_mock_message_sid',
      account_sid: 'AC_mock_account_sid',
      from: '+15551234567',
      to: '+15559876543',
      body: 'Test message',
      status: 'sent',
      date_created: new Date().toISOString()
    })
  }),

  http.post('https://api.twilio.com/2010-04-01/Accounts/:accountSid/Calls.json', () => {
    return HttpResponse.json({
      sid: 'CA_mock_call_sid',
      account_sid: 'AC_mock_account_sid',
      from: '+15551234567',
      to: '+15559876543',
      status: 'queued',
      date_created: new Date().toISOString()
    })
  }),

  // SendGrid API
  http.post('https://api.sendgrid.com/v3/mail/send', () => {
    return HttpResponse.json(
      {},
      { status: 202 }
    )
  }),

  // Database Services (D1, KV, R2 simulation)
  http.get('https://*.cloudflarestorage.com/*', () => {
    return HttpResponse.json({
      success: true,
      result: {
        key: 'mock-key',
        value: 'mock-value',
        metadata: {}
      }
    })
  }),

  http.put('https://*.cloudflarestorage.com/*', () => {
    return HttpResponse.json({
      success: true,
      result: {
        operation: 'put',
        key: 'mock-key'
      }
    })
  }),

  // Error simulation endpoints
  http.get('https://api.example.com/error/500', () => {
    return HttpResponse.json(
      { error: 'Internal Server Error' },
      { status: 500 }
    )
  }),

  http.get('https://api.example.com/error/timeout', () => {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(HttpResponse.json({ error: 'Timeout' }, { status: 408 }))
      }, 30000) // 30 second timeout
    })
  }),

  // Rate limiting simulation
  http.get('https://api.example.com/rate-limited', () => {
    return HttpResponse.json(
      { error: 'Rate limit exceeded' },
      {
        status: 429,
        headers: {
          'Retry-After': '60'
        }
      }
    )
  })
]