/**
 * AI Service Mock Handlers
 * MSW handlers for external AI service APIs (Anthropic Claude, OpenAI, etc.)
 */

import { http, HttpResponse } from 'msw'

export const aiServiceHandlers = [
  // Anthropic Claude API mock
  http.post('https://api.anthropic.com/v1/messages', async ({ request }) => {
    const body = await request.json() as any

    // Mock different responses based on message content
    const content = body.messages?.[0]?.content || ''

    let response = 'This is a mock response from Claude.'

    if (content.includes('financial') || content.includes('budget')) {
      response = 'Based on the financial data provided, I recommend proceeding with caution. The projected ROI of 15% is within acceptable parameters for this type of investment.'
    } else if (content.includes('decision') || content.includes('analyze')) {
      response = 'After analyzing the provided information, my recommendation is to proceed with the proposed action. The risk assessment indicates a moderate level of complexity with high potential for success.'
    } else if (content.includes('workflow') || content.includes('process')) {
      response = 'The workflow optimization can be achieved through automation of the identified bottlenecks. I suggest implementing a phased approach starting with the highest impact areas.'
    }

    return HttpResponse.json({
      id: `msg_${Date.now()}`,
      type: 'message',
      role: 'assistant',
      content: [{
        type: 'text',
        text: response
      }],
      model: 'claude-3-sonnet-20240229',
      stop_reason: 'end_turn',
      stop_sequence: null,
      usage: {
        input_tokens: 150,
        output_tokens: 75
      }
    })
  }),

  // OpenAI API mock
  http.post('https://api.openai.com/v1/chat/completions', async ({ request }) => {
    const body = await request.json() as any

    const content = body.messages?.[body.messages.length - 1]?.content || ''

    let response = 'This is a mock response from OpenAI GPT.'

    if (content.includes('code') || content.includes('function')) {
      response = 'Here\'s a solution that should work for your use case:\n\n```javascript\nfunction processData(input) {\n  return input.map(item => item.value * 2);\n}\n```'
    } else if (content.includes('summary') || content.includes('summarize')) {
      response = 'Summary: The key points are efficiency improvement, cost reduction, and enhanced user experience. Implementation should be phased over 3 months.'
    }

    return HttpResponse.json({
      id: `chatcmpl-${Date.now()}`,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: body.model || 'gpt-4',
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: response
        },
        finish_reason: 'stop'
      }],
      usage: {
        prompt_tokens: 120,
        completion_tokens: 65,
        total_tokens: 185
      }
    })
  }),

  // OpenAI Embeddings mock
  http.post('https://api.openai.com/v1/embeddings', async ({ request }) => {
    const body = await request.json() as any

    // Generate mock embeddings (1536 dimensions for text-embedding-ada-002)
    const mockEmbedding = Array.from({ length: 1536 }, () => Math.random() * 2 - 1)

    return HttpResponse.json({
      object: 'list',
      data: [{
        object: 'embedding',
        index: 0,
        embedding: mockEmbedding
      }],
      model: body.model || 'text-embedding-ada-002',
      usage: {
        prompt_tokens: 8,
        total_tokens: 8
      }
    })
  }),

  // Cloudflare AI Workers mock
  http.post('https://api.cloudflare.com/client/v4/accounts/:accountId/ai/run/:model', async ({ params, request }) => {
    const { accountId, model } = params
    const body = await request.json() as any

    // Mock responses based on model type
    if (model === '@cf/meta/llama-2-7b-chat-int8') {
      return HttpResponse.json({
        result: {
          response: 'This is a mock response from Llama 2 model running on Cloudflare Workers AI.'
        },
        success: true,
        errors: [],
        messages: []
      })
    }

    if (model === '@cf/baai/bge-base-en-v1.5') {
      // Text embeddings model
      return HttpResponse.json({
        result: {
          shape: [1, 768],
          data: Array.from({ length: 768 }, () => Math.random() * 2 - 1)
        },
        success: true,
        errors: [],
        messages: []
      })
    }

    return HttpResponse.json({
      result: {
        response: 'Mock AI response'
      },
      success: true,
      errors: [],
      messages: []
    })
  }),

  // Hugging Face API mock
  http.post('https://api-inference.huggingface.co/models/:model', async ({ params, request }) => {
    const { model } = params
    const body = await request.json() as any

    if (model?.includes('sentence-transformers')) {
      // Sentence transformer embeddings
      return HttpResponse.json([
        Array.from({ length: 384 }, () => Math.random() * 2 - 1)
      ])
    }

    if (model?.includes('text-generation')) {
      return HttpResponse.json([{
        generated_text: 'This is a mock generated text from Hugging Face model.'
      }])
    }

    return HttpResponse.json({
      error: 'Model not found or not supported in mock'
    }, { status: 404 })
  }),

  // Custom AI service endpoints
  http.post('*/api/ai/chat', async ({ request }) => {
    const body = await request.json() as any

    return HttpResponse.json({
      id: `chat-${Date.now()}`,
      message: 'Mock AI chat response based on your input.',
      confidence: 0.85,
      timestamp: new Date().toISOString(),
      metadata: {
        model: 'mock-model',
        tokens: 45
      }
    })
  }),

  http.post('*/api/ai/analyze', async ({ request }) => {
    const body = await request.json() as any

    return HttpResponse.json({
      analysis: {
        sentiment: 'positive',
        confidence: 0.82,
        entities: [
          { text: 'CoreFlow360', type: 'ORGANIZATION', confidence: 0.95 },
          { text: 'Q4', type: 'DATE', confidence: 0.89 }
        ],
        keywords: ['efficiency', 'growth', 'optimization'],
        summary: 'The text indicates positive business performance with focus on operational efficiency.'
      },
      timestamp: new Date().toISOString()
    })
  }),

  http.post('*/api/ai/decision', async ({ request }) => {
    const body = await request.json() as any

    return HttpResponse.json({
      decision: {
        recommendation: 'APPROVE',
        confidence: 0.78,
        reasoning: 'Based on the provided context and historical data, this decision aligns with business objectives.',
        factors: [
          { name: 'Risk Assessment', score: 0.7, weight: 0.3 },
          { name: 'Financial Impact', score: 0.8, weight: 0.4 },
          { name: 'Strategic Alignment', score: 0.9, weight: 0.3 }
        ],
        alternatives: [
          { option: 'Delay implementation', score: 0.4 },
          { option: 'Partial implementation', score: 0.6 }
        ]
      },
      timestamp: new Date().toISOString()
    })
  }),

  // AI model health checks
  http.get('*/api/ai/models/status', () => {
    return HttpResponse.json({
      models: [
        {
          name: 'claude-3-sonnet',
          status: 'healthy',
          latency: 245,
          availability: 99.9
        },
        {
          name: 'gpt-4',
          status: 'healthy',
          latency: 189,
          availability: 99.8
        },
        {
          name: 'llama-2-7b',
          status: 'healthy',
          latency: 156,
          availability: 99.5
        }
      ],
      timestamp: new Date().toISOString()
    })
  }),

  // AI usage metrics
  http.get('*/api/ai/metrics', () => {
    return HttpResponse.json({
      usage: {
        totalRequests: 1247,
        successfulRequests: 1198,
        failedRequests: 49,
        averageLatency: 210,
        totalTokens: 156789,
        totalCost: 12.45
      },
      models: {
        'claude-3-sonnet': { requests: 567, tokens: 78432, cost: 5.67 },
        'gpt-4': { requests: 432, tokens: 65123, cost: 4.32 },
        'llama-2-7b': { requests: 248, tokens: 13234, cost: 2.46 }
      },
      period: {
        start: new Date(Date.now() - 86400000).toISOString(),
        end: new Date().toISOString()
      }
    })
  }),

  // Error simulation endpoints
  http.post('*/api/ai/error-test', () => {
    return HttpResponse.json({
      error: 'Rate limit exceeded',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: 60
    }, { status: 429 })
  }),

  http.post('*/api/ai/timeout-test', () => {
    // Simulate timeout - return after delay
    return new Promise(resolve => {
      setTimeout(() => {
        resolve(HttpResponse.json({
          error: 'Request timeout',
          code: 'TIMEOUT'
        }, { status: 408 }))
      }, 5000)
    })
  })
]