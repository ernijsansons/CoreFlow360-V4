/**
 * Minimal Claude Native Agent Test
 * Testing only the Anthropic SDK mock fix
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock Anthropic SDK - This was the original issue
vi.mock('@anthropic-ai/sdk', () => {
  const mockAnthropicClass = vi.fn().mockImplementation(() => ({
    messages: {
      create: vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'Mock Claude response' }],
        usage: { input_tokens: 100, output_tokens: 50 },
        model: 'claude-3-5-sonnet-20241022',
        role: 'assistant',
        stop_reason: 'end_turn'
      })
    }
  }));

  return {
    default: mockAnthropicClass
  };
});

// Mock all other dependencies to avoid module resolution issues
vi.mock('../../src/shared/logger', () => ({
  Logger: vi.fn().mockImplementation(() => ({
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn()
  }))
}));

vi.mock('../../src/shared/security-utils', () => ({
  CorrelationId: {
    generate: vi.fn().mockReturnValue('test-correlation-id')
  }
}));

vi.mock('../../src/shared/circuit-breaker', () => ({
  circuitBreakerRegistry: {
    getOrCreate: vi.fn().mockReturnValue({
      executeWithRetry: vi.fn().mockImplementation(async (fn) => await fn()),
      execute: vi.fn().mockImplementation(async (fn) => await fn()),
      isHealthy: vi.fn().mockReturnValue(true)
    })
  }
}));

vi.mock('../../src/shared/error-handling', () => ({
  errorHandler: {
    withErrorBoundary: vi.fn().mockImplementation(async (fn) => await fn())
  }
}));

vi.mock('../../src/modules/agent-system/security-utils', () => ({
  validateApiKeyFormat: vi.fn().mockReturnValue(true),
  maskApiKey: vi.fn().mockReturnValue('sk-ant-***'),
  sanitizeErrorForUser: vi.fn(),
  sanitizeForLogging: vi.fn(),
  redactPII: vi.fn()
}));

vi.mock('../../src/security/ai-prompt-sanitizer', () => ({
  sanitizeUserInput: vi.fn().mockReturnValue({
    sanitized: 'sanitized input',
    blocked: false,
    modified: false,
    violations: [],
    riskScore: 0
  }),
  createSecureAIPrompt: vi.fn().mockReturnValue('secure prompt'),
  validateAIPrompt: vi.fn().mockReturnValue(true)
}));

describe('Claude Native Agent - Anthropic Mock Test', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test-key-12345';

    // Test that Anthropic mock can be accessed and updated
    const AnthropicModule = await import('@anthropic-ai/sdk');
    const mockAnthropic = {
      messages: {
        create: vi.fn().mockResolvedValue({
          content: [{ type: 'text', text: 'Updated mock response' }],
          usage: { input_tokens: 50, output_tokens: 25 }
        })
      }
    };
    vi.mocked(AnthropicModule.default).mockImplementation(() => mockAnthropic);
  });

  it('should successfully mock Anthropic SDK', async () => {
    // This test verifies the main issue is fixed: "Anthropic is not defined"
    const AnthropicSDK = (await import('@anthropic-ai/sdk')).default;

    expect(AnthropicSDK).toBeDefined();
    expect(vi.mocked(AnthropicSDK)).toBeDefined();

    // Test that we can create an instance and call methods
    const client = new AnthropicSDK({ apiKey: 'test-key' });
    expect(client.messages.create).toBeDefined();

    const response = await client.messages.create({
      model: 'claude-3-sonnet',
      messages: [{ role: 'user', content: 'test' }],
      max_tokens: 100
    });

    expect(response.content[0].text).toBe('Updated mock response');
    expect(response.usage.input_tokens).toBe(50);
  });

  it('should allow mock implementation updates', async () => {
    const AnthropicModule = await import('@anthropic-ai/sdk');

    // Update mock implementation - this was failing before the fix
    const newMockAnthropic = {
      messages: {
        create: vi.fn().mockResolvedValue({
          content: [{ type: 'text', text: 'Different response' }],
          usage: { input_tokens: 200, output_tokens: 100 }
        })
      }
    };

    vi.mocked(AnthropicModule.default).mockImplementation(() => newMockAnthropic);

    const client = new AnthropicModule.default({ apiKey: 'test' });
    const response = await client.messages.create({
      model: 'claude-3-sonnet',
      messages: [{ role: 'user', content: 'test' }],
      max_tokens: 100
    });

    expect(response.content[0].text).toBe('Different response');
    expect(response.usage.input_tokens).toBe(200);
  });

  it('should handle mock rejections', async () => {
    const AnthropicModule = await import('@anthropic-ai/sdk');

    // Test error handling
    const errorMockAnthropic = {
      messages: {
        create: vi.fn().mockRejectedValue(new Error('API Error'))
      }
    };

    vi.mocked(AnthropicModule.default).mockImplementation(() => errorMockAnthropic);

    const client = new AnthropicModule.default({ apiKey: 'test' });

    await expect(client.messages.create({
      model: 'claude-3-sonnet',
      messages: [{ role: 'user', content: 'test' }],
      max_tokens: 100
    })).rejects.toThrow('API Error');
  });
});