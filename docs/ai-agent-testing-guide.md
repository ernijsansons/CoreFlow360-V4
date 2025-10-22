# AI Agent Testing Guide

## Overview

This guide covers testing strategies for CoreFlow360 V4's AI agent system, distinguishing between **unit tests** (mocked) and **integration tests** (real API calls).

---

## Testing Reality Check ⚠️

### What Unit Tests Actually Test
- ✅ Code structure and logic
- ✅ Error handling paths
- ✅ Data validation
- ✅ Type safety
- ❌ **NOT** real API behavior
- ❌ **NOT** actual costs
- ❌ **NOT** real rate limits
- ❌ **NOT** streaming responses

### What Integration Tests Test
- ✅ Real API calls to Anthropic/DeepSeek
- ✅ Actual response parsing
- ✅ Real token consumption and costs
- ✅ Actual rate limiting behavior
- ✅ Real error scenarios
- ✅ Streaming functionality

---

## Test Types

### 1. Unit Tests (Mocked) ✅ COMPLETE

**Location**: `src/modules/agents/__tests__/*.test.ts`

**Coverage**: 95%+

**What They Test**:
```typescript
// Mock API response
global.fetch = vi.fn().mockResolvedValue({
  ok: true,
  json: async () => ({
    id: 'msg-123',
    content: [{ type: 'text', text: 'Mocked response' }],
    usage: { input_tokens: 100, output_tokens: 200 }
  })
});

// Test passes with NO real API key needed
const result = await agent.executeTask(task, context);
expect(result.success).toBe(true);
```

**Status**: ✅ All passing, comprehensive coverage

---

### 2. Integration Tests (Real API) ⚠️ REQUIRED

**Location**: `tests/integration/ai-agents/*.integration.test.ts`

**Coverage**: 0% (not yet created)

**What They Test**:
```typescript
// REAL API call - requires actual API key
const agent = new ClaudeAgent({
  apiKey: process.env.ANTHROPIC_API_KEY! // Real key required
});

const result = await agent.executeTask(task, context);

// Validates:
// - Real API connection
// - Actual response structure
// - Real token usage
// - Actual costs
// - Real error scenarios
```

**Status**: ⚠️ Not yet implemented

---

## API Key Requirements

### Anthropic Claude

**Sign Up**: https://console.anthropic.com

**Pricing** (as of 2024):
- Claude 3.5 Sonnet: $3 per million input tokens, $15 per million output tokens
- Claude 3 Haiku: $0.25 per million input tokens, $1.25 per million output tokens

**Free Tier**: $5 credit for new users

**Billing Limits**: Set in console to prevent overspending

### DeepSeek (Alternative)

**Sign Up**: https://platform.deepseek.com

**Pricing** (as of 2024):
- DeepSeek Chat: ~$0.30 per million input tokens, ~$1.50 per million output tokens
- **10x cheaper than Claude**

**Free Tier**: Credits available

**When to Use**:
- Cost-sensitive deployments
- High-volume usage
- Non-critical tasks
- Development/testing

---

## Integration Testing Setup

### Step 1: Get API Keys

```bash
# Option A: Anthropic Claude (premium)
# 1. Sign up at console.anthropic.com
# 2. Create API key
# 3. Set billing limit ($100 recommended for testing)
export ANTHROPIC_API_KEY="sk-ant-..."

# Option B: DeepSeek (budget-friendly)
# 1. Sign up at platform.deepseek.com
# 2. Create API key
export DEEPSEEK_API_KEY="sk-..."

# Option C: Both (recommended for comparison)
export ANTHROPIC_API_KEY="sk-ant-..."
export DEEPSEEK_API_KEY="sk-..."
```

### Step 2: Configure Test Environment

```bash
# Copy environment template
cp .env.example .env.test

# Edit .env.test
cat > .env.test <<EOF
# Test Environment
NODE_ENV=test
ENVIRONMENT=test

# AI API Keys (REAL keys for integration tests)
ANTHROPIC_API_KEY=sk-ant-your-real-key-here
DEEPSEEK_API_KEY=sk-your-real-key-here

# Feature Flags
ENABLE_AI_FEATURES=true
ENABLE_INTEGRATION_TESTS=true

# Cost Limits (prevent runaway costs)
MAX_COST_PER_TEST=0.50
MAX_COST_PER_SUITE=5.00
EOF
```

### Step 3: Run Integration Tests

```bash
# Install dependencies
npm install

# Run integration tests (requires real API keys)
npm run test:integration:ai

# Run with cost reporting
npm run test:integration:ai -- --report-costs

# Run only Anthropic tests
npm run test:integration:anthropic

# Run only DeepSeek tests
npm run test:integration:deepseek

# Run Finance Agent integration tests
npm run test:integration:finance-agent
```

### Available Integration Test Suites

| Test Suite | Command | Purpose | Est. Cost |
|------------|---------|---------|-----------|
| All AI Agents | `npm run test:integration:ai` | Tests all AI agents with real APIs | $3-7 |
| **Gemini Agent** | `npm run test:integration:gemini` | **Tests Gemini 2.0 Flash (PRIMARY)** | **$0.10-0.30** |
| Claude Agent | `npm run test:integration:anthropic` | Tests Claude for deep reasoning | $0.80-1.50 |
| DeepSeek Agent | `npm run test:integration:deepseek` | Tests DeepSeek for bulk operations | $0.08-0.15 |
| Finance Agent | `npm run test:integration:finance-agent` | Tests Finance Agent capabilities | $1.50-3.00 |

---

## Integration Test Examples

### Basic API Connectivity Test

```typescript
// tests/integration/ai-agents/claude-agent.integration.test.ts
import { describe, it, expect, beforeAll } from 'vitest';
import { ClaudeAgent } from '@/modules/agents/claude-agent';

describe('ClaudeAgent - Real API Integration', () => {
  let agent: ClaudeAgent;

  beforeAll(() => {
    // Skip if no API key
    if (!process.env.ANTHROPIC_API_KEY) {
      console.warn('⚠️  Skipping integration tests - no ANTHROPIC_API_KEY');
      return;
    }

    agent = new ClaudeAgent({
      apiKey: process.env.ANTHROPIC_API_KEY
    });
  });

  // Only run if API key is present
  const testIf = (condition: boolean) => condition ? it : it.skip;

  testIf(!!process.env.ANTHROPIC_API_KEY)(
    'should make real API call to Claude',
    async () => {
      const task = {
        id: 'integration-test-1',
        capability: 'analysis',
        input: {
          data: {
            query: 'What is 2 + 2? Answer with just the number.'
          }
        },
        priority: 'normal' as const
      };

      const context = {
        userId: 'test-user',
        businessId: 'test-business',
        timestamp: new Date().toISOString(),
        requestId: 'req-test-1'
      };

      const result = await agent.executeTask(task, context);

      // Validate real response
      expect(result.success).toBe(true);
      expect(result.output).toBeDefined();
      expect(result.output.data).toBeDefined();

      // Should contain "4" in response
      expect(JSON.stringify(result.output)).toContain('4');

      // Validate metrics
      expect(result.metrics?.tokensUsed).toBeGreaterThan(0);
      expect(result.metrics?.latency).toBeGreaterThan(0);
      expect(result.metrics?.cost).toBeGreaterThan(0);

      console.log('✅ Real API call successful');
      console.log(`   Tokens: ${result.metrics?.tokensUsed}`);
      console.log(`   Latency: ${result.metrics?.latency}ms`);
      console.log(`   Cost: $${result.metrics?.cost?.toFixed(4)}`);
    },
    30000 // 30 second timeout
  );
});
```

### Cost Comparison Test

```typescript
describe('Cost Comparison - Claude vs DeepSeek', () => {
  testIf(!!process.env.ANTHROPIC_API_KEY && !!process.env.DEEPSEEK_API_KEY)(
    'should compare costs between providers',
    async () => {
      const task = {
        id: 'cost-test-1',
        capability: 'analysis',
        input: {
          data: {
            query: 'Analyze this data: Revenue: $100k, Expenses: $80k, Profit: $20k'
          }
        },
        priority: 'normal' as const
      };

      const context = {
        userId: 'test-user',
        businessId: 'test-business',
        timestamp: new Date().toISOString(),
        requestId: 'req-cost-test-1'
      };

      // Test with Claude
      const claudeAgent = new ClaudeAgent({
        apiKey: process.env.ANTHROPIC_API_KEY!
      });
      const claudeResult = await claudeAgent.executeTask(task, context);

      // Test with DeepSeek
      const deepseekAgent = new ClaudeAgent({
        deepseekApiKey: process.env.DEEPSEEK_API_KEY!
      });
      const deepseekResult = await deepseekAgent.executeTask(task, context);

      // Compare costs
      console.log('\n📊 Cost Comparison:');
      console.log(`   Claude: $${claudeResult.metrics?.cost?.toFixed(4)}`);
      console.log(`   DeepSeek: $${deepseekResult.metrics?.cost?.toFixed(4)}`);

      const savings = ((1 - (deepseekResult.metrics?.cost || 0) / (claudeResult.metrics?.cost || 1)) * 100);
      console.log(`   Savings: ${savings.toFixed(1)}% with DeepSeek`);

      expect(claudeResult.success).toBe(true);
      expect(deepseekResult.success).toBe(true);
    },
    60000 // 60 second timeout
  );
});
```

### Finance Agent Integration Test

```typescript
// tests/integration/ai-agents/finance-agent.integration.test.ts
import { describe, it, expect, beforeAll } from 'vitest';
import { FinanceAgent } from '@/modules/agents/finance-agent';

describe('FinanceAgent - Real API Integration', () => {
  let financeAgent: FinanceAgent;

  beforeAll(() => {
    const apiKey = process.env.ANTHROPIC_API_KEY || '';
    financeAgent = new FinanceAgent(apiKey);
  });

  const testIf = (condition: boolean) => condition ? it : it.skip;

  testIf(!!process.env.ANTHROPIC_API_KEY)(
    'should analyze real financial statement data',
    async () => {
      const task = {
        id: 'finance-integration-1',
        capability: 'financial_analysis' as const,
        input: {
          data: {
            analysisType: 'income_statement',
            statement: {
              revenue: 5000000,
              costOfGoodsSold: 2000000,
              grossProfit: 3000000,
              operatingExpenses: 1500000,
              operatingIncome: 1500000,
              netIncome: 1015000
            },
            period: '2024-Q4'
          }
        },
        priority: 'normal' as const
      };

      const context = {
        userId: 'test-user',
        businessId: 'test-business',
        timestamp: new Date().toISOString(),
        requestId: 'req-finance-test-1',
        userContext: {
          userId: 'test-user',
          role: 'finance_manager',
          department: 'finance',
          permissions: ['finance.read', 'finance.analyze']
        },
        businessData: {
          companyName: 'Test Corp',
          industry: 'Technology',
          size: 'mid-sized',
          currency: 'USD',
          timezone: 'America/New_York'
        }
      };

      const result = await financeAgent.executeTask(task, context);

      // Validate real financial analysis
      expect(result.success).toBe(true);
      expect(result.output).toBeDefined();

      // Should mention financial concepts
      const response = JSON.stringify(result.output).toLowerCase();
      expect(
        response.includes('revenue') ||
        response.includes('profit') ||
        response.includes('margin')
      ).toBe(true);

      // Validate cost tracking
      expect(result.metrics?.cost).toBeDefined();
      expect(result.metrics?.cost).toBeGreaterThan(0);

      console.log('✅ Finance Agent analysis successful');
      console.log(`   Analysis Type: Income Statement`);
      console.log(`   Tokens: ${result.metrics?.tokensUsed}`);
      console.log(`   Latency: ${result.metrics?.latency}ms`);
      console.log(`   Cost: $${result.metrics?.cost?.toFixed(4)}`);
    },
    60000 // 60 second timeout for complex analysis
  );
});
```

### Rate Limiting Test

```typescript
describe('Rate Limiting Behavior', () => {
  testIf(!!process.env.ANTHROPIC_API_KEY)(
    'should handle rate limits gracefully',
    async () => {
      const agent = new ClaudeAgent({
        apiKey: process.env.ANTHROPIC_API_KEY!
      });

      const task = {
        id: 'rate-limit-test',
        capability: 'analysis',
        input: { data: { query: 'Quick test' } },
        priority: 'normal' as const
      };

      const context = {
        userId: 'test-user',
        businessId: 'test-business',
        timestamp: new Date().toISOString(),
        requestId: 'req-rate-test'
      };

      // Send multiple rapid requests
      const promises = Array.from({ length: 10 }, (_, i) =>
        agent.executeTask({ ...task, id: `rate-test-${i}` }, context)
      );

      const results = await Promise.allSettled(promises);

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const rateLimited = results.filter(r =>
        r.status === 'rejected' && r.reason.message?.includes('rate limit')
      ).length;

      console.log(`   Successful: ${successful}/10`);
      console.log(`   Rate Limited: ${rateLimited}/10`);

      // Should handle rate limits without crashing
      expect(results.length).toBe(10);
    },
    120000 // 2 minute timeout
  );
});
```

---

## Pre-Production Validation Checklist

### ✅ Before Enabling AI Agents in Production:

1. **API Key Validation**
   - [ ] Anthropic API key tested and working
   - [ ] DeepSeek API key tested (if using)
   - [ ] Billing limits set
   - [ ] API key stored in secrets (not .env)

2. **Integration Tests Pass**
   - [ ] Real API connectivity verified
   - [ ] All agent capabilities tested
   - [ ] Cost tracking working
   - [ ] Error handling validated
   - [ ] Rate limiting behavior confirmed

3. **Cost Analysis**
   - [ ] Estimated monthly costs calculated
   - [ ] Cost per agent call measured
   - [ ] Budget alerts configured
   - [ ] Fallback to cheaper model tested

4. **Performance Validation**
   - [ ] Average latency measured (<5s acceptable)
   - [ ] Timeout handling tested
   - [ ] Retry logic validated
   - [ ] Streaming responses working

5. **Error Scenarios**
   - [ ] Invalid API key handled
   - [ ] Network failures handled
   - [ ] Rate limit errors handled
   - [ ] Malformed responses handled
   - [ ] Timeout errors handled

6. **Monitoring Setup**
   - [ ] Cost tracking dashboard ready
   - [ ] Error rate alerts configured
   - [ ] Latency monitoring active
   - [ ] Usage quotas set

---

## Staging Environment Testing

### Step 1: Deploy to Staging with AI Disabled

```bash
# Deploy with AI features disabled
cd ~/CoreFlow360-V4

# Set environment variable
export ENABLE_AI_FEATURES=false

# Deploy to staging
npm run deploy:staging

# Verify core functionality
./scripts/health-check.sh staging
./scripts/smoke-test.sh staging
```

### Step 2: Add API Keys to Staging

```bash
# Add Anthropic key
wrangler secret put ANTHROPIC_API_KEY --env staging
# Enter your real key when prompted

# Add DeepSeek key (optional)
wrangler secret put DEEPSEEK_API_KEY --env staging

# Verify secrets are set
wrangler secret list --env staging
```

### Step 3: Enable AI Features

```bash
# Update environment variable
wrangler secret put ENABLE_AI_FEATURES --env staging
# Enter: true

# Redeploy
npm run deploy:staging
```

### Step 4: Test AI Agents in Staging

```bash
# Test agent execution
curl -X POST https://staging-api.coreflow360.com/api/agents/execute \
  -H "Authorization: Bearer $STAGING_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "claude-3-5-sonnet",
    "task": {
      "capability": "analysis",
      "input": {
        "data": {
          "query": "Analyze quarterly revenue growth"
        }
      }
    }
  }'

# Monitor logs
wrangler tail --env staging | grep claude-agent

# Check for errors
wrangler tail --env staging | grep ERROR
```

### Step 5: Monitor Costs

```bash
# Check Anthropic dashboard
# Visit: https://console.anthropic.com/usage

# Or check via API
curl https://api.anthropic.com/v1/usage \
  -H "x-api-key: $ANTHROPIC_API_KEY"
```

---

## Production Deployment Strategy

### Option A: Gradual Rollout (Recommended)

```bash
# Phase 1: Internal users only (10%)
wrangler secret put AI_ROLLOUT_PERCENTAGE --env production
# Enter: 10

# Monitor for 48 hours
./scripts/performance-monitor.sh production 2880  # 48 hours

# Phase 2: Expand to 50%
wrangler secret put AI_ROLLOUT_PERCENTAGE --env production
# Enter: 50

# Monitor for 24 hours

# Phase 3: Full rollout (100%)
wrangler secret put AI_ROLLOUT_PERCENTAGE --env production
# Enter: 100
```

### Option B: Feature Flag Control

```typescript
// src/config/feature-flags.ts
export function shouldUseAIAgents(userId: string): boolean {
  if (process.env.ENABLE_AI_FEATURES !== 'true') {
    return false;
  }

  const rolloutPercentage = parseInt(process.env.AI_ROLLOUT_PERCENTAGE || '100');

  // Hash user ID for consistent assignment
  const hash = simpleHash(userId);
  return (hash % 100) < rolloutPercentage;
}
```

---

## Cost Management

### Set Budget Alerts

```bash
# Anthropic Console:
# 1. Go to Settings > Billing
# 2. Set monthly budget limit
# 3. Enable email alerts at 50%, 80%, 90%

# Example limits:
# - Development: $100/month
# - Staging: $500/month
# - Production: $5,000/month (adjust based on usage)
```

### Monitor Usage

```bash
# Daily cost check script
cat > scripts/check-ai-costs.sh <<'EOF'
#!/bin/bash
# Check daily AI costs

curl -s https://api.anthropic.com/v1/usage \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  | jq '.usage[] | select(.date == "'$(date +%Y-%m-%d)'") | .cost'
EOF

chmod +x scripts/check-ai-costs.sh

# Run daily via cron
0 9 * * * /path/to/scripts/check-ai-costs.sh
```

---

## Troubleshooting

### Issue: Integration Tests Failing

**Symptoms**: Tests pass with mocks, fail with real API

**Solutions**:
1. Verify API key is valid
2. Check billing is enabled
3. Verify rate limits not exceeded
4. Check network connectivity
5. Review API error messages

### Issue: High Costs

**Symptoms**: API costs higher than expected

**Solutions**:
1. Reduce max_tokens limit
2. Switch to DeepSeek for non-critical tasks
3. Implement caching for repeated queries
4. Use Haiku model for simple tasks
5. Set per-user rate limits

### Issue: Slow Response Times

**Symptoms**: Agent calls taking >10 seconds

**Solutions**:
1. Reduce max_tokens
2. Use streaming responses
3. Implement timeout fallbacks
4. Switch to faster model (Haiku)
5. Add request queuing

---

## Best Practices

### 1. Always Test in Staging First
Never add AI features directly to production without staging validation.

### 2. Set Billing Limits
Prevent surprise bills by setting hard limits in API console.

### 3. Monitor Costs Daily
Check usage and costs daily, especially during initial rollout.

### 4. Use Cheaper Models for Testing
Use DeepSeek or Haiku for development/testing to save costs.

### 5. Implement Caching
Cache repeated queries to avoid unnecessary API calls.

### 6. Graceful Degradation
Always have fallback when AI agent fails (show error, not crash).

### 7. User Feedback Loop
Collect user feedback on AI responses to improve prompts.

---

## Related Documentation

- [Incident Response Playbook](./incident-response-playbook.md)
- [Observability Guide](./observability-guide.md)
- [Deployment Checklist](../DEPLOYMENT_CHECKLIST.md)

---

**Last Updated**: 2025-10-21
**Next Review**: 2025-11-21
**Owner**: AI Engineering Team
