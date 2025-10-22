# Gemini Quick Start Guide

**Get 80% Cost Savings + 2-4x Faster Response Times in 5 Minutes**

---

## Option 1: Free Tier (Recommended Start)

### Step 1: Get Free API Key (2 minutes)

1. Visit: https://aistudio.google.com/app/apikey
2. Click "Get API key"
3. Create project or use existing
4. Copy your API key

**No credit card required!**

### Step 2: Configure (1 minute)

```bash
# Set environment variable
export GEMINI_API_KEY="your-api-key-here"

# Or add to .env file
echo 'GEMINI_API_KEY=your-api-key-here' >> .env
```

### Step 3: Test (2 minutes)

```bash
# Run integration tests
npm run test:integration:gemini

# Expected output:
# ✅ 8/8 tests passing
# 💰 Total cost: $0.10-0.30
# ⚡ Average latency: 800ms (2-4x faster than Claude)
```

### Done! 🎉

- **80% of tasks now use Gemini** (ultra-fast, ultra-cheap)
- **20% still use Claude** (complex reasoning)
- **Automatic routing** - no code changes needed

---

## Option 2: Multi-Model (Maximum Savings)

### Get All Three API Keys

```bash
# Gemini (primary - fast + cheap)
export GEMINI_API_KEY="your-gemini-key"

# Claude (reasoning - complex tasks)
export ANTHROPIC_API_KEY="sk-ant-your-claude-key"

# DeepSeek (bulk - high volume) - Optional
export DEEPSEEK_API_KEY="sk-your-deepseek-key"
```

### Enable Auto Selection

```bash
echo 'ENABLE_AUTO_MODEL_SELECTION=true' >> .env
```

### Test All Models

```bash
npm run test:integration:ai
```

---

## What You Get

### Gemini 2.0 Flash (Primary - 80% of tasks)

- ⚡ **Speed**: 800ms avg (2-4x faster than Claude)
- 💰 **Cost**: $0.075/1M input, $0.30/1M output (20x cheaper)
- 🆓 **Free Tier**: 1500 requests/day
- ✅ **Best For**: Invoice processing, email generation, lead qualification, standard analysis

### Claude 3.5 Sonnet (Reasoning - 15% of tasks)

- 🧠 **Quality**: Best-in-class deep reasoning
- 💰 **Cost**: $3/1M input, $15/1M output
- ✅ **Best For**: Financial analysis, contract review, strategic planning, risk assessment

### DeepSeek V3.2 (Bulk - 5% of tasks)

- 📊 **Volume**: Optimized for high-volume operations
- 💰 **Cost**: $0.14/1M input, $0.28/1M output
- ✅ **Best For**: Data extraction, classification, code generation

---

## Cost Comparison

### 1000 Tasks/Day Example

| Model Strategy | Daily | Monthly | Annual | Savings |
|----------------|-------|---------|--------|---------|
| All Claude | $18.00 | $540 | $6,480 | - |
| **Multi-Model** | **$3.60** | **$108** | **$1,296** | **80%** |
| Gemini Only | $1.80 | $54 | $648 | 90% |

**Recommendation**: Multi-model for best quality + cost balance

---

## Quick Commands

```bash
# Test Gemini only
npm run test:integration:gemini

# Test Claude only
npm run test:integration:anthropic

# Test all AI models
npm run test:integration:ai

# Test Finance Agent (uses auto-selection)
npm run test:integration:finance-agent
```

---

## Usage Example

```typescript
// No code changes needed!
// ModelSelector automatically routes to optimal model

const task: AgentTask = {
  id: 'task-1',
  capability: 'invoice_processing',  // → Gemini (fast + cheap)
  priority: 'normal'
};

const agent = new ClaudeAgent({
  geminiApiKey: process.env.GEMINI_API_KEY
});

const result = await agent.executeTask(task, context);
// ⚡ Response in ~800ms
// 💰 Cost: ~$0.0001
```

```typescript
const complexTask: AgentTask = {
  id: 'task-2',
  capability: 'financial_analysis',  // → Claude (deep reasoning)
  priority: 'high'
};

// Automatic routing - no changes needed!
```

---

## FAQ

### Q: Do I need all three models?

**A**: No. Start with Gemini only (free tier). Add Claude later for complex tasks.

### Q: Will this break existing code?

**A**: No. Backward compatible. Existing Claude code continues to work.

### Q: How does auto-selection work?

**A**:
- **Gemini**: Standard tasks (invoice, email, lead, etc.)
- **Claude**: Complex tasks (financial analysis, contracts, etc.)
- **DeepSeek**: Bulk operations (classification, extraction, etc.)

### Q: Can I override the selection?

**A**: Yes.
```typescript
const selection = ModelSelector.selectModel({
  task,
  priorityOverride: 'anthropic'  // Force Claude
});
```

---

## Troubleshooting

### Tests Fail with "No API key"

```bash
# Make sure environment variable is set
echo $GEMINI_API_KEY

# If empty, set it:
export GEMINI_API_KEY="your-key-here"
```

### API Key Invalid

```
Visit https://aistudio.google.com/app/apikey
Verify your key is correct
Check for spaces or hidden characters
```

### Rate Limit Errors

```
Free tier: 1500 requests/day
Wait for reset or upgrade to paid tier
```

---

## Next Steps

1. ✅ **Get API Key**: https://aistudio.google.com/app/apikey (2 min)
2. ✅ **Run Tests**: `npm run test:integration:gemini` (2 min)
3. ✅ **Deploy Staging**: `npm run deploy:staging` (5 min)
4. ✅ **Monitor Savings**: Track cost reduction
5. ✅ **Production**: Gradual rollout (1-2 weeks)

---

**Ready?**

```bash
export GEMINI_API_KEY="your-key-here"
npm run test:integration:gemini
```

**Expected Result**: 80% cost reduction + 2-4x speed improvement in 5 minutes! 🚀
