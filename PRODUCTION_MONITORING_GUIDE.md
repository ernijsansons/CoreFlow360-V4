# Production Monitoring Guide - AI Agent System

**Date**: 2025-10-21
**Status**: Production Monitoring Setup for 5 Ready Agents
**Environment**: Cloudflare Workers + D1 + R2

---

## 🎯 Quick Start - 5 Minute Setup

```bash
# 1. Deploy monitoring infrastructure
wrangler deploy --name agent-monitoring

# 2. Configure Cloudflare Analytics
npm run setup:analytics

# 3. Set up alerts
npm run alerts:configure -- \
  --channels slack,email \
  --severity critical,high

# 4. Start monitoring dashboard
npm run dashboard:agents -- --env production

# ✅ Done! Monitoring active
```

---

## 📊 Monitoring Architecture

### Three-Tier Monitoring Strategy

```
┌─────────────────────────────────────────────────────────┐
│  Tier 1: Real-Time Health Checks (Every 60s)          │
│  • Agent availability                                   │
│  • Response time                                        │
│  • Error rate                                          │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Tier 2: Performance Metrics (Every 5 min)             │
│  • Cost per call                                       │
│  • Token usage                                         │
│  • Cache hit rate                                      │
│  • Concurrency levels                                  │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Tier 3: Business Metrics (Every hour)                 │
│  • Tasks completed                                     │
│  • Business value generated                            │
│  • User satisfaction                                   │
│  • ROI tracking                                        │
└─────────────────────────────────────────────────────────┘
```

---

## 🔍 Agent-Specific Monitoring

### QualificationAgent (37 tests passing)

#### Health Check Endpoint
```bash
curl https://api.coreflow360.com/agents/qualification-agent/health

# Expected Response:
{
  "status": "healthy",
  "latency": 450,
  "errorRate": 0.01,
  "capabilities": [...],
  "details": {
    "apiConnectivity": true,
    "memoryUsage": 45,
    "activeConnections": 12
  }
}
```

#### Key Metrics to Monitor
| Metric | Target | Alert If |
|--------|--------|----------|
| Response Time | <500ms | >1000ms |
| Error Rate | <1% | >5% |
| BANT Completion | >80% | <60% |
| Qualification Accuracy | >85% | <75% |
| Cost per Call | <$0.01 | >$0.05 |

#### Business Metrics
```javascript
// Daily qualification metrics
{
  "leadsQualified": 150,
  "bantCompletionRate": 0.85,
  "qualificationAccuracy": 0.89,
  "avgConfidenceScore": 0.82,
  "timeSaved": "20 hours",
  "estimatedValue": "$250/day"
}
```

---

### ChatSupportAgent (39 tests passing)

#### Health Check
```bash
curl https://api.coreflow360.com/agents/chat-support-agent/health
```

#### Key Metrics
| Metric | Target | Alert If |
|--------|--------|----------|
| Response Time | <800ms | >2000ms |
| Error Rate | <2% | >10% |
| Human Handoff Rate | <15% | >30% |
| CSAT Score | >4.2/5 | <3.5/5 |
| Resolution Rate | >75% | <60% |

#### Business Metrics
```javascript
{
  "ticketsHandled": 500,
  "humanHandoffRate": 0.12,
  "averageCSAT": 4.3,
  "resolutionRate": 0.78,
  "supportStaffSaved": 2,
  "estimatedValue": "$400/day"
}
```

---

### FinanceAgent (90 tests passing) ⭐⭐⭐

#### Health Check
```bash
curl https://api.coreflow360.com/agents/finance-agent/health
```

#### Key Metrics
| Metric | Target | Alert If |
|--------|--------|----------|
| Response Time | <1000ms | >3000ms |
| Error Rate | <0.5% | >2% |
| Reconciliation Accuracy | >99% | <95% |
| Invoice Generation Time | <200ms | >1000ms |
| Data Consistency | 100% | <99.9% |

#### Business Metrics
```javascript
{
  "transactionsProcessed": 1200,
  "invoicesGenerated": 450,
  "reconciliationAccuracy": 0.998,
  "auditTrailComplete": true,
  "accountingHoursSaved": "40 hours/week",
  "estimatedValue": "$650/day"
}
```

---

### OnboardingAgent (18 tests passing)

#### Health Check
```bash
curl https://api.coreflow360.com/agents/onboarding-agent/health
```

#### Key Metrics
| Metric | Target | Alert If |
|--------|--------|----------|
| Response Time | <1500ms | >3000ms |
| Error Rate | <3% | >10% |
| Import Success Rate | >95% | <85% |
| Time to Activation | <10 min | >30 min |

#### Business Metrics
```javascript
{
  "customersOnboarded": 85,
  "dataImportSuccessRate": 0.97,
  "avgTimeToActivation": "8 minutes",
  "teamMembersAdded": 120,
  "onboardingHoursSaved": "15 hours/week",
  "estimatedValue": "$200/day"
}
```

---

### KnowledgeBaseAgent (34 tests passing)

#### Health Check
```bash
curl https://api.coreflow360.com/agents/knowledge-base-agent/health
```

#### Key Metrics
| Metric | Target | Alert If |
|--------|--------|----------|
| Response Time | <600ms | >2000ms |
| Error Rate | <1% | >5% |
| Search Relevance | >90% | <75% |
| Cache Hit Rate | >80% | <60% |

#### Business Metrics
```javascript
{
  "articlesServed": 2500,
  "searchQueries": 1800,
  "relevanceScore": 0.92,
  "selfServiceRate": 0.75,
  "ticketDeflection": "30%",
  "estimatedValue": "$250/day"
}
```

---

## 🚨 Alert Configuration

### Critical Alerts (Immediate Action)

```yaml
# alerts.critical.yaml
alerts:
  - name: agent-down
    condition: health_status != "healthy"
    duration: 2m
    channels: [slack, pagerduty, email]
    severity: critical
    message: "Agent {agent_name} is down - immediate action required"

  - name: high-error-rate
    condition: error_rate > 0.10
    duration: 5m
    channels: [slack, email]
    severity: critical
    message: "Agent {agent_name} error rate above 10%"

  - name: api-key-invalid
    condition: last_error contains "authentication"
    duration: 1m
    channels: [slack, pagerduty]
    severity: critical
    message: "API key validation failed for {agent_name}"
```

### High Priority Alerts

```yaml
# alerts.high.yaml
alerts:
  - name: slow-response-time
    condition: p95_latency > 3000
    duration: 10m
    channels: [slack]
    severity: high
    message: "Agent {agent_name} response time degraded"

  - name: cost-spike
    condition: hourly_cost > average_cost * 2
    duration: 1h
    channels: [email, slack]
    severity: high
    message: "Agent {agent_name} costs doubled - investigate"

  - name: low-success-rate
    condition: success_rate < 0.90
    duration: 15m
    channels: [slack]
    severity: high
    message: "Agent {agent_name} success rate below 90%"
```

### Medium Priority Alerts

```yaml
# alerts.medium.yaml
alerts:
  - name: cache-miss-rate-high
    condition: cache_hit_rate < 0.60
    duration: 30m
    channels: [email]
    severity: medium
    message: "Agent {agent_name} cache performance degraded"

  - name: token-usage-high
    condition: avg_tokens_per_call > baseline * 1.5
    duration: 1h
    channels: [email]
    severity: medium
    message: "Agent {agent_name} using more tokens than normal"
```

---

## 📈 Dashboards

### Real-Time Operations Dashboard

```javascript
// Dashboard Configuration
{
  "name": "AI Agents - Operations",
  "refresh": "60s",
  "panels": [
    {
      "title": "Agent Health Status",
      "type": "status-grid",
      "agents": [
        "qualification-agent",
        "chat-support-agent",
        "finance-agent",
        "onboarding-agent",
        "knowledge-base-agent"
      ],
      "metrics": ["status", "latency", "errorRate"]
    },
    {
      "title": "Request Rate (Last Hour)",
      "type": "time-series",
      "query": "sum(rate(agent_requests_total[1h])) by (agent)"
    },
    {
      "title": "Error Rate by Agent",
      "type": "bar-chart",
      "query": "rate(agent_errors_total[5m]) / rate(agent_requests_total[5m])"
    },
    {
      "title": "Response Time Distribution",
      "type": "heatmap",
      "query": "histogram_quantile(0.95, agent_latency_seconds)"
    }
  ]
}
```

### Business Metrics Dashboard

```javascript
{
  "name": "AI Agents - Business Impact",
  "refresh": "5m",
  "panels": [
    {
      "title": "Daily Value Generated",
      "type": "stat",
      "query": "sum(agent_business_value_usd)",
      "format": "$0,0"
    },
    {
      "title": "Tasks Completed",
      "type": "counter",
      "query": "sum(agent_tasks_completed_total)"
    },
    {
      "title": "Time Saved (Hours)",
      "type": "gauge",
      "query": "sum(agent_time_saved_hours)",
      "max": 200
    },
    {
      "title": "ROI by Agent",
      "type": "bar-chart",
      "query": "agent_value_generated / agent_cost_total"
    }
  ]
}
```

### Cost Optimization Dashboard

```javascript
{
  "name": "AI Agents - Cost Analysis",
  "refresh": "15m",
  "panels": [
    {
      "title": "Cost per Agent (24h)",
      "type": "pie-chart",
      "query": "sum(agent_cost_usd[24h]) by (agent)"
    },
    {
      "title": "Token Usage Trend",
      "type": "time-series",
      "query": "sum(rate(agent_tokens_used[1h])) by (agent)"
    },
    {
      "title": "Cost vs Budget",
      "type": "gauge",
      "query": "sum(agent_cost_usd[1d]) / daily_budget",
      "max": 1.0
    },
    {
      "title": "Most Expensive Calls",
      "type": "table",
      "query": "topk(10, agent_call_cost_usd)"
    }
  ]
}
```

---

## 🔧 Monitoring Setup Scripts

### 1. Install Dependencies

```bash
# Install monitoring tools
npm install --save-dev @cloudflare/workers-types
npm install prom-client
npm install winston
```

### 2. Configure Cloudflare Analytics

```bash
# Enable Workers Analytics
wrangler analytics enable

# Set up custom metrics
cat > wrangler.toml <<EOF
[analytics_engine_datasets]
AGENT_METRICS = "agent_metrics"
BUSINESS_METRICS = "business_metrics"
EOF
```

### 3. Set Up Slack Notifications

```bash
# Configure Slack webhook
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Test notification
curl -X POST $SLACK_WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "✅ Agent monitoring configured successfully!",
    "channel": "#agent-monitoring"
  }'
```

### 4. Create Health Check Cron

```javascript
// cron.js - Add to wrangler.toml
export default {
  async scheduled(event, env, ctx) {
    const agents = [
      'qualification-agent',
      'chat-support-agent',
      'finance-agent',
      'onboarding-agent',
      'knowledge-base-agent'
    ];

    for (const agent of agents) {
      const health = await fetch(`https://api.coreflow360.com/agents/${agent}/health`);
      const data = await health.json();

      if (data.status !== 'healthy') {
        await sendAlert({
          severity: 'critical',
          agent: agent,
          message: `Agent ${agent} health check failed`,
          data: data
        });
      }

      // Record metrics
      await env.AGENT_METRICS.writeDataPoint({
        blobs: [agent],
        doubles: [data.latency, data.errorRate],
        indexes: [data.status]
      });
    }
  }
};

// Add to wrangler.toml:
// [triggers]
// crons = ["*/1 * * * *"]  # Every minute
```

---

## 📊 Metrics Collection

### Agent Metrics Schema

```typescript
interface AgentMetrics {
  // Identity
  agentId: string;
  timestamp: number;

  // Performance
  latency: number;          // ms
  errorRate: number;        // 0-1
  successRate: number;      // 0-1
  throughput: number;       // requests/second

  // Resource Usage
  tokensUsed: number;
  costUSD: number;
  memoryUsage: number;      // MB
  cpuUsage: number;         // %

  // Business Metrics
  tasksCompleted: number;
  valueGenerated: number;   // USD
  timeSaved: number;        // hours
  userSatisfaction: number; // 0-5

  // Quality
  confidence: number;       // 0-1
  accuracy: number;         // 0-1
  cacheHitRate: number;     // 0-1
}
```

### Logging Standards

```typescript
// Use structured logging
logger.info('Agent execution completed', {
  agentId: 'finance-agent',
  taskId: 'task-123',
  duration: 450,
  tokensUsed: 1200,
  cost: 0.018,
  success: true,
  errorCode: null,
  businessMetrics: {
    invoicesGenerated: 1,
    valueCreated: 50
  }
});
```

---

## 🎯 Success Criteria

### Production Deployment Checklist

```markdown
## Pre-Deployment
- [ ] All agents showing 100% test pass rate
- [ ] TypeScript compilation clean
- [ ] Environment variables configured
- [ ] API keys validated
- [ ] Rate limits configured

## Deployment
- [ ] Agents deployed successfully
- [ ] Health checks passing
- [ ] Smoke tests completed
- [ ] No errors in logs

## Post-Deployment (24h)
- [ ] Response times within targets
- [ ] Error rates <2%
- [ ] No critical alerts
- [ ] Business metrics tracking
- [ ] Cost within budget

## Week 1
- [ ] User feedback collected
- [ ] Performance optimized
- [ ] Cost per call optimized
- [ ] Documentation updated
```

### Performance Targets

| Agent | P95 Latency | Error Rate | Availability |
|-------|-------------|------------|--------------|
| QualificationAgent | <500ms | <1% | 99.9% |
| ChatSupportAgent | <800ms | <2% | 99.9% |
| FinanceAgent | <1000ms | <0.5% | 99.95% |
| OnboardingAgent | <1500ms | <3% | 99.5% |
| KnowledgeBaseAgent | <600ms | <1% | 99.9% |

---

## 📞 Support & Escalation

### On-Call Rotation

```yaml
schedule:
  primary: DevOps Team
  backup: Engineering Team
  escalation: CTO

alerts:
  critical: 0-5 min response
  high: 15 min response
  medium: 4 hour response
```

### Runbooks

**Agent Down**: See `runbooks/agent-down.md`
**High Error Rate**: See `runbooks/high-errors.md`
**Cost Spike**: See `runbooks/cost-spike.md`
**Performance Degradation**: See `runbooks/slow-response.md`

---

## 🎉 Summary

**Monitoring is configured for 5 production-ready agents:**
- ✅ Real-time health checks
- ✅ Performance metrics
- ✅ Business value tracking
- ✅ Cost optimization
- ✅ Automated alerts

**Expected Outcomes:**
- <1 min detection of critical issues
- <5 min response to agent failures
- 99.9% uptime for all agents
- Complete visibility into costs and value

**Deploy monitoring alongside agents for full observability!** 📊

---

*Last Updated: 2025-10-21*
*Status: Ready for Production*
*Agents Monitored: 5*
