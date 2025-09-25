# CoreFlow360 Agent System Integration

This document describes the integration between the CoreFlow360 main application and the CoreFlow360 Agents system.

## Overview

The integration provides seamless connectivity between the CoreFlow360 enterprise platform and the AI agent system, enabling intelligent decision-making and autonomous operations across the entire business ecosystem.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CoreFlow360 Main App                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ AgentService │  │ Agent Routes │  │ Agent Proxy  │      │
│  │   /agents    │  │  /api/v4/    │  │  /api/ai/*   │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│  ┌──────▼──────────────────▼──────────────────▼──────┐      │
│  │           Integration Bridge & Connectors          │      │
│  │  - Real-time WebSocket                            │      │
│  │  - Bidirectional Data Sync                        │      │
│  │  - Decision Routing                               │      │
│  └────────────────────────┬───────────────────────────┘     │
│                           │                                  │
└───────────────────────────┼───────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  CoreFlow360 Agents System                   │
│                    (localhost:3000)                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   CEO    │  │   CFO    │  │   CTO    │  │   HR     │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Sales   │  │Operations│  │   Risk   │  │  Market  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Access Patterns

The integration provides three distinct access patterns:

### 1. AgentService (`/agents/*`)
Direct service interface for agent operations:
- `/agents/health` - Service health check
- `/agents/status` - Agent system status
- `/agents/list` - List available agents
- `/agents/decide` - Request decisions
- `/agents/collaborate` - Multi-agent collaboration
- `/agents/sync/*` - Data synchronization control

### 2. Agent API (`/api/v4/agents/*`)
RESTful API for comprehensive agent management:
- `/api/v4/agents/capabilities` - Agent capabilities
- `/api/v4/agents/decision` - Decision requests
- `/api/v4/agents/workflow/:id/*` - Workflow integration
- `/api/v4/agents/sync/*` - Sync operations
- `/api/v4/agents/metrics` - Performance metrics
- `/api/v4/agents/stream` - Real-time events

### 3. Proxy Access (`/api/ai/*`)
Direct proxy to agent system for low-level access:
- `/api/ai/*` - HTTP request forwarding
- `/api/ai/ws` - WebSocket proxy
- `/api/ai/stream` - SSE proxy

## Configuration

### Environment Variables

```env
# Agent System Configuration
AGENT_SYSTEM_URL=http://localhost:3000
AGENT_API_KEY=your-api-key-here

# CoreFlow360 Configuration
COREFLOW_API_URL=http://localhost:8787

# Sync Configuration
SYNC_INTERVAL=60000
ENABLE_BIDIRECTIONAL_SYNC=true
CONFLICT_RESOLUTION=newest
```

### Initialization

The AgentService automatically initializes on first request after startup validation:

```typescript
// Automatic initialization in index.ts
if (!agentServiceInitialized && validationComplete) {
  await agentService.initialize(c.env);
  agentServiceInitialized = true;
}
```

## Usage Examples

### Requesting a Decision

```typescript
// Via AgentService
const response = await fetch('/agents/decide', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    type: 'strategic_financial',
    data: {
      investment: 500000,
      expectedReturn: 750000
    },
    priority: 'high'
  })
});

const { decision } = await response.json();
```

### Multi-Agent Collaboration

```typescript
// Execute task with multiple agents
const response = await fetch('/agents/collaborate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    task: 'evaluate_expansion',
    agents: ['ceo', 'cfo', 'cto'],
    context: {
      budget: 5000000,
      markets: ['US', 'EU', 'APAC']
    }
  })
});

const { results, consensus } = await response.json();
```

### Connecting Workflows

```typescript
// Connect workflow to agent system
const response = await fetch('/api/v4/agents/workflow/wf-123/connect', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    businessUnit: 'finance',
    data: {
      budget: 1000000,
      department: 'R&D'
    }
  })
});
```

### Real-time Streaming

```typescript
// Subscribe to real-time agent events
const eventSource = new EventSource('/agents/stream');

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Agent event:', data);
};
```

## Data Synchronization

The integration includes automatic bidirectional data synchronization:

### Sync Flow
1. **Agent → CoreFlow360**: Decisions, status updates, alerts
2. **CoreFlow360 → Agents**: Business data, workflow status, metrics

### Sync Configuration

```typescript
// Start automatic sync
await fetch('/agents/sync/start', { method: 'POST' });

// Perform full sync
await fetch('/agents/sync/full', { method: 'POST' });

// Get sync status
const response = await fetch('/agents/sync/status');
const { statistics } = await response.json();
```

## Available Agents

### Executive Agents
- **CEO**: Strategic planning, vision setting, major decisions
- **CFO**: Financial analysis, budget planning, investment decisions
- **CTO**: Technology strategy, innovation planning, system architecture

### Department Agents
- **HR Manager**: Recruitment, performance management, employee relations
- **Sales Manager**: Sales forecasting, lead qualification, deal closing

### Operational Agents
- **Operations**: Process optimization, resource allocation, workflow automation

### Specialist Agents
- **Risk Analyst**: Risk assessment, compliance checking, mitigation planning
- **Market Analyst**: Market research, competitor analysis, trend prediction

## Testing

Run integration tests:

```bash
# Run all integration tests
npm test tests/integration/agent-integration.test.ts

# Run specific test suites
npm test -- --testNamePattern="AgentService"
npm test -- --testNamePattern="Proxy"
npm test -- --testNamePattern="Sync"
```

## Monitoring

### Health Checks

```bash
# Check CoreFlow360 health
curl http://localhost:8787/health

# Check AgentService health
curl http://localhost:8787/agents/health

# Check Agent System (via proxy)
curl http://localhost:8787/api/ai/health
```

### Metrics

```bash
# Get agent metrics
curl http://localhost:8787/agents/metrics

# Get sync statistics
curl http://localhost:8787/agents/sync/status
```

## Troubleshooting

### Common Issues

1. **Agent System Unreachable**
   - Verify AGENT_SYSTEM_URL environment variable
   - Check if agent system is running on port 3000
   - Review proxy configuration

2. **Sync Failures**
   - Check sync status: `/agents/sync/status`
   - Review conflict resolution settings
   - Verify data mappings in `data-sync.ts`

3. **WebSocket Connection Issues**
   - Ensure WebSocket upgrade headers are present
   - Check firewall/proxy settings
   - Verify real-time configuration

### Debug Mode

Enable debug logging:

```typescript
// In agent-service.ts
console.log('AgentService Debug:', {
  initialized: this.initialized,
  bridgeConnected: this.bridge.isConnected,
  syncRunning: this.dataSync.isRunning
});
```

## Security

### Authentication
- API key authentication via `AGENT_API_KEY`
- Request signing for sensitive operations
- Rate limiting on all endpoints

### Data Protection
- Encrypted data transmission
- Sensitive data masking in logs
- Audit trail for all operations

## Performance

### Optimization Tips
1. Use batch operations for multiple agent requests
2. Enable connection pooling for WebSocket
3. Configure appropriate sync intervals
4. Implement caching for frequently accessed data

### Benchmarks
- Decision latency: < 200ms average
- Sync throughput: 1000 records/second
- WebSocket messages: 10,000/second
- Concurrent connections: 1000+

## Future Enhancements

- [ ] GraphQL API for complex queries
- [ ] Agent marketplace integration
- [ ] Custom agent development SDK
- [ ] Advanced machine learning pipelines
- [ ] Distributed agent orchestration
- [ ] Enhanced observability dashboard

## Support

For issues or questions:
1. Check this documentation
2. Review integration tests
3. Contact the development team
4. Submit issues to the repository