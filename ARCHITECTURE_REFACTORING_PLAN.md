# CoreFlow360 V4 - Critical Architecture Refactoring Plan

## Executive Summary

**CRITICAL ARCHITECTURAL VIOLATIONS DETECTED**

The CoreFlow360 V4 system contains multiple god objects that violate SOLID principles and threaten system scalability. Immediate refactoring is required to maintain architectural integrity and support enterprise-scale operations.

## Critical God Objects Identified

| Component | Lines | Violations | Risk Level |
|-----------|-------|------------|------------|
| CRMDatabase | 1,210 | SRP, OCP, DIP | CRITICAL |
| AgentOrchestrator | 1,190 | SRP, ISP, OCP | HIGH |
| AgentRegistry | 657 | SRP, DIP | MEDIUM |
| CacheService | 717 | SRP, OCP | MEDIUM |
| APIGateway | 824 | SRP, ISP | MEDIUM |

## Priority 1: CRMDatabase Refactoring (CRITICAL)

### Current State Analysis
- **Lines of Code**: 1,210 (4x the acceptable limit)
- **Responsibilities**: 8 distinct concerns in one class
- **Methods**: 28 methods with mixed responsibilities
- **Dependencies**: Tightly coupled to validation, caching, and business logic

### Target Architecture

```typescript
// 1. Repository Interfaces (ISP Compliance)
interface ILeadRepository {
  create(lead: CreateLead): Promise<DatabaseResult<{ id: string }>>;
  findById(id: string, businessId: string): Promise<DatabaseResult<Lead>>;
  findByFilters(filters: LeadFilters, pagination: PaginationOptions): Promise<DatabaseResult<Lead[]>>;
  updateStatus(id: string, status: string, summary?: string): Promise<DatabaseResult>;
}

interface IContactRepository {
  create(contact: CreateContact): Promise<DatabaseResult<{ id: string }>>;
  findById(id: string, businessId: string): Promise<DatabaseResult<Contact>>;
  findByEmail(email: string, businessId: string): Promise<DatabaseResult<Contact>>;
  batchCreate(contacts: CreateContact[]): Promise<DatabaseResult<{ created: number; errors: number }>>;
}

interface ICompanyRepository {
  create(company: CreateCompany): Promise<DatabaseResult<{ id: string }>>;
  findById(id: string, businessId: string): Promise<DatabaseResult<Company>>;
  updateAIData(id: string, businessId: string, aiData: AICompanyData): Promise<DatabaseResult>;
  batchCreate(companies: CreateCompany[], businessId: string): Promise<DatabaseResult>;
}

// 2. Query Builder (SRP Compliance)
class QueryBuilder {
  private query: string = '';
  private params: any[] = [];

  select(fields: string[]): QueryBuilder {
    this.query = `SELECT ${fields.join(', ')}`;
    return this;
  }

  from(table: string): QueryBuilder {
    this.query += ` FROM ${table}`;
    return this;
  }

  where(condition: string, value?: any): QueryBuilder {
    const prefix = this.query.includes('WHERE') ? ' AND' : ' WHERE';
    this.query += `${prefix} ${condition}`;
    if (value !== undefined) this.params.push(value);
    return this;
  }

  build(): { query: string; params: any[] } {
    return { query: this.query, params: this.params };
  }
}

// 3. Connection Manager (SRP Compliance)
class DatabaseConnectionManager {
  private readonly connectionPool: Set<D1Database>;
  private readonly maxPoolSize: number = 10;

  constructor(private env: Env) {
    this.connectionPool = new Set();
    this.initializePool();
  }

  private initializePool(): void {
    for (let i = 0; i < this.maxPoolSize; i++) {
      this.connectionPool.add(this.env.DB_MAIN);
    }
  }

  async execute<T>(
    query: string,
    params: any[] = [],
    operation: 'first' | 'all' | 'run' = 'all'
  ): Promise<T> {
    const db = this.getConnection();
    const statement = db.prepare(query);
    const boundStatement = params.length > 0 ? statement.bind(...params) : statement;

    switch (operation) {
      case 'first': return await boundStatement.first();
      case 'all': return await boundStatement.all();
      case 'run': return await boundStatement.run();
    }
  }

  private getConnection(): D1Database {
    // Simple round-robin connection selection
    return Array.from(this.connectionPool)[0];
  }
}

// 4. Performance Monitor (SRP Compliance)
class DatabasePerformanceMonitor {
  private metrics = new Map<string, { totalTime: number; count: number; avgTime: number }>();

  trackQuery(query: string, executionTime: number): void {
    const queryKey = query.substring(0, 100);
    const existing = this.metrics.get(queryKey) || { totalTime: 0, count: 0, avgTime: 0 };

    existing.totalTime += executionTime;
    existing.count += 1;
    existing.avgTime = existing.totalTime / existing.count;

    this.metrics.set(queryKey, existing);
  }

  getSlowQueries(threshold: number = 50): Array<{ query: string; avgTime: number; count: number }> {
    return Array.from(this.metrics.entries())
      .filter(([_, data]) => data.avgTime > threshold)
      .map(([query, data]) => ({
        query: query.substring(0, 80) + '...',
        avgTime: Math.round(data.avgTime),
        count: data.count
      }))
      .sort((a, b) => b.avgTime - a.avgTime);
  }
}

// 5. Lead Repository Implementation (SRP Compliance)
class LeadRepository implements ILeadRepository {
  constructor(
    private connectionManager: DatabaseConnectionManager,
    private performanceMonitor: DatabasePerformanceMonitor,
    private validator: DataValidator,
    private logger: Logger
  ) {}

  async create(lead: CreateLead): Promise<DatabaseResult<{ id: string }>> {
    const startTime = performance.now();

    try {
      // Validation (delegated)
      const validation = this.validator.validateLead(lead);
      if (!validation.success) {
        return { success: false, error: validation.error };
      }

      // Query building (delegated)
      const id = this.generateId();
      const query = new QueryBuilder()
        .select(['*'])
        .from('leads')
        .build();

      // Execution (delegated)
      const result = await this.connectionManager.execute(
        `INSERT INTO leads (id, ${Object.keys(lead).join(', ')}) VALUES (?, ${Object.keys(lead).map(() => '?').join(', ')})`,
        [id, ...Object.values(lead)],
        'run'
      );

      // Performance tracking (delegated)
      this.performanceMonitor.trackQuery('INSERT INTO leads', performance.now() - startTime);

      return { success: true, data: { id } };
    } catch (error: any) {
      this.logger.error('Failed to create lead', error);
      return { success: false, error: error.message };
    }
  }

  async findByFilters(
    filters: LeadFilters,
    pagination: PaginationOptions
  ): Promise<DatabaseResult<Lead[]>> {
    const startTime = performance.now();

    try {
      const queryBuilder = new QueryBuilder()
        .select(['l.*', 'c.first_name', 'c.last_name', 'co.name as company_name'])
        .from('leads l')
        .join('LEFT JOIN contacts c ON l.contact_id = c.id')
        .join('LEFT JOIN companies co ON l.company_id = co.id');

      // Apply filters dynamically
      if (filters.status) queryBuilder.where('l.status = ?', filters.status);
      if (filters.assigned_to) queryBuilder.where('l.assigned_to = ?', filters.assigned_to);
      if (filters.source) queryBuilder.where('l.source = ?', filters.source);

      const { query, params } = queryBuilder.build();
      const results = await this.connectionManager.execute<Lead[]>(query, params, 'all');

      this.performanceMonitor.trackQuery('SELECT FROM leads', performance.now() - startTime);

      return { success: true, data: results };
    } catch (error: any) {
      this.logger.error('Failed to find leads', error);
      return { success: false, error: error.message };
    }
  }

  private generateId(): string {
    return crypto.randomUUID();
  }
}
```

### Migration Strategy (Zero Downtime)

**Phase 1: Interface Extraction**
1. Extract repository interfaces from existing CRMDatabase
2. Create wrapper implementations that delegate to current CRMDatabase
3. Update all consumers to use interfaces

**Phase 2: Implementation Splitting**
1. Create focused repository implementations
2. Migrate consumers one by one using feature flags
3. Remove old implementations once all consumers migrated

**Phase 3: Testing & Validation**
1. Comprehensive unit tests for each repository
2. Integration tests with existing business logic
3. Performance benchmarking to ensure no degradation

## Priority 2: AgentOrchestrator Refactoring (HIGH)

### Current Violations
- **Lines**: 1,190 (mixing task scheduling, execution, memory, cost tracking)
- **Responsibilities**: 7 distinct concerns
- **Methods**: 35+ methods with overlapping concerns

### Target Architecture

```typescript
// 1. Task Scheduler (SRP Compliance)
class TaskScheduler {
  constructor(
    private registry: IAgentRegistry,
    private costTracker: ICostTracker,
    private logger: Logger
  ) {}

  async scheduleTask(task: AgentTask, context: BusinessContext): Promise<ScheduledTask> {
    // Focus only on task scheduling logic
    const agent = await this.selectOptimalAgent(task, context);
    const priority = this.calculatePriority(task);

    return {
      id: crypto.randomUUID(),
      task,
      agentId: agent.id,
      priority,
      scheduledAt: Date.now(),
      context
    };
  }

  private async selectOptimalAgent(task: AgentTask, context: BusinessContext): Promise<IAgent> {
    const candidates = this.registry.findByCapability(task.capability);
    return this.selectBestCandidate(candidates, task, context);
  }
}

// 2. Agent Executor (SRP Compliance)
class AgentExecutor {
  constructor(
    private retryManager: IRetryManager,
    private memoryManager: IMemoryManager,
    private logger: Logger
  ) {}

  async executeTask(scheduledTask: ScheduledTask): Promise<AgentResult> {
    const { task, agentId, context } = scheduledTask;

    try {
      // Focus only on task execution
      const agent = await this.getAgent(agentId);
      const enhancedTask = await this.enhanceWithMemory(task, context);

      return await this.retryManager.executeWithRetry(
        () => agent.execute(enhancedTask, context)
      );
    } catch (error) {
      this.logger.error('Task execution failed', error);
      throw error;
    }
  }

  private async enhanceWithMemory(task: AgentTask, context: BusinessContext): Promise<AgentTask> {
    const memory = await this.memoryManager.getRelevantMemory(context.userId, task.capability);
    return { ...task, input: { ...task.input, memoryContext: memory } };
  }
}

// 3. Capability Selector (Strategy Pattern)
interface ICapabilitySelector {
  selectAgent(task: AgentTask, candidates: IAgent[]): Promise<IAgent>;
}

class CostOptimizedSelector implements ICapabilitySelector {
  async selectAgent(task: AgentTask, candidates: IAgent[]): Promise<IAgent> {
    return candidates.reduce((best, current) =>
      current.costPerCall < best.costPerCall ? current : best
    );
  }
}

class LatencyOptimizedSelector implements ICapabilitySelector {
  async selectAgent(task: AgentTask, candidates: IAgent[]): Promise<IAgent> {
    return candidates.reduce((best, current) =>
      current.averageLatency < best.averageLatency ? current : best
    );
  }
}

// 4. Orchestrator Coordinator (OCP Compliance)
class AgentOrchestrator {
  constructor(
    private scheduler: TaskScheduler,
    private executor: AgentExecutor,
    private capabilitySelector: ICapabilitySelector,
    private costTracker: ICostTracker,
    private auditService: IAuditService
  ) {}

  async executeTask(task: AgentTask, context: BusinessContext): Promise<AgentResult> {
    // Orchestration logic only - delegates to specialized components
    const scheduledTask = await this.scheduler.scheduleTask(task, context);
    const result = await this.executor.executeTask(scheduledTask);

    await this.costTracker.trackCost(result, context);
    await this.auditService.logExecution(task, result, context);

    return result;
  }

  // Strategy pattern for different selection algorithms
  setCapabilitySelector(selector: ICapabilitySelector): void {
    this.capabilitySelector = selector;
  }
}
```

## Priority 3: Remaining Components

### AgentRegistry Refactoring
- Split into AgentManager (lifecycle) and CapabilityRegistry (routing)
- Implement Factory pattern for agent creation
- Add Observer pattern for health monitoring

### CacheService Refactoring
- Separate L1Cache and L2Cache implementations
- Extract CachePolicy and CacheInvalidator
- Implement Strategy pattern for different cache policies

### APIGateway Refactoring
- Split into RouteHandler, MiddlewareChain, and RequestValidator
- Implement Chain of Responsibility for middleware
- Extract RateLimiter and AuthenticationManager

## Implementation Timeline

### Week 1-2: CRMDatabase Refactoring
- Interface extraction and wrapper creation
- Repository implementations
- Migration of lead operations

### Week 3-4: AgentOrchestrator Refactoring
- Component separation and interface definition
- Strategy pattern implementation
- Integration testing

### Week 5-6: Remaining Components
- AgentRegistry, CacheService, APIGateway refactoring
- Cross-component integration
- Performance validation

### Week 7-8: Testing & Optimization
- Comprehensive testing suite
- Performance benchmarking
- Production deployment preparation

## Success Metrics

- **Code Quality**: All classes under 300 lines
- **SOLID Compliance**: 100% adherence to SOLID principles
- **Test Coverage**: Maintain 95%+ coverage
- **Performance**: No degradation in response times
- **Maintainability**: Reduced coupling, improved cohesion

## Risk Mitigation

1. **Feature Flags**: Gradual rollout with ability to rollback
2. **Parallel Implementation**: Keep old system running during migration
3. **Comprehensive Testing**: Unit, integration, and performance tests
4. **Performance Monitoring**: Real-time metrics during migration
5. **Rollback Plan**: Immediate fallback to previous implementation

This refactoring plan ensures zero breaking changes while dramatically improving system architecture, maintainability, and scalability for enterprise-grade operations.