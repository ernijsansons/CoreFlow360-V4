/**
 * Database Integration Layer for Agent System
 * Provides shared database access and agent-specific tables
 */

export interface AgentDecisionRecord {
  id: string;
  agent_id: string;
  workflow_id?: string;
  decision_type: string;
  decision_action: string;
  confidence: number;
  reasoning: string;
  context: string; // JSON
  applied: boolean;
  created_at: string;
  applied_at?: string;
}

export interface AgentPatternRecord {
  id: string;
  agent_id: string;
  pattern_type: string;
  pattern_data: string; // JSON
  frequency: number;
  success_rate: number;
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface AgentMemoryRecord {
  id: string;
  agent_id: string;
  memory_type: 'short' | 'long' | 'episodic' | 'semantic';
  key: string;
  value: string; // JSON
  importance: number;
  access_count: number;
  last_accessed: string;
  expires_at?: string;
  created_at: string;
}

export interface AgentPerformanceRecord {
  id: string;
  agent_id: string;
  metric_type: string;
  value: number;
  timestamp: string;
  context: string; // JSON
}

export interface AgentInteractionRecord {
  id: string;
  agent_id: string;
  interaction_type: string;
  source_system: string;
  request: string; // JSON
  response: string; // JSON
  duration_ms: number;
  success: boolean;
  error?: string;
  created_at: string;
}

export class AgentDatabaseIntegration {
  private db: any; // D1Database or other database connection
  private env: any;
  private initialized: boolean = false;

  constructor(env: any) {
    this.env = env;
    this.db = env.DB || env.COREFLOW_DB;
  }

  // === Database Initialization ===

  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      await this.createAgentTables();
      await this.createIndices();
      await this.verifyConnection();
      this.initialized = true;
    } catch (error: any) {
      throw error;
    }
  }

  private async createAgentTables(): Promise<void> {
    const tables = [
      // Agent Decisions Table
      `CREATE TABLE IF NOT EXISTS agent_decisions (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        workflow_id TEXT,
        decision_type TEXT NOT NULL,
        decision_action TEXT NOT NULL,
        confidence REAL NOT NULL,
        reasoning TEXT,
        context TEXT,
        applied BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        applied_at TIMESTAMP,
        FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE
      )`,

      // Agent Patterns Table
      `CREATE TABLE IF NOT EXISTS agent_patterns (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        pattern_type TEXT NOT NULL,
        pattern_data TEXT NOT NULL,
        frequency INTEGER DEFAULT 0,
        success_rate REAL DEFAULT 0.0,
        last_seen TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`,

      // Agent Memory Table
      `CREATE TABLE IF NOT EXISTS agent_memory (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        memory_type TEXT NOT NULL CHECK(memory_type IN ('short', 'long', 'episodic', 'semantic')),
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        importance REAL DEFAULT 0.5,
        access_count INTEGER DEFAULT 0,
        last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(agent_id, memory_type, key)
      )`,

      // Agent Performance Metrics Table
      `CREATE TABLE IF NOT EXISTS agent_performance (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        metric_type TEXT NOT NULL,
        value REAL NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        context TEXT
      )`,

      // Agent Interactions Log Table
      `CREATE TABLE IF NOT EXISTS agent_interactions (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        interaction_type TEXT NOT NULL,
        source_system TEXT NOT NULL,
        request TEXT,
        response TEXT,
        duration_ms INTEGER,
        success BOOLEAN DEFAULT TRUE,
        error TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    ];

    for (const query of tables) {
      try {
        await this.db.prepare(query).run();
      } catch (error: any) {
        throw error;
      }
    }
  }

  private async createIndices(): Promise<void> {
    const indices = [
      `CREATE INDEX IF NOT EXISTS idx_agent_decisions_agent ON agent_decisions(agent_id)`,
      `CREATE INDEX IF NOT EXISTS idx_agent_decisions_workflow ON agent_decisions(workflow_id)`,
      `CREATE INDEX IF NOT EXISTS idx_agent_decisions_created ON agent_decisions(created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_agent_patterns_agent ON agent_patterns(agent_id)`,
      `CREATE INDEX IF NOT EXISTS idx_agent_memory_agent ON agent_memory(agent_id, memory_type)`,
      `CREATE INDEX IF NOT EXISTS idx_agent_memory_expires ON agent_memory(expires_at)`,
      `CREATE INDEX IF NOT EXISTS idx_agent_performance_agent ON agent_performance(agent_id, timestamp DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_agent_interactions_agent ON agent_interactions(agent_id, created_at DESC)`
    ];

    for (const query of indices) {
      try {
        await this.db.prepare(query).run();
      } catch (error: any) {
        // Non-critical, continue
      }
    }
  }

  private async verifyConnection(): Promise<void> {
    const result = await this.db.prepare('SELECT 1 as test').first();
    if (!result) {
      throw new Error('Database connection verification failed');
    }
  }

  // === Decision Management ===

  async saveDecision(decision: Omit<AgentDecisionRecord, 'created_at'>): Promise<string> {
    const id = decision.id || crypto.randomUUID();
    const query = `
      INSERT INTO agent_decisions (
        id, agent_id, workflow_id, decision_type, decision_action,
        confidence, reasoning, context, applied
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await this.db.prepare(query).bind(
      id,
      decision.agent_id,
      decision.workflow_id || null,
      decision.decision_type,
      decision.decision_action,
      decision.confidence,
      decision.reasoning,
      decision.context,
      decision.applied || false
    ).run();

    return id;
  }

  async getDecision(decisionId: string): Promise<AgentDecisionRecord | null> {
    const query = `SELECT * FROM agent_decisions WHERE id = ?`;
    return await this.db.prepare(query).bind(decisionId).first();
  }

  async getAgentDecisions(
    agentId: string,
    limit: number = 100,
    offset: number = 0
  ): Promise<AgentDecisionRecord[]> {
    const query = `
      SELECT * FROM agent_decisions
      WHERE agent_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `;

    const result = await this.db.prepare(query).bind(agentId, limit, offset).all();
    return result.results || [];
  }

  async getWorkflowDecisions(workflowId: string): Promise<AgentDecisionRecord[]> {
    const query = `
      SELECT * FROM agent_decisions
      WHERE workflow_id = ?
      ORDER BY created_at DESC
    `;

    const result = await this.db.prepare(query).bind(workflowId).all();
    return result.results || [];
  }

  async markDecisionApplied(decisionId: string): Promise<void> {
    const query = `
      UPDATE agent_decisions
      SET applied = TRUE, applied_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;

    await this.db.prepare(query).bind(decisionId).run();
  }

  // === Pattern Recognition ===

  async savePattern(pattern: Omit<AgentPatternRecord, 'created_at' | 'updated_at'>): Promise<string> {
    const id = pattern.id || crypto.randomUUID();
    const query = `
      INSERT INTO agent_patterns (
        id, agent_id, pattern_type, pattern_data,
        frequency, success_rate, last_seen
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        frequency = frequency + 1,
        success_rate = excluded.success_rate,
        last_seen = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
    `;

    await this.db.prepare(query).bind(
      id,
      pattern.agent_id,
      pattern.pattern_type,
      pattern.pattern_data,
      pattern.frequency || 1,
      pattern.success_rate || 0,
      pattern.last_seen || new Date().toISOString()
    ).run();

    return id;
  }

  async getAgentPatterns(
    agentId: string,
    patternType?: string
  ): Promise<AgentPatternRecord[]> {
    let query = `
      SELECT * FROM agent_patterns
      WHERE agent_id = ?
    `;

    const params = [agentId];

    if (patternType) {
      query += ` AND pattern_type = ?`;
      params.push(patternType);
    }

    query += ` ORDER BY frequency DESC, success_rate DESC`;

    const result = await this.db.prepare(query).bind(...params).all();
    return result.results || [];
  }

  async updatePatternSuccess(patternId: string, success: boolean): Promise<void> {
    const currentPattern = await this.db.prepare(
      `SELECT frequency, success_rate FROM agent_patterns WHERE id = ?`
    ).bind(patternId).first();

    if (currentPattern) {
      const newFrequency = currentPattern.frequency + 1;
      const currentSuccessCount = currentPattern.success_rate * currentPattern.frequency;
      const newSuccessRate = (currentSuccessCount + (success ? 1 : 0)) / newFrequency;

      await this.db.prepare(`
        UPDATE agent_patterns
        SET frequency = ?, success_rate = ?, last_seen = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(newFrequency, newSuccessRate, patternId).run();
    }
  }

  // === Memory Management ===

  async saveMemory(memory: Omit<AgentMemoryRecord, 'created_at' | 'last_accessed'>): Promise<string> {
    const id = memory.id || crypto.randomUUID();
    const query = `
      INSERT INTO agent_memory (
        id, agent_id, memory_type, key, value,
        importance, access_count, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(agent_id, memory_type, key) DO UPDATE SET
        value = excluded.value,
        importance = excluded.importance,
        access_count = agent_memory.access_count + 1,
        last_accessed = CURRENT_TIMESTAMP
    `;

    await this.db.prepare(query).bind(
      id,
      memory.agent_id,
      memory.memory_type,
      memory.key,
      memory.value,
      memory.importance || 0.5,
      memory.access_count || 0,
      memory.expires_at || null
    ).run();

    return id;
  }

  async getMemory(agentId: string, memoryType: string, key: string): Promise<AgentMemoryRecord | null> {
    const query = `
      SELECT * FROM agent_memory
      WHERE agent_id = ? AND memory_type = ? AND key = ?
    `;

    const memory = await this.db.prepare(query).bind(agentId, memoryType, key).first();

    if (memory) {
      // Update access count and last accessed
      await this.db.prepare(`
        UPDATE agent_memory
        SET access_count = access_count + 1, last_accessed = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(memory.id).run();
    }

    return memory;
  }

  async getAgentMemories(
    agentId: string,
    memoryType?: string
  ): Promise<AgentMemoryRecord[]> {
    let query = `
      SELECT * FROM agent_memory
      WHERE agent_id = ?
    `;

    const params = [agentId];

    if (memoryType) {
      query += ` AND memory_type = ?`;
      params.push(memoryType);
    }

    query += ` AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
               ORDER BY importance DESC, last_accessed DESC`;

    const result = await this.db.prepare(query).bind(...params).all();
    return result.results || [];
  }

  async cleanExpiredMemories(): Promise<number> {
    const result = await this.db.prepare(`
      DELETE FROM agent_memory
      WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP
    `).run();

    return result.meta.changes || 0;
  }

  // === Performance Tracking ===

  async recordPerformance(
    agentId: string,
    metricType: string,
    value: number,
    context?: any
  ): Promise<string> {
    const id = crypto.randomUUID();
    const query = `
      INSERT INTO agent_performance (id, agent_id, metric_type, value, context)
      VALUES (?, ?, ?, ?, ?)
    `;

    await this.db.prepare(query).bind(
      id,
      agentId,
      metricType,
      value,
      context ? JSON.stringify(context) : null
    ).run();

    return id;
  }

  async getAgentPerformance(
    agentId: string,
    metricType?: string,
    since?: Date
  ): Promise<AgentPerformanceRecord[]> {
    let query = `
      SELECT * FROM agent_performance
      WHERE agent_id = ?
    `;

    const params: any[] = [agentId];

    if (metricType) {
      query += ` AND metric_type = ?`;
      params.push(metricType);
    }

    if (since) {
      query += ` AND timestamp > ?`;
      params.push(since.toISOString());
    }

    query += ` ORDER BY timestamp DESC LIMIT 1000`;

    const result = await this.db.prepare(query).bind(...params).all();
    return result.results || [];
  }

  async getAggregatedPerformance(
    agentId: string,
    metricType: string,
    aggregation: 'avg' | 'sum' | 'min' | 'max',
    since?: Date
  ): Promise<number> {
    let query = `
      SELECT ${aggregation}(value) as result
      FROM agent_performance
      WHERE agent_id = ? AND metric_type = ?
    `;

    const params: any[] = [agentId, metricType];

    if (since) {
      query += ` AND timestamp > ?`;
      params.push(since.toISOString());
    }

    const result = await this.db.prepare(query).bind(...params).first();
    return result?.result || 0;
  }

  // === Interaction Logging ===

  async logInteraction(interaction: Omit<AgentInteractionRecord, 'id' | 'created_at'>): Promise<string> {
    const id = crypto.randomUUID();
    const query = `
      INSERT INTO agent_interactions (
        id, agent_id, interaction_type, source_system,
        request, response, duration_ms, success, error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await this.db.prepare(query).bind(
      id,
      interaction.agent_id,
      interaction.interaction_type,
      interaction.source_system,
      interaction.request,
      interaction.response,
      interaction.duration_ms,
      interaction.success,
      interaction.error || null
    ).run();

    return id;
  }

  async getAgentInteractions(
    agentId: string,
    limit: number = 100
  ): Promise<AgentInteractionRecord[]> {
    const query = `
      SELECT * FROM agent_interactions
      WHERE agent_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `;

    const result = await this.db.prepare(query).bind(agentId, limit).all();
    return result.results || [];
  }

  // === Analytics Queries ===

  async getAgentAnalytics(agentId: string): Promise<any> {
    const [
      totalDecisions,
      successfulDecisions,
      totalPatterns,
      memoryUsage,
      avgResponseTime,
      recentInteractions
    ] = await Promise.all([
      this.db.prepare(`
        SELECT COUNT(*) as count FROM agent_decisions WHERE agent_id = ?
      `).bind(agentId).first(),

      this.db.prepare(`
        SELECT COUNT(*) as count FROM agent_decisions
        WHERE agent_id = ? AND applied = TRUE
      `).bind(agentId).first(),

      this.db.prepare(`
        SELECT COUNT(*) as count FROM agent_patterns WHERE agent_id = ?
      `).bind(agentId).first(),

      this.db.prepare(`
        SELECT COUNT(*) as count, memory_type
        FROM agent_memory
        WHERE agent_id = ?
        GROUP BY memory_type
      `).bind(agentId).all(),

      this.db.prepare(`
        SELECT AVG(duration_ms) as avg_time
        FROM agent_interactions
        WHERE agent_id = ? AND success = TRUE
      `).bind(agentId).first(),

      this.db.prepare(`
        SELECT COUNT(*) as count, interaction_type
        FROM agent_interactions
        WHERE agent_id = ? AND created_at > datetime('now', '-7 days')
        GROUP BY interaction_type
      `).bind(agentId).all()
    ]);

    return {
      decisions: {
        total: totalDecisions?.count || 0,
        applied: successfulDecisions?.count || 0,
        successRate: totalDecisions?.count > 0
          ? (successfulDecisions?.count || 0) / totalDecisions.count
          : 0
      },
      patterns: {
        total: totalPatterns?.count || 0
      },
      memory: {
        types: memoryUsage?.results || []
      },
      performance: {
        avgResponseTime: avgResponseTime?.avg_time || 0
      },
      interactions: {
        recent: recentInteractions?.results || []
      }
    };
  }

  // === Cleanup and Maintenance ===

  async cleanupOldData(daysToKeep: number = 90): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
    const cutoffStr = cutoffDate.toISOString();

    await Promise.all([
      this.db.prepare(`
        DELETE FROM agent_decisions
        WHERE created_at < ? AND applied = TRUE
      `).bind(cutoffStr).run(),

      this.db.prepare(`
        DELETE FROM agent_interactions
        WHERE created_at < ?
      `).bind(cutoffStr).run(),

      this.db.prepare(`
        DELETE FROM agent_performance
        WHERE timestamp < ?
      `).bind(cutoffStr).run()
    ]);

    // Clean expired memories
    await this.cleanExpiredMemories();
  }
}