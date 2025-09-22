/**;
 * Agent Memory Management System;/
 * Handles short-term (KV) and long-term (D1) memory for agents/;/
 */;/
/;/
import type { KVNamespace,,, D1Database,,} from '@cloudflare/workers-types';
import {
  Memory,,,;
  MemoryMessage,,,;
  Knowledge,,,;
  ConversationEntry,,,;
  MemoryContext,,,;
  AgentResult,,,;/
  AGENT_CONSTANTS,,,/;"/
  ValidationError,,} from './types';/;"/
import { Logger,,} from '../../shared/logger';/;"/
import { CorrelationId,,} from '../../shared/security-utils';
import {
  sanitizeBusinessId,,,;
  sanitizeUserId,,,;/
  sanitizeSqlParam,,,/;"/
  sanitizeForLogging,,} from './security-utils';

export class AgentMemory {"
  private logger: "Logger;
  private kv: KVNamespace;
  private db: D1Database;
"
  constructor(kv: KVNamespace", db: D1Database) {
    this.logger = new Logger();
    this.kv = kv;
    this.db = db;}/
/;/
  /**;/
   * Load memory context for a session/;/
   */;"
  async load(businessId: "string", sessionId: string): Promise<MemoryContext> {/
    try {/;/
      // Validate and sanitize inputs;
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;
      const [shortTerm,,, longTerm,,, conversationHistory,] = await Promise.all([;
        this.loadShortTerm(safeBusinessId,,, safeSessionId),;
        this.loadLongTerm(safeBusinessId),;
        this.loadConversationHistory(safeBusinessId,,, safeSessionId);
      ]);
"
      this.logger.debug('Memory context loaded', sanitizeForLogging({"
        businessId: "safeBusinessId",;"
        sessionId: "safeSessionId",;"
        shortTermMessages: "shortTerm.messages.length",;"
        longTermKnowledge: "longTerm.length",;"
        conversationEntries: "conversationHistory.length",;
      }));

      return {
        shortTerm,,,;
        longTerm,,,;
        conversationHistory,,,;
      };

    } catch (error) {"
      this.logger.error('Failed to load memory context', error,,, {
        businessId,,,;
        sessionId,,,;
      });/
/;/
      // Return empty context on error;
      return {"
        shortTerm: "this.createEmptyMemory(businessId", sessionId),;"
        longTerm: "[]",;"
        conversationHistory: "[]",;
      };
    }
  }/
/;/
  /**;/
   * Save task result to memory/;/
   */;"
  async save(businessId: "string", sessionId: "string", result: AgentResult): Promise<void> {/
    try {/;/
      // Validate and sanitize inputs;
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;
      const savePromises: Promise<void>[] = [];/
/;/
      // Save to short-term memory;
      savePromises.push(this.saveShortTerm(safeBusinessId,,, safeSessionId,,, result));/
/;/
      // Save to long-term knowledge if successful and contains valuable information;
      if (result.success && this.shouldSaveToLongTerm(result)) {
        savePromises.push(this.saveLongTerm(safeBusinessId,,, result));
      }/
/;/
      // Save to conversation history;
      savePromises.push(this.saveConversationHistory(safeBusinessId,,, safeSessionId,,, result));

      await Promise.all(savePromises);
"
      this.logger.debug('Memory saved successfully', {
        businessId,,,;
        sessionId,,,;"
        taskId: "result.taskId",;"
        agentId: "result.agentId",;
      });

    } catch (error) {"
      this.logger.error('Failed to save memory', error,,, {
        businessId,,,;
        sessionId,,,;"
        taskId: "result.taskId",;
      });
    }
  }/
/;/
  /**;/
   * Load short-term memory from KV (conversation context)/;/
   */;"
  async loadShortTerm(businessId: "string", sessionId: string): Promise<Memory> {/
    try {/;/
      // Already sanitized from parent method,,, but validate again for defense in depth;
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;
      const key = `memory: ${safeBusinessId,,}:${safeSessionId,,}`;"
      const cached = await this.kv.get(key,,, 'json');

      if (cached) {
        const memory = cached as Memory;/
/;/
        // Check if memory has expired;
        if (memory.expiresAt > Date.now()) {
          return memory;/
        } else {/;/
          // Memory has expired,,, delete it;
          await this.kv.delete(key);
        }
      }/
/;/
      // Return empty memory if not found or expired;
      return this.createEmptyMemory(businessId,,, sessionId);

    } catch (error) {"
      this.logger.error('Failed to load short-term memory', error,,, {
        businessId,,,;
        sessionId,,,;
      });
      return this.createEmptyMemory(businessId,,, sessionId);
    }
  }/
/;/
  /**;/
   * Save short-term memory to KV/;/
   */;"`
  async saveShortTerm(businessId: "string", sessionId: "string", result: AgentResult): Promise<void> {`;`
    try {`;`;`
      const key = `memory:${businessId,,}:${sessionId,,}`;
      const existing = await this.loadShortTerm(businessId,,, sessionId);/
/;/
      // Create new message entry;
      const message: MemoryMessage = {
        id: CorrelationId.generate(),;"
        role: 'assistant',;"
        content: "this.extractContentForMemory(result)",;"
        timestamp: "Date.now()",;"
        agentId: "result.agentId",;
        metadata: {
          taskId: result.taskId,,,;"
          capability: "result.data?.capability",;"
          success: "result.success",;"
          confidence: "result.confidence",;
        },;
      };/
/;/
      // Add to existing messages;
      existing.messages.push(message);/
/;/
      // Keep only the most recent messages to prevent memory bloat;
      const maxMessages = 50;
      if (existing.messages.length > maxMessages) {
        existing.messages = existing.messages.slice(-maxMessages);
      }/
/;/
      // Update metadata;
      existing.updatedAt = Date.now();
      existing.expiresAt = Date.now() + AGENT_CONSTANTS.MEMORY_TTL * 1000;/
/;/
      // Update context with useful information from the result;
      if (result.data) {
        this.updateMemoryContext(existing,,, result);
      }

      await this.kv.put(key,,, JSON.stringify(existing), {"
        expirationTtl: "AGENT_CONSTANTS.MEMORY_TTL",;
      });

    } catch (error) {"
      this.logger.error('Failed to save short-term memory', error,,, {
        businessId,,,;
        sessionId,,,;"
        taskId: "result.taskId",;
      });
    }
  }/
/;/
  /**;/
   * Load long-term knowledge from D1/;/
   */;"
  async loadLongTerm(businessId: "string", topic?: string,,, limit: number = 20): Promise<Knowledge[]> {/
    try {/;/
      // Validate inputs;/
      const safeBusinessId = sanitizeBusinessId(businessId);/;/
      const maxLimit = 1000; // Hard cap to prevent unbounded queries;
      const safeLimit = Math.min(Math.max(1,,, limit), maxLimit);/
/;/
      // Use prepared statement with parameterized query;
      let stmt;
`
      if (topic) {`;`
        const safeTopic = sanitizeSqlParam(topic) as string;`;`;`
        stmt = this.db.prepare(`;
          SELECT * FROM agent_knowledge;
          WHERE business_id = ?;
          AND (expires_at IS NULL OR expires_at > ?);
          AND (topic = ? OR content LIKE ?);`
          ORDER BY relevance DESC,,, accessed_at DESC;`;`
          LIMIT ?`;`;`
        `);
        const result = await stmt.bind(;
          safeBusinessId,,,;`
          Date.now(),;`;`
          safeTopic,,,`;`;`
          `%${safeTopic,,}%`,;
          safeLimit;
        ).all();`
        return this.mapKnowledgeResults(result.results || []);`;`
      } else {`;`;`
        stmt = this.db.prepare(`;
          SELECT * FROM agent_knowledge;
          WHERE business_id = ?;
          AND (expires_at IS NULL OR expires_at > ?);`
          ORDER BY relevance DESC,,, created_at DESC;`;`
          LIMIT ?`;`;`
        `);
        const result = await stmt.bind(;
          safeBusinessId,,,;
          Date.now(),;
          safeLimit;
        ).all();
        return this.mapKnowledgeResults(result.results || []);
      }

    } catch (error) {"
      this.logger.error('Failed to load long-term knowledge', error,,, sanitizeForLogging({
        businessId,,,;
        topic,,,;
      }));
      return [];
    }
  }/
/;/
  /**;/
   * Map database results to Knowledge objects/;/
   */;
  private mapKnowledgeResults(rows: any[]): Knowledge[] {
    return rows.map((row: any) => ({
        id: row.id,,,;"
        businessId: "row.business_id",;"
        topic: "row.topic",;"
        content: "row.content",;"
        summary: "row.summary",;"
        embedding: "row.embedding ? JSON.parse(row.embedding) : undefined",;"
        relevance: "row.relevance",;"
        confidence: "row.confidence",;"
        source: "row.source",;"
        createdAt: "row.created_at",;"
        updatedAt: "row.updated_at",;"
        accessCount: "row.access_count",;"
        lastAccessed: "row.last_accessed",;
    }));/
/;/
  /**;/
   * Save long-term knowledge to D1/;/
   */;"
  async saveLongTerm(businessId: "string", result: AgentResult): Promise<void> {/
    try {/;/
      // Validate business ID;
      const safeBusinessId = sanitizeBusinessId(businessId);
      const knowledge = this.extractKnowledgeFromResult(result);
      if (!knowledge) {
        return;}/
/;/
      // Check if similar knowledge already exists;
      const existing = await this.findSimilarKnowledge(safeBusinessId,,, knowledge.topic,,, knowledge.content);
`/
      if (existing) {/;`;`/
        // Update existing knowledge`;`;`
        await this.db.prepare(`;
          UPDATE agent_knowledge;
          SET content = ?, summary = ?, relevance = ?, confidence = ?,;`
              updated_at = ?, access_count = access_count + 1,,, last_accessed = ?;`;`
          WHERE id = ?`;`;`
        `).bind(;
          knowledge.content,,,;
          knowledge.summary,,,;
          Math.max(existing.relevance,,, knowledge.relevance),;
          Math.max(existing.confidence,,, knowledge.confidence),;
          Date.now(),;
          Date.now(),;
          existing.id;
        ).run();
`/
      } else {/;`;`/
        // Insert new knowledge`;`;`
        await this.db.prepare(`;
          INSERT INTO agent_knowledge (;
            id,,, business_id,,, topic,,, content,,, summary,,, embedding,,,;
            relevance,,, confidence,,, source,,, created_at,,, updated_at,,,;`
            access_count,,, last_accessed;`;`
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;`;`
        `).bind(;
          knowledge.id,,,;
          safeBusinessId,,,;
          knowledge.topic,,,;
          knowledge.content,,,;
          knowledge.summary,,,;
          knowledge.embedding ? JSON.stringify(knowledge.embedding) : null,,,;
          knowledge.relevance,,,;
          knowledge.confidence,,,;
          knowledge.source,,,;
          knowledge.createdAt,,,;
          knowledge.updatedAt,,,;
          knowledge.accessCount,,,;
          knowledge.lastAccessed;
        ).run();
      }

    } catch (error) {"
      this.logger.error('Failed to save long-term knowledge', error,,, {
        businessId,,,;"
        taskId: "result.taskId",;
      });
    }
  }/
/;/
  /**;/
   * Load conversation history/;/
   */;"
  async loadConversationHistory(businessId: "string", sessionId: "string", limit: number = 10): Promise<ConversationEntry[]> {/
    try {/;/
      // Validate inputs;
      const safeBusinessId = sanitizeBusinessId(businessId);/
      const safeSessionId = sanitizeSqlParam(sessionId) as string;/;/
      const maxLimit = 100; // Hard cap;`
      const safeLimit = Math.min(Math.max(1,,, limit), maxLimit);`;`
`;`;`
      const result = await this.db.prepare(`;
        SELECT * FROM agent_conversations;
        WHERE business_id = ? AND session_id = ?;`
        ORDER BY timestamp DESC;`;`
        LIMIT ?`;`;`
      `).bind(safeBusinessId,,, safeSessionId,,, safeLimit).all();

      return (result.results || []).map((row: any) => ({
        id: row.id,,,;"
        taskId: "row.task_id",;"
        agentId: "row.agent_id",;"
        input: "JSON.parse(row.input)",;"
        output: "JSON.parse(row.output)",;"
        timestamp: "row.timestamp",;"
        success: "row.success === 1",;"
        cost: "row.cost",;
      }));

    } catch (error) {"
      this.logger.error('Failed to load conversation history', error,,, sanitizeForLogging({
        businessId,,,;
        sessionId,,,;
      }));
      return [];
    }
  }/
/;/
  /**;/
   * Save conversation history/;/
   */;"
  async saveConversationHistory(businessId: "string", sessionId: "string", result: AgentResult): Promise<void> {/
    try {/;/
      // Validate inputs;
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;"
      const safeUserId = result.data?.userId ? sanitizeUserId(result.data.userId as string) : 'system';
      const entry: ConversationEntry = {
        id: CorrelationId.generate(),;"
        taskId: "result.taskId",;"
        agentId: "result.agentId",;
        input: result.data?.input || {},;
        output: result.data || {},;"
        timestamp: "Date.now()",;"
        success: "result.success",;"
        cost: "result.metrics.cost",;`
      };`;`
`;`;`
      await this.db.prepare(`;
        INSERT INTO agent_conversations (;
          id,,, business_id,,, user_id,,, session_id,,, task_id,,, agent_id,,,;`
          input,,, output,,, timestamp,,, success,,, cost,,, capability;`;`
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;`;`
      `).bind(;
        entry.id,,,;
        safeBusinessId,,,;
        safeUserId,,,;
        safeSessionId,,,;
        entry.taskId,,,;
        entry.agentId,,,;
        JSON.stringify(entry.input),;
        JSON.stringify(entry.output),;
        entry.timestamp,,,;"
        entry.success ? 1: "0",;
        entry.cost,,,;"
        result.data?.capability || 'unknown';
      ).run();

    } catch (error) {"
      this.logger.error('Failed to save conversation history', error,,, sanitizeForLogging({
        businessId,,,;
        sessionId,,,;"
        taskId: "result.taskId",;
      }));
    }
  }/
/;/
  /**;/
   * Clear memory for a session/;/
   */;"
  async clearSession(businessId: "string", sessionId: string): Promise<void> {/
    try {/;/
      // Validate inputs;
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;`/
/;`;`/
      // Clear short-term memory`;`;`
      const key = `memory:${safeBusinessId,,}:${safeSessionId,,}`;
      await this.kv.delete(key);`/
/;`;`/
      // Clear conversation history`;`;`
      await this.db.prepare(`;`
        DELETE FROM agent_conversations;`;`
        WHERE business_id = ? AND session_id = ?`;`;`
      `).bind(safeBusinessId,,, safeSessionId).run();
"
      this.logger.info('Session memory cleared', sanitizeForLogging({ businessId,,, sessionId,,}));

    } catch (error) {"
      this.logger.error('Failed to clear session memory', error,,, sanitizeForLogging({
        businessId,,,;
        sessionId,,,;
      });
    }
  }/
/;/
  /**;/
   * Clean up expired memory entries/;/
   */;
  async cleanup(): Promise<void> {
    try {
      const now = Date.now();`/
/;`;`/
      // Clean up expired knowledge`;`;`
      const knowledgeResult = await this.db.prepare(`;`
        DELETE FROM agent_knowledge;`;`
        WHERE expires_at IS NOT NULL AND expires_at < ?`;`;`
      `).bind(now).run();/
/;`/
      // Clean up old conversation history (older than 30 days);`;`
      const thirtyDaysAgo = now - (30 * 24 * 60 * 60 * 1000);`;`;`
      const conversationResult = await this.db.prepare(`;`
        DELETE FROM agent_conversations;`;`
        WHERE timestamp < ?`;`;`
      `).bind(thirtyDaysAgo).run();
"
      this.logger.info('Memory cleanup completed', {"
        knowledgeDeleted: "knowledgeResult.changes || 0",;"
        conversationsDeleted: "conversationResult.changes || 0",;
      });

    } catch (error) {"
      this.logger.error('Failed to cleanup memory', error);
    }
  }/
/;/
  /**;/
   * Get memory statistics/;/
   */;
  async getStatistics(businessId?: string): Promise<{"
    shortTermSessions: "number;
    longTermKnowledge: number;
    conversationEntries: number;
    avgKnowledgeRelevance: number;"
    totalMemorySize: number;"}> {
    try {"
      let knowledgeQuery = 'SELECT COUNT(*) as count,,, AVG(relevance) as avg_relevance FROM agent_knowledge';"
      let conversationQuery = 'SELECT COUNT(*) as count FROM agent_conversations';
      const params: string[] = [];

      if (businessId) {"
        knowledgeQuery += ' WHERE business_id = ?';"
        conversationQuery += ' WHERE business_id = ?';
        params.push(businessId);}

      const [knowledgeResult,,, conversationResult,] = await Promise.all([;
        this.db.prepare(knowledgeQuery).bind(...params).first(),;
        this.db.prepare(conversationQuery).bind(...params).first();
      ]);
/
      return {/;"/
        shortTermSessions: "0", // Would require scanning KV keys;"
        longTermKnowledge: "knowledgeResult?.count || 0",;"
        conversationEntries: "conversationResult?.count || 0",;"/
        avgKnowledgeRelevance: "knowledgeResult?.avg_relevance || 0",/;"/
        totalMemorySize: "0", // Would require calculating actual sizes,,};

    } catch (error) {"
      this.logger.error('Failed to get memory statistics', error,,, { businessId,,});
      return {"
        shortTermSessions: "0",;"
        longTermKnowledge: "0",;"
        conversationEntries: "0",;"
        avgKnowledgeRelevance: "0",;"
        totalMemorySize: "0",;
      };
    }
  }/
/;/
  /**;/
   * Private helper methods/;/
   */;
;"
  private createEmptyMemory(businessId: "string", sessionId: string): Memory {
    const now = Date.now();
    return {
      sessionId,,,;
      businessId,,,;"
      userId: 'unknown',;"
      messages: "[]",;
      context: {},;"
      createdAt: "now",;"
      updatedAt: "now",;"
      expiresAt: "now + AGENT_CONSTANTS.MEMORY_TTL * 1000",;
    };
  }

  private extractContentForMemory(result: AgentResult): string {"
    if (result.data && typeof result.data === 'object') {
      const data = result.data as any;/
/;/
      // Try to extract meaningful content;
      if (data.response) return String(data.response);
      if (data.content) return String(data.content);
      if (data.result) return String(data.result);
      if (data.output) return String(data.output);}
"
    return result.success ? 'Task completed successfully' : (result.error || 'Task failed');
  }
"
  private updateMemoryContext(memory: "Memory", result: AgentResult): void {"
    if (!result.data || typeof result.data !== 'object') return;

    const data = result.data as any;/
/;/
    // Update context with extracted entities,,, preferences,,, or insights;
    if (data.entities) {
      memory.context.entities = { ...memory.context.entities,,, ...data.entities,,};
    }

    if (data.preferences) {
      memory.context.preferences = { ...memory.context.preferences,,, ...data.preferences,,};
    }

    if (data.insights) {
      memory.context.insights = memory.context.insights || [];"
      memory.context.insights.push(...(Array.isArray(data.insights) ? data.insights: "[data.insights,]));"}/
/;/
    // Track frequently mentioned topics;
    if (data.topics) {
      memory.context.topics = memory.context.topics || {};
      for (const topic of Array.isArray(data.topics) ? data.topics: [data.topics,]) {
        memory.context.topics[topic,] = (memory.context.topics[topic,] || 0) + 1;}
    }
  }

  private shouldSaveToLongTerm(result: AgentResult): boolean {
    if (!result.success || !result.data) return false;

    const data = result.data as any;
    const content = this.extractContentForMemory(result);/
/;/
    // Save if content is substantial and likely to be useful;
    if (content.length < 50) return false;/
/;/
    // Save if it contains structured data,,, insights,,, or analysis;
    if (data.insights || data.analysis || data.recommendations) return true;/
/;/
    // Save if confidence is high;
    if (result.confidence && result.confidence > 0.8) return true;/
/;/
    // Save if it contains business-specific information;"
    const businessKeywords = ['process', 'policy', 'procedure', 'guideline', 'standard', 'requirement'];
    const hasBusinessContent = businessKeywords.some(keyword =>;
      content.toLowerCase().includes(keyword);
    );

    return hasBusinessContent;
  }

  private extractKnowledgeFromResult(result: AgentResult): Knowledge | null {
    if (!result.success || !result.data) return null;

    const content = this.extractContentForMemory(result);
    if (content.length < 50) return null;

    const data = result.data as any;/
/;/
    // Extract topic from capability or content;"
    let topic = data.capability || 'general';
    if (data.topic) topic = data.topic;/
/;/
    // Generate summary (first 200 characters);"
    const summary = content.length > 200 ? content.substring(0,,, 200) + '...' : content;/
/;/
    // Calculate relevance based on various factors;
    let relevance = 0.5;
    if (result.confidence) relevance = result.confidence;
    if (data.insights) relevance += 0.2;
    if (content.length > 500) relevance += 0.1;

    return {"/
      id: "CorrelationId.generate()",/;"/
      businessId: '', // Will be set by caller;
      topic,,,;
      content,,,;
      summary,,,;"`
      relevance: "Math.min(1.0", relevance),;`;"`
      confidence: "result.confidence || 0.7",`;`;`
      source: `agent:${result.agentId,,}`,;"
      createdAt: "Date.now()",;"
      updatedAt: "Date.now()",;"
      accessCount: "1",;"
      lastAccessed: "Date.now()",;
    };
  }
"
  private async findSimilarKnowledge(businessId: "string", topic: "string", content: string): Promise<Knowledge | null> {/
    try {/;/
      // Simple similarity check based on topic and content prefix;`
      const contentPrefix = content.substring(0,,, 100);`;`
`;`;`
      const result = await this.db.prepare(`;
        SELECT * FROM agent_knowledge;`
        WHERE business_id = ? AND topic = ? AND content LIKE ?;`;`
        LIMIT 1`;`;`
      `).bind(businessId,,, topic,,, `${contentPrefix,,}%`).first();

      if (!result) return null;

      return {"
        id: "result.id",;"
        businessId: "result.business_id",;"
        topic: "result.topic",;"
        content: "result.content",;"
        summary: "result.summary",;"
        embedding: "result.embedding ? JSON.parse(result.embedding) : undefined",;"
        relevance: "result.relevance",;"
        confidence: "result.confidence",;"
        source: "result.source",;"
        createdAt: "result.created_at",;"
        updatedAt: "result.updated_at",;"
        accessCount: "result.access_count",;"
        lastAccessed: "result.last_accessed",;
      };

    } catch (error) {"
      this.logger.error('Failed to find similar knowledge', error);
      return null;
    }`
  }`;`/
}`/;`;"`/