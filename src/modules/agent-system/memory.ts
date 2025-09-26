/**
 * Agent Memory Management System
 * Handles short-term (KV) and long-term (D1) memory for agents
 */
import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import {
  Memory,
  MemoryMessage,
  Knowledge,
  ConversationEntry,
  MemoryContext,
  AgentResult,
  AGENT_CONSTANTS
} from './types';
import { Logger } from '../../shared/logger';
import { ApplicationError as ValidationError } from '../../shared/error-handling';
import {
  sanitizeBusinessId,
  sanitizeUserId,
  sanitizeSqlParam,
  sanitizeForLogging
} from './security-utils';

export class AgentMemory {
  private logger: Logger;
  private kv: KVNamespace;
  private db: D1Database;

  constructor(kv: KVNamespace, db: D1Database) {
    this.logger = new Logger();
    this.kv = kv;
    this.db = db;
  }

  /**
   * Load memory context for a session
   */
  async load(businessId: string, sessionId: string): Promise<MemoryContext> {
    try {
      // Validate and sanitize inputs
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;
      
      const [shortTerm, longTerm, conversationHistory] = await Promise.all([
        this.loadShortTerm(safeBusinessId, safeSessionId),
        this.loadLongTerm(safeBusinessId),
        this.loadConversationHistory(safeBusinessId, safeSessionId)
      ]);

      this.logger.debug('Memory context loaded', sanitizeForLogging({
        businessId: safeBusinessId,
        sessionId: safeSessionId,
        shortTermCount: shortTerm.length,
        longTermCount: longTerm.length,
        conversationCount: conversationHistory.length
      }) as Record<string, unknown>);

      return {
        shortTerm,
        longTerm,
        conversationHistory
      };
    } catch (error) {
      this.logger.error('Failed to load memory context', {
        businessId: sanitizeForLogging(businessId),
        sessionId: sanitizeForLogging(sessionId),
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ValidationError('Failed to load memory context');
    }
  }

  /**
   * Save memory context for a session
   */
  async save(context: MemoryContext): Promise<void> {
    try {
      const { shortTerm, longTerm, conversationHistory } = context;
      
      // This is a placeholder for where businessId and sessionId would be retrieved
      const safeBusinessId = 'placeholder-business-id';
      const safeSessionId = 'placeholder-session-id';

      await Promise.all([
        this.saveShortTerm(safeBusinessId, safeSessionId, shortTerm),
        this.saveLongTerm(safeBusinessId, longTerm),
        this.saveConversationHistory(safeBusinessId, safeSessionId, conversationHistory)
      ]);

      this.logger.debug('Memory context saved', sanitizeForLogging({
        businessId: safeBusinessId,
        sessionId: safeSessionId,
        shortTermCount: shortTerm.length,
        longTermCount: longTerm.length,
        conversationCount: conversationHistory.length
      }) as Record<string, unknown>);
    } catch (error) {
      this.logger.error('Failed to save memory context', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ValidationError('Failed to save memory context');
    }
  }

  /**
   * Add a memory message to short-term memory
   */
  async addMemory(
    businessId: string,
    sessionId: string,
    message: MemoryMessage
  ): Promise<void> {
    try {
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;
      const safeUserId = 'placeholder-user-id';
      
      const key = this.getShortTermKey(safeBusinessId, safeSessionId);
      const existing = await this.kv.get(key, 'json') as Memory[] || [];
      
      // Add new memory with timestamp
      const memory: Memory = {
        messages: [message],
        createdAt: Date.now(),
        updatedAt: Date.now(),
        expiresAt: Date.now() + AGENT_CONSTANTS.MEMORY_TTL * 1000,
        businessId: safeBusinessId,
        sessionId: safeSessionId,
        userId: safeUserId,
        context: {}
      };
      
      existing.push(memory);
      
      // Keep only recent memories (limit to AGENT_CONSTANTS.MAX_MEMORY_SIZE)
      const recentMemories = existing
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, AGENT_CONSTANTS.MAX_MEMORY_SIZE);
      
      await this.kv.put(key, JSON.stringify(recentMemories), {
        expirationTtl: AGENT_CONSTANTS.MEMORY_TTL
      });

      this.logger.debug('Memory added', sanitizeForLogging({
        businessId: safeBusinessId,
        sessionId: safeSessionId,
        memoryId: message.id,
        type: message.role
      }) as Record<string, unknown>);
    } catch (error) {
      this.logger.error('Failed to add memory', {
        businessId: sanitizeForLogging(businessId),
        sessionId: sanitizeForLogging(sessionId),
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ValidationError('Failed to add memory');
    }
  }

  /**
   * Add knowledge to long-term memory
   */
  async addKnowledge(
    businessId: string,
    knowledge: Knowledge
  ): Promise<void> {
    try {
      const safeBusinessId = sanitizeBusinessId(businessId);
      
      // Store in D1 database for persistence
      await this.db.prepare(`
        INSERT INTO agent_knowledge (
          id, business_id, topic, content, summary, 
          relevance, confidence, source, created_at, updated_at, access_count, last_accessed
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        knowledge.id,
        safeBusinessId,
        knowledge.topic,
        knowledge.content,
        knowledge.summary,
        knowledge.relevance,
        knowledge.confidence,
        knowledge.source,
        knowledge.createdAt,
        knowledge.updatedAt,
        knowledge.accessCount,
        knowledge.lastAccessed
      ).run();

      this.logger.debug('Knowledge added', sanitizeForLogging({
        businessId: safeBusinessId,
        knowledgeId: knowledge.id,
        topic: knowledge.topic,
        source: knowledge.source
      }) as Record<string, unknown>);
    } catch (error) {
      this.logger.error('Failed to add knowledge', {
        businessId: sanitizeForLogging(businessId),
        knowledgeId: knowledge.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ValidationError('Failed to add knowledge');
    }
  }

  /**
   * Search knowledge in long-term memory
   */
  async searchKnowledge(
    businessId: string,
    query: string,
    category?: string,
    limit: number = 10
  ): Promise<Knowledge[]> {
    try {
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeQuery = sanitizeSqlParam(query) as string;
      const safeCategory = category ? sanitizeSqlParam(category) as string : null;
      
      let sql = `
        SELECT id, business_id, topic, content, summary, relevance, confidence, source, created_at, updated_at, access_count, last_accessed
        FROM agent_knowledge 
        WHERE business_id = ? 
        AND (topic LIKE ? OR content LIKE ? OR summary LIKE ?)
      `;
      
      const params: (string | number)[] = [safeBusinessId, `%${safeQuery}%`, `%${safeQuery}%`, `%${safeQuery}%`];
      
      if (safeCategory) {
        sql += ' AND category = ?';
        params.push(safeCategory);
      }
      
      sql += ' ORDER BY relevance DESC, last_accessed DESC LIMIT ?';
      params.push(limit);
      
      const result = await this.db.prepare(sql).bind(...params).all();
      
      return result.results as Knowledge[];
    } catch (error) {
      this.logger.error('Failed to search knowledge', {
        businessId: sanitizeForLogging(businessId),
        query: sanitizeForLogging(query),
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ValidationError('Failed to search knowledge');
    }
  }

  /**
   * Add conversation entry
   */
  async addConversationEntry(
    businessId: string,
    sessionId: string,
    entry: ConversationEntry
  ): Promise<void> {
    try {
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;
      
      // Store in D1 database
      await this.db.prepare(`
        INSERT INTO agent_conversations (
          id, taskId, agentId, input, 
          output, timestamp, success, cost
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        entry.id,
        entry.taskId,
        entry.agentId,
        JSON.stringify(entry.input),
        JSON.stringify(entry.output),
        entry.timestamp,
        entry.success,
        entry.cost
      ).run();

      this.logger.debug('Conversation entry added', sanitizeForLogging({
        businessId: safeBusinessId,
        sessionId: safeSessionId,
        entryId: entry.id,
        agentId: entry.agentId
      }) as Record<string, unknown>);
    } catch (error) {
      this.logger.error('Failed to add conversation entry', {
        businessId: sanitizeForLogging(businessId),
        sessionId: sanitizeForLogging(sessionId),
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ValidationError('Failed to add conversation entry');
    }
  }

  /**
   * Clear short-term memory for a session
   */
  async clearShortTerm(businessId: string, sessionId: string): Promise<void> {
    try {
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;
      
      const key = this.getShortTermKey(safeBusinessId, safeSessionId);
      await this.kv.delete(key);

      this.logger.debug('Short-term memory cleared', sanitizeForLogging({
        businessId: safeBusinessId,
        sessionId: safeSessionId
      }));
    } catch (error) {
      this.logger.error('Failed to clear short-term memory', {
        businessId: sanitizeForLogging(businessId),
        sessionId: sanitizeForLogging(sessionId),
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ValidationError('Failed to clear short-term memory');
    }
  }

  /**
   * Clear all memory for a business
   */
  async clearAll(businessId: string): Promise<void> {
    try {
      const safeBusinessId = sanitizeBusinessId(businessId);
      
      // Clear short-term memory (KV)
      const keys = await this.kv.list({ prefix: `agent_memory:${safeBusinessId}:` });
      const deletePromises = keys.keys.map(key => this.kv.delete(key.name));
      await Promise.all(deletePromises);
      
      // Clear long-term memory (D1)
      await this.db.prepare(`
        DELETE FROM agent_knowledge WHERE business_id = ?
      `).bind(safeBusinessId).run();
      
      // Clear conversation history (D1)
      await this.db.prepare(`
        DELETE FROM agent_conversations WHERE business_id = ?
      `).bind(safeBusinessId).run();

      this.logger.debug('All memory cleared', sanitizeForLogging({
        businessId: safeBusinessId
      }));
    } catch (error) {
      this.logger.error('Failed to clear all memory', {
        businessId: sanitizeForLogging(businessId),
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ValidationError('Failed to clear all memory');
    }
  }

  private async loadShortTerm(businessId: string, sessionId: string): Promise<Memory[]> {
    const key = this.getShortTermKey(businessId, sessionId);
    const data = await this.kv.get(key, 'json');
    return data as Memory[] || [];
  }

  private async saveShortTerm(businessId: string, sessionId: string, memories: Memory[]): Promise<void> {
    const key = this.getShortTermKey(businessId, sessionId);
    await this.kv.put(key, JSON.stringify(memories), {
      expirationTtl: AGENT_CONSTANTS.MEMORY_TTL
    });
  }

  private async loadLongTerm(businessId: string): Promise<Knowledge[]> {
    const result = await this.db.prepare(`
      SELECT id, business_id, topic, content, summary, relevance, confidence, source, created_at, updated_at, access_count, last_accessed
      FROM agent_knowledge 
      WHERE business_id = ?
      ORDER BY relevance DESC, last_accessed DESC
      LIMIT ?
    `).bind(businessId, AGENT_CONSTANTS.MAX_KNOWLEDGE_SIZE).all();

    return result.results as Knowledge[];
  }

  private async saveLongTerm(businessId: string, knowledge: Knowledge[]): Promise<void> {
    // Long-term memory is already persisted in D1, no need to save again
    // This method exists for interface consistency
  }

  private async loadConversationHistory(businessId: string, sessionId: string): Promise<ConversationEntry[]> {
    const result = await this.db.prepare(`
      SELECT id, taskId, agentId, input, output, timestamp, success, cost
      FROM agent_conversations 
      WHERE business_id = ? AND session_id = ?
      ORDER BY timestamp DESC
      LIMIT ?
    `).bind(businessId, sessionId, 100).all();

    return result.results as ConversationEntry[];
  }

  private async saveConversationHistory(
    businessId: string, 
    sessionId: string, 
    entries: ConversationEntry[]
  ): Promise<void> {
    // Conversation history is already persisted in D1, no need to save again
    // This method exists for interface consistency
  }

  private getShortTermKey(businessId: string, sessionId: string): string {
    return `agent_memory:${businessId}:${sessionId}`;
  }

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

