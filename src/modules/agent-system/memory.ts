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
import { ValidationError } from '../../shared/errors/app-error';
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
      }));

      return {
        shortTerm,
        longTerm,
        conversationHistory,
        businessId: safeBusinessId,
        sessionId: safeSessionId,
        loadedAt: new Date()
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
      const { businessId, sessionId, shortTerm, longTerm, conversationHistory } = context;
      
      // Validate and sanitize inputs
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeSessionId = sanitizeSqlParam(sessionId) as string;

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
      }));
    } catch (error) {
      this.logger.error('Failed to save memory context', {
        businessId: sanitizeForLogging(context.businessId),
        sessionId: sanitizeForLogging(context.sessionId),
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
      
      const key = this.getShortTermKey(safeBusinessId, safeSessionId);
      const existing = await this.kv.get(key, 'json') as Memory[] || [];
      
      // Add new memory with timestamp
      const memory: Memory = {
        ...message,
        id: this.generateId(),
        timestamp: new Date(),
        businessId: safeBusinessId,
        sessionId: safeSessionId
      };
      
      existing.push(memory);
      
      // Keep only recent memories (limit to AGENT_CONSTANTS.MAX_SHORT_TERM_MEMORIES)
      const recentMemories = existing
        .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
        .slice(0, AGENT_CONSTANTS.MAX_SHORT_TERM_MEMORIES);
      
      await this.kv.put(key, JSON.stringify(recentMemories), {
        expirationTtl: AGENT_CONSTANTS.SHORT_TERM_TTL
      });

      this.logger.debug('Memory added', sanitizeForLogging({
        businessId: safeBusinessId,
        sessionId: safeSessionId,
        memoryId: memory.id,
        type: memory.type
      }));
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
          id, business_id, title, content, category, 
          importance, created_at, updated_at, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        knowledge.id,
        safeBusinessId,
        knowledge.title,
        knowledge.content,
        knowledge.category,
        knowledge.importance,
        knowledge.createdAt.toISOString(),
        knowledge.updatedAt.toISOString(),
        JSON.stringify(knowledge.metadata)
      ).run();

      this.logger.debug('Knowledge added', sanitizeForLogging({
        businessId: safeBusinessId,
        knowledgeId: knowledge.id,
        title: knowledge.title,
        category: knowledge.category
      }));
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
        SELECT id, business_id, title, content, category, 
               importance, created_at, updated_at, metadata
        FROM agent_knowledge 
        WHERE business_id = ? 
        AND (title LIKE ? OR content LIKE ?)
      `;
      
      const params = [safeBusinessId, `%${safeQuery}%`, `%${safeQuery}%`];
      
      if (safeCategory) {
        sql += ' AND category = ?';
        params.push(safeCategory);
      }
      
      sql += ' ORDER BY importance DESC, updated_at DESC LIMIT ?';
      params.push(limit);
      
      const result = await this.db.prepare(sql).bind(...params).all();
      
      return result.results.map((row: any) => ({
        id: row.id,
        title: row.title,
        content: row.content,
        category: row.category,
        importance: row.importance,
        createdAt: new Date(row.created_at),
        updatedAt: new Date(row.updated_at),
        metadata: JSON.parse(row.metadata || '{}')
      }));
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
          id, business_id, session_id, role, content, 
          metadata, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(
        entry.id,
        safeBusinessId,
        safeSessionId,
        entry.role,
        entry.content,
        JSON.stringify(entry.metadata),
        entry.timestamp.toISOString()
      ).run();

      this.logger.debug('Conversation entry added', sanitizeForLogging({
        businessId: safeBusinessId,
        sessionId: safeSessionId,
        entryId: entry.id,
        role: entry.role
      }));
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
      expirationTtl: AGENT_CONSTANTS.SHORT_TERM_TTL
    });
  }

  private async loadLongTerm(businessId: string): Promise<Knowledge[]> {
    const result = await this.db.prepare(`
      SELECT id, title, content, category, importance, 
             created_at, updated_at, metadata
      FROM agent_knowledge 
      WHERE business_id = ?
      ORDER BY importance DESC, updated_at DESC
      LIMIT ?
    `).bind(businessId, AGENT_CONSTANTS.MAX_LONG_TERM_MEMORIES).all();

    return result.results.map((row: any) => ({
      id: row.id,
      title: row.title,
      content: row.content,
      category: row.category,
      importance: row.importance,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
      metadata: JSON.parse(row.metadata || '{}')
    }));
  }

  private async saveLongTerm(businessId: string, knowledge: Knowledge[]): Promise<void> {
    // Long-term memory is already persisted in D1, no need to save again
    // This method exists for interface consistency
  }

  private async loadConversationHistory(businessId: string, sessionId: string): Promise<ConversationEntry[]> {
    const result = await this.db.prepare(`
      SELECT id, role, content, metadata, created_at
      FROM agent_conversations 
      WHERE business_id = ? AND session_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(businessId, sessionId, AGENT_CONSTANTS.MAX_CONVERSATION_HISTORY).all();

    return result.results.map((row: any) => ({
      id: row.id,
      role: row.role,
      content: row.content,
      metadata: JSON.parse(row.metadata || '{}'),
      timestamp: new Date(row.created_at)
    }));
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

