/**
 * Relationship Graph Service
 * LinkedIn-style network intelligence with warm intro path finding
 * Part of Phase 1 Sprint 1 - Feature #1
 */

import type { Env } from '../../types/env';

export interface Relationship {
  id: string;
  business_id: string;
  source_id: string;
  source_type: 'contact' | 'company' | 'user' | 'lead';
  target_id: string;
  target_type: 'contact' | 'company' | 'user' | 'lead';
  relationship_type: string;
  strength_score: number;
  confidence_level: 'low' | 'medium' | 'high' | 'verified';
  interaction_count: number;
  last_interaction_at?: string;
  first_interaction_at?: string;
  detected_via?: string;
  detection_confidence?: number;
  is_bidirectional: boolean;
  notes?: string;
  metadata?: Record<string, any>;
  tags?: string[];
}

export interface NetworkPath {
  start_contact_id: string;
  end_contact_id: string;
  path_length: number;
  path_nodes: string[];
  path_types: string[];
  total_strength_score: number;
  weakest_link_score: number;
  best_introducer_id?: string;
  intro_success_probability: number;
}

export interface RelationshipInsight {
  target_id: string;
  target_type: 'contact' | 'company' | 'deal';
  insight_type: string;
  title: string;
  description: string;
  recommended_action?: string;
  priority: 'low' | 'medium' | 'high' | 'urgent';
  related_contact_ids?: string[];
  confidence_score: number;
}

export class RelationshipGraphService {
  constructor(private env: Env) {}

  /**
   * Create a new relationship between two entities
   */
  async createRelationship(
    businessId: string,
    data: Partial<Relationship>
  ): Promise<Relationship> {
    const id = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();

    const relationship: Relationship = {
      id,
      business_id: businessId,
      source_id: data.source_id!,
      source_type: data.source_type!,
      target_id: data.target_id!,
      target_type: data.target_type!,
      relationship_type: data.relationship_type || 'linkedin_connection',
      strength_score: data.strength_score || 50,
      confidence_level: data.confidence_level || 'medium',
      interaction_count: 0,
      detected_via: data.detected_via,
      detection_confidence: data.detection_confidence,
      is_bidirectional: data.is_bidirectional || false,
      notes: data.notes,
      metadata: data.metadata,
      tags: data.tags,
    };

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_relationships (
        id, business_id, source_id, source_type, target_id, target_type,
        relationship_type, strength_score, confidence_level, interaction_count,
        detected_via, detection_confidence, is_bidirectional, notes, metadata, tags,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      businessId,
      relationship.source_id,
      relationship.source_type,
      relationship.target_id,
      relationship.target_type,
      relationship.relationship_type,
      relationship.strength_score,
      relationship.confidence_level,
      relationship.interaction_count,
      relationship.detected_via || null,
      relationship.detection_confidence || null,
      relationship.is_bidirectional ? 1 : 0,
      relationship.notes || null,
      relationship.metadata ? JSON.stringify(relationship.metadata) : null,
      relationship.tags ? JSON.stringify(relationship.tags) : null,
      now,
      now
    ).run();

    return relationship;
  }

  /**
   * Get all relationships for an entity
   */
  async getRelationships(
    businessId: string,
    entityId: string,
    entityType: string
  ): Promise<Relationship[]> {
    const result = await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_relationships
      WHERE business_id = ?
        AND ((source_id = ? AND source_type = ?) OR (target_id = ? AND target_type = ?))
        AND deleted_at IS NULL
      ORDER BY strength_score DESC, last_interaction_at DESC
    `).bind(businessId, entityId, entityType, entityId, entityType).all();

    return (result.results as any[] || []).map(row => this.parseRelationship(row));
  }

  /**
   * Find warm introduction path between two contacts
   * Uses breadth-first search to find shortest path
   */
  async findWarmIntroPath(
    businessId: string,
    startContactId: string,
    endContactId: string,
    maxHops: number = 3
  ): Promise<NetworkPath | null> {
    // Check if path already exists in cache
    const cached = await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_network_paths
      WHERE business_id = ?
        AND start_contact_id = ?
        AND end_contact_id = ?
        AND expires_at > datetime('now')
    `).bind(businessId, startContactId, endContactId).first();

    if (cached) {
      return this.parseNetworkPath(cached as Record<string, unknown>);
    }

    // Perform BFS to find path
    const path = await this.bfsPathSearch(businessId, startContactId, endContactId, maxHops);

    if (!path) {
      return null;
    }

    // Cache the result
    await this.cacheNetworkPath(businessId, path);

    return path;
  }

  /**
   * BFS algorithm to find shortest path between contacts
   */
  private async bfsPathSearch(
    businessId: string,
    startId: string,
    endId: string,
    maxHops: number
  ): Promise<NetworkPath | null> {
    interface QueueItem {
      contactId: string;
      path: string[];
      relationshipTypes: string[];
      strengthScores: number[];
    }

    const queue: QueueItem[] = [{
      contactId: startId,
      path: [startId],
      relationshipTypes: [],
      strengthScores: []
    }];

    const visited = new Set<string>([startId]);

    while (queue.length > 0) {
      const current = queue.shift()!;

      if (current.path.length > maxHops + 1) {
        continue;
      }

      if (current.contactId === endId) {
        // Found path!
        const totalStrength = Math.round(
          current.strengthScores.reduce((a, b) => a + b, 0) / current.strengthScores.length
        );
        const weakestLink = Math.min(...current.strengthScores);

        // Find best introducer (contact with strongest connection to end)
        const introIndex = current.path.length - 2;
        const bestIntroducerId = introIndex >= 0 ? current.path[introIndex] : undefined;

        return {
          start_contact_id: startId,
          end_contact_id: endId,
          path_length: current.path.length - 1,
          path_nodes: current.path,
          path_types: current.relationshipTypes,
          total_strength_score: totalStrength,
          weakest_link_score: weakestLink,
          best_introducer_id: bestIntroducerId,
          intro_success_probability: this.calculateIntroSuccessProbability(
            totalStrength,
            weakestLink,
            current.path.length - 1
          ),
        };
      }

      // Get neighbors
      const neighbors = await this.env.DB_MAIN.prepare(`
        SELECT target_id as next_id, relationship_type, strength_score
        FROM crm_relationships
        WHERE business_id = ?
          AND source_id = ?
          AND source_type = 'contact'
          AND target_type = 'contact'
          AND deleted_at IS NULL
        UNION
        SELECT source_id as next_id, relationship_type, strength_score
        FROM crm_relationships
        WHERE business_id = ?
          AND target_id = ?
          AND target_type = 'contact'
          AND source_type = 'contact'
          AND is_bidirectional = 1
          AND deleted_at IS NULL
      `).bind(businessId, current.contactId, businessId, current.contactId).all();

      for (const neighbor of (neighbors.results || [])) {
        const nextId = (neighbor as any).next_id;
        if (!visited.has(nextId)) {
          visited.add(nextId);
          queue.push({
            contactId: nextId,
            path: [...current.path, nextId],
            relationshipTypes: [...current.relationshipTypes, (neighbor as any).relationship_type],
            strengthScores: [...current.strengthScores, (neighbor as any).strength_score],
          });
        }
      }
    }

    return null;
  }

  /**
   * Calculate probability of successful introduction
   */
  private calculateIntroSuccessProbability(
    avgStrength: number,
    weakestLink: number,
    pathLength: number
  ): number {
    // Formula: base success rate * strength multiplier * path penalty
    const baseRate = 0.5;
    const strengthMultiplier = (avgStrength + weakestLink) / 200;
    const pathPenalty = Math.pow(0.8, pathLength - 1);

    return Math.min(1.0, baseRate * strengthMultiplier * pathPenalty);
  }

  /**
   * Cache network path for 7 days
   */
  private async cacheNetworkPath(businessId: string, path: NetworkPath): Promise<void> {
    const id = crypto.randomUUID().replace(/-/g, '');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_network_paths (
        id, business_id, start_contact_id, end_contact_id, path_length,
        path_nodes, path_types, total_strength_score, weakest_link_score,
        best_introducer_id, intro_success_probability, computed_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      businessId,
      path.start_contact_id,
      path.end_contact_id,
      path.path_length,
      JSON.stringify(path.path_nodes),
      JSON.stringify(path.path_types),
      path.total_strength_score,
      path.weakest_link_score,
      path.best_introducer_id || null,
      path.intro_success_probability,
      now.toISOString(),
      expiresAt.toISOString()
    ).run();
  }

  /**
   * Get relationship insights for a target entity
   */
  async getRelationshipInsights(
    businessId: string,
    targetId: string,
    targetType: 'contact' | 'company' | 'deal'
  ): Promise<RelationshipInsight[]> {
    const result = await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_relationship_insights
      WHERE business_id = ?
        AND target_id = ?
        AND target_type = ?
        AND status = 'new'
        AND (expires_at IS NULL OR expires_at > datetime('now'))
        AND deleted_at IS NULL
      ORDER BY priority DESC, confidence_score DESC
    `).bind(businessId, targetId, targetType).all();

    return (result.results as any[] || []).map(row => this.parseRelationshipInsight(row));
  }

  /**
   * Generate AI-powered relationship insights
   * Detects patterns like warm intro availability, key decision makers, etc.
   */
  async generateInsights(
    businessId: string,
    contactId: string
  ): Promise<RelationshipInsight[]> {
    const insights: RelationshipInsight[] = [];

    // Get all relationships for contact
    const relationships = await this.getRelationships(businessId, contactId, 'contact');

    // Insight 1: Warm intro availability
    const strongConnections = relationships.filter(r => r.strength_score >= 75);
    if (strongConnections.length > 0) {
      insights.push({
        target_id: contactId,
        target_type: 'contact',
        insight_type: 'warm_intro_available',
        title: 'Warm Introduction Paths Available',
        description: `You have ${strongConnections.length} strong connections who could introduce you.`,
        recommended_action: 'Request warm introduction from your strongest connection',
        priority: 'high',
        related_contact_ids: strongConnections.slice(0, 5).map(r => r.target_id),
        confidence_score: 0.9,
      });
    }

    // Insight 2: Key decision maker
    const seniorRoles = ['c-level', 'vp', 'director'];
    const contact = await this.env.DB_MAIN.prepare(
      'SELECT seniority_level FROM crm_contacts WHERE id = ?'
    ).bind(contactId).first() as { seniority_level: string } | null;

    if (contact && seniorRoles.includes(contact.seniority_level)) {
      insights.push({
        target_id: contactId,
        target_type: 'contact',
        insight_type: 'key_decision_maker',
        title: 'Key Decision Maker Identified',
        description: 'This contact holds a senior decision-making position',
        recommended_action: 'Prioritize engagement with tailored executive messaging',
        priority: 'high',
        confidence_score: 0.95,
      });
    }

    // Save insights to database
    for (const insight of insights) {
      await this.saveInsight(businessId, insight);
    }

    return insights;
  }

  /**
   * Save relationship insight to database
   */
  private async saveInsight(businessId: string, insight: RelationshipInsight): Promise<void> {
    const id = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_relationship_insights (
        id, business_id, target_id, target_type, insight_type,
        title, description, recommended_action, priority,
        related_contact_ids, confidence_score, status, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)
    `).bind(
      id,
      businessId,
      insight.target_id,
      insight.target_type,
      insight.insight_type,
      insight.title,
      insight.description,
      insight.recommended_action || null,
      insight.priority,
      insight.related_contact_ids ? JSON.stringify(insight.related_contact_ids) : null,
      insight.confidence_score,
      now,
      expiresAt
    ).run();
  }

  /**
   * Log relationship activity (email, meeting, call)
   */
  async logActivity(
    relationshipId: string,
    businessId: string,
    activityType: string,
    data: {
      subject?: string;
      description?: string;
      outcome?: string;
      sentiment_score?: number;
      strength_impact?: number;
      occurred_at?: string;
    }
  ): Promise<void> {
    const id = crypto.randomUUID().replace(/-/g, '');
    const occurredAt = data.occurred_at || new Date().toISOString();

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_relationship_activities (
        id, relationship_id, business_id, activity_type,
        subject, description, outcome, sentiment_score, strength_impact, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      relationshipId,
      businessId,
      activityType,
      data.subject || null,
      data.description || null,
      data.outcome || null,
      data.sentiment_score || null,
      data.strength_impact || 5, // Default: +5 points per interaction
      occurredAt
    ).run();
  }

  /**
   * Parse database relationship record
   */
  private parseRelationship(row: Record<string, unknown>): Relationship {
    return {
      id: row.id as string,
      business_id: row.business_id as string,
      source_id: row.source_id as string,
      source_type: row.source_type as 'contact' | 'company' | 'user' | 'lead',
      target_id: row.target_id as string,
      target_type: row.target_type as 'contact' | 'company' | 'user' | 'lead',
      relationship_type: row.relationship_type as string,
      strength_score: row.strength_score as number,
      confidence_level: row.confidence_level as 'low' | 'medium' | 'high' | 'verified',
      interaction_count: row.interaction_count as number,
      last_interaction_at: row.last_interaction_at as string | undefined,
      first_interaction_at: row.first_interaction_at as string | undefined,
      detected_via: row.detected_via as string | undefined,
      detection_confidence: row.detection_confidence as number | undefined,
      is_bidirectional: Boolean(row.is_bidirectional),
      notes: row.notes as string | undefined,
      metadata: row.metadata ? JSON.parse(row.metadata as string) : undefined,
      tags: row.tags ? JSON.parse(row.tags as string) : undefined,
    };
  }

  /**
   * Parse network path record
   */
  private parseNetworkPath(row: Record<string, unknown>): NetworkPath {
    return {
      start_contact_id: row.start_contact_id as string,
      end_contact_id: row.end_contact_id as string,
      path_length: row.path_length as number,
      path_nodes: JSON.parse(row.path_nodes as string),
      path_types: JSON.parse(row.path_types as string),
      total_strength_score: row.total_strength_score as number,
      weakest_link_score: row.weakest_link_score as number,
      best_introducer_id: row.best_introducer_id as string | undefined,
      intro_success_probability: row.intro_success_probability as number,
    };
  }

  /**
   * Parse relationship insight record
   */
  private parseRelationshipInsight(row: Record<string, unknown>): RelationshipInsight {
    return {
      target_id: row.target_id as string,
      target_type: row.target_type as 'contact' | 'company' | 'deal',
      insight_type: row.insight_type as string,
      title: row.title as string,
      description: row.description as string,
      recommended_action: row.recommended_action as string | undefined,
      priority: row.priority as 'low' | 'medium' | 'high' | 'urgent',
      related_contact_ids: row.related_contact_ids ? JSON.parse(row.related_contact_ids as string) : undefined,
      confidence_score: row.confidence_score as number,
    };
  }
}
