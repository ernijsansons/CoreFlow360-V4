/**
 * Workflow Collaboration - Durable Object
 * Real-time multi-user editing with conflict resolution and presence
 */

import type { Env } from '../types/env';

// =====================================================
// TYPES AND INTERFACES
// =====================================================

interface CollaborationMessage {
  type: 'join' | 'leave' | 'cursor_move' | 'selection_change' | 'node_update' | 'edge_update' | 'comment' | 'presence';
  userId: string;
  workflowId: string;
  timestamp: string;
  data: any;
}

interface Participant {
  userId: string;
  userName: string;
  userAvatar?: string;
  role: 'owner' | 'editor' | 'viewer' | 'commenter';
  joinedAt: string;
  lastSeenAt: string;
  isOnline: boolean;
  cursor?: {
    x: number;
    y: number;
    nodeId?: string;
  };
  selection?: {
    nodeIds: string[];
    edgeIds: string[];
  };
  color: string; // User's collaboration color
}

interface WorkflowChange {
  id: string;
  type: 'node_add' | 'node_update' | 'node_delete' | 'edge_add' | 'edge_update' | 'edge_delete' | 'workflow_update';
  userId: string;
  timestamp: string;
  data: any;
  parentChangeId?: string; // For conflict resolution
  applied: boolean;
  conflicted: boolean;
}

interface Comment {
  id: string;
  userId: string;
  userName: string;
  content: string;
  position?: { x: number; y: number };
  attachedToNodeId?: string;
  parentCommentId?: string;
  isResolved: boolean;
  resolvedBy?: string;
  resolvedAt?: string;
  reactions: Record<string, string[]>; // emoji -> userIds
  createdAt: string;
  updatedAt: string;
}

interface AwarenessState {
  participants: Map<string, Participant>;
  activeEditors: Set<string>;
  pendingChanges: Map<string, WorkflowChange>;
  comments: Map<string, Comment>;
  workflowLock?: {
    userId: string;
    lockType: 'editing' | 'executing';
    acquiredAt: string;
    expiresAt: string;
  };
}

// =====================================================
// COLLABORATION DURABLE OBJECT
// =====================================================

export class WorkflowCollaboration {
  private state: DurableObjectState;
  private env: Env;
  private websockets = new Map<string, WebSocket>();
  private participants = new Map<string, Participant>();
  private pendingChanges = new Map<string, WorkflowChange>();
  private comments = new Map<string, Comment>();
  private changeHistory: WorkflowChange[] = [];
  private workflowId: string = '';
  private lastSnapshot?: any;
  private conflictResolver: ConflictResolver;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.conflictResolver = new ConflictResolver();
    this.setupCleanupAlarm();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case '/websocket':
          return this.handleWebSocket(request);
        case '/join':
          return this.handleJoinSession(request);
        case '/leave':
          return this.handleLeaveSession(request);
        case '/state':
          return this.handleGetState(request);
        case '/comment':
          return this.handleComment(request);
        case '/resolve-comment':
          return this.handleResolveComment(request);
        case '/lock':
          return this.handleAcquireLock(request);
        case '/unlock':
          return this.handleReleaseLock(request);
        case '/history':
          return this.handleGetHistory(request);
        case '/snapshot':
          return this.handleCreateSnapshot(request);
        default:
          return new Response('Not found', { status: 404 });
      }
    } catch (error) {
      return new Response('Internal error', { status: 500 });
    }
  }

  // =====================================================
  // WEBSOCKET CONNECTION MANAGEMENT
  // =====================================================

  private async handleWebSocket(request: Request): Promise<Response> {
    const { 0: client, 1: server } = new WebSocketPair();

    server.accept();

    const url = new URL(request.url);
    const userId = url.searchParams.get('userId');
    const workflowId = url.searchParams.get('workflowId');

    if (!userId || !workflowId) {
      server.close(1008, 'Missing userId or workflowId');
      return new Response(null, { status: 400 });
    }

    this.workflowId = workflowId;
    this.websockets.set(userId, server);

    // Load participant data
    await this.loadParticipantData(userId);

    server.addEventListener('message', async (event) => {
      try {
        const message: CollaborationMessage = JSON.parse(event.data);
        await this.handleCollaborationMessage(message);
      } catch (error) {
      }
    });

    server.addEventListener('close', () => {
      this.websockets.delete(userId);
      this.handleParticipantDisconnect(userId);
    });

    // Send initial state
    await this.sendToParticipant(userId, {
      type: 'state_sync',
      data: await this.getCollaborationState()
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  private async handleCollaborationMessage(message: CollaborationMessage): Promise<void> {
    const { type, userId, data } = message;

    switch (type) {
      case 'join':
        await this.handleParticipantJoin(userId, data);
        break;

      case 'cursor_move':
        await this.handleCursorMove(userId, data);
        break;

      case 'selection_change':
        await this.handleSelectionChange(userId, data);
        break;

      case 'node_update':
        await this.handleNodeUpdate(userId, data);
        break;

      case 'edge_update':
        await this.handleEdgeUpdate(userId, data);
        break;

      case 'comment':
        await this.handleCommentMessage(userId, data);
        break;

      case 'presence':
        await this.handlePresenceUpdate(userId, data);
        break;
    }
  }

  // =====================================================
  // PARTICIPANT MANAGEMENT
  // =====================================================

  private async handleParticipantJoin(userId: string, data: any): Promise<void> {
    const participant: Participant = {
      userId,
      userName: data.userName,
      userAvatar: data.userAvatar,
      role: data.role || 'viewer',
      joinedAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      isOnline: true,
      color: this.assignUserColor(userId)
    };

    this.participants.set(userId, participant);

    // Save to database
    await this.saveParticipantToDatabase(participant);

    // Broadcast to all participants
    this.broadcastToAll({
      type: 'participant_joined',
      data: participant
    }, userId);

  }

  private async handleParticipantDisconnect(userId: string): Promise<void> {
    const participant = this.participants.get(userId);
    if (participant) {
      participant.isOnline = false;
      participant.lastSeenAt = new Date().toISOString();

      // Release any locks held by this user
      await this.releaseLocksByUser(userId);

      this.broadcastToAll({
        type: 'participant_left',
        data: { userId }
      }, userId);

    }
  }

  private async handleCursorMove(userId: string, data: any): Promise<void> {
    const participant = this.participants.get(userId);
    if (participant) {
      participant.cursor = data.cursor;
      participant.lastSeenAt = new Date().toISOString();

      // Broadcast cursor position to others (throttled)
      this.broadcastToAll({
        type: 'cursor_moved',
        data: {
          userId,
          cursor: data.cursor
        }
      }, userId);
    }
  }

  private async handleSelectionChange(userId: string, data: any): Promise<void> {
    const participant = this.participants.get(userId);
    if (participant) {
      participant.selection = data.selection;
      participant.lastSeenAt = new Date().toISOString();

      this.broadcastToAll({
        type: 'selection_changed',
        data: {
          userId,
          selection: data.selection
        }
      }, userId);
    }
  }

  private async handlePresenceUpdate(userId: string, data: any): Promise<void> {
    const participant = this.participants.get(userId);
    if (participant) {
      participant.lastSeenAt = new Date().toISOString();

      // Update any presence-specific data
      if (data.isTyping !== undefined) {
        this.broadcastToAll({
          type: 'typing_indicator',
          data: {
            userId,
            isTyping: data.isTyping,
            nodeId: data.nodeId
          }
        }, userId);
      }
    }
  }

  // =====================================================
  // CHANGE MANAGEMENT & CONFLICT RESOLUTION
  // =====================================================

  private async handleNodeUpdate(userId: string, data: any): Promise<void> {
    const participant = this.participants.get(userId);
    if (!participant || !this.canEdit(participant.role)) {
      return;
    }

    const change: WorkflowChange = {
      id: `change_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: 'node_update',
      userId,
      timestamp: new Date().toISOString(),
      data,
      applied: false,
      conflicted: false
    };

    // Check for conflicts
    const conflict = await this.detectConflict(change);
    if (conflict) {
      change.conflicted = true;
      const resolution = await this.conflictResolver.resolve(conflict, change);

      if (resolution.canApply) {
        change.data = resolution.resolvedData;
        change.applied = true;
      } else {
        // Send conflict notification to user
        await this.sendToParticipant(userId, {
          type: 'conflict_detected',
          data: {
            changeId: change.id,
            conflict: resolution
          }
        });
        return;
      }
    } else {
      change.applied = true;
    }

    // Store the change
    this.pendingChanges.set(change.id, change);
    this.changeHistory.push(change);

    // Apply to workflow state
    if (change.applied) {
      await this.applyChangeToWorkflow(change);

      // Broadcast to all participants
      this.broadcastToAll({
        type: 'node_updated',
        data: {
          change,
          appliedBy: userId
        }
      }, userId);

      // Persist to database
      await this.saveChangeToDatabase(change);
    }
  }

  private async handleEdgeUpdate(userId: string, data: any): Promise<void> {
    // Similar to handleNodeUpdate but for edges
    const participant = this.participants.get(userId);
    if (!participant || !this.canEdit(participant.role)) {
      return;
    }

    const change: WorkflowChange = {
      id: `change_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: 'edge_update',
      userId,
      timestamp: new Date().toISOString(),
      data,
      applied: true,
      conflicted: false
    };

    this.pendingChanges.set(change.id, change);
    this.changeHistory.push(change);

    await this.applyChangeToWorkflow(change);

    this.broadcastToAll({
      type: 'edge_updated',
      data: {
        change,
        appliedBy: userId
      }
    }, userId);

    await this.saveChangeToDatabase(change);
  }

  private async detectConflict(change: WorkflowChange): Promise<any> {
    // Check if another user is editing the same node/edge
    for (const [changeId, pendingChange] of this.pendingChanges) {
      if (pendingChange.userId !== change.userId &&
          pendingChange.type === change.type &&
          this.isOverlappingChange(pendingChange, change)) {
        return {
          conflictingChange: pendingChange,
          conflictType: 'concurrent_edit',
          timeWindow: Date.now() - new Date(pendingChange.timestamp).getTime()
        };
      }
    }

    return null;
  }

  private isOverlappingChange(change1: WorkflowChange, change2: WorkflowChange): boolean {
    if (change1.type === 'node_update' && change2.type === 'node_update') {
      return change1.data.nodeId === change2.data.nodeId;
    }
    if (change1.type === 'edge_update' && change2.type === 'edge_update') {
      return change1.data.edgeId === change2.data.edgeId;
    }
    return false;
  }

  private async applyChangeToWorkflow(change: WorkflowChange): Promise<void> {
    // Apply the change to the workflow state in the database
    const db = this.env.DB_CRM;

    switch (change.type) {
      case 'node_update':
        await db.prepare(`
          UPDATE workflow_nodes
          SET config = ?, position_x = ?, position_y = ?, updated_at = ?
          WHERE id = ? AND workflow_id = ?
        `).bind(
          JSON.stringify(change.data.config),
          change.data.position?.x,
          change.data.position?.y,
          change.timestamp,
          change.data.nodeId,
          this.workflowId
        ).run();
        break;

      case 'edge_update':
        await db.prepare(`
          UPDATE workflow_edges
          SET condition_expression = ?, label = ?
          WHERE id = ? AND workflow_id = ?
        `).bind(
          change.data.conditionExpression,
          change.data.label,
          change.data.edgeId,
          this.workflowId
        ).run();
        break;
    }
  }

  // =====================================================
  // COMMENTING SYSTEM
  // =====================================================

  private async handleCommentMessage(userId: string, data: any): Promise<void> {
    const participant = this.participants.get(userId);
    if (!participant || !this.canComment(participant.role)) {
      return;
    }

    const comment: Comment = {
      id: `comment_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      userName: participant.userName,
      content: data.content,
      position: data.position,
      attachedToNodeId: data.attachedToNodeId,
      parentCommentId: data.parentCommentId,
      isResolved: false,
      reactions: {},
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.comments.set(comment.id, comment);

    // Save to database
    await this.saveCommentToDatabase(comment);

    // Broadcast to all participants
    this.broadcastToAll({
      type: 'comment_added',
      data: comment
    });

  }

  private async handleComment(request: Request): Promise<Response> {
    const { action, commentId, data } = await request.json() as any;

    switch (action) {
      case 'react':
        await this.handleCommentReaction(data.userId, commentId, data.emoji);
        break;
      case 'edit':
        await this.handleCommentEdit(data.userId, commentId, data.content);
        break;
      case 'delete':
        await this.handleCommentDelete(data.userId, commentId);
        break;
    }

    return new Response(JSON.stringify({ success: true }));
  }

  private async handleCommentEdit(userId: string, commentId: string, content: string): Promise<void> {
    const comment = this.comments.get(commentId);
    if (comment && comment.userId === userId) {
      comment.content = content;
      comment.updatedAt = new Date().toISOString();

      this.broadcastToAll({
        type: 'comment_edited',
        data: {
          commentId,
          content,
          userId
        }
      });

      await this.updateCommentInDatabase(comment);
    }
  }

  private async handleCommentDelete(userId: string, commentId: string): Promise<void> {
    const comment = this.comments.get(commentId);
    if (comment && comment.userId === userId) {
      this.comments.delete(commentId);

      this.broadcastToAll({
        type: 'comment_deleted',
        data: {
          commentId,
          userId
        }
      });

      const db = this.env.DB_CRM;
      await db.prepare('DELETE FROM workflow_comments WHERE id = ?').bind(commentId).run();
    }
  }

  private async handleCommentReaction(userId: string, commentId: string, emoji: string): Promise<void> {
    const comment = this.comments.get(commentId);
    if (comment) {
      if (!comment.reactions[emoji]) {
        comment.reactions[emoji] = [];
      }

      const userIndex = comment.reactions[emoji].indexOf(userId);
      if (userIndex === -1) {
        comment.reactions[emoji].push(userId);
      } else {
        comment.reactions[emoji].splice(userIndex, 1);
        if (comment.reactions[emoji].length === 0) {
          delete comment.reactions[emoji];
        }
      }

      comment.updatedAt = new Date().toISOString();

      this.broadcastToAll({
        type: 'comment_reaction',
        data: {
          commentId,
          reactions: comment.reactions,
          userId,
          emoji
        }
      });

      await this.updateCommentInDatabase(comment);
    }
  }

  private async handleResolveComment(request: Request): Promise<Response> {
    const { commentId, userId, resolved } = await request.json() as any;

    const comment = this.comments.get(commentId);
    if (comment) {
      comment.isResolved = resolved;
      comment.resolvedBy = resolved ? userId : undefined;
      comment.resolvedAt = resolved ? new Date().toISOString() : undefined;
      comment.updatedAt = new Date().toISOString();

      this.broadcastToAll({
        type: 'comment_resolved',
        data: {
          commentId,
          isResolved: resolved,
          resolvedBy: userId
        }
      });

      await this.updateCommentInDatabase(comment);
    }

    return new Response(JSON.stringify({ success: true }));
  }

  // =====================================================
  // LOCKING MECHANISM
  // =====================================================

  private async handleAcquireLock(request: Request): Promise<Response> {
    const { userId, lockType = 'editing', duration = 300000 } = await request.json() as any; // 5 min default

    const participant = this.participants.get(userId);
    if (!participant || !this.canEdit(participant.role)) {
      return new Response(JSON.stringify({ success: false, error: 'Insufficient permissions' }), {
        status: 403
      });
    }

    // Check if workflow is already locked
    const existingLock = await this.state.storage.get('workflowLock') as any;
    if (existingLock && new Date(existingLock.expiresAt) > new Date()) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Workflow is already locked',
        lockedBy: existingLock.userId
      }), { status: 409 });
    }

    // Acquire lock
    const lock = {
      userId,
      lockType,
      acquiredAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + duration).toISOString()
    };

    await this.state.storage.put('workflowLock', lock);

    this.broadcastToAll({
      type: 'workflow_locked',
      data: lock
    }, userId);

    // Set alarm to auto-release lock
    await this.state.storage.setAlarm(Date.now() + duration);

    return new Response(JSON.stringify({ success: true, lock }));
  }

  private async handleReleaseLock(request: Request): Promise<Response> {
    const { userId } = await request.json() as any;

    const lock = await this.state.storage.get('workflowLock') as any;
    if (!lock || lock.userId !== userId) {
      return new Response(JSON.stringify({ success: false, error: 'No lock held by user' }), {
        status: 400
      });
    }

    await this.state.storage.delete('workflowLock');
    await this.state.storage.deleteAlarm();

    this.broadcastToAll({
      type: 'workflow_unlocked',
      data: { userId }
    });

    return new Response(JSON.stringify({ success: true }));
  }

  private async releaseLocksByUser(userId: string): Promise<void> {
    const lock = await this.state.storage.get('workflowLock') as any;
    if (lock && lock.userId === userId) {
      await this.state.storage.delete('workflowLock');
      await this.state.storage.deleteAlarm();

      this.broadcastToAll({
        type: 'workflow_unlocked',
        data: { userId, reason: 'user_disconnected' }
      });
    }
  }

  // =====================================================
  // STATE MANAGEMENT
  // =====================================================

  private async handleGetState(request: Request): Promise<Response> {
    const state = await this.getCollaborationState();
    return new Response(JSON.stringify(state));
  }

  private async getCollaborationState(): Promise<any> {
    return {
      participants: Array.from(this.participants.values()),
      comments: Array.from(this.comments.values()),
      workflowLock: await this.state.storage.get('workflowLock'),
      lastSnapshot: this.lastSnapshot,
      changeCount: this.changeHistory.length
    };
  }

  private async handleCreateSnapshot(request: Request): Promise<Response> {
    const snapshot = {
      workflowId: this.workflowId,
      participants: Array.from(this.participants.values()),
      changeHistory: this.changeHistory.slice(-100), // Last 100 changes
      createdAt: new Date().toISOString()
    };

    this.lastSnapshot = snapshot;
    await this.state.storage.put('lastSnapshot', snapshot);

    return new Response(JSON.stringify({ success: true, snapshot }));
  }

  private async handleGetHistory(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit') || '50');
    const offset = parseInt(url.searchParams.get('offset') || '0');

    const history = this.changeHistory
      .slice(-limit - offset, -offset || undefined)
      .reverse();

    return new Response(JSON.stringify({
      changes: history,
      total: this.changeHistory.length
    }));
  }

  // =====================================================
  // UTILITY METHODS
  // =====================================================

  private canEdit(role: string): boolean {
    return ['owner', 'editor'].includes(role);
  }

  private canComment(role: string): boolean {
    return ['owner', 'editor', 'commenter'].includes(role);
  }

  private assignUserColor(userId: string): string {
    const colors = [
      '#3b82f6', '#ef4444', '#10b981', '#f59e0b',
      '#8b5cf6', '#06b6d4', '#f97316', '#84cc16',
      '#ec4899', '#6366f1', '#14b8a6', '#eab308'
    ];

    // Simple hash-based color assignment
    let hash = 0;
    for (let i = 0; i < userId.length; i++) {
      hash = userId.charCodeAt(i) + ((hash << 5) - hash);
    }
    return colors[Math.abs(hash) % colors.length];
  }

  private broadcastToAll(message: any, excludeUserId?: string): void {
    const messageStr = JSON.stringify(message);
    this.websockets.forEach((ws, userId) => {
      if (userId !== excludeUserId) {
        try {
          ws.send(messageStr);
        } catch (error) {
        }
      }
    });
  }

  private async sendToParticipant(userId: string, message: any): Promise<void> {
    const ws = this.websockets.get(userId);
    if (ws) {
      try {
        ws.send(JSON.stringify(message));
      } catch (error) {
      }
    }
  }

  // =====================================================
  // DATABASE OPERATIONS
  // =====================================================

  private async loadParticipantData(userId: string): Promise<void> {
    const db = this.env.DB_CRM;

    // Add business isolation to prevent cross-tenant access
    const participant = await db.prepare(`
      SELECT * FROM workflow_collaborators
      WHERE workflow_id = ? AND user_id = ?
        AND business_id = (SELECT business_id FROM workflow_designs WHERE id = ?)
      LIMIT 1
    `).bind(this.workflowId, userId, this.workflowId).first() as any;

    if (participant) {
      // Load existing participant data
      this.participants.set(userId, {
        userId: participant.user_id,
        userName: participant.user_name || 'Unknown User',
        role: participant.role,
        joinedAt: participant.created_at,
        lastSeenAt: participant.last_seen_at || new Date().toISOString(),
        isOnline: true,
        color: participant.color || this.assignUserColor(userId)
      });
    }
  }

  private async saveParticipantToDatabase(participant: Participant): Promise<void> {
    const db = this.env.DB_CRM;

    // Get business_id from workflow_designs to ensure proper business isolation
    await db.prepare(`
      INSERT OR REPLACE INTO workflow_collaborators (
        workflow_id, user_id, business_id, role, color, last_seen_at, is_online, created_at, updated_at
      ) VALUES (?, ?, (SELECT business_id FROM workflow_designs WHERE id = ?), ?, ?, ?, ?, ?, ?)
    `).bind(
      this.workflowId,
      participant.userId,
      this.workflowId, // For business_id subquery
      participant.role,
      participant.color,
      participant.lastSeenAt,
      participant.isOnline ? 1 : 0,
      participant.joinedAt,
      new Date().toISOString()
    ).run();
  }

  private async saveCommentToDatabase(comment: Comment): Promise<void> {
    const db = this.env.DB_CRM;

    await db.prepare(`
      INSERT INTO workflow_comments (
        id, workflow_id, user_id, content, position_x, position_y,
        attached_to_node_id, parent_comment_id, is_resolved,
        reactions, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      comment.id,
      this.workflowId,
      comment.userId,
      comment.content,
      comment.position?.x,
      comment.position?.y,
      comment.attachedToNodeId,
      comment.parentCommentId,
      comment.isResolved ? 1 : 0,
      JSON.stringify(comment.reactions),
      comment.createdAt,
      comment.updatedAt
    ).run();
  }

  private async updateCommentInDatabase(comment: Comment): Promise<void> {
    const db = this.env.DB_CRM;

    await db.prepare(`
      UPDATE workflow_comments
      SET content = ?, is_resolved = ?, resolved_by = ?, resolved_at = ?,
          reactions = ?, updated_at = ?
      WHERE id = ?
    `).bind(
      comment.content,
      comment.isResolved ? 1 : 0,
      comment.resolvedBy,
      comment.resolvedAt,
      JSON.stringify(comment.reactions),
      comment.updatedAt,
      comment.id
    ).run();
  }

  private async saveChangeToDatabase(change: WorkflowChange): Promise<void> {
    // Store change history for audit and conflict resolution
    const db = this.env.DB_CRM;

    await db.prepare(`
      INSERT INTO workflow_change_history (
        id, workflow_id, user_id, change_type, change_data,
        applied, conflicted, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      change.id,
      this.workflowId,
      change.userId,
      change.type,
      JSON.stringify(change.data),
      change.applied ? 1 : 0,
      change.conflicted ? 1 : 0,
      change.timestamp
    ).run();
  }

  // =====================================================
  // CLEANUP AND MAINTENANCE
  // =====================================================

  private async setupCleanupAlarm(): Promise<void> {
    // Set alarm for periodic cleanup (every hour)
    const alarmTime = Date.now() + 3600000; // 1 hour
    await this.state.storage.setAlarm(alarmTime);
  }

  async alarm(): Promise<void> {
    // Handle alarm - cleanup expired locks and offline participants
    const now = new Date();

    // Check for expired lock
    const lock = await this.state.storage.get('workflowLock') as any;
    if (lock && new Date(lock.expiresAt) <= now) {
      await this.state.storage.delete('workflowLock');
      this.broadcastToAll({
        type: 'workflow_unlocked',
        data: { reason: 'expired' }
      });
    }

    // Cleanup old change history (keep last 1000 changes)
    if (this.changeHistory.length > 1000) {
      this.changeHistory = this.changeHistory.slice(-1000);
    }

    // Mark inactive participants as offline
    for (const [userId, participant] of this.participants) {
      if (participant.isOnline) {
        const lastSeen = new Date(participant.lastSeenAt);
        const inactiveTime = now.getTime() - lastSeen.getTime();

        if (inactiveTime > 300000) { // 5 minutes inactive
          participant.isOnline = false;
          await this.saveParticipantToDatabase(participant);

          this.broadcastToAll({
            type: 'participant_inactive',
            data: { userId }
          });
        }
      }
    }

    // Set next cleanup alarm
    await this.setupCleanupAlarm();
  }

  // Session management endpoints
  private async handleJoinSession(request: Request): Promise<Response> {
    const { userId, userName, role } = await request.json() as any;

    await this.handleParticipantJoin(userId, { userName, role });

    return new Response(JSON.stringify({
      success: true,
      sessionId: `${this.workflowId}_${userId}`,
      participantCount: this.participants.size
    }));
  }

  private async handleLeaveSession(request: Request): Promise<Response> {
    const { userId } = await request.json() as any;

    await this.handleParticipantDisconnect(userId);
    this.participants.delete(userId);

    return new Response(JSON.stringify({ success: true }));
  }
}

// =====================================================
// CONFLICT RESOLUTION SYSTEM
// =====================================================

class ConflictResolver {
  async resolve(conflict: any, newChange: WorkflowChange): Promise<any> {
    const { conflictingChange, conflictType } = conflict;

    switch (conflictType) {
      case 'concurrent_edit':
        return this.resolveConcurrentEdit(conflictingChange, newChange);

      default:
        return {
          canApply: false,
          reason: 'Unknown conflict type',
          suggestedAction: 'Manual resolution required'
        };
    }
  }

  private resolveConcurrentEdit(existing: WorkflowChange, incoming: WorkflowChange): any {
    // Simple last-writer-wins with user notification
    if (incoming.type === 'node_update' && existing.type === 'node_update') {
      // Merge configurations where possible
      const mergedConfig = {
        ...existing.data.config,
        ...incoming.data.config
      };

      // Use latest position
      const position = incoming.data.position || existing.data.position;

      return {
        canApply: true,
        resolvedData: {
          ...incoming.data,
          config: mergedConfig,
          position
        },
        resolutionStrategy: 'merge',
        warnings: ['Configuration merged due to concurrent edits']
      };
    }

    return {
      canApply: true,
      resolvedData: incoming.data,
      resolutionStrategy: 'last_writer_wins',
      warnings: ['Overwrote concurrent changes']
    };
  }
}