/**
 * Admin Management API Routes
 * Fortune 50 Level Management Tools for System Administrators
 *
 * Features:
 * - User management (CRUD operations)
 * - Business management
 * - Feature flags management
 * - System configuration
 * - Audit log queries
 * - Session management
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';

const adminManagement = new Hono<{ Bindings: Env }>();

// ============================================================================
// USER MANAGEMENT
// ============================================================================

/**
 * List All Users
 * GET /api/admin/users
 */
adminManagement.get('/users', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    // Query parameters
    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '50');
    const status = c.req.query('status');
    const role = c.req.query('role');
    const search = c.req.query('search');

    const offset = (page - 1) * limit;

    // Build query
    let query = 'SELECT id, email, first_name, last_name, role, status, mfa_enabled, created_at, last_login_at FROM users WHERE 1=1';
    const params: any[] = [];

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (role) {
      query += ' AND role = ?';
      params.push(role);
    }

    if (search) {
      query += ' AND (email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const users = await c.env.DB_MAIN.prepare(query).bind(...params).all();

    // Get total count
    let countQuery = 'SELECT COUNT(*) as total FROM users WHERE 1=1';
    const countParams: any[] = [];

    if (status) {
      countQuery += ' AND status = ?';
      countParams.push(status);
    }

    if (role) {
      countQuery += ' AND role = ?';
      countParams.push(role);
    }

    if (search) {
      countQuery += ' AND (email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)';
      countParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    const total = await c.env.DB_MAIN.prepare(countQuery).bind(...countParams).first() as { total: number } | null;

    return c.json({
      success: true,
      data: {
        users: users.results || [],
        pagination: {
          page,
          limit,
          total: total?.total || 0,
          totalPages: Math.ceil((total?.total || 0) / limit)
        }
      }
    });

  } catch (error) {
    console.error('List Users Error:', error);
    return c.json({
      success: false,
      error: 'Failed to list users',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Get User Details
 * GET /api/admin/users/:id
 */
adminManagement.get('/users/:id', async (c) => {
  try {
    const adminUserId = c.req.header('X-User-ID');
    const targetUserId = c.req.param('id');

    if (!adminUserId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const admin = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(adminUserId).first() as { role: string } | null;

    if (!admin || admin.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    // Get user details
    const user = await c.env.DB_MAIN.prepare(`
      SELECT
        id, email, first_name, last_name, role, status,
        mfa_enabled, created_at, updated_at, last_login_at,
        email_verified, phone, avatar_url
      FROM users
      WHERE id = ?
    `).bind(targetUserId).first();

    if (!user) {
      return c.json({ error: 'User not found' }, 404);
    }

    // Get user's businesses
    const businesses = await c.env.DB_MAIN.prepare(`
      SELECT id, name, status, industry, created_at
      FROM businesses
      WHERE owner_id = ?
      ORDER BY created_at DESC
    `).bind(targetUserId).all();

    // Get active sessions
    const sessions = await c.env.DB_MAIN.prepare(`
      SELECT id, device_info, last_activity_at, expires_at
      FROM sessions
      WHERE user_id = ? AND invalidated = 0 AND expires_at > datetime('now')
      ORDER BY last_activity_at DESC
    `).bind(targetUserId).all();

    // Get recent activity
    const activity = await c.env.DB_MAIN.prepare(`
      SELECT action, ip_address, user_agent, created_at, status_code
      FROM audit_log
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 20
    `).bind(targetUserId).all();

    return c.json({
      success: true,
      data: {
        user,
        businesses: businesses.results || [],
        sessions: sessions.results || [],
        recentActivity: activity.results || []
      }
    });

  } catch (error) {
    console.error('Get User Error:', error);
    return c.json({
      success: false,
      error: 'Failed to get user details',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Update User
 * PATCH /api/admin/users/:id
 */
adminManagement.patch('/users/:id', async (c) => {
  try {
    const adminUserId = c.req.header('X-User-ID');
    const targetUserId = c.req.param('id');

    if (!adminUserId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const admin = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(adminUserId).first() as { role: string } | null;

    if (!admin || admin.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    const body = await c.req.json();
    const { email, firstName, lastName, role, status, mfaEnabled } = body;

    // Build update query
    const updates: string[] = [];
    const params: any[] = [];

    if (email !== undefined) {
      updates.push('email = ?');
      params.push(email);
    }

    if (firstName !== undefined) {
      updates.push('first_name = ?');
      params.push(firstName);
    }

    if (lastName !== undefined) {
      updates.push('last_name = ?');
      params.push(lastName);
    }

    if (role !== undefined) {
      updates.push('role = ?');
      params.push(role);
    }

    if (status !== undefined) {
      updates.push('status = ?');
      params.push(status);
    }

    if (mfaEnabled !== undefined) {
      updates.push('mfa_enabled = ?');
      params.push(mfaEnabled ? 1 : 0);
    }

    if (updates.length === 0) {
      return c.json({ error: 'No fields to update' }, 400);
    }

    updates.push('updated_at = datetime("now")');
    params.push(targetUserId);

    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
    await c.env.DB_MAIN.prepare(query).bind(...params).run();

    // Get updated user
    const user = await c.env.DB_MAIN.prepare(
      'SELECT id, email, first_name, last_name, role, status, mfa_enabled, updated_at FROM users WHERE id = ?'
    ).bind(targetUserId).first();

    // Log the action
    await c.env.DB_MAIN.prepare(`
      INSERT INTO audit_log (user_id, action, details, status_code, created_at)
      VALUES (?, 'admin_user_update', ?, 200, datetime('now'))
    `).bind(adminUserId, `Updated user ${targetUserId}`, 200).run();

    return c.json({
      success: true,
      data: { user },
      message: 'User updated successfully'
    });

  } catch (error) {
    console.error('Update User Error:', error);
    return c.json({
      success: false,
      error: 'Failed to update user',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Suspend User
 * POST /api/admin/users/:id/suspend
 */
adminManagement.post('/users/:id/suspend', async (c) => {
  try {
    const adminUserId = c.req.header('X-User-ID');
    const targetUserId = c.req.param('id');

    if (!adminUserId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const admin = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(adminUserId).first() as { role: string } | null;

    if (!admin || admin.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    const body = await c.req.json();
    const { reason } = body;

    // Suspend user
    await c.env.DB_MAIN.prepare(`
      UPDATE users
      SET status = 'suspended', updated_at = datetime('now')
      WHERE id = ?
    `).bind(targetUserId).run();

    // Invalidate all sessions
    await c.env.DB_MAIN.prepare(`
      UPDATE sessions
      SET invalidated = 1
      WHERE user_id = ?
    `).bind(targetUserId).run();

    // Log suspension
    await c.env.DB_MAIN.prepare(`
      INSERT INTO audit_log (user_id, action, details, status_code, created_at)
      VALUES (?, 'admin_user_suspended', ?, 200, datetime('now'))
    `).bind(adminUserId, `Suspended user ${targetUserId}: ${reason || 'No reason provided'}`).run();

    return c.json({
      success: true,
      message: 'User suspended successfully'
    });

  } catch (error) {
    console.error('Suspend User Error:', error);
    return c.json({
      success: false,
      error: 'Failed to suspend user',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Reactivate User
 * POST /api/admin/users/:id/reactivate
 */
adminManagement.post('/users/:id/reactivate', async (c) => {
  try {
    const adminUserId = c.req.header('X-User-ID');
    const targetUserId = c.req.param('id');

    if (!adminUserId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const admin = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(adminUserId).first() as { role: string } | null;

    if (!admin || admin.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    // Reactivate user
    await c.env.DB_MAIN.prepare(`
      UPDATE users
      SET status = 'active', updated_at = datetime('now')
      WHERE id = ?
    `).bind(targetUserId).run();

    // Log reactivation
    await c.env.DB_MAIN.prepare(`
      INSERT INTO audit_log (user_id, action, details, status_code, created_at)
      VALUES (?, 'admin_user_reactivated', ?, 200, datetime('now'))
    `).bind(adminUserId, `Reactivated user ${targetUserId}`).run();

    return c.json({
      success: true,
      message: 'User reactivated successfully'
    });

  } catch (error) {
    console.error('Reactivate User Error:', error);
    return c.json({
      success: false,
      error: 'Failed to reactivate user',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// ============================================================================
// BUSINESS MANAGEMENT
// ============================================================================

/**
 * List All Businesses
 * GET /api/admin/businesses
 */
adminManagement.get('/businesses', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '50');
    const status = c.req.query('status');
    const industry = c.req.query('industry');

    const offset = (page - 1) * limit;

    let query = `
      SELECT
        b.id, b.name, b.status, b.industry, b.created_at,
        u.email as owner_email, u.first_name as owner_first_name, u.last_name as owner_last_name
      FROM businesses b
      JOIN users u ON b.owner_id = u.id
      WHERE 1=1
    `;
    const params: any[] = [];

    if (status) {
      query += ' AND b.status = ?';
      params.push(status);
    }

    if (industry) {
      query += ' AND b.industry = ?';
      params.push(industry);
    }

    query += ' ORDER BY b.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const businesses = await c.env.DB_MAIN.prepare(query).bind(...params).all();

    // Get total count
    let countQuery = 'SELECT COUNT(*) as total FROM businesses WHERE 1=1';
    const countParams: any[] = [];

    if (status) {
      countQuery += ' AND status = ?';
      countParams.push(status);
    }

    if (industry) {
      countQuery += ' AND industry = ?';
      countParams.push(industry);
    }

    const total = await c.env.DB_MAIN.prepare(countQuery).bind(...countParams).first() as { total: number } | null;

    return c.json({
      success: true,
      data: {
        businesses: businesses.results || [],
        pagination: {
          page,
          limit,
          total: total?.total || 0,
          totalPages: Math.ceil((total?.total || 0) / limit)
        }
      }
    });

  } catch (error) {
    console.error('List Businesses Error:', error);
    return c.json({
      success: false,
      error: 'Failed to list businesses',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// ============================================================================
// AUDIT LOG QUERIES
// ============================================================================

/**
 * Query Audit Logs
 * GET /api/admin/audit-logs
 */
adminManagement.get('/audit-logs', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '100');
    const action = c.req.query('action');
    const targetUserId = c.req.query('user_id');
    const fromDate = c.req.query('from');
    const toDate = c.req.query('to');

    const offset = (page - 1) * limit;

    let query = `
      SELECT
        a.id, a.user_id, a.action, a.ip_address, a.user_agent,
        a.details, a.status_code, a.created_at,
        u.email as user_email
      FROM audit_log a
      LEFT JOIN users u ON a.user_id = u.id
      WHERE 1=1
    `;
    const params: any[] = [];

    if (action) {
      query += ' AND a.action = ?';
      params.push(action);
    }

    if (targetUserId) {
      query += ' AND a.user_id = ?';
      params.push(targetUserId);
    }

    if (fromDate) {
      query += ' AND a.created_at >= ?';
      params.push(fromDate);
    }

    if (toDate) {
      query += ' AND a.created_at <= ?';
      params.push(toDate);
    }

    query += ' ORDER BY a.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const logs = await c.env.DB_MAIN.prepare(query).bind(...params).all();

    return c.json({
      success: true,
      data: {
        logs: logs.results || [],
        pagination: {
          page,
          limit
        }
      }
    });

  } catch (error) {
    console.error('Query Audit Logs Error:', error);
    return c.json({
      success: false,
      error: 'Failed to query audit logs',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

/**
 * List Active Sessions
 * GET /api/admin/sessions
 */
adminManagement.get('/sessions', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    const sessions = await c.env.DB_MAIN.prepare(`
      SELECT
        s.id, s.user_id, s.device_info, s.last_activity_at, s.expires_at,
        u.email as user_email, u.first_name, u.last_name
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.invalidated = 0 AND s.expires_at > datetime('now')
      ORDER BY s.last_activity_at DESC
      LIMIT 100
    `).all();

    return c.json({
      success: true,
      data: {
        sessions: sessions.results || []
      }
    });

  } catch (error) {
    console.error('List Sessions Error:', error);
    return c.json({
      success: false,
      error: 'Failed to list sessions',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Revoke Session
 * DELETE /api/admin/sessions/:id
 */
adminManagement.delete('/sessions/:id', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');
    const sessionId = c.req.param('id');

    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    await c.env.DB_MAIN.prepare(`
      UPDATE sessions
      SET invalidated = 1
      WHERE id = ?
    `).bind(sessionId).run();

    // Log the action
    await c.env.DB_MAIN.prepare(`
      INSERT INTO audit_log (user_id, action, details, status_code, created_at)
      VALUES (?, 'admin_session_revoked', ?, 200, datetime('now'))
    `).bind(userId, `Revoked session ${sessionId}`).run();

    return c.json({
      success: true,
      message: 'Session revoked successfully'
    });

  } catch (error) {
    console.error('Revoke Session Error:', error);
    return c.json({
      success: false,
      error: 'Failed to revoke session',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

export default adminManagement;
