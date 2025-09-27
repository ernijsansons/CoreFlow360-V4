import type { SessionData, AuthContext } from './types';
import { JWTService } from './jwt';

// Session configuration
const SESSION_DURATION = 15 * 60 * 1000; // 15 minutes sliding window
const MAX_SESSION_DURATION = 8 * 60 * 60 * 1000; // 8 hours absolute max
const SESSION_PREFIX = 'session:';
const USER_SESSIONS_PREFIX = 'user_sessions:';

export // TODO: Consider splitting SessionManager into smaller, focused classes
class SessionManager {
  private kv: KVNamespace;
  private jwtService: JWTService;

  constructor(kv: KVNamespace, jwtService: JWTService) {
    this.kv = kv;
    this.jwtService = jwtService;
  }

  /**
   * Create a new session
   */
  async createSession(
    userId: string,
    businessId: string,
    email: string,
    role: string,
    permissions: string[],
    ipAddress: string,
    userAgent: string,
    businessName: string
  ): Promise<SessionData> {
    const sessionId = JWTService.generateSessionId();
    const now = Date.now();

    // Generate token pair
    const tokens = await this.jwtService.generateTokenPair({
      sub: userId,
      email,
      businessId,
      businessName,
      role: role as any,
      permissions,
      sessionId,
      ipAddress,
    });

    const session: SessionData = {
      id: sessionId,
      userId,
      businessId,
      email,
      role,
      permissions,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      accessTokenExp: tokens.accessTokenExp,
      refreshTokenExp: tokens.refreshTokenExp,
      createdAt: now,
      lastActivityAt: now,
      expiresAt: now + SESSION_DURATION,
      ipAddress,
      userAgent,
      mfaEnabled: false,
      mfaVerified: false,
      requestCount: 0,
      lastRequestAt: now,
    };

    // Store session in KV
    await this.saveSession(session);

    // Add to user's session list
    await this.addToUserSessions(userId, sessionId);

    return session;
  }

  /**
   * Get session by ID
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    const key = `${SESSION_PREFIX}${sessionId}`;
    const data = await this.kv.get<SessionData>(key, 'json');

    if (!data) {
      return null;
    }

    // Check if session is expired
    const now = Date.now();
    if (data.expiresAt < now) {
      await this.deleteSession(sessionId);
      return null;
    }

    // Check absolute max duration
    if (now - data.createdAt > MAX_SESSION_DURATION) {
      await this.deleteSession(sessionId);
      return null;
    }

    return data;
  }

  /**
   * Update session activity (sliding window)
   */
  async updateActivity(sessionId: string): Promise<SessionData | null> {
    const session = await this.getSession(sessionId);
    if (!session) {
      return null;
    }

    const now = Date.now();

    // Update sliding window
    session.lastActivityAt = now;
    session.expiresAt = Math.min(
      now + SESSION_DURATION,
      session.createdAt + MAX_SESSION_DURATION
    );

    // Increment request count for rate limiting
    session.requestCount++;
    session.lastRequestAt = now;

    // Check if access token needs refresh
    if (session.accessTokenExp < now + 60000) { // Refresh if expiring in 1 minute
      const tokens = await this.jwtService.generateTokenPair({
        sub: session.userId,
        email: session.email,
        businessId: session.businessId,
        businessName: '', // Will be fetched from DB if needed
        role: session.role as any,
        permissions: session.permissions,
        sessionId: session.id,
        ipAddress: session.ipAddress,
      });

      session.accessToken = tokens.accessToken;
      session.refreshToken = tokens.refreshToken;
      session.accessTokenExp = tokens.accessTokenExp;
      session.refreshTokenExp = tokens.refreshTokenExp;
    }

    await this.saveSession(session);
    return session;
  }

  /**
   * Save session to KV
   */
  private async saveSession(session: SessionData): Promise<void> {
    const key = `${SESSION_PREFIX}${session.id}`;
    const ttl = Math.floor((session.expiresAt - Date.now()) / 1000);

    if (ttl > 0) {
      await this.kv.put(key, JSON.stringify(session), {
        expirationTtl: ttl,
      });
    }
  }

  /**
   * Delete session
   */
  async deleteSession(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      await this.removeFromUserSessions(session.userId, sessionId);
    }

    const key = `${SESSION_PREFIX}${sessionId}`;
    await this.kv.delete(key);
  }

  /**
   * Delete all sessions for a user
   */
  async deleteUserSessions(userId: string): Promise<void> {
    const sessions = await this.getUserSessions(userId);

    // Delete each session
    await Promise.all(
      sessions.map((sessionId: any) => this.kv.delete(`${SESSION_PREFIX}${sessionId}`))
    );

    // Clear user's session list
    await this.kv.delete(`${USER_SESSIONS_PREFIX}${userId}`);
  }

  /**
   * Get all active sessions for a user
   */
  async getUserSessions(userId: string): Promise<string[]> {
    const key = `${USER_SESSIONS_PREFIX}${userId}`;
    const sessions = await this.kv.get<string[]>(key, 'json');
    return sessions || [];
  }

  /**
   * Add session to user's session list
   */
  private async addToUserSessions(userId: string, sessionId: string): Promise<void> {
    const sessions = await this.getUserSessions(userId);
    if (!sessions.includes(sessionId)) {
      sessions.push(sessionId);
      await this.kv.put(
        `${USER_SESSIONS_PREFIX}${userId}`,
        JSON.stringify(sessions),
        { expirationTtl: 86400 } // 24 hours
      );
    }
  }

  /**
   * Remove session from user's session list
   */
  private async removeFromUserSessions(userId: string, sessionId: string): Promise<void> {
    const sessions = await this.getUserSessions(userId);
    const filtered = sessions.filter((id: any) => id !== sessionId);

    if (filtered.length > 0) {
      await this.kv.put(
        `${USER_SESSIONS_PREFIX}${userId}`,
        JSON.stringify(filtered),
        { expirationTtl: 86400 }
      );
    } else {
      await this.kv.delete(`${USER_SESSIONS_PREFIX}${userId}`);
    }
  }

  /**
   * Verify session and get auth context
   */
  async verifySession(sessionId: string, token: string): Promise<AuthContext | null> {
    const session = await this.getSession(sessionId);
    if (!session) {
      return null;
    }

    // Verify token belongs to this session
    try {
      const claims = await this.jwtService.verifyToken(token);
      if (claims.sessionId !== sessionId) {
        return null;
      }

      // Update activity
      await this.updateActivity(sessionId);

      return {
        userId: session.userId,
        email: session.email,
        businessId: session.businessId,
        businessName: '', // Will be fetched if needed
        role: session.role,
        permissions: session.permissions,
        sessionId: session.id,
        isAuthenticated: true,
        mfaRequired: session.mfaEnabled && !session.mfaVerified,
        mfaVerified: session.mfaVerified,
      };
    } catch (error: any) {
      return null;
    }
  }

  /**
   * Refresh session tokens
   */
  async refreshTokens(refreshToken: string): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  } | null> {
    try {
      // Verify refresh token
      const claims = await this.jwtService.verifyToken(refreshToken, 'refresh');

      // Get session
      const session = await this.getSession(claims.sessionId as string);
      if (!session) {
        return null;
      }

      // Verify refresh token matches
      if (session.refreshToken !== refreshToken) {
        // Possible token reuse attack - invalidate session
        await this.deleteSession(session.id);
        return null;
      }

      // Generate new tokens
      const tokens = await this.jwtService.generateTokenPair({
        sub: session.userId,
        email: session.email,
        businessId: session.businessId,
        businessName: '', // Will be fetched from DB
        role: session.role as any,
        permissions: session.permissions,
        sessionId: session.id,
        ipAddress: session.ipAddress,
      });

      // Update session
      session.accessToken = tokens.accessToken;
      session.refreshToken = tokens.refreshToken;
      session.accessTokenExp = tokens.accessTokenExp;
      session.refreshTokenExp = tokens.refreshTokenExp;
      session.lastActivityAt = Date.now();

      await this.saveSession(session);

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: 900, // 15 minutes
      };
    } catch (error: any) {
      return null;
    }
  }

  /**
   * Update MFA status for session
   */
  async updateMFAStatus(sessionId: string, mfaVerified: boolean): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      session.mfaVerified = mfaVerified;
      await this.saveSession(session);
    }
  }

  /**
   * Get session statistics for monitoring
   */
  async getSessionStats(): Promise<{
    totalSessions: number;
    activeSessions: number;
    expiringSoon: number;
  }> {
    // This would need to be implemented with KV list operations
    // For now, return placeholder stats
    return {
      totalSessions: 0,
      activeSessions: 0,
      expiringSoon: 0,
    };
  }

  /**
   * Clean up expired sessions (should be called periodically)
   */
  async cleanupExpiredSessions(): Promise<number> {
    // KV automatically expires keys, but we can clean up the user session lists
    // This would need to be implemented with a scheduled worker
    return 0;
  }
}