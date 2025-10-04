/**
 * Enterprise Session Management System
 * SECURITY: Implements secure session handling with fingerprinting and rotation
 * Fixes: CVSS 7.5 vulnerability - Session hijacking prevention
 */

import { createHash } from 'crypto';

export interface SessionData {
  id: string;
  userId: string;
  businessId: string;
  email: string;
  roles: string[];
  permissions: string[];
  createdAt: number;
  lastActivity: number;
  expiresAt: number;
  fingerprint: string;
  ipAddress: string;
  userAgent: string;
  rotationCount: number;
  mfaVerified: boolean;
  metadata?: Record<string, any>;
}

export interface SessionFingerprint {
  userAgent: string;
  acceptLanguage: string;
  acceptEncoding: string;
  ipAddress: string;
  screenResolution?: string;
  timezone?: string;
  plugins?: string[];
  canvas?: string;
}

export interface SessionConfig {
  maxAge: number; // milliseconds (default: 8 hours)
  slidingExpiration: boolean; // Extend on activity
  maxRotations: number; // Max session regenerations
  requireFingerprint: boolean;
  requireMFA: boolean;
  maxConcurrentSessions: number;
  ipValidation: boolean;
  userAgentValidation: boolean;
}

export class SessionManager {
  private readonly kv: KVNamespace;
  private readonly config: SessionConfig;
  private readonly sessionPrefix = 'session:';
  private readonly userSessionsPrefix = 'user:sessions:';
  private readonly fingerprintPrefix = 'fingerprint:';

  constructor(kv: KVNamespace, config?: Partial<SessionConfig>) {
    this.kv = kv;
    this.config = {
      maxAge: config?.maxAge || 8 * 60 * 60 * 1000, // 8 hours
      slidingExpiration: config?.slidingExpiration ?? true,
      maxRotations: config?.maxRotations || 10,
      requireFingerprint: config?.requireFingerprint ?? true,
      requireMFA: config?.requireMFA ?? false,
      maxConcurrentSessions: config?.maxConcurrentSessions || 5,
      ipValidation: config?.ipValidation ?? true,
      userAgentValidation: config?.userAgentValidation ?? true
    };
  }

  /**
   * Create a new session with fingerprinting
   */
  async createSession(
    userId: string,
    businessId: string,
    email: string,
    roles: string[],
    permissions: string[],
    request: Request,
    mfaVerified = false
  ): Promise<{ sessionId: string; session: SessionData }> {
    // Generate secure session ID
    const sessionId = this.generateSecureSessionId();

    // Extract fingerprint from request
    const fingerprint = await this.generateFingerprint(request);

    // Check concurrent sessions limit
    await this.enforceConcurrentSessionLimit(userId);

    const now = Date.now();
    const session: SessionData = {
      id: sessionId,
      userId,
      businessId,
      email,
      roles,
      permissions,
      createdAt: now,
      lastActivity: now,
      expiresAt: now + this.config.maxAge,
      fingerprint: fingerprint.hash,
      ipAddress: this.getClientIP(request),
      userAgent: request.headers.get('User-Agent') || '',
      rotationCount: 0,
      mfaVerified,
      metadata: {
        created: new Date(now).toISOString(),
        source: 'web'
      }
    };

    // Store session
    await this.storeSession(sessionId, session);

    // Track user session
    await this.trackUserSession(userId, sessionId);

    // Store fingerprint details for validation
    await this.storeFingerprintDetails(sessionId, fingerprint);

    // Log session creation
    await this.logSessionEvent(sessionId, 'created', userId);

    return { sessionId, session };
  }

  /**
   * Validate session with security checks
   */
  async validateSession(
    sessionId: string,
    request: Request
  ): Promise<{ valid: boolean; session?: SessionData; reason?: string }> {
    try {
      // Get session data
      const session = await this.getSession(sessionId);

      if (!session) {
        return { valid: false, reason: 'Session not found' };
      }

      const now = Date.now();

      // Check expiration
      if (session.expiresAt <= now) {
        await this.destroySession(sessionId);
        return { valid: false, reason: 'Session expired' };
      }

      // Validate fingerprint
      if (this.config.requireFingerprint) {
        const currentFingerprint = await this.generateFingerprint(request);
        if (currentFingerprint.hash !== session.fingerprint) {
          await this.handleSuspiciousActivity(sessionId, 'fingerprint_mismatch');
          return { valid: false, reason: 'Fingerprint mismatch - possible hijacking attempt' };
        }
      }

      // Validate IP address
      if (this.config.ipValidation) {
        const currentIP = this.getClientIP(request);
        if (currentIP !== session.ipAddress) {
          // Allow IP change but log it
          await this.logSessionEvent(sessionId, 'ip_changed', session.userId, {
            oldIP: session.ipAddress,
            newIP: currentIP
          });

          // Require re-authentication for sensitive operations
          session.metadata = session.metadata || {};
          session.metadata.requireReauth = true;
        }
      }

      // Validate user agent
      if (this.config.userAgentValidation) {
        const currentUA = request.headers.get('User-Agent') || '';
        if (currentUA !== session.userAgent) {
          await this.handleSuspiciousActivity(sessionId, 'useragent_mismatch');
          return { valid: false, reason: 'User agent mismatch' };
        }
      }

      // Check MFA requirement
      if (this.config.requireMFA && !session.mfaVerified) {
        return { valid: false, reason: 'MFA verification required' };
      }

      // Update last activity if sliding expiration
      if (this.config.slidingExpiration) {
        session.lastActivity = now;
        session.expiresAt = now + this.config.maxAge;
        await this.storeSession(sessionId, session);
      }

      return { valid: true, session };

    } catch (error: any) {
      console.error('Session validation error:', error);
      return { valid: false, reason: 'Validation failed' };
    }
  }

  /**
   * Regenerate session ID (rotation) to prevent fixation attacks
   */
  async regenerateSession(
    oldSessionId: string,
    request: Request
  ): Promise<{ sessionId: string; session: SessionData } | null> {
    const session = await this.getSession(oldSessionId);

    if (!session) {
      return null;
    }

    // Check rotation limit
    if (session.rotationCount >= this.config.maxRotations) {
      await this.destroySession(oldSessionId);
      return null;
    }

    // Generate new session ID
    const newSessionId = this.generateSecureSessionId();

    // Update session with new ID
    session.id = newSessionId;
    session.rotationCount++;
    session.lastActivity = Date.now();

    // Generate new fingerprint
    const newFingerprint = await this.generateFingerprint(request);
    session.fingerprint = newFingerprint.hash;

    // Store new session
    await this.storeSession(newSessionId, session);

    // Store new fingerprint
    await this.storeFingerprintDetails(newSessionId, newFingerprint);

    // Delete old session
    await this.kv.delete(`${this.sessionPrefix}${oldSessionId}`);

    // Update user session tracking
    await this.updateUserSessionTracking(session.userId, oldSessionId, newSessionId);

    // Log rotation
    await this.logSessionEvent(newSessionId, 'rotated', session.userId, {
      oldSessionId,
      rotationCount: session.rotationCount
    });

    return { sessionId: newSessionId, session };
  }

  /**
   * Destroy session
   */
  async destroySession(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);

    if (session) {
      // Remove from user sessions
      await this.removeUserSession(session.userId, sessionId);

      // Log destruction
      await this.logSessionEvent(sessionId, 'destroyed', session.userId);
    }

    // Delete session and fingerprint
    await this.kv.delete(`${this.sessionPrefix}${sessionId}`);
    await this.kv.delete(`${this.fingerprintPrefix}${sessionId}`);
  }

  /**
   * Destroy all user sessions (logout from all devices)
   */
  async destroyAllUserSessions(userId: string): Promise<void> {
    const sessionIds = await this.getUserSessions(userId);

    for (const sessionId of sessionIds) {
      await this.destroySession(sessionId);
    }

    // Clear user session list
    await this.kv.delete(`${this.userSessionsPrefix}${userId}`);
  }

  /**
   * Generate secure session ID
   */
  private generateSecureSessionId(): string {
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);

    // Add timestamp for uniqueness
    const timestamp = Date.now().toString(36);
    const random = btoa(String.fromCharCode(...randomBytes))
      .replace(/[+/=]/g, '') // Remove URL-unsafe characters
      .substring(0, 32);

    return `${timestamp}_${random}`;
  }

  /**
   * Generate session fingerprint
   */
  private async generateFingerprint(request: Request): Promise<{ hash: string; details: SessionFingerprint }> {
    const details: SessionFingerprint = {
      userAgent: request.headers.get('User-Agent') || '',
      acceptLanguage: request.headers.get('Accept-Language') || '',
      acceptEncoding: request.headers.get('Accept-Encoding') || '',
      ipAddress: this.getClientIP(request)
    };

    // Add client hints if available
    const clientHints = {
      platform: request.headers.get('Sec-CH-UA-Platform') || '',
      mobile: request.headers.get('Sec-CH-UA-Mobile') || '',
      model: request.headers.get('Sec-CH-UA-Model') || ''
    };

    // Create fingerprint hash
    const fingerprintString = JSON.stringify({ ...details, ...clientHints });
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprintString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return { hash, details };
  }

  /**
   * Get client IP address
   */
  private getClientIP(request: Request): string {
    return request.headers.get('CF-Connecting-IP') ||
           request.headers.get('X-Forwarded-For')?.split(',')[0].trim() ||
           request.headers.get('X-Real-IP') ||
           '0.0.0.0';
  }

  /**
   * Store session in KV
   */
  private async storeSession(sessionId: string, session: SessionData): Promise<void> {
    const ttl = Math.ceil((session.expiresAt - Date.now()) / 1000);

    if (ttl > 0) {
      await this.kv.put(
        `${this.sessionPrefix}${sessionId}`,
        JSON.stringify(session),
        { expirationTtl: ttl }
      );
    }
  }

  /**
   * Get session from KV
   */
  private async getSession(sessionId: string): Promise<SessionData | null> {
    const data = await this.kv.get(`${this.sessionPrefix}${sessionId}`);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Store fingerprint details
   */
  private async storeFingerprintDetails(sessionId: string, fingerprint: { hash: string; details: SessionFingerprint }): Promise<void> {
    await this.kv.put(
      `${this.fingerprintPrefix}${sessionId}`,
      JSON.stringify(fingerprint),
      { expirationTtl: Math.ceil(this.config.maxAge / 1000) }
    );
  }

  /**
   * Track user sessions
   */
  private async trackUserSession(userId: string, sessionId: string): Promise<void> {
    const key = `${this.userSessionsPrefix}${userId}`;
    const existingData = await this.kv.get(key);
    const sessions = existingData ? JSON.parse(existingData) : [];

    if (!sessions.includes(sessionId)) {
      sessions.push(sessionId);
      await this.kv.put(key, JSON.stringify(sessions), {
        expirationTtl: Math.ceil(this.config.maxAge / 1000)
      });
    }
  }

  /**
   * Get user sessions
   */
  private async getUserSessions(userId: string): Promise<string[]> {
    const key = `${this.userSessionsPrefix}${userId}`;
    const data = await this.kv.get(key);
    return data ? JSON.parse(data) : [];
  }

  /**
   * Remove user session
   */
  private async removeUserSession(userId: string, sessionId: string): Promise<void> {
    const sessions = await this.getUserSessions(userId);
    const filtered = sessions.filter(id => id !== sessionId);

    if (filtered.length > 0) {
      await this.kv.put(
        `${this.userSessionsPrefix}${userId}`,
        JSON.stringify(filtered),
        { expirationTtl: Math.ceil(this.config.maxAge / 1000) }
      );
    } else {
      await this.kv.delete(`${this.userSessionsPrefix}${userId}`);
    }
  }

  /**
   * Update user session tracking after rotation
   */
  private async updateUserSessionTracking(userId: string, oldSessionId: string, newSessionId: string): Promise<void> {
    const sessions = await this.getUserSessions(userId);
    const index = sessions.indexOf(oldSessionId);

    if (index !== -1) {
      sessions[index] = newSessionId;
      await this.kv.put(
        `${this.userSessionsPrefix}${userId}`,
        JSON.stringify(sessions),
        { expirationTtl: Math.ceil(this.config.maxAge / 1000) }
      );
    }
  }

  /**
   * Enforce concurrent session limit
   */
  private async enforceConcurrentSessionLimit(userId: string): Promise<void> {
    const sessions = await this.getUserSessions(userId);

    if (sessions.length >= this.config.maxConcurrentSessions) {
      // Remove oldest session
      const oldestSessionId = sessions[0];
      await this.destroySession(oldestSessionId);

      // Log forced logout
      await this.logSessionEvent(oldestSessionId, 'force_logout', userId, {
        reason: 'concurrent_session_limit'
      });
    }
  }

  /**
   * Handle suspicious activity
   */
  private async handleSuspiciousActivity(sessionId: string, reason: string): Promise<void> {
    const session = await this.getSession(sessionId);

    if (session) {
      // Log security event
      await this.logSessionEvent(sessionId, 'security_alert', session.userId, {
        reason,
        ipAddress: session.ipAddress,
        userAgent: session.userAgent
      });

      // Destroy compromised session
      await this.destroySession(sessionId);

      // Could trigger additional security measures here
      // e.g., notify user, require password reset, etc.
    }
  }

  /**
   * Log session events
   */
  private async logSessionEvent(
    sessionId: string,
    event: string,
    userId: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    const logEntry = {
      sessionId,
      event,
      userId,
      timestamp: new Date().toISOString(),
      metadata
    };

    // Store in KV with TTL for audit trail
    await this.kv.put(
      `session:log:${Date.now()}_${sessionId}`,
      JSON.stringify(logEntry),
      { expirationTtl: 30 * 24 * 60 * 60 } // 30 days
    );
  }

  /**
   * Get session metrics
   */
  async getSessionMetrics(userId?: string): Promise<{
    totalSessions: number;
    activeSessions: number;
    suspiciousActivities: number;
    averageSessionDuration: number;
  }> {
    // Implementation would query session logs and calculate metrics
    // This is a placeholder for the actual implementation
    return {
      totalSessions: 0,
      activeSessions: userId ? (await this.getUserSessions(userId)).length : 0,
      suspiciousActivities: 0,
      averageSessionDuration: 0
    };
  }
}

// Export factory function
export function createSessionManager(kv: KVNamespace, config?: Partial<SessionConfig>): SessionManager {
  return new SessionManager(kv, config);
}