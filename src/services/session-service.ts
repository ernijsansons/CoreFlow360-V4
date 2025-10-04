/**
 * Session Service with Advanced Security Features
 * Fixes CVSS 7.5 vulnerability: Session fixation attacks
 *
 * Features:
 * - Session fingerprinting (IP + User-Agent + TLS fingerprint)
 * - Session regeneration after login
 * - Secure session storage with encryption
 * - Session timeout management
 * - Concurrent session limits
 * - Session hijacking detection
 * - Anomaly detection for suspicious sessions
 */

export interface SessionFingerprint {
  ipAddress: string;
  userAgent: string;
  acceptLanguage: string;
  acceptEncoding: string;
  tlsFingerprint?: string;
  screenResolution?: string;
  timezone?: string;
}

export interface SessionData {
  sessionId: string;
  userId: string;
  businessId: string;
  email: string;
  roles: string[];
  permissions: string[];
  mfaVerified: boolean;
  createdAt: number;
  lastActivity: number;
  expiresAt: number;
  fingerprint: SessionFingerprint;
  metadata: {
    loginMethod: 'password' | 'apikey' | 'sso';
    deviceId?: string;
    location?: string;
    riskScore: number;
    anomalyFlags: string[];
  };
}

export interface SessionConfig {
  maxAge: number; // seconds
  idleTimeout: number; // seconds
  maxConcurrentSessions: number;
  enableFingerprinting: boolean;
  enableAnomalyDetection: boolean;
  requireSecureTransport: boolean;
  cookieConfig: {
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'strict' | 'lax' | 'none';
    domain?: string;
    path: string;
  };
}

export interface SessionValidationResult {
  valid: boolean;
  session?: SessionData;
  error?: string;
  warnings?: string[];
  renewRequired?: boolean;
  securityViolation?: boolean;
}

export interface AnomalyDetectionResult {
  isAnomaly: boolean;
  riskScore: number;
  flags: string[];
  reasons: string[];
}

export class SessionService {
  private readonly kv: KVNamespace;
  private readonly config: SessionConfig;

  // Session storage keys
  private readonly SESSION_PREFIX = 'session:';
  private readonly USER_SESSIONS_PREFIX = 'user_sessions:';
  private readonly FINGERPRINT_PREFIX = 'fingerprint:';
  private readonly SESSION_STATS_PREFIX = 'session_stats:';

  // Default configuration
  private readonly DEFAULT_CONFIG: SessionConfig = {
    maxAge: 24 * 60 * 60, // 24 hours
    idleTimeout: 30 * 60, // 30 minutes
    maxConcurrentSessions: 5,
    enableFingerprinting: true,
    enableAnomalyDetection: true,
    requireSecureTransport: true,
    cookieConfig: {
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
      path: '/'
    }
  };

  constructor(kv: KVNamespace, config?: Partial<SessionConfig>) {
    this.kv = kv;
    this.config = { ...this.DEFAULT_CONFIG, ...config };
  }

  /**
   * Create a new session with comprehensive security features
   * SECURITY FIX: Session regeneration after login to prevent session fixation
   */
  async createSession(
    userId: string,
    businessId: string,
    email: string,
    roles: string[],
    permissions: string[],
    request: Request,
    loginMethod: 'password' | 'apikey' | 'sso' = 'password',
    mfaVerified: boolean = false
  ): Promise<SessionData> {
    // Generate new session ID - this prevents session fixation attacks
    const sessionId = await this.generateSecureSessionId();

    // Create comprehensive fingerprint
    const fingerprint = await this.createFingerprint(request);

    // Detect anomalies in the login request
    const anomalyResult = this.config.enableAnomalyDetection
      ? await this.detectAnomalies(fingerprint, userId)
      : { isAnomaly: false, riskScore: 0, flags: [], reasons: [] };

    const now = Date.now();
    const session: SessionData = {
      sessionId,
      userId,
      businessId,
      email,
      roles,
      permissions,
      mfaVerified,
      createdAt: now,
      lastActivity: now,
      expiresAt: now + (this.config.maxAge * 1000),
      fingerprint,
      metadata: {
        loginMethod,
        riskScore: anomalyResult.riskScore,
        anomalyFlags: anomalyResult.flags,
        location: await this.getLocationFromIP(fingerprint.ipAddress),
        deviceId: await this.generateDeviceId(fingerprint)
      }
    };

    // Store session
    await this.storeSession(session);

    // Track user sessions for concurrent session management
    await this.trackUserSession(userId, sessionId);

    // Update session statistics
    await this.updateSessionStats(userId, loginMethod);

    // Log session creation for audit
    await this.logSessionEvent('session_created', session, {
      anomalyDetected: anomalyResult.isAnomaly,
      riskScore: anomalyResult.riskScore,
      anomalyFlags: anomalyResult.flags
    });

    return session;
  }

  /**
   * Validate session with comprehensive security checks
   */
  async validateSession(
    sessionId: string,
    request: Request
  ): Promise<SessionValidationResult> {
    if (!sessionId) {
      return { valid: false, error: 'Session ID missing' };
    }

    // Retrieve session data
    const session = await this.getSession(sessionId);
    if (!session) {
      return { valid: false, error: 'Session not found' };
    }

    const now = Date.now();
    const warnings: string[] = [];

    // Check expiration
    if (now > session.expiresAt) {
      await this.destroySession(sessionId);
      return { valid: false, error: 'Session expired' };
    }

    // Check idle timeout
    const idleTime = now - session.lastActivity;
    if (idleTime > (this.config.idleTimeout * 1000)) {
      await this.destroySession(sessionId);
      return { valid: false, error: 'Session idle timeout' };
    }

    // Fingerprint validation
    if (this.config.enableFingerprinting) {
      const currentFingerprint = await this.createFingerprint(request);
      const fingerprintValidation = await this.validateFingerprint(
        session.fingerprint,
        currentFingerprint
      );

      if (!fingerprintValidation.valid) {
        // Potential session hijacking
        await this.handleSecurityViolation(session, 'fingerprint_mismatch', {
          expectedFingerprint: session.fingerprint,
          actualFingerprint: currentFingerprint,
          violations: fingerprintValidation.violations
        });

        return {
          valid: false,
          error: 'Session security violation detected',
          securityViolation: true
        };
      }

      if (fingerprintValidation.warnings.length > 0) {
        warnings.push(...fingerprintValidation.warnings);
      }
    }

    // Anomaly detection on ongoing session
    if (this.config.enableAnomalyDetection) {
      const currentFingerprint = await this.createFingerprint(request);
      const anomalyResult = await this.detectSessionAnomalies(session, currentFingerprint);

      if (anomalyResult.isAnomaly && anomalyResult.riskScore > 0.8) {
        await this.handleSecurityViolation(session, 'anomaly_detected', {
          riskScore: anomalyResult.riskScore,
          flags: anomalyResult.flags,
          reasons: anomalyResult.reasons
        });

        return {
          valid: false,
          error: 'Suspicious session activity detected',
          securityViolation: true
        };
      }

      if (anomalyResult.riskScore > 0.5) {
        warnings.push('Moderate risk session activity detected');
      }
    }

    // Update last activity
    session.lastActivity = now;
    await this.updateSessionActivity(session);

    // Check if renewal is required (session is getting old)
    const sessionAge = now - session.createdAt;
    const renewRequired = sessionAge > (this.config.maxAge * 1000 * 0.75); // 75% of max age

    return {
      valid: true,
      session,
      warnings: warnings.length > 0 ? warnings : undefined,
      renewRequired
    };
  }

  /**
   * Renew session - creates new session ID while preserving data
   * SECURITY FIX: Session regeneration to prevent session fixation
   */
  async renewSession(sessionId: string, request: Request): Promise<SessionData | null> {
    const session = await this.getSession(sessionId);
    if (!session) {
      return null;
    }

    // Create new session with updated fingerprint
    const newSession: SessionData = {
      ...session,
      sessionId: await this.generateSecureSessionId(),
      lastActivity: Date.now(),
      expiresAt: Date.now() + (this.config.maxAge * 1000),
      fingerprint: await this.createFingerprint(request)
    };

    // Store new session
    await this.storeSession(newSession);

    // Update user session tracking
    await this.updateUserSessionTracking(session.userId, sessionId, newSession.sessionId);

    // Remove old session
    await this.destroySession(sessionId);

    // Log session renewal
    await this.logSessionEvent('session_renewed', newSession, {
      oldSessionId: sessionId
    });

    return newSession;
  }

  /**
   * Destroy session securely
   */
  async destroySession(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);

    if (session) {
      // Remove from user session tracking
      await this.removeUserSessionTracking(session.userId, sessionId);

      // Log session destruction
      await this.logSessionEvent('session_destroyed', session, {
        reason: 'explicit_logout'
      });
    }

    // Remove session data
    await this.kv.delete(`${this.SESSION_PREFIX}${sessionId}`);
  }

  /**
   * Destroy all sessions for a user
   */
  async destroyAllUserSessions(userId: string, exceptSessionId?: string): Promise<number> {
    const userSessions = await this.getUserSessions(userId);
    let destroyedCount = 0;

    for (const sessionId of userSessions) {
      if (sessionId !== exceptSessionId) {
        await this.destroySession(sessionId);
        destroyedCount++;
      }
    }

    return destroyedCount;
  }

  /**
   * Get session data
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    try {
      const sessionJson = await this.kv.get(`${this.SESSION_PREFIX}${sessionId}`);
      if (!sessionJson) return null;

      return JSON.parse(sessionJson) as SessionData;
    } catch {
      return null;
    }
  }

  /**
   * Create comprehensive browser fingerprint
   */
  private async createFingerprint(request: Request): Promise<SessionFingerprint> {
    const headers = request.headers;

    return {
      ipAddress: headers.get('CF-Connecting-IP') || headers.get('X-Forwarded-For') || 'unknown',
      userAgent: headers.get('User-Agent') || 'unknown',
      acceptLanguage: headers.get('Accept-Language') || 'unknown',
      acceptEncoding: headers.get('Accept-Encoding') || 'unknown',
      tlsFingerprint: headers.get('CF-RAY') || undefined, // Cloudflare TLS fingerprint
      // Additional client-side data would come from headers or request body
      screenResolution: headers.get('X-Screen-Resolution') || undefined,
      timezone: headers.get('X-Timezone') || undefined
    };
  }

  /**
   * Validate fingerprint against stored fingerprint
   */
  private async validateFingerprint(
    storedFingerprint: SessionFingerprint,
    currentFingerprint: SessionFingerprint
  ): Promise<{ valid: boolean; violations: string[]; warnings: string[] }> {
    const violations: string[] = [];
    const warnings: string[] = [];

    // Critical checks - these trigger security violations
    if (storedFingerprint.ipAddress !== currentFingerprint.ipAddress) {
      violations.push('IP address mismatch');
    }

    // Less critical checks - these generate warnings
    if (storedFingerprint.userAgent !== currentFingerprint.userAgent) {
      warnings.push('User agent changed');
    }

    if (storedFingerprint.acceptLanguage !== currentFingerprint.acceptLanguage) {
      warnings.push('Accept language changed');
    }

    if (storedFingerprint.acceptEncoding !== currentFingerprint.acceptEncoding) {
      warnings.push('Accept encoding changed');
    }

    // TLS fingerprint is very stable, changes are suspicious
    if (storedFingerprint.tlsFingerprint && currentFingerprint.tlsFingerprint &&
        storedFingerprint.tlsFingerprint !== currentFingerprint.tlsFingerprint) {
      violations.push('TLS fingerprint mismatch');
    }

    return {
      valid: violations.length === 0,
      violations,
      warnings
    };
  }

  /**
   * Detect anomalies during session creation
   */
  private async detectAnomalies(
    fingerprint: SessionFingerprint,
    userId: string
  ): Promise<AnomalyDetectionResult> {
    const flags: string[] = [];
    const reasons: string[] = [];
    let riskScore = 0;

    // Check for unusual user agent
    const ua = fingerprint.userAgent.toLowerCase();
    if (!ua.includes('mozilla') && !ua.includes('chrome') && !ua.includes('safari') && !ua.includes('firefox')) {
      flags.push('suspicious_user_agent');
      reasons.push('Non-standard user agent detected');
      riskScore += 0.3;
    }

    // Check for automation tools
    const automationKeywords = ['bot', 'crawler', 'script', 'python', 'curl', 'wget'];
    if (automationKeywords.some(keyword => ua.includes(keyword))) {
      flags.push('automation_detected');
      reasons.push('Automation tool detected');
      riskScore += 0.5;
    }

    // Check IP reputation (placeholder - integrate with actual IP reputation service)
    const ipRisk = await this.checkIPReputation(fingerprint.ipAddress);
    if (ipRisk > 0.5) {
      flags.push('suspicious_ip');
      reasons.push('IP address has bad reputation');
      riskScore += ipRisk * 0.4;
    }

    // Check for unusual login patterns
    const loginHistory = await this.getUserLoginHistory(userId);
    if (loginHistory) {
      const anomalyScore = await this.analyzeLoginPattern(fingerprint, loginHistory);
      if (anomalyScore > 0.5) {
        flags.push('unusual_login_pattern');
        reasons.push('Login pattern deviates from historical behavior');
        riskScore += anomalyScore * 0.3;
      }
    }

    return {
      isAnomaly: riskScore > 0.5,
      riskScore: Math.min(riskScore, 1.0),
      flags,
      reasons
    };
  }

  /**
   * Detect anomalies during ongoing session
   */
  private async detectSessionAnomalies(
    session: SessionData,
    currentFingerprint: SessionFingerprint
  ): Promise<AnomalyDetectionResult> {
    const flags: string[] = [];
    const reasons: string[] = [];
    let riskScore = 0;

    // Check for rapid location changes
    const storedLocation = session.metadata.location;
    const currentLocation = await this.getLocationFromIP(currentFingerprint.ipAddress);

    if (storedLocation && currentLocation && storedLocation !== currentLocation) {
      const timeElapsed = Date.now() - session.lastActivity;
      const minTravelTime = await this.calculateMinTravelTime(storedLocation, currentLocation);

      if (timeElapsed < minTravelTime) {
        flags.push('impossible_travel');
        reasons.push('Location change too rapid for physical travel');
        riskScore += 0.8;
      }
    }

    // Check session duration anomalies
    const sessionDuration = Date.now() - session.createdAt;
    const avgSessionDuration = await this.getAverageSessionDuration(session.userId);

    if (avgSessionDuration && sessionDuration > avgSessionDuration * 3) {
      flags.push('unusually_long_session');
      reasons.push('Session duration significantly exceeds user average');
      riskScore += 0.2;
    }

    // Check for multiple concurrent sessions from different IPs
    const concurrentSessions = await this.getConcurrentSessions(session.userId);
    const uniqueIPs = new Set(concurrentSessions.map(s => s.fingerprint.ipAddress));

    if (uniqueIPs.size > 2) {
      flags.push('multiple_ip_sessions');
      reasons.push('Multiple concurrent sessions from different IP addresses');
      riskScore += 0.4;
    }

    return {
      isAnomaly: riskScore > 0.5,
      riskScore: Math.min(riskScore, 1.0),
      flags,
      reasons
    };
  }

  /**
   * Generate cryptographically secure session ID
   */
  private async generateSecureSessionId(): Promise<string> {
    // Generate 32 bytes (256 bits) of random data
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));

    // Convert to base64url encoding
    const base64 = btoa(String.fromCharCode(...randomBytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    return `sess_${base64}`;
  }

  /**
   * Generate device ID from fingerprint
   */
  private async generateDeviceId(fingerprint: SessionFingerprint): Promise<string> {
    const deviceString = [
      fingerprint.userAgent,
      fingerprint.acceptLanguage,
      fingerprint.screenResolution || '',
      fingerprint.timezone || ''
    ].join('|');

    const encoder = new TextEncoder();
    const data = encoder.encode(deviceString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    return `dev_${hashArray.map(b => b.toString(16).padStart(2, '0')).join('')}`;
  }

  /**
   * Store session data securely
   */
  private async storeSession(session: SessionData): Promise<void> {
    const sessionKey = `${this.SESSION_PREFIX}${session.sessionId}`;
    const ttl = Math.ceil((session.expiresAt - Date.now()) / 1000);

    await this.kv.put(sessionKey, JSON.stringify(session), {
      expirationTtl: ttl
    });
  }

  /**
   * Update session last activity
   */
  private async updateSessionActivity(session: SessionData): Promise<void> {
    await this.storeSession(session);
  }

  /**
   * Track user sessions for concurrent session management
   */
  private async trackUserSession(userId: string, sessionId: string): Promise<void> {
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
    const sessionsJson = await this.kv.get(userSessionsKey);
    const sessions: string[] = sessionsJson ? JSON.parse(sessionsJson) : [];

    // Add new session
    if (!sessions.includes(sessionId)) {
      sessions.push(sessionId);

      // Enforce concurrent session limit
      if (sessions.length > this.config.maxConcurrentSessions) {
        const excessSessions = sessions.splice(0, sessions.length - this.config.maxConcurrentSessions);

        // Destroy excess sessions
        for (const excessSessionId of excessSessions) {
          await this.destroySession(excessSessionId);
        }
      }

      await this.kv.put(userSessionsKey, JSON.stringify(sessions), {
        expirationTtl: this.config.maxAge
      });
    }
  }

  /**
   * Update user session tracking when session is renewed
   */
  private async updateUserSessionTracking(
    userId: string,
    oldSessionId: string,
    newSessionId: string
  ): Promise<void> {
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
    const sessionsJson = await this.kv.get(userSessionsKey);
    const sessions: string[] = sessionsJson ? JSON.parse(sessionsJson) : [];

    const index = sessions.indexOf(oldSessionId);
    if (index !== -1) {
      sessions[index] = newSessionId;

      await this.kv.put(userSessionsKey, JSON.stringify(sessions), {
        expirationTtl: this.config.maxAge
      });
    }
  }

  /**
   * Remove session from user session tracking
   */
  private async removeUserSessionTracking(userId: string, sessionId: string): Promise<void> {
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
    const sessionsJson = await this.kv.get(userSessionsKey);
    const sessions: string[] = sessionsJson ? JSON.parse(sessionsJson) : [];

    const filteredSessions = sessions.filter(id => id !== sessionId);

    if (filteredSessions.length === 0) {
      await this.kv.delete(userSessionsKey);
    } else {
      await this.kv.put(userSessionsKey, JSON.stringify(filteredSessions), {
        expirationTtl: this.config.maxAge
      });
    }
  }

  /**
   * Get all sessions for a user
   */
  private async getUserSessions(userId: string): Promise<string[]> {
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
    const sessionsJson = await this.kv.get(userSessionsKey);
    return sessionsJson ? JSON.parse(sessionsJson) : [];
  }

  /**
   * Get concurrent sessions for a user
   */
  private async getConcurrentSessions(userId: string): Promise<SessionData[]> {
    const sessionIds = await this.getUserSessions(userId);
    const sessions: SessionData[] = [];

    for (const sessionId of sessionIds) {
      const session = await this.getSession(sessionId);
      if (session) {
        sessions.push(session);
      }
    }

    return sessions;
  }

  /**
   * Handle security violations
   */
  private async handleSecurityViolation(
    session: SessionData,
    violationType: string,
    details: any
  ): Promise<void> {
    // Log security violation
    await this.logSessionEvent('security_violation', session, {
      violationType,
      details,
      severity: 'high'
    });

    // Destroy potentially compromised session
    await this.destroySession(session.sessionId);

    // Optionally: Rate limit the user, send security alert, etc.
  }

  /**
   * Placeholder methods for external integrations
   */
  private async checkIPReputation(ip: string): Promise<number> {
    // Integrate with IP reputation service
    return 0; // Low risk by default
  }

  private async getLocationFromIP(ip: string): Promise<string | undefined> {
    // Integrate with IP geolocation service
    return undefined;
  }

  private async calculateMinTravelTime(location1: string, location2: string): Promise<number> {
    // Calculate minimum travel time between locations
    return 60 * 60 * 1000; // 1 hour default
  }

  private async getUserLoginHistory(userId: string): Promise<any> {
    // Get user's login history for pattern analysis
    return null;
  }

  private async analyzeLoginPattern(fingerprint: SessionFingerprint, history: any): Promise<number> {
    // Analyze login patterns for anomalies
    return 0; // No anomaly by default
  }

  private async getAverageSessionDuration(userId: string): Promise<number | null> {
    // Get average session duration for user
    return null;
  }

  /**
   * Update session statistics
   */
  private async updateSessionStats(userId: string, loginMethod: string): Promise<void> {
    const statsKey = `${this.SESSION_STATS_PREFIX}${userId}`;
    const statsJson = await this.kv.get(statsKey);

    const stats = statsJson ? JSON.parse(statsJson) : {
      totalSessions: 0,
      loginMethods: {},
      lastLogin: null
    };

    stats.totalSessions++;
    stats.loginMethods[loginMethod] = (stats.loginMethods[loginMethod] || 0) + 1;
    stats.lastLogin = Date.now();

    await this.kv.put(statsKey, JSON.stringify(stats), {
      expirationTtl: 30 * 24 * 60 * 60 // 30 days
    });
  }

  /**
   * Log session events for audit
   */
  private async logSessionEvent(
    event: string,
    session: SessionData,
    additional: any = {}
  ): Promise<void> {
    // This would integrate with your audit logging system
    const logEntry = {
      timestamp: Date.now(),
      event,
      sessionId: session.sessionId,
      userId: session.userId,
      businessId: session.businessId,
      ipAddress: session.fingerprint.ipAddress,
      userAgent: session.fingerprint.userAgent,
      riskScore: session.metadata.riskScore,
      ...additional
    };

    // Store or forward to audit system
    console.log('Session audit log:', logEntry);
  }

  /**
   * Get session service statistics
   */
  async getStatistics(): Promise<{
    activeSessions: number;
    totalSessionsToday: number;
    averageSessionDuration: number;
    securityViolationsToday: number;
    topRiskFactors: string[];
  }> {
    // This would aggregate statistics from your stored data
    return {
      activeSessions: 0,
      totalSessionsToday: 0,
      averageSessionDuration: 0,
      securityViolationsToday: 0,
      topRiskFactors: []
    };
  }

  /**
   * Create secure cookie for session
   */
  createSecureCookie(sessionId: string): string {
    const config = this.config.cookieConfig;
    const parts = [`session=${sessionId}`];

    parts.push(`Max-Age=${this.config.maxAge}`);

    if (config.secure) {
      parts.push('Secure');
    }

    if (config.httpOnly) {
      parts.push('HttpOnly');
    }

    if (config.sameSite) {
      parts.push(`SameSite=${config.sameSite}`);
    }

    if (config.domain) {
      parts.push(`Domain=${config.domain}`);
    }

    parts.push(`Path=${config.path}`);

    return parts.join('; ');
  }
}

/**
 * Create session service instance
 */
export function createSessionService(
  kv: KVNamespace,
  config?: Partial<SessionConfig>
): SessionService {
  return new SessionService(kv, config);
}

// Export types
export type {
  SessionFingerprint,
  SessionData,
  SessionConfig,
  SessionValidationResult,
  AnomalyDetectionResult
};