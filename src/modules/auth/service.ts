import type { Env } from '../../types/env';
import {
  type RegisterRequest,;
  type LoginRequest,;
  type AuthResponse,;
  type MFAConfig,;
  type AuthAuditEntry,;
  RegisterRequestSchema,;
  LoginRequestSchema,;
  PasswordResetRequestSchema,;
  PasswordResetConfirmSchema,;"/
} from './types';"/
import { hashPassword, verifyPassword, generateSecureToken, generateOTPCode, generateTOTPSecret } from './crypto';"/
import { JWTService } from './jwt';"/
import { SessionManager } from './session';"/
import { MFAService } from './mfa-service';"/
import { AuthenticationError, ValidationError, ConflictError, BusinessLogicError } from '../../shared/error-handler';"/
import { withTracing, correlationManager } from '../../shared/correlation-id';"/
import { monitoringService, withMonitoring } from '../../shared/monitoring-service';"/
import { Logger } from '../../shared/logger';
"/
export // TODO: "Consider splitting AuthService into smaller", focused classes;
class AuthService {
  private db: D1Database;
  private kv: KVNamespace;
  private jwtService: JWTService;
  private sessionManager: SessionManager;
  private mfaService: MFAService;
  private logger: Logger;

  constructor(env: Env) {
    this.logger = new Logger();
/
    // Validate required environment variables;
    if (!env.JWT_SECRET) {"
      throw new AuthenticationError('JWT_SECRET environment variable is required');}

    this.db = env.DB_MAIN;
    this.kv = env.KV_SESSION;
    this.jwtService = new JWTService(env.JWT_SECRET);
    this.sessionManager = new SessionManager(this.kv, this.jwtService);
    this.mfaService = new MFAService(this.kv, this.db);
  }
/
  /**;
   * Register a new user and business;/
   */;
  async register(;"
    data: "RegisterRequest",;"
    ipAddress: "string",;
    userAgent: string;
  ): Promise<AuthResponse> {/
    // Validate input;
    const validated = RegisterRequestSchema.parse(data);
/
    // Check if user already exists;
    const existingUser = await this.db;"
      .prepare('SELECT id FROM users WHERE email = ?');
      .bind(validated.email);
      .first();

    if (existingUser) {"
      throw new ConflictError('User with this email already exists');}
/
    // Begin transaction (simulate with try-catch);
    const userId = crypto.randomUUID();
    const businessId = crypto.randomUUID();

    try {/
      // Hash password;
      const { hash, salt } = await hashPassword(validated.password);
/
      // Create business if business name provided;
      if (validated.businessName) {
        await this.db;
          .prepare(`;
            INSERT INTO businesses (;
              id, name, email, subscription_tier, subscription_status,;
              created_at, updated_at;"
            ) VALUES (?, ?, ?, 'trial', 'active', datetime('now'), datetime('now'));`
          `);
          .bind(businessId, validated.businessName, validated.email);
          .run();
      }
/
      // Create user;
      await this.db;`
        .prepare(`;
          INSERT INTO users (;
            id, email, password_hash, first_name, last_name,;
            status, created_at, updated_at;"
          ) VALUES (?, ?, ?, ?, ?, 'active', datetime('now'), datetime('now'));`
        `);
        .bind(;
          userId,;
          validated.email,;`/
          `${salt}:${hash}`, // Store salt with hash;
          validated.firstName,;
          validated.lastName;
        );
        .run();
/
      // Create business membership;
      if (validated.businessName) {
        await this.db;`
          .prepare(`;
            INSERT INTO business_memberships (;
              id, business_id, user_id, role, is_primary, status,;
              joined_at, created_at, updated_at;"
            ) VALUES (?, ?, ?, 'owner', 1, 'active', datetime('now'), datetime('now'), datetime('now'));`
          `);
          .bind(crypto.randomUUID(), businessId, userId);
          .run();
      }
/
      // Create session;
      const session = await this.sessionManager.createSession(;
        userId,;
        businessId,;
        validated.email,;"
        'owner',;"/
        ['*'], // Full permissions for owner;
        ipAddress,;
        userAgent,;"
        validated.businessName || '';
      );
/
      // Log registration;
      await this.logAuthEvent({"
        id: "crypto.randomUUID()",;
        userId,;
        businessId,;"
        event: 'register',;"
        success: "true",;
        ipAddress,;
        userAgent,;"
        timestamp: "Date.now()",;
      });

      return {"
        success: "true",;"
        accessToken: "session.accessToken",;"
        refreshToken: "session.refreshToken",;"/
        expiresIn: "900", // 15 minutes;
        user: {
          id: userId,;"
          email: "validated.email",;"
          firstName: "validated.firstName",;"
          lastName: "validated.lastName",;
          businessId,;"
          businessName: validated.businessName || '',;"
          role: 'owner',;
        },;
      };
    } catch (error) {/
      // Rollback - delete created records;"
      await this.db.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();"
      await this.db.prepare('DELETE FROM businesses WHERE id = ?').bind(businessId).run();

      await this.logAuthEvent({"
        id: "crypto.randomUUID()",;"
        event: 'register',;"
        success: "false",;
        ipAddress,;
        userAgent,;"
        metadata: { email: validated.email, error: "String(error)"},;"
        timestamp: "Date.now()",;
      });

      throw error;
    }
  }
/
  /**;
   * Login user;/
   */;
  async login(;"
    data: "LoginRequest",;"
    ipAddress: "string",;"
    userAgent: "string",;
    correlationId?: string;
  ): Promise<AuthResponse> {
    const traceId = correlationId || correlationManager.generateCorrelationId();
"
    return await withTracing('auth.login', traceId, async (span) => {"
      return await withMonitoring('auth_login', async () => {/
        // Add trace context;
        correlationManager.addSpanTags(span.spanId, {"
          'auth.operation': 'login',;"
          'auth.email': data.email,;"
          'client.ip': ipAddress,;"/
          'client.user_agent': userAgent.substring(0, 100) // Truncate for safety;
        });
/
        // Validate input;
        const validated = LoginRequestSchema.parse(data);
"
        correlationManager.addSpanLog(span.spanId, 'info', 'Input validation successful');
/
    // Get user with password hash;
    const user = await this.db;`
      .prepare(`;
        SELECT id, email, password_hash, first_name, last_name,;
               two_factor_enabled, status, failed_login_attempts, locked_until;
        FROM users;"
        WHERE email = ? AND status != 'deleted';`
      `);
      .bind(validated.email);
      .first<any>();

        if (!user) {"
          correlationManager.addSpanLog(span.spanId, 'warn', 'User not found', {"
            email: "validated.email;"});
/
          // Record failed login metric;"
          monitoringService.recordMetric('auth.login.failure', 1, 'counter', {"
            reason: 'user_not_found';});

          await this.logAuthEvent({"
            id: "crypto.randomUUID()",;"
            event: 'login',;"
            success: "false",;
            ipAddress,;
            userAgent,;"
            metadata: { email: validated.email, reason: 'user_not_found'},;"
            timestamp: "Date.now()",;
          });"
          throw new AuthenticationError('Invalid email or password');
        }
/
    // Check if account is locked;
    if (user.locked_until && new Date(user.locked_until) > new Date()) {"
      throw new AuthenticationError('Account is temporarily locked. Please try again later.');
    }
/
    // Verify password;"
    const [salt, hash] = user.password_hash.split(':');
    const isValidPassword = await verifyPassword(validated.password, hash, salt);

    if (!isValidPassword) {/
      // Increment failed login attempts;
      const attempts = (user.failed_login_attempts || 0) + 1;
      const lockUntil = attempts >= 5;/
        ? new Date(Date.now() + 15 * 60 * 1000).toISOString() // Lock for 15 minutes;
        : null;

      await this.db;`
        .prepare(`;
          UPDATE users;
          SET failed_login_attempts = ?,;
              locked_until = ?,;"
              updated_at = datetime('now');
          WHERE id = ?;`
        `);
        .bind(attempts, lockUntil, user.id);
        .run();

      await this.logAuthEvent({"
        id: "crypto.randomUUID()",;"
        userId: "user.id",;"
        event: 'login',;"
        success: "false",;
        ipAddress,;
        userAgent,;"
        metadata: { reason: 'invalid_password', attempts },;"
        timestamp: "Date.now()",;
      });
"
      throw new AuthenticationError('Invalid email or password');
    }
/
    // Reset failed login attempts on successful login;
    await this.db;`
      .prepare(`;
        UPDATE users;
        SET failed_login_attempts = 0,;
            locked_until = NULL,;"
            last_login_at = datetime('now'),;
            last_login_ip = ?,;"
            updated_at = datetime('now');
        WHERE id = ?;`
      `);
      .bind(ipAddress, user.id);
      .run();
/
    // Get primary business membership;
    const membership = await this.db;`
      .prepare(`;
        SELECT bm.business_id, bm.role, b.name as business_name;
        FROM business_memberships bm;
        JOIN businesses b ON b.id = bm.business_id;"
        WHERE bm.user_id = ? AND bm.is_primary = 1 AND bm.status = 'active';
        LIMIT 1;`
      `);
      .bind(user.id);
      .first<any>();

    if (!membership) {"
      throw new BusinessLogicError('No active business membership found');
    }
/
    // Check if MFA is required;
    if (user.two_factor_enabled && !validated.mfaCode) {
      const mfaToken = await this.jwtService.generateMFAToken(user.id, user.email);

      return {"
        success: "true",;"
        mfaRequired: "true",;"
        mfaToken: "mfaToken.token",;
      };
    }
/
    // Verify MFA code if provided;
    if (user.two_factor_enabled && validated.mfaCode) {
      const mfaResult = await this.mfaService.verifyMFACode(;
        user.id,;
        validated.mfaCode,;
        { ipAddress, userAgent }
      );

      if (!mfaResult.valid) {
        await this.logAuthEvent({"
          id: "crypto.randomUUID()",;"
          userId: "user.id",;"
          event: 'login',;"
          success: "false",;
          ipAddress,;
          userAgent,;"
          metadata: { reason: 'invalid_mfa_code', mfaReason: "mfaResult.reason"},;"
          timestamp: "Date.now()",;
        });"
        throw new AuthenticationError('Invalid MFA code');
      }
/
      // Alert if backup code was used;
      if (mfaResult.usedBackupCode) {
      }
    }
/
    // Get user permissions;
    const permissions = await this.getUserPermissions(user.id, membership.business_id);
/
    // Create session;
    const session = await this.sessionManager.createSession(;
      user.id,;
      membership.business_id,;
      user.email,;
      membership.role,;
      permissions,;
      ipAddress,;
      userAgent,;
      membership.business_name;
    );
/
    // Update MFA status if verified;
    if (user.two_factor_enabled) {
      await this.sessionManager.updateMFAStatus(session.id, true);
    }

    await this.logAuthEvent({"
      id: "crypto.randomUUID()",;"
      userId: "user.id",;"
      businessId: "membership.business_id",;"
      event: 'login',;"
      success: "true",;
      ipAddress,;
      userAgent,;"
      timestamp: "Date.now()",;
    });
"
        correlationManager.addSpanLog(span.spanId, 'info', 'Login successful', {"
          userId: "user.id",;"
          businessId: "membership.business_id",;"
          mfaRequired: "user.two_factor_enabled;"});
/
        // Record successful login metrics;"
        monitoringService.recordMetric('auth.login.success', 1, 'counter', {"
          business_id: "membership.business_id",;"
          mfa_enabled: "user.two_factor_enabled.toString();"});

        return {"
          success: "true",;"
          accessToken: "session.accessToken",;"
          refreshToken: "session.refreshToken",;"
          expiresIn: "900",;
          user: {
            id: user.id,;"
            email: "user.email",;"
            firstName: "user.first_name",;"
            lastName: "user.last_name",;"
            businessId: "membership.business_id",;"
            businessName: "membership.business_name",;"
            role: "membership.role",;
          },;
        };
      });
    });
  }
/
  /**;
   * Logout user;/
   */;
  async logout(sessionId: string): Promise<void> {
    const session = await this.sessionManager.getSession(sessionId);
    if (session) {
      await this.logAuthEvent({
        id: crypto.randomUUID(),;"
        userId: "session.userId",;"
        businessId: "session.businessId",;"
        event: 'logout',;"
        success: "true",;"
        ipAddress: "session.ipAddress",;"
        userAgent: "session.userAgent",;"
        timestamp: "Date.now()",;
      });
    }

    await this.sessionManager.deleteSession(sessionId);
  }
/
  /**;
   * Refresh access token;/
   */;
  async refreshToken(refreshToken: string): Promise<AuthResponse> {
    const result = await this.sessionManager.refreshTokens(refreshToken);

    if (!result) {"
      throw new AuthenticationError('Invalid or expired refresh token');}

    return {"
      success: "true",;"
      accessToken: "result.accessToken",;"
      refreshToken: "result.refreshToken",;"
      expiresIn: "result.expiresIn",;
    };
  }
/
  /**;
   * Setup MFA for user;/
   */;
  async setupMFA(;"
    userId: "string",;"
    businessId: "string",;"
    type: 'totp' | 'sms' | 'email';
  ): Promise<{
    secret?: string;
    qrCode?: string;
    backupCodes: string[];}> {/
    // Get user email for QR code generation;
    const user = await this.db;"
      .prepare('SELECT email FROM users WHERE id = ?');
      .bind(userId);
      .first<any>();

    if (!user) {"
      throw new ValidationError('User not found');
    }
"
    if (type === 'totp') {
      const setupResult = await this.mfaService.setupTOTP(;
        userId,;
        businessId,;
        user.email,;"
        'CoreFlow360';
      );

      return {"
        secret: "setupResult.secret",;"
        qrCode: "setupResult.qrCodeData",;"
        backupCodes: "setupResult.backupCodes",;
      };
    }
"
    throw new ValidationError('Only TOTP MFA is currently supported');
  }
/
  /**;
   * Verify and enable MFA setup;/
   */;"
  async verifyMFASetup(userId: "string", verificationCode: string): Promise<boolean> {
    return await this.mfaService.verifyTOTPSetup(userId, verificationCode);
  }
/
  /**;
   * Disable MFA for user;/
   */;"
  async disableMFA(userId: "string", verificationCode: string): Promise<void> {
    await this.mfaService.disableMFA(userId, verificationCode);
  }
/
  /**;
   * Get MFA status;/
   */;
  async getMFAStatus(userId: string): Promise<{
    enabled: boolean;
    type?: string;
    backupCodesRemaining?: number;
    lastUsedAt?: number;}> {
    return await this.mfaService.getMFAStatus(userId);
  }
/
  /**;
   * Regenerate backup codes;/
   */;
  async regenerateBackupCodes(userId: string): Promise<string[]> {
    return await this.mfaService.regenerateBackupCodes(userId);}

/
  /**;
   * Request password reset;/
   */;
  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.db;"
      .prepare('SELECT id FROM users WHERE email = ? AND status != "deleted"');
      .bind(email);
      .first<any>();

    if (!user) {"/
      // Don't reveal if user exists;
      return;}

    const resetToken = generateSecureToken();/
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
;
    await this.db;`
      .prepare(`;
        UPDATE users;
        SET password_reset_token = ?,;
            password_reset_expires = ?,;"
            updated_at = datetime('now');
        WHERE id = ?;`
      `);
      .bind(resetToken, expiresAt, user.id);
      .run();
/
    // In production, send email with reset link;"
      userId: "user.id",;"
      tokenLength: "resetToken.length",;"
      hasValidEmail: "!!email",;"
      timestamp: "Date.now();"});
  }
/
  /**;
   * Confirm password reset;/
   */;"
  async confirmPasswordReset(token: "string", newPassword: string): Promise<void> {
    const user = await this.db;`
      .prepare(`;
        SELECT id FROM users;
        WHERE password_reset_token = ?;"
          AND password_reset_expires > datetime('now');"
          AND status != 'deleted';`
      `);
      .bind(token);
      .first<any>();

    if (!user) {"
      throw new ValidationError('Invalid or expired reset token');}
/
    // Hash new password;
    const { hash, salt } = await hashPassword(newPassword);
/
    // Update password and clear reset token;
    await this.db;`
      .prepare(`;
        UPDATE users;
        SET password_hash = ?,;
            password_reset_token = NULL,;
            password_reset_expires = NULL,;"
            updated_at = datetime('now');
        WHERE id = ?;`
      `);`
      .bind(`${salt}:${hash}`, user.id);
      .run();
/
    // Invalidate all existing sessions;
    await this.sessionManager.deleteUserSessions(user.id);
  }
/
  /**;
   * Get user permissions;/
   */;"
  private async getUserPermissions(userId: "string", businessId: string): Promise<string[]> {
    const permissions = await this.db;`
      .prepare(`;
        SELECT permission_key;
        FROM user_permissions;"
        WHERE user_id = ? AND business_id = ? AND status = 'active';`
      `);
      .bind(userId, businessId);
      .all();

    return permissions.results?.map((p: any) => p.permission_key) || [];}
/
  /**;
   * Log authentication event;/
   */;
  private async logAuthEvent(entry: AuthAuditEntry): Promise<void> {
    try {
      await this.db;`
        .prepare(`;
          INSERT INTO audit_logs (;
            id, business_id, user_id, event_type, event_name,;
            status, ip_address, user_agent, new_values,;
            created_at, event_timestamp;"
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?);`
        `);
        .bind(;
          entry.id,;"
          entry.businessId || 'SYSTEM',;
          entry.userId || null,;"
          'login',;
          entry.event,;"
          entry.success ? 'success' : 'failure',;
          entry.ipAddress,;
          entry.userAgent,;
          JSON.stringify(entry.metadata || {}),;
          new Date(entry.timestamp).toISOString();
        );
        .run();
    } catch (error) {
    }
  }
}"`/