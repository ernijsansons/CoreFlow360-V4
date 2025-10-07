import type { Env } from '../../types/env';
import {
  type RegisterRequest,
  type LoginRequest,
  type AuthResponse,
  type MFAConfig,
  type AuthAuditEntry,
  type TokenClaims,
  RegisterRequestSchema,
  LoginRequestSchema,
  PasswordResetRequestSchema,
  PasswordResetConfirmSchema,
} from './types';
import { hashPassword, verifyPassword, generateSecureToken } from './crypto';
import { JWTService } from './jwt';
import { SessionManager } from './session';
import { MFAService } from './mfa-service';
import { AuthenticationError, ValidationError, ConflictError } from '../../shared/error-handler';
import { withTracing } from '../../shared/correlation-id';
import { Logger } from '../../shared/logger';

// Database row types
interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  password_salt: string;
  first_name: string;
  last_name: string;
  phone?: string;
  business_id: string;
  created_at: string;
  updated_at: string;
  business_name?: string;
  business_domain?: string;
}

// Extended RegisterRequest with optional fields
interface ExtendedRegisterRequest extends RegisterRequest {
  id?: string;
  phone?: string;
  businessDomain?: string;
  industry?: string;
  sizeRange?: string;
}

export // TODO: Consider splitting AuthService into smaller, focused classes
class AuthService {
  private db: D1Database;
  private kv: KVNamespace;
  private jwtService: JWTService;
  private sessionManager: SessionManager;
  private mfaService: MFAService;
  private logger: Logger;

  constructor(env: Env) {
    this.logger = new Logger();

    // Validate required environment variables
    if (!env.JWT_SECRET) {
      throw new AuthenticationError('JWT_SECRET environment variable is required');
    }

    this.db = env.DB_MAIN;
    this.kv = env.KV_SESSION;
    this.jwtService = new JWTService(env.JWT_SECRET);
    this.sessionManager = new SessionManager(this.kv as any, this.jwtService);
    this.mfaService = new MFAService(this.kv as any, this.db);
  }

  /**
   * Register a new user and business
   */
  async register(
    data: RegisterRequest | ExtendedRegisterRequest,
    ipAddress: string,
    userAgent: string
  ): Promise<AuthResponse> {
    const correlationId = crypto.randomUUID();

    return withTracing('auth.register', correlationId, async () => {
      try {
        // Validate input
        const validatedData = RegisterRequestSchema.parse(data) as RegisterRequest;
        const extendedData = data as ExtendedRegisterRequest;

        // Check if user already exists
        const existingUser = await this.db.prepare(`
          SELECT id FROM users WHERE email = ?
        `).bind(validatedData.email).first<{ id: string }>();

        if (existingUser) {
          throw new ConflictError('User with this email already exists');
        }

        // Hash password
        const { hash: hashedPassword, salt: passwordSalt } = await hashPassword(validatedData.password);

        // Generate IDs
        const userId = extendedData.id || `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const businessId = `biz_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const sessionId = JWTService.generateSessionId();

        // Create user and business in transaction
        await this.db.batch([
          this.db.prepare(`
            INSERT INTO users (
              id, email, password_hash, password_salt, first_name, last_name,
              phone, business_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            userId,
            validatedData.email,
            hashedPassword,
            passwordSalt,
            validatedData.firstName,
            validatedData.lastName,
            extendedData.phone || null,
            businessId,
            new Date().toISOString(),
            new Date().toISOString()
          ),
          this.db.prepare(`
            INSERT INTO businesses (
              id, name, domain, industry, size_range,
              created_at, updated_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            businessId,
            validatedData.businessName || 'My Business',
            extendedData.businessDomain || null,
            extendedData.industry || null,
            extendedData.sizeRange || null,
            new Date().toISOString(),
            new Date().toISOString(),
            userId
          )
        ]);

        // Generate JWT tokens
        const accessTokenResult = await this.jwtService.generateAccessToken({
          sub: userId,
          email: validatedData.email,
          businessId,
          businessName: validatedData.businessName || 'My Business',
          role: 'owner',
          permissions: ['*'],
          sessionId,
          ipAddress,
        });

        const refreshTokenResult = await this.jwtService.generateRefreshToken(userId, sessionId);

        // Create session
        await this.sessionManager.createSession(
          userId,
          businessId,
          validatedData.email,
          'owner',
          ['*'],
          ipAddress,
          userAgent,
          validatedData.businessName || 'My Business'
        );

        // Log audit entry
        await this.logAuthEvent({
          id: crypto.randomUUID(),
          userId,
          businessId,
          event: 'register',
          ipAddress,
          userAgent,
          success: true,
          timestamp: Date.now(),
        });

        return {
          success: true,
          accessToken: accessTokenResult.token,
          refreshToken: refreshTokenResult.token,
          expiresIn: accessTokenResult.expiresIn,
          user: {
            id: userId,
            email: validatedData.email,
            firstName: validatedData.firstName,
            lastName: validatedData.lastName,
            businessId,
            businessName: validatedData.businessName || 'My Business',
            role: 'owner',
          }
        };

      } catch (error: any) {
        this.logger.error('Registration failed', { error: error.message, email: data.email });

        // Log audit entry
        await this.logAuthEvent({
          id: crypto.randomUUID(),
          userId: undefined,
          businessId: undefined,
          event: 'register',
          ipAddress,
          userAgent,
          success: false,
          timestamp: Date.now(),
          metadata: { error: error.message },
        });

        throw error;
      }
    });
  }

  /**
   * Login user
   */
  async login(
    data: LoginRequest,
    ipAddress: string,
    userAgent: string
  ): Promise<AuthResponse> {
    const correlationId = crypto.randomUUID();

    return withTracing('auth.login', correlationId, async () => {
      try {
        // Validate input
        const validatedData = LoginRequestSchema.parse(data);

        // Get user from database
        const user = await this.db.prepare(`
          SELECT u.*, b.name as business_name, b.domain as business_domain
          FROM users u
          LEFT JOIN businesses b ON u.business_id = b.id
          WHERE u.email = ?
        `).bind(validatedData.email).first<UserRow>();

        if (!user) {
          throw new AuthenticationError('Invalid email or password');
        }

        // Verify password
        const isValidPassword = await verifyPassword(validatedData.password, user.password_hash, user.password_salt);
        if (!isValidPassword) {
          throw new AuthenticationError('Invalid email or password');
        }

        // Check if MFA is required
        const mfaStatus = await this.mfaService.getMFAStatus(user.id);
        if (mfaStatus.enabled) {
          // Generate MFA token for temporary authentication
          const mfaToken = await this.jwtService.generateMFAToken(user.id, user.email);

          return {
            success: true,
            requiresMFA: true,
            mfaToken: mfaToken.token,
            user: {
              id: user.id,
              email: user.email,
              firstName: user.first_name,
              lastName: user.last_name,
              businessId: user.business_id,
              businessName: user.business_name || '',
              role: 'owner',
            }
          };
        }

        // Generate session ID
        const sessionId = JWTService.generateSessionId();

        // Generate JWT tokens
        const accessTokenResult = await this.jwtService.generateAccessToken({
          sub: user.id,
          businessId: user.business_id,
          email: user.email,
          businessName: user.business_name || '',
          role: 'owner',
          permissions: ['*'],
          sessionId,
          ipAddress,
        });

        const refreshTokenResult = await this.jwtService.generateRefreshToken(user.id, sessionId);

        // Create session
        await this.sessionManager.createSession(
          user.id,
          user.business_id,
          user.email,
          'owner',
          ['*'],
          ipAddress,
          userAgent,
          user.business_name || ''
        );

        // Log audit entry
        await this.logAuthEvent({
          id: crypto.randomUUID(),
          userId: user.id,
          businessId: user.business_id,
          event: 'login',
          ipAddress,
          userAgent,
          success: true,
          timestamp: Date.now(),
        });

        return {
          success: true,
          accessToken: accessTokenResult.token,
          refreshToken: refreshTokenResult.token,
          expiresIn: accessTokenResult.expiresIn,
          user: {
            id: user.id,
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name,
            businessId: user.business_id,
            businessName: user.business_name || '',
            role: 'owner',
          }
        };

      } catch (error: any) {
        this.logger.error('Login failed', { error: error.message, email: data.email });

        // Log audit entry
        await this.logAuthEvent({
          id: crypto.randomUUID(),
          userId: undefined,
          businessId: undefined,
          event: 'login',
          ipAddress,
          userAgent,
          success: false,
          timestamp: Date.now(),
          metadata: { error: error.message },
        });

        throw error;
      }
    });
  }

  /**
   * Verify MFA and complete login
   */
  async verifyMFA(
    mfaToken: string,
    code: string,
    ipAddress: string,
    userAgent: string
  ): Promise<AuthResponse> {
    const correlationId = crypto.randomUUID();

    return withTracing('auth.verifyMFA', correlationId, async () => {
      try {
        // Verify MFA token
        const tokenPayload = await this.jwtService.verifyToken(mfaToken, 'mfa');

        // Verify MFA code
        const verification = await this.mfaService.verifyMFACode(
          tokenPayload.sub,
          code,
          { ipAddress, userAgent }
        );

        if (!verification.valid) {
          throw new AuthenticationError(verification.reason || 'Invalid MFA code');
        }

        // Get user from database
        const user = await this.db.prepare(`
          SELECT u.*, b.name as business_name
          FROM users u
          LEFT JOIN businesses b ON u.business_id = b.id
          WHERE u.id = ?
        `).bind(tokenPayload.sub).first<UserRow>();

        if (!user) {
          throw new AuthenticationError('User not found');
        }

        // Generate session ID
        const sessionId = JWTService.generateSessionId();

        // Generate JWT tokens
        const accessTokenResult = await this.jwtService.generateAccessToken({
          sub: user.id,
          businessId: user.business_id,
          email: user.email,
          businessName: user.business_name || '',
          role: 'owner',
          permissions: ['*'],
          sessionId,
          ipAddress,
        });

        const refreshTokenResult = await this.jwtService.generateRefreshToken(user.id, sessionId);

        // Create session with MFA verified
        await this.sessionManager.createSession(
          user.id,
          user.business_id,
          user.email,
          'owner',
          ['*'],
          ipAddress,
          userAgent,
          user.business_name || ''
        );

        // Log audit entry
        await this.logAuthEvent({
          id: crypto.randomUUID(),
          userId: user.id,
          businessId: user.business_id,
          event: 'login',
          ipAddress,
          userAgent,
          success: true,
          timestamp: Date.now(),
          metadata: { mfaVerified: true, usedBackupCode: verification.usedBackupCode },
        });

        return {
          success: true,
          accessToken: accessTokenResult.token,
          refreshToken: refreshTokenResult.token,
          expiresIn: accessTokenResult.expiresIn,
          user: {
            id: user.id,
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name,
            businessId: user.business_id,
            businessName: user.business_name || '',
            role: 'owner',
          }
        };

      } catch (error: any) {
        this.logger.error('MFA verification failed', { error: error.message });

        // Log audit entry
        await this.logAuthEvent({
          id: crypto.randomUUID(),
          userId: undefined,
          businessId: undefined,
          event: 'login',
          ipAddress,
          userAgent,
          success: false,
          timestamp: Date.now(),
          metadata: { error: error.message, mfaFailed: true },
        });

        throw error;
      }
    });
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }> {
    const correlationId = crypto.randomUUID();

    return withTracing('auth.refreshToken', correlationId, async () => {
      try {
        // Use SessionManager's refresh method which handles all verification
        const result = await this.sessionManager.refreshTokens(refreshToken);

        if (!result) {
          throw new AuthenticationError('Invalid refresh token');
        }

        return result;

      } catch (error: any) {
        this.logger.error('Token refresh failed', { error: error.message });
        throw new AuthenticationError('Invalid refresh token');
      }
    });
  }

  /**
   * Logout user
   */
  async logout(refreshToken: string, ipAddress: string, userAgent: string): Promise<void> {
    const correlationId = crypto.randomUUID();

    return withTracing('auth.logout', correlationId, async () => {
      try {
        // Verify refresh token to get user info
        const payload = await this.jwtService.verifyToken(refreshToken, 'refresh');

        // Get session ID from token
        const sessionId = (payload as any).sessionId as string;

        // Delete session
        if (sessionId) {
          await this.sessionManager.deleteSession(sessionId);
        }

        // Log audit entry
        await this.logAuthEvent({
          id: crypto.randomUUID(),
          userId: payload.sub,
          businessId: (payload as any).businessId,
          event: 'logout',
          ipAddress,
          userAgent,
          success: true,
          timestamp: Date.now(),
        });

      } catch (error: any) {
        this.logger.error('Logout failed', { error: error.message });
        // Don't throw error for logout failures
      }
    });
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(email: string, ipAddress: string, userAgent: string): Promise<void> {
    const correlationId = crypto.randomUUID();

    return withTracing('auth.requestPasswordReset', correlationId, async () => {
      try {
        // Get user from database
        const user = await this.db.prepare(`
          SELECT id, email FROM users WHERE email = ?
        `).bind(email).first<{ id: string; email: string }>();

        if (!user) {
          // Don't reveal if user exists or not
          return;
        }

        // Generate reset token
        const resetToken = generateSecureToken(32);
        const expiresAt = new Date(Date.now() + 3600000); // 1 hour

        // Store reset token
        await this.kv.put(
          `password_reset:${resetToken}`,
          JSON.stringify({
            userId: user.id,
            email: user.email,
            expiresAt: expiresAt.toISOString()
          }),
          { expirationTtl: 3600 }
        );

        // TODO: Send email with reset link
        // await this.emailService.sendPasswordResetEmail(user.email, resetToken);

        // Log audit entry
        await this.logAuthEvent({
          id: crypto.randomUUID(),
          userId: user.id,
          businessId: undefined,
          event: 'password_reset',
          ipAddress,
          userAgent,
          success: true,
          timestamp: Date.now(),
        });

      } catch (error: any) {
        this.logger.error('Password reset request failed', { error: error.message, email });
        throw error;
      }
    });
  }

  /**
   * Confirm password reset
   */
  async confirmPasswordReset(
    token: string,
    newPassword: string,
    ipAddress: string,
    userAgent: string
  ): Promise<void> {
    const correlationId = crypto.randomUUID();

    return withTracing('auth.confirmPasswordReset', correlationId, async () => {
      try {
        // Get reset token from KV
        const resetData = await this.kv.get(`password_reset:${token}`);
        if (!resetData) {
          throw new AuthenticationError('Invalid or expired reset token');
        }

        const { userId, email, expiresAt } = JSON.parse(resetData);

        // Check if token is expired
        if (new Date(expiresAt) < new Date()) {
          throw new AuthenticationError('Reset token has expired');
        }

        // Hash new password
        const { hash: hashedPassword, salt: passwordSalt } = await hashPassword(newPassword);

        // Update user password
        await this.db.prepare(`
          UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ? WHERE id = ?
        `).bind(hashedPassword, passwordSalt, new Date().toISOString(), userId).run();

        // Delete reset token
        await this.kv.delete(`password_reset:${token}`);

        // Invalidate all user sessions
        await this.sessionManager.deleteUserSessions(userId);

        // Log audit entry
        await this.logAuthEvent({
          id: crypto.randomUUID(),
          userId,
          businessId: undefined,
          event: 'password_reset',
          ipAddress,
          userAgent,
          success: true,
          timestamp: Date.now(),
        });

      } catch (error: any) {
        this.logger.error('Password reset confirmation failed', { error: error.message });
        throw error;
      }
    });
  }

  /**
   * Get user profile
   */
  async getUserProfile(userId: string): Promise<any> {
    const correlationId = crypto.randomUUID();

    return withTracing('auth.getUserProfile', correlationId, async () => {
      try {
        const user = await this.db.prepare(`
          SELECT u.*, b.name as business_name, b.domain as business_domain
          FROM users u
          LEFT JOIN businesses b ON u.business_id = b.id
          WHERE u.id = ?
        `).bind(userId).first<UserRow>();

        if (!user) {
          throw new AuthenticationError('User not found');
        }

        return {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          phone: user.phone,
          businessId: user.business_id,
          businessName: user.business_name,
          businessDomain: user.business_domain,
          createdAt: user.created_at,
          updatedAt: user.updated_at
        };

      } catch (error: any) {
        this.logger.error('Get user profile failed', { error: error.message, userId });
        throw error;
      }
    });
  }

  /**
   * Update user profile
   */
  async updateUserProfile(userId: string, updates: any): Promise<any> {
    const correlationId = crypto.randomUUID();

    return withTracing('auth.updateUserProfile', correlationId, async () => {
      try {
        // Validate updates
        const allowedFields = ['first_name', 'last_name', 'phone'];
        const updateFields = Object.keys(updates).filter((key: any) => allowedFields.includes(key));

        if (updateFields.length === 0) {
          throw new ValidationError('No valid fields to update');
        }

        // Build update query
        const setClause = updateFields.map((field: any) => `${field} = ?`).join(', ');
        const values = updateFields.map((field: any) => updates[field]);
        values.push(new Date().toISOString(), userId);

        await this.db.prepare(`
          UPDATE users SET ${setClause}, updated_at = ? WHERE id = ?
        `).bind(...values).run();

        // Return updated profile
        return await this.getUserProfile(userId);

      } catch (error: any) {
        this.logger.error('Update user profile failed', { error: error.message, userId });
        throw error;
      }
    });
  }

  /**
   * Log authentication event
   */
  private async logAuthEvent(event: AuthAuditEntry): Promise<void> {
    try {
      await this.db.prepare(`
        INSERT INTO auth_audit_log (
          id, user_id, business_id, event, ip_address, user_agent,
          success, metadata, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        event.id,
        event.userId || null,
        event.businessId || null,
        event.event,
        event.ipAddress,
        event.userAgent,
        event.success ? 1 : 0,
        event.metadata ? JSON.stringify(event.metadata) : null,
        new Date(event.timestamp).toISOString()
      ).run();
    } catch (error: any) {
      this.logger.error('Failed to log auth event', { error: error.message });
    }
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      // Test database connection
      await this.db.prepare('SELECT 1').first();
      
      return {
        status: 'healthy',
        timestamp: new Date().toISOString()
      };
    } catch (error: any) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      };
    }
  }
}

