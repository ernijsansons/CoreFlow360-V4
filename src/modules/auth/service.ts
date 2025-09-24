import type { Env } from '../../types/env';
import {
  type RegisterRequest,
  type LoginRequest,
  type AuthResponse,
  type MFAConfig,
  type AuthAuditEntry,
  RegisterRequestSchema,
  LoginRequestSchema,
  PasswordResetRequestSchema,
  PasswordResetConfirmSchema,
} from './types';
import { hashPassword, verifyPassword, generateSecureToken, generateOTPCode, generateTOTPSecret } from './crypto';
import { JWTService } from './jwt';
import { SessionManager } from './session';
import { MFAService } from './mfa-service';
import { AuthenticationError, ValidationError, ConflictError, BusinessLogicError } from '../../shared/error-handler';
import { withTracing, correlationManager } from '../../shared/correlation-id';
import { monitoringService, withMonitoring } from '../../shared/monitoring-service';
import { Logger } from '../../shared/logger';

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
    this.sessionManager = new SessionManager(this.kv, this.jwtService);
    this.mfaService = new MFAService(this.kv, this.db);
  }

  /**
   * Register a new user and business
   */
  async register(
    data: RegisterRequest,
    ipAddress: string,
    userAgent: string
  ): Promise<AuthResponse> {
    return withTracing('auth.register', async () => {
      try {
        // Validate input
        const validatedData = RegisterRequestSchema.parse(data);

        // Check if user already exists
        const existingUser = await this.db.prepare(`
          SELECT id FROM users WHERE email = ?
        `).bind(validatedData.email).first();

        if (existingUser) {
          throw new ConflictError('User with this email already exists');
        }

        // Hash password
        const hashedPassword = await hashPassword(validatedData.password);

        // Generate business ID
        const businessId = `biz_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // Create user and business in transaction
        await this.db.batch([
          this.db.prepare(`
            INSERT INTO users (
              id, email, password_hash, first_name, last_name, 
              phone, business_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            validatedData.id || `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            validatedData.email,
            hashedPassword,
            validatedData.firstName,
            validatedData.lastName,
            validatedData.phone,
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
            validatedData.businessName,
            validatedData.businessDomain,
            validatedData.industry,
            validatedData.sizeRange,
            new Date().toISOString(),
            new Date().toISOString(),
            validatedData.id || `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
          )
        ]);

        // Generate JWT tokens
        const accessToken = await this.jwtService.generateAccessToken({
          userId: validatedData.id || `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          businessId,
          email: validatedData.email
        });

        const refreshToken = await this.jwtService.generateRefreshToken({
          userId: validatedData.id || `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          businessId
        });

        // Create session
        await this.sessionManager.createSession({
          userId: validatedData.id || `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          businessId,
          accessToken,
          refreshToken,
          ipAddress,
          userAgent
        });

        // Log audit entry
        await this.logAuthEvent({
          userId: validatedData.id || `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          businessId,
          action: 'register',
          ipAddress,
          userAgent,
          success: true
        });

        return {
          success: true,
          accessToken,
          refreshToken,
          user: {
            id: validatedData.id || `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            email: validatedData.email,
            firstName: validatedData.firstName,
            lastName: validatedData.lastName,
            businessId
          }
        };

      } catch (error) {
        this.logger.error('Registration failed', { error: error.message, email: data.email });
        
        // Log audit entry
        await this.logAuthEvent({
          userId: data.id,
          businessId: undefined,
          action: 'register',
          ipAddress,
          userAgent,
          success: false,
          error: error.message
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
    return withTracing('auth.login', async () => {
      try {
        // Validate input
        const validatedData = LoginRequestSchema.parse(data);

        // Get user from database
        const user = await this.db.prepare(`
          SELECT u.*, b.name as business_name, b.domain as business_domain
          FROM users u
          LEFT JOIN businesses b ON u.business_id = b.id
          WHERE u.email = ?
        `).bind(validatedData.email).first();

        if (!user) {
          throw new AuthenticationError('Invalid email or password');
        }

        // Verify password
        const isValidPassword = await verifyPassword(validatedData.password, user.password_hash);
        if (!isValidPassword) {
          throw new AuthenticationError('Invalid email or password');
        }

        // Check if MFA is required
        const mfaConfig = await this.mfaService.getMFAConfig(user.id);
        if (mfaConfig && mfaConfig.enabled) {
          // Generate MFA challenge
          const challenge = await this.mfaService.generateChallenge(user.id, mfaConfig.type);
          
          return {
            success: true,
            requiresMFA: true,
            mfaChallenge: challenge,
            user: {
              id: user.id,
              email: user.email,
              firstName: user.first_name,
              lastName: user.last_name,
              businessId: user.business_id
            }
          };
        }

        // Generate JWT tokens
        const accessToken = await this.jwtService.generateAccessToken({
          userId: user.id,
          businessId: user.business_id,
          email: user.email
        });

        const refreshToken = await this.jwtService.generateRefreshToken({
          userId: user.id,
          businessId: user.business_id
        });

        // Create session
        await this.sessionManager.createSession({
          userId: user.id,
          businessId: user.business_id,
          accessToken,
          refreshToken,
          ipAddress,
          userAgent
        });

        // Log audit entry
        await this.logAuthEvent({
          userId: user.id,
          businessId: user.business_id,
          action: 'login',
          ipAddress,
          userAgent,
          success: true
        });

        return {
          success: true,
          accessToken,
          refreshToken,
          user: {
            id: user.id,
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name,
            businessId: user.business_id
          }
        };

      } catch (error) {
        this.logger.error('Login failed', { error: error.message, email: data.email });
        
        // Log audit entry
        await this.logAuthEvent({
          userId: undefined,
          businessId: undefined,
          action: 'login',
          ipAddress,
          userAgent,
          success: false,
          error: error.message
        });

        throw error;
      }
    });
  }

  /**
   * Verify MFA and complete login
   */
  async verifyMFA(
    challengeId: string,
    code: string,
    ipAddress: string,
    userAgent: string
  ): Promise<AuthResponse> {
    return withTracing('auth.verifyMFA', async () => {
      try {
        // Verify MFA code
        const verification = await this.mfaService.verifyChallenge(challengeId, code);
        if (!verification.success) {
          throw new AuthenticationError('Invalid MFA code');
        }

        const user = verification.user;

        // Generate JWT tokens
        const accessToken = await this.jwtService.generateAccessToken({
          userId: user.id,
          businessId: user.business_id,
          email: user.email
        });

        const refreshToken = await this.jwtService.generateRefreshToken({
          userId: user.id,
          businessId: user.business_id
        });

        // Create session
        await this.sessionManager.createSession({
          userId: user.id,
          businessId: user.business_id,
          accessToken,
          refreshToken,
          ipAddress,
          userAgent
        });

        // Log audit entry
        await this.logAuthEvent({
          userId: user.id,
          businessId: user.business_id,
          action: 'mfa_verify',
          ipAddress,
          userAgent,
          success: true
        });

        return {
          success: true,
          accessToken,
          refreshToken,
          user: {
            id: user.id,
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name,
            businessId: user.business_id
          }
        };

      } catch (error) {
        this.logger.error('MFA verification failed', { error: error.message, challengeId });
        
        // Log audit entry
        await this.logAuthEvent({
          userId: undefined,
          businessId: undefined,
          action: 'mfa_verify',
          ipAddress,
          userAgent,
          success: false,
          error: error.message
        });

        throw error;
      }
    });
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
    return withTracing('auth.refreshToken', async () => {
      try {
        // Verify refresh token
        const payload = await this.jwtService.verifyRefreshToken(refreshToken);
        
        // Get user from database
        const user = await this.db.prepare(`
          SELECT id, email, business_id FROM users WHERE id = ?
        `).bind(payload.userId).first();

        if (!user) {
          throw new AuthenticationError('User not found');
        }

        // Generate new tokens
        const newAccessToken = await this.jwtService.generateAccessToken({
          userId: user.id,
          businessId: user.business_id,
          email: user.email
        });

        const newRefreshToken = await this.jwtService.generateRefreshToken({
          userId: user.id,
          businessId: user.business_id
        });

        // Update session
        await this.sessionManager.updateSession(refreshToken, {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken
        });

        return {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken
        };

      } catch (error) {
        this.logger.error('Token refresh failed', { error: error.message });
        throw new AuthenticationError('Invalid refresh token');
      }
    });
  }

  /**
   * Logout user
   */
  async logout(refreshToken: string, ipAddress: string, userAgent: string): Promise<void> {
    return withTracing('auth.logout', async () => {
      try {
        // Verify refresh token to get user info
        const payload = await this.jwtService.verifyRefreshToken(refreshToken);
        
        // Invalidate session
        await this.sessionManager.invalidateSession(refreshToken);

        // Log audit entry
        await this.logAuthEvent({
          userId: payload.userId,
          businessId: payload.businessId,
          action: 'logout',
          ipAddress,
          userAgent,
          success: true
        });

      } catch (error) {
        this.logger.error('Logout failed', { error: error.message });
        // Don't throw error for logout failures
      }
    });
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(email: string, ipAddress: string, userAgent: string): Promise<void> {
    return withTracing('auth.requestPasswordReset', async () => {
      try {
        // Get user from database
        const user = await this.db.prepare(`
          SELECT id, email FROM users WHERE email = ?
        `).bind(email).first();

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
          userId: user.id,
          businessId: undefined,
          action: 'password_reset_request',
          ipAddress,
          userAgent,
          success: true
        });

      } catch (error) {
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
    return withTracing('auth.confirmPasswordReset', async () => {
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
        const hashedPassword = await hashPassword(newPassword);

        // Update user password
        await this.db.prepare(`
          UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?
        `).bind(hashedPassword, new Date().toISOString(), userId).run();

        // Delete reset token
        await this.kv.delete(`password_reset:${token}`);

        // Invalidate all user sessions
        await this.sessionManager.invalidateAllUserSessions(userId);

        // Log audit entry
        await this.logAuthEvent({
          userId,
          businessId: undefined,
          action: 'password_reset_confirm',
          ipAddress,
          userAgent,
          success: true
        });

      } catch (error) {
        this.logger.error('Password reset confirmation failed', { error: error.message });
        throw error;
      }
    });
  }

  /**
   * Get user profile
   */
  async getUserProfile(userId: string): Promise<any> {
    return withTracing('auth.getUserProfile', async () => {
      try {
        const user = await this.db.prepare(`
          SELECT u.*, b.name as business_name, b.domain as business_domain
          FROM users u
          LEFT JOIN businesses b ON u.business_id = b.id
          WHERE u.id = ?
        `).bind(userId).first();

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

      } catch (error) {
        this.logger.error('Get user profile failed', { error: error.message, userId });
        throw error;
      }
    });
  }

  /**
   * Update user profile
   */
  async updateUserProfile(userId: string, updates: any): Promise<any> {
    return withTracing('auth.updateUserProfile', async () => {
      try {
        // Validate updates
        const allowedFields = ['first_name', 'last_name', 'phone'];
        const updateFields = Object.keys(updates).filter(key => allowedFields.includes(key));
        
        if (updateFields.length === 0) {
          throw new ValidationError('No valid fields to update');
        }

        // Build update query
        const setClause = updateFields.map(field => `${field} = ?`).join(', ');
        const values = updateFields.map(field => updates[field]);
        values.push(new Date().toISOString(), userId);

        await this.db.prepare(`
          UPDATE users SET ${setClause}, updated_at = ? WHERE id = ?
        `).bind(...values).run();

        // Return updated profile
        return await this.getUserProfile(userId);

      } catch (error) {
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
          id, user_id, business_id, action, ip_address, user_agent,
          success, error_message, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        event.userId,
        event.businessId,
        event.action,
        event.ipAddress,
        event.userAgent,
        event.success,
        event.error,
        new Date().toISOString()
      ).run();
    } catch (error) {
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
    } catch (error) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      };
    }
  }
}

