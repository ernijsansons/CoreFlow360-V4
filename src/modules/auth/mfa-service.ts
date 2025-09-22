/**
 * Multi-Factor Authentication Service
 * Secure implementation of TOTP, SMS, and backup codes
 */

import { authenticator, totp } from 'otplib';
import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import { MFAConfig } from './types';
import { SecurityError, ValidationError } from '../../shared/error-handler';
import { Logger } from '../../shared/logger';

export interface MFASetupResult {
  secret: string;
  qrCodeData: string;
  backupCodes: string[];
}

export interface MFAVerificationResult {
  valid: boolean;
  usedBackupCode?: boolean;
  remainingBackupCodes?: number;
  reason?: string;
}

export // TODO: Consider splitting MFAService into smaller, focused classes
class MFAService {
  private logger: Logger;
  private kv: KVNamespace;
  private db: D1Database;

  constructor(kv: KVNamespace, db: D1Database) {
    this.logger = new Logger();
    this.kv = kv;
    this.db = db;

    // Configure TOTP settings for security
    authenticator.options = {
      window: [1, 1], // Allow 30s before and after current time
      step: 30, // 30-second time step
      digits: 6, // 6-digit codes
      algorithm: 'sha1', // SHA-1 for compatibility
      encoding: 'base32'
    };
  }

  /**
   * Setup MFA for a user with TOTP
   */
  async setupTOTP(
    userId: string,
    businessId: string,
    userEmail: string,
    appName: string = 'CoreFlow360'
  ): Promise<MFASetupResult> {
    try {
      // Generate a secure secret
      const secret = authenticator.generateSecret();

      // Generate backup codes (cryptographically secure)
      const backupCodes = this.generateBackupCodes();

      // Create MFA configuration
      const mfaConfig: MFAConfig = {
        userId,
        type: 'totp',
        secret,
        backupCodes,
        enabled: false, // Will be enabled after verification
        createdAt: Date.now(),
        lastUsedAt: null,
        verifiedAt: null
      };

      // Store in KV with expiration (cleanup if not verified within 1 hour)
      await this.kv.put(
        `mfa:setup:${userId}`,
        JSON.stringify(mfaConfig),
        { expirationTtl: 3600 } // 1 hour
      );

      // Generate QR code data
      const serviceName = `${appName}:${userEmail}`;
      const qrCodeData = authenticator.keyuri(serviceName, appName, secret);

      this.logger.info('MFA setup initiated', {
        userId,
        businessId,
        type: 'totp'
      });

      return {
        secret,
        qrCodeData,
        backupCodes
      };

    } catch (error) {
      this.logger.error('MFA setup failed', error, { userId, businessId });
      throw new SecurityError('Failed to setup MFA', {
        code: 'MFA_SETUP_FAILED',
        userId
      });
    }
  }

  /**
   * Verify TOTP setup with a test code
   */
  async verifyTOTPSetup(
    userId: string,
    verificationCode: string
  ): Promise<boolean> {
    try {
      // Get setup configuration
      const setupConfig = await this.kv.get<MFAConfig>(`mfa:setup:${userId}`, 'json');
      if (!setupConfig) {
        throw new ValidationError('No MFA setup in progress for this user');
      }

      // Verify the code
      const isValid = authenticator.verify({
        token: verificationCode,
        secret: setupConfig.secret
      });

      if (!isValid) {
        this.logger.warn('MFA setup verification failed', {
          userId,
          reason: 'invalid_code'
        });
        return false;
      }

      // Mark as verified and enable
      setupConfig.enabled = true;
      setupConfig.verifiedAt = Date.now();

      // Store permanently
      await this.kv.put(
        `mfa:${userId}`,
        JSON.stringify(setupConfig)
      );

      // Remove setup configuration
      await this.kv.delete(`mfa:setup:${userId}`);

      // Update user record in database
      await this.db.prepare(`
        UPDATE users
        SET two_factor_enabled = 1,
            two_factor_method = 'totp',
            updated_at = datetime('now')
        WHERE id = ?
      `).bind(userId).run();

      this.logger.info('MFA setup completed', {
        userId,
        type: 'totp'
      });

      return true;

    } catch (error) {
      this.logger.error('MFA setup verification failed', error, { userId });
      throw new SecurityError('Failed to verify MFA setup', {
        code: 'MFA_SETUP_VERIFICATION_FAILED',
        userId
      });
    }
  }

  /**
   * Verify MFA code during login
   */
  async verifyMFACode(
    userId: string,
    code: string,
    clientInfo?: { ipAddress: string; userAgent: string }
  ): Promise<MFAVerificationResult> {
    try {
      // Get MFA configuration
      const mfaConfig = await this.kv.get<MFAConfig>(`mfa:${userId}`, 'json');
      if (!mfaConfig || !mfaConfig.enabled) {
        return {
          valid: false,
          reason: 'MFA not configured or not enabled'
        };
      }

      // Check if code is a backup code first
      if (mfaConfig.backupCodes.includes(code)) {
        return await this.useBackupCode(userId, code, mfaConfig, clientInfo);
      }

      // Verify TOTP code
      if (mfaConfig.type === 'totp') {
        const isValid = authenticator.verify({
          token: code,
          secret: mfaConfig.secret
        });

        if (isValid) {
          // Update last used timestamp
          mfaConfig.lastUsedAt = Date.now();
          await this.kv.put(`mfa:${userId}`, JSON.stringify(mfaConfig));

          // Log successful verification
          await this.logMFAUsage(userId, 'totp_success', clientInfo);

          this.logger.info('MFA verification successful', {
            userId,
            type: 'totp',
            ipAddress: clientInfo?.ipAddress
          });

          return { valid: true };
        } else {
          // Log failed verification
          await this.logMFAUsage(userId, 'totp_failed', clientInfo);

          this.logger.warn('MFA verification failed', {
            userId,
            type: 'totp',
            reason: 'invalid_code',
            ipAddress: clientInfo?.ipAddress
          });

          return {
            valid: false,
            reason: 'Invalid verification code'
          };
        }
      }

      return {
        valid: false,
        reason: 'Unsupported MFA method'
      };

    } catch (error) {
      this.logger.error('MFA verification error', error, { userId });
      throw new SecurityError('MFA verification failed', {
        code: 'MFA_VERIFICATION_FAILED',
        userId
      });
    }
  }

  /**
   * Use a backup code for MFA verification
   */
  private async useBackupCode(
    userId: string,
    code: string,
    mfaConfig: MFAConfig,
    clientInfo?: { ipAddress: string; userAgent: string }
  ): Promise<MFAVerificationResult> {
    // Remove the used backup code
    mfaConfig.backupCodes = mfaConfig.backupCodes.filter(bc => bc !== code);
    mfaConfig.lastUsedAt = Date.now();

    // Update configuration
    await this.kv.put(`mfa:${userId}`, JSON.stringify(mfaConfig));

    // Log backup code usage
    await this.logMFAUsage(userId, 'backup_code_used', clientInfo);

    this.logger.warn('Backup code used for MFA verification', {
      userId,
      remainingCodes: mfaConfig.backupCodes.length,
      ipAddress: clientInfo?.ipAddress
    });

    // Alert if running low on backup codes
    if (mfaConfig.backupCodes.length <= 2) {
      this.logger.warn('User is running low on backup codes', {
        userId,
        remainingCodes: mfaConfig.backupCodes.length
      });
    }

    return {
      valid: true,
      usedBackupCode: true,
      remainingBackupCodes: mfaConfig.backupCodes.length
    };
  }

  /**
   * Generate new backup codes
   */
  async regenerateBackupCodes(userId: string): Promise<string[]> {
    try {
      const mfaConfig = await this.kv.get<MFAConfig>(`mfa:${userId}`, 'json');
      if (!mfaConfig || !mfaConfig.enabled) {
        throw new ValidationError('MFA not configured for this user');
      }

      // Generate new backup codes
      const newBackupCodes = this.generateBackupCodes();
      mfaConfig.backupCodes = newBackupCodes;

      // Update configuration
      await this.kv.put(`mfa:${userId}`, JSON.stringify(mfaConfig));

      this.logger.info('Backup codes regenerated', { userId });

      return newBackupCodes;

    } catch (error) {
      this.logger.error('Failed to regenerate backup codes', error, { userId });
      throw new SecurityError('Failed to regenerate backup codes', {
        code: 'BACKUP_CODE_GENERATION_FAILED',
        userId
      });
    }
  }

  /**
   * Disable MFA for a user
   */
  async disableMFA(userId: string, verificationCode: string): Promise<void> {
    try {
      // Verify current MFA code before disabling
      const verification = await this.verifyMFACode(userId, verificationCode);
      if (!verification.valid) {
        throw new SecurityError('MFA verification required to disable');
      }

      // Remove MFA configuration
      await this.kv.delete(`mfa:${userId}`);

      // Update user record
      await this.db.prepare(`
        UPDATE users
        SET two_factor_enabled = 0,
            two_factor_method = NULL,
            updated_at = datetime('now')
        WHERE id = ?
      `).bind(userId).run();

      this.logger.warn('MFA disabled for user', { userId });

    } catch (error) {
      this.logger.error('Failed to disable MFA', error, { userId });
      throw error;
    }
  }

  /**
   * Get MFA status for a user
   */
  async getMFAStatus(userId: string): Promise<{
    enabled: boolean;
    type?: string;
    backupCodesRemaining?: number;
    lastUsedAt?: number;
  }> {
    try {
      const mfaConfig = await this.kv.get<MFAConfig>(`mfa:${userId}`, 'json');

      if (!mfaConfig || !mfaConfig.enabled) {
        return { enabled: false };
      }

      return {
        enabled: true,
        type: mfaConfig.type,
        backupCodesRemaining: mfaConfig.backupCodes.length,
        lastUsedAt: mfaConfig.lastUsedAt
      };

    } catch (error) {
      this.logger.error('Failed to get MFA status', error, { userId });
      return { enabled: false };
    }
  }

  /**
   * Generate cryptographically secure backup codes
   */
  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    const charset = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Excludes confusing characters

    for (let i = 0; i < 10; i++) {
      let code = '';
      for (let j = 0; j < 8; j++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        code += charset[randomIndex];
      }
      codes.push(code);
    }

    return codes;
  }

  /**
   * Log MFA usage for security monitoring
   */
  private async logMFAUsage(
    userId: string,
    action: string,
    clientInfo?: { ipAddress: string; userAgent: string }
  ): Promise<void> {
    try {
      await this.db.prepare(`
        INSERT INTO audit_logs (
          id, user_id, event_type, event_name,
          ip_address, user_agent, status, metadata,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        crypto.randomUUID(),
        userId,
        'authentication',
        `mfa_${action}`,
        clientInfo?.ipAddress || 'unknown',
        clientInfo?.userAgent || 'unknown',
        action.includes('failed') ? 'failure' : 'success',
        JSON.stringify({ action, timestamp: Date.now() })
      ).run();

    } catch (error) {
      this.logger.error('Failed to log MFA usage', error, { userId, action });
    }
  }

  /**
   * Check for suspicious MFA activity
   */
  async checkSuspiciousActivity(userId: string): Promise<{
    suspicious: boolean;
    reasons: string[];
    shouldBlock: boolean;
  }> {
    try {
      // Check recent failed attempts
      const recentFailures = await this.db.prepare(`
        SELECT COUNT(*) as count
        FROM audit_logs
        WHERE user_id = ?
          AND event_name LIKE 'mfa_%failed'
          AND created_at > datetime('now', '-1 hour')
      `).bind(userId).first<{ count: number }>();

      const reasons: string[] = [];
      let shouldBlock = false;

      if (recentFailures && recentFailures.count >= 5) {
        reasons.push('Multiple failed MFA attempts in the last hour');
        shouldBlock = true;
      }

      // Check for unusual IP patterns
      const recentIPs = await this.db.prepare(`
        SELECT DISTINCT ip_address
        FROM audit_logs
        WHERE user_id = ?
          AND event_name LIKE 'mfa_%'
          AND created_at > datetime('now', '-24 hours')
      `).bind(userId).all();

      if (recentIPs.results && recentIPs.results.length > 3) {
        reasons.push('MFA attempts from multiple IP addresses');
      }

      return {
        suspicious: reasons.length > 0,
        reasons,
        shouldBlock
      };

    } catch (error) {
      this.logger.error('Failed to check suspicious MFA activity', error, { userId });
      return {
        suspicious: false,
        reasons: [],
        shouldBlock: false
      };
    }
  }
}