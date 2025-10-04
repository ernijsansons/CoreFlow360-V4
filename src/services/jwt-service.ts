/**
 * JWT Service with Automatic Secret Rotation
 * Fixes CVSS 8.1 vulnerability: JWT secret rotation
 *
 * Features:
 * - Daily automatic secret rotation
 * - Multiple secret support for rotation period
 * - Token generation with secure claims
 * - Token refresh mechanism
 * - Blacklist checking
 * - Constant-time verification
 */

import { jwtVerify, SignJWT, type JWTPayload } from 'jose';

export interface JWTClaims extends JWTPayload {
  sub: string; // user ID
  email: string;
  businessId: string;
  roles: string[];
  permissions: string[];
  iat: number;
  exp: number;
  jti: string; // token ID for blacklisting
  iss: string; // issuer
  aud: string; // audience
  typ: 'access' | 'refresh';
  sessionId?: string;
  mfaVerified?: boolean;
}

export interface JWTSecret {
  id: string;
  value: string;
  active: boolean;
  createdAt: number;
  rotatedAt: number;
  algorithm: string;
}

export interface JWTTokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

export interface JWTVerificationResult {
  valid: boolean;
  payload?: JWTClaims;
  error?: string;
  isExpired?: boolean;
  needsRefresh?: boolean;
}

export class JWTService {
  private readonly kv: KVNamespace;
  private readonly issuer: string;
  private readonly audience: string;
  private readonly algorithm: string = 'HS256';

  // Rotation settings
  private readonly ROTATION_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
  private readonly SECRET_RETENTION_PERIOD = 7 * 24 * 60 * 60 * 1000; // 7 days
  private readonly SECRETS_KEY = 'jwt:secrets:v2';
  private readonly BLACKLIST_PREFIX = 'jwt:blacklist:';

  // Token lifetimes
  private readonly ACCESS_TOKEN_LIFETIME = 15 * 60; // 15 minutes
  private readonly REFRESH_TOKEN_LIFETIME = 7 * 24 * 60 * 60; // 7 days

  constructor(kv: KVNamespace, issuer: string = 'coreflow360', audience: string = 'api') {
    this.kv = kv;
    this.issuer = issuer;
    this.audience = audience;
  }

  /**
   * Get the current active secret, rotating if necessary
   */
  async getActiveSecret(): Promise<JWTSecret> {
    const secrets = await this.getSecrets();
    const activeSecret = secrets.find(s => s.active);

    // If no active secret exists or rotation is needed
    if (!activeSecret || this.needsRotation(activeSecret)) {
      return await this.rotateSecrets();
    }

    return activeSecret;
  }

  /**
   * Get all valid secrets for token verification
   */
  async getAllSecrets(): Promise<JWTSecret[]> {
    const secrets = await this.getSecrets();
    const now = Date.now();

    // Return secrets that are still within retention period
    return secrets.filter(secret =>
      (now - secret.createdAt) < this.SECRET_RETENTION_PERIOD
    );
  }

  /**
   * Generate JWT token pair (access + refresh)
   */
  async generateTokenPair(
    userId: string,
    email: string,
    businessId: string,
    roles: string[],
    permissions: string[],
    sessionId?: string,
    mfaVerified: boolean = false
  ): Promise<JWTTokenPair> {
    const activeSecret = await this.getActiveSecret();
    const now = Math.floor(Date.now() / 1000);

    // Generate unique JTIs for both tokens
    const accessTokenId = await this.generateSecureId();
    const refreshTokenId = await this.generateSecureId();

    // Create access token claims
    const accessClaims: JWTClaims = {
      sub: userId,
      email,
      businessId,
      roles,
      permissions,
      iat: now,
      exp: now + this.ACCESS_TOKEN_LIFETIME,
      jti: accessTokenId,
      iss: this.issuer,
      aud: this.audience,
      typ: 'access',
      sessionId,
      mfaVerified
    };

    // Create refresh token claims (minimal data)
    const refreshClaims: JWTClaims = {
      sub: userId,
      email,
      businessId,
      roles: [],
      permissions: [],
      iat: now,
      exp: now + this.REFRESH_TOKEN_LIFETIME,
      jti: refreshTokenId,
      iss: this.issuer,
      aud: this.audience,
      typ: 'refresh',
      sessionId
    };

    const secret = new TextEncoder().encode(activeSecret.value);

    // Generate tokens
    const accessToken = await new SignJWT(accessClaims)
      .setProtectedHeader({ alg: this.algorithm, kid: activeSecret.id })
      .setIssuedAt()
      .setExpirationTime(accessClaims.exp)
      .setJti(accessTokenId)
      .setSubject(userId)
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .sign(secret);

    const refreshToken = await new SignJWT(refreshClaims)
      .setProtectedHeader({ alg: this.algorithm, kid: activeSecret.id })
      .setIssuedAt()
      .setExpirationTime(refreshClaims.exp)
      .setJti(refreshTokenId)
      .setSubject(userId)
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .sign(secret);

    // Store refresh token for revocation tracking
    await this.storeRefreshToken(refreshTokenId, userId, businessId);

    return {
      accessToken,
      refreshToken,
      expiresIn: this.ACCESS_TOKEN_LIFETIME,
      tokenType: 'Bearer'
    };
  }

  /**
   * Verify JWT token with comprehensive security checks
   */
  async verifyToken(token: string): Promise<JWTVerificationResult> {
    try {
      // Extract header to get key ID
      const header = this.extractHeader(token);
      const keyId = header?.kid;

      // Get all valid secrets for verification
      const secrets = await this.getAllSecrets();

      let verificationResult: JWTVerificationResult | null = null;
      let lastError: string = 'Unknown verification error';

      // Try verification with each valid secret
      for (const secret of secrets) {
        // If key ID is specified, only try matching secret
        if (keyId && secret.id !== keyId) {
          continue;
        }

        try {
          const secretKey = new TextEncoder().encode(secret.value);

          const { payload } = await jwtVerify(token, secretKey, {
            algorithms: [this.algorithm],
            issuer: this.issuer,
            audience: this.audience,
            clockTolerance: 30, // 30 seconds clock skew tolerance
            maxTokenAge: '7d' // Maximum token age
          });

          const claims = payload as JWTClaims;

          // Additional security validations
          const validation = await this.validateTokenClaims(claims, token);
          if (!validation.valid) {
            verificationResult = validation;
            break;
          }

          verificationResult = {
            valid: true,
            payload: claims,
            needsRefresh: this.shouldRefresh(claims)
          };
          break;

        } catch (error: any) {
          lastError = this.parseJWTError(error);

          // Check for expiration specifically
          if (error.message?.includes('expired')) {
            verificationResult = {
              valid: false,
              error: 'Token expired',
              isExpired: true,
              needsRefresh: true
            };
            break;
          }
        }
      }

      return verificationResult || {
        valid: false,
        error: lastError
      };

    } catch (error: any) {
      return {
        valid: false,
        error: this.parseJWTError(error)
      };
    }
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(refreshToken: string): Promise<JWTTokenPair | { error: string }> {
    try {
      // Verify refresh token
      const verification = await this.verifyToken(refreshToken);

      if (!verification.valid || !verification.payload) {
        return { error: verification.error || 'Invalid refresh token' };
      }

      const claims = verification.payload;

      // Ensure it's actually a refresh token
      if (claims.typ !== 'refresh') {
        return { error: 'Invalid token type for refresh' };
      }

      // Check if refresh token is still valid in our storage
      const isValidRefreshToken = await this.isValidRefreshToken(claims.jti);
      if (!isValidRefreshToken) {
        return { error: 'Refresh token revoked or expired' };
      }

      // Get fresh user data (permissions might have changed)
      const freshUserData = await this.getFreshUserData(claims.sub, claims.businessId);
      if (!freshUserData) {
        return { error: 'User no longer exists or is inactive' };
      }

      // Revoke old refresh token
      await this.revokeRefreshToken(claims.jti);

      // Generate new token pair
      return await this.generateTokenPair(
        claims.sub,
        claims.email,
        claims.businessId,
        freshUserData.roles,
        freshUserData.permissions,
        claims.sessionId,
        freshUserData.mfaVerified
      );

    } catch (error: any) {
      return { error: 'Token refresh failed' };
    }
  }

  /**
   * Revoke token (add to blacklist)
   */
  async revokeToken(token: string, reason: string = 'logout'): Promise<void> {
    try {
      const verification = await this.verifyToken(token);
      if (verification.valid && verification.payload) {
        const jti = verification.payload.jti;
        const exp = verification.payload.exp;

        // Calculate TTL based on token expiration
        const now = Math.floor(Date.now() / 1000);
        const ttl = Math.max(exp - now, 60); // At least 60 seconds

        // Add to blacklist
        await this.kv.put(
          `${this.BLACKLIST_PREFIX}${jti}`,
          JSON.stringify({
            jti,
            revokedAt: Date.now(),
            reason,
            expiresAt: exp * 1000
          }),
          { expirationTtl: ttl }
        );

        // If it's a refresh token, also revoke it from storage
        if (verification.payload.typ === 'refresh') {
          await this.revokeRefreshToken(jti);
        }
      }
    } catch (error) {
      // Log error but don't throw - revocation should be best effort
      console.error('Token revocation failed:', error);
    }
  }

  /**
   * Check if token is blacklisted
   */
  async isTokenBlacklisted(jti: string): Promise<boolean> {
    const blacklistEntry = await this.kv.get(`${this.BLACKLIST_PREFIX}${jti}`);
    return !!blacklistEntry;
  }

  /**
   * Revoke all tokens for a user
   */
  async revokeAllUserTokens(userId: string): Promise<void> {
    // Get all refresh tokens for user
    const userRefreshTokensKey = `refresh_tokens:${userId}`;
    const tokenListJson = await this.kv.get(userRefreshTokensKey);

    if (tokenListJson) {
      const tokenList: string[] = JSON.parse(tokenListJson);

      // Revoke each refresh token
      for (const jti of tokenList) {
        await this.revokeRefreshToken(jti);
      }

      // Clear the list
      await this.kv.delete(userRefreshTokensKey);
    }
  }

  /**
   * Rotate JWT secrets
   */
  private async rotateSecrets(): Promise<JWTSecret> {
    const secrets = await this.getSecrets();
    const now = Date.now();

    // Generate new secret
    const newSecret: JWTSecret = {
      id: await this.generateSecureId(),
      value: await this.generateSecretValue(),
      active: true,
      createdAt: now,
      rotatedAt: now,
      algorithm: this.algorithm
    };

    // Deactivate old secrets but keep for verification
    const updatedSecrets = secrets.map(s => ({
      ...s,
      active: false
    }));

    // Add new active secret
    updatedSecrets.push(newSecret);

    // Remove secrets older than retention period
    const validSecrets = updatedSecrets.filter(s =>
      (now - s.createdAt) < this.SECRET_RETENTION_PERIOD
    );

    // Store updated secrets
    await this.kv.put(this.SECRETS_KEY, JSON.stringify(validSecrets));

    return newSecret;
  }

  /**
   * Get secrets from storage
   */
  private async getSecrets(): Promise<JWTSecret[]> {
    const secretsJson = await this.kv.get(this.SECRETS_KEY);

    if (!secretsJson) {
      // No secrets exist, create initial secret
      const initialSecret: JWTSecret = {
        id: await this.generateSecureId(),
        value: await this.generateSecretValue(),
        active: true,
        createdAt: Date.now(),
        rotatedAt: Date.now(),
        algorithm: this.algorithm
      };

      await this.kv.put(this.SECRETS_KEY, JSON.stringify([initialSecret]));
      return [initialSecret];
    }

    try {
      return JSON.parse(secretsJson);
    } catch {
      // Corrupted data, reinitialize
      return [];
    }
  }

  /**
   * Check if secret needs rotation
   */
  private needsRotation(secret: JWTSecret): boolean {
    const age = Date.now() - secret.rotatedAt;
    return age > this.ROTATION_INTERVAL;
  }

  /**
   * Generate cryptographically secure secret value
   */
  private async generateSecretValue(): Promise<string> {
    // Generate 64 bytes (512 bits) of random data
    const randomBytes = crypto.getRandomValues(new Uint8Array(64));

    // Convert to base64url for storage
    const base64 = btoa(String.fromCharCode(...randomBytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    return base64;
  }

  /**
   * Generate secure ID
   */
  private async generateSecureId(): Promise<string> {
    const randomBytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(randomBytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Extract JWT header without verification
   */
  private extractHeader(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const header = JSON.parse(atob(parts[0]));
      return header;
    } catch {
      return null;
    }
  }

  /**
   * Validate token claims for security
   */
  private async validateTokenClaims(claims: JWTClaims, token: string): Promise<JWTVerificationResult> {
    // Check if token is blacklisted
    if (await this.isTokenBlacklisted(claims.jti)) {
      return {
        valid: false,
        error: 'Token has been revoked'
      };
    }

    // Validate required claims
    if (!claims.sub || !claims.email || !claims.businessId) {
      return {
        valid: false,
        error: 'Missing required claims'
      };
    }

    // Validate token type
    if (!claims.typ || !['access', 'refresh'].includes(claims.typ)) {
      return {
        valid: false,
        error: 'Invalid token type'
      };
    }

    // Validate arrays
    if (!Array.isArray(claims.roles) || !Array.isArray(claims.permissions)) {
      return {
        valid: false,
        error: 'Invalid roles or permissions format'
      };
    }

    // Additional business logic validations can be added here

    return { valid: true };
  }

  /**
   * Check if token should be refreshed soon
   */
  private shouldRefresh(claims: JWTClaims): boolean {
    const now = Math.floor(Date.now() / 1000);
    const timeToExpiry = claims.exp - now;

    // Suggest refresh if less than 5 minutes remaining
    return timeToExpiry < 300;
  }

  /**
   * Parse JWT verification errors
   */
  private parseJWTError(error: any): string {
    if (error.message?.includes('signature')) {
      return 'Invalid token signature';
    }
    if (error.message?.includes('expired')) {
      return 'Token expired';
    }
    if (error.message?.includes('not yet valid')) {
      return 'Token not yet valid';
    }
    if (error.message?.includes('invalid')) {
      return 'Invalid token format';
    }
    return 'Token verification failed';
  }

  /**
   * Store refresh token for tracking
   */
  private async storeRefreshToken(jti: string, userId: string, businessId: string): Promise<void> {
    // Store individual refresh token
    const refreshTokenKey = `refresh_token:${jti}`;
    await this.kv.put(refreshTokenKey, JSON.stringify({
      jti,
      userId,
      businessId,
      createdAt: Date.now(),
      active: true
    }), {
      expirationTtl: this.REFRESH_TOKEN_LIFETIME
    });

    // Track all refresh tokens for user
    const userRefreshTokensKey = `refresh_tokens:${userId}`;
    const tokenListJson = await this.kv.get(userRefreshTokensKey);
    const tokenList: string[] = tokenListJson ? JSON.parse(tokenListJson) : [];

    if (!tokenList.includes(jti)) {
      tokenList.push(jti);

      // Limit concurrent refresh tokens per user
      if (tokenList.length > 10) {
        const oldestJti = tokenList.shift();
        if (oldestJti) {
          await this.revokeRefreshToken(oldestJti);
        }
      }

      await this.kv.put(userRefreshTokensKey, JSON.stringify(tokenList), {
        expirationTtl: this.REFRESH_TOKEN_LIFETIME
      });
    }
  }

  /**
   * Check if refresh token is valid
   */
  private async isValidRefreshToken(jti: string): Promise<boolean> {
    const refreshTokenKey = `refresh_token:${jti}`;
    const tokenData = await this.kv.get(refreshTokenKey);

    if (!tokenData) return false;

    try {
      const data = JSON.parse(tokenData);
      return data.active === true;
    } catch {
      return false;
    }
  }

  /**
   * Revoke refresh token
   */
  private async revokeRefreshToken(jti: string): Promise<void> {
    const refreshTokenKey = `refresh_token:${jti}`;
    await this.kv.delete(refreshTokenKey);
  }

  /**
   * Get fresh user data for token refresh
   * This should integrate with your user service
   */
  private async getFreshUserData(userId: string, businessId: string): Promise<{
    roles: string[];
    permissions: string[];
    mfaVerified: boolean;
  } | null> {
    // This is a placeholder - implement actual user data fetching
    // In a real implementation, this would query your user database

    // For now, return basic data structure
    // You should replace this with actual user service integration
    return {
      roles: ['user'],
      permissions: ['read:profile', 'update:profile'],
      mfaVerified: false
    };
  }

  /**
   * Get JWT service statistics for monitoring
   */
  async getStatistics(): Promise<{
    activeSecrets: number;
    oldestSecretAge: number;
    rotationDue: boolean;
    totalBlacklistedTokens: number;
  }> {
    const secrets = await this.getSecrets();
    const activeSecret = secrets.find(s => s.active);

    // Count blacklisted tokens (approximate)
    const blacklistKeys = await this.kv.list({ prefix: this.BLACKLIST_PREFIX });

    return {
      activeSecrets: secrets.filter(s => s.active).length,
      oldestSecretAge: activeSecret ? Date.now() - activeSecret.createdAt : 0,
      rotationDue: activeSecret ? this.needsRotation(activeSecret) : true,
      totalBlacklistedTokens: blacklistKeys.keys.length
    };
  }
}

/**
 * Utility function to create JWT service instance
 */
export function createJWTService(
  kv: KVNamespace,
  issuer?: string,
  audience?: string
): JWTService {
  return new JWTService(kv, issuer, audience);
}

/**
 * Middleware helper for JWT verification
 */
export async function verifyJWTMiddleware(
  request: Request,
  jwtService: JWTService
): Promise<{ valid: boolean; claims?: JWTClaims; error?: string }> {
  const authHeader = request.headers.get('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { valid: false, error: 'Missing or invalid authorization header' };
  }

  const token = authHeader.substring(7); // Remove 'Bearer '

  if (!token) {
    return { valid: false, error: 'No token provided' };
  }

  const verification = await jwtService.verifyToken(token);

  if (!verification.valid) {
    return {
      valid: false,
      error: verification.error || 'Token verification failed'
    };
  }

  // Ensure it's an access token
  if (verification.payload?.typ !== 'access') {
    return { valid: false, error: 'Invalid token type for API access' };
  }

  return {
    valid: true,
    claims: verification.payload
  };
}

// Export types for external use
export type {
  JWTClaims,
  JWTSecret,
  JWTTokenPair,
  JWTVerificationResult
};