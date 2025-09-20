import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { TokenClaims } from './types';
import { signHMAC, verifyHMAC } from './crypto';

// Token configuration
const ACCESS_TOKEN_DURATION = 15 * 60; // 15 minutes
const REFRESH_TOKEN_DURATION = 7 * 24 * 60 * 60; // 7 days
const MFA_TOKEN_DURATION = 5 * 60; // 5 minutes for MFA verification

export class JWTService {
  private secret: Uint8Array;
  private issuer: string;
  private audience: string;

  constructor(secret: string, issuer: string = 'coreflow360', audience: string = 'coreflow360-api') {
    this.secret = new TextEncoder().encode(secret);
    this.issuer = issuer;
    this.audience = audience;
  }

  /**
   * Generate access token with business context
   */
  async generateAccessToken(claims: Omit<TokenClaims, 'iat' | 'exp' | 'jti'>): Promise<{
    token: string;
    expiresIn: number;
    expiresAt: number;
  }> {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + ACCESS_TOKEN_DURATION;

    const token = await new SignJWT({
      ...claims,
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuedAt(now)
      .setExpirationTime(expiresAt)
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setSubject(claims.sub)
      .sign(this.secret);

    return {
      token,
      expiresIn: ACCESS_TOKEN_DURATION,
      expiresAt: expiresAt * 1000, // Convert back to milliseconds
    };
  }

  /**
   * Generate refresh token
   */
  async generateRefreshToken(userId: string, sessionId: string): Promise<{
    token: string;
    expiresIn: number;
    expiresAt: number;
  }> {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + REFRESH_TOKEN_DURATION;

    const token = await new SignJWT({
      sub: userId,
      sessionId,
      type: 'refresh',
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuedAt(now)
      .setExpirationTime(expiresAt)
      .setIssuer(this.issuer)
      .sign(this.secret);

    return {
      token,
      expiresIn: REFRESH_TOKEN_DURATION,
      expiresAt: expiresAt * 1000,
    };
  }

  /**
   * Generate temporary MFA token
   */
  async generateMFAToken(userId: string, email: string): Promise<{
    token: string;
    expiresIn: number;
  }> {
    const now = Math.floor(Date.now() / 1000);

    const token = await new SignJWT({
      sub: userId,
      email,
      type: 'mfa',
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuedAt(now)
      .setExpirationTime(now + MFA_TOKEN_DURATION)
      .setIssuer(this.issuer)
      .sign(this.secret);

    return {
      token,
      expiresIn: MFA_TOKEN_DURATION,
    };
  }

  /**
   * Verify and decode token
   */
  async verifyToken(token: string, expectedType?: string): Promise<TokenClaims & JWTPayload> {
    try {
      const { payload } = await jwtVerify(token, this.secret, {
        issuer: this.issuer,
        audience: this.audience,
      });

      // Check token type if specified
      if (expectedType && (payload as any).type !== expectedType) {
        throw new Error('Invalid token type');
      }

      return payload as TokenClaims & JWTPayload;
    } catch (error) {
      if (error instanceof Error) {
        if (error.message.includes('expired')) {
          throw new Error('Token has expired');
        }
        if (error.message.includes('signature')) {
          throw new Error('Invalid token signature');
        }
      }
      throw new Error('Invalid token');
    }
  }

  /**
   * Decode token without verification (for debugging)
   */
  decodeToken(token: string): any {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid token format');
    }

    try {
      const payload = JSON.parse(atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/')));
      return payload;
    } catch (error) {
      throw new Error('Failed to decode token');
    }
  }

  /**
   * Check if token is expired
   */
  isTokenExpired(token: string): boolean {
    try {
      const payload = this.decodeToken(token);
      const now = Math.floor(Date.now() / 1000);
      return payload.exp ? payload.exp < now : true;
    } catch {
      return true;
    }
  }

  /**
   * Generate token pair (access + refresh)
   */
  async generateTokenPair(claims: Omit<TokenClaims, 'iat' | 'exp' | 'jti'>): Promise<{
    accessToken: string;
    refreshToken: string;
    accessTokenExp: number;
    refreshTokenExp: number;
  }> {
    const access = await this.generateAccessToken(claims);
    const refresh = await this.generateRefreshToken(claims.sub, claims.sessionId);

    return {
      accessToken: access.token,
      refreshToken: refresh.token,
      accessTokenExp: access.expiresAt,
      refreshTokenExp: refresh.expiresAt,
    };
  }

  /**
   * Rotate refresh token (generate new token pair from refresh token)
   */
  async rotateTokens(refreshToken: string, claims: Omit<TokenClaims, 'iat' | 'exp' | 'jti'>): Promise<{
    accessToken: string;
    refreshToken: string;
    accessTokenExp: number;
    refreshTokenExp: number;
  }> {
    // Verify refresh token
    const refreshPayload = await this.verifyToken(refreshToken, 'refresh');

    // Check if refresh token belongs to the same user
    if (refreshPayload.sub !== claims.sub) {
      throw new Error('Invalid refresh token');
    }

    // Generate new token pair
    return this.generateTokenPair(claims);
  }

  /**
   * Create a signed URL for secure downloads/uploads
   */
  async createSignedUrl(
    url: string,
    expiresIn: number = 3600,
    additionalClaims?: Record<string, any>
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const expires = now + expiresIn;

    const claims = {
      url,
      expires,
      ...additionalClaims,
    };

    const signature = await signHMAC(JSON.stringify(claims), this.secret.toString());

    const urlObj = new URL(url);
    urlObj.searchParams.set('signature', signature);
    urlObj.searchParams.set('expires', expires.toString());

    if (additionalClaims) {
      Object.entries(additionalClaims).forEach(([key, value]) => {
        urlObj.searchParams.set(key, String(value));
      });
    }

    return urlObj.toString();
  }

  /**
   * Verify a signed URL
   */
  async verifySignedUrl(signedUrl: string): Promise<boolean> {
    try {
      const urlObj = new URL(signedUrl);
      const signature = urlObj.searchParams.get('signature');
      const expires = urlObj.searchParams.get('expires');

      if (!signature || !expires) {
        return false;
      }

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (parseInt(expires) < now) {
        return false;
      }

      // Reconstruct claims
      const claims: Record<string, any> = {
        url: `${urlObj.origin}${urlObj.pathname}`,
        expires: parseInt(expires),
      };

      // Add additional claims from URL params
      urlObj.searchParams.forEach((value, key) => {
        if (key !== 'signature' && key !== 'expires') {
          claims[key] = value;
        }
      });

      // Verify signature
      return await verifyHMAC(JSON.stringify(claims), signature, this.secret.toString());
    } catch (error) {
      console.error('Error verifying signed URL:', error);
      return false;
    }
  }

  /**
   * Extract bearer token from Authorization header
   */
  static extractBearerToken(authHeader: string | null | undefined): string | null {
    if (!authHeader) return null;

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0]?.toLowerCase() !== 'bearer') {
      return null;
    }

    return parts[1] || null;
  }

  /**
   * Generate a secure session ID
   */
  static generateSessionId(): string {
    const buffer = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(buffer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}