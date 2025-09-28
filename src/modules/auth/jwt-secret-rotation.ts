import { Env } from '../../types/env';
import * as jose from 'jose';
import { JWTSecretManager } from '../../shared/security/jwt-secret-manager';

export interface JWTSecretConfig {
  current: string;
  previous?: string;
  rotationInterval: number; // milliseconds
  lastRotated: number;
}

export class JWTSecretRotation {
  private readonly kvNamespace: KVNamespace;
  private readonly configKey = 'jwt:secret:config';
  private readonly rotationInterval = 30 * 24 * 60 * 60 * 1000; // 30 days

  constructor(private readonly env: Env) {
    this.kvNamespace = env.KV_AUTH;
  }

  async getCurrentSecret(): Promise<string> {
    const config = await this.getConfig();
    if (!config) {
      // CRITICAL SECURITY FIX: Never auto-generate secrets - this prevents JWT bypass attacks
      if (!this.env.JWT_SECRET) {
        throw new Error(
          'CRITICAL SECURITY ERROR: JWT_SECRET is required but not configured. ' +
          'This prevents JWT Authentication Bypass vulnerability (CVSS 9.8). ' +
          'Set a secure JWT_SECRET environment variable with at least 64 characters.'
        );
      }

      // Validate the environment secret before using it
      const validation = await this.validateSecret(this.env.JWT_SECRET);
      if (!validation.isValid) {
        throw new Error(
          `CRITICAL SECURITY ERROR: JWT_SECRET validation failed: ${validation.errors.join(', ')}. ` +
          'This could enable authentication bypass attacks.'
        );
      }

      // Initialize config with validated secret
      const initialConfig: JWTSecretConfig = {
        current: this.env.JWT_SECRET,
        previous: undefined,
        rotationInterval: this.rotationInterval,
        lastRotated: Date.now()
      };
      await this.kvNamespace.put(this.configKey, JSON.stringify(initialConfig));
      return this.env.JWT_SECRET;
    }

    // Check if rotation is needed
    if (this.shouldRotate(config)) {
      await this.rotate();
      const newConfig = await this.getConfig();
      return newConfig!.current;
    }

    return config.current;
  }

  async getPreviousSecret(): Promise<string | undefined> {
    const config = await this.getConfig();
    return config?.previous;
  }

  async getConfig(): Promise<JWTSecretConfig | null> {
    const data = await this.kvNamespace.get(this.configKey);
    if (!data) return null;
    return JSON.parse(data);
  }

  private shouldRotate(config: JWTSecretConfig): boolean {
    const timeSinceRotation = Date.now() - config.lastRotated;
    return timeSinceRotation >= config.rotationInterval;
  }

  async rotate(): Promise<void> {
    const config = await this.getConfig();
    const newSecret = this.generateSecret();

    // SECURITY: Validate the newly generated secret before using it
    const validation = await this.validateSecret(newSecret);
    if (!validation.isValid) {
      throw new Error(
        `CRITICAL: Generated secret failed validation: ${validation.errors.join(', ')}. ` +
        'This should never happen with properly generated secrets.'
      );
    }

    const newConfig: JWTSecretConfig = {
      current: newSecret,
      previous: config?.current,
      rotationInterval: this.rotationInterval,
      lastRotated: Date.now(),
    };

    await this.kvNamespace.put(this.configKey, JSON.stringify(newConfig));

    // Notify monitoring
    console.log('JWT secret rotated successfully - New secret validated and stored securely');
  }

  private generateSecret(): string {
    // Use the secure secret generator from JWTSecretManager
    return JWTSecretManager.generateSecureSecret(64);
  }

  private async validateSecret(secret: string): Promise<{ isValid: boolean; errors: string[] }> {
    // Validate using the comprehensive security checks from JWTSecretManager
    const validation = JWTSecretManager.validateJWTSecret(secret, this.env.ENVIRONMENT || 'production');
    return {
      isValid: validation.isValid,
      errors: validation.errors
    };
  }

  async verifyToken(token: string): Promise<jose.JWTPayload | null> {
    const currentSecret = await this.getCurrentSecret();

    try {
      // Try with current secret first
      const secret = new TextEncoder().encode(currentSecret);
      const { payload } = await jose.jwtVerify(token, secret);
      return payload;
    } catch (error: any) {
      // Try with previous secret if available
      const previousSecret = await this.getPreviousSecret();
      if (previousSecret) {
        try {
          const secret = new TextEncoder().encode(previousSecret);
          const { payload } = await jose.jwtVerify(token, secret);
          return payload;
        } catch {
          // Both secrets failed
          return null;
        }
      }
      return null;
    }
  }

  async signToken(payload: jose.JWTPayload): Promise<string> {
    const currentSecret = await this.getCurrentSecret();
    const secret = new TextEncoder().encode(currentSecret);

    const jwt = await new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('2h')
      .sign(secret);

    return jwt;
  }

  async forceRotation(): Promise<void> {
    await this.rotate();
  }
}