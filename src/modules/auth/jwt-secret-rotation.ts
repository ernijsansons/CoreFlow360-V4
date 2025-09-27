import { Env } from '../../types/env';
import * as jose from 'jose';

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
      return this.env.JWT_SECRET || this.generateSecret();
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

    const newConfig: JWTSecretConfig = {
      current: newSecret,
      previous: config?.current,
      rotationInterval: this.rotationInterval,
      lastRotated: Date.now(),
    };

    await this.kvNamespace.put(this.configKey, JSON.stringify(newConfig));

    // Notify monitoring
    console.log('JWT secret rotated successfully');
  }

  private generateSecret(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array));
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