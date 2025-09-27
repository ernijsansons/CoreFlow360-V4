import { Env } from '../../types/env';

export interface BlacklistedToken {
  token: string;
  userId: string;
  expiresAt: number;
  reason: string;
  blacklistedAt: number;
}

export class TokenBlacklist {
  private readonly kvNamespace: KVNamespace;
  private readonly prefix = 'blacklist:';
  private readonly ttl = 60 * 60 * 24 * 7; // 7 days

  constructor(env: Env) {
    this.kvNamespace = env.KV_AUTH;
  }

  async add(
    token: string,
    userId: string,
    expiresAt: number,
    reason: string
  ): Promise<void> {
    const key = `${this.prefix}${token}`;
    const data: BlacklistedToken = {
      token,
      userId,
      expiresAt,
      reason,
      blacklistedAt: Date.now(),
    };

    // Store with expiration based on token expiry
    const ttl = Math.max(
      Math.floor((expiresAt - Date.now()) / 1000),
      this.ttl
    );

    await this.kvNamespace.put(key, JSON.stringify(data), {
      expirationTtl: ttl,
    });
  }

  async isBlacklisted(token: string): Promise<boolean> {
    const key = `${this.prefix}${token}`;
    const data = await this.kvNamespace.get(key);

    if (!data) return false;

    const blacklistedToken: BlacklistedToken = JSON.parse(data);

    // Check if token has expired
    if (blacklistedToken.expiresAt < Date.now()) {
      await this.remove(token);
      return false;
    }

    return true;
  }

  async remove(token: string): Promise<void> {
    const key = `${this.prefix}${token}`;
    await this.kvNamespace.delete(key);
  }

  async getUserBlacklistedTokens(userId: string): Promise<BlacklistedToken[]> {
    // List all blacklisted tokens (with pagination if needed)
    const list = await this.kvNamespace.list({ prefix: this.prefix });
    const tokens: BlacklistedToken[] = [];

    for (const key of list.keys) {
      const data = await this.kvNamespace.get(key.name);
      if (data) {
        const token: BlacklistedToken = JSON.parse(data);
        if (token.userId === userId) {
          tokens.push(token);
        }
      }
    }

    return tokens;
  }

  async clearExpiredTokens(): Promise<number> {
    const list = await this.kvNamespace.list({ prefix: this.prefix });
    let cleared = 0;

    for (const key of list.keys) {
      const data = await this.kvNamespace.get(key.name);
      if (data) {
        const token: BlacklistedToken = JSON.parse(data);
        if (token.expiresAt < Date.now()) {
          await this.kvNamespace.delete(key.name);
          cleared++;
        }
      }
    }

    return cleared;
  }
}