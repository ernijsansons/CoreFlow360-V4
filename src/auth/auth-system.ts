// Comprehensive Authentication System for CoreFlow360 V4
import { jwtVerify, SignJWT } from 'jose';

// Cloudflare types
declare global {
  interface D1Database {
    prepare(query: string): D1PreparedStatement;
  }
  interface D1PreparedStatement {
    bind(...values: any[]): D1PreparedStatement;
    first<T = unknown>(): Promise<T | null>;
    run(): Promise<D1Result>;
    all<T = unknown>(): Promise<D1Result<T>>;
  }
  // D1Result interface is already defined in @cloudflare/workers-types
  interface KVNamespace {
    get(key: string): Promise<string | null>;
    put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  }
}

export interface User {
  id: string;
  email: string;
  name: string;
  businessId: string;
  roles: string[];
  permissions: string[];
  isActive: boolean;
  createdAt: number;
  updatedAt: number;
  lastLoginAt?: number;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
}

export interface AuthToken {
  sub: string; // user ID
  email: string;
  businessId: string;
  roles: string[];
  permissions: string[];
  iat: number;
  exp: number;
  jti: string; // token ID for blacklisting
  [key: string]: any; // Index signature for JWTPayload compatibility
}

export interface LoginRequest {
  email: string;
  password: string;
  businessId?: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  name: string;
  businessId: string;
  companyName?: string;
}

export interface ApiKey {
  id: string;
  userId: string;
  businessId: string;
  name: string;
  keyHash: string;
  permissions: string[];
  expiresAt?: number;
  isActive: boolean;
  createdAt: number;
  lastUsedAt?: number;
}

export class AuthSystem {
  private readonly db: D1Database;
  private readonly kvAuth: KVNamespace;
  private readonly jwtSecret: string;

  constructor(db: D1Database, kvAuth: KVNamespace, jwtSecret: string) {
    this.db = db;
    this.kvAuth = kvAuth;
    this.jwtSecret = jwtSecret;
  }

  // Initialize database tables
  async initializeDatabase(): Promise<void> {
    const tables = [
      `CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        business_id TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        roles TEXT NOT NULL DEFAULT '["user"]',
        permissions TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER DEFAULT 1,
        email_verified INTEGER DEFAULT 0,
        two_factor_enabled INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_login_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS businesses (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        domain TEXT,
        plan TEXT DEFAULT 'starter',
        is_active INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        business_id TEXT NOT NULL,
        name TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        permissions TEXT NOT NULL DEFAULT '[]',
        expires_at INTEGER,
        is_active INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (business_id) REFERENCES businesses(id)
      )`,
      `CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_jti TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`
    ];

    for (const sql of tables) {
      await this.db.prepare(sql).run();
    }

    // Create indexes
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
      'CREATE INDEX IF NOT EXISTS idx_users_business_id ON users(business_id)',
      'CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)'
    ];

    for (const sql of indexes) {
      await this.db.prepare(sql).run();
    }
  }

  // Register new user
  async register(request: RegisterRequest): Promise<{ success: boolean; user?: User; error?: string }> {
    try {
      // Validate input
      if (!this.isValidEmail(request.email)) {
        return { success: false, error: 'Invalid email format' };
      }

      if (request.password.length < 8) {
        return { success: false, error: 'Password must be at least 8 characters' };
      }

      // Check if user already exists
      const existingUser = await this.db.prepare('SELECT id FROM users WHERE email = ?')
        .bind(request.email).first();

      if (existingUser) {
        return { success: false, error: 'User already exists' };
      }

      // Create business if it doesn't exist
      const businessId = request.businessId || crypto.randomUUID();
      const existingBusiness = await this.db.prepare('SELECT id FROM businesses WHERE id = ?')
        .bind(businessId).first();

      if (!existingBusiness) {
        await this.db.prepare(`
          INSERT INTO businesses (id, name, created_at, updated_at)
          VALUES (?, ?, ?, ?)
        `).bind(
          businessId,
          request.companyName || 'Default Company',
          Date.now(),
          Date.now()
        ).run();
      }

      // Hash password
      const passwordHash = await this.hashPassword(request.password);

      // Create user
      const userId = crypto.randomUUID();
      const now = Date.now();

      const user: User = {
        id: userId,
        email: request.email,
        name: request.name,
        businessId,
        roles: ['user'],
        permissions: ['read:profile', 'update:profile'],
        isActive: true,
        createdAt: now,
        updatedAt: now,
        emailVerified: false,
        twoFactorEnabled: false
      };

      await this.db.prepare(`
        INSERT INTO users (id, email, name, business_id, password_hash, roles, permissions, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        userId,
        request.email,
        request.name,
        businessId,
        passwordHash,
        JSON.stringify(user.roles),
        JSON.stringify(user.permissions),
        now,
        now
      ).run();

      return { success: true, user };

    } catch (error: any) {
      console.error('Registration error:', error);
      return { success: false, error: 'Registration failed' };
    }
  }

  // Login user
  async login(request: LoginRequest, ipAddress?: string, userAgent?: string): Promise<{
    success: boolean;
    token?: string;
    user?: User;
    error?: string;
  }> {
    try {
      // Find user
      const userRow = await this.db.prepare('SELECT * FROM users WHERE email = ? AND is_active = 1')
        .bind(request.email).first() as any;

      if (!userRow) {
        return { success: false, error: 'Invalid credentials' };
      }

      // Verify password
      const passwordValid = await this.verifyPassword(request.password, userRow.password_hash);
      if (!passwordValid) {
        return { success: false, error: 'Invalid credentials' };
      }

      // Update last login
      await this.db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?')
        .bind(Date.now(), userRow.id).run();

      // Create user object
      const user: User = {
        id: userRow.id,
        email: userRow.email,
        name: userRow.name,
        businessId: userRow.business_id,
        roles: JSON.parse(userRow.roles),
        permissions: JSON.parse(userRow.permissions),
        isActive: userRow.is_active === 1,
        createdAt: userRow.created_at,
        updatedAt: userRow.updated_at,
        lastLoginAt: userRow.last_login_at,
        emailVerified: userRow.email_verified === 1,
        twoFactorEnabled: userRow.two_factor_enabled === 1
      };

      // Generate JWT token
      const token = await this.generateToken(user);

      // Store session
      const sessionId = crypto.randomUUID();
      const jti = this.extractJtiFromToken(token);

      await this.db.prepare(`
        INSERT INTO sessions (id, user_id, token_jti, expires_at, created_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(
        sessionId,
        user.id,
        jti,
        Date.now() + 24 * 60 * 60 * 1000, // 24 hours
        Date.now(),
        ipAddress || null,
        userAgent || null
      ).run();

      return { success: true, token, user };

    } catch (error: any) {
      console.error('Login error:', error);
      return { success: false, error: 'Login failed' };
    }
  }

  // Verify JWT token
  async verifyToken(token: string): Promise<{ valid: boolean; user?: User; error?: string }> {
    try {
      // Check if token is blacklisted
      const blacklisted = await this.kvAuth.get(`blacklist:${token}`);
      if (blacklisted) {
        return { valid: false, error: 'Token is blacklisted' };
      }

      // Verify JWT
      const secret = new TextEncoder().encode(this.jwtSecret);
      const { payload } = await jwtVerify(token, secret) as { payload: AuthToken };

      // Get current user data from database
      const userRow = await this.db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1')
        .bind(payload.sub).first() as any;

      if (!userRow) {
        return { valid: false, error: 'User not found or inactive' };
      }

      const user: User = {
        id: userRow.id,
        email: userRow.email,
        name: userRow.name,
        businessId: userRow.business_id,
        roles: JSON.parse(userRow.roles),
        permissions: JSON.parse(userRow.permissions),
        isActive: userRow.is_active === 1,
        createdAt: userRow.created_at,
        updatedAt: userRow.updated_at,
        lastLoginAt: userRow.last_login_at,
        emailVerified: userRow.email_verified === 1,
        twoFactorEnabled: userRow.two_factor_enabled === 1
      };

      return { valid: true, user };

    } catch (error: any) {
      console.error('Token verification error:', error);
      return { valid: false, error: 'Invalid token' };
    }
  }

  // Generate API key
  async generateApiKey(userId: string, name: string, permissions: string[], expiresAt?: number): Promise<{
    success: boolean;
    apiKey?: string;
    error?: string;
  }> {
    try {
      const user = await this.getUserById(userId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

      const apiKeyId = crypto.randomUUID();
      const rawKey = `cf_${apiKeyId.replace(/-/g, '')}_${crypto.randomUUID().replace(/-/g, '')}`;
      const keyHash = await this.hashApiKey(rawKey);

      await this.db.prepare(`
        INSERT INTO api_keys (id, user_id, business_id, name, key_hash, permissions, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        apiKeyId,
        userId,
        user.businessId,
        name,
        keyHash,
        JSON.stringify(permissions),
        expiresAt || null,
        Date.now()
      ).run();

      return { success: true, apiKey: rawKey };

    } catch (error: any) {
      console.error('API key generation error:', error);
      return { success: false, error: 'Failed to generate API key' };
    }
  }

  // Verify API key
  async verifyApiKey(apiKey: string): Promise<{ valid: boolean; user?: User; permissions?: string[]; error?: string }> {
    try {
      const keyHash = await this.hashApiKey(apiKey);

      const keyRow = await this.db.prepare(`
        SELECT ak.*, u.* FROM api_keys ak
        JOIN users u ON ak.user_id = u.id
        WHERE ak.key_hash = ? AND ak.is_active = 1 AND u.is_active = 1
        AND (ak.expires_at IS NULL OR ak.expires_at > ?)
      `).bind(keyHash, Date.now()).first() as any;

      if (!keyRow) {
        return { valid: false, error: 'Invalid API key' };
      }

      // Update last used timestamp
      await this.db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?')
        .bind(Date.now(), keyRow.id).run();

      const user: User = {
        id: keyRow.user_id,
        email: keyRow.email,
        name: keyRow.name,
        businessId: keyRow.business_id,
        roles: JSON.parse(keyRow.roles),
        permissions: JSON.parse(keyRow.permissions),
        isActive: keyRow.is_active === 1,
        createdAt: keyRow.created_at,
        updatedAt: keyRow.updated_at,
        lastLoginAt: keyRow.last_login_at,
        emailVerified: keyRow.email_verified === 1,
        twoFactorEnabled: keyRow.two_factor_enabled === 1
      };

      const apiPermissions = JSON.parse(keyRow.permissions);

      return { valid: true, user, permissions: apiPermissions };

    } catch (error: any) {
      console.error('API key verification error:', error);
      return { valid: false, error: 'API key verification failed' };
    }
  }

  // Logout (blacklist token)
  async logout(token: string): Promise<{ success: boolean; error?: string }> {
    try {
      const jti = this.extractJtiFromToken(token);

      // Add to blacklist
      await this.kvAuth.put(`blacklist:${token}`, JSON.stringify({
        jti,
        blacklistedAt: Date.now(),
        reason: 'logout'
      }), { expirationTtl: 24 * 60 * 60 }); // 24 hours

      // Remove session
      await this.db.prepare('DELETE FROM sessions WHERE token_jti = ?').bind(jti).run();

      return { success: true };

    } catch (error: any) {
      console.error('Logout error:', error);
      return { success: false, error: 'Logout failed' };
    }
  }

  // Private helper methods
  private async hashPassword(password: string): Promise<string> {
    // In a real implementation, use bcrypt or similar
    const encoder = new TextEncoder();
    const data = encoder.encode(password + 'salt');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  private async verifyPassword(password: string, hash: string): Promise<boolean> {
    const passwordHash = await this.hashPassword(password);
    return passwordHash === hash;
  }

  private async hashApiKey(apiKey: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(apiKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  private async generateToken(user: User): Promise<string> {
    const jti = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (24 * 60 * 60); // 24 hours

    const payload: AuthToken = {
      sub: user.id,
      email: user.email,
      businessId: user.businessId,
      roles: user.roles,
      permissions: user.permissions,
      iat: now,
      exp,
      jti
    };

    const secret = new TextEncoder().encode(this.jwtSecret);
    return await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime(exp)
      .setJti(jti)
      .sign(secret);
  }

  private extractJtiFromToken(token: string): string {
    try {
      const parts = token.split('.');
      const payload = JSON.parse(atob(parts[1]));
      return payload.jti || '';
    } catch {
      return '';
    }
  }

  private async getUserById(id: string): Promise<User | null> {
    const userRow = await this.db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1')
      .bind(id).first() as any;

    if (!userRow) return null;

    return {
      id: userRow.id,
      email: userRow.email,
      name: userRow.name,
      businessId: userRow.business_id,
      roles: JSON.parse(userRow.roles),
      permissions: JSON.parse(userRow.permissions),
      isActive: userRow.is_active === 1,
      createdAt: userRow.created_at,
      updatedAt: userRow.updated_at,
      lastLoginAt: userRow.last_login_at,
      emailVerified: userRow.email_verified === 1,
      twoFactorEnabled: userRow.two_factor_enabled === 1
    };
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}