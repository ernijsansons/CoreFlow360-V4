// Authentication System Tests for CoreFlow360 V4
import { describe, it, expect, beforeAll, afterAll } from 'vitest';

const API_BASE = 'http://localhost:8788';
let authToken: string;
let apiKey: string;
let testUserId: string;

// Test user data
const testUser = {
  email: `test.${Date.now()}@example.com`,
  password: 'SecurePassword123!',
  name: 'Test User',
  businessId: 'test-business-' + Date.now(),
  companyName: 'Test Company'
};

const adminUser = {
  email: `admin.${Date.now()}@example.com`,
  password: 'AdminPassword123!',
  name: 'Admin User',
  businessId: testUser.businessId,
  companyName: 'Test Company'
};

describe('Authentication System', () => {
  describe('User Registration', () => {
    it('should register a new user successfully', async () => {
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testUser)
      });

      const data = await response.json();
      expect(response.status).toBe(201);
      expect(data.success).toBe(true);
      expect(data.user).toBeDefined();
      expect(data.user.email).toBe(testUser.email);
      testUserId = data.user.id;
    });

    it('should reject duplicate email registration', async () => {
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testUser)
      });

      const data = await response.json();
      expect(response.status).toBe(400);
      expect(data.success).toBe(false);
      expect(data.error).toContain('already exists');
    });

    it('should validate password requirements', async () => {
      const weakUser = { ...testUser, email: 'weak@example.com', password: '123' };
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(weakUser)
      });

      const data = await response.json();
      expect(response.status).toBe(400);
      expect(data.success).toBe(false);
      expect(data.error).toContain('8 characters');
    });

    it('should validate email format', async () => {
      const invalidEmail = { ...testUser, email: 'not-an-email' };
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(invalidEmail)
      });

      const data = await response.json();
      expect(response.status).toBe(400);
      expect(data.success).toBe(false);
      expect(data.error).toContain('Invalid email');
    });
  });

  describe('User Login', () => {
    it('should login with valid credentials', async () => {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testUser.email,
          password: testUser.password
        })
      });

      const data = await response.json();
      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.token).toBeDefined();
      expect(data.user).toBeDefined();
      authToken = data.token;
    });

    it('should reject invalid password', async () => {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testUser.email,
          password: 'WrongPassword'
        })
      });

      const data = await response.json();
      expect(response.status).toBe(401);
      expect(data.success).toBe(false);
      expect(data.error).toContain('Invalid credentials');
    });

    it('should reject non-existent user', async () => {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'nonexistent@example.com',
          password: 'SomePassword123'
        })
      });

      const data = await response.json();
      expect(response.status).toBe(401);
      expect(data.success).toBe(false);
    });
  });

  describe('Profile Access', () => {
    it('should retrieve user profile with valid token', async () => {
      const response = await fetch(`${API_BASE}/api/auth/profile`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });

      const data = await response.json();
      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.user).toBeDefined();
      expect(data.user.email).toBe(testUser.email);
    });

    it('should reject profile access without token', async () => {
      const response = await fetch(`${API_BASE}/api/auth/profile`);

      const data = await response.json();
      expect(response.status).toBe(401);
      expect(data.error).toContain('authorization header');
    });

    it('should reject profile access with invalid token', async () => {
      const response = await fetch(`${API_BASE}/api/auth/profile`, {
        headers: { 'Authorization': 'Bearer invalid-token' }
      });

      const data = await response.json();
      expect(response.status).toBe(401);
      expect(data.error).toBeDefined();
    });
  });

  describe('API Key Management', () => {
    it('should create API key for authenticated user', async () => {
      const response = await fetch(`${API_BASE}/api/users/create-api-key`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: 'Test API Key',
          permissions: ['read:profile', 'update:profile'],
          expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
        })
      });

      const data = await response.json();
      expect(response.status).toBe(201);
      expect(data.success).toBe(true);
      expect(data.apiKey).toBeDefined();
      expect(data.apiKey).toMatch(/^cf_/);
      apiKey = data.apiKey;
    });

    it('should reject API key creation without auth', async () => {
      const response = await fetch(`${API_BASE}/api/users/create-api-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Unauthorized Key',
          permissions: []
        })
      });

      expect(response.status).toBe(401);
    });
  });

  describe('Logout', () => {
    it('should logout successfully', async () => {
      const response = await fetch(`${API_BASE}/api/auth/logout`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` }
      });

      const data = await response.json();
      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
    });

    it('should reject blacklisted token after logout', async () => {
      const response = await fetch(`${API_BASE}/api/auth/profile`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });

      const data = await response.json();
      expect(response.status).toBe(401);
      expect(data.error).toContain('blacklisted');
    });
  });
});

describe('Admin Endpoints', () => {
  let adminToken: string;

  beforeAll(async () => {
    // Register admin user
    await fetch(`${API_BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(adminUser)
    });

    // Login as admin
    const loginResponse = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: adminUser.email,
        password: adminUser.password
      })
    });

    const loginData = await loginResponse.json();
    adminToken = loginData.token;
  });

  describe('User Management', () => {
    it('should list users for admin', async () => {
      const response = await fetch(`${API_BASE}/api/admin/users`, {
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });

      const data = await response.json();
      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.users).toBeDefined();
      expect(Array.isArray(data.users)).toBe(true);
    });

    it('should reject user list for non-admin', async () => {
      // Get a regular user token
      const loginResponse = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testUser.email,
          password: testUser.password
        })
      });

      const loginData = await loginResponse.json();
      const userToken = loginData.token;

      const response = await fetch(`${API_BASE}/api/admin/users`, {
        headers: { 'Authorization': `Bearer ${userToken}` }
      });

      expect(response.status).toBe(403);
      const data = await response.json();
      expect(data.error).toContain('Insufficient permissions');
    });
  });

  describe('Analytics', () => {
    it('should retrieve analytics dashboard', async () => {
      const response = await fetch(`${API_BASE}/api/analytics/dashboard`, {
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });

      const data = await response.json();
      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.analytics).toBeDefined();
      expect(data.analytics.users).toBeDefined();
      expect(data.analytics.api_usage).toBeDefined();
    });

    it('should export logs in JSON format', async () => {
      const response = await fetch(`${API_BASE}/api/logs/export?days=7&format=json`, {
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });

      const data = await response.json();
      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.logs).toBeDefined();
      expect(Array.isArray(data.logs)).toBe(true);
    });

    it('should export logs in CSV format', async () => {
      const response = await fetch(`${API_BASE}/api/logs/export?days=7&format=csv`, {
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });

      expect(response.status).toBe(200);
      const contentType = response.headers.get('Content-Type');
      expect(contentType).toBe('text/csv');
    });
  });
});

describe('Rate Limiting', () => {
  it('should enforce rate limits', async () => {
    const requests = [];

    // Make 100 rapid requests
    for (let i = 0; i < 100; i++) {
      requests.push(fetch(`${API_BASE}/api/status`));
    }

    const responses = await Promise.all(requests);
    const statusCodes = responses.map(r => r.status);

    // Some requests should be rate limited
    expect(statusCodes).toContain(429);
  });

  it('should include rate limit headers', async () => {
    const response = await fetch(`${API_BASE}/api/status`);

    expect(response.headers.get('X-RateLimit-Limit')).toBeDefined();
    expect(response.headers.get('X-RateLimit-Remaining')).toBeDefined();
    expect(response.headers.get('X-RateLimit-Reset')).toBeDefined();
  });
});

describe('Cache Performance', () => {
  it('should retrieve cache statistics', async () => {
    const response = await fetch(`${API_BASE}/api/cache/stats`);

    const data = await response.json();
    expect(response.status).toBe(200);
    expect(data.cache_hits).toBeDefined();
    expect(data.cache_misses).toBeDefined();
    expect(data.hit_ratio).toBeDefined();
  });
});