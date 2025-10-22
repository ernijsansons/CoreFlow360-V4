/**
 * Developer Platform API Routes
 * Handles developer registration, authentication, and management
 */

import { Logger } from '@/shared/logger';
import { Hono } from 'hono';
import type { Env } from '@/types/env';
import { DeveloperService } from '@/services/developers/developer.service';
import { AnalyticsService } from '@/services/developers/analytics.service';
import { JWTService } from '@/modules/auth/jwt';

const logger = new Logger({ component: 'Developers' });


/**
 * Helper function to verify JWT tokens
 */
async function verifyJWT(token: string, secret: string): Promise<any> {
  const jwtService = new JWTService(secret);
  try {
    const payload = await jwtService.verifyToken(token);
    return { userId: payload.sub, ...(payload as any) };
  } catch (error) {
    return null;
  }
}

const app = new Hono<{ Bindings: Env }>();

/**
 * POST /developers/register
 * Register new developer account
 */
app.post('/register', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const body = await c.req.json();
    const developerService = new DeveloperService(c.env);

    const result = await developerService.registerDeveloper(payload.userId, {
      developer_name: body.developer_name,
      developer_email: body.developer_email,
      company_name: body.company_name,
      website_url: body.website_url,
      github_username: body.github_username,
      developer_tier: body.tier || 'free',
    });

    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      success: true,
      developer: result.developer,
      api_key: result.api_key,
      api_secret: result.api_secret,
      webhook_secret: result.webhook_secret,
    });
  } catch (error) {
    logger.error('Developer registration error:', error);
    return c.json({ error: 'Registration failed' }, 500);
  }
});

/**
 * GET /developers/me
 * Get current developer profile
 */
app.get('/me', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId);

    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    return c.json({ developer });
  } catch (error) {
    logger.error('Get developer profile error:', error);
    return c.json({ error: 'Failed to get profile' }, 500);
  }
});

/**
 * PATCH /developers/me
 * Update developer profile
 */
app.patch('/me', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId);

    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const body = await c.req.json();
    const result = await developerService.updateDeveloper(developer.id, {
      developer_name: body.developer_name,
      developer_email: body.developer_email,
      company_name: body.company_name,
      website_url: body.website_url,
      github_username: body.github_username,
    });

    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({ success: true, developer: result.developer });
  } catch (error) {
    logger.error('Update developer profile error:', error);
    return c.json({ error: 'Failed to update profile' }, 500);
  }
});

/**
 * GET /developers/me/quotas
 * Get developer quota usage
 */
app.get('/me/quotas', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId);

    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const quotas = await developerService.checkQuotas(developer.id);
    return c.json({ quotas });
  } catch (error) {
    logger.error('Get quotas error:', error);
    return c.json({ error: 'Failed to get quotas' }, 500);
  }
});

/**
 * GET /developers/me/dashboard
 * Get developer dashboard analytics
 */
app.get('/me/dashboard', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId);

    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const analyticsService = new AnalyticsService(c.env);
    const dashboard = await analyticsService.getDeveloperDashboard(developer.id);

    return c.json({ dashboard });
  } catch (error) {
    logger.error('Get developer dashboard error:', error);
    return c.json({ error: 'Failed to get dashboard' }, 500);
  }
});

/**
 * POST /developers/me/api-keys
 * Generate new API key
 */
app.post('/me/api-keys', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId);

    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const body = await c.req.json();
    const result = await developerService.createApiKey(developer.id, {
      key_name: body.key_name,
      scopes: body.scopes || [],
      rate_limit_per_hour: body.rate_limit_per_hour,
      ip_whitelist: body.ip_whitelist,
      expires_at: body.expires_at,
    });

    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      success: true,
      api_key: result.api_key,
      api_key_prefix: result.api_key_prefix,
    });
  } catch (error) {
    logger.error('Create API key error:', error);
    return c.json({ error: 'Failed to create API key' }, 500);
  }
});

/**
 * GET /developers/me/api-keys
 * List developer API keys
 */
app.get('/me/api-keys', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId);

    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const apiKeys = await developerService.listApiKeys(developer.id);
    return c.json({ api_keys: apiKeys });
  } catch (error) {
    logger.error('List API keys error:', error);
    return c.json({ error: 'Failed to list API keys' }, 500);
  }
});

/**
 * DELETE /developers/me/api-keys/:key_id
 * Revoke API key
 */
app.delete('/me/api-keys/:key_id', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId);

    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const keyId = c.req.param('key_id');
    const success = await developerService.revokeApiKey(keyId, payload.userId);

    if (!success) {
      return c.json({ error: 'Failed to revoke API key' }, 400);
    }

    return c.json({ success: true });
  } catch (error) {
    logger.error('Revoke API key error:', error);
    return c.json({ error: 'Failed to revoke API key' }, 500);
  }
});

/**
 * GET /developers/me/tier-details
 * Get tier limits and upgrade options
 */
app.get('/me/tier-details', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId);

    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    // Return tier comparison
    const tiers = {
      current: developer.developer_tier,
      tiers: {
        free: {
          max_custom_integrations: 5,
          max_installs: 25,
          max_api_calls_per_day: 10000,
          price_per_month: 0,
          features: ['Private integrations only', 'Community support', 'Basic analytics'],
        },
        pro: {
          max_custom_integrations: -1, // Unlimited
          max_installs: 500,
          max_api_calls_per_day: 100000,
          price_per_month: 99,
          features: [
            'Public marketplace listing',
            'Priority support',
            'Advanced analytics',
            'Custom branding',
          ],
        },
        enterprise: {
          max_custom_integrations: -1,
          max_installs: -1,
          max_api_calls_per_day: -1,
          price_per_month: 499,
          features: [
            'Everything in Pro',
            'White-label integrations',
            'SLA guarantee',
            'Dedicated support',
            'Custom contract terms',
          ],
        },
      },
    };

    return c.json({ tier_details: tiers });
  } catch (error) {
    logger.error('Get tier details error:', error);
    return c.json({ error: 'Failed to get tier details' }, 500);
  }
});

export default app;
