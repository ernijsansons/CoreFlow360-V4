/**
 * Custom Integrations API Routes
 * Handles custom integration CRUD, marketplace, and execution
 */

import { Logger } from '@/shared/logger';
import { Hono } from 'hono';
import type { Env } from '@/types/env';
import { DeveloperService } from '@/services/developers/developer.service';
import { CustomIntegrationService } from '@/services/developers/custom-integration.service';

import { OAuthHelperService } from '@/services/developers/oauth-helper.service';
import { AnalyticsService } from '@/services/developers/analytics.service';
import { JWTService } from '@/modules/auth/jwt';

const logger = new Logger({ component: 'CustomIntegrations' });

const app = new Hono<{ Bindings: Env }>();

// ============================================================
// CUSTOM INTEGRATION MANAGEMENT
// ============================================================

/**
 * POST /custom-integrations
 * Create new custom integration
 */
app.post('/', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    // Get developer profile
    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId as string);
    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    // Check quota
    const quotas = await developerService.checkQuotas(developer.id);
    if (!quotas.canCreateIntegration) {
      return c.json({
        error: 'Integration quota exceeded',
        quota: {
          used: developer.total_integrations,
          limit: developer.max_custom_integrations,
        },
      }, 403);
    }

    const body = await c.req.json();
    const integrationService = new CustomIntegrationService(c.env);

    const result = await integrationService.createIntegration(developer.id, {
      integration_key: body.integration_key,
      integration_name: body.integration_name,
      integration_description: body.integration_description,
      integration_version: body.integration_version || '1.0.0',
      provider_category: body.provider_category,
      category_tags: body.category_tags || [],
      code_bundle: body.code_bundle,
      manifest: body.manifest,
      auth_type: body.auth_type,
      auth_config: body.auth_config,
      visibility: body.visibility || 'private',
      pricing_model: body.pricing_model || 'free',
      price_usd: body.price_usd || 0.0,
    });

    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({ success: true, integration: result.integration }, 201);
  } catch (error) {
    logger.error('Create integration error:', error);
    return c.json({ error: 'Failed to create integration' }, 500);
  }
});

/**
 * GET /custom-integrations
 * List developer's custom integrations
 */
app.get('/', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId as string);
    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const integrationService = new CustomIntegrationService(c.env);
    const integrations = await integrationService.listDeveloperIntegrations(developer.id, {
      status: c.req.query('status') as any,
      visibility: c.req.query('visibility') as any,
      limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50,
      offset: c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0,
    });

    return c.json({ integrations });
  } catch (error) {
    logger.error('List integrations error:', error);
    return c.json({ error: 'Failed to list integrations' }, 500);
  }
});

/**
 * GET /custom-integrations/:id
 * Get integration details
 */
app.get('/:id', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const integrationId = c.req.param('id');
    const integrationService = new CustomIntegrationService(c.env);
    const integration = await integrationService.getIntegrationById(integrationId);

    if (!integration) {
      return c.json({ error: 'Integration not found' }, 404);
    }

    // Verify ownership for non-public integrations
    if (integration.visibility !== 'public') {
      const developerService = new DeveloperService(c.env);
      const developer = await developerService.getDeveloperByUserId(payload.userId as string);
      if (!developer || integration.developer_id !== developer.id) {
        return c.json({ error: 'Forbidden' }, 403);
      }
    }

    return c.json({ integration });
  } catch (error) {
    logger.error('Get integration error:', error);
    return c.json({ error: 'Failed to get integration' }, 500);
  }
});

/**
 * PATCH /custom-integrations/:id
 * Update custom integration
 */
app.patch('/:id', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId as string);
    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const integrationId = c.req.param('id');
    const body = await c.req.json();
    const integrationService = new CustomIntegrationService(c.env);

    const result = await integrationService.updateIntegration(integrationId, developer.id, {
      integration_name: body.integration_name,
      integration_description: body.integration_description,
      integration_version: body.integration_version,
      code_bundle: body.code_bundle,
      manifest: body.manifest,
      visibility: body.visibility,
      pricing_model: body.pricing_model,
      price_usd: body.price_usd,
    }) as any;

    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({ success: true, integration: result.integration });
  } catch (error) {
    logger.error('Update integration error:', error);
    return c.json({ error: 'Failed to update integration' }, 500);
  }
});

/**
 * DELETE /custom-integrations/:id
 * Delete custom integration
 */
app.delete('/:id', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId as string);
    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const integrationId = c.req.param('id');
    const integrationService = new CustomIntegrationService(c.env);

    const success = await integrationService.deleteIntegration(integrationId, developer.id);
    if (!success) {
      return c.json({ error: 'Cannot delete integration with active installs' }, 400);
    }

    return c.json({ success: true });
  } catch (error) {
    logger.error('Delete integration error:', error);
    return c.json({ error: 'Failed to delete integration' }, 500);
  }
});

// ============================================================
// MARKETPLACE OPERATIONS
// ============================================================

/**
 * POST /custom-integrations/:id/submit
 * Submit integration for marketplace review
 */
app.post('/:id/submit', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId as string);
    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    // Check tier - only Pro+ can submit to marketplace
    if (developer.developer_tier === 'free') {
      return c.json({
        error: 'Marketplace submission requires Pro or Enterprise tier',
        upgrade_url: '/developers/upgrade',
      }, 403);
    }

    const integrationId = c.req.param('id');
    const integrationService = new CustomIntegrationService(c.env);

    const result = await integrationService.submitForReview(integrationId, developer.id);
    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({ success: true, message: 'Integration submitted for review' });
  } catch (error) {
    logger.error('Submit integration error:', error);
    return c.json({ error: 'Failed to submit integration' }, 500);
  }
});

/**
 * GET /custom-integrations/marketplace
 * Browse marketplace integrations
 */
app.get('/marketplace', async (c) => {
  try {
    const integrationService = new CustomIntegrationService(c.env);
    const integrations = await integrationService.listMarketplaceIntegrations({
      category: c.req.query('category'),
      search: c.req.query('search'),
      limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 20,
      offset: c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0,
    });

    return c.json({ integrations });
  } catch (error) {
    logger.error('Browse marketplace error:', error);
    return c.json({ error: 'Failed to browse marketplace' }, 500);
  }
});

// ============================================================
// ANALYTICS
// ============================================================

/**
 * GET /custom-integrations/:id/analytics
 * Get integration analytics
 */
app.get('/:id/analytics', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const developerService = new DeveloperService(c.env);
    const developer = await developerService.getDeveloperByUserId(payload.userId as string);
    if (!developer) {
      return c.json({ error: 'Developer profile not found' }, 404);
    }

    const integrationId = c.req.param('id');
    const integrationService = new CustomIntegrationService(c.env);
    const integration = await integrationService.getIntegrationById(integrationId);

    if (!integration || integration.developer_id !== developer.id) {
      return c.json({ error: 'Forbidden' }, 403);
    }

    const timeframe = (c.req.query('timeframe') as '7d' | '30d' | '90d') || '30d';
    const analyticsService = new AnalyticsService(c.env);
    const analytics = await analyticsService.getIntegrationAnalytics(integrationId, timeframe);

    return c.json({ analytics });
  } catch (error) {
    logger.error('Get integration analytics error:', error);
    return c.json({ error: 'Failed to get analytics' }, 500);
  }
});

// ============================================================
// OAUTH HELPERS
// ============================================================

/**
 * POST /custom-integrations/:key/oauth/authorize
 * Initiate OAuth2 authorization flow
 */
app.post('/:key/oauth/authorize', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const integrationKey = c.req.param('key');
    const body = await c.req.json();

    const oauthService = new OAuthHelperService(c.env);
    const result = await oauthService.initiateAuthorization({
      integration_key: integrationKey,
      business_id: payload.businessId,
      redirect_uri: body.redirect_uri,
      install_id: body.install_id,
      additional_params: body.additional_params,
    });

    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      success: true,
      authorization_url: result.authorization_url,
      state: result.state,
    });
  } catch (error) {
    logger.error('OAuth authorization error:', error);
    return c.json({ error: 'Failed to initiate OAuth flow' }, 500);
  }
});

/**
 * POST /custom-integrations/:key/oauth/callback
 * Handle OAuth2 callback and exchange code for token
 */
app.post('/:key/oauth/callback', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const body = await c.req.json();
    const oauthService = new OAuthHelperService(c.env);

    const result = await oauthService.exchangeCodeForToken({
      code: body.code,
      state: body.state,
      redirect_uri: body.redirect_uri,
    });

    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      success: true,
      connection_id: result.connection_id,
      expires_at: result.expires_at,
    });
  } catch (error) {
    logger.error('OAuth callback error:', error);
    return c.json({ error: 'Failed to complete OAuth flow' }, 500);
  }
});

/**
 * POST /custom-integrations/oauth/:connection_id/refresh
 * Refresh OAuth access token
 */
app.post('/oauth/:connection_id/refresh', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
    if (!payload) {
      return c.json({ error: 'Invalid token' }, 401);
    }

    const connectionId = c.req.param('connection_id');
    const oauthService = new OAuthHelperService(c.env);

    const result = await oauthService.refreshAccessToken({ connection_id: connectionId });
    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    return c.json({
      success: true,
      expires_at: result.expires_at,
    });
  } catch (error) {
    logger.error('OAuth refresh error:', error);
    return c.json({ error: 'Failed to refresh token' }, 500);
  }
});

export default app;
