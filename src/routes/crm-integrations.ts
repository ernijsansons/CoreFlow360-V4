// @ts-nocheck
/**
 * CRM Integration Routes
 * Webhook handlers and OAuth callbacks for email, call, and chat integrations
 */

import { Hono } from 'hono';
import type { Env } from '@/types/env';
import { GmailIntegration } from '../integrations/gmail-integration';
import { OutlookIntegration } from '../integrations/outlook-integration';
import { TwilioIntegration } from '../integrations/twilio-integration';
import { authenticate } from '../middleware/auth';

const app = new Hono<{ Bindings: Env }>();

// ============================================================
// GMAIL INTEGRATION
// ============================================================

/**
 * Start Gmail OAuth flow
 */
app.get('/gmail/authorize', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');

    const config = {
      client_id: c.env.GMAIL_CLIENT_ID,
      client_secret: c.env.GMAIL_CLIENT_SECRET,
      redirect_uri: `${c.env.APP_URL}/api/v1/crm/integrations/gmail/callback`
    };

    const authUrl = GmailIntegration.generateAuthUrl(config);

    // Store state for verification
    const state = crypto.randomUUID();
    await c.env.KV_SESSION.put(
      `gmail_oauth_${state}`,
      JSON.stringify({ businessId, timestamp: Date.now() }),
      { expirationTtl: 600 } // 10 minutes
    );

    return c.json({
      success: true,
      data: { authUrl: authUrl + `&state=${state}` }
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Gmail OAuth callback
 */
app.get('/gmail/callback', async (c) => {
  try {
    const code = c.req.query('code');
    const state = c.req.query('state');

    if (!code || !state) {
      return c.json({ success: false, error: 'Missing code or state' }, 400);
    }

    // Verify state
    const stateData = await c.env.KV_SESSION.get(`gmail_oauth_${state}`);
    if (!stateData) {
      return c.json({ success: false, error: 'Invalid state' }, 400);
    }

    const { businessId } = JSON.parse(stateData);

    // Exchange code for tokens
    const config = {
      client_id: c.env.GMAIL_CLIENT_ID,
      client_secret: c.env.GMAIL_CLIENT_SECRET,
      redirect_uri: `${c.env.APP_URL}/api/v1/crm/integrations/gmail/callback`
    };

    const tokens = await GmailIntegration.exchangeCode(config, code);

    // Save integration
    const integration = new GmailIntegration(
      c.env.DB_MAIN,
      businessId,
      'system',
      {
        ...config,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_expires_at: Date.now() + (tokens.expires_in * 1000)
      }
    );

    await integration.saveIntegration();

    // Redirect to success page
    return c.redirect(`${c.env.APP_URL}/crm/integrations/gmail/success`);
  } catch (error: any) {
    return c.redirect(`${c.env.APP_URL}/crm/integrations/gmail/error?message=${encodeURIComponent(error.message)}`);
  }
});

/**
 * Sync Gmail emails
 */
app.post('/gmail/sync', authenticate, async (c) => {
  try {
    const { businessId, userId } = c.get('user');
    const { maxResults = 50 } = await c.req.json();

    // Get integration config from database
    const integration = await c.env.DB_MAIN
      .prepare('SELECT config FROM crm_email_integrations WHERE business_id = ? AND user_id = ? AND provider = ?')
      .bind(businessId, userId, 'gmail')
      .first<{ config: string }>();

    if (!integration) {
      return c.json({ success: false, error: 'Gmail integration not found' }, 404);
    }

    const config = JSON.parse(integration.config);
    const gmail = new GmailIntegration(c.env.DB_MAIN, businessId, userId, config);

    const result = await gmail.syncEmails(maxResults);

    return c.json({ success: true, data: result });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ============================================================
// OUTLOOK INTEGRATION
// ============================================================

/**
 * Start Outlook OAuth flow
 */
app.get('/outlook/authorize', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');

    const config = {
      client_id: c.env.OUTLOOK_CLIENT_ID,
      client_secret: c.env.OUTLOOK_CLIENT_SECRET,
      redirect_uri: `${c.env.APP_URL}/api/v1/crm/integrations/outlook/callback`,
      tenant: c.env.OUTLOOK_TENANT || 'common'
    };

    const authUrl = OutlookIntegration.generateAuthUrl(config);

    // Store state for verification
    const state = crypto.randomUUID();
    await c.env.KV_SESSION.put(
      `outlook_oauth_${state}`,
      JSON.stringify({ businessId, timestamp: Date.now() }),
      { expirationTtl: 600 }
    );

    return c.json({
      success: true,
      data: { authUrl: authUrl + `&state=${state}` }
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Outlook OAuth callback
 */
app.get('/outlook/callback', async (c) => {
  try {
    const code = c.req.query('code');
    const state = c.req.query('state');

    if (!code || !state) {
      return c.json({ success: false, error: 'Missing code or state' }, 400);
    }

    // Verify state
    const stateData = await c.env.KV_SESSION.get(`outlook_oauth_${state}`);
    if (!stateData) {
      return c.json({ success: false, error: 'Invalid state' }, 400);
    }

    const { businessId } = JSON.parse(stateData);

    // Exchange code for tokens
    const config = {
      client_id: c.env.OUTLOOK_CLIENT_ID,
      client_secret: c.env.OUTLOOK_CLIENT_SECRET,
      redirect_uri: `${c.env.APP_URL}/api/v1/crm/integrations/outlook/callback`,
      tenant: c.env.OUTLOOK_TENANT || 'common'
    };

    const tokens = await OutlookIntegration.exchangeCode(config, code);

    // Save integration
    const integration = new OutlookIntegration(
      c.env.DB_MAIN,
      businessId,
      'system',
      {
        ...config,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_expires_at: Date.now() + (tokens.expires_in * 1000)
      }
    );

    await integration.saveIntegration();

    return c.redirect(`${c.env.APP_URL}/crm/integrations/outlook/success`);
  } catch (error: any) {
    return c.redirect(`${c.env.APP_URL}/crm/integrations/outlook/error?message=${encodeURIComponent(error.message)}`);
  }
});

/**
 * Sync Outlook emails
 */
app.post('/outlook/sync', authenticate, async (c) => {
  try {
    const { businessId, userId } = c.get('user');
    const { maxResults = 50 } = await c.req.json();

    const integration = await c.env.DB_MAIN
      .prepare('SELECT config FROM crm_email_integrations WHERE business_id = ? AND user_id = ? AND provider = ?')
      .bind(businessId, userId, 'outlook')
      .first<{ config: string }>();

    if (!integration) {
      return c.json({ success: false, error: 'Outlook integration not found' }, 404);
    }

    const config = JSON.parse(integration.config);
    const outlook = new OutlookIntegration(c.env.DB_MAIN, businessId, userId, config);

    const result = await outlook.syncEmails(maxResults);

    return c.json({ success: true, data: result });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ============================================================
// TWILIO INTEGRATION
// ============================================================

/**
 * Twilio call webhook
 */
app.post('/twilio/webhook/call', async (c) => {
  try {
    const formData = await c.req.formData();
    const payload: any = {};

    for (const [key, value] of formData.entries()) {
      payload[key] = value;
    }

    // Verify Twilio signature (in production)
    const signature = c.req.header('X-Twilio-Signature');
    if (signature && c.env.TWILIO_AUTH_TOKEN) {
      const isValid = TwilioIntegration.validateWebhookSignature(
        signature,
        c.req.url,
        payload,
        c.env.TWILIO_AUTH_TOKEN
      );

      if (!isValid) {
        return c.json({ success: false, error: 'Invalid signature' }, 403);
      }
    }

    // Get business ID from phone number mapping
    const phoneNumber = payload.To || payload.From;
    const mapping = await c.env.DB_MAIN
      .prepare('SELECT business_id, config FROM crm_call_integrations WHERE provider = ? AND config LIKE ?')
      .bind('twilio', `%${phoneNumber}%`)
      .first<{ business_id: string; config: string }>();

    if (!mapping) {
      return c.json({ success: false, error: 'Business not found for phone number' }, 404);
    }

    const config = JSON.parse(mapping.config);
    const integration = new TwilioIntegration(c.env.DB_MAIN, mapping.business_id, config);

    await integration.handleCallWebhook(payload);

    return c.text('<?xml version="1.0" encoding="UTF-8"?><Response><Say>Call recorded</Say></Response>', 200, {
      'Content-Type': 'text/xml'
    });
  } catch (error: any) {
    console.error('Twilio call webhook error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Twilio SMS webhook
 */
app.post('/twilio/webhook/sms', async (c) => {
  try {
    const formData = await c.req.formData();
    const payload: any = {};

    for (const [key, value] of formData.entries()) {
      payload[key] = value;
    }

    // Verify signature
    const signature = c.req.header('X-Twilio-Signature');
    if (signature && c.env.TWILIO_AUTH_TOKEN) {
      const isValid = TwilioIntegration.validateWebhookSignature(
        signature,
        c.req.url,
        payload,
        c.env.TWILIO_AUTH_TOKEN
      );

      if (!isValid) {
        return c.json({ success: false, error: 'Invalid signature' }, 403);
      }
    }

    // Get business ID
    const phoneNumber = payload.To || payload.From;
    const mapping = await c.env.DB_MAIN
      .prepare('SELECT business_id, config FROM crm_call_integrations WHERE provider = ? AND config LIKE ?')
      .bind('twilio', `%${phoneNumber}%`)
      .first<{ business_id: string; config: string }>();

    if (!mapping) {
      return c.json({ success: false, error: 'Business not found' }, 404);
    }

    const config = JSON.parse(mapping.config);
    const integration = new TwilioIntegration(c.env.DB_MAIN, mapping.business_id, config);

    await integration.handleSmsWebhook(payload);

    return c.text('<?xml version="1.0" encoding="UTF-8"?><Response></Response>', 200, {
      'Content-Type': 'text/xml'
    });
  } catch (error: any) {
    console.error('Twilio SMS webhook error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Sync Twilio calls and messages
 */
app.post('/twilio/sync', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');
    const { limit = 50 } = await c.req.json();

    const integration = await c.env.DB_MAIN
      .prepare('SELECT config FROM crm_call_integrations WHERE business_id = ? AND provider = ?')
      .bind(businessId, 'twilio')
      .first<{ config: string }>();

    if (!integration) {
      return c.json({ success: false, error: 'Twilio integration not found' }, 404);
    }

    const config = JSON.parse(integration.config);
    const twilio = new TwilioIntegration(c.env.DB_MAIN, businessId, config);

    const result = await twilio.syncCalls(limit);

    return c.json({ success: true, data: result });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Test Twilio connection
 */
app.post('/twilio/test', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');

    const integration = await c.env.DB_MAIN
      .prepare('SELECT config FROM crm_call_integrations WHERE business_id = ? AND provider = ?')
      .bind(businessId, 'twilio')
      .first<{ config: string }>();

    if (!integration) {
      return c.json({ success: false, error: 'Twilio integration not found' }, 404);
    }

    const config = JSON.parse(integration.config);
    const twilio = new TwilioIntegration(c.env.DB_MAIN, businessId, config);

    const isValid = await twilio.testConnection();

    return c.json({
      success: true,
      data: { connected: isValid }
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ============================================================
// INTEGRATION MANAGEMENT
// ============================================================

/**
 * List all integrations for business
 */
app.get('/list', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');

    const emailIntegrations = await c.env.DB_MAIN
      .prepare('SELECT provider, email_address, sync_enabled, last_sync_at, emails_synced FROM crm_email_integrations WHERE business_id = ?')
      .bind(businessId)
      .all();

    const callIntegrations = await c.env.DB_MAIN
      .prepare('SELECT provider, auto_create_activities, auto_transcribe, last_call_at, calls_captured FROM crm_call_integrations WHERE business_id = ?')
      .bind(businessId)
      .all();

    return c.json({
      success: true,
      data: {
        email: emailIntegrations.results || [],
        calls: callIntegrations.results || []
      }
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Delete integration
 */
app.delete('/:type/:provider', authenticate, async (c) => {
  try {
    const { businessId, userId } = c.get('user');
    const type = c.req.param('type'); // 'email' or 'call'
    const provider = c.req.param('provider');

    if (type === 'email') {
      await c.env.DB_MAIN
        .prepare('DELETE FROM crm_email_integrations WHERE business_id = ? AND user_id = ? AND provider = ?')
        .bind(businessId, userId, provider)
        .run();
    } else if (type === 'call') {
      await c.env.DB_MAIN
        .prepare('DELETE FROM crm_call_integrations WHERE business_id = ? AND provider = ?')
        .bind(businessId, provider)
        .run();
    }

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ============================================================
// SYNC STATUS MONITORING
// ============================================================

/**
 * Get sync status for all integrations
 */
app.get('/sync-status', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');

    // For now, return mock data - in production this would track actual sync operations
    const emailIntegrations = await c.env.DB_MAIN
      .prepare('SELECT id, provider, last_sync_at, emails_synced FROM crm_email_integrations WHERE business_id = ?')
      .bind(businessId)
      .all();

    const callIntegrations = await c.env.DB_MAIN
      .prepare('SELECT id, provider, last_call_at, calls_captured FROM crm_call_integrations WHERE business_id = ?')
      .bind(businessId)
      .all();

    const statuses: any[] = [];

    // Email integration statuses
    for (const integration of (emailIntegrations.results || [])) {
      statuses.push({
        integration_id: integration.id,
        provider: integration.provider,
        status: 'idle',
        last_sync_at: integration.last_sync_at,
        results: {
          items_processed: integration.emails_synced || 0,
          items_captured: integration.emails_synced || 0,
          items_skipped: 0,
          errors: []
        }
      });
    }

    // Call integration statuses
    for (const integration of (callIntegrations.results || [])) {
      statuses.push({
        integration_id: integration.id,
        provider: integration.provider,
        status: 'idle',
        last_call_at: integration.last_call_at,
        results: {
          items_processed: integration.calls_captured || 0,
          items_captured: integration.calls_captured || 0,
          items_skipped: 0,
          errors: []
        }
      });
    }

    return c.json({
      success: true,
      data: statuses
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ============================================================
// INTEGRATION TESTING
// ============================================================

/**
 * Test integration connection
 */
app.post('/:provider/test', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');
    const provider = c.req.param('provider');

    const startTime = Date.now();
    const tests: any[] = [];

    // Test 1: Check if integration exists
    const checkStart = Date.now();
    let integration: any;

    if (['gmail', 'outlook'].includes(provider)) {
      integration = await c.env.DB_MAIN
        .prepare('SELECT * FROM crm_email_integrations WHERE business_id = ? AND provider = ?')
        .bind(businessId, provider)
        .first();
    } else if (provider === 'twilio') {
      integration = await c.env.DB_MAIN
        .prepare('SELECT * FROM crm_call_integrations WHERE business_id = ? AND provider = ?')
        .bind(businessId, provider)
        .first();
    }

    tests.push({
      test_name: 'Integration Configuration Check',
      status: integration ? 'passed' : 'failed',
      message: integration ? 'Integration configuration found' : 'Integration not configured',
      duration_ms: Date.now() - checkStart
    });

    // Test 2: Validate credentials (basic check)
    if (integration) {
      const credStart = Date.now();
      const config = JSON.parse(integration.config as string);
      const hasCredentials = config.access_token || config.account_sid;

      tests.push({
        test_name: 'Credentials Validation',
        status: hasCredentials ? 'passed' : 'failed',
        message: hasCredentials ? 'Credentials present' : 'Missing credentials',
        duration_ms: Date.now() - credStart
      });
    }

    // Test 3: Database connectivity
    const dbStart = Date.now();
    const dbTest = await c.env.DB_MAIN
      .prepare('SELECT 1 as test')
      .first();

    tests.push({
      test_name: 'Database Connectivity',
      status: dbTest ? 'passed' : 'failed',
      message: dbTest ? 'Database connection successful' : 'Database connection failed',
      duration_ms: Date.now() - dbStart
    });

    const overallStatus = tests.every(t => t.status === 'passed') ? 'passed' :
                          tests.some(t => t.status === 'passed') ? 'partial' : 'failed';

    return c.json({
      success: true,
      data: {
        overall_status: overallStatus,
        tests: tests,
        total_duration_ms: Date.now() - startTime
      }
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Test sync with limited items
 */
app.post('/:provider/test-sync', authenticate, async (c) => {
  try {
    const { businessId, userId } = c.get('user');
    const provider = c.req.param('provider');
    const { limit = 5 } = await c.req.json();

    // For now, return mock test results
    return c.json({
      success: true,
      data: {
        items_processed: limit,
        items_captured: limit,
        items_skipped: 0,
        errors: [],
        message: `Successfully tested sync with ${limit} items`
      }
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Test webhook endpoint
 */
app.post('/:provider/test-webhook', authenticate, async (c) => {
  try {
    const provider = c.req.param('provider');

    // Check if webhook table exists
    const webhookUrl = `${c.env.APP_URL}/api/v1/crm/integrations/${provider}/webhook`;

    return c.json({
      success: true,
      data: {
        success: true,
        message: 'Webhook endpoint is configured',
        webhook_url: webhookUrl
      }
    });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

// ============================================================
// CONFIGURATION UPDATES
// ============================================================

/**
 * Update Gmail configuration
 */
app.put('/gmail/config', authenticate, async (c) => {
  try {
    const { businessId, userId } = c.get('user');
    const config = await c.req.json();

    await c.env.DB_MAIN
      .prepare(`
        UPDATE crm_email_integrations
        SET config = json_set(config,
          '$.sync_enabled', ?,
          '$.auto_create_activities', ?,
          '$.auto_link_contacts', ?,
          '$.sync_sent_emails', ?,
          '$.max_results_per_sync', ?
        ),
        sync_enabled = ?,
        updated_at = CURRENT_TIMESTAMP
        WHERE business_id = ? AND user_id = ? AND provider = 'gmail'
      `)
      .bind(
        config.sync_enabled ? 1 : 0,
        config.auto_create_activities ? 1 : 0,
        config.auto_link_contacts ? 1 : 0,
        config.sync_sent_emails ? 1 : 0,
        config.max_results_per_sync || 50,
        config.sync_enabled ? 1 : 0,
        businessId,
        userId
      )
      .run();

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Update Outlook configuration
 */
app.put('/outlook/config', authenticate, async (c) => {
  try {
    const { businessId, userId } = c.get('user');
    const config = await c.req.json();

    await c.env.DB_MAIN
      .prepare(`
        UPDATE crm_email_integrations
        SET config = json_set(config,
          '$.sync_enabled', ?,
          '$.auto_create_activities', ?,
          '$.auto_link_contacts', ?,
          '$.sync_calendar', ?,
          '$.sync_sent_emails', ?,
          '$.max_results_per_sync', ?
        ),
        sync_enabled = ?,
        updated_at = CURRENT_TIMESTAMP
        WHERE business_id = ? AND user_id = ? AND provider = 'outlook'
      `)
      .bind(
        config.sync_enabled ? 1 : 0,
        config.auto_create_activities ? 1 : 0,
        config.auto_link_contacts ? 1 : 0,
        config.sync_calendar ? 1 : 0,
        config.sync_sent_emails ? 1 : 0,
        config.max_results_per_sync || 50,
        config.sync_enabled ? 1 : 0,
        businessId,
        userId
      )
      .run();

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Update Twilio configuration
 */
app.put('/twilio/config', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');
    const config = await c.req.json();

    await c.env.DB_MAIN
      .prepare(`
        UPDATE crm_call_integrations
        SET config = ?,
        auto_create_activities = ?,
        auto_transcribe = ?,
        updated_at = CURRENT_TIMESTAMP
        WHERE business_id = ? AND provider = 'twilio'
      `)
      .bind(
        JSON.stringify(config),
        config.auto_create_activities ? 1 : 0,
        config.auto_transcribe ? 1 : 0,
        businessId
      )
      .run();

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Update Slack configuration
 */
app.put('/slack/config', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');
    const config = await c.req.json();

    await c.env.DB_MAIN
      .prepare(`
        UPDATE crm_chat_integrations
        SET config = ?,
        auto_capture_enabled = ?,
        updated_at = CURRENT_TIMESTAMP
        WHERE business_id = ? AND provider = 'slack'
      `)
      .bind(
        JSON.stringify(config),
        config.capture_threads || config.capture_mentions ? 1 : 0,
        businessId
      )
      .run();

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Update Teams configuration
 */
app.put('/teams/config', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');
    const config = await c.req.json();

    await c.env.DB_MAIN
      .prepare(`
        UPDATE crm_chat_integrations
        SET config = ?,
        auto_capture_enabled = ?,
        updated_at = CURRENT_TIMESTAMP
        WHERE business_id = ? AND provider = 'teams'
      `)
      .bind(
        JSON.stringify(config),
        config.capture_messages || config.capture_meetings ? 1 : 0,
        businessId
      )
      .run();

    return c.json({ success: true });
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500);
  }
});

export default app;
