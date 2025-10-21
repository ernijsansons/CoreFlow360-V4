/**
 * OAuth Helper Service for Custom Integrations
 * Handles OAuth2 authorization flows with PKCE support
 * Manages token refresh, revocation, and secure storage
 */

import { Logger } from '../../shared/logger';
import type { Env } from '../../types/env';

const logger = new Logger({ component: 'oauth-helper-service' });
import type {
  OAuthConnection,
  OAuthAuthorizationRequest,
  OAuthAuthorizationResponse,
  OAuthTokenExchangeRequest,
  OAuthTokenExchangeResponse,
  OAuthRefreshTokenRequest,
  OAuthRefreshTokenResponse,
  OAuthRevokeTokenRequest,
  CustomIntegration,
  CustomIntegrationInstall,
} from './developer.types';
import type { IntegrationManifest } from './developer.types';

/**
 * OAuth Helper Service
 * Simplifies OAuth2 flows for custom integrations
 */
export class OAuthHelperService {
  private logger = new Logger('OAuthHelperService');

  constructor(private env: Env) {}

  /**
   * Initiate OAuth2 Authorization Flow
   * Generates authorization URL with PKCE
   */
  async initiateAuthorization(
    request: OAuthAuthorizationRequest
  ): Promise<OAuthAuthorizationResponse> {
    try {
      // 1. Get integration details
      const integration = await this.getIntegrationByKey(request.integration_key);
      if (!integration) {
        return {
          success: false,
          error: 'Integration not found',
        };
      }

      // 2. Validate OAuth configuration
      const manifest = JSON.parse(integration.manifest) as IntegrationManifest;
      const authConfig = manifest.auth;
      if (authConfig.type !== 'oauth2') {
        return {
          success: false,
          error: 'Integration does not support OAuth2',
        };
      }

      if (!authConfig.oauth_config?.authorization_url || !authConfig.oauth_config?.scopes) {
        return {
          success: false,
          error: 'Invalid OAuth configuration in integration manifest',
        };
      }

      // 3. Generate PKCE challenge
      const codeVerifier = this.generateCodeVerifier();
      const codeChallenge = await this.generateCodeChallenge(codeVerifier);

      // 4. Generate state for CSRF protection
      const state = this.generateState();

      // 5. Store PKCE values temporarily (10 minutes)
      const pkceKey = `oauth:pkce:${state}`;
      await this.env.KV_CACHE.put(
        pkceKey,
        JSON.stringify({
          code_verifier: codeVerifier,
          business_id: request.business_id,
          integration_key: request.integration_key,
          install_id: request.install_id,
        }),
        { expirationTtl: 600 } // 10 minutes
      );

      // 6. Build authorization URL
      const authUrl = new URL(authConfig.oauth_config.authorization_url);
      authUrl.searchParams.set('client_id', authConfig.oauth_config.client_id);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('redirect_uri', request.redirect_uri);
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('scope', authConfig.oauth_config.scopes.join(' '));
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      // Add optional parameters
      if (request.additional_params) {
        Object.entries(request.additional_params).forEach(([key, value]) => {
          authUrl.searchParams.set(key, value);
        });
      }

      return {
        success: true,
        authorization_url: authUrl.toString(),
        state,
      };
    } catch (error) {
      logger.error('OAuth authorization initiation error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Authorization failed',
      };
    }
  }

  /**
   * Exchange Authorization Code for Access Token
   * Completes OAuth2 flow with PKCE verification
   */
  async exchangeCodeForToken(
    request: OAuthTokenExchangeRequest
  ): Promise<OAuthTokenExchangeResponse> {
    try {
      // 1. Retrieve PKCE data from state
      const pkceKey = `oauth:pkce:${request.state}`;
      const pkceDataStr = await this.env.KV_CACHE.get(pkceKey);
      if (!pkceDataStr) {
        return {
          success: false,
          error: 'Invalid or expired state parameter',
        };
      }

      const pkceData = JSON.parse(pkceDataStr);

      // 2. Get integration
      const integration = await this.getIntegrationByKey(pkceData.integration_key);
      if (!integration) {
        return {
          success: false,
          error: 'Integration not found',
        };
      }

      const manifest = JSON.parse(integration.manifest) as IntegrationManifest;
      const authConfig = manifest.auth;

      if (!authConfig.oauth_config?.token_url) {
        return {
          success: false,
          error: 'Token URL not configured',
        };
      }

      // 3. Exchange code for token
      const tokenResponse = await fetch(authConfig.oauth_config.token_url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: request.code,
          redirect_uri: request.redirect_uri,
          client_id: authConfig.oauth_config.client_id,
          client_secret: authConfig.oauth_config.client_secret,
          code_verifier: pkceData.code_verifier,
        }),
      });

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        return {
          success: false,
          error: `Token exchange failed: ${errorText}`,
        };
      }

      const tokenData = await tokenResponse.json() as any;

      // 4. Calculate token expiration
      const expiresAt = tokenData.expires_in
        ? new Date(Date.now() + tokenData.expires_in * 1000).toISOString()
        : null;

      // 5. Get or create install
      let install: CustomIntegrationInstall | null = null;
      if (pkceData.install_id) {
        install = await this.getInstall(pkceData.install_id);
      }

      // 6. Store OAuth connection
      const connectionId = await this.storeOAuthConnection({
        custom_integration_install_id: install?.id || '',
        custom_integration_id: integration.id,
        business_id: pkceData.business_id,
        authorization_code: request.code,
        state: request.state,
        code_verifier: pkceData.code_verifier,
        code_challenge: '', // Already used
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        token_type: tokenData.token_type || 'Bearer',
        expires_at: expiresAt || undefined,
        scopes: tokenData.scope ? tokenData.scope.split(' ') : authConfig.oauth_config.scopes,
        provider_user_id: tokenData.user_id,
        provider_account_info: JSON.stringify(tokenData),
        connection_status: 'active',
      });

      // 7. Update install with OAuth tokens
      if (install) {
        await this.updateInstallOAuthTokens(install.id, {
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token,
          expires_at: expiresAt,
          scopes: tokenData.scope ? tokenData.scope.split(' ') : authConfig.oauth_config.scopes,
        });
      }

      // 8. Clean up PKCE data
      await this.env.KV_CACHE.delete(pkceKey);

      return {
        success: true,
        connection_id: connectionId,
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        expires_at: expiresAt,
        token_type: tokenData.token_type || 'Bearer',
        scopes: tokenData.scope ? tokenData.scope.split(' ') : authConfig.oauth_config.scopes,
      };
    } catch (error) {
      logger.error('OAuth token exchange error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Token exchange failed',
      };
    }
  }

  /**
   * Refresh Access Token
   * Uses refresh token to obtain new access token
   */
  async refreshAccessToken(
    request: OAuthRefreshTokenRequest
  ): Promise<OAuthRefreshTokenResponse> {
    try {
      // 1. Get OAuth connection
      const connection = await this.getOAuthConnection(request.connection_id);
      if (!connection) {
        return {
          success: false,
          error: 'OAuth connection not found',
        };
      }

      if (!connection.refresh_token) {
        return {
          success: false,
          error: 'No refresh token available',
        };
      }

      // 2. Get integration for OAuth config
      const integration = await this.getIntegration(connection.custom_integration_id);
      if (!integration) {
        return {
          success: false,
          error: 'Integration not found',
        };
      }

      const manifest = JSON.parse(integration.manifest) as IntegrationManifest;
      const authConfig = manifest.auth;

      if (!authConfig.oauth_config?.token_url) {
        return {
          success: false,
          error: 'Token URL not configured',
        };
      }

      // 3. Request new access token
      const tokenResponse = await fetch(authConfig.oauth_config.token_url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: connection.refresh_token,
          client_id: authConfig.oauth_config.client_id,
          client_secret: authConfig.oauth_config.client_secret,
        }),
      });

      if (!tokenResponse.ok) {
        // Handle expired/revoked refresh token
        await this.updateConnectionStatus(connection.id, 'expired');
        const errorText = await tokenResponse.text();
        return {
          success: false,
          error: `Token refresh failed: ${errorText}`,
        };
      }

      const tokenData = await tokenResponse.json() as any;

      // 4. Calculate new expiration
      const expiresAt = tokenData.expires_in
        ? new Date(Date.now() + tokenData.expires_in * 1000).toISOString()
        : null;

      // 5. Update OAuth connection
      await this.updateOAuthTokens(connection.id, {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token || connection.refresh_token,
        expires_at: expiresAt,
      });

      // 6. Update install if linked
      if (connection.custom_integration_install_id) {
        await this.updateInstallOAuthTokens(connection.custom_integration_install_id, {
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token || connection.refresh_token,
          expires_at: expiresAt,
          scopes: connection.scopes ? JSON.parse(connection.scopes) : [],
        });
      }

      return {
        success: true,
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token || connection.refresh_token,
        expires_at: expiresAt,
        token_type: tokenData.token_type || 'Bearer',
      };
    } catch (error) {
      logger.error('OAuth token refresh error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Token refresh failed',
      };
    }
  }

  /**
   * Revoke OAuth Token
   * Revokes access/refresh token at provider
   */
  async revokeToken(request: OAuthRevokeTokenRequest): Promise<{ success: boolean; error?: string }> {
    try {
      // 1. Get OAuth connection
      const connection = await this.getOAuthConnection(request.connection_id);
      if (!connection) {
        return {
          success: false,
          error: 'OAuth connection not found',
        };
      }

      // 2. Get integration for revocation endpoint
      const integration = await this.getIntegration(connection.custom_integration_id);
      if (!integration) {
        return {
          success: false,
          error: 'Integration not found',
        };
      }

      const manifest = JSON.parse(integration.manifest) as IntegrationManifest;
      const authConfig = manifest.auth;

      // 3. Revoke at provider if endpoint available
      if (authConfig.oauth_config?.revoke_url) {
        const token = request.token_type === 'refresh'
          ? connection.refresh_token
          : connection.access_token;

        if (token) {
          await fetch(authConfig.oauth_config.revoke_url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
              token,
              token_type_hint: request.token_type === 'refresh' ? 'refresh_token' : 'access_token',
              client_id: authConfig.oauth_config.client_id,
              client_secret: authConfig.oauth_config.client_secret,
            }),
          });
        }
      }

      // 4. Update connection status
      await this.updateConnectionStatus(connection.id, 'revoked');

      return {
        success: true,
      };
    } catch (error) {
      logger.error('OAuth token revocation error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Token revocation failed',
      };
    }
  }

  /**
   * Check if Token Needs Refresh
   * Returns true if token expires within 5 minutes
   */
  async needsRefresh(connectionId: string): Promise<boolean> {
    const connection = await this.getOAuthConnection(connectionId);
    if (!connection || !connection.expires_at) {
      return false;
    }

    const expiresAt = new Date(connection.expires_at).getTime();
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000;

    return expiresAt - now < fiveMinutes;
  }

  /**
   * Auto-Refresh Token if Needed
   * Checks expiration and refreshes automatically
   */
  async autoRefreshIfNeeded(connectionId: string): Promise<boolean> {
    if (await this.needsRefresh(connectionId)) {
      const result = await this.refreshAccessToken({ connection_id: connectionId });
      return result.success;
    }
    return true; // No refresh needed
  }

  // ============================================================
  // PRIVATE HELPER METHODS
  // ============================================================

  /**
   * Generate PKCE Code Verifier
   * Random 43-128 character string
   */
  private generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return this.base64UrlEncode(array);
  }

  /**
   * Generate PKCE Code Challenge
   * SHA-256 hash of code verifier
   */
  private async generateCodeChallenge(verifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return this.base64UrlEncode(new Uint8Array(hashBuffer));
  }

  /**
   * Base64 URL Encoding
   * RFC 7636 compliant encoding
   */
  private base64UrlEncode(buffer: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Generate Random State
   * For CSRF protection
   */
  private generateState(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return this.base64UrlEncode(array);
  }

  /**
   * Store OAuth Connection
   */
  private async storeOAuthConnection(connection: Partial<OAuthConnection>): Promise<string> {
    const id = this.generateId();

    await this.env.DB_MAIN.prepare(
      `INSERT INTO custom_integration_oauth_connections (
        id, custom_integration_install_id, custom_integration_id, business_id,
        authorization_code, state, code_verifier, code_challenge,
        access_token, refresh_token, token_type, expires_at, scopes,
        provider_user_id, provider_account_info, connection_status,
        last_refreshed_at, refresh_count, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        connection.custom_integration_install_id,
        connection.custom_integration_id,
        connection.business_id,
        connection.authorization_code,
        connection.state,
        connection.code_verifier,
        connection.code_challenge || '',
        connection.access_token,
        connection.refresh_token || null,
        connection.token_type || 'Bearer',
        connection.expires_at || null,
        JSON.stringify(connection.scopes || []),
        connection.provider_user_id || null,
        connection.provider_account_info || null,
        connection.connection_status || 'active',
        null,
        0,
        new Date().toISOString(),
        new Date().toISOString()
      )
      .run();

    return id;
  }

  /**
   * Update OAuth Tokens
   */
  private async updateOAuthTokens(
    connectionId: string,
    tokens: {
      access_token: string;
      refresh_token?: string;
      expires_at: string | null;
    }
  ): Promise<void> {
    await this.env.DB_MAIN.prepare(
      `UPDATE custom_integration_oauth_connections SET
        access_token = ?,
        refresh_token = COALESCE(?, refresh_token),
        expires_at = ?,
        last_refreshed_at = ?,
        refresh_count = refresh_count + 1,
        updated_at = ?
      WHERE id = ?`
    )
      .bind(
        tokens.access_token,
        tokens.refresh_token || null,
        tokens.expires_at,
        new Date().toISOString(),
        new Date().toISOString(),
        connectionId
      )
      .run();
  }

  /**
   * Update Connection Status
   */
  private async updateConnectionStatus(
    connectionId: string,
    status: 'active' | 'expired' | 'revoked' | 'error'
  ): Promise<void> {
    await this.env.DB_MAIN.prepare(
      'UPDATE custom_integration_oauth_connections SET connection_status = ?, updated_at = ? WHERE id = ?'
    )
      .bind(status, new Date().toISOString(), connectionId)
      .run();
  }

  /**
   * Update Install OAuth Tokens
   */
  private async updateInstallOAuthTokens(
    installId: string,
    tokens: {
      access_token: string;
      refresh_token?: string;
      expires_at: string | null;
      scopes: string[];
    }
  ): Promise<void> {
    await this.env.DB_MAIN.prepare(
      `UPDATE custom_integration_installs SET
        oauth_access_token = ?,
        oauth_refresh_token = COALESCE(?, oauth_refresh_token),
        oauth_token_expires_at = ?,
        oauth_scopes = ?,
        updated_at = ?
      WHERE id = ?`
    )
      .bind(
        tokens.access_token,
        tokens.refresh_token || null,
        tokens.expires_at,
        JSON.stringify(tokens.scopes),
        new Date().toISOString(),
        installId
      )
      .run();
  }

  /**
   * Get OAuth Connection by ID
   */
  private async getOAuthConnection(connectionId: string): Promise<OAuthConnection | null> {
    const result = await this.env.DB_MAIN.prepare(
      'SELECT * FROM custom_integration_oauth_connections WHERE id = ?'
    )
      .bind(connectionId)
      .first() as any;

    return result ? this.mapOAuthConnection(result) : null;
  }

  /**
   * Get Integration by Key
   */
  private async getIntegrationByKey(integrationKey: string): Promise<CustomIntegration | null> {
    const result = await this.env.DB_MAIN.prepare(
      'SELECT * FROM custom_integrations WHERE integration_key = ?'
    )
      .bind(integrationKey)
      .first() as any;

    return result ? this.mapIntegration(result) : null;
  }

  /**
   * Get Integration by ID
   */
  private async getIntegration(integrationId: string): Promise<CustomIntegration | null> {
    const result = await this.env.DB_MAIN.prepare(
      'SELECT * FROM custom_integrations WHERE id = ?'
    )
      .bind(integrationId)
      .first() as any;

    return result ? this.mapIntegration(result) : null;
  }

  /**
   * Get Install by ID
   */
  private async getInstall(installId: string): Promise<CustomIntegrationInstall | null> {
    const result = await this.env.DB_MAIN.prepare(
      'SELECT * FROM custom_integration_installs WHERE id = ?'
    )
      .bind(installId)
      .first() as any;

    return result ? this.mapInstall(result) : null;
  }

  /**
   * Map Database Row to OAuth Connection
   */
  private mapOAuthConnection(row: any): OAuthConnection {
    return {
      id: row.id,
      custom_integration_install_id: row.custom_integration_install_id,
      custom_integration_id: row.custom_integration_id,
      business_id: row.business_id,
      authorization_code: row.authorization_code,
      state: row.state,
      code_verifier: row.code_verifier,
      code_challenge: row.code_challenge,
      access_token: row.access_token,
      refresh_token: row.refresh_token,
      token_type: row.token_type,
      expires_at: row.expires_at,
      scopes: row.scopes,
      provider_user_id: row.provider_user_id,
      provider_account_info: row.provider_account_info,
      connection_status: row.connection_status,
      last_refreshed_at: row.last_refreshed_at,
      refresh_count: row.refresh_count,
      last_error: row.last_error,
      last_error_at: row.last_error_at,
      retry_count: row.retry_count,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  /**
   * Map Database Row to Integration
   */
  private mapIntegration(row: any): CustomIntegration {
    return {
      id: row.id,
      developer_id: row.developer_id,
      integration_key: row.integration_key,
      integration_name: row.integration_name,
      integration_description: row.integration_description,
      integration_version: row.integration_version,
      provider_logo_url: row.provider_logo_url,
      provider_website: row.provider_website,
      provider_category: row.provider_category,
      category_tags: row.category_tags,
      code_bundle: row.code_bundle,
      manifest: row.manifest,
      source_code_url: row.source_code_url,
      auth_type: row.auth_type,
      auth_config: row.auth_config,
      supported_actions: row.supported_actions,
      supported_triggers: row.supported_triggers,
      supported_entities: row.supported_entities,
      visibility: row.visibility,
      marketplace_status: row.marketplace_status,
      pricing_model: row.pricing_model,
      price_usd: row.price_usd,
      install_count: row.install_count,
      active_install_count: row.active_install_count,
      rating: row.rating,
      total_reviews: row.total_reviews,
      security_reviewed: Boolean(row.security_reviewed),
      security_review_date: row.security_review_date,
      security_reviewer_id: row.security_reviewer_id,
      data_privacy_compliant: Boolean(row.data_privacy_compliant),
      documentation_url: row.documentation_url,
      changelog_url: row.changelog_url,
      support_email: row.support_email,
      support_url: row.support_url,
      webhook_support: Boolean(row.webhook_support),
      webhook_events: row.webhook_events,
      created_at: row.created_at,
      updated_at: row.updated_at,
      published_at: row.published_at,
      last_deployed_at: row.last_deployed_at,
    };
  }

  /**
   * Map Database Row to Install
   */
  private mapInstall(row: any): CustomIntegrationInstall {
    return {
      id: row.id,
      business_id: row.business_id,
      custom_integration_id: row.custom_integration_id,
      integration_version: row.integration_version,
      credentials_encrypted: row.credentials_encrypted,
      oauth_access_token: row.oauth_access_token,
      oauth_refresh_token: row.oauth_refresh_token,
      oauth_token_expires_at: row.oauth_token_expires_at,
      oauth_scopes: row.oauth_scopes,
      settings: row.settings,
      enabled_features: row.enabled_features,
      webhook_url: row.webhook_url,
      webhook_secret: row.webhook_secret,
      webhook_events: row.webhook_events,
      total_requests: row.total_requests,
      requests_this_month: row.requests_this_month,
      last_request_at: row.last_request_at,
      install_status: row.install_status,
      error_count: row.error_count,
      last_error_message: row.last_error_message,
      last_error_at: row.last_error_at,
      installed_by: row.installed_by,
      installed_at: row.installed_at,
      uninstalled_at: row.uninstalled_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  /**
   * Generate UUID
   */
  private generateId(): string {
    return crypto.randomUUID();
  }
}
