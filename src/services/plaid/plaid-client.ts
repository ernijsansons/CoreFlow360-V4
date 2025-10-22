// @ts-nocheck
/**
 * Plaid API Client
 * Handles all communication with Plaid API
 */

import type { Env } from '../../types/env';

// ==================
// Plaid Types
// ==================

export interface PlaidLinkTokenRequest {
  user_id: string;
  business_name: string;
  products?: string[];
  country_codes?: string[];
  language?: string;
  redirect_uri?: string;
}

export interface PlaidLinkTokenResponse {
  link_token: string;
  expiration: string;
}

export interface PlaidPublicTokenExchangeRequest {
  public_token: string;
}

export interface PlaidPublicTokenExchangeResponse {
  access_token: string;
  item_id: string;
}

export interface PlaidAccount {
  account_id: string;
  balances: {
    current: number | null;
    available: number | null;
    limit: number | null;
    iso_currency_code: string;
  };
  mask: string | null;
  name: string;
  official_name: string | null;
  type: string;
  subtype: string | null;
}

export interface PlaidAccountsResponse {
  accounts: PlaidAccount[];
  item: {
    item_id: string;
    institution_id: string;
    error: any | null;
  };
}

export interface PlaidTransaction {
  transaction_id: string;
  account_id: string;
  amount: number;
  date: string;
  authorized_date: string | null;
  name: string;
  merchant_name: string | null;
  category: string[] | null;
  category_id: string | null;
  pending: boolean;
  payment_channel: string;
  payment_meta: Record<string, any>;
  location: {
    address: string | null;
    city: string | null;
    region: string | null;
    postal_code: string | null;
    country: string | null;
    lat: number | null;
    lon: number | null;
  };
}

export interface PlaidTransactionsSyncRequest {
  access_token: string;
  cursor?: string;
  count?: number;
}

export interface PlaidTransactionsSyncResponse {
  added: PlaidTransaction[];
  modified: PlaidTransaction[];
  removed: { transaction_id: string }[];
  next_cursor: string;
  has_more: boolean;
}

export interface PlaidInstitution {
  institution_id: string;
  name: string;
  logo: string | null;
  primary_color: string | null;
  url: string | null;
}

export interface PlaidItemResponse {
  item: {
    item_id: string;
    institution_id: string;
    webhook: string | null;
    error: any | null;
    available_products: string[];
    billed_products: string[];
    consent_expiration_time: string | null;
  };
  status: {
    transactions: {
      last_successful_update: string | null;
      last_failed_update: string | null;
    };
  };
}

// ==================
// Plaid Client
// ==================

export class PlaidClient {
  private clientId: string;
  private secret: string;
  private environment: 'sandbox' | 'development' | 'production';
  private baseUrl: string;

  constructor(env: Env) {
    this.clientId = env.PLAID_CLIENT_ID;
    this.secret = env.PLAID_SECRET;
    this.environment = (env.PLAID_ENVIRONMENT as any) || 'sandbox';

    // Determine base URL based on environment
    if (this.environment === 'production') {
      this.baseUrl = 'https://production.plaid.com';
    } else if (this.environment === 'development') {
      this.baseUrl = 'https://development.plaid.com';
    } else {
      this.baseUrl = 'https://sandbox.plaid.com';
    }
  }

  /**
   * Make authenticated request to Plaid API
   */
  private async request<T>(endpoint: string, body: any): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: this.clientId,
        secret: this.secret,
        ...body,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Plaid API error: ${error.error_code} - ${error.error_message}`);
    }

    return response.json();
  }

  /**
   * Create Link token for Plaid Link UI
   */
  async createLinkToken(params: PlaidLinkTokenRequest): Promise<PlaidLinkTokenResponse> {
    return this.request<PlaidLinkTokenResponse>('/link/token/create', {
      user: {
        client_user_id: params.user_id,
      },
      client_name: params.business_name,
      products: params.products || ['transactions'],
      country_codes: params.country_codes || ['US'],
      language: params.language || 'en',
      redirect_uri: params.redirect_uri,
    });
  }

  /**
   * Exchange public token for access token
   */
  async exchangePublicToken(
    publicToken: string
  ): Promise<PlaidPublicTokenExchangeResponse> {
    return this.request<PlaidPublicTokenExchangeResponse>('/item/public_token/exchange', {
      public_token: publicToken,
    });
  }

  /**
   * Get accounts for an item
   */
  async getAccounts(accessToken: string): Promise<PlaidAccountsResponse> {
    return this.request<PlaidAccountsResponse>('/accounts/get', {
      access_token: accessToken,
    });
  }

  /**
   * Get item details
   */
  async getItem(accessToken: string): Promise<PlaidItemResponse> {
    return this.request<PlaidItemResponse>('/item/get', {
      access_token: accessToken,
    });
  }

  /**
   * Get institution details
   */
  async getInstitution(institutionId: string): Promise<PlaidInstitution> {
    const response = await this.request<{ institution: PlaidInstitution }>(
      '/institutions/get_by_id',
      {
        institution_id: institutionId,
        country_codes: ['US'],
      }
    );
    return response.institution;
  }

  /**
   * Sync transactions using cursor-based pagination
   */
  async syncTransactions(
    params: PlaidTransactionsSyncRequest
  ): Promise<PlaidTransactionsSyncResponse> {
    return this.request<PlaidTransactionsSyncResponse>('/transactions/sync', {
      access_token: params.access_token,
      cursor: params.cursor,
      count: params.count || 500,
    });
  }

  /**
   * Remove item (disconnect bank connection)
   */
  async removeItem(accessToken: string): Promise<{ removed: boolean }> {
    return this.request<{ removed: boolean }>('/item/remove', {
      access_token: accessToken,
    });
  }

  /**
   * Update webhook URL for an item
   */
  async updateWebhook(accessToken: string, webhookUrl: string): Promise<{ item: any }> {
    return this.request<{ item: any }>('/item/webhook/update', {
      access_token: accessToken,
      webhook: webhookUrl,
    });
  }

  /**
   * Refresh transactions (force sync)
   */
  async refreshTransactions(accessToken: string): Promise<{ request_id: string }> {
    return this.request<{ request_id: string }>('/transactions/refresh', {
      access_token: accessToken,
    });
  }
}
