/**
 * Standardized Test Data Fixtures
 * Complete, type-safe test data objects with all required fields
 *
 * Usage:
 * import { createTestUser, createTestBusiness } from '../fixtures';
 * const user = createTestUser({ email: 'custom@example.com' });
 */

/**
 * Test User Factory
 * Creates a complete user object with all required fields
 */
export function createTestUser(overrides?: Partial<{
  id: string;
  business_id: string;
  email: string;
  password_hash: string;
  full_name: string;
  role: string;
  status: string;
  email_verified: number;
  mfa_enabled: number;
  mfa_secret: string | null;
  created_at: string;
  updated_at: string;
  created_by: string;
  last_login_at: string | null;
  failed_login_attempts: number;
  locked_until: string | null;
  password_reset_token: string | null;
  password_reset_expires: string | null;
  email_verification_token: string | null;
  profile_picture_url: string | null;
  phone: string | null;
  timezone: string;
  locale: string;
  metadata: string | null;
}>) {
  const now = new Date().toISOString();

  return {
    id: overrides?.id || 'test-user-id',
    business_id: overrides?.business_id || 'test-business-id',
    email: overrides?.email || 'test@example.com',
    password_hash: overrides?.password_hash || '$2a$10$test.hash.value.here',
    full_name: overrides?.full_name || 'Test User',
    role: overrides?.role || 'user',
    status: overrides?.status || 'active',
    email_verified: overrides?.email_verified !== undefined ? overrides.email_verified : 1,
    mfa_enabled: overrides?.mfa_enabled !== undefined ? overrides.mfa_enabled : 0,
    mfa_secret: overrides?.mfa_secret !== undefined ? overrides.mfa_secret : null,
    created_at: overrides?.created_at || now,
    updated_at: overrides?.updated_at || now,
    created_by: overrides?.created_by || 'system',
    last_login_at: overrides?.last_login_at !== undefined ? overrides.last_login_at : null,
    failed_login_attempts: overrides?.failed_login_attempts || 0,
    locked_until: overrides?.locked_until !== undefined ? overrides.locked_until : null,
    password_reset_token: overrides?.password_reset_token !== undefined ? overrides.password_reset_token : null,
    password_reset_expires: overrides?.password_reset_expires !== undefined ? overrides.password_reset_expires : null,
    email_verification_token: overrides?.email_verification_token !== undefined ? overrides.email_verification_token : null,
    profile_picture_url: overrides?.profile_picture_url !== undefined ? overrides.profile_picture_url : null,
    phone: overrides?.phone !== undefined ? overrides.phone : null,
    timezone: overrides?.timezone || 'UTC',
    locale: overrides?.locale || 'en-US',
    metadata: overrides?.metadata !== undefined ? overrides.metadata : null,
  };
}

/**
 * Test Business Factory
 * Creates a complete business object with all required fields
 */
export function createTestBusiness(overrides?: Partial<{
  id: string;
  name: string;
  slug: string;
  owner_id: string;
  status: string;
  plan: string;
  industry: string;
  size: string;
  timezone: string;
  locale: string;
  currency: string;
  fiscal_year_start: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  logo_url: string | null;
  website: string | null;
  phone: string | null;
  email: string | null;
  address_line1: string | null;
  address_line2: string | null;
  city: string | null;
  state: string | null;
  postal_code: string | null;
  country: string | null;
  tax_id: string | null;
  metadata: string | null;
}>) {
  const now = new Date().toISOString();

  return {
    id: overrides?.id || 'test-business-id',
    name: overrides?.name || 'Test Business',
    slug: overrides?.slug || 'test-business',
    owner_id: overrides?.owner_id || 'test-user-id',
    status: overrides?.status || 'active',
    plan: overrides?.plan || 'professional',
    industry: overrides?.industry || 'technology',
    size: overrides?.size || 'small',
    timezone: overrides?.timezone || 'UTC',
    locale: overrides?.locale || 'en-US',
    currency: overrides?.currency || 'USD',
    fiscal_year_start: overrides?.fiscal_year_start || '01-01',
    created_at: overrides?.created_at || now,
    updated_at: overrides?.updated_at || now,
    created_by: overrides?.created_by || 'system',
    logo_url: overrides?.logo_url !== undefined ? overrides.logo_url : null,
    website: overrides?.website !== undefined ? overrides.website : null,
    phone: overrides?.phone !== undefined ? overrides.phone : null,
    email: overrides?.email !== undefined ? overrides.email : null,
    address_line1: overrides?.address_line1 !== undefined ? overrides.address_line1 : null,
    address_line2: overrides?.address_line2 !== undefined ? overrides.address_line2 : null,
    city: overrides?.city !== undefined ? overrides.city : null,
    state: overrides?.state !== undefined ? overrides.state : null,
    postal_code: overrides?.postal_code !== undefined ? overrides.postal_code : null,
    country: overrides?.country !== undefined ? overrides.country : null,
    tax_id: overrides?.tax_id !== undefined ? overrides.tax_id : null,
    metadata: overrides?.metadata !== undefined ? overrides.metadata : null,
  };
}

/**
 * Test Session Factory
 * Creates a complete session object
 */
export function createTestSession(overrides?: Partial<{
  id: string;
  user_id: string;
  business_id: string;
  token_hash: string;
  ip_address: string;
  user_agent: string;
  expires_at: string;
  created_at: string;
  last_activity_at: string;
  mfa_verified: number;
  device_id: string | null;
  device_name: string | null;
  metadata: string | null;
}>) {
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  return {
    id: overrides?.id || 'test-session-id',
    user_id: overrides?.user_id || 'test-user-id',
    business_id: overrides?.business_id || 'test-business-id',
    token_hash: overrides?.token_hash || 'test-token-hash',
    ip_address: overrides?.ip_address || '127.0.0.1',
    user_agent: overrides?.user_agent || 'Test User Agent',
    expires_at: overrides?.expires_at || expiresAt,
    created_at: overrides?.created_at || now,
    last_activity_at: overrides?.last_activity_at || now,
    mfa_verified: overrides?.mfa_verified !== undefined ? overrides.mfa_verified : 0,
    device_id: overrides?.device_id !== undefined ? overrides.device_id : null,
    device_name: overrides?.device_name !== undefined ? overrides.device_name : null,
    metadata: overrides?.metadata !== undefined ? overrides.metadata : null,
  };
}

/**
 * Test Ledger Entry Factory
 * Creates a complete double-entry ledger entry
 */
export function createTestLedgerEntry(overrides?: Partial<{
  id: string;
  business_id: string;
  transaction_id: string;
  account_id: string;
  account_code: string;
  account_name: string;
  debit: number;
  credit: number;
  currency: string;
  description: string;
  reference: string | null;
  posted_at: string;
  created_at: string;
  created_by: string;
  metadata: string | null;
}>) {
  const now = new Date().toISOString();

  return {
    id: overrides?.id || 'test-ledger-entry-id',
    business_id: overrides?.business_id || 'test-business-id',
    transaction_id: overrides?.transaction_id || 'test-transaction-id',
    account_id: overrides?.account_id || 'test-account-id',
    account_code: overrides?.account_code || '1000',
    account_name: overrides?.account_name || 'Test Account',
    debit: overrides?.debit !== undefined ? overrides.debit : 0,
    credit: overrides?.credit !== undefined ? overrides.credit : 0,
    currency: overrides?.currency || 'USD',
    description: overrides?.description || 'Test transaction',
    reference: overrides?.reference !== undefined ? overrides.reference : null,
    posted_at: overrides?.posted_at || now,
    created_at: overrides?.created_at || now,
    created_by: overrides?.created_by || 'system',
    metadata: overrides?.metadata !== undefined ? overrides.metadata : null,
  };
}

/**
 * Test Audit Log Entry Factory
 */
export function createTestAuditLog(overrides?: Partial<{
  id: string;
  business_id: string;
  user_id: string;
  event_type: string;
  resource_type: string;
  resource_id: string;
  action: string;
  status: string;
  ip_address: string;
  user_agent: string;
  changes: string | null;
  metadata: string | null;
  created_at: string;
}>) {
  const now = new Date().toISOString();

  return {
    id: overrides?.id || 'test-audit-log-id',
    business_id: overrides?.business_id || 'test-business-id',
    user_id: overrides?.user_id || 'test-user-id',
    event_type: overrides?.event_type || 'user.login',
    resource_type: overrides?.resource_type || 'user',
    resource_id: overrides?.resource_id || 'test-user-id',
    action: overrides?.action || 'read',
    status: overrides?.status || 'success',
    ip_address: overrides?.ip_address || '127.0.0.1',
    user_agent: overrides?.user_agent || 'Test User Agent',
    changes: overrides?.changes !== undefined ? overrides.changes : null,
    metadata: overrides?.metadata !== undefined ? overrides.metadata : null,
    created_at: overrides?.created_at || now,
  };
}

/**
 * Test JWT Payload Factory
 */
export function createTestJWTPayload(overrides?: Partial<{
  sub: string;
  email: string;
  businessId: string;
  role: string;
  permissions: string[];
  iat: number;
  exp: number;
  jti: string;
}>) {
  const now = Math.floor(Date.now() / 1000);

  return {
    sub: overrides?.sub || 'test-user-id',
    email: overrides?.email || 'test@example.com',
    businessId: overrides?.businessId || 'test-business-id',
    role: overrides?.role || 'user',
    permissions: overrides?.permissions || ['read'],
    iat: overrides?.iat || now,
    exp: overrides?.exp || now + 86400,
    jti: overrides?.jti || 'test-jwt-id',
  };
}

/**
 * Test Security Context Factory
 */
export function createTestSecurityContext(overrides?: Partial<{
  userId: string;
  businessId: string;
  role: string;
  permissions: string[];
  ipAddress: string;
  userAgent: string;
  requestId: string;
}>) {
  return {
    userId: overrides?.userId || 'test-user-id',
    businessId: overrides?.businessId || 'test-business-id',
    role: overrides?.role || 'user',
    permissions: overrides?.permissions || ['read'],
    ipAddress: overrides?.ipAddress || '127.0.0.1',
    userAgent: overrides?.userAgent || 'Test User Agent',
    requestId: overrides?.requestId || 'test-request-id',
  };
}

/**
 * Test Request Factory
 * Creates a mock Request object for testing
 */
export function createTestRequest(overrides?: Partial<{
  url: string;
  method: string;
  headers: Record<string, string>;
  body: any;
}>) {
  const headers = new Headers(overrides?.headers || {});

  const init: RequestInit = {
    method: overrides?.method || 'GET',
    headers,
  };

  if (overrides?.body && overrides.method !== 'GET' && overrides.method !== 'HEAD') {
    init.body = typeof overrides.body === 'string'
      ? overrides.body
      : JSON.stringify(overrides.body);

    if (!headers.has('content-type')) {
      headers.set('content-type', 'application/json');
    }
  }

  return new Request(overrides?.url || 'http://localhost:8787/test', init);
}

/**
 * Batch fixture creator
 * Creates multiple instances of a fixture
 */
export function createBatch<T>(
  factory: (overrides?: any) => T,
  count: number,
  overridesFn?: (index: number) => any
): T[] {
  return Array.from({ length: count }, (_, i) =>
    factory(overridesFn ? overridesFn(i) : undefined)
  );
}
