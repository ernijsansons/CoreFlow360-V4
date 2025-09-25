import { z } from 'zod';

// Auth Request Schemas
export const RegisterRequestSchema = z.object({
  email: z.string().email().toLowerCase(),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  firstName: z.string().min(1).max(50),
  lastName: z.string().min(1).max(50),
  businessName: z.string().min(2).max(100).optional(),
  acceptTerms: z.boolean().refine((val) => val === true, {
    message: 'You must accept the terms and conditions',
  }),
});

export const LoginRequestSchema = z.object({
  email: z.string().email().toLowerCase(),
  password: z.string(),
  rememberMe: z.boolean().default(false),
  mfaCode: z.string().length(6).optional(),
});

export const RefreshTokenRequestSchema = z.object({
  refreshToken: z.string(),
});

export const MFASetupRequestSchema = z.object({
  type: z.enum(['totp', 'sms', 'email']),
});

export const MFAVerifyRequestSchema = z.object({
  code: z.string().length(6),
  type: z.enum(['totp', 'sms', 'email']),
});

export const PasswordResetRequestSchema = z.object({
  email: z.string().email().toLowerCase(),
});

export const PasswordResetConfirmSchema = z.object({
  token: z.string(),
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
});

// Type definitions
export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;
export type LoginRequest = z.infer<typeof LoginRequestSchema>;
export type RefreshTokenRequest = z.infer<typeof RefreshTokenRequestSchema>;
export type MFASetupRequest = z.infer<typeof MFASetupRequestSchema>;
export type MFAVerifyRequest = z.infer<typeof MFAVerifyRequestSchema>;
export type PasswordResetRequest = z.infer<typeof PasswordResetRequestSchema>;
export type PasswordResetConfirm = z.infer<typeof PasswordResetConfirmSchema>;

// JWT Token Claims
export interface TokenClaims {
  // Standard JWT claims
  sub: string;  // User ID
  iat: number;  // Issued at
  exp: number;  // Expiration
  jti: string;  // JWT ID (for revocation)

  // Custom claims
  email: string;
  businessId: string;
  businessName: string;
  role: 'owner' | 'director' | 'manager' | 'employee' | 'viewer';
  permissions: string[];
  sessionId: string;
  ipAddress?: string;
}

// Session data stored in KV
export interface SessionData {
  id: string;
  userId: string;
  businessId: string;
  email: string;
  role: string;
  permissions: string[];

  // Token management
  accessToken: string;
  refreshToken: string;
  accessTokenExp: number;
  refreshTokenExp: number;

  // Session metadata
  createdAt: number;
  lastActivityAt: number;
  expiresAt: number;

  // Security context
  ipAddress: string;
  userAgent: string;
  deviceFingerprint?: string;

  // MFA status
  mfaEnabled: boolean;
  mfaVerified: boolean;

  // Rate limiting
  requestCount: number;
  lastRequestAt: number;
}

// User Auth Context
export interface AuthContext {
  userId: string;
  email: string;
  businessId: string;
  businessName: string;
  role: string;
  permissions: string[];
  sessionId: string;
  isAuthenticated: boolean;
  mfaRequired: boolean;
  mfaVerified: boolean;
}

// MFA Configuration
export interface MFAConfig {
  userId: string;
  type: 'totp' | 'sms' | 'email';
  secret?: string; // For TOTP
  phoneNumber?: string; // For SMS
  email?: string; // For email
  backupCodes: string[];
  enabled: boolean;
  createdAt: number;
  verifiedAt?: number | null;
  lastUsedAt?: number | null;
}

// Rate Limit Config
export interface RateLimitConfig {
  // Login attempts
  loginMaxAttempts: number;
  loginWindowMs: number;

  // Registration
  registerMaxAttempts: number;
  registerWindowMs: number;

  // Password reset
  resetMaxAttempts: number;
  resetWindowMs: number;

  // API calls
  apiMaxRequests: number;
  apiWindowMs: number;
}

// Auth Service Response Types
export interface AuthResponse {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  expiresIn?: number;
  user?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    businessId: string;
    businessName: string;
    role: string;
  };
  mfaRequired?: boolean;
  mfaToken?: string; // Temporary token for MFA verification
  error?: {
    code: string;
    message: string;
    details?: Record<string, string | number | boolean>;
  };
}

export interface SessionInfo {
  id: string;
  userId: string;
  businessId: string;
  createdAt: string;
  lastActivityAt: string;
  expiresAt: string;
  ipAddress: string;
  userAgent: string;
  isActive: boolean;
  isCurrent: boolean;
}

// Password validation result
export interface PasswordStrength {
  score: number; // 0-4
  feedback: string[];
  isValid: boolean;
}

// Audit log entry for auth events
export interface AuthAuditEntry {
  id: string;
  userId?: string;
  businessId?: string;
  event: 'login' | 'logout' | 'register' |
  'password_reset' | 'mfa_enable' | 'mfa_disable' | 'session_expired' | 'token_refresh';
  success: boolean;
  ipAddress: string;
  userAgent: string;
  metadata?: Record<string, any>;
  timestamp: number;
}