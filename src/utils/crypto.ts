/**
 * Cryptographic Security Utilities for CoreFlow360 V4
 *
 * SECURITY FEATURES:
 * - CSRF token generation and validation
 * - Secure random string generation
 * - Request signature validation
 * - Nonce generation for CSP
 * - Cryptographic hash functions
 *
 * @security-level CRITICAL
 * @compliance SOC2, GDPR, HIPAA
 */

/**
 * Helper: Ensure Uint8Array has proper ArrayBuffer for Web Crypto API
 * Converts ArrayBufferLike to ArrayBuffer if needed
 * @security-critical Prevents type mismatches in crypto operations
 */
function ensureBufferSource(data: Uint8Array): BufferSource {
  // If buffer is already ArrayBuffer, return as-is
  if (data.buffer instanceof ArrayBuffer && data.byteOffset === 0 && data.byteLength === data.buffer.byteLength) {
    return data as BufferSource;
  }
  // Create a proper copy with ArrayBuffer - explicitly slice to ensure ArrayBuffer
  return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)) as BufferSource;
}

/**
 * Generate cryptographically secure nonce for CSP
 * Uses 16 bytes of random data for maximum entropy
 */
export function generateSecureNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate CSRF token using HMAC-SHA256
 * Implements double-submit cookie pattern with cryptographic validation
 */
export async function generateCSRFToken(secret: string, url: string): Promise<string> {
  const timestamp = Date.now().toString();
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  const random = btoa(String.fromCharCode(...randomBytes));

  const data = `${timestamp}:${random}:${url}`;
  const signature = await generateHMAC(secret, data);

  return btoa(`${data}:${signature}`)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Validate CSRF token
 * Verifies timestamp, signature, and URL binding
 */
export async function validateCSRFToken(
  token: string,
  secret: string,
  url: string,
  maxAge = 3600000 // 1 hour
): Promise<boolean> {
  try {
    // Restore base64 padding
    const paddedToken = token + '='.repeat((4 - token.length % 4) % 4);
    const decoded = atob(paddedToken.replace(/-/g, '+').replace(/_/g, '/'));

    const parts = decoded.split(':');
    if (parts.length !== 4) return false;

    const [timestamp, random, tokenUrl, signature] = parts;

    // Validate timestamp (prevent replay attacks)
    const tokenTime = parseInt(timestamp);
    if (isNaN(tokenTime) || Date.now() - tokenTime > maxAge) {
      return false;
    }

    // Validate URL binding
    if (tokenUrl !== url) {
      return false;
    }

    // Validate signature
    const data = `${timestamp}:${random}:${tokenUrl}`;
    const expectedSignature = await generateHMAC(secret, data);

    return constantTimeCompare(signature, expectedSignature);
  } catch {
    return false;
  }
}

/**
 * Generate HMAC-SHA256 signature
 */
export async function generateHMAC(secret: string, data: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(data);

  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, messageData);
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

/**
 * Verify HMAC signature
 */
export async function verifyHMAC(
  signature: string,
  secret: string,
  data: string
): Promise<boolean> {
  const expectedSignature = await generateHMAC(secret, data);
  return constantTimeCompare(signature, expectedSignature);
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Generate cryptographically secure random string
 */
export function generateSecureRandomString(
  length: number,
  charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }

  return result;
}

/**
 * Generate secure session ID
 */
export function generateSessionId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate secure API key with proper format
 */
export function generateAPIKey(): string {
  const keyBytes = new Uint8Array(32);
  crypto.getRandomValues(keyBytes);

  const key = btoa(String.fromCharCode(...keyBytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return `cfk_${key}`;
}

/**
 * Hash string using SHA-256
 */
export async function hashString(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate salted hash using PBKDF2
 */
export async function generateSaltedHash(
  input: string,
  salt?: Uint8Array,
  iterations = 100000
): Promise<{ hash: string; salt: string }> {
  if (!salt) {
    salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
  }

  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(input),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: ensureBufferSource(salt),
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  const hash = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
  const saltString = btoa(String.fromCharCode(...salt));

  return { hash, salt: saltString };
}

/**
 * Verify salted hash
 */
export async function verifySaltedHash(
  input: string,
  storedHash: string,
  storedSalt: string,
  iterations = 100000
): Promise<boolean> {
  try {
    const salt = Uint8Array.from(atob(storedSalt), c => c.charCodeAt(0));
    const { hash } = await generateSaltedHash(input, salt, iterations);
    return constantTimeCompare(hash, storedHash);
  } catch {
    return false;
  }
}

/**
 * Encrypt data using AES-GCM
 */
export async function encryptData(
  data: string,
  password: string
): Promise<{ encrypted: string; iv: string; salt: string }> {
  const encoder = new TextEncoder();
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  // Derive key from password
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Generate IV
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  // Encrypt data
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(data)
  );

  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer))),
    iv: btoa(String.fromCharCode(...iv)),
    salt: btoa(String.fromCharCode(...salt))
  };
}

/**
 * Decrypt data using AES-GCM
 */
export async function decryptData(
  encryptedData: string,
  password: string,
  ivString: string,
  saltString: string
): Promise<string> {
  const encoder = new TextEncoder();
  const encrypted = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivString), c => c.charCodeAt(0));
  const salt = Uint8Array.from(atob(saltString), c => c.charCodeAt(0));

  // Derive key from password
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Decrypt data
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * Generate request signature for API authentication
 */
export async function generateRequestSignature(
  method: string,
  url: string,
  body: string,
  timestamp: string,
  secret: string
): Promise<string> {
  const message = `${method}\n${url}\n${body}\n${timestamp}`;
  return await generateHMAC(secret, message);
}

/**
 * Validate request signature
 */
export async function validateRequestSignature(
  method: string,
  url: string,
  body: string,
  timestamp: string,
  signature: string,
  secret: string,
  maxAge = 300000 // 5 minutes
): Promise<boolean> {
  // Validate timestamp to prevent replay attacks
  const requestTime = parseInt(timestamp);
  if (isNaN(requestTime) || Date.now() - requestTime > maxAge) {
    return false;
  }

  const expectedSignature = await generateRequestSignature(
    method,
    url,
    body,
    timestamp,
    secret
  );

  return constantTimeCompare(signature, expectedSignature);
}

/**
 * Security utilities for password validation
 */
export const PasswordSecurity = {
  /**
   * Check password strength
   */
  checkStrength(password: string): {
    score: number;
    feedback: string[];
    isStrong: boolean;
  } {
    const feedback: string[] = [];
    let score = 0;

    // Length check
    if (password.length < 8) {
      feedback.push('Password must be at least 8 characters long');
    } else if (password.length >= 12) {
      score += 25;
    } else {
      score += 10;
    }

    // Character variety checks
    if (/[a-z]/.test(password)) score += 15;
    else feedback.push('Add lowercase letters');

    if (/[A-Z]/.test(password)) score += 15;
    else feedback.push('Add uppercase letters');

    if (/\d/.test(password)) score += 15;
    else feedback.push('Add numbers');

    if (/[^A-Za-z0-9]/.test(password)) score += 20;
    else feedback.push('Add special characters');

    // Common patterns check
    if (/(.)\1{2,}/.test(password)) {
      feedback.push('Avoid repeating characters');
      score -= 10;
    }

    if (/^[a-zA-Z]+$/.test(password)) {
      feedback.push('Use a mix of characters');
      score -= 10;
    }

    if (/^[0-9]+$/.test(password)) {
      feedback.push('Avoid using only numbers');
      score -= 20;
    }

    const isStrong = score >= 70 && feedback.length === 0;

    return {
      score: Math.max(0, Math.min(100, score)),
      feedback,
      isStrong
    };
  },

  /**
   * Generate secure password
   */
  generateSecure(length = 16): string {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const allChars = lowercase + uppercase + numbers + symbols;

    // Ensure at least one character from each category
    let password = [
      lowercase[Math.floor(Math.random() * lowercase.length)],
      uppercase[Math.floor(Math.random() * uppercase.length)],
      numbers[Math.floor(Math.random() * numbers.length)],
      symbols[Math.floor(Math.random() * symbols.length)]
    ].join('');

    // Fill remaining length with random characters
    for (let i = password.length; i < length; i++) {
      password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
  }
};

// All functions are already exported inline above