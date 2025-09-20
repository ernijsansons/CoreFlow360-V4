/**
 * Cryptographic utilities using Web Crypto API
 */

// Constants for password hashing
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 32;
const HASH_LENGTH = 32;
const ALGORITHM = 'PBKDF2';

/**
 * Generate a random salt
 */
export async function generateSalt(): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  return bufferToBase64(salt);
}

/**
 * Hash a password using PBKDF2 with Web Crypto API
 */
export async function hashPassword(password: string, salt?: string): Promise<{ hash: string; salt: string }> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Generate or decode salt
  const saltBuffer = salt
    ? base64ToBuffer(salt)
    : crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

  const saltString = salt || bufferToBase64(saltBuffer);

  // Import password as CryptoKey
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive hash using PBKDF2
  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    passwordKey,
    HASH_LENGTH * 8 // bits
  );

  const hashString = bufferToBase64(new Uint8Array(hashBuffer));

  return {
    hash: hashString,
    salt: saltString
  };
}

/**
 * Verify a password against a hash
 */
export async function verifyPassword(password: string, hash: string, salt: string): Promise<boolean> {
  try {
    const { hash: newHash } = await hashPassword(password, salt);

    // Constant-time comparison to prevent timing attacks
    if (newHash.length !== hash.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < newHash.length; i++) {
      result |= newHash.charCodeAt(i) ^ hash.charCodeAt(i);
    }

    return result === 0;
  } catch (error) {
    console.error('Password verification error:', error);
    return false;
  }
}

/**
 * Generate a cryptographically secure random token
 */
export function generateSecureToken(length: number = 32): string {
  const buffer = crypto.getRandomValues(new Uint8Array(length));
  return bufferToBase64url(buffer);
}

/**
 * Generate a 6-digit OTP code
 */
export function generateOTPCode(): string {
  const buffer = crypto.getRandomValues(new Uint8Array(3));
  const num = (buffer[0]! << 16) | (buffer[1]! << 8) | buffer[2]!;
  return String(num % 1000000).padStart(6, '0');
}

/**
 * Generate TOTP secret for 2FA
 */
export function generateTOTPSecret(): string {
  const buffer = crypto.getRandomValues(new Uint8Array(20));
  return base32Encode(buffer);
}

/**
 * Sign data using HMAC-SHA256
 */
export async function signHMAC(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const secretBuffer = encoder.encode(secret);

  // Import secret as CryptoKey
  const key = await crypto.subtle.importKey(
    'raw',
    secretBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // Sign the data
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    dataBuffer
  );

  return bufferToBase64url(new Uint8Array(signature));
}

/**
 * Verify HMAC signature
 */
export async function verifyHMAC(data: string, signature: string, secret: string): Promise<boolean> {
  try {
    const expectedSignature = await signHMAC(data, secret);

    // Constant-time comparison
    if (expectedSignature.length !== signature.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < expectedSignature.length; i++) {
      result |= expectedSignature.charCodeAt(i) ^ signature.charCodeAt(i);
    }

    return result === 0;
  } catch (error) {
    console.error('HMAC verification error:', error);
    return false;
  }
}

/**
 * Encrypt data using AES-GCM
 */
export async function encrypt(data: string, key: string): Promise<{ encrypted: string; iv: string }> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  // Generate IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Derive key from string
  const keyBuffer = await deriveKey(key);

  // Import key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    'AES-GCM',
    false,
    ['encrypt']
  );

  // Encrypt
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    dataBuffer
  );

  return {
    encrypted: bufferToBase64(new Uint8Array(encrypted)),
    iv: bufferToBase64(iv)
  };
}

/**
 * Decrypt data using AES-GCM
 */
export async function decrypt(encryptedData: string, iv: string, key: string): Promise<string> {
  const encryptedBuffer = base64ToBuffer(encryptedData);
  const ivBuffer = base64ToBuffer(iv);

  // Derive key from string
  const keyBuffer = await deriveKey(key);

  // Import key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    'AES-GCM',
    false,
    ['decrypt']
  );

  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuffer },
    cryptoKey,
    encryptedBuffer
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

/**
 * Derive a key from a password string
 */
async function deriveKey(password: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const hash = await crypto.subtle.digest('SHA-256', passwordBuffer);
  return hash;
}

/**
 * Convert ArrayBuffer to base64
 */
function bufferToBase64(buffer: Uint8Array): string {
  const binString = Array.from(buffer, (x) => String.fromCodePoint(x)).join('');
  return btoa(binString);
}

/**
 * Convert ArrayBuffer to base64url (URL-safe)
 */
function bufferToBase64url(buffer: Uint8Array): string {
  return bufferToBase64(buffer)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Convert base64 to ArrayBuffer
 */
function base64ToBuffer(base64: string): Uint8Array {
  const binString = atob(base64);
  const buffer = new Uint8Array(binString.length);
  for (let i = 0; i < binString.length; i++) {
    buffer[i] = binString.charCodeAt(i);
  }
  return buffer;
}

/**
 * Base32 encode (for TOTP secrets)
 */
function base32Encode(buffer: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i]!;
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Calculate password strength score
 */
export function calculatePasswordStrength(password: string): {
  score: number;
  feedback: string[];
  isValid: boolean;
} {
  const feedback: string[] = [];
  let score = 0;

  // Length check
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  else if (password.length < 8) feedback.push('Password should be at least 8 characters');

  // Character variety
  if (/[a-z]/.test(password)) score++;
  else feedback.push('Add lowercase letters');

  if (/[A-Z]/.test(password)) score++;
  else feedback.push('Add uppercase letters');

  if (/[0-9]/.test(password)) score++;
  else feedback.push('Add numbers');

  if (/[^A-Za-z0-9]/.test(password)) score++;
  else feedback.push('Add special characters');

  // Common patterns to avoid
  if (/(.)\1{2,}/.test(password)) {
    score--;
    feedback.push('Avoid repeated characters');
  }

  if (/^[0-9]+$/.test(password)) {
    score--;
    feedback.push('Don\'t use only numbers');
  }

  if (/^[a-zA-Z]+$/.test(password)) {
    score--;
    feedback.push('Don\'t use only letters');
  }

  // Sequential characters
  if (/abc|bcd|cde|def|123|234|345|456|567|678|789/i.test(password)) {
    score--;
    feedback.push('Avoid sequential characters');
  }

  // Normalize score to 0-4 range
  score = Math.max(0, Math.min(4, Math.floor(score / 2)));

  return {
    score,
    feedback,
    isValid: score >= 3 && password.length >= 8
  };
}