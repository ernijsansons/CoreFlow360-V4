#!/usr/bin/env node

/**
 * Development JWT Token Generator
 * Creates a valid JWT token for testing/development purposes
 * TEMPORARY WORKAROUND for authentication issue
 */

import crypto from 'crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-for-testing-only';
const USER_ID = '550e8400-e29b-41d4-a716-446655440000'; // Founder account ID
const BUSINESS_ID = 'business-founder-001';
const EMAIL = 'founder@coreflow360.com';

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function createJWT() {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: USER_ID,
    businessId: BUSINESS_ID,
    email: EMAIL,
    role: 'super_admin',
    iat: now,
    exp: now + (24 * 60 * 60), // 24 hours
    jti: crypto.randomUUID()
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));

  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(signatureInput)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${signatureInput}.${signature}`;
}

const token = createJWT();

console.log('🔑 Development JWT Token Generated\n');
console.log('Token:', token);
console.log('\nUser Details:');
console.log('- User ID:', USER_ID);
console.log('- Business ID:', BUSINESS_ID);
console.log('- Email:', EMAIL);
console.log('- Role: super_admin');
console.log('- Expires: 24 hours from now');
console.log('\n📋 Usage:');
console.log('Add this to your requests:');
console.log('Authorization: Bearer', token);
console.log('\nOr in browser localStorage:');
console.log(`localStorage.setItem('accessToken', '${token}');`);
