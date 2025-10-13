// Temporary test endpoint for debugging password verification
import { Hono } from 'hono';
import { verifyPassword } from '../modules/auth/crypto';
import type { Env } from '../types/env';

const test = new Hono<{ Bindings: Env }>();

test.post('/verify', async (c) => {
  try {
    const { password, hash, salt } = await c.req.json();

    console.log('[TEST] Password verification test:', {
      passwordLength: password?.length,
      hashLength: hash?.length,
      saltLength: salt?.length,
      password: password?.substring(0, 10) + '...',
      hash: hash?.substring(0, 20) + '...',
      salt: salt?.substring(0, 20) + '...'
    });

    const isValid = await verifyPassword(password, hash, salt);

    console.log('[TEST] Verification result:', isValid);

    return c.json({
      success: true,
      isValid,
      debug: {
        passwordLength: password?.length,
        hashLength: hash?.length,
        saltLength: salt?.length
      }
    });
  } catch (error: any) {
    console.log('[TEST] Error:', error.message);
    return c.json({
      success: false,
      error: error.message,
      stack: error.stack
    }, 500);
  }
});

// Test with founder credentials from database
test.get('/verify-founder', async (c) => {
  try {
    const db = c.env.DB_MAIN || c.env.DB;
    const user = await db.prepare(`
      SELECT email, password_hash, password_salt
      FROM users
      WHERE email = 'founder@coreflow360.com'
    `).first<any>();

    if (!user) {
      return c.json({ success: false, error: 'User not found' }, 404);
    }

    console.log('[TEST] User data:', {
      email: user.email,
      hasHash: !!user.password_hash,
      hasSalt: !!user.password_salt,
      hashLength: user.password_hash?.length,
      saltLength: user.password_salt?.length
    });

    const testPassword = 'REDACTED';
    const isValid = await verifyPassword(testPassword, user.password_hash, user.password_salt);

    console.log('[TEST] Password verification with DB data:', isValid);

    return c.json({
      success: true,
      isValid,
      userEmail: user.email,
      hasHash: !!user.password_hash,
      hasSalt: !!user.password_salt
    });
  } catch (error: any) {
    console.log('[TEST] Error:', error.message, error.stack);
    return c.json({
      success: false,
      error: error.message,
      stack: error.stack
    }, 500);
  }
});

export default test;
