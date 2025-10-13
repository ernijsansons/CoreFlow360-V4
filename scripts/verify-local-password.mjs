#!/usr/bin/env node

const PASSWORD = 'REDACTED';
const DB_HASH = '7ReLeGm2ttjp+z3DBaD4yvfP4MjDaZSL3tjJeAF8azM=';
const DB_SALT = 'dBpVkci53M5Ahco3SLvySoStq+2Ktt2YLbDCx4nAHQU=';

const PBKDF2_ITERATIONS = 100000;
const HASH_LENGTH = 32;

async function hashPassword(password, saltBase64) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Decode the base64 salt
  const saltBuffer = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));

  // Import password as key
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive hash
  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    passwordKey,
    HASH_LENGTH * 8
  );

  // Convert to base64
  const hashArray = new Uint8Array(hashBuffer);
  const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));

  return hashBase64;
}

async function verify() {
  console.log('🔐 Local Password Verification Test\n');
  console.log('Password:', PASSWORD);
  console.log('DB Hash:', DB_HASH);
  console.log('DB Salt:', DB_SALT);
  console.log('');

  const generatedHash = await hashPassword(PASSWORD, DB_SALT);

  console.log('Generated Hash:', generatedHash);
  console.log('');

  const hashesMatch = generatedHash === DB_HASH;

  console.log('✅ Hashes Match:', hashesMatch);

  if (!hashesMatch) {
    console.log('\n❌ MISMATCH DETECTED!');
    console.log('Expected:', DB_HASH);
    console.log('Got:     ', generatedHash);

    // Character-by-character comparison
    console.log('\nCharacter comparison:');
    for (let i = 0; i < Math.max(DB_HASH.length, generatedHash.length); i++) {
      if (DB_HASH[i] !== generatedHash[i]) {
        console.log(`Position ${i}: expected '${DB_HASH[i]}', got '${generatedHash[i]}'`);
      }
    }
  } else {
    console.log('\n✅ Password verification logic is CORRECT!');
    console.log('The issue must be elsewhere in the authentication flow.');
  }
}

verify().catch(console.error);
