// Quick debug script to test JWT validation
import { JWTSecretManager } from './src/shared/security/jwt-secret-manager.js';

const testSecret = 'kL9#mN2$pQ8&rT5%vW1@xZ4^yA7*bC3!dE6+fG9-hI2~jK5_lM8|nO1}pR4{sU7';

console.log('Testing secret:', testSecret);
console.log('Secret length:', testSecret.length);

const result = JWTSecretManager.validateJWTSecret(testSecret, 'production');

console.log('Validation result:', JSON.stringify(result, null, 2));