// Cloudflare environment types and utilities
export interface CloudflareEnv {
  // Add your Cloudflare environment variables here
  API_KEY?: string;
  JWT_SECRET?: string;
  ENCRYPTION_KEY?: string;
  AUTH_SECRET?: string;
  ALLOWED_ORIGINS?: string;
  NODE_ENV?: string;
}

// Default environment for development
export const defaultCloudflareEnv: CloudflareEnv = {
  NODE_ENV: 'development',
  API_KEY: 'development-api-key',
  JWT_SECRET: 'development-jwt-secret-key-minimum-32-characters-long',
  ENCRYPTION_KEY: 'development-encryption-key-32-chars',
  AUTH_SECRET: 'development-auth-secret-key',
  ALLOWED_ORIGINS: 'http://localhost:5173,http://localhost:3001'
};
