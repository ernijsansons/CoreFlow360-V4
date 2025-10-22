/**
 * Environment Variable Validation
 * Validates required environment variables at application startup
 */

export interface EnvValidationResult {
  valid: boolean
  missing: string[]
  warnings: string[]
}

/**
 * Validates that all required environment variables are present
 * @throws Error if critical environment variables are missing
 */
export function validateEnvironment(): EnvValidationResult {
  const missing: string[] = []
  const warnings: string[] = []

  // Check required variables using direct property access (not bracket notation)
  // This is required for Vite's define config to work correctly
  // VITE_API_URL is now optional with fallback in vite.config.ts
  if (!import.meta.env.VITE_API_URL) {
    warnings.push('VITE_API_URL not set, using fallback from vite.config.ts')
  }

  // Check optional variables (warn but don't fail)
  if (!import.meta.env.VITE_SENTRY_DSN) {
    warnings.push('Optional environment variable VITE_SENTRY_DSN is not set')
  }
  if (!import.meta.env.VITE_ENVIRONMENT) {
    warnings.push('Optional environment variable VITE_ENVIRONMENT is not set')
  }

  // Validate API URL format
  const apiUrl = import.meta.env.VITE_API_URL
  if (apiUrl && !apiUrl.startsWith('http')) {
    warnings.push('VITE_API_URL should start with http:// or https://')
  }

  const result: EnvValidationResult = {
    valid: missing.length === 0,
    missing,
    warnings,
  }

  if (!result.valid) {
    const errorMessage = [
      '❌ Environment Validation Failed',
      '',
      'Missing required environment variables:',
      ...missing.map(key => `  - ${key}`),
      '',
      'Please ensure all required environment variables are set.',
      'Check .env.production or .env.local file.',
    ].join('\n')

    console.error(errorMessage)
    throw new Error(`Missing environment variables: ${missing.join(', ')}`)
  }

  // Log warnings (non-blocking)
  if (warnings.length > 0) {
    console.warn('⚠️ Environment warnings:')
    warnings.forEach(warning => console.warn(`  - ${warning}`))
  }

  // Log success in development
  if (import.meta.env.MODE === 'development') {
    console.log('✅ Environment validation passed')
    console.log('Environment:', {
      MODE: import.meta.env.MODE,
      API_URL: import.meta.env.VITE_API_URL,
      ENVIRONMENT: import.meta.env.VITE_ENVIRONMENT || 'not set',
    })
  }

  return result
}

/**
 * Gets the API base URL with fallback
 * This matches the fallback defined in vite.config.ts
 */
export function getApiUrl(): string {
  return (
    import.meta.env.VITE_API_URL ||
    'https://coreflow360-v4-prod.ernijs-ansons.workers.dev'
  )
}

/**
 * Gets the current environment
 */
export function getEnvironment(): 'development' | 'staging' | 'production' {
  return (import.meta.env.VITE_ENVIRONMENT || import.meta.env.MODE || 'development') as
    | 'development'
    | 'staging'
    | 'production'
}

/**
 * Checks if running in production
 */
export function isProduction(): boolean {
  return getEnvironment() === 'production'
}

/**
 * Checks if running in development
 */
export function isDevelopment(): boolean {
  return getEnvironment() === 'development'
}
