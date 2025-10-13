/**
 * CSS Variable Validation Utility
 * Validates that critical CSS design tokens are properly loaded
 */

export interface CSSValidationResult {
  valid: boolean
  missing: string[]
  warnings: string[]
  loaded: string[]
}

/**
 * Critical CSS variables that must be present for the app to function
 */
const CRITICAL_CSS_VARIABLES = [
  // Brand colors
  '--brand-primary-600',
  '--brand-accent-600', 
  '--brand-teal-600',
  
  // Semantic colors
  '--semantic-success-500',
  '--semantic-warning-500',
  '--semantic-error-500',
  
  // Neutral colors
  '--neutral-0',
  '--neutral-900',
  '--gray-50',
  '--gray-900',
  
  // Spacing
  '--space-4',
  '--space-8',
  
  // Border radius
  '--radius-lg',
  
  // Shadows
  '--shadow-sm',
  '--shadow-md',
  
  // Typography
  '--font-sans',
  
  // Motion
  '--duration-base',
  '--ease-in-out',
] as const

/**
 * Important CSS variables that should be present but aren't critical
 */
const IMPORTANT_CSS_VARIABLES = [
  '--brand-primary-50',
  '--brand-primary-100',
  '--brand-primary-200',
  '--brand-primary-300',
  '--brand-primary-400',
  '--brand-primary-500',
  '--brand-primary-700',
  '--brand-primary-800',
  '--brand-primary-900',
  '--brand-primary-950',
  
  '--brand-accent-50',
  '--brand-accent-100',
  '--brand-accent-200',
  '--brand-accent-300',
  '--brand-accent-400',
  '--brand-accent-500',
  '--brand-accent-700',
  '--brand-accent-800',
  '--brand-accent-900',
  '--brand-accent-950',
  
  '--brand-teal-50',
  '--brand-teal-100',
  '--brand-teal-200',
  '--brand-teal-300',
  '--brand-teal-400',
  '--brand-teal-500',
  '--brand-teal-700',
  '--brand-teal-800',
  '--brand-teal-900',
  '--brand-teal-950',
] as const

/**
 * Validates that CSS variables are properly loaded
 */
export function validateCSSVariables(): CSSValidationResult {
  const missing: string[] = []
  const warnings: string[] = []
  const loaded: string[] = []
  
  // Check if we're in a browser environment
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return {
      valid: false,
      missing: ['Browser environment not available'],
      warnings: ['CSS validation skipped - not in browser environment'],
      loaded: []
    }
  }
  
  // Get computed styles from document root
  const rootStyles = getComputedStyle(document.documentElement)
  
  // Check critical variables
  for (const variable of CRITICAL_CSS_VARIABLES) {
    const value = rootStyles.getPropertyValue(variable).trim()
    if (value) {
      loaded.push(variable)
    } else {
      missing.push(variable)
    }
  }
  
  // Check important variables (warn if missing but don't fail)
  for (const variable of IMPORTANT_CSS_VARIABLES) {
    const value = rootStyles.getPropertyValue(variable).trim()
    if (value) {
      loaded.push(variable)
    } else {
      warnings.push(`Important CSS variable missing: ${variable}`)
    }
  }
  
  const result: CSSValidationResult = {
    valid: missing.length === 0,
    missing,
    warnings,
    loaded
  }
  
  return result
}

/**
 * Logs CSS validation results to console with appropriate styling
 */
export function logCSSValidation(result: CSSValidationResult): void {
  const { valid, missing, warnings, loaded } = result
  
  if (valid) {
    console.log(
      '%c✅ CSS Design Tokens Validation Passed',
      'color: #16a34a; font-weight: bold; font-size: 14px;'
    )
    console.log(`Loaded ${loaded.length} CSS variables successfully`)
    
    if (warnings.length > 0) {
      console.warn(
        '%c⚠️  CSS Validation Warnings:',
        'color: #d97706; font-weight: bold;'
      )
      warnings.forEach(warning => console.warn(`  - ${warning}`))
    }
  } else {
    console.error(
      '%c❌ CSS Design Tokens Validation Failed',
      'color: #dc2626; font-weight: bold; font-size: 14px;'
    )
    console.error('Missing critical CSS variables:')
    missing.forEach(variable => {
      console.error(`  - ${variable}`)
    })
    
    if (warnings.length > 0) {
      console.warn(
        '%c⚠️  Additional CSS Warnings:',
        'color: #d97706; font-weight: bold;'
      )
      warnings.forEach(warning => console.warn(`  - ${warning}`))
    }
    
    console.error(
      '%c💡 Troubleshooting:',
      'color: #2563eb; font-weight: bold;'
    )
    console.error('1. Check if design-tokens.css is properly imported')
    console.error('2. Verify Vite build copied design-tokens.css to dist/assets/')
    console.error('3. Check browser Network tab for failed CSS imports')
    console.error('4. Ensure CSS variables are defined in :root selector')
  }
}

/**
 * Validates CSS variables and throws an error if critical ones are missing
 * @throws Error if critical CSS variables are missing
 */
export function validateCSSVariablesOrThrow(): CSSValidationResult {
  const result = validateCSSVariables()
  
  if (!result.valid) {
    const errorMessage = [
      'CSS Design Tokens Validation Failed',
      '',
      'Missing critical CSS variables:',
      ...result.missing.map(variable => `  - ${variable}`),
      '',
      'This usually indicates:',
      '1. design-tokens.css import failed',
      '2. Vite build configuration issue',
      '3. CSS variables not properly defined',
      '',
      'Check browser console and Network tab for more details.'
    ].join('\n')
    
    throw new Error(errorMessage)
  }
  
  return result
}

/**
 * Checks if a specific CSS variable is defined
 */
export function isCSSVariableDefined(variable: string): boolean {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return false
  }
  
  const rootStyles = getComputedStyle(document.documentElement)
  const value = rootStyles.getPropertyValue(variable).trim()
  return value.length > 0
}

/**
 * Gets the computed value of a CSS variable
 */
export function getCSSVariableValue(variable: string): string | null {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return null
  }
  
  const rootStyles = getComputedStyle(document.documentElement)
  const value = rootStyles.getPropertyValue(variable).trim()
  return value || null
}

/**
 * Waits for CSS variables to be loaded (useful for async loading scenarios)
 */
export async function waitForCSSVariables(
  variables: string[],
  timeout: number = 5000
): Promise<boolean> {
  const startTime = Date.now()
  
  while (Date.now() - startTime < timeout) {
    const allLoaded = variables.every(variable => isCSSVariableDefined(variable))
    if (allLoaded) {
      return true
    }
    
    // Wait 100ms before checking again
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  
  return false
}
