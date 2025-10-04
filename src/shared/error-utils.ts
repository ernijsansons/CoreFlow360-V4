/**
 * Error Utility Functions
 * Simple helpers for handling unknown error types in TypeScript 4.4+
 *
 * Grug say: Make error handling simple and safe!
 */

/**
 * Extract error message from unknown error type
 * @param error - Unknown error (from catch block)
 * @returns Error message string
 */
export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

/**
 * Extract error stack from unknown error type
 * @param error - Unknown error (from catch block)
 * @returns Error stack string or undefined
 */
export function getErrorStack(error: unknown): string | undefined {
  if (error instanceof Error) {
    return error.stack;
  }
  return undefined;
}

/**
 * Check if error is an Error instance
 * @param error - Unknown error (from catch block)
 * @returns True if error is Error instance
 */
export function isError(error: unknown): error is Error {
  return error instanceof Error;
}

/**
 * Convert unknown error to Error instance
 * @param error - Unknown error (from catch block)
 * @returns Error instance
 */
export function toError(error: unknown): Error {
  if (error instanceof Error) {
    return error;
  }
  return new Error(String(error));
}

/**
 * Extract error code from unknown error (if available)
 * @param error - Unknown error (from catch block)
 * @returns Error code or undefined
 */
export function getErrorCode(error: unknown): string | number | undefined {
  if (error && typeof error === 'object' && 'code' in error) {
    const code = (error as any).code;
    if (typeof code === 'string' || typeof code === 'number') {
      return code;
    }
  }
  return undefined;
}
