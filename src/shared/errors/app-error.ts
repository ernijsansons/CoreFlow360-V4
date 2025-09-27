export class AppError extends Error {
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly context?: Record<string, unknown>;

  constructor(
    message: string,
    statusCode: number = 500,
    isOperational: boolean = true,
    context?: Record<string, unknown>
  ) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.context = context;

    Object.setPrototypeOf(this, AppError.prototype);
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 400, true, context);
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 401, true, context);
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 403, true, context);
  }
}

export class NotFoundError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 404, true, context);
  }
}

export class ConflictError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 409, true, context);
  }
}

export class RateLimitError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 429, true, context);
  }
}

export class InternalError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 500, false, context);
  }
}

export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

export function formatErrorResponse(error: AppError): {
  error: {
    message: string;
    code: string;
    statusCode: number;
    context?: Record<string, unknown>;
  };
} {
  return {
    error: {
      message: error.message,
      code: error.constructor.name,
      statusCode: error.statusCode,
      context: error.isOperational ? error.context : undefined,
    },
  };
}