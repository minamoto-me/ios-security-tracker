import { Logger } from './logger';

export class ErrorHandler {
  static async handleAsyncOperation<T>(
    operation: () => Promise<T>,
    operationName: string,
    fallbackValue?: T
  ): Promise<T | undefined> {
    try {
      return await operation();
    } catch (error) {
      Logger.error(`Failed to execute ${operationName}`, error);
      return fallbackValue;
    }
  }

  static handleSyncOperation<T>(
    operation: () => T,
    operationName: string,
    fallbackValue?: T
  ): T | undefined {
    try {
      return operation();
    } catch (error) {
      Logger.error(`Failed to execute ${operationName}`, error);
      return fallbackValue;
    }
  }

  static createErrorResponse(
    message: string,
    statusCode: number = 500,
    details?: any
  ): Response {
    const errorBody = {
      error: message,
      timestamp: new Date().toISOString(),
      ...(details && { details }),
    };

    return new Response(JSON.stringify(errorBody), {
      status: statusCode,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }

  static isNetworkError(error: any): boolean {
    return (
      error instanceof TypeError ||
      (error.name && error.name.includes('Network')) ||
      (error.message && error.message.includes('fetch'))
    );
  }

  static isRateLimitError(error: any): boolean {
    return (
      error.status === 429 ||
      (error.message && error.message.includes('rate limit'))
    );
  }

  static shouldRetry(error: any, attemptCount: number, maxAttempts: number = 3): boolean {
    if (attemptCount >= maxAttempts) return false;

    return (
      this.isNetworkError(error) ||
      this.isRateLimitError(error) ||
      (error.status && error.status >= 500)
    );
  }

  static getRetryDelay(attemptCount: number, baseDelay: number = 1000): number {
    return baseDelay * Math.pow(2, attemptCount - 1);
  }

  static async retryOperation<T>(
    operation: () => Promise<T>,
    operationName: string,
    maxAttempts: number = 3,
    baseDelay: number = 1000
  ): Promise<T> {
    let lastError: any;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;

        if (!this.shouldRetry(error, attempt, maxAttempts)) {
          Logger.error(`${operationName} failed after ${attempt} attempts`, error);
          throw error;
        }

        if (attempt < maxAttempts) {
          const delay = this.getRetryDelay(attempt, baseDelay);
          Logger.warn(`${operationName} attempt ${attempt} failed, retrying in ${delay}ms`, error);
          await this.delay(delay);
        }
      }
    }

    throw lastError;
  }

  private static delay(ms: number): Promise<void> {
    return new Promise(resolve => {
      const timer = setTimeout(resolve, ms);
      return timer;
    });
  }
}

export class ValidationError extends Error {
  constructor(message: string, public field?: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string, public resource?: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class RateLimitError extends Error {
  constructor(message: string, public retryAfter?: number) {
    super(message);
    this.name = 'RateLimitError';
  }
}