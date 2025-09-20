export class Logger {
  private static formatTimestamp(): string {
    return new Date().toISOString();
  }

  private static formatMessage(level: string, message: string, context?: any): string {
    const timestamp = this.formatTimestamp();
    const contextStr = context ? ` | Context: ${JSON.stringify(context)}` : '';
    return `[${timestamp}] ${level.toUpperCase()}: ${message}${contextStr}`;
  }

  static info(message: string, context?: any): void {
    console.log(this.formatMessage('info', message, context));
  }

  static warn(message: string, context?: any): void {
    console.warn(this.formatMessage('warn', message, context));
  }

  static error(message: string, error?: Error | any, context?: any): void {
    const errorInfo = error instanceof Error ? {
      name: error.name,
      message: error.message,
      stack: error.stack
    } : error;

    const fullContext = { ...context, error: errorInfo };
    console.error(this.formatMessage('error', message, fullContext));
  }

  static debug(message: string, context?: any): void {
    console.debug(this.formatMessage('debug', message, context));
  }

  static performance(operation: string, startTime: number, context?: any): void {
    const duration = Date.now() - startTime;
    this.info(`Performance: ${operation} completed in ${duration}ms`, context);
  }
}