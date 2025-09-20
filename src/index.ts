import { Env } from './types';
import { DatabaseMigrations } from './database/migrations';
import { VulnerabilityScanner } from './services/vulnerability-scanner';
import { ApiHandler } from './api/handler';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      // Initialize database if needed
      await this.initializeDatabase(env);

      // Handle API requests
      const apiHandler = new ApiHandler(env);
      return await apiHandler.handle(request);
    } catch (error) {
      console.error('Error handling request:', error);
      return new Response(
        JSON.stringify({
          error: 'Internal server error',
          message: error instanceof Error ? error.message : 'Unknown error',
        }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    console.log('Scheduled vulnerability scan started at:', new Date().toISOString());
    const startTime = Date.now();

    try {
      // Initialize database if needed
      await this.initializeDatabase(env);

      // Create and run vulnerability scanner
      const scanner = new VulnerabilityScanner(env);
      const scanResult = await scanner.runWeeklyVulnerabilityScan();

      const executionTime = Date.now() - startTime;
      console.log(`Scheduled scan completed successfully in ${executionTime}ms`);
      console.log('Scan results:', scanResult);

      // Wait for any pending operations
      ctx.waitUntil(Promise.resolve());

    } catch (error) {
      const executionTime = Date.now() - startTime;
      console.error(`Scheduled scan failed after ${executionTime}ms:`, error);

      // Log failure to database if possible
      try {
        const scanner = new VulnerabilityScanner(env);
        await scanner.logProcessingResult({
          status: 'FAILED',
          vulnerabilities_found: 0,
          vulnerabilities_new: 0,
          vulnerabilities_updated: 0,
          ios_releases_processed: 0,
          execution_time_ms: executionTime,
          errors: error instanceof Error ? error.message : 'Unknown error during scan',
        });
      } catch (logError) {
        console.error('Failed to log error to database:', logError);
      }

      // Re-throw to ensure proper error reporting
      throw error;
    }
  },

  async initializeDatabase(env: Env): Promise<void> {
    try {
      const migrations = new DatabaseMigrations(env);
      await migrations.runMigrations();
    } catch (error) {
      console.error('Database initialization failed:', error);
      throw error;
    }
  },
};