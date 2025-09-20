import { Env } from '../types';

export class DatabaseMigrations {
  private db: D1Database;

  constructor(env: Env) {
    this.db = env.DB;
  }

  async runMigrations(): Promise<void> {
    console.log('Running database migrations...');

    try {
      // Check if migrations table exists
      await this.createMigrationsTable();

      const migrations = [
        {
          version: 1,
          name: 'initial_schema',
          sql: this.getInitialSchemaSql()
        },
      ];

      for (const migration of migrations) {
        await this.runMigration(migration);
      }

      console.log('Database migrations completed successfully');
    } catch (error) {
      console.error('Database migration failed:', error);
      throw error;
    }
  }

  private async createMigrationsTable(): Promise<void> {
    await this.db.exec(`
      CREATE TABLE IF NOT EXISTS migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }

  private async runMigration(migration: { version: number; name: string; sql: string }): Promise<void> {
    // Check if migration already applied
    const result = await this.db.prepare(
      'SELECT version FROM migrations WHERE version = ?'
    ).bind(migration.version).first();

    if (result) {
      console.log(`Migration ${migration.version} (${migration.name}) already applied, skipping`);
      return;
    }

    console.log(`Applying migration ${migration.version}: ${migration.name}`);

    // Apply migration
    await this.db.exec(migration.sql);

    // Record migration
    await this.db.prepare(
      'INSERT INTO migrations (version, name) VALUES (?, ?)'
    ).bind(migration.version, migration.name).run();

    console.log(`Migration ${migration.version} applied successfully`);
  }

  private getInitialSchemaSql(): string {
    return `
      -- iOS Security Vulnerabilities Database Schema

      -- Table to store vulnerability information
      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        cve_id TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL,
        severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
        cvss_score REAL CHECK (cvss_score >= 0 AND cvss_score <= 10),
        cvss_vector TEXT,
        ios_versions_affected TEXT NOT NULL,
        discovered_date DATE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      -- Table to track iOS releases and their security content
      CREATE TABLE IF NOT EXISTS ios_releases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version TEXT NOT NULL,
        release_date DATE NOT NULL,
        security_content_url TEXT,
        processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(version)
      );

      -- Table to log processing runs
      CREATE TABLE IF NOT EXISTS processing_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT CHECK (status IN ('SUCCESS', 'PARTIAL', 'FAILED')) NOT NULL,
        vulnerabilities_found INTEGER DEFAULT 0,
        vulnerabilities_new INTEGER DEFAULT 0,
        vulnerabilities_updated INTEGER DEFAULT 0,
        ios_releases_processed INTEGER DEFAULT 0,
        execution_time_ms INTEGER,
        errors TEXT
      );

      -- Table to track vulnerability-to-release relationships
      CREATE TABLE IF NOT EXISTS vulnerability_releases (
        vulnerability_id TEXT,
        ios_release_id INTEGER,
        PRIMARY KEY (vulnerability_id, ios_release_id),
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
        FOREIGN KEY (ios_release_id) REFERENCES ios_releases(id)
      );

      -- Indexes for better query performance
      CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
      CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
      CREATE INDEX IF NOT EXISTS idx_vulnerabilities_discovered_date ON vulnerabilities(discovered_date);
      CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score);
      CREATE INDEX IF NOT EXISTS idx_ios_releases_version ON ios_releases(version);
      CREATE INDEX IF NOT EXISTS idx_ios_releases_release_date ON ios_releases(release_date);
      CREATE INDEX IF NOT EXISTS idx_processing_logs_run_date ON processing_logs(run_date);
      CREATE INDEX IF NOT EXISTS idx_processing_logs_status ON processing_logs(status);
    `;
  }
}