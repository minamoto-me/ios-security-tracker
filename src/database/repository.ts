import { Env, Vulnerability, IOSRelease, ProcessingLog } from '../types';

export class VulnerabilityRepository {
  private db: D1Database;

  constructor(env: Env) {
    this.db = env.DB;
  }

  async insertVulnerability(vulnerability: Omit<Vulnerability, 'created_at'>): Promise<void> {
    await this.db.prepare(`
      INSERT OR REPLACE INTO vulnerabilities (
        id, cve_id, description, severity, cvss_score, cvss_vector,
        ios_versions_affected, discovered_date, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(
      vulnerability.id,
      vulnerability.cve_id,
      vulnerability.description,
      vulnerability.severity,
      vulnerability.cvss_score,
      vulnerability.cvss_vector,
      vulnerability.ios_versions_affected,
      vulnerability.discovered_date
    ).run();
  }

  async getVulnerabilityByCveId(cveId: string): Promise<Vulnerability | null> {
    const result = await this.db.prepare(
      'SELECT * FROM vulnerabilities WHERE cve_id = ?'
    ).bind(cveId).first();

    return result as Vulnerability | null;
  }

  async getAllVulnerabilities(
    limit = 100,
    offset = 0,
    severity?: string,
    searchTerm?: string
  ): Promise<Vulnerability[]> {
    let query = 'SELECT * FROM vulnerabilities WHERE 1=1';
    const params: any[] = [];

    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }

    if (searchTerm) {
      query += ' AND (description LIKE ? OR cve_id LIKE ?)';
      params.push(`%${searchTerm}%`, `%${searchTerm}%`);
    }

    query += ' ORDER BY discovered_date DESC, cvss_score DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const result = await this.db.prepare(query).bind(...params).all();
    return (result.results as unknown) as Vulnerability[];
  }

  async getVulnerabilityCount(severity?: string, searchTerm?: string): Promise<number> {
    let query = 'SELECT COUNT(*) as count FROM vulnerabilities WHERE 1=1';
    const params: any[] = [];

    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }

    if (searchTerm) {
      query += ' AND (description LIKE ? OR cve_id LIKE ?)';
      params.push(`%${searchTerm}%`, `%${searchTerm}%`);
    }

    const result = await this.db.prepare(query).bind(...params).first();
    return (result as any)?.count || 0;
  }

  async insertIOSRelease(release: Omit<IOSRelease, 'id' | 'processed_at'>): Promise<number> {
    const result = await this.db.prepare(`
      INSERT OR REPLACE INTO ios_releases (version, release_date, security_content_url)
      VALUES (?, ?, ?)
    `).bind(
      release.version,
      release.release_date,
      release.security_content_url
    ).run();

    return result.meta.last_row_id as number;
  }

  async getIOSReleaseByVersion(version: string): Promise<IOSRelease | null> {
    const result = await this.db.prepare(
      'SELECT * FROM ios_releases WHERE version = ?'
    ).bind(version).first();

    return result as IOSRelease | null;
  }

  async getAllIOSReleases(limit = 50): Promise<IOSRelease[]> {
    const result = await this.db.prepare(
      'SELECT * FROM ios_releases ORDER BY release_date DESC LIMIT ?'
    ).bind(limit).all();

    return (result.results as unknown) as IOSRelease[];
  }

  async insertProcessingLog(log: Omit<ProcessingLog, 'id' | 'run_date'>): Promise<void> {
    await this.db.prepare(`
      INSERT INTO processing_logs (
        status, vulnerabilities_found, vulnerabilities_new,
        vulnerabilities_updated, ios_releases_processed,
        execution_time_ms, errors
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      log.status,
      log.vulnerabilities_found,
      log.vulnerabilities_new || 0,
      log.vulnerabilities_updated || 0,
      log.ios_releases_processed || 0,
      log.execution_time_ms || 0,
      log.errors
    ).run();
  }

  async getRecentProcessingLogs(limit = 10): Promise<ProcessingLog[]> {
    const result = await this.db.prepare(
      'SELECT * FROM processing_logs ORDER BY run_date DESC LIMIT ?'
    ).bind(limit).all();

    return (result.results as unknown) as ProcessingLog[];
  }

  async linkVulnerabilityToRelease(vulnerabilityId: string, releaseId: number): Promise<void> {
    await this.db.prepare(`
      INSERT OR IGNORE INTO vulnerability_releases (vulnerability_id, ios_release_id)
      VALUES (?, ?)
    `).bind(vulnerabilityId, releaseId).run();
  }

  async getVulnerabilitiesForRelease(releaseId: number): Promise<Vulnerability[]> {
    const result = await this.db.prepare(`
      SELECT v.* FROM vulnerabilities v
      JOIN vulnerability_releases vr ON v.id = vr.vulnerability_id
      WHERE vr.ios_release_id = ?
      ORDER BY v.cvss_score DESC
    `).bind(releaseId).all();

    return (result.results as unknown) as Vulnerability[];
  }

  async getVulnerabilityStats(): Promise<{
    total: number;
    bySeverity: Record<string, number>;
    recentCount: number;
  }> {
    const totalResult = await this.db.prepare(
      'SELECT COUNT(*) as count FROM vulnerabilities'
    ).first();

    const severityResult = await this.db.prepare(`
      SELECT severity, COUNT(*) as count
      FROM vulnerabilities
      GROUP BY severity
    `).all();

    const recentResult = await this.db.prepare(`
      SELECT COUNT(*) as count
      FROM vulnerabilities
      WHERE discovered_date >= date('now', '-30 days')
    `).first();

    const bySeverity: Record<string, number> = {};
    severityResult.results.forEach((row: any) => {
      bySeverity[row.severity] = row.count;
    });

    return {
      total: (totalResult as any)?.count || 0,
      bySeverity,
      recentCount: (recentResult as any)?.count || 0,
    };
  }
}