import { Env, Vulnerability, IOSRelease, ProcessingLog } from '../types';

export class VulnerabilityRepository {
  private db: D1Database;

  constructor(env: Env) {
    this.db = env.DB;
  }

  async insertVulnerability(vulnerability: Omit<Vulnerability, 'created_at'>): Promise<void> {
    // Ensure all values are properly defined (convert undefined to null)
    const safeVulnerability = {
      id: vulnerability.id || null,
      cve_id: vulnerability.cve_id || null,
      description: vulnerability.description || null,
      severity: vulnerability.severity || null,
      cvss_score: vulnerability.cvss_score !== undefined ? vulnerability.cvss_score : null,
      cvss_vector: vulnerability.cvss_vector || null,
      ios_versions_affected: vulnerability.ios_versions_affected || null,
      discovered_date: vulnerability.discovered_date || null,
      apple_description: vulnerability.apple_description || null,
      apple_available_for: vulnerability.apple_available_for || null,
      apple_impact: vulnerability.apple_impact || null,
      apple_product: vulnerability.apple_product || null,
    };

    await this.db.prepare(`
      INSERT OR REPLACE INTO vulnerabilities (
        id, cve_id, description, severity, cvss_score, cvss_vector,
        ios_versions_affected, discovered_date, updated_at,
        apple_description, apple_available_for, apple_impact, apple_product
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
    `).bind(
      safeVulnerability.id,
      safeVulnerability.cve_id,
      safeVulnerability.description,
      safeVulnerability.severity,
      safeVulnerability.cvss_score,
      safeVulnerability.cvss_vector,
      safeVulnerability.ios_versions_affected,
      safeVulnerability.discovered_date,
      safeVulnerability.apple_description,
      safeVulnerability.apple_available_for,
      safeVulnerability.apple_impact,
      safeVulnerability.apple_product
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
    searchTerm?: string,
    iosVersion?: string,
    sortBy = 'discovered_date',
    sortOrder = 'desc'
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

    if (iosVersion) {
      // Use more precise iOS version matching to avoid "18.6" matching "18.6.2"
      // Match the version as a standalone version (surrounded by word boundaries, spaces, or commas)
      query += ' AND (ios_versions_affected LIKE ? OR ios_versions_affected LIKE ? OR ios_versions_affected LIKE ? OR ios_versions_affected = ?)';
      params.push(
        `${iosVersion},%`,     // version at start followed by comma
        `%, ${iosVersion},%`,  // version in middle with spaces
        `%, ${iosVersion}`,    // version at end with space
        iosVersion             // exact match
      );
    }

    // Add sorting
    const validSortColumns = ['discovered_date', 'cvss_score', 'severity', 'cve_id'];
    const validSortOrders = ['asc', 'desc'];

    const finalSortBy = validSortColumns.includes(sortBy) ? sortBy : 'discovered_date';
    const finalSortOrder = validSortOrders.includes(sortOrder) ? sortOrder : 'desc';

    // Special handling for severity sorting
    if (finalSortBy === 'severity') {
      const severityOrder = finalSortOrder === 'desc'
        ? "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END"
        : "CASE severity WHEN 'LOW' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'HIGH' THEN 3 WHEN 'CRITICAL' THEN 4 ELSE 5 END";
      query += ` ORDER BY ${severityOrder}, cvss_score DESC`;
    } else {
      query += ` ORDER BY ${finalSortBy} ${finalSortOrder.toUpperCase()}`;
      // Add secondary sort for consistency
      if (finalSortBy !== 'cvss_score') {
        query += ', cvss_score DESC';
      }
    }

    query += ' LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const result = await this.db.prepare(query).bind(...params).all();
    return (result.results as unknown) as Vulnerability[];
  }

  async getVulnerabilityCount(severity?: string, searchTerm?: string, iosVersion?: string): Promise<number> {
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

    if (iosVersion) {
      // Use more precise iOS version matching to avoid "18.6" matching "18.6.2"
      // Match the version as a standalone version (surrounded by word boundaries, spaces, or commas)
      query += ' AND (ios_versions_affected LIKE ? OR ios_versions_affected LIKE ? OR ios_versions_affected LIKE ? OR ios_versions_affected = ?)';
      params.push(
        `${iosVersion},%`,     // version at start followed by comma
        `%, ${iosVersion},%`,  // version in middle with spaces
        `%, ${iosVersion}`,    // version at end with space
        iosVersion             // exact match
      );
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

  async getAvailableIOSVersions(): Promise<string[]> {
    const result = await this.db.prepare(`
      SELECT DISTINCT ios_versions_affected
      FROM vulnerabilities
      WHERE ios_versions_affected IS NOT NULL
      ORDER BY ios_versions_affected DESC
    `).all();

    const versions = (result.results as any[])
      .map(row => row.ios_versions_affected)
      .filter(version => version && version.trim().length > 0);

    // Extract individual versions from comma-separated strings
    const allVersions = new Set<string>();
    versions.forEach(versionString => {
      // Split by comma and extract version numbers
      const parts = versionString.split(',');
      parts.forEach((part: string) => {
        const match = part.trim().match(/(\d+(?:\.\d+)*)/);
        if (match) {
          allVersions.add(match[1]);
        }
      });
    });

    // Sort versions in descending order
    return Array.from(allVersions).sort((a, b) => {
      const aParts = a.split('.').map(Number);
      const bParts = b.split('.').map(Number);

      for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
        const aVal = aParts[i] || 0;
        const bVal = bParts[i] || 0;
        if (aVal !== bVal) {
          return bVal - aVal; // Descending order
        }
      }
      return 0;
    });
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

  async checkDatabaseIntegrity(): Promise<{
    total_vulnerabilities: number;
    duplicate_cve_ids: number;
    duplicate_vulnerability_ids: number;
    total_ios_releases: number;
    duplicate_versions: number;
  }> {
    // Check for duplicate CVE IDs
    const duplicateCves = await this.db.prepare(`
      SELECT COUNT(*) as count FROM (
        SELECT cve_id, COUNT(*) as occurrences
        FROM vulnerabilities
        GROUP BY cve_id
        HAVING COUNT(*) > 1
      )
    `).first();

    // Check for duplicate vulnerability IDs
    const duplicateIds = await this.db.prepare(`
      SELECT COUNT(*) as count FROM (
        SELECT id, COUNT(*) as occurrences
        FROM vulnerabilities
        GROUP BY id
        HAVING COUNT(*) > 1
      )
    `).first();

    // Check for duplicate iOS versions
    const duplicateVersions = await this.db.prepare(`
      SELECT COUNT(*) as count FROM (
        SELECT version, COUNT(*) as occurrences
        FROM ios_releases
        GROUP BY version
        HAVING COUNT(*) > 1
      )
    `).first();

    // Get total counts
    const totalVulns = await this.db.prepare('SELECT COUNT(*) as count FROM vulnerabilities').first();
    const totalReleases = await this.db.prepare('SELECT COUNT(*) as count FROM ios_releases').first();

    return {
      total_vulnerabilities: (totalVulns as any)?.count || 0,
      duplicate_cve_ids: (duplicateCves as any)?.count || 0,
      duplicate_vulnerability_ids: (duplicateIds as any)?.count || 0,
      total_ios_releases: (totalReleases as any)?.count || 0,
      duplicate_versions: (duplicateVersions as any)?.count || 0,
    };
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