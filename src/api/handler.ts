import { Env } from '../types';
import { VulnerabilityRepository } from '../database/repository';

export class ApiHandler {
  private repository: VulnerabilityRepository;
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.repository = new VulnerabilityRepository(env);
  }

  async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Add CORS headers for all responses
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Content-Type': 'application/json',
    };

    // Handle preflight OPTIONS requests
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      // Route requests
      if (method === 'GET') {
        if (path === '/api/vulnerabilities') {
          return await this.getVulnerabilities(url, corsHeaders);
        }
        if (path === '/api/vulnerabilities/stats') {
          return await this.getVulnerabilityStats(corsHeaders);
        }
        if (path.startsWith('/api/vulnerabilities/')) {
          const cveId = path.split('/').pop();
          if (cveId) {
            return await this.getVulnerability(cveId, corsHeaders);
          }
        }
        if (path === '/api/releases') {
          return await this.getIOSReleases(corsHeaders);
        }
        if (path === '/api/logs') {
          return await this.getProcessingLogs(corsHeaders);
        }
        if (path === '/api/health') {
          return await this.getHealthCheck(corsHeaders);
        }
        if (path === '/' || path === '/api') {
          return await this.getApiInfo(corsHeaders);
        }
      }

      if (method === 'POST' && path === '/api/scan/trigger') {
        return await this.triggerManualScan(corsHeaders);
      }

      if (method === 'POST' && path === '/api/populate-sample-data') {
        return await this.populateSampleData(corsHeaders);
      }

      if (method === 'POST' && path === '/api/test-apple-parser') {
        return await this.testAppleParser(corsHeaders);
      }

      if (method === 'POST' && path === '/api/test-apple-links') {
        return await this.testAppleLinksParser(corsHeaders);
      }

      if (method === 'POST' && path === '/api/process-latest-ios') {
        return await this.processLatestIOS(corsHeaders);
      }

      // Not found
      return new Response(
        JSON.stringify({ error: 'Not found', path }),
        { status: 404, headers: corsHeaders }
      );

    } catch (error) {
      console.error('API error:', error);
      return new Response(
        JSON.stringify({
          error: 'Internal server error',
          message: error instanceof Error ? error.message : 'Unknown error',
        }),
        { status: 500, headers: corsHeaders }
      );
    }
  }

  private async getVulnerabilities(url: URL, headers: Record<string, string>): Promise<Response> {
    const searchParams = url.searchParams;
    const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);
    const offset = Math.max(parseInt(searchParams.get('offset') || '0'), 0);
    const severity = searchParams.get('severity') || undefined;
    const search = searchParams.get('search') || undefined;

    const [vulnerabilities, total] = await Promise.all([
      this.repository.getAllVulnerabilities(limit, offset, severity, search),
      this.repository.getVulnerabilityCount(severity, search),
    ]);

    const response = {
      vulnerabilities,
      pagination: {
        total,
        limit,
        offset,
        has_more: offset + limit < total,
      },
      filters: {
        severity,
        search,
      },
    };

    return new Response(JSON.stringify(response), { headers });
  }

  private async getVulnerability(cveId: string, headers: Record<string, string>): Promise<Response> {
    const vulnerability = await this.repository.getVulnerabilityByCveId(cveId);

    if (!vulnerability) {
      return new Response(
        JSON.stringify({ error: 'Vulnerability not found', cve_id: cveId }),
        { status: 404, headers }
      );
    }

    return new Response(JSON.stringify({ vulnerability }), { headers });
  }

  private async getVulnerabilityStats(headers: Record<string, string>): Promise<Response> {
    const stats = await this.repository.getVulnerabilityStats();
    return new Response(JSON.stringify({ stats }), { headers });
  }

  private async getIOSReleases(headers: Record<string, string>): Promise<Response> {
    const releases = await this.repository.getAllIOSReleases();
    return new Response(JSON.stringify({ releases }), { headers });
  }

  private async getProcessingLogs(headers: Record<string, string>): Promise<Response> {
    const logs = await this.repository.getRecentProcessingLogs();
    return new Response(JSON.stringify({ logs }), { headers });
  }

  private async getHealthCheck(headers: Record<string, string>): Promise<Response> {
    try {
      // Test database connectivity
      const stats = await this.repository.getVulnerabilityStats();
      const recentLogs = await this.repository.getRecentProcessingLogs(1);

      const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: {
          connected: true,
          total_vulnerabilities: stats.total,
        },
        last_scan: recentLogs.length > 0 ? {
          date: recentLogs[0].run_date,
          status: recentLogs[0].status,
          vulnerabilities_found: recentLogs[0].vulnerabilities_found,
        } : null,
      };

      return new Response(JSON.stringify(health), { headers });

    } catch (error) {
      const health = {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };

      return new Response(
        JSON.stringify(health),
        { status: 503, headers }
      );
    }
  }

  private async getApiInfo(headers: Record<string, string>): Promise<Response> {
    const info = {
      name: 'iOS Security Vulnerability Tracker API',
      version: '1.0.0',
      description: 'API for tracking iOS security vulnerabilities with CVSS scores',
      endpoints: {
        vulnerabilities: {
          'GET /api/vulnerabilities': 'List vulnerabilities with filtering and pagination',
          'GET /api/vulnerabilities/stats': 'Get vulnerability statistics',
          'GET /api/vulnerabilities/{cve_id}': 'Get specific vulnerability by CVE ID',
        },
        releases: {
          'GET /api/releases': 'List iOS security releases',
        },
        system: {
          'GET /api/health': 'System health check',
          'GET /api/logs': 'Recent processing logs',
          'POST /api/scan/trigger': 'Manually trigger vulnerability scan',
        },
      },
      query_parameters: {
        vulnerabilities: {
          limit: 'Number of results (max 100, default 50)',
          offset: 'Pagination offset (default 0)',
          severity: 'Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)',
          search: 'Search in CVE ID and description',
        },
      },
      last_updated: new Date().toISOString(),
    };

    return new Response(JSON.stringify(info, null, 2), { headers });
  }

  private async triggerManualScan(headers: Record<string, string>): Promise<Response> {
    try {
      // Import the VulnerabilityScanner
      const { VulnerabilityScanner } = await import('../services/vulnerability-scanner');

      const startTime = Date.now();
      console.log('Manual vulnerability scan started at:', new Date().toISOString());

      // Create and run vulnerability scanner
      const scanner = new VulnerabilityScanner(this.env);
      const scanResult = await scanner.runWeeklyVulnerabilityScan();

      const executionTime = Date.now() - startTime;
      console.log(`Manual scan completed successfully in ${executionTime}ms`);
      console.log('Scan results:', scanResult);

      const response = {
        message: 'Manual scan completed successfully',
        execution_time_ms: executionTime,
        scan_results: scanResult,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), { headers });

    } catch (error) {
      console.error('Manual scan failed:', error);

      const response = {
        message: 'Manual scan failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async populateSampleData(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Populating sample vulnerability data...');

      // Sample vulnerabilities based on real iOS CVEs
      const sampleVulnerabilities = [
        {
          id: 'CVE-2024-44308',
          cve_id: 'CVE-2024-44308',
          description: 'A buffer overflow issue was addressed with improved memory handling.',
          severity: 'HIGH',
          cvss_score: 7.8,
          cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
          ios_versions_affected: 'iOS 18.1',
          discovered_date: '2024-10-28',
        },
        {
          id: 'CVE-2024-44309',
          cve_id: 'CVE-2024-44309',
          description: 'A memory corruption issue was addressed with improved input validation.',
          severity: 'CRITICAL',
          cvss_score: 9.8,
          cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          ios_versions_affected: 'iOS 18.1',
          discovered_date: '2024-10-28',
        },
        {
          id: 'CVE-2024-44310',
          cve_id: 'CVE-2024-44310',
          description: 'An out-of-bounds read issue was addressed with improved bounds checking.',
          severity: 'MEDIUM',
          cvss_score: 5.5,
          cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
          ios_versions_affected: 'iOS 18.0, iOS 17.7',
          discovered_date: '2024-09-16',
        },
        {
          id: 'CVE-2024-40866',
          cve_id: 'CVE-2024-40866',
          description: 'A logic issue was addressed with improved state management.',
          severity: 'HIGH',
          cvss_score: 8.1,
          cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
          ios_versions_affected: 'iOS 17.6',
          discovered_date: '2024-07-29',
        },
        {
          id: 'CVE-2024-40857',
          cve_id: 'CVE-2024-40857',
          description: 'A use-after-free issue was addressed with improved memory management.',
          severity: 'CRITICAL',
          cvss_score: 9.8,
          cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          ios_versions_affected: 'iOS 17.6',
          discovered_date: '2024-07-29',
        },
      ];

      let inserted = 0;
      for (const vuln of sampleVulnerabilities) {
        try {
          await this.repository.insertVulnerability(vuln);
          inserted++;
          console.log(`Inserted vulnerability: ${vuln.cve_id}`);
        } catch (error) {
          console.warn(`Failed to insert ${vuln.cve_id}:`, error);
        }
      }

      // Also insert some iOS releases
      const sampleReleases = [
        {
          version: '18.1',
          release_date: '2024-10-28',
          security_content_url: 'https://support.apple.com/en-us/121238',
        },
        {
          version: '18.0',
          release_date: '2024-09-16',
          security_content_url: 'https://support.apple.com/en-us/121250',
        },
        {
          version: '17.7',
          release_date: '2024-09-16',
          security_content_url: 'https://support.apple.com/en-us/121251',
        },
        {
          version: '17.6',
          release_date: '2024-07-29',
          security_content_url: 'https://support.apple.com/en-us/121234',
        },
      ];

      let releasesInserted = 0;
      for (const release of sampleReleases) {
        try {
          await this.repository.insertIOSRelease(release);
          releasesInserted++;
          console.log(`Inserted iOS release: ${release.version}`);
        } catch (error) {
          console.warn(`Failed to insert iOS ${release.version}:`, error);
        }
      }

      const response = {
        message: 'Sample data populated successfully',
        vulnerabilities_inserted: inserted,
        releases_inserted: releasesInserted,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), { headers });

    } catch (error) {
      console.error('Failed to populate sample data:', error);

      const response = {
        message: 'Failed to populate sample data',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async testAppleParser(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Testing Apple security page parser...');

      // Import the AppleSecurityParser
      const { AppleSecurityParser } = await import('../services/apple-security-parser');

      // Test with the same page you used in Python: HT122066
      const testUrl = 'https://support.apple.com/en-us/122066';

      console.log(`Fetching Apple security page: ${testUrl}`);
      const response = await fetch(testUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch ${testUrl}: ${response.status}`);
      }

      const html = await response.text();
      console.log(`Fetched ${html.length} characters from Apple security page`);

      // Parse the security content
      const parsedData = AppleSecurityParser.parseSecurityContent(html, '18.1');

      const result = {
        message: 'Apple parser test completed',
        test_url: testUrl,
        html_length: html.length,
        vulnerabilities_found: parsedData.vulnerabilities.length,
        vulnerabilities: parsedData.vulnerabilities,
        release_date: parsedData.releaseDate,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(result, null, 2), { headers });

    } catch (error) {
      console.error('Apple parser test failed:', error);

      const response = {
        message: 'Apple parser test failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async testAppleLinksParser(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Testing Apple security links parser...');

      // Import the VulnerabilityScanner to access the link extraction method
      const { VulnerabilityScanner } = await import('../services/vulnerability-scanner');

      // Test with main Apple security page
      const testUrl = 'https://support.apple.com/en-us/100100';

      console.log(`Fetching Apple main security page: ${testUrl}`);
      const response = await fetch(testUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch ${testUrl}: ${response.status}`);
      }

      const html = await response.text();
      console.log(`Fetched ${html.length} characters from main Apple security page`);

      // Create scanner to test link extraction
      const scanner = new VulnerabilityScanner(this.env);

      // Use reflection to call private method (for testing purposes)
      const extractMethod = (scanner as any).extractIOSReleaseLinks;
      const iosReleases = extractMethod.call(scanner, html);

      const result = {
        message: 'Apple links parser test completed',
        test_url: testUrl,
        html_length: html.length,
        ios_releases_found: iosReleases.length,
        ios_releases: iosReleases.slice(0, 10), // Show first 10 releases
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(result, null, 2), { headers });

    } catch (error) {
      console.error('Apple links parser test failed:', error);

      const response = {
        message: 'Apple links parser test failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async processLatestIOS(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Processing latest iOS security release...');

      // Import required services
      const { AppleSecurityParser } = await import('../services/apple-security-parser');
      const { NVDClient } = await import('../services/nvd-client');

      // Process iOS 18.3 (the latest release we know has CVEs)
      const version = '18.3';
      const url = 'https://support.apple.com/en-us/122066';

      console.log(`Processing iOS ${version} from ${url}`);

      // Fetch the iOS security page
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch ${url}: ${response.status}`);
      }

      const html = await response.text();
      console.log(`Fetched ${html.length} characters from iOS security page`);

      // Parse vulnerabilities
      const parsedData = AppleSecurityParser.parseSecurityContent(html, version);
      console.log(`Found ${parsedData.vulnerabilities.length} vulnerabilities`);

      // Insert iOS release record
      const releaseId = await this.repository.insertIOSRelease({
        version: parsedData.version,
        release_date: parsedData.releaseDate,
        security_content_url: url,
      });

      console.log(`Inserted iOS release ${version} with ID ${releaseId}`);

      // Process vulnerabilities (limit to first 5 for testing)
      const nvdClient = new NVDClient(this.env);
      const processedVulns = [];
      const vulnsToProcess = parsedData.vulnerabilities.slice(0, 5);

      for (const vuln of vulnsToProcess) {
        try {
          console.log(`Processing ${vuln.cveId}...`);

          // Get CVSS data from NVD
          const cvssData = await nvdClient.getCVSSData(vuln.cveId);

          // Create vulnerability record
          const vulnerability = {
            id: vuln.cveId,
            cve_id: vuln.cveId,
            description: vuln.description,
            severity: cvssData?.severity || 'UNKNOWN',
            cvss_score: cvssData?.score || null,
            cvss_vector: cvssData?.vector || null,
            ios_versions_affected: parsedData.version,
            discovered_date: parsedData.releaseDate,
          };

          // Insert into database
          await this.repository.insertVulnerability(vulnerability);

          // Link to release
          await this.repository.linkVulnerabilityToRelease(vuln.cveId, releaseId);

          processedVulns.push({
            cve_id: vuln.cveId,
            cvss_score: cvssData?.score,
            severity: cvssData?.severity,
          });

          console.log(`Processed ${vuln.cveId}: ${cvssData?.severity} (${cvssData?.score})`);

        } catch (error) {
          console.error(`Failed to process ${vuln.cveId}:`, error);
        }
      }

      const result = {
        message: 'Latest iOS processing completed',
        ios_version: version,
        release_id: releaseId,
        total_vulnerabilities: parsedData.vulnerabilities.length,
        processed_vulnerabilities: processedVulns.length,
        processed_details: processedVulns,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(result, null, 2), { headers });

    } catch (error) {
      console.error('Latest iOS processing failed:', error);

      const response = {
        message: 'Latest iOS processing failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }
}